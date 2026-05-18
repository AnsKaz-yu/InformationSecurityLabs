import argparse
import random
import re
import string
from dataclasses import dataclass
from pathlib import Path

from state_manager import load_state

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
STATE_PATH = BASE_DIR / "state.json"
GUESS_PATH = BASE_DIR / "plaintexts_guess.txt"
OT_PATH = ROOT_DIR / "Oliver Twist (1).txt"
PP_PATH = ROOT_DIR / "Dickens Charles. The Pickwick Papers - royallib.ru.txt"

GOOD_CHARS = set(string.ascii_letters + string.digits + " .,;:!?'-\"()[]_")
PRINTABLE_MIN = 32
PRINTABLE_MAX = 126
UNKNOWN_RUN_MIN = 8


@dataclass
class Candidate:
    side_idx: int
    gap_idx: int
    suffix: str
    chunk: str
    other_chunk: str
    ref_pos: int
    score: int
    match_count: int


@dataclass
class ReferenceBridge:
    side_idx: int
    gap_idx: int
    suffix: str
    chunk: str
    other_chunk: str
    ref_pos: int


def normalize_text(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n\n+", " ", text)
    text = text.replace("\n", " ")
    text = text.replace("\u2018", "'").replace("\u2019", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2013", "-").replace("\u2014", "--")
    text = text.replace("\u2026", "...")
    text = text.replace(
        "the dreadful occurrences that so recently taken place.",
        "the dreadful occurrences that had so recently taken place.",
    )
    text = text.replace("_", "")
    return text


def load_reference_texts():
    ot_text = normalize_text(OT_PATH.read_text(encoding="utf-8"))
    pp_text = normalize_text(PP_PATH.read_text(encoding="cp1251"))
    return [ot_text, pp_text]


def fit_text_length(chars, expected_len):
    if len(chars) < expected_len:
        chars = chars + ["_"] * (expected_len - len(chars))
    elif len(chars) > expected_len:
        chars = chars[:expected_len]
    return chars


def find_unknown_start(text):
    limit = len(text) - UNKNOWN_RUN_MIN + 1
    if limit < 1:
        return -1
    for idx in range(limit):
        if all(text[idx + offset] == "_" for offset in range(UNKNOWN_RUN_MIN)):
            return idx
    return -1


def split_known_prefix(raw_text):
    unknown_start = find_unknown_start(raw_text)
    if unknown_start < 0:
        return raw_text
    return raw_text[:unknown_start]


def trim_bad_tail(raw_text):
    for idx, char in enumerate(raw_text):
        if not is_good_char(char):
            return raw_text[:idx]
    return raw_text


def read_guess_file(path, expected_len):
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 5 or lines[0] != "P1:" or lines[3] != "P2:":
        raise ValueError(f"Unexpected guess file format: {path}")
    texts = [
        list(trim_bad_tail(split_known_prefix(lines[1]))),
        list(trim_bad_tail(split_known_prefix(lines[4]))),
    ]
    normalized = any(len(text) != expected_len for text in texts)
    texts = [fit_text_length(text, expected_len) for text in texts]
    return texts, normalized


def heal_text_from_reference(text, ref_text, window_sizes=(200, 160, 120, 100, 80, 60, 40, 30, 20), search_back=420):
    frontier = find_unknown_start(text)
    if frontier < 0:
        frontier = len(text)

    prefix = "".join(text[:frontier])
    if not prefix or ref_text.find(prefix) >= 0:
        return 0

    search_start = max(0, frontier - search_back)
    best_start = None
    best_replacement = None
    for window_size in window_sizes:
        if frontier - search_start < window_size:
            continue
        for start in range(search_start, frontier - window_size + 1):
            needle = prefix[start:start + window_size]
            if not needle or ref_text.count(needle) != 1:
                continue
            ref_start = ref_text.find(needle)
            replacement = ref_text[ref_start:ref_start + (frontier - start)]
            if len(replacement) != frontier - start:
                continue
            if best_start is None or start < best_start:
                best_start = start
                best_replacement = replacement

    if best_start is not None:
        text[best_start:frontier] = list(best_replacement)
        return frontier - best_start

    return 0


def heal_texts_from_references(texts, refs):
    healed = []
    for side_idx, (text, ref_text) in enumerate(zip(texts, refs), start=1):
        healed_len = heal_text_from_reference(text, ref_text)
        if healed_len:
            healed.append((side_idx, healed_len))
    return healed


def write_guess_file(path, texts):
    path.write_text(
        "P1:\n" + "".join(texts[0]) + "\n\nP2:\n" + "".join(texts[1]) + "\n",
        encoding="utf-8",
    )


def is_known_char(char):
    return char != "_" and ord(char) < 128


def is_good_char(char):
    return char in GOOD_CHARS


def is_printable_ascii(value):
    return PRINTABLE_MIN <= value <= PRINTABLE_MAX


def is_good_text(text):
    return bool(text) and all(is_good_char(char) for char in text)


def strip_reference_marks(text):
    return text.replace("_", "").replace("'", "")


def normalize_combined_probe_text(text):
    text = strip_reference_marks(text).lower()
    text = text.replace(" ", "").replace("-", "")
    text = text.replace("hne", "one")
    return text


def find_unique_ref_insert(text, ref_text, gap_idx, max_suffix=200, min_suffix=20):
    if gap_idx <= 0:
        return None

    max_len = min(max_suffix, gap_idx)
    suffix_lengths = []
    for size in (max_len, 160, 120, 100, 80, 60, 40, 30, 20, 15, 10, 8, 5):
        if min_suffix <= size <= max_len and size not in suffix_lengths:
            suffix_lengths.append(size)

    for suffix_len in suffix_lengths:
        suffix = "".join(text[gap_idx - suffix_len:gap_idx])
        needle = suffix.replace("_", "")
        if not needle:
            continue
        match_positions = find_all_occurrences(ref_text, needle, 2)
        if len(match_positions) == 1:
            ref_pos = match_positions[0]
            return suffix, ref_pos + len(needle), ref_pos

    return None


def combined_probe_confirmed_prefix_len(text, ref_text, gap_idx, chunk, tail_lengths=(100, 80, 60, 40, 30, 20)):
    normalized_chunk = normalize_combined_probe_text(chunk)
    if not normalized_chunk:
        return 0

    normalized_ref = normalize_combined_probe_text(ref_text)
    for tail_len in tail_lengths:
        tail = normalize_combined_probe_text("".join(text[max(0, gap_idx - tail_len):gap_idx]))
        probe = tail + normalized_chunk
        if len(probe) < max(24, len(normalized_chunk) + 8):
            continue
        if len(find_all_occurrences(normalized_ref, probe, 2)) == 1:
            return len(chunk)

    return 0


def reference_confirmed_prefix_len(text, ref_text, gap_idx, chunk, max_suffix=200, min_suffix=20):
    if not chunk or gap_idx <= 0:
        return 0

    match = find_unique_ref_insert(text, ref_text, gap_idx, max_suffix, min_suffix)
    if match is None:
        return combined_probe_confirmed_prefix_len(text, ref_text, gap_idx, chunk)

    _, ref_pos, _ = match
    match_len = 0
    ref_offset = 0
    while match_len < len(chunk) and ref_pos + ref_offset < len(ref_text):
        char = chunk[match_len]
        if char in "_'":
            match_len += 1
            continue
        while ref_pos + ref_offset < len(ref_text) and ref_text[ref_pos + ref_offset] == "'":
            ref_offset += 1
            if ref_pos + ref_offset >= len(ref_text):
                break
        if ref_pos + ref_offset >= len(ref_text):
            break
        if char != ref_text[ref_pos + ref_offset]:
            return combined_probe_confirmed_prefix_len(text, ref_text, gap_idx, chunk)
        match_len += 1
        ref_offset += 1
    return match_len


def allow_relaxed_confirmation(suffix, chunk):
    normalized_suffix = suffix.replace("_", "").replace("'", "")
    return len(normalized_suffix) >= 180 and is_good_text(chunk)


def find_first_conflict(texts, xor12):
    for idx, (left, right) in enumerate(zip(texts[0], texts[1])):
        if not (is_known_char(left) and is_known_char(right)):
            continue
        if (ord(left) ^ ord(right)) != xor12[idx]:
            return idx
    return -1


def truncate_from_index(texts, start_idx):
    if start_idx < 0:
        return 0

    truncated = 0
    for text in texts:
        for pos in range(start_idx, len(text)):
            if text[pos] != "_":
                text[pos] = "_"
                truncated += 1
    return truncated


def rollback_frontier(texts, backtrack):
    frontiers = summarize_frontiers(texts)
    if any(frontier <= 0 for frontier in frontiers):
        return 0

    rollback_to = min(frontiers) - backtrack
    if rollback_to < 0:
        return 0

    return truncate_from_index(texts, rollback_to)


def find_recovery_backtrack(texts, refs, xor12, chunk_size, max_suffix, min_suffix, max_hits, max_backtrack=16):
    for backtrack in range(1, max_backtrack + 1):
        trial_texts = [list(texts[0]), list(texts[1])]
        changed = rollback_frontier(trial_texts, backtrack)
        if not changed:
            continue

        for side_idx in (0, 1):
            candidate = choose_candidate(
                trial_texts,
                refs,
                xor12,
                side_idx,
                chunk_size,
                max_suffix,
                min_suffix,
                max_hits,
            )
            if candidate is not None and len(candidate.chunk) > backtrack:
                return backtrack

            bridge = choose_reference_bridge(
                trial_texts,
                refs,
                xor12,
                side_idx,
                chunk_size,
                max(max_suffix, 200),
                max(min_suffix, 20),
            )
            if bridge is not None and len(bridge.chunk) > backtrack:
                return backtrack

    return 0


def fill_other_from_known(texts, xor12, refs):
    filled = 0

    left_frontier = find_unknown_start(texts[0])
    right_frontier = find_unknown_start(texts[1])
    if left_frontier < 0:
        left_frontier = len(texts[0])
    if right_frontier < 0:
        right_frontier = len(texts[1])

    if left_frontier < right_frontier:
        derived_chars = []
        for pos in range(left_frontier, right_frontier):
            right = texts[1][pos]
            if not is_known_char(right):
                break
            derived = xor12[pos] ^ ord(right)
            if not (is_printable_ascii(derived) and is_good_char(chr(derived))):
                break
            derived_chars.append(chr(derived))

        confirmed = reference_confirmed_prefix_len(
            texts[0],
            refs[0],
            left_frontier,
            "".join(derived_chars),
        )
        for rel_idx in range(confirmed):
            texts[0][left_frontier + rel_idx] = derived_chars[rel_idx]
        filled += confirmed
    elif right_frontier < left_frontier:
        derived_chars = []
        for pos in range(right_frontier, left_frontier):
            left = texts[0][pos]
            if not is_known_char(left):
                break
            derived = xor12[pos] ^ ord(left)
            if not (is_printable_ascii(derived) and is_good_char(chr(derived))):
                break
            derived_chars.append(chr(derived))

        confirmed = reference_confirmed_prefix_len(
            texts[1],
            refs[1],
            right_frontier,
            "".join(derived_chars),
        )
        for rel_idx in range(confirmed):
            texts[1][right_frontier + rel_idx] = derived_chars[rel_idx]
        filled += confirmed

    return filled


def find_frontier(text):
    return find_unknown_start(text)


def find_good_suffix(text, end_idx, max_len, min_len):
    start_idx = end_idx
    while start_idx >= 0 and is_good_char(text[start_idx]):
        start_idx -= 1
    suffix = "".join(text[start_idx + 1 : end_idx + 1])
    if len(suffix) > max_len:
        suffix = suffix[-max_len:]
    if len(suffix) < min_len:
        return ""
    return suffix


def find_all_occurrences(text, needle, max_hits):
    hits = []
    start = 0
    while len(hits) < max_hits:
        pos = text.find(needle, start)
        if pos < 0:
            break
        hits.append(pos)
        start = pos + 1
    return hits


def find_good_chunk_to_insert(text, start_idx, max_len):
    end_idx = start_idx
    while end_idx < len(text) and is_good_char(text[end_idx]) and end_idx - start_idx < max_len:
        end_idx += 1
    return text[start_idx:end_idx]


def iter_insert_starts(insert_start, text_len, max_adjust=8):
    yield insert_start, 0
    for adjust in range(1, max_adjust + 1):
        if insert_start + adjust < text_len:
            yield insert_start + adjust, adjust
        if insert_start - adjust >= 0:
            yield insert_start - adjust, adjust


def count_occurrences(text, needle, max_count=3):
    if not needle:
        return 0
    count = 0
    start = 0
    while count < max_count:
        pos = text.find(needle, start)
        if pos < 0:
            break
        count += 1
        start = pos + 1
    return count


def compatibility_bonus(other_text, other_ref, gap_idx, other_chunk, max_suffix):
    suffix = find_good_suffix(other_text, gap_idx - 1, max_suffix, 1)
    probe = (suffix + other_chunk[: min(16, len(other_chunk))]).strip()
    hits = count_occurrences(other_ref, probe)
    if hits == 1:
        return 40
    if hits > 1:
        return 10 - hits
    return 0


def derive_other_chunk(texts, side_idx, gap_idx, chunk, xor12):
    other_idx = 1 - side_idx
    other_chars = []
    usable = 0
    for rel_idx, char in enumerate(chunk):
        pos = gap_idx + rel_idx
        if pos >= len(xor12):
            break
        if texts[side_idx][pos] not in ("_", char):
            break
        derived = xor12[pos] ^ ord(char)
        if not is_printable_ascii(derived):
            break
        other_char = chr(derived)
        if texts[other_idx][pos] not in ("_", other_char):
            break
        other_chars.append(other_char)
        usable += 1
    return "".join(other_chars), usable


def choose_candidate(texts, refs, xor12, side_idx, chunk_size, max_suffix, min_suffix, max_hits):
    text = texts[side_idx]
    other_text = texts[1 - side_idx]
    ref_text = refs[side_idx]
    other_ref = refs[1 - side_idx]
    gap_idx = find_frontier(text)
    if gap_idx <= 0:
        return None

    suffix = find_good_suffix(text, gap_idx - 1, max_suffix, min_suffix)
    if not suffix:
        return None

    match_positions = find_all_occurrences(ref_text, suffix, max_hits)
    if not match_positions:
        return None

    best = None
    for ref_pos in match_positions:
        base_insert_start = ref_pos + len(suffix.replace("_", ""))
        for insert_start, adjust in iter_insert_starts(base_insert_start, len(ref_text)):
            chunk = find_good_chunk_to_insert(ref_text, insert_start, chunk_size)
            if not chunk:
                continue
            other_chunk, usable = derive_other_chunk(texts, side_idx, gap_idx, chunk, xor12)
            if usable <= 0:
                continue
            confirmed = reference_confirmed_prefix_len(
                other_text,
                other_ref,
                gap_idx,
                other_chunk,
                max(max_suffix, 200),
                max(min_suffix, 20),
            )
            if confirmed <= 0 and allow_relaxed_confirmation(suffix, other_chunk):
                confirmed = usable
            usable = min(usable, confirmed)
            if usable <= 0:
                continue
            chunk = chunk[:usable]
            other_chunk = other_chunk[:usable]
            if not is_good_text(chunk) or not is_good_text(other_chunk):
                continue
            score = usable * 100
            score -= adjust
            score += compatibility_bonus(other_text, other_ref, gap_idx, other_chunk, max_suffix)
            if best is None or score > best.score:
                best = Candidate(
                    side_idx=side_idx,
                    gap_idx=gap_idx,
                    suffix=suffix,
                    chunk=chunk,
                    other_chunk=other_chunk,
                    ref_pos=ref_pos,
                    score=score,
                    match_count=len(match_positions),
                )
    return best


def apply_candidate(texts, candidate):
    side_idx = candidate.side_idx
    other_idx = 1 - side_idx
    for rel_idx, char in enumerate(candidate.chunk):
        pos = candidate.gap_idx + rel_idx
        texts[side_idx][pos] = char
        texts[other_idx][pos] = candidate.other_chunk[rel_idx]


def choose_reference_bridge(texts, refs, xor12, side_idx, chunk_size, max_suffix, min_suffix):
    text = texts[side_idx]
    other_text = texts[1 - side_idx]
    ref_text = refs[side_idx]
    other_ref = refs[1 - side_idx]
    text_len = len(text)
    gap_idx = find_frontier(text)
    if gap_idx <= 0:
        return None

    match = find_unique_ref_insert(text, ref_text, gap_idx, max_suffix, min_suffix)
    if match is None:
        return None

    suffix, insert_start, ref_pos = match
    remaining = text_len - gap_idx
    if remaining <= 0:
        return None

    best = None
    for adjusted_start, _ in iter_insert_starts(insert_start, len(ref_text)):
        chunk = find_good_chunk_to_insert(ref_text, adjusted_start, chunk_size)
        chunk = chunk[:remaining]
        if not chunk or not is_good_text(chunk):
            continue

        other_chunk, usable = derive_other_chunk(texts, side_idx, gap_idx, chunk, xor12)
        if usable <= 0:
            continue

        confirmed = reference_confirmed_prefix_len(
            other_text,
            other_ref,
            gap_idx,
            other_chunk,
            max_suffix,
            min_suffix,
        )
        if confirmed <= 0 and allow_relaxed_confirmation(suffix, other_chunk):
            confirmed = usable
        usable = min(usable, confirmed)
        if usable <= 0:
            continue

        chunk = chunk[:usable]
        other_chunk = other_chunk[:usable]
        if not is_good_text(chunk) or not is_good_text(other_chunk):
            continue

        best = ReferenceBridge(
            side_idx=side_idx,
            gap_idx=gap_idx,
            suffix=suffix,
            chunk=chunk,
            other_chunk=other_chunk,
            ref_pos=ref_pos,
        )
        break

    return best


def apply_reference_bridge(texts, bridge):
    other_idx = 1 - bridge.side_idx
    for rel_idx, char in enumerate(bridge.chunk):
        pos = bridge.gap_idx + rel_idx
        texts[bridge.side_idx][pos] = char
        texts[other_idx][pos] = bridge.other_chunk[rel_idx]


def summarize_frontiers(texts):
    frontiers = []
    for text in texts:
        frontier = find_frontier(text)
        frontiers.append(frontier if frontier >= 0 else len(text))
    return frontiers


def parse_args():
    parser = argparse.ArgumentParser(description="Iterative K2 plaintext extension via book matching and XOR propagation.")
    parser.add_argument("--max-steps", type=int, default=100)
    parser.add_argument("--chunk-size", type=int, default=24)
    parser.add_argument("--max-suffix", type=int, default=20)
    parser.add_argument("--min-suffix", type=int, default=5)
    parser.add_argument("--max-hits", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    ct, _ = load_state(str(STATE_PATH))
    xor12 = bytes(left ^ right for left, right in zip(ct[0], ct[1]))
    texts, normalized = read_guess_file(GUESS_PATH, len(xor12))
    refs = load_reference_texts()

    initial_conflict_idx = find_first_conflict(texts, xor12)

    healed = []
    if initial_conflict_idx >= 0:
        healed = heal_texts_from_references(texts, refs)
    if healed:
        details = ", ".join(f"P{side_idx}:{healed_len}" for side_idx, healed_len in healed)
        print(f"healed corrupted tails from reference ({details})")
        if not args.dry_run:
            write_guess_file(GUESS_PATH, texts)

    if normalized:
        print("normalized plaintexts_guess.txt line lengths")
        if not args.dry_run:
            write_guess_file(GUESS_PATH, texts)

    conflict_idx = find_first_conflict(texts, xor12)
    if conflict_idx >= 0:
        truncated = truncate_from_index(texts, conflict_idx)
        print(f"truncated from first XOR conflict at {conflict_idx} ({truncated} chars reset)")
        if not args.dry_run:
            write_guess_file(GUESS_PATH, texts)

    filled = fill_other_from_known(texts, xor12, refs)
    if filled:
        print(f"backfilled {filled} chars from known plaintext")
        if not args.dry_run:
            write_guess_file(GUESS_PATH, texts)

    next_side = random.randrange(2)
    print(f"starting side: P{next_side + 1}")
    completed_steps = 0
    while completed_steps < args.max_steps:
        candidates = []
        for side_idx in (next_side, 1 - next_side):
            candidate = choose_candidate(
                texts,
                refs,
                xor12,
                side_idx,
                args.chunk_size,
                args.max_suffix,
                args.min_suffix,
                args.max_hits,
            )
            if candidate is not None:
                candidates.append(candidate)

        if not candidates:
            bridge = None
            for side_idx in (next_side, 1 - next_side):
                bridge = choose_reference_bridge(
                    texts,
                    refs,
                    xor12,
                    side_idx,
                    args.chunk_size,
                    max(args.max_suffix, 200),
                    max(args.min_suffix, 20),
                )
                if bridge is not None:
                    break

            if bridge is None:
                backtrack = find_recovery_backtrack(
                    texts,
                    refs,
                    xor12,
                    args.chunk_size,
                    args.max_suffix,
                    args.min_suffix,
                    args.max_hits,
                )
                if not backtrack:
                    break

                rolled_back = rollback_frontier(texts, backtrack)
                print(f"rolled back frontier by {backtrack} chars ({rolled_back} chars reset)")
                if not args.dry_run:
                    write_guess_file(GUESS_PATH, texts)
                continue

            apply_reference_bridge(texts, bridge)
            completed_steps += 1
            next_side = 1 - bridge.side_idx

            print(
                f"step {completed_steps}: bridged P{bridge.side_idx + 1} at {bridge.gap_idx} "
                f"by {len(bridge.chunk)} chars from XOR-confirmed reference match"
            )
            print(f"  suffix={bridge.suffix!r}")
            print(f"  inserted={bridge.chunk!r}")
            print(f"  xor->P{2 - bridge.side_idx}={bridge.other_chunk!r}")

            if not args.dry_run:
                write_guess_file(GUESS_PATH, texts)
            continue

        candidate = max(candidates, key=lambda item: item.score)
        apply_candidate(texts, candidate)
        completed_steps += 1
        next_side = 1 - candidate.side_idx

        print(
            f"step {completed_steps}: extended P{candidate.side_idx + 1} at {candidate.gap_idx} "
            f"by {len(candidate.chunk)} chars using {candidate.match_count} ref hits"
        )
        print(f"  suffix={candidate.suffix!r}")
        print(f"  inserted={candidate.chunk!r}")
        print(f"  xor->P{2 - candidate.side_idx}={candidate.other_chunk!r}")

        filled = fill_other_from_known(texts, xor12, refs)
        if filled:
            print(f"  backfilled extra {filled} chars from XOR")

        if not args.dry_run:
            write_guess_file(GUESS_PATH, texts)

    frontiers = summarize_frontiers(texts)
    print(f"frontiers: P1={frontiers[0]}, P2={frontiers[1]}")
    if args.dry_run:
        print("dry-run: plaintexts_guess.txt not modified")


if __name__ == "__main__":
    main()

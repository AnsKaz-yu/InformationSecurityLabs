from __future__ import annotations

import argparse
import string
import subprocess
import sys
from pathlib import Path

from help_methods import (
	crib_drag,
	generate_crib_drag_report,
	load_ciphertexts,
	parse_masks_two,
	parse_plaintexts,
	write_plaintexts_file,
	xor_bytes,
)


def _is_space_or_punct(ch: str) -> bool:
	return ch == " " or (len(ch) == 1 and ch in string.punctuation)


def _mask_allows_char(mask3_ch: str, mask4_ch: str, ch: str) -> bool:
	"""Check if a character is compatible with mask constraints at this position.

	Constraints are only enforced when the mask char is one of '#', '<', '>'.
	Other mask symbols (hex digits, '_', '&', '?', '|') are treated as 'no constraint'.
	"""
	if not ch:
		return False
	if ch == "\uFFFD":
		return False

	# Prefer mask4 (3-class) when it has a class symbol.
	if mask4_ch == "#":
		return _is_space_or_punct(ch)
	if mask4_ch == "<":
		return ch.isalpha() and ch.islower()
	if mask4_ch == ">":
		return ch.isalpha() and ch.isupper()

	# Fallback: mask3 (2-class)
	if mask3_ch == "#":
		return _is_space_or_punct(ch)
	if mask3_ch in {"<", ">"}:
		return ch.isalpha()

	return True


def _try_apply_fragment(
	*,
	plaintext_block: str,
	mask3_line: str,
	mask4_line: str,
	offset: int,
	fragment: str,
	unknown_char: str = "_",
) -> tuple[str, int] | None:
	"""Apply fragment into the FIRST line of a plaintext block.

	Returns (new_block, changed_count) or None if conflict / mask violation.
	"""
	lines = plaintext_block.split("\n")
	if not lines:
		return None

	base = lines[0]
	end = offset + len(fragment)
	if offset < 0:
		return None

	if len(base) < end:
		base = base.ljust(end, unknown_char)

	buf = list(base)
	changed = 0
	for i, ch in enumerate(fragment):
		pos = offset + i
		current = buf[pos]
		if current != unknown_char and current != ch:
			return None
		m3 = mask3_line[pos] if pos < len(mask3_line) else "_"
		m4 = mask4_line[pos] if pos < len(mask4_line) else "_"
		if not _mask_allows_char(m3, m4, ch):
			return None
		if current != ch:
			buf[pos] = ch
			changed += 1

	lines[0] = "".join(buf)
	return "\n".join(lines), changed


def _load_reference_texts(path: Path, *, expected_count: int) -> list[str]:
	if not path.exists():
		return []
	raw_lines = [ln.rstrip("\n") for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()]
	if expected_count <= 0:
		return []
	if not raw_lines:
		return [""] * expected_count
	if len(raw_lines) == expected_count:
		return raw_lines
	if len(raw_lines) % expected_count == 0:
		per_text = len(raw_lines) // expected_count
		grouped_votes = 0
		if per_text >= 2:
			for i in range(expected_count):
				second = raw_lines[i * per_text + 1] if (i * per_text + 1) < len(raw_lines) else ""
				first = raw_lines[i * per_text] if (i * per_text) < len(raw_lines) else ""
				if second.startswith("?") and not first.startswith("?"):
					grouped_votes += 1
			use_grouped = grouped_votes >= max(1, expected_count - 1)
		else:
			use_grouped = True
		groups: list[list[str]] = [[] for _ in range(expected_count)]
		if use_grouped:
			for i in range(expected_count):
				start = i * per_text
				groups[i] = raw_lines[start : start + per_text]
		else:
			for idx, line in enumerate(raw_lines):
				groups[idx % expected_count].append(line)
		return ["\n".join(g).rstrip("\n") for g in groups]
	groups = [[] for _ in range(expected_count)]
	for idx, line in enumerate(raw_lines):
		groups[idx % expected_count].append(line)
	return ["\n".join(g).rstrip("\n") for g in groups]


def main() -> None:
	parser = argparse.ArgumentParser(
		description=(
			"K3 crib-dragging: generate report and auto-insert selected found fragments into "
			"K3/plaintexts_guess copy.txt (only into '_' slots, mask-checked), then run K3/main.py."
		)
	)
	parser.add_argument(
		"--apply",
		action="store_true",
		help="(Compatibility) Auto-apply is ON by default; use --no-apply to disable",
	)
	parser.add_argument(
		"--no-apply",
		action="store_true",
		help="Only generate the report (no modifications)",
	)
	parser.add_argument(
		"--max-hits-per-crib",
		type=int,
		default=5,
		help="How many top hits per crib to consider per pair (default: 5)",
	)
	parser.add_argument(
		"--max-applied-cribs",
		type=int,
		default=20,
		help="Max number of (pair,crib,hit) applications (default: 20)",
	)
	args = parser.parse_args()

	auto_apply = not args.no_apply
	print("K3: crib-dragging отчёт" + (" + авто-вставка" if auto_apply else ""))

	default_task_path = Path("K3") / "2026_02_24_10_27_04_Анна_Казакевич_task.txt"
	ciphertexts = load_ciphertexts(default_task_path)
	common_len = min(len(c) for c in ciphertexts)

	cribs = [
		" the ",
		" and ",
		" to ",
		" of ",
		" in ",
		" that ",
		" you ",
		" for ",
		" with ",
		" is ",
	]

	out_path = Path("K3") / "crib_drag_report.txt"
	path = generate_crib_drag_report(
		ciphertexts=ciphertexts,
		common_len=common_len,
		out_path=out_path,
		cribs=cribs,
		min_printable_ratio=0.90,
		max_hits_per_crib=args.max_hits_per_crib,
	)
	print(f"Сохранено: {path}")

	if not auto_apply:
		return

	editable_path = Path("K3") / "plaintexts_guess copy.txt"
	if not editable_path.exists():
		raise FileNotFoundError(str(editable_path))

	plaintexts = parse_plaintexts(editable_path, expected_count=len(ciphertexts))
	m3, m4 = parse_masks_two(editable_path, expected_count=len(ciphertexts))
	ref_texts = _load_reference_texts(Path("K3") / "texts.txt", expected_count=len(ciphertexts))

	applied_events = 0
	changed_chars_total = 0

	for i in range(len(ciphertexts)):
		for j in range(i + 1, len(ciphertexts)):
			xored = xor_bytes(ciphertexts[i][:common_len], ciphertexts[j][:common_len])
			for crib in cribs:
				if applied_events >= args.max_applied_cribs:
					break
				hits = crib_drag(xored, crib, min_printable_ratio=0.90)
				if args.max_hits_per_crib > 0:
					hits = hits[: args.max_hits_per_crib]
				if not hits:
					continue

				# We assume crib is in Plaintext i, so the recovered fragment belongs to Plaintext j.
				for hit in hits:
					if applied_events >= args.max_applied_cribs:
						break
					offset = int(hit["offset"])
					fragment = str(hit["fragment_ascii"])
					if "\uFFFD" in fragment:
						continue
					applied = _try_apply_fragment(
						plaintext_block=plaintexts[j],
						mask3_line=m3[j],
						mask4_line=m4[j],
						offset=offset,
						fragment=fragment,
					)
					if applied is None:
						continue
					new_block, changed = applied
					if changed <= 0:
						continue
					plaintexts[j] = new_block
					applied_events += 1
					changed_chars_total += changed
					break

			if applied_events >= args.max_applied_cribs:
				break
		if applied_events >= args.max_applied_cribs:
			break

	if applied_events:
		write_plaintexts_file(
			editable_path,
			plaintexts,
			encoding="utf-8",
			masks=m3,
			masks2=m4,
			reference_texts=ref_texts,
		)
		print(f"Авто-вставка: events={applied_events} chars={changed_chars_total}")
		# Run main to propagate into key and plaintexts_guess.txt.
		print("Запуск K3/main.py для применения в ключ и обновления вывода...")
		subprocess.run([sys.executable, str(Path('K3') / 'main.py')], check=False)
	else:
		print("Авто-вставка: подходящих вставок не найдено (или все конфликтуют с масками/ручными символами)")


if __name__ == "__main__":
	main()

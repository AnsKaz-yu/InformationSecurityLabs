
from pathlib import Path
import sys

from help_methods import (
	apply_partial_key_to_all,
	load_ciphertexts,
	load_state,
	manual_char_to_byte,
	parse_masks_two,
	apply_manual_mask_overrides,
	merge_manual_mask_constraints,
	refine_mask_lines_with_manual_constraints,
	make_partial_key,
	parse_plaintexts,
	try_restore_plaintexts_from_state,
	save_key_history,
	save_state,
	apply_manual_plaintexts_to_key,
	write_manual_mismatch_report,
	write_star_triplet_options,
	write_plaintexts_file,
)


def _manual_char_to_byte_with_unicode_apostrophe(ch: str) -> int | None:
	# The source texts may use the right single quotation mark '’' (U+2019).
	# It must be treated as a distinct symbol (e.g. cp1251 byte 0x92),
	# i.e. do NOT normalize it to ASCII apostrophe.
	return manual_char_to_byte(ch)


def _load_mask_lines_txt(path: Path, *, expected_count: int) -> list[str]:
	if not path.exists():
		raise FileNotFoundError(str(path))
	# Keep raw lines; mask payloads should not contain spaces.
	lines = [ln.rstrip("\n") for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
	if len(lines) < expected_count:
		raise ValueError(f"Expected at least {expected_count} mask lines in {path}, got {len(lines)}")
	return lines[:expected_count]


def _load_reference_texts(path: Path, *, expected_count: int) -> list[str]:
	if not path.exists():
		return []
	# texts.txt can contain 1+ lines per text.
	# Common cases:
	# 1) Exactly one line per text: (t1, t2, ..., tn)
	# 2) Grouped blocks: (t1 line1..k, t2 line1..k, ..., tn line1..k)
	# 3) Interleaved rounds: (round1 t1..tn, round2 t1..tn, ...)
	raw_lines = [ln.rstrip("\n") for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()]
	lines = [ln for ln in raw_lines if ln.strip()]
	if expected_count <= 0:
		return []
	if not lines:
		return [""] * expected_count
	if len(lines) == expected_count:
		return lines

	if (len(lines) % expected_count) == 0:
		per_text = len(lines) // expected_count

		def build_grouped() -> list[str]:
			groups = [lines[i * per_text : (i + 1) * per_text] for i in range(expected_count)]
			return ["\n".join(g).rstrip("\n") for g in groups]

		def build_interleaved() -> list[str]:
			groups: list[list[str]] = [[] for _ in range(expected_count)]
			for idx, line in enumerate(lines):
				groups[idx % expected_count].append(line)
			return ["\n".join(g).rstrip("\n") for g in groups]

		def score(groups: list[str]) -> int:
			# Heuristic: often the 2nd line per text starts with '?' (very uncertain)
			# while the 1st line does not. Prefer the arrangement that matches this pattern.
			s = 0
			for item in groups:
				parts = item.splitlines()
				if len(parts) < 2:
					continue
				first = parts[0].lstrip()
				second = parts[1].lstrip()
				if second.startswith("?") and not first.startswith("?"):
					s += 1
				elif first.startswith("?") and not second.startswith("?"):
					s -= 1
			return s

		grouped = build_grouped()
		interleaved = build_interleaved()
		return grouped if score(grouped) >= score(interleaved) else interleaved

	# Fallback: round-robin assign lines.
	groups = [[] for _ in range(expected_count)]
	for idx, line in enumerate(lines):
		groups[idx % expected_count].append(line)
	return ["\n".join(g).rstrip("\n") for g in groups]


#
def go_main():
	print("K3: первичный анализ многократно использованного OTP (Вермам)")

	default_task_path = "2026_02_24_10_27_04_Анна_Казакевич_task.txt"
	task_path = default_task_path

	ciphertexts = load_ciphertexts(task_path)
	print(f"Найдено шифротекстов: {len(ciphertexts)}")

	common_len = min(len(c) for c in ciphertexts)
	print(f"Общая длина для анализа (min len): {common_len}")

	# Load mask3/mask4 (as produced by build_mask3.py / build_mask4.py)
	mask3_path =  Path("mask3_final_3.txt")
	mask4_path = Path("mask4_final_3.txt")
	try:
		base_mask3_lines = _load_mask_lines_txt(mask3_path, expected_count=len(ciphertexts))
		base_mask4_lines = _load_mask_lines_txt(mask4_path, expected_count=len(ciphertexts))
		print(f"mask3 загружена из: {mask3_path}")
		print(f"mask4 загружена из: {mask4_path}")
	except Exception as exc:
		print(f"Не удалось загрузить mask3/mask4 ({mask3_path.name}, {mask4_path.name}): {exc}")
		# Fallback: keep workflow usable even if mask files are missing.
		# IMPORTANT: do NOT mix with the legacy class_masks.txt here.
		base_mask3_lines = ["_" * len(c) for c in ciphertexts]
		base_mask4_lines = ["_" * len(c) for c in ciphertexts]

	state_path = Path("state.json")
	history_path =  Path("key_history.jsonl")
	prev_plaintexts = try_restore_plaintexts_from_state(state_path)

	# Key is stored in state.json and is updated incrementally from manual edits.
	# This allows '_' changes to clear key bytes and concrete changes to overwrite them.
	key: list[int | None]
	if state_path.exists():
		try:
			state = load_state(state_path)
			key_raw = state.get("key") or []
			key = [b if isinstance(b, int) else None for b in key_raw]
			if len(key) < common_len:
				key.extend([None] * (common_len - len(key)))
			else:
				key = key[:common_len]
			print("Ключ загружен из state.json и будет обновлён по ручным правкам")
		except Exception:
			key = make_partial_key(common_len)
			print("state.json прочитать не удалось — ключ начнётся пустым")
	else:
		key = make_partial_key(common_len)
		print("state.json не найден — ключ начнётся пустым")

	edited_plaintexts_path = Path("plaintexts_guess copy.txt")
	ref_texts = _load_reference_texts( Path("texts.txt"), expected_count=len(ciphertexts))
	manual_stats = None
	edited_plaintexts = None
	edited_masks3 = None
	edited_masks4 = None
	if edited_plaintexts_path.exists():
		try:
			edited_plaintexts = parse_plaintexts(edited_plaintexts_path, expected_count=len(ciphertexts))
			edited_masks3, edited_masks4 = parse_masks_two(
				edited_plaintexts_path,
				expected_count=len(ciphertexts),
			)
			manual_stats = apply_manual_plaintexts_to_key(
				ciphertexts=ciphertexts,
				manual_plaintexts=edited_plaintexts,
				key=key,
				common_len=common_len,
				prev_plaintexts=prev_plaintexts or None,
				char_to_byte=_manual_char_to_byte_with_unicode_apostrophe,
			)
			conflict_count = len(manual_stats.get("conflicts", []))
			clears = int(manual_stats.get("clears", 0) or 0)
			print(
				"2-й подход: применены ручные правки из plaintexts_guess copy.txt:",
				f"updates={manual_stats.get('updates')}",
				f"conflicts={conflict_count}",
				f"clears={clears}",
			)
		except Exception as exc:
			print(f"Не удалось применить ручные правки ({edited_plaintexts_path}): {exc}")
			edited_plaintexts = None
	else:
		print("Файл ручных правок не найден: plaintexts_guess copy.txt")

	guesses_from_key = apply_partial_key_to_all(ciphertexts, key, unknown_byte=ord("_"))

	# Manual mask overrides are stored in the editable copy file. They must be
	# independent from plaintext edits.
	if edited_masks3 is not None or edited_masks4 is not None:
		manual_mask3_overrides = apply_manual_mask_overrides(
			base_masks=base_mask3_lines,
			manual_masks=edited_masks3 or [],
		)
		manual_mask4_overrides = apply_manual_mask_overrides(
			base_masks=base_mask4_lines,
			manual_masks=edited_masks4 or [],
		)
	else:
		manual_mask3_overrides = list(base_mask3_lines)
		manual_mask4_overrides = list(base_mask4_lines)

	# Merge class constraints from both mask sets so edits in either one
	# refine both mask3 and mask4 consistently.
	constraint_masks = merge_manual_mask_constraints(manual_mask3_overrides, manual_mask4_overrides)

	mask3_lines_for_display = refine_mask_lines_with_manual_constraints(
		ciphertexts=ciphertexts,
		base_masks=base_mask3_lines,
		manual_masks=manual_mask3_overrides,
		constraint_masks=constraint_masks,
		mask_variant="mask3",
	)
	mask4_lines_for_display = refine_mask_lines_with_manual_constraints(
		ciphertexts=ciphertexts,
		base_masks=base_mask4_lines,
		manual_masks=manual_mask4_overrides,
		constraint_masks=constraint_masks,
		mask_variant="mask4",
	)

	# If the user placed '*' in the editable plaintexts, write all possible concrete
	# (p1,p2,p3) triples for those positions, consistent with current masks.
	if edited_plaintexts is not None:
		try:
			star_stats = write_star_triplet_options(
				ciphertexts=ciphertexts,
				manual_plaintexts=edited_plaintexts,
				mask3_lines=mask3_lines_for_display,
				mask4_lines=mask4_lines_for_display,
				common_len=common_len,
			)
			if star_stats.get("files"):
				print(
					"Сгенерированы варианты для '*' позиций:",
					f"files={star_stats.get('files')} dir={star_stats.get('out_dir')}",
				)
		except Exception as exc:
			print(f"Не удалось построить варианты для '*' позиций: {exc}")

	# Output plaintexts MUST follow the current key. We do not keep stale manual
	# overrides in the computed output; the editable copy is the place for editing.
	guessed_plaintexts = guesses_from_key

	# Build the next editable plaintexts from the key-derived guesses, so other
	# texts update immediately when key changes (including clears via '_').
	# If multiple plaintexts changed at the same position in one run, we keep only
	# the last changed one (consistent with conflict resolution).
	manual_snapshot_for_state: list[str] = []
	editable_plaintexts_bytes: list[bytes] | None = None
	if edited_plaintexts is not None:
		prev = prev_plaintexts or []
		bufs = [bytearray(pt) for pt in guesses_from_key]
		for pos in range(common_len):
			winner_text = None
			winner_ch = None
			for text_index, _cipher in enumerate(ciphertexts):
				if text_index >= len(edited_plaintexts):
					break
				new_text = edited_plaintexts[text_index]
				if pos >= len(new_text):
					continue
				prev_text = prev[text_index] if text_index < len(prev) else ""
				prev_ch = prev_text[pos] if pos < len(prev_text) else ""
				new_ch = new_text[pos]
				if prev_ch != new_ch:
					winner_text = text_index
					winner_ch = new_ch
			if winner_text is None:
				continue
			if winner_ch in {"_", "*"}:
				# Clear: key-derived guess already has '_' where key byte became None.
				continue
			plain_b = _manual_char_to_byte_with_unicode_apostrophe(winner_ch)
			if plain_b is None:
				continue
			if winner_text < len(bufs) and pos < len(bufs[winner_text]):
				bufs[winner_text][pos] = plain_b
		editable_plaintexts_bytes = [bytes(b) for b in bufs]
		manual_snapshot_for_state = [b.decode("cp1251", errors="replace") for b in editable_plaintexts_bytes]
	else:
		manual_snapshot_for_state = []

	# Sanity-check: the derived key MUST reproduce concrete manual characters from the
	# regenerated editable snapshot.
	if editable_plaintexts_bytes is not None:
		report_path, mismatch_count = write_manual_mismatch_report(
			ciphertexts=ciphertexts,
			manual_plaintexts=manual_snapshot_for_state,
			key=key,
			common_len=common_len,
			out_path= "manual_mismatch_report.txt",
			char_to_byte=_manual_char_to_byte_with_unicode_apostrophe,
		)
		if mismatch_count:
			print(f"Несовпадения manual vs key: {mismatch_count} (см. {report_path})")

	plaintexts_path = "plaintexts_guess.txt"
	write_plaintexts_file(
		plaintexts_path,
		guessed_plaintexts,
		encoding="cp1251",
		masks=mask3_lines_for_display,
		masks2=mask4_lines_for_display,
		reference_texts=ref_texts,
	)
	print(f"Черновики plaintext сохранены в: {plaintexts_path}")

	# Keep an editable copy with the same convenience masks underneath.
	# The editable copy is regenerated from the key, so all plaintexts stay consistent.
	if editable_plaintexts_bytes is not None:
		write_plaintexts_file(
			edited_plaintexts_path,
			editable_plaintexts_bytes,
			encoding="cp1251",
			masks=mask3_lines_for_display,
			masks2=mask4_lines_for_display,
			reference_texts=ref_texts,
		)
	else:
		# First run convenience: create the copy file alongside the guess.
		if not edited_plaintexts_path.exists():
			write_plaintexts_file(
				edited_plaintexts_path,
				guessed_plaintexts,
				encoding="cp1251",
				masks=mask3_lines_for_display,
				masks2=mask4_lines_for_display,
				reference_texts=ref_texts,
			)

	save_state(
		state_path,
		ciphertexts=ciphertexts,
		key=key,
		plaintexts=guessed_plaintexts,
		manual_plaintexts=manual_snapshot_for_state,
		meta={
			"task_path": str(task_path),
			"common_len": common_len,
			"manual_edits": manual_stats or {},
			"reports": {},
		},
	)
	print(f"Состояние сохранено в: {state_path}")

if __name__ == "__main__":
	go_main()
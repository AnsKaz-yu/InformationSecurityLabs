from __future__ import annotations

import base64
import json
import itertools
import re
import string

from collections import defaultdict, deque
from datetime import datetime
from itertools import combinations
from pathlib import Path
from typing import Callable, Iterable, Literal, Optional, Sequence


_HEADER_RE = re.compile(r"^\s*Шифр\s+(\d+)\s*(?:\(base64\))?\s*:\s*(.*)\s*$")
_HEADER_ONLY_RE = re.compile(r"^\s*Шифр\s+(\d+)\s*\(base64\)\s*:\s*$")
_BYTES_LITERAL_RE = re.compile(r"^\s*b([\"'])(.*)\1\s*$")


def load_ciphertexts(task_path: str | Path) -> list[bytes]:
	"""Load ciphertexts from a task text file.

	Supported formats:
	- Two-line blocks:
		Шифр 1 (base64):
		b'...'
	- One-line blocks:
		Шифр 1: b'...'
		Шифр 1: ...

	Returns ciphertexts as decoded bytes in the order they appear.
	"""
	path = Path(task_path)
	if not path.exists():
		raise FileNotFoundError(f"Task file not found: {path}")

	with path.open("r", encoding="utf-8") as file:
		raw_lines = [line.rstrip("\n") for line in file]

	ciphertexts: list[tuple[int, bytes]] = []

	index = 0
	while index < len(raw_lines):
		line = raw_lines[index].strip()
		index += 1
		if not line:
			continue

		match_inline = _HEADER_RE.match(line)
		if match_inline:
			number = int(match_inline.group(1))
			remainder = (match_inline.group(2) or "").strip()
			if remainder:
				b64_text = _extract_base64_payload(remainder)
				ciphertexts.append((number, base64.b64decode(b64_text)))
				continue

		match_header_only = _HEADER_ONLY_RE.match(line)
		if not match_header_only:
			continue

		number = int(match_header_only.group(1))

		# Next non-empty line should contain b'...'
		while index < len(raw_lines) and not raw_lines[index].strip():
			index += 1
		if index >= len(raw_lines):
			break

		data_line = raw_lines[index].strip()
		index += 1
		b64_text = _extract_base64_payload(data_line)
		ciphertexts.append((number, base64.b64decode(b64_text)))

	if not ciphertexts:
		raise ValueError("No ciphertext blocks found in the task file")

	# Keep stable order by appearance; numbering is useful but not enforced.
	ciphertexts.sort(key=lambda item: item[0])
	return [cipher for _, cipher in ciphertexts]


def _extract_base64_payload(text: str) -> str:
	text = text.strip()
	literal_match = _BYTES_LITERAL_RE.match(text)
	if literal_match:
		return literal_match.group(2)
	if text.startswith("b'") and text.endswith("'"):
		return text[2:-1]
	if text.startswith('b"') and text.endswith('"'):
		return text[2:-1]
	return text


def xor_bytes(left: bytes, right: bytes, *, truncate_to_min: bool = True) -> bytes:
	"""XOR two byte arrays element-wise.

	If truncate_to_min=True, XORs up to min(len(left), len(right)).
	Otherwise, requires equal length.
	"""
	if not truncate_to_min and len(left) != len(right):
		raise ValueError("xor_bytes requires equal-length inputs when truncate_to_min=False")
	return bytes(a ^ b for a, b in zip(left, right))



def try_restore_plaintexts_from_state(state_path: str | Path) -> list[str]:
	"""Best-effort load of previous *manual plaintexts* from state.json.

	We use this only to detect what the user changed between runs, to resolve
	manual conflicts by preferring the most recently changed symbol.
	"""
	path = Path(state_path)
	if not path.exists():
		return []
	try:
		state = load_state(path)
	except Exception:
		return []
	manual_plaintexts = state.get("manual_plaintexts") or []
	if isinstance(manual_plaintexts, list) and all(isinstance(x, str) for x in manual_plaintexts):
		return list(manual_plaintexts)
	return []


def generate_pairwise_xor_report(
	*,
	ciphertexts: Sequence[bytes],
	common_len: int,
	out_path: str | Path,
	chunk: int = 32,
) -> Path:
	"""Write pairwise XOR dump (C_i XOR C_j) to a txt file.

	Output includes hex and ASCII (non-printable -> '.').
	"""
	path = Path(out_path)

	def _xor_ascii(b: int) -> str:
		return chr(b) if 32 <= b <= 126 else "."

	lines: list[str] = []
	lines.append("Pairwise XOR of ciphertexts (C_i XOR C_j)")
	lines.append(f"ciphertexts={len(ciphertexts)} common_len={common_len}")
	lines.append("Format: offset: <hex bytes> |<ASCII>|  (non-printable -> '.')")
	lines.append("")

	for i in range(len(ciphertexts)):
		for j in range(i + 1, len(ciphertexts)):
			xored = xor_bytes(
				ciphertexts[i][:common_len],
				ciphertexts[j][:common_len],
				truncate_to_min=False,
			)
			lines.append(f"Pair C{i + 1} ^ C{j + 1} (len={len(xored)})")
			for offset in range(0, len(xored), chunk):
				block = xored[offset : offset + chunk]
				hex_part = " ".join(f"{b:02x}" for b in block)
				ascii_part = "".join(_xor_ascii(b) for b in block)
				lines.append(f"{offset:04x}: {hex_part:<{chunk * 3 - 1}} |{ascii_part}|")
			lines.append("")

	path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
	return path


# --- Ciphertext class masks (top-3-bits constraints) ---
# Corrected implementation provided by the user.
CLASS_SYMBOL = {
	1: "#",  # punctuation / space
	2: ">",  # uppercase
	3: "<",  # lowercase
}

CLASS_SYMBOL_INV = {v: k for k, v in CLASS_SYMBOL.items()}

ALLOWED = {1, 2, 3}


def top3bits(b: int) -> int:
	return (b >> 5) & 0b111


def top2bits(b: int) -> int:
	return (b >> 6) & 0b11


def solve_component_generic(
	nodes: list[int],
	edges: list[tuple[int, int, int]],
	*,
	allowed: set[int],
	fixed: dict[int, int] | None = None,
) -> list[dict[int, int]]:
	"""Solve connected component constraints for an arbitrary class set.

	nodes: list of vertices
	edges: list of (i, j, d) where class_i XOR class_j = d
	allowed: allowed class values
	fixed: optional {node: class} constraints
	Returns a list of valid assignments [{node: class}, ...]
	"""
	fixed = fixed or {}
	adj: dict[int, list[tuple[int, int]]] = defaultdict(list)
	for i, j, d in edges:
		adj[i].append((j, d))
		adj[j].append((i, d))

	root = nodes[0]
	valid_assignments: list[dict[int, int]] = []

	root_values = [fixed[root]] if root in fixed else list(allowed)
	for root_val in root_values:
		assign: dict[int, int] = {root: root_val}
		queue = deque([root])
		ok = True

		while queue and ok:
			u = queue.popleft()
			cu = assign[u]
			for v, d in adj[u]:
				expected = cu ^ d
				if expected not in allowed:
					ok = False
					break
				if v in fixed and fixed[v] != expected:
					ok = False
					break
				if v in assign:
					if assign[v] != expected:
						ok = False
						break
				else:
					assign[v] = expected
					queue.append(v)

		if ok:
			for node, node_val in fixed.items():
				if node in assign and assign[node] != node_val:
					ok = False
					break

		if ok:
			valid_assignments.append(assign)

	return valid_assignments


_MASK_ALLOWED_CHARS = set("#<>_|&?0123456789ABCDEF")
_MASK_LINE_RE_ANY = re.compile(r"^(?=.*[&#<>\|0-9A-F\?])[0-9A-F#<>_|&\?]{20,}$", re.IGNORECASE)


def _mask_char_to_class_mask3(sym: str) -> int | None:
	# mask3 model: 2 classes
	# - '#' : punctuation / space
	# - '<' or '>' : letter (case ignored)
	if sym == "#":
		return 0
	if sym in {"<", ">"}:
		return 1
	return None


def _mask_char_to_class_mask4(sym: str) -> int | None:
	return CLASS_SYMBOL_INV.get(sym)


def merge_manual_mask_constraints(mask3_lines: Sequence[str], mask4_lines: Sequence[str]) -> list[str]:
	"""Merge manual class constraints from both mask sets.

	At each position for each ciphertext:
	- Prefer a class symbol found in mask4 line; else take from mask3 line.
	- If neither has a class symbol, keep '_'.
	
	This makes edits in either mask line affect refinement of BOTH mask sets.
	"""
	count = max(len(mask3_lines), len(mask4_lines))
	out: list[str] = []
	for i in range(count):
		m3 = mask3_lines[i] if i < len(mask3_lines) else ""
		m4 = mask4_lines[i] if i < len(mask4_lines) else ""
		length = max(len(m3), len(m4))
		buf: list[str] = ["_"] * length
		for pos in range(length):
			s4 = m4[pos] if pos < len(m4) else "_"
			s3 = m3[pos] if pos < len(m3) else "_"
			if s4 in CLASS_SYMBOL_INV:
				buf[pos] = s4
			elif s3 in {"#", "<", ">"}:
				buf[pos] = s3
		out.append("".join(buf))
	return out


def refine_mask_lines_with_manual_constraints(
	*,
	ciphertexts: Sequence[bytes],
	base_masks: Sequence[str],
	manual_masks: Sequence[str],
	constraint_masks: Sequence[str],
	mask_variant: Literal["mask3", "mask4"],
) -> list[str]:
	"""Refine mask lines using manual class constraints and ciphertext-only XOR constraints.

	This is a generalized refinement used to support two mask sets:
	- mask3: 2-class model (punct/space vs letter) using top-2-bits XOR.
	- mask4: 3-class model (punct/space vs UPPER vs lower) using top-3-bits XOR.

	Output keeps the original base/manual characters and only replaces positions
	when refinement can force a class symbol ('#', '<', '>') or forced-equality ('|')
	(or '&' on equal ciphertext bytes).

	Edits in either mask line influence both sets via `constraint_masks`.
	"""
	n = len(ciphertexts)
	maxlen = max((len(c) for c in ciphertexts), default=0)

	# Start from manual masks so user edits are visible.
	out_masks: list[list[str]] = []
	manual_constraint_syms = set(CLASS_SYMBOL_INV.keys()) | {"#", "<", ">"}
	for i in range(n):
		base = base_masks[i] if i < len(base_masks) else ""  # may contain hex digits
		manual = manual_masks[i] if i < len(manual_masks) else ""
		length = len(ciphertexts[i])
		buf = list(base[:length])
		# Apply ONLY manual class constraints on top of base.
		# This keeps the editable file free to contain display helpers like '|' and '_'
		# without them being treated as persistent overrides.
		limit = min(len(buf), len(manual))
		for pos in range(limit):
			s = manual[pos]
			if s in manual_constraint_syms and s != buf[pos]:
				buf[pos] = s
		out_masks.append(buf)

	if mask_variant == "mask3":
		allowed = {0, 1}
		class_to_sym = {0: "#", 1: "<"}
		sym_to_class = _mask_char_to_class_mask3
		delta = top2bits
		valid_deltas = {0, 1}
	elif mask_variant == "mask4":
		allowed = set(ALLOWED)
		class_to_sym = dict(CLASS_SYMBOL)
		sym_to_class = _mask_char_to_class_mask4
		delta = top3bits
		valid_deltas = {0, 1, 2, 3}
	else:
		raise ValueError(f"Unknown mask_variant: {mask_variant!r}")

	for pos in range(maxlen):
		present = [i for i, c in enumerate(ciphertexts) if pos < len(c)]
		if not present:
			continue

		bytes_here = [ciphertexts[i][pos] for i in present]
		if all(b == bytes_here[0] for b in bytes_here):
			for i in present:
				out_masks[i][pos] = "&"
			continue

		fixed: dict[int, int] = {}
		for i in present:
			if i >= len(constraint_masks):
				continue
			cm = constraint_masks[i]
			if pos >= len(cm):
				continue
			cls = sym_to_class(cm[pos])
			if cls is not None:
				fixed[i] = cls

		edges: list[tuple[int, int, int]] = []
		for i, j in combinations(present, 2):
			x = ciphertexts[i][pos] ^ ciphertexts[j][pos]
			if x == 0:
				edges.append((i, j, 0))
			else:
				d = delta(x)
				if d in valid_deltas:
					edges.append((i, j, d))

		if not edges:
			continue

		graph: dict[int, set[int]] = defaultdict(set)
		for i, j, _d in edges:
			graph[i].add(j)
			graph[j].add(i)

		visited: set[int] = set()
		components: list[list[int]] = []
		for i in present:
			if i in visited:
				continue
			stack = [i]
			comp: list[int] = []
			visited.add(i)
			while stack:
				u = stack.pop()
				comp.append(u)
				for v in graph[u]:
					if v not in visited:
						visited.add(v)
						stack.append(v)
			components.append(comp)

		for comp in components:
			comp_edges = [(i, j, d) for (i, j, d) in edges if i in comp and j in comp]
			fixed_comp = {i: fixed[i] for i in comp if i in fixed}
			solutions = solve_component_generic(comp, comp_edges, allowed=allowed, fixed=fixed_comp)
			if not solutions:
				# Keep existing output characters (base/manual) if constraints are unsatisfiable.
				continue

			possible: dict[int, set[int]] = {i: set() for i in comp}
			for sol in solutions:
				for i in comp:
					possible[i].add(sol[i])

			for i in comp:
				# Do not override concrete user class symbols.
				if out_masks[i][pos] in {"#", "<", ">"}:
					continue
				if len(possible[i]) == 1:
					cls = next(iter(possible[i]))
					out_masks[i][pos] = class_to_sym[cls]

	return ["".join(m) for m in out_masks]


def solve_component(
	nodes: list[int],
	edges: list[tuple[int, int, int]],
	*,
	fixed: dict[int, int] | None = None,
):
	"""Solve connected component constraints.

	nodes: list of vertices
	edges: list of (i, j, d) where class_i XOR class_j = d
	fixed: optional {node: class} constraints (classes must be in ALLOWED)
	Returns a list of valid assignments [{node: class}, ...]
	"""
	fixed = fixed or {}
	adj: dict[int, list[tuple[int, int]]] = defaultdict(list)
	for i, j, d in edges:
		adj[i].append((j, d))
		adj[j].append((i, d))

	root = nodes[0]
	valid_assignments: list[dict[int, int]] = []

	root_values = [fixed[root]] if root in fixed else list(ALLOWED)
	for root_val in root_values:
		assign: dict[int, int] = {root: root_val}
		queue = deque([root])
		ok = True

		while queue and ok:
			u = queue.popleft()
			cu = assign[u]

			for v, d in adj[u]:
				expected = cu ^ d

				if expected not in ALLOWED:
					ok = False
					break

				if v in fixed and fixed[v] != expected:
					ok = False
					break

				if v in assign:
					if assign[v] != expected:
						ok = False
						break
				else:
					assign[v] = expected
					queue.append(v)

		if ok:
			# Verify all fixed nodes in this component match.
			for node, node_val in fixed.items():
				if node in assign and assign[node] != node_val:
					ok = False
					break

		if ok:
			valid_assignments.append(assign)

	return valid_assignments


def refine_class_masks_with_manual_plaintexts(
	*,
	ciphertexts: Sequence[bytes],
	manual_plaintexts: Sequence[str],
	mask_lines: Sequence[str],
	char_to_byte: Callable[[str], int | None] | None = None,
) -> list[str]:
	"""Refine class masks using ONLY manual plaintext edits as class constraints.

	We do NOT use derived key bytes or decrypted plaintext bytes.
	Each concrete manual character may imply an ASCII top-3-bits class (1..3).
	Those fixed class assignments are then propagated through the existing
	(ciphertext-only) XOR class constraints.

	If a manual character does not fall into our 3-class model, it's ignored
	for mask refinement.
	"""
	if char_to_byte is None:
		char_to_byte = manual_char_to_byte

	n = len(ciphertexts)
	maxlen = max((len(c) for c in ciphertexts), default=0)
	# Start from the existing ciphertext-only masks, but recompute per-position
	# to allow manual class constraints to reduce ambiguity.
	base_masks: list[list[str]] = []
	for i in range(n):
		base = mask_lines[i] if i < len(mask_lines) else "_" * len(ciphertexts[i])
		base_masks.append(list(base[: len(ciphertexts[i])]))

	for pos in range(maxlen):
		present = [i for i, c in enumerate(ciphertexts) if pos < len(c)]
		if not present:
			continue

		# Full match check (ciphertext bytes equal -> plaintext bytes equal).
		bytes_here = [ciphertexts[i][pos] for i in present]
		if all(b == bytes_here[0] for b in bytes_here):
			for i in present:
				base_masks[i][pos] = "&"
			continue

		# Fixed class constraints from manual edits at this position.
		fixed: dict[int, int] = {}
		for i in present:
			if i >= len(manual_plaintexts):
				continue
			manual_text = manual_plaintexts[i]
			if pos >= len(manual_text):
				continue
			ch = manual_text[pos]
			if ch == "_":
				continue
			pb = char_to_byte(ch)
			if pb is None:
				continue
			cls = top3bits(pb)
			if cls in ALLOWED:
				fixed[i] = cls

		# Build constraints based on ciphertext XOR (same as compute_mask).
		edges: list[tuple[int, int, int]] = []
		invalid_nodes: set[int] = set()
		for i, j in combinations(present, 2):
			x = ciphertexts[i][pos] ^ ciphertexts[j][pos]
			if x == 0:
				edges.append((i, j, 0))
			else:
				d = top3bits(x)
				if d in {0, 1, 2, 3}:
					edges.append((i, j, d))
				else:
					invalid_nodes.add(i)
					invalid_nodes.add(j)

		if not edges:
			for i in present:
				base_masks[i][pos] = "_"
			continue

		graph: dict[int, set[int]] = defaultdict(set)
		for i, j, _d in edges:
			graph[i].add(j)
			graph[j].add(i)

		visited: set[int] = set()
		components: list[list[int]] = []
		for i in present:
			if i in visited:
				continue
			stack = [i]
			comp: list[int] = []
			visited.add(i)
			while stack:
				u = stack.pop()
				comp.append(u)
				for v in graph[u]:
					if v not in visited:
						visited.add(v)
						stack.append(v)
			components.append(comp)

		for comp in components:
			comp_edges = [(i, j, d) for (i, j, d) in edges if i in comp and j in comp]
			fixed_comp = {i: fixed[i] for i in comp if i in fixed}
			solutions = solve_component(comp, comp_edges, fixed=fixed_comp)

			if not solutions:
				for i in comp:
					base_masks[i][pos] = "_"
				continue

			possible: dict[int, set[int]] = {i: set() for i in comp}
			for sol in solutions:
				for i in comp:
					possible[i].add(sol[i])

			forced_equal: set[int] = set()
			if len(comp) > 1:
				for i, j in combinations(comp, 2):
					diffs = {sol[i] ^ sol[j] for sol in solutions}
					if diffs == {0}:
						forced_equal.add(i)
						forced_equal.add(j)

			for i in comp:
				if len(possible[i]) == 1:
					cls = next(iter(possible[i]))
					base_masks[i][pos] = CLASS_SYMBOL[cls]
				elif i in forced_equal:
					base_masks[i][pos] = "|"
				else:
					base_masks[i][pos] = "_"

		for i in invalid_nodes:
			base_masks[i][pos] = "_"

	return ["".join(m) for m in base_masks]


def parse_masks(file_path: str | Path, *, expected_count: Optional[int] = None) -> list[str]:
	"""Parse mask lines from a TXT produced by write_plaintexts_file.

	Looks for blocks:
	- Mask N:
	  <mask-line>

	Returns a list of strings (one per ciphertext). Missing masks become "".

	Backward compatibility:
	- Older versions wrote the mask payload line directly under each plaintext
	  block without a "Mask N:" header. If no explicit mask blocks are found,
	  this parser will extract the last mask-looking line (only from the charset
	  '#', '>', '<', '_', '|', '&') from each plaintext block.
	"""
	path = Path(file_path)
	content = path.read_text(encoding="utf-8")
	lines = content.splitlines()

	mask_header_re = re.compile(r"^\s*Mask\s+(\d+)\s*:\s*$", re.IGNORECASE)
	plaintext_header_re = re.compile(r"^\s*Plaintext\s+(\d+)\s*:\s*$", re.IGNORECASE)
	# Require at least one non-'_' symbol to avoid treating a plaintext line of
	# all '_' as a mask.
	mask_line_re = re.compile(r"^(?=.*[#<>\|&])[#<>_|&]{20,}$")
	results: dict[int, str] = {}

	index = 0
	while index < len(lines):
		match_mask = mask_header_re.match(lines[index])
		index += 1
		if not match_mask:
			continue
		num = int(match_mask.group(1))
		# Next line (even empty) is the mask payload.
		payload = lines[index] if index < len(lines) else ""
		index += 1
		results[num - 1] = payload

	# Fallback: if no explicit Mask N: blocks were found, try extracting
	# bare mask lines that were written directly under plaintext blocks.
	if not results:
		current_num: Optional[int] = None
		current_lines: list[str] = []

		def flush_block() -> None:
			nonlocal current_num, current_lines
			if current_num is None:
				return
			# Take the last mask-looking line in the block.
			candidates = [ln.strip() for ln in current_lines if mask_line_re.fullmatch(ln.strip())]
			if candidates:
				results[current_num - 1] = candidates[-1]
			current_num = None
			current_lines = []

		for line in lines:
			m = plaintext_header_re.match(line)
			if m:
				flush_block()
				current_num = int(m.group(1))
				current_lines = []
				continue
			if current_num is not None:
				current_lines.append(line)
				# If blocks are separated by blank lines, we can flush early.
				if line.strip() == "":
					flush_block()
		flush_block()

	if expected_count is None:
		if not results:
			return []
		max_index = max(results.keys())
		count = max_index + 1
	else:
		count = expected_count

	out: list[str] = []
	for i in range(count):
		out.append(results.get(i, ""))
	return out


def parse_masks_two(
	file_path: str | Path,
	*,
	expected_count: Optional[int] = None,
) -> tuple[list[str], list[str]]:
	"""Parse TWO mask lines per plaintext block (mask3 line then mask4 line).

	The writer stores mask lines immediately under each plaintext, so we locate
	the last 2 mask-looking lines in each plaintext block.

	Returns (mask3_lines, mask4_lines). Missing lines become "".
	"""
	path = Path(file_path)
	content = path.read_text(encoding="utf-8")
	lines = content.splitlines()

	plaintext_header_re = re.compile(r"^\s*Plaintext\s+(\d+)\s*:\s*$", re.IGNORECASE)

	results3: dict[int, str] = {}
	results4: dict[int, str] = {}

	current_num: Optional[int] = None
	current_lines: list[str] = []

	def flush_block() -> None:
		nonlocal current_num, current_lines
		if current_num is None:
			return
		candidates = [ln.strip() for ln in current_lines if _MASK_LINE_RE_ANY.fullmatch(ln.strip())]
		if len(candidates) >= 2:
			results3[current_num - 1] = candidates[-2]
			results4[current_num - 1] = candidates[-1]
		elif len(candidates) == 1:
			# Backward compatibility: single mask line.
			only = candidates[-1]
			if re.search(r"[A-F4-9]", only, flags=re.IGNORECASE):
				results4[current_num - 1] = only
			else:
				results3[current_num - 1] = only
		current_num = None
		current_lines = []

	for line in lines:
		m = plaintext_header_re.match(line)
		if m:
			flush_block()
			current_num = int(m.group(1))
			current_lines = []
			continue
		if current_num is not None:
			current_lines.append(line)
	flush_block()

	if expected_count is None:
		if not (results3 or results4):
			return ([], [])
		max_index = max([*results3.keys(), *results4.keys()])
		count = max_index + 1
	else:
		count = expected_count

	out3: list[str] = []
	out4: list[str] = []
	for i in range(count):
		out3.append(results3.get(i, ""))
		out4.append(results4.get(i, ""))
	return out3, out4


def refine_class_masks_with_manual_masks(
	*,
	ciphertexts: Sequence[bytes],
	manual_masks: Sequence[str],
	mask_lines: Sequence[str],
) -> list[str]:
	"""Refine class masks using ONLY manual mask edits as class constraints.

	We DO NOT use derived key bytes or decrypted/plaintext bytes.
	Only the symbols in manual mask lines are used as constraints:
	- '#', '>', '<' fix the class (1..3) for that ciphertext at that position.
	- other symbols are treated as "no constraint".
	
	The constraints are then propagated through ciphertext-only XOR class edges.
	"""
	n = len(ciphertexts)
	maxlen = max((len(c) for c in ciphertexts), default=0)
	base_masks: list[list[str]] = []
	for i in range(n):
		base = mask_lines[i] if i < len(mask_lines) else "_" * len(ciphertexts[i])
		base_masks.append(list(base[: len(ciphertexts[i])]))

	for pos in range(maxlen):
		present = [i for i, c in enumerate(ciphertexts) if pos < len(c)]
		if not present:
			continue

		bytes_here = [ciphertexts[i][pos] for i in present]
		if all(b == bytes_here[0] for b in bytes_here):
			for i in present:
				base_masks[i][pos] = "&"
			continue

		fixed: dict[int, int] = {}
		for i in present:
			if i >= len(manual_masks):
				continue
			line = manual_masks[i]
			if pos >= len(line):
				continue
			sym = line[pos]
			# Only treat as a user constraint if it differs from the current
			# ciphertext-only mask at the same position.
			base_line = mask_lines[i] if i < len(mask_lines) else ""
			base_sym = base_line[pos] if pos < len(base_line) else "_"
			if sym == base_sym:
				continue
			cls = CLASS_SYMBOL_INV.get(sym)
			if cls is not None:
				fixed[i] = cls

		edges: list[tuple[int, int, int]] = []
		invalid_nodes: set[int] = set()
		for i, j in combinations(present, 2):
			x = ciphertexts[i][pos] ^ ciphertexts[j][pos]
			if x == 0:
				edges.append((i, j, 0))
			else:
				d = top3bits(x)
				if d in {0, 1, 2, 3}:
					edges.append((i, j, d))
				else:
					invalid_nodes.add(i)
					invalid_nodes.add(j)

		if not edges:
			for i in present:
				base_masks[i][pos] = "_"
			continue

		graph: dict[int, set[int]] = defaultdict(set)
		for i, j, _d in edges:
			graph[i].add(j)
			graph[j].add(i)

		visited: set[int] = set()
		components: list[list[int]] = []
		for i in present:
			if i in visited:
				continue
			stack = [i]
			comp: list[int] = []
			visited.add(i)
			while stack:
				u = stack.pop()
				comp.append(u)
				for v in graph[u]:
					if v not in visited:
						visited.add(v)
						stack.append(v)
			components.append(comp)

		for comp in components:
			comp_edges = [(i, j, d) for (i, j, d) in edges if i in comp and j in comp]
			fixed_comp = {i: fixed[i] for i in comp if i in fixed}
			solutions = solve_component(comp, comp_edges, fixed=fixed_comp)

			if not solutions:
				for i in comp:
					base_masks[i][pos] = "_"
				continue

			possible: dict[int, set[int]] = {i: set() for i in comp}
			for sol in solutions:
				for i in comp:
					possible[i].add(sol[i])

			forced_equal: set[int] = set()
			if len(comp) > 1:
				for i, j in combinations(comp, 2):
					diffs = {sol[i] ^ sol[j] for sol in solutions}
					if diffs == {0}:
						forced_equal.add(i)
						forced_equal.add(j)

			for i in comp:
				if len(possible[i]) == 1:
					cls = next(iter(possible[i]))
					base_masks[i][pos] = CLASS_SYMBOL[cls]
				elif i in forced_equal:
					base_masks[i][pos] = "|"
				else:
					base_masks[i][pos] = "_"

		for i in invalid_nodes:
			base_masks[i][pos] = "_"

	return ["".join(m) for m in base_masks]


def apply_manual_mask_overrides(
	*,
	base_masks: Sequence[str],
	manual_masks: Sequence[str],
) -> list[str]:
	"""Overlay manual-edited mask characters onto base masks.

	This is used to preserve user edits in `plaintexts_guess copy.txt` while
	keeping the baseline as the ciphertext-only computed mask.

	Rules:
	- Only explicit class constraint symbols are considered: '#', '<', '>'.
	  (Display helpers like '_' and '|' are ignored to avoid them becoming persistent overrides.)
	- A manual character is applied only if it differs from the base at that position.
	"""
	allowed = {"#", "<", ">"}
	out: list[str] = []
	count = max(len(base_masks), len(manual_masks))
	for i in range(count):
		base = base_masks[i] if i < len(base_masks) else ""
		manual = manual_masks[i] if i < len(manual_masks) else ""
		buf = list(base)
		limit = min(len(buf), len(manual))
		for pos in range(limit):
			sym = manual[pos]
			if sym not in allowed:
				continue
			if sym != buf[pos]:
				buf[pos] = sym
		out.append("".join(buf))
	return out


def compute_mask(ciphertexts: Sequence[bytes]) -> list[str]:
	n = len(ciphertexts)
	maxlen = max((len(c) for c in ciphertexts), default=0)
	masks: list[list[str]] = [list("_" * len(c)) for c in ciphertexts]

	for pos in range(maxlen):
		present = [i for i, c in enumerate(ciphertexts) if pos < len(c)]
		if not present:
			continue

		# Full match check
		bytes_here = [ciphertexts[i][pos] for i in present]
		if all(b == bytes_here[0] for b in bytes_here):
			for i in present:
				masks[i][pos] = "&"
			continue

		# Build constraints
		edges: list[tuple[int, int, int]] = []
		invalid_nodes: set[int] = set()
		for i, j in combinations(present, 2):
			x = ciphertexts[i][pos] ^ ciphertexts[j][pos]
			if x == 0:
				edges.append((i, j, 0))
			else:
				d = top3bits(x)
				if d in {0, 1, 2, 3}:
					edges.append((i, j, d))
				else:
					# This pair cannot be explained if BOTH symbols are in our 3 classes.
					# Mark both nodes as unsafe to classify at this position.
					invalid_nodes.add(i)
					invalid_nodes.add(j)

		# No constraints
		if not edges:
			for i in present:
				masks[i][pos] = "_"
			continue

		# Determine connected components
		graph: dict[int, set[int]] = defaultdict(set)
		for i, j, d in edges:
			graph[i].add(j)
			graph[j].add(i)

		visited: set[int] = set()
		components: list[list[int]] = []

		for i in present:
			if i in visited:
				continue
			stack = [i]
			comp: list[int] = []
			visited.add(i)
			while stack:
				u = stack.pop()
				comp.append(u)
				for v in graph[u]:
					if v not in visited:
						visited.add(v)
						stack.append(v)
			components.append(comp)

		# Process each component
		for comp in components:
			comp_edges = [(i, j, d) for (i, j, d) in edges if i in comp and j in comp]
			solutions = solve_component(comp, comp_edges)

			if not solutions:
				for i in comp:
					masks[i][pos] = "_"
				continue

			possible: dict[int, set[int]] = {i: set() for i in comp}
			for sol in solutions:
				for i in comp:
					possible[i].add(sol[i])

			# Determine which nodes are forced to be equal-by-class with someone else.
			# We mark '|' only when equality (xor=0) holds across ALL solutions.
			forced_equal: set[int] = set()
			if len(comp) > 1:
				for i, j in combinations(comp, 2):
					diffs = {sol[i] ^ sol[j] for sol in solutions}
					if diffs == {0}:
						forced_equal.add(i)
						forced_equal.add(j)

			for i in comp:
				if len(possible[i]) == 1:
					cls = next(iter(possible[i]))
					masks[i][pos] = CLASS_SYMBOL[cls]
				elif i in forced_equal:
					masks[i][pos] = "|"
				else:
					masks[i][pos] = "_"

		# Any node participating in an invalid pair is not reliably classifiable here.
		for i in invalid_nodes:
			masks[i][pos] = "_"

	return ["".join(m) for m in masks]


def compute_and_save_class_masks(
	ciphertexts: Sequence[bytes],
	out_mask_path: str | Path,
	out_json_path: str | Path | None = None,
):
	"""Compute class masks for ciphertexts and save them to a txt file.

	If out_json_path is provided, saves a small JSON metadata file.
	"""
	mask_lines = compute_mask(ciphertexts)

	out_mask_path = Path(out_mask_path)
	out_mask_path.parent.mkdir(parents=True, exist_ok=True)
	out_mask_path.write_text("\n".join(mask_lines) + "\n", encoding="utf-8")

	if out_json_path is not None:
		out_json_path = Path(out_json_path)
		out_json_path.parent.mkdir(parents=True, exist_ok=True)
		meta = {
			"ciphertexts": len(ciphertexts),
			"maxlen": max((len(c) for c in ciphertexts), default=0),
			"class_symbol": CLASS_SYMBOL,
			"allowed": sorted(ALLOWED),
		}
		out_json_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

	return mask_lines


def manual_char_to_byte(ch: str, *, encodings: Sequence[str] = ("cp1251", "latin-1")) -> int | None:
	"""Convert a single manual character into a plaintext byte constraint.

	- '_' means "unknown" -> None
	- Control chars are accepted (except newlines), because the OTP is byte-based.
	- ASCII is accepted
	- Otherwise tries single-byte encodings (cp1251, latin-1)
	"""
	if not ch:
		return None
	# Normalize some common punctuation to 1-byte equivalents.
	TRANSLATE = {
		"\u00A0": " ",  # NBSP
		"\u2010": "-",  # hyphen
		"\u2011": "-",  # non-breaking hyphen
		"\u2012": "-",
		"\u2013": "-",  # en dash
		"\u2014": "-",  # em dash
		"\u2212": "-",  # minus sign
		# NOTE: do NOT normalize smart quotes to ASCII.
		# In this lab the right single quotation mark '’' (U+2019) must be treated
		# as a distinct symbol with its own single-byte representation in cp1251.
	}
	ch = TRANSLATE.get(ch, ch)
	if ch == "_":
		return None
	if ch in ("\n", "\r"):
		return None
	if len(ch) != 1:
		return None
	code = ord(ch)
	if 0 <= code <= 0x7F:
		return code
	for encoding in encodings:
		try:
			raw = ch.encode(encoding)
		except UnicodeEncodeError:
			continue
		if len(raw) == 1:
			return raw[0]
	return None


def apply_manual_plaintexts_to_key(
	*,
	ciphertexts: Sequence[bytes],
	manual_plaintexts: Sequence[str],
	key: list[int | None],
	common_len: int,
	prev_plaintexts: Sequence[str] | None,
	char_to_byte: Callable[[str], int | None] = manual_char_to_byte,
) -> dict:
	"""Incrementally update a global partial key from manual plaintext edits.

	Rules (as requested):
	- We compare manual plaintexts to the previous manual snapshot from state.json.
	- If at position `pos` the user changed a symbol to '_' => key[pos] becomes None.
	- If at position `pos` the user changed a symbol to any other concrete character =>
	  key[pos] is recomputed from that symbol.
	- If multiple plaintexts changed at the same position in one run, the LAST changed
	  plaintext in file order wins (higher Plaintext index).
	"""
	updates = 0
	clears = 0
	conflicts: list[dict] = []

	prev_plaintexts = prev_plaintexts or []

	for pos in range(common_len):
		events: list[dict] = []
		for text_index, cipher in enumerate(ciphertexts):
			if text_index >= len(manual_plaintexts):
				break
			manual_text = manual_plaintexts[text_index]
			if pos >= len(manual_text) or pos >= len(cipher):
				continue

			prev_text = prev_plaintexts[text_index] if text_index < len(prev_plaintexts) else ""
			prev_ch = prev_text[pos] if pos < len(prev_text) else ""
			new_ch = manual_text[pos]
			changed = (prev_ch != new_ch)
			if not changed:
				continue

			if new_ch == "_":
				events.append({"text": text_index, "pos": pos, "type": "clear"})
				continue
			if new_ch == "*":
				# Query marker: does not affect key.
				continue

			plain_b = char_to_byte(new_ch)
			if plain_b is None:
				continue
			key_b = cipher[pos] ^ plain_b
			events.append(
				{
					"text": text_index,
					"pos": pos,
					"type": "set",
					"plain": plain_b,
					"key": key_b,
				}
			)

		if not events:
			continue

		# Detect same-position multi-change conflicts (informational).
		set_keys = {e["key"] for e in events if e["type"] == "set"}
		if len(set_keys) > 1:
			conflicts.append({"pos": pos, "events": events})

		chosen = events[-1]
		if chosen["type"] == "clear":
			if key[pos] is not None:
				clears += 1
			key[pos] = None
			continue

		new_key_byte = chosen["key"]
		if key[pos] != new_key_byte:
			key[pos] = new_key_byte
			updates += 1

	return {"common_len": common_len, "updates": updates, "clears": clears, "conflicts": conflicts}


def write_manual_mismatch_report(
	*,
	ciphertexts: Sequence[bytes],
	manual_plaintexts: Sequence[str],
	key: Sequence[int | None],
	common_len: int,
	out_path: str | Path,
	char_to_byte: Callable[[str], int | None] = manual_char_to_byte,
	max_rows: int = 500,
) -> tuple[Path, int]:
	"""Write a report of places where key does not reproduce manual non-'_' chars."""
	path = Path(out_path)

	def _byte_to_display(b: int) -> str:
		if b == ord("_"):
			return "_"
		if 32 <= b <= 126:
			return chr(b)
		for encoding in ("cp1251", "latin-1"):
			try:
				return bytes([b]).decode(encoding)
			except Exception:
				continue
		return f"\\x{b:02x}"

	mismatch_rows: list[str] = []
	for text_index, cipher in enumerate(ciphertexts):
		if text_index >= len(manual_plaintexts):
			break
		manual_text = manual_plaintexts[text_index]
		limit = min(common_len, len(manual_text), len(cipher))
		for pos in range(limit):
			ch = manual_text[pos]
			if ch in {"_", "*"}:
				continue
			manual_b = char_to_byte(ch)
			if manual_b is None:
				continue
			key_b = key[pos]
			if key_b is None:
				mismatch_rows.append(
					f"text={text_index + 1} pos={pos:>4} manual={ch!r}/{manual_b:02x} key=None dec=_"
				)
				continue
			dec_b = cipher[pos] ^ key_b
			if dec_b != manual_b:
				mismatch_rows.append(
					f"text={text_index + 1} pos={pos:>4} manual={ch!r}/{manual_b:02x}"
					f" key={key_b:02x} dec={_byte_to_display(dec_b)!r}/{dec_b:02x}"
				)

	lines: list[str] = []
	lines.append("Manual mismatch report (manual fixes vs derived key)")
	lines.append(f"ciphertexts={len(ciphertexts)} common_len={common_len}")
	lines.append("Rule: '_' is treated as unknown/mask and is NOT a key constraint.")
	lines.append("")
	if mismatch_rows:
		lines.append(f"Mismatches: {len(mismatch_rows)}")
		lines.extend(mismatch_rows[:max_rows])
		if len(mismatch_rows) > max_rows:
			lines.append("...")
	else:
		lines.append("Mismatches: 0")

	path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
	return path, len(mismatch_rows)


def _bin_prefix(value: int, prefix_len: int) -> str:
	return format(value, "08b")[:prefix_len]


def _xor_triplet_key(ciphertexts: Sequence[bytes], pos: int, prefix_len: int) -> str:
	if len(ciphertexts) != 3:
		raise ValueError("Expected exactly 3 ciphertexts")
	c1, c2, c3 = ciphertexts
	b1, b2, b3 = c1[pos], c2[pos], c3[pos]
	xor_ab = _bin_prefix(b1 ^ b2, prefix_len)
	xor_ac = _bin_prefix(b1 ^ b3, prefix_len)
	xor_bc = _bin_prefix(b2 ^ b3, prefix_len)
	return f"{xor_ab}|{xor_ac}|{xor_bc}"


def _allowed_classes_from_mask_chars(mask3_ch: str, mask4_ch: str) -> set[str]:
	"""Allowed class labels {' ', 'a', 'A'} based on mask symbols."""
	# mask4: '#' -> punct/space, '<' -> lowercase, '>' -> uppercase
	if mask4_ch == "#":
		return {" "}
	if mask4_ch == "<":
		return {"a"}
	if mask4_ch == ">":
		return {"A"}

	# mask3: '#' -> punct/space, '<' or '>' -> letter (either case)
	if mask3_ch == "#":
		return {" "}
	if mask3_ch in {"<", ">"}:
		return {"a", "A"}

	return {" ", "a", "A"}


def _space_punct_chars() -> list[str]:
	# Space class: literal space + punctuation.
	# Cached because it's used frequently for filtering.
	cache = getattr(_space_punct_chars, "_cache", None)
	if cache is not None:
		return cache  # type: ignore[return-value]
	chars = [" "] + list(string.punctuation)
	seen: set[str] = set()
	out: list[str] = []
	for ch in chars:
		if ch not in seen:
			out.append(ch)
			seen.add(ch)
	setattr(_space_punct_chars, "_cache", out)
	setattr(_space_punct_chars, "_cache_set", set(out))
	return out


def _class_chars(symbol: str) -> list[str]:
	if symbol == "a":
		return list(string.ascii_lowercase)
	if symbol == "A":
		return list(string.ascii_uppercase)
	if symbol == " ":
		return _space_punct_chars()
	raise ValueError(f"Unknown class symbol: {symbol!r}")


def _char_to_class(ch: str) -> str | None:
	if len(ch) != 1:
		return None
	if ch in string.ascii_lowercase:
		return "a"
	if ch in string.ascii_uppercase:
		return "A"
	cache_set = getattr(_space_punct_chars, "_cache_set", None)
	if cache_set is None:
		_space_punct_chars()
		cache_set = getattr(_space_punct_chars, "_cache_set", set())
	if ch == " " or ch in cache_set:
		return " "
	return None


def _iter_star_positions(manual_plaintexts: Sequence[str], *, common_len: int) -> list[int]:
	positions: set[int] = set()
	for text in manual_plaintexts:
		limit = min(common_len, len(text))
		for pos in range(limit):
			if text[pos] == "*":
				positions.add(pos)
	return sorted(positions)


def write_star_triplet_options(
	*,
	ciphertexts: Sequence[bytes],
	manual_plaintexts: Sequence[str],
	mask3_lines: Sequence[str],
	mask4_lines: Sequence[str],
	common_len: int,
	xor_maps4_path: str | Path = Path("K3") / "xor_maps4.json",
	out_dir: str | Path = Path("K3") / "star_triplets",
) -> dict:
	"""For each position marked with '*' in manual plaintexts, write all possible
	concrete triples (p1,p2,p3) that are mutually consistent.

	Mutual consistency means there exists a single key byte k such that:
		k = c1[pos] ^ p1 = c2[pos] ^ p2 = c3[pos] ^ p3
	And each pi belongs to the class allowed by the current masks.

	Output: JSONL files, each line is [ch1, ch2, ch3].
	"""
	star_positions = _iter_star_positions(manual_plaintexts, common_len=common_len)
	if not star_positions:
		return {"positions": 0, "files": 0}

	xor_maps4_path = Path(xor_maps4_path)
	data = json.loads(xor_maps4_path.read_text(encoding="utf-8"))
	prefix_len = int(data.get("bin_prefix_len", 3))
	mapping = data.get("xor_triplet_to_triples")
	if not isinstance(mapping, dict):
		mapping = {}

	out_dir = Path(out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)

	index: dict[str, dict[str, object]] = {}
	written = 0

	for pos in star_positions:
		if pos >= common_len:
			continue
		if any(pos >= len(c) for c in ciphertexts):
			continue

		xor_key = _xor_triplet_key(ciphertexts, pos, prefix_len)
		xor_id = "?"
		entry = mapping.get(xor_key)
		if isinstance(entry, dict) and isinstance(entry.get("id"), str):
			xor_id = entry["id"]

		allowed_classes: list[set[str]] = []
		for i in range(3):
			m3 = mask3_lines[i] if i < len(mask3_lines) else ""
			m4 = mask4_lines[i] if i < len(mask4_lines) else ""
			m3_ch = m3[pos] if pos < len(m3) else "_"
			m4_ch = m4[pos] if pos < len(m4) else "_"
			allowed_classes.append(_allowed_classes_from_mask_chars(m3_ch, m4_ch))

		# Build per-text concrete byte pools from allowed classes.
		pools_b: list[list[int]] = []
		pools_set: list[set[int]] = []
		for cls_set in allowed_classes:
			chars: list[str] = []
			for cls in (" ", "a", "A"):
				if cls in cls_set:
					chars.extend(_class_chars(cls))
			# convert to bytes (ASCII only here)
			b_list: list[int] = []
			seen_b: set[int] = set()
			for ch in chars:
				b = ord(ch)
				if b not in seen_b:
					b_list.append(b)
					seen_b.add(b)
			pools_b.append(b_list)
			pools_set.append(seen_b)

		c1, c2, c3 = ciphertexts[0][pos], ciphertexts[1][pos], ciphertexts[2][pos]

		# Enumerate mutually consistent triples efficiently:
		# for each possible p1, key byte is determined, hence p2 and p3 are determined.
		results: list[tuple[int, int, int]] = []
		for p1 in pools_b[0]:
			k = c1 ^ p1
			p2 = c2 ^ k
			if p2 not in pools_set[1]:
				continue
			p3 = c3 ^ k
			if p3 not in pools_set[2]:
				continue
			results.append((p1, p2, p3))

		out_path = out_dir / f"pos.jsonl"
		with out_path.open("w", encoding="utf-8") as f:
			for p1, p2, p3 in results:
				f.write(json.dumps([chr(p1), chr(p2), chr(p3)], ensure_ascii=False) + "\n")

		index[str(pos)] = {
			"pos": pos,
			"xor_key": xor_key,
			"id": xor_id,
			"file": out_path.name,
			"count": len(results),
			"allowed_classes": [sorted(s) for s in allowed_classes],
			"status": "ok",
		}
		written += 1

	(out_dir / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")

	return {"positions": len(star_positions), "files": written, "out_dir": str(out_dir)}


def overlay_manual_plaintexts_on_guesses(
	*,
	guessed_plaintexts: Sequence[bytes],
	ciphertexts: Sequence[bytes],
	manual_plaintexts: Sequence[str],
	common_len: int,
	char_to_byte: Callable[[str], int | None] = manual_char_to_byte,
	underscore_policy: Literal["mask", "ignore"] = "mask",
) -> tuple[list[bytes], dict]:
	"""Overlay manual plaintext chars onto the guessed plaintext bytes.

	- Concrete chars override output bytes.
	- '_' can optionally act as a display mask: forces '_' in output but does not constrain key.
	"""
	merged: list[bytes] = []
	applied = 0
	mismatches = 0

	for text_index, pt in enumerate(guessed_plaintexts):
		buf = bytearray(pt)
		if text_index < len(manual_plaintexts):
			manual_text = manual_plaintexts[text_index]
			limit = min(common_len, len(manual_text), len(buf), len(ciphertexts[text_index]))
			for pos in range(limit):
				ch = manual_text[pos]
				if ch == "_":
					if underscore_policy == "mask":
						if buf[pos] != ord("_"):
							mismatches += 1
						buf[pos] = ord("_")
						applied += 1
					continue
				manual_b = char_to_byte(ch)
				if manual_b is None:
					continue
				if buf[pos] != manual_b:
					mismatches += 1
				buf[pos] = manual_b
				applied += 1
		merged.append(bytes(buf))

	return merged, {"applied": applied, "mismatches": mismatches}


def refine_class_masks_with_key(
	*,
	ciphertexts: Sequence[bytes],
	key: Sequence[int | None],
	mask_lines: Sequence[str],
) -> list[str]:
	"""Deprecated: do not refine masks from decrypted plaintext.

	Kept for backward compatibility, but intentionally returns the original
	(ciphertext-only) masks without looking at the key.
	"""
	_ = (ciphertexts, key)
	return list(mask_lines)


def decrypt_with_key(ciphertext: bytes, key: bytes) -> bytes:
	"""Decrypt OTP/Vernam ciphertext with a full known key of the same length."""
	if len(ciphertext) != len(key):
		raise ValueError("decrypt_with_key requires key to be the same length as ciphertext")
	return xor_bytes(ciphertext, key, truncate_to_min=False)


def apply_key_to_all(ciphertexts: Sequence[bytes], key: bytes) -> list[bytes]:
	return [decrypt_with_key(ciphertext, key) for ciphertext in ciphertexts]


def make_partial_key(length: int) -> list[Optional[int]]:
	return [None] * length


def apply_partial_key(ciphertext: bytes, key: Sequence[Optional[int]], *, unknown_byte: int = ord("_")) -> bytes:
	"""Apply a partial key (with None values) to ciphertext.

	Known positions decrypt, unknown positions become `unknown_byte`.
	"""
	output = bytearray()
	limit = min(len(ciphertext), len(key))
	for index in range(limit):
		key_byte = key[index]
		output.append((ciphertext[index] ^ key_byte) if key_byte is not None else unknown_byte)
	if len(ciphertext) > limit:
		output.extend([unknown_byte] * (len(ciphertext) - limit))
	return bytes(output)


def apply_partial_key_to_all(
	ciphertexts: Sequence[bytes],
	key: Sequence[Optional[int]],
	*,
	unknown_byte: int = ord("_"),
) -> list[bytes]:
	return [apply_partial_key(ciphertext, key, unknown_byte=unknown_byte) for ciphertext in ciphertexts]


def _is_ascii_letter(byte_value: int) -> bool:
	return 65 <= byte_value <= 90 or 97 <= byte_value <= 122


def _is_ascii_printable(byte_value: int) -> bool:
	return 32 <= byte_value <= 126


def _is_common_punct_or_digit(byte_value: int) -> bool:
	return (
		48 <= byte_value <= 57
		or 33 <= byte_value <= 47
		or 58 <= byte_value <= 64
		or 91 <= byte_value <= 96
		or 123 <= byte_value <= 126
	)


def guess_space_positions(
	ciphertexts: Sequence[bytes],
	key: Optional[list[Optional[int]]] = None,
	plaintexts: Optional[list[bytearray]] = None,
	*,
	unknown_byte: int = ord("_"),
	min_votes: Optional[int] = None,
) -> tuple[list[Optional[int]], list[bytearray], dict]:
	"""Heuristic: guess spaces across multiple OTP-reused ciphertexts.

	For each position i and each text j we count how many pairwise XORs
	(cj[i] ^ ck[i]) look like an ASCII letter. If many votes, we assume
	plaintext[j][i] == space (0x20), and thus key[i] = cj[i] ^ 0x20.
	"""
	if len(ciphertexts) < 2:
		raise ValueError("Need at least 2 ciphertexts for space-guessing")

	common_len = min(len(ciphertext) for ciphertext in ciphertexts)
	if key is None:
		key = make_partial_key(common_len)
	if len(key) < common_len:
		key.extend([None] * (common_len - len(key)))

	if plaintexts is None:
		plaintexts = [bytearray([unknown_byte] * common_len) for _ in ciphertexts]
	else:
		for index in range(len(plaintexts)):
			if len(plaintexts[index]) < common_len:
				plaintexts[index].extend([unknown_byte] * (common_len - len(plaintexts[index])))

	n = len(ciphertexts)
	required_votes = min_votes
	if required_votes is None:
		# For n=3 => 2 votes; for larger n => ~60% of other texts.
		required_votes = max(2, int((n - 1) * 0.6 + 0.999))

	votes_per_text = [0] * n
	decided_positions = 0

	for pos in range(common_len):
		for j in range(n):
			if plaintexts[j][pos] != unknown_byte:
				continue

			votes = 0
			cj = ciphertexts[j][pos]
			for k in range(n):
				if k == j:
					continue
				x = cj ^ ciphertexts[k][pos]
				if _is_ascii_letter(x):
					votes += 1

			if votes >= required_votes:
				plaintexts[j][pos] = 0x20
				key[pos] = cj ^ 0x20
				votes_per_text[j] += 1
				decided_positions += 1

	hints = {
		"common_len": common_len,
		"required_votes": required_votes,
		"spaces_per_text": votes_per_text,
		"decided_positions": decided_positions,
	}
	return key, plaintexts, hints


def guess_punctuation_positions(
	ciphertexts: Sequence[bytes],
	*,
	common_len: Optional[int] = None,
) -> dict:
	"""Loose heuristic: positions where many pairwise XORs look like digits/punct.

	Returns a dict with counts per position.
	"""
	if len(ciphertexts) < 2:
		return {"common_len": 0, "punct_counts": []}

	if common_len is None:
		common_len = min(len(ciphertext) for ciphertext in ciphertexts)

	counts = [0] * common_len
	for i in range(common_len):
		for a in range(len(ciphertexts)):
			for b in range(a + 1, len(ciphertexts)):
				x = ciphertexts[a][i] ^ ciphertexts[b][i]
				if _is_common_punct_or_digit(x):
					counts[i] += 1

	return {
		"common_len": common_len,
		"punct_counts": counts,
	}


def suggest_punctuation_chars(
	ciphertexts: Sequence[bytes],
	*,
	key: Optional[Sequence[Optional[int]]] = None,
	punctuation: str = ".,!-?",
	common_len: Optional[int] = None,
	min_support_ratio: float = 0.75,
	max_suggestions: int = 200,
) -> dict:
	"""Suggest positions where plaintext may contain specific punctuation.

	This does NOT modify the key. It produces a report-friendly structure with:
	- confirmed: positions where the current key already decrypts to one of punctuation chars
	- suggestions: heuristic candidates for positions (even if key byte is unknown)

	Heuristic: assume some text j has punctuation char p at pos i, derive candidate key byte,
	then count how many texts decrypt to a "reasonable" ASCII byte at that position.
	"""
	if len(ciphertexts) < 2:
		return {"common_len": 0, "punctuation": punctuation, "confirmed": [], "suggestions": []}

	if common_len is None:
		common_len = min(len(ciphertext) for ciphertext in ciphertexts)

	punct_bytes = [ord(ch) for ch in punctuation]

	n = len(ciphertexts)
	other_count = max(0, n - 1)
	required_other_support = max(1, int(other_count * min_support_ratio + 0.999))

	def is_other_reasonable(byte_value: int) -> bool:
		# Stricter than "printable": we want mostly text-ish bytes.
		if byte_value == 32:
			return True
		if _is_ascii_letter(byte_value):
			return True
		if 48 <= byte_value <= 57:
			return True
		return False

	confirmed: list[dict] = []
	suggestions: list[dict] = []

	key_list: list[Optional[int]]
	if key is None:
		key_list = [None] * common_len
	else:
		key_list = list(key) + [None] * max(0, common_len - len(key))
		key_list = key_list[:common_len]

	# Confirmed punctuation based on existing key bytes.
	for pos in range(common_len):
		kb = key_list[pos]
		if kb is None:
			continue
		for text_index, ciphertext in enumerate(ciphertexts):
			plain_byte = ciphertext[pos] ^ kb
			if plain_byte in punct_bytes:
				confirmed.append(
					{
						"pos": pos,
						"text": text_index,
						"char": chr(plain_byte),
						"key_known": True,
					}
				)

	# Heuristic suggestions (include positions even if key is known).
	for pos in range(common_len):
		kb_existing = key_list[pos]
		for text_index, ciphertext in enumerate(ciphertexts):
			for pb in punct_bytes:
				candidate_kb = ciphertext[pos] ^ pb
				other_support = 0
				for other_index, other_cipher in enumerate(ciphertexts):
					if other_index == text_index:
						continue
					plain_byte = other_cipher[pos] ^ candidate_kb
					if is_other_reasonable(plain_byte):
						other_support += 1
				conflict = kb_existing is not None and kb_existing != candidate_kb
				if other_support < required_other_support:
					continue
				suggestions.append(
					{
						"pos": pos,
						"text": text_index,
						"char": chr(pb),
						"support": other_support,
						"required_support": required_other_support,
						"conflict_with_known_key": conflict,
					}
				)

	# Sort best-first; keep the list bounded.
	suggestions.sort(key=lambda item: (-item["support"], item["conflict_with_known_key"], item["pos"], item["text"]))
	if max_suggestions > 0:
		suggestions = suggestions[:max_suggestions]

	return {
		"common_len": common_len,
		"punctuation": punctuation,
		"min_support_ratio": min_support_ratio,
		"confirmed": confirmed,
		"suggestions": suggestions,
	}


def crib_drag(
	xored_plaintexts: bytes,
	guess: str | bytes,
	*,
	encoding: str = "ascii",
	min_printable_ratio: float = 0.85,
) -> list[dict]:
	"""Classic crib-dragging helper.

	Given xored_plaintexts = m1 ^ m2 and a guess (crib) for m1 at some offset,
	we compute candidate fragment of m2.
	"""
	if isinstance(guess, str):
		guess_bytes = guess.encode(encoding, errors="strict")
	else:
		guess_bytes = bytes(guess)

	if not guess_bytes:
		return []

	results: list[dict] = []
	for offset in range(0, max(0, len(xored_plaintexts) - len(guess_bytes) + 1)):
		fragment = xor_bytes(xored_plaintexts[offset:offset + len(guess_bytes)], guess_bytes)
		printable = sum(1 for b in fragment if _is_ascii_printable(b) or b in (10, 13, 9))
		ratio = printable / len(fragment)
		if ratio < min_printable_ratio:
			continue

		results.append(
			{
				"offset": offset,
				"fragment_bytes": fragment,
				"fragment_ascii": fragment.decode("ascii", errors="replace"),
				"printable_ratio": ratio,
			}
		)

	results.sort(key=lambda item: (-item["printable_ratio"], item["offset"]))
	return results


def generate_crib_drag_report(
	*,
	ciphertexts: Sequence[bytes],
	common_len: int,
	out_path: str | Path,
	cribs: Sequence[str],
	min_printable_ratio: float = 0.90,
	max_hits_per_crib: int = 5,
) -> Path:
	"""Generate a crib-dragging report file.

	This does not modify the key; it only writes analysis output.
	"""
	path = Path(out_path)
	lines: list[str] = []
	lines.append("Crib-dragging report (OTP reuse / multi-time pad)")
	lines.append(f"ciphertexts={len(ciphertexts)} common_len={common_len}")
	lines.append("")
	for i in range(len(ciphertexts)):
		for j in range(i + 1, len(ciphertexts)):
			xored = xor_bytes(ciphertexts[i][:common_len], ciphertexts[j][:common_len])
			any_for_pair = False
			for crib in cribs:
				hits = crib_drag(xored, crib, min_printable_ratio=min_printable_ratio)
				if max_hits_per_crib > 0:
					hits = hits[:max_hits_per_crib]
				if not hits:
					continue
				if not any_for_pair:
					lines.append(f"Pair Plaintext {i + 1} ^ Plaintext {j + 1}")
					any_for_pair = True
				lines.append(f"  crib={crib!r} (assuming it is in Plaintext {i + 1})")
				for hit in hits:
					lines.append(f"    offset={hit['offset']:>4}: {hit['fragment_ascii']}")
			if any_for_pair:
				lines.append("")
	path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
	return path


def generate_punctuation_report(
	*,
	ciphertexts: Sequence[bytes],
	key: Sequence[Optional[int]] | None,
	common_len: int,
	out_path: str | Path,
	punctuation: str = ".,!-?",
	max_items: int = 200,
) -> Path:
	"""Generate a punctuation report file using suggest_punctuation_chars()."""
	path = Path(out_path)
	report = suggest_punctuation_chars(ciphertexts, key=key, punctuation=punctuation, common_len=common_len)
	lines: list[str] = []
	lines.append(f"Punctuation report for chars: {punctuation}")
	lines.append(f"ciphertexts={len(ciphertexts)} common_len={common_len}")
	lines.append(f"min_support_ratio={report.get('min_support_ratio')}")
	lines.append("")

	confirmed = report.get("confirmed", [])
	lines.append(f"Confirmed with current key: {len(confirmed)}")
	for item in confirmed[:max_items]:
		lines.append(f"  pos={item['pos']:>4} text={item['text'] + 1}: {item['char']}")
	if len(confirmed) > max_items:
		lines.append("  ...")
	lines.append("")

	suggestions = report.get("suggestions", [])
	lines.append(f"Heuristic suggestions: {len(suggestions)} (showing up to {max_items})")
	for item in suggestions[:max_items]:
		conflict = "CONFLICT" if item.get("conflict_with_known_key") else "ok"
		lines.append(
			f"  pos={item['pos']:>4} text={item['text'] + 1} char={item['char']!r}"
			f" support={item['support']}/{item['required_support']} key={conflict}"
		)
	if len(suggestions) > max_items:
		lines.append("  ...")

	path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
	return path


def save_state(
	state_path: str | Path,
	*,
	ciphertexts: Sequence[bytes],
	key: Sequence[Optional[int]],
	plaintexts: Optional[Sequence[bytes | bytearray]] = None,
	manual_plaintexts: Optional[Sequence[str]] = None,
	meta: Optional[dict] = None,
) -> None:
	"""Save current cracking state to JSON."""
	path = Path(state_path)
	payload = {
		"saved_at": datetime.now().isoformat(timespec="seconds"),
		"ciphertexts_b64": [base64.b64encode(c).decode("ascii") for c in ciphertexts],
		"key": list(key),
		"plaintexts_b64": [base64.b64encode(bytes(p)).decode("ascii") for p in (plaintexts or [])],
		"manual_plaintexts": list(manual_plaintexts or []),
		"meta": meta or {},
	}
	path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_state(state_path: str | Path) -> dict:
	"""Load cracking state from JSON."""
	path = Path(state_path)
	payload = json.loads(path.read_text(encoding="utf-8"))

	ciphertexts = [base64.b64decode(s) for s in payload.get("ciphertexts_b64", [])]
	plaintexts = [base64.b64decode(s) for s in payload.get("plaintexts_b64", [])]
	key = payload.get("key", [])
	manual_plaintexts = payload.get("manual_plaintexts", [])

	return {
		"saved_at": payload.get("saved_at"),
		"ciphertexts": ciphertexts,
		"plaintexts": plaintexts,
		"key": key,
		"manual_plaintexts": manual_plaintexts,
		"meta": payload.get("meta", {}),
	}


def save_key_history(
	history_path: str | Path,
	key: Sequence[Optional[int]],
	*,
	note: str = "",
) -> None:
	"""Append a key snapshot (JSONL) so user can rollback."""
	path = Path(history_path)
	record = {
		"ts": datetime.now().isoformat(timespec="seconds"),
		"note": note,
		"key": list(key),
	}
	with path.open("a", encoding="utf-8") as file:
		file.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_plaintexts_file(
	output_path: str | Path,
	plaintexts: Sequence[bytes | bytearray | str],
	*,
	encoding: str = "utf-8",
	masks: Sequence[str] | None = None,
	masks2: Sequence[str] | None = None,
	reference_texts: Sequence[str] | None = None,
) -> None:
	"""Write current plaintext guesses to a human-editable TXT file.

	If masks are provided, writes the mask line(s) directly under each plaintext.
	- If only `masks` is provided: writes one mask line.
	- If `masks` and `masks2` are provided: writes two lines (mask3 then mask4).

	This file is intended to be edited by hand; parsers must be able to skip
	mask lines so plaintext edits don't affect masks and vice versa.
	"""
	path = Path(output_path)
	lines: list[str] = []
	for index, pt in enumerate(plaintexts, start=1):
		lines.append(f"Plaintext {index}:")
		if isinstance(pt, str):
			decoded = pt
		else:
			decoded = bytes(pt).decode(encoding, errors="replace")
		lines.append(decoded)
		if masks is not None and (index - 1) < len(masks):
			lines.append(masks[index - 1])
		if masks2 is not None and (index - 1) < len(masks2):
			lines.append(masks2[index - 1])
		if reference_texts is not None and (index - 1) < len(reference_texts):
			ref = reference_texts[index - 1] or ""
			for ref_line in ref.splitlines() or [""]:
				lines.append(ref_line)
		lines.append("")
	# Do not strip spaces: they can be meaningful for manual plaintext edits.
	text = "\n".join(lines)
	if not text.endswith("\n"):
		text += "\n"
	path.write_text(text, encoding="utf-8")


def parse_plaintexts(file_path: str | Path, *, expected_count: Optional[int] = None) -> list[str]:
	"""Parse plaintexts from a TXT produced by write_plaintexts_file.

	Returns a list of strings (Unicode). Unknown bytes are expected to be '_' (underscore).
	"""
	path = Path(file_path)
	content = path.read_text(encoding="utf-8")
	lines = content.splitlines()

	plaintexts: list[str] = []
	current: list[str] = []

	def flush():
		if current or (expected_count is not None and len(plaintexts) < expected_count):
			plaintexts.append("\n".join(current).rstrip("\n"))

	plaintext_header_re = re.compile(r"^\s*Plaintext\s+(\d+)\s*:\s*$", re.IGNORECASE)
	mask_header_re = re.compile(r"^\s*Mask\s+(\d+)\s*:\s*$", re.IGNORECASE)
	# Require at least one non-'_' symbol to avoid dropping plaintext lines that
	# might be all '_' early in the workflow.
	mask_line_re = _MASK_LINE_RE_ANY
	saw_any_header = False
	in_mask_block = False
	# Some files (including the editable copy) write mask lines directly under plaintext.
	# In the current format we also write a reference text line under the TWO mask lines.
	# Those reference line(s) must be ignored when parsing plaintext edits.
	seen_inline_masks_in_block = 0
	skipping_reference = False

	for line in lines:
		if plaintext_header_re.match(line):
			if saw_any_header:
				flush()
				current = []
			else:
				saw_any_header = True
			in_mask_block = False
			seen_inline_masks_in_block = 0
			skipping_reference = False
			continue
		if mask_header_re.match(line):
			# Ignore everything in a mask block until the next "Plaintext N:" header.
			in_mask_block = True
			continue
		if saw_any_header and not in_mask_block:
			# Backward/forward compatibility: some versions write mask line(s)
			# directly under plaintext. Detect and skip such lines.
			if current and mask_line_re.fullmatch(line):
				seen_inline_masks_in_block += 1
				if seen_inline_masks_in_block >= 2:
					skipping_reference = True
				continue
			# After two inline mask lines, ignore reference line(s) until the blank
			# separator (or next header).
			if skipping_reference:
				if not line.strip():
					skipping_reference = False
				continue
			if not line.strip():
				# Keep empty lines as part of plaintext (rare).
				current.append(line)
				continue
			current.append(line)

	if saw_any_header:
		flush()
	else:
		# Fallback: treat each non-empty line as separate plaintext guess.
		plaintexts = [line for line in lines if line.strip()]

	if expected_count is not None and len(plaintexts) < expected_count:
		raise ValueError(f"Expected at least {expected_count} plaintext blocks, got {len(plaintexts)}")

	return plaintexts


def _char_to_single_byte(char: str) -> Optional[int]:
	if char == "_":
		return None
	if char == "\uFFFD":
		return None
	if len(char) != 1:
		return None

	code = ord(char)
	if 0 <= code <= 0x7F:
		return code

	for encoding in ("cp1251", "latin-1"):
		try:
			raw = char.encode(encoding)
		except UnicodeEncodeError:
			continue
		if len(raw) == 1:
			return raw[0]

	return None


def update_key_from_plaintexts(
	ciphertexts: Sequence[bytes],
	plaintexts: Sequence[str | bytes | bytearray],
	key: Optional[list[Optional[int]]] = None,
	*,
	override_conflicts: bool = True,
) -> tuple[list[Optional[int]], dict]:
	"""Update partial key from user-supplied plaintext guesses.

	For each known plaintext byte at position i: key[i] = ciphertext[i] ^ plaintext[i].
	Unknown bytes are denoted by '_' in text.
	"""
	if not ciphertexts:
		raise ValueError("ciphertexts must not be empty")

	common_len = min(len(ciphertext) for ciphertext in ciphertexts)
	if key is None:
		key = make_partial_key(common_len)
	if len(key) < common_len:
		key.extend([None] * (common_len - len(key)))

	conflicts: list[dict] = []
	updates = 0

	for text_index, ciphertext in enumerate(ciphertexts):
		if text_index >= len(plaintexts):
			break
		pt = plaintexts[text_index]
		if isinstance(pt, (bytes, bytearray)):
			pt_bytes = bytes(pt)
			limit = min(common_len, len(pt_bytes), len(ciphertext))
			for pos in range(limit):
				value = pt_bytes[pos]
				if value == ord("_"):
					continue
				new_key_byte = ciphertext[pos] ^ value
				old_key_byte = key[pos]
				if old_key_byte is not None and old_key_byte != new_key_byte:
					conflicts.append({"pos": pos, "old": old_key_byte, "new": new_key_byte, "text": text_index})
					if not override_conflicts:
						continue
				key[pos] = new_key_byte
				updates += 1
			continue

		pt_text = str(pt)
		limit = min(common_len, len(pt_text), len(ciphertext))
		for pos in range(limit):
			byte_value = _char_to_single_byte(pt_text[pos])
			if byte_value is None:
				continue
			new_key_byte = ciphertext[pos] ^ byte_value
			old_key_byte = key[pos]
			if old_key_byte is not None and old_key_byte != new_key_byte:
				conflicts.append({"pos": pos, "old": old_key_byte, "new": new_key_byte, "text": text_index})
				if not override_conflicts:
					continue
			key[pos] = new_key_byte
			updates += 1

	stats = {
		"common_len": common_len,
		"updates": updates,
		"conflicts": conflicts,
	}
	return key, stats


from pathlib import Path

from help_methods import (
	generate_punctuation_report,
	guess_punctuation_positions,
	load_ciphertexts,
	load_state,
)


def main() -> None:
	print("K3: отчёт по пунктуации/цифрам (эвристика + с учётом key из state.json)")

	default_task_path = Path("K3") / "2026_02_24_10_27_04_Анна_Казакевич_task.txt"
	ciphertexts = load_ciphertexts(default_task_path)
	common_len = min(len(c) for c in ciphertexts)

	# Lightweight hint: positions where XOR often looks like punct/digit.
	hints = guess_punctuation_positions(ciphertexts, common_len=common_len)
	top_positions = sorted(
		range(common_len),
		key=lambda i: hints["punct_counts"][i],
		reverse=True,
	)[:10]
	print("Топ позиций по 'punct XOR' (подсказка):", top_positions)

	# Report that uses current key if present.
	state_path = Path("K3") / "state.json"
	if state_path.exists():
		state = load_state(state_path)
		key = state.get("key") or [None] * common_len
		print(f"Ключ загружен из: {state_path}")
	else:
		key = [None] * common_len
		print("state.json не найден — отчёт будет без учёта известного key")

	out_path = Path("K3") / "punctuation_report.txt"
	path = generate_punctuation_report(
		ciphertexts=ciphertexts,
		key=key,
		common_len=common_len,
		out_path=out_path,
		punctuation=".,!-?",
		max_items=200,
	)
	print(f"Сохранено: {path}")


if __name__ == "__main__":
	main()

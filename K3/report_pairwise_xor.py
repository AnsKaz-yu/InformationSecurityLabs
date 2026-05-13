from pathlib import Path

from help_methods import generate_pairwise_xor_report, load_ciphertexts


def main() -> None:
	print("K3: отчёт попарного XOR (C_i XOR C_j)")

	default_task_path = Path("K3") / "2026_02_24_10_27_04_Анна_Казакевич_task.txt"
	ciphertexts = load_ciphertexts(default_task_path)
	common_len = min(len(c) for c in ciphertexts)

	out_path = Path("K3") / "pairwise_xor.txt"
	path = generate_pairwise_xor_report(ciphertexts=ciphertexts, common_len=common_len, out_path=out_path)
	print(f"Сохранено: {path}")


if __name__ == "__main__":
	main()

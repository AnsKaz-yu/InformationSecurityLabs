from pathlib import Path

from help_methods import compute_and_save_class_masks, load_ciphertexts


def main() -> None:
	print("K3: генерация class_masks (старый формат, top-3-bits)")

	default_task_path = Path("K3") / "2026_02_24_10_27_04_Анна_Казакевич_task.txt"
	ciphertexts = load_ciphertexts(default_task_path)

	mask_path = Path("K3") / "class_masks.txt"
	mask_json_path = Path("K3") / "class_masks_report.json"
	compute_and_save_class_masks(ciphertexts, mask_path, mask_json_path)

	print(f"Сохранено: {mask_path}")
	print(f"Сохранено: {mask_json_path}")


if __name__ == "__main__":
	main()

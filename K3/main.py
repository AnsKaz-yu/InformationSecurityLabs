from help_methods import (
	key_length_candidates_three_texts,
	key_candidates_for_length_three_texts,
	decrypt_vigenere,
	clean_text,
)


if __name__ == "__main__":
	print("Автоматический статистический взлом Виженера по 3 шифротекстам")

	default_path_1 = "K3\\ciphertext1.txt"
	default_path_2 = "K3\\ciphertext2.txt"
	default_path_3 = "K3\\ciphertext3.txt"

	path_1 = input(f"Путь к 1-му шифротексту (по умолчанию: {default_path_1}): ") or default_path_1
	path_2 = input(f"Путь ко 2-му шифротексту (по умолчанию: {default_path_2}): ") or default_path_2
	path_3 = input(f"Путь к 3-му шифротексту (по умолчанию: {default_path_3}): ") or default_path_3

	with open(path_1, "r") as file:
		ciphertext_1 = file.read()

	with open(path_2, "r") as file:
		ciphertext_2 = file.read()

	with open(path_3, "r") as file:
		ciphertext_3 = file.read()

	total_letters = (
		len(clean_text(ciphertext_1))
		+ len(clean_text(ciphertext_2))
		+ len(clean_text(ciphertext_3))
	)
	if total_letters == 0:
		print("В текстах нет букв для анализа")
		raise SystemExit(0)

	length_candidates = key_length_candidates_three_texts(
		ciphertext_1,
		ciphertext_2,
		ciphertext_3,
		max_key_length=20,
		top_n=10,
	)

	if not length_candidates:
		print("Недостаточно данных для оценки длины ключа")
		raise SystemExit(0)

	print("\nНаиболее вероятные длины ключа (score):")
	for key_length, score in length_candidates:
		normalized = -score / total_letters
		print(f"{key_length} -> score={round(score, 2)}, -score/len={round(normalized, 4)}")

	for key_length, _ in length_candidates[:3]:
		print(f"\n===== Длина ключа: {key_length} =====")

		key_candidates = key_candidates_for_length_three_texts(
			ciphertext_1,
			ciphertext_2,
			ciphertext_3,
			key_length,
			top_shifts_per_column=3,
			max_candidates=3,
		)

		print("Топ-3 расшифровки:")
		for index, (key, score) in enumerate(key_candidates, start=1):
			normalized = -score / total_letters
			plain_1 = decrypt_vigenere(ciphertext_1, key)
			plain_2 = decrypt_vigenere(ciphertext_2, key)
			plain_3 = decrypt_vigenere(ciphertext_3, key)

			print(f"\n{index}) ключ={key}, score={round(score, 2)}, -score/len={round(normalized, 4)}")
			print("Текст 1:")
			print(plain_1)
			print("Текст 2:")
			print(plain_2)
			print("Текст 3:")
			print(plain_3)

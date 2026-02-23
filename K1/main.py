from help_methods import (
    Kasiski,
    friedman_key_length_candidates,
    estimate_vigenere_key_candidates,
    decrypt_vigenere,
    text_chi_squared,
)


def normalize_scores(scores):
    if not scores:
        return {}

    min_value = min(scores.values())
    max_value = max(scores.values())
    value_range = max_value - min_value

    if value_range == 0:
        return {key: 1.0 for key in scores}

    return {
        key: (value - min_value) / value_range
        for key, value in scores.items()
    }


def top_items(scores, limit=10):
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:limit]


if __name__ == "__main__":
    print("Программа для взлома шифра Вижинера")
    default_path = "K1\\ciphertext.txt"
    path = input(f"Введите путь к файлу с зашифрованным текстом (по умолчанию: {default_path}): ") or default_path

    with open(path, "r") as file:
        ciphertext = file.read()

    kasiski_scores = normalize_scores(Kasiski(ciphertext, min_length=4, max_length=4, max_key_length=20))
    friedman_scores = normalize_scores(friedman_key_length_candidates(ciphertext, max_key_length=20, top_n=20))

    print("Касиски (длина -> score):")
    for key_length, score in top_items(kasiski_scores):
        print(f"{key_length} -> {round(score, 4)}")

    print("\nФридман (длина -> score):")
    for key_length, score in top_items(friedman_scores):
        print(f"{key_length} -> {round(score, 4)}")

    combined_scores = {
        key_length: kasiski_scores.get(key_length, 0.0) + friedman_scores.get(key_length, 0.0)
        for key_length in set(kasiski_scores) | set(friedman_scores)
    }

    if not combined_scores:
        print("Недостаточно повторов для оценки длины ключа")
        raise SystemExit(0)

    print("\nОбъединенный score (Касиски + Фридман):")
    for key_length, score in top_items(combined_scores):
        print(f"{key_length} -> {round(score, 4)}")

    probable_key_lengths = [key_length for key_length, _ in top_items(combined_scores, limit=10)]
    print("\nНаиболее вероятные длины ключа:")
    print(probable_key_lengths)

    for key_length in probable_key_lengths[:3]:
        print(f"\nДлина ключа: {key_length}")
        key_candidates = estimate_vigenere_key_candidates(
            ciphertext,
            key_length,
            top_shifts_per_column=3,
            max_candidates=5,
        )

        decryptions = []
        for key, _ in key_candidates:
            decrypted_text = decrypt_vigenere(ciphertext, key)
            decryptions.append((key, text_chi_squared(decrypted_text), decrypted_text))

        decryptions.sort(key=lambda item: item[1])
        print("Топ-3 расшифровки:")
        for index, (key, score, text) in enumerate(decryptions[:3], start=1):
            print(f"{index}) ключ={key}, score={round(score, 2)}")
            print(text)

        








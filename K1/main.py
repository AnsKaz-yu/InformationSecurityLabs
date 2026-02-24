from help_methods import (
    Kasiski,
    friedman_key_length_candidates,
    estimate_vigenere_key_candidates,
    decrypt_vigenere,
    text_chi_squared,
    get_language_profile,
)
from charset_normalizer import from_bytes


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
    default_path = "K1\\2026_02_24_10_28_23_Анна_Казакевич_task.txt"
    path = input(f"Введите путь к файлу с зашифрованным текстом (по умолчанию: {default_path}): ") or default_path

    with open(path, "rb") as file:
        raw_data = file.read()

    detected = from_bytes(raw_data).best()
    source_encoding = detected.encoding if detected and detected.encoding else "utf-8"
    ciphertext = raw_data.decode(source_encoding, errors="replace")

    profile = get_language_profile(ciphertext, source_encoding=source_encoding)
    alphabet = profile["alphabet"]
    frequencies = profile["frequencies"]
    language_code = profile["language_code"]

    print(f"Кодировка файла: {source_encoding}")
    print(f"Язык/алфавит анализа: {language_code.upper()} / {alphabet}")

    kasiski_scores = normalize_scores(
        Kasiski(ciphertext, alphabet=alphabet, min_length=4, max_length=4, max_key_length=20)
    )
    friedman_scores = normalize_scores(
        friedman_key_length_candidates(ciphertext, alphabet=alphabet, max_key_length=20, top_n=20)
    )

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

    best_variant = None

    for key_length in probable_key_lengths[:3]:
        print(f"\nДлина ключа: {key_length}")
        key_candidates = estimate_vigenere_key_candidates(
            ciphertext,
            key_length,
            frequencies=frequencies,
            alphabet=alphabet,
            top_shifts_per_column=3,
            max_candidates=5,
        )

        decryptions = []
        for key, _ in key_candidates:
            decrypted_text = decrypt_vigenere(ciphertext, key, alphabet=alphabet)
            score = text_chi_squared(decrypted_text, frequencies=frequencies, alphabet=alphabet)
            decryptions.append((key, score, decrypted_text, key_length))

        decryptions.sort(key=lambda item: item[1])
        print("Топ-3 расшифровки:")
        for index, (key, score, text, candidate_key_length) in enumerate(decryptions[:3], start=1):
            print(f"{index}) ключ={key}, score={round(score, 2)}")
            print(text)

            if best_variant is None or score < best_variant["score"]:
                best_variant = {
                    "key": key,
                    "score": score,
                    "text": text,
                    "key_length": candidate_key_length,
                }

    if best_variant is not None:
        answer_path = "K1\\K1answer.txt"
        with open(answer_path, "w", encoding="utf-8") as answer_file:
            answer_file.write(f"key_length={best_variant['key_length']}\n")
            answer_file.write(f"key={best_variant['key']}\n")
            answer_file.write("plaintext:\n")
            answer_file.write(best_variant["text"])

        print(f"\nЛучший вариант сохранен в {answer_path}")

        








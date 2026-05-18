from help_methods import (
    read_vernam_ciphers,
    decode_base64_cipher,
    break_vernam_two_ciphertexts,
    decode_best_effort,
)


if __name__ == "__main__":
    print("Программа для взлома шифра Вернама по двум шифротекстам")

    default_path = "K2\\2026_02_24_10_26_59_Анна_Казакевич_task.txt"
    task_path = input(f"Введите путь к task-файлу (по умолчанию: {default_path}): ") or default_path

    cipher_1_b64, cipher_2_b64 = read_vernam_ciphers(task_path, expected_count=2)
    ciphertext_1 = decode_base64_cipher(cipher_1_b64)
    ciphertext_2 = decode_base64_cipher(cipher_2_b64)

    guessed_plain_1_bytes, guessed_plain_2_bytes, score_sum = break_vernam_two_ciphertexts(
        ciphertext_1,
        ciphertext_2,
    )

    guessed_plain_1, encoding_1 = decode_best_effort(guessed_plain_1_bytes)
    guessed_plain_2, encoding_2 = decode_best_effort(guessed_plain_2_bytes)

    print("\nПредполагаемый открытый текст 1:")
    print(guessed_plain_1)

    print("\nПредполагаемый открытый текст 2:")
    print(guessed_plain_2)

    answer_path = "K2\\K2answer.txt"
    with open(answer_path, "w", encoding="utf-8") as answer_file:
        answer_file.write(f"min_length={min(len(ciphertext_1), len(ciphertext_2))}\n")
        answer_file.write(f"score_sum={round(score_sum, 4)}\n")
        answer_file.write(f"plaintext_1_encoding={encoding_1}\n")
        answer_file.write(f"plaintext_2_encoding={encoding_2}\n")
        answer_file.write("plaintext_1:\n")
        answer_file.write(guessed_plain_1)
        answer_file.write("\n\nplaintext_2:\n")
        answer_file.write(guessed_plain_2)

    print(f"\nРезультат сохранен в {answer_path}")

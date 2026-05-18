import base64
import re


COMMON_BYTE_SCORES = {
    ord(" "): 8.0,
    ord("e"): 3.2,
    ord("t"): 3.0,
    ord("a"): 2.8,
    ord("o"): 2.8,
    ord("i"): 2.6,
    ord("n"): 2.6,
    ord("s"): 2.4,
    ord("r"): 2.4,
    ord("h"): 2.2,
    ord("l"): 2.1,
    ord("d"): 2.0,
    ord("u"): 1.9,
    ord("m"): 1.8,
    ord("c"): 1.8,
    ord("f"): 1.7,
    ord("w"): 1.6,
    ord("y"): 1.5,
    ord("g"): 1.4,
    ord("p"): 1.3,
    ord("b"): 1.2,
    ord("v"): 1.1,
    ord("k"): 1.0,
    ord("x"): 0.8,
    ord("j"): 0.6,
    ord("q"): 0.5,
    ord("z"): 0.4,
    ord("."): 1.2,
    ord(","): 1.2,
    ord("!"): 1.0,
    ord("?"): 1.0,
    ord(":"): 0.9,
    ord(";"): 0.8,
    ord("-"): 0.9,
    ord("("): 0.7,
    ord(")"): 0.7,
    ord("\n"): 0.7,
    ord("\r"): 0.4,
    ord("\t"): 0.5,
}

RUSSIAN_FREQUENCIES = {
    "о": 10.97,
    "е": 8.45,
    "а": 8.01,
    "и": 7.35,
    "н": 6.70,
    "т": 6.26,
    "с": 5.47,
    "р": 4.73,
    "в": 4.54,
    "л": 4.40,
    "к": 3.49,
    "м": 3.21,
    "д": 2.98,
    "п": 2.81,
    "у": 2.62,
    "я": 2.01,
    "ы": 1.90,
    "ь": 1.74,
    "г": 1.70,
    "з": 1.65,
    "б": 1.59,
    "ч": 1.44,
    "й": 1.21,
    "х": 0.97,
    "ж": 0.94,
    "ш": 0.73,
    "ю": 0.64,
    "ц": 0.48,
    "щ": 0.36,
    "э": 0.32,
    "ф": 0.26,
    "ъ": 0.04,
    "ё": 0.04,
}


def _build_russian_byte_scores():
    scores = {}
    for letter, frequency in RUSSIAN_FREQUENCIES.items():
        score = 0.5 + (frequency / 100) * 14
        for variant in (letter, letter.upper()):
            byte_value = variant.encode("cp1251")[0]
            scores[byte_value] = max(scores.get(byte_value, float("-inf")), score)
    return scores


RUSSIAN_BYTE_SCORES = _build_russian_byte_scores()


def read_vernam_ciphers(task_path, expected_count=2):
    with open(task_path, "r", encoding="utf-8") as file:
        lines = [line.strip() for line in file.readlines() if line.strip()]

    ciphers = []
    for index in range(0, len(lines), 2):
        if index + 1 >= len(lines):
            break

        header = lines[index]
        data_line = lines[index + 1]

        if not re.match(r"^Шифр \d+ \(base64\):$", header):
            continue

        if not (data_line.startswith("b'") and data_line.endswith("'")):
            raise ValueError(f"Некорректный формат данных после заголовка: {header}")

        ciphers.append(data_line[2:-1])

    if len(ciphers) < expected_count:
        raise ValueError(
            f"В task-файле найдено {len(ciphers)} base64-блоков, ожидалось минимум {expected_count}"
        )

    return ciphers[:expected_count]


def decode_base64_cipher(base64_cipher):
    return base64.b64decode(base64_cipher)


def _byte_score(byte_value):
    if byte_value in COMMON_BYTE_SCORES:
        return COMMON_BYTE_SCORES[byte_value]

    lower_ascii = byte_value + 32 if 65 <= byte_value <= 90 else byte_value
    if lower_ascii in COMMON_BYTE_SCORES:
        return COMMON_BYTE_SCORES[lower_ascii]

    if byte_value in RUSSIAN_BYTE_SCORES:
        return RUSSIAN_BYTE_SCORES[byte_value]

    if 32 <= byte_value <= 126:
        return 0.3

    if 128 <= byte_value <= 255:
        return -0.2

    return -4.0


def _is_ascii_letter(byte_value):
    return 65 <= byte_value <= 90 or 97 <= byte_value <= 122


def _is_russian_cp1251_letter(byte_value):
    return byte_value in RUSSIAN_BYTE_SCORES


def _is_letter(byte_value):
    return _is_ascii_letter(byte_value) or _is_russian_cp1251_letter(byte_value)


def _pair_bonus(left_byte, right_byte):
    bonus = 0.0

    left_is_letter = _is_letter(left_byte)
    right_is_letter = _is_letter(right_byte)

    if left_byte == 32 and right_is_letter:
        bonus += 1.2
    if right_byte == 32 and left_is_letter:
        bonus += 1.2

    if left_byte == 32 and right_byte == 32:
        bonus -= 0.8

    return bonus


def _candidate_pairs_for_xor_byte(xor_byte, top_k=24):
    variants = []

    for left_byte in range(256):
        right_byte = left_byte ^ xor_byte
        score = _byte_score(left_byte) + _byte_score(right_byte) + _pair_bonus(left_byte, right_byte)
        variants.append((left_byte, right_byte, score))

    variants.sort(key=lambda item: item[2], reverse=True)
    return variants[:top_k]


def _transition_bonus(prev_byte, current_byte):
    if prev_byte is None:
        return 0.0

    prev_is_letter = _is_letter(prev_byte)
    curr_is_letter = _is_letter(current_byte)
    prev_is_space = prev_byte == 32
    curr_is_space = current_byte == 32
    prev_is_punct = prev_byte in (ord("."), ord(","), ord("!"), ord("?"), ord(":"), ord(";"))

    if prev_is_letter and curr_is_letter:
        return 0.35
    if prev_is_space and curr_is_letter:
        return 0.7
    if prev_is_letter and curr_is_space:
        return 0.45
    if prev_is_punct and curr_is_space:
        return 0.4
    if prev_is_space and curr_is_space:
        return -1.4

    return 0.0


def break_vernam_two_ciphertexts(ciphertext_1, ciphertext_2):
    min_len = min(len(ciphertext_1), len(ciphertext_2))
    left = ciphertext_1[:min_len]
    right = ciphertext_2[:min_len]

    plaintext_1 = bytearray()
    plaintext_2 = bytearray()
    score_sum = 0.0
    prev_1 = None
    prev_2 = None

    for byte_1, byte_2 in zip(left, right):
        xor_byte = byte_1 ^ byte_2
        candidates = _candidate_pairs_for_xor_byte(xor_byte)

        best_pair = None
        best_pair_score = float("-inf")

        for guessed_1, guessed_2, base_score in candidates:
            score = (
                base_score
                + _transition_bonus(prev_1, guessed_1)
                + _transition_bonus(prev_2, guessed_2)
            )
            if score > best_pair_score:
                best_pair_score = score
                best_pair = (guessed_1, guessed_2)

        selected_1, selected_2 = best_pair if best_pair is not None else (ord("?"), ord("?"))
        plaintext_1.append(selected_1)
        plaintext_2.append(selected_2)
        score_sum += best_pair_score if best_pair is not None else -10.0
        prev_1 = selected_1
        prev_2 = selected_2

    return bytes(plaintext_1), bytes(plaintext_2), score_sum


def decode_best_effort(data):
    utf8_decoded = data.decode("utf-8", errors="replace")
    cp1251_decoded = data.decode("cp1251", errors="replace")

    utf8_score = _decoded_text_quality(utf8_decoded)
    cp1251_score = _decoded_text_quality(cp1251_decoded)

    if cp1251_score > utf8_score:
        return cp1251_decoded, "cp1251"

    return utf8_decoded, "utf-8"


def _decoded_text_quality(text):
    score = 0.0
    for char in text:
        code = ord(char)
        if char == "�":
            score -= 3.0
        elif char.isalpha() or char.isdigit():
            score += 1.0
        elif char in " .,!?;:-()\n\r\t'\"":
            score += 0.4
        elif 32 <= code <= 126:
            score += 0.2
        else:
            score -= 0.8

    return score

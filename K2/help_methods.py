import math


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = len(ALPHABET)
LETTER_TO_INDEX = {char: index for index, char in enumerate(ALPHABET)}

ENGLISH_FREQUENCIES = {
    "A": 8.167,
    "B": 1.492,
    "C": 2.782,
    "D": 4.253,
    "E": 12.702,
    "F": 2.228,
    "G": 2.015,
    "H": 6.094,
    "I": 6.966,
    "J": 0.153,
    "K": 0.772,
    "L": 4.025,
    "M": 2.406,
    "N": 6.749,
    "O": 7.507,
    "P": 1.929,
    "Q": 0.095,
    "R": 5.987,
    "S": 6.327,
    "T": 9.056,
    "U": 2.758,
    "V": 0.978,
    "W": 2.360,
    "X": 0.150,
    "Y": 1.974,
    "Z": 0.074,
}

LOG_LETTER_PROB = {
    char: math.log(freq / 100)
    for char, freq in ENGLISH_FREQUENCIES.items()
}


def clean_text(text):
    return "".join(char.upper() for char in text if char.upper() in LETTER_TO_INDEX)


def decrypt_vigenere(ciphertext, key):
    if not key:
        raise ValueError("key не должен быть пустым")

    key_indexes = [LETTER_TO_INDEX[char] for char in key.upper() if char in LETTER_TO_INDEX]
    if not key_indexes:
        raise ValueError("key не содержит символов латинского алфавита")

    result = []
    key_pos = 0
    for char in ciphertext:
        upper = char.upper()
        if upper in LETTER_TO_INDEX:
            shift = key_indexes[key_pos % len(key_indexes)]
            plain_index = (LETTER_TO_INDEX[upper] - shift) % ALPHABET_SIZE
            plain_char = ALPHABET[plain_index]
            result.append(plain_char if char.isupper() else plain_char.lower())
            key_pos += 1
        else:
            result.append(char)

    return "".join(result)


def column_decrypt_score(column_text, shift):
    score = 0.0
    for char in column_text:
        plain_index = (LETTER_TO_INDEX[char] - shift) % ALPHABET_SIZE
        plain_char = ALPHABET[plain_index]
        score += LOG_LETTER_PROB[plain_char]
    return score


def key_candidates_for_length_two_texts(
    ciphertext_1,
    ciphertext_2,
    key_length,
    top_shifts_per_column=3,
    max_candidates=3,
):
    if key_length < 1:
        raise ValueError("key_length должен быть не меньше 1")

    text_1 = clean_text(ciphertext_1)
    text_2 = clean_text(ciphertext_2)

    best_shifts_per_column = []
    for column_index in range(key_length):
        col_1 = text_1[column_index::key_length]
        col_2 = text_2[column_index::key_length]

        shift_scores = []
        for shift in range(ALPHABET_SIZE):
            score = column_decrypt_score(col_1, shift) + column_decrypt_score(col_2, shift)
            shift_scores.append((shift, score))

        shift_scores.sort(key=lambda item: item[1], reverse=True)
        best_shifts_per_column.append(shift_scores[:top_shifts_per_column])

    candidates = [("", 0.0)]
    for column_options in best_shifts_per_column:
        next_candidates = []
        for prefix_key, prefix_score in candidates:
            for shift, shift_score in column_options:
                next_key = prefix_key + ALPHABET[shift]
                next_candidates.append((next_key, prefix_score + shift_score))

        next_candidates.sort(key=lambda item: item[1], reverse=True)
        candidates = next_candidates[:max_candidates]

    return candidates


def score_key_length_two_texts(ciphertext_1, ciphertext_2, key_length):
    best_candidate = key_candidates_for_length_two_texts(
        ciphertext_1,
        ciphertext_2,
        key_length,
        top_shifts_per_column=1,
        max_candidates=1,
    )
    if not best_candidate:
        return float("-inf")
    return best_candidate[0][1]


def key_length_candidates_two_texts(ciphertext_1, ciphertext_2, max_key_length=20, top_n=10):
    scores = {}
    for key_length in range(1, max_key_length + 1):
        scores[key_length] = score_key_length_two_texts(ciphertext_1, ciphertext_2, key_length)

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))

    filtered = []
    group = []
    current_score = None
    tolerance = 1e-12

    for key_length, score in ranked:
        if current_score is None or abs(score - current_score) <= tolerance:
            group.append((key_length, score))
            current_score = score if current_score is None else current_score
            continue

        filtered.extend(_remove_multiples_inside_group(group))
        group = [(key_length, score)]
        current_score = score

    if group:
        filtered.extend(_remove_multiples_inside_group(group))

    return filtered[:top_n]


def _remove_multiples_inside_group(group):
    sorted_group = sorted(group, key=lambda item: item[0])
    selected = []

    for key_length, score in sorted_group:
        is_multiple = any(
            key_length != base_length and key_length % base_length == 0
            for base_length, _ in selected
        )
        if not is_multiple:
            selected.append((key_length, score))

    return selected
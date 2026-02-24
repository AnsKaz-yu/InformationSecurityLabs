from collections import Counter, defaultdict
import math


LATIN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CYRILLIC_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

STATIC_FREQUENCIES = {
    "en": {
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
    },
    "ru": {
        "А": 8.01,
        "Б": 1.59,
        "В": 4.54,
        "Г": 1.70,
        "Д": 2.98,
        "Е": 8.45,
        "Ё": 0.04,
        "Ж": 0.94,
        "З": 1.65,
        "И": 7.35,
        "Й": 1.21,
        "К": 3.49,
        "Л": 4.40,
        "М": 3.21,
        "Н": 6.70,
        "О": 10.97,
        "П": 2.81,
        "Р": 4.73,
        "С": 5.47,
        "Т": 6.26,
        "У": 2.62,
        "Ф": 0.26,
        "Х": 0.97,
        "Ц": 0.48,
        "Ч": 1.44,
        "Ш": 0.73,
        "Щ": 0.36,
        "Ъ": 0.04,
        "Ы": 1.90,
        "Ь": 1.74,
        "Э": 0.32,
        "Ю": 0.64,
        "Я": 2.01,
    },
}


def clean_text(text, alphabet):
    alphabet_set = set(alphabet)
    return "".join(char.upper() for char in text if char.upper() in alphabet_set)


def get_language_profile(ciphertext, source_encoding="utf-8"):
    encoding = (source_encoding or "").lower()

    if any(tag in encoding for tag in ("1251", "koi8", "cp866")):
        language_code = "ru"
        alphabet = CYRILLIC_ALPHABET
    elif any(tag in encoding for tag in ("1252", "iso-8859-1", "latin", "ascii")):
        language_code = "en"
        alphabet = LATIN_ALPHABET
    else:
        upper = ciphertext.upper()
        cyrillic_count = sum("А" <= char <= "Я" or char == "Ё" for char in upper)
        latin_count = sum("A" <= char <= "Z" for char in upper)
        if cyrillic_count > latin_count:
            language_code = "ru"
            alphabet = CYRILLIC_ALPHABET
        else:
            language_code = "en"
            alphabet = LATIN_ALPHABET

    frequencies = {char: STATIC_FREQUENCIES[language_code].get(char, 0.01) for char in alphabet}

    return {
        "language_code": language_code,
        "alphabet": alphabet,
        "frequencies": frequencies,
    }


def Kasiski(ciphertext, alphabet, min_length=4, max_length=4, max_key_length=20):
    if min_length < 2:
        raise ValueError("min_length должен быть не меньше 2")
    if max_length < min_length:
        raise ValueError("max_length должен быть больше или равен min_length")

    text = clean_text(ciphertext, alphabet)

    sequence_positions = defaultdict(list)
    for ngram_length in range(min_length, max_length + 1):
        for index in range(len(text) - ngram_length + 1):
            sequence = text[index:index + ngram_length]
            sequence_positions[sequence].append(index)

    repeated_sequences = {
        sequence: positions
        for sequence, positions in sequence_positions.items()
        if len(positions) > 1
    }

    distances = []
    for positions in repeated_sequences.values():
        for i in range(len(positions) - 1):
            distance = positions[i + 1] - positions[i]
            if distance > 0:
                distances.append(distance)

    factor_counts = Counter()
    for distance in distances:
        limit = min(max_key_length, int(math.sqrt(distance)) + 1)
        for factor in range(2, limit):
            if distance % factor == 0:
                factor_counts[factor] += 1
                other = distance // factor
                if other <= max_key_length:
                    factor_counts[other] += 1

        if distance <= max_key_length:
            factor_counts[distance] += 1

    sorted_counts = sorted(factor_counts.items(), key=lambda item: (-item[1], item[0]))
    return {key_length: count for key_length, count in sorted_counts}


def index_of_coincidence(text, alphabet):
    cleaned = clean_text(text, alphabet)
    n = len(cleaned)
    if n < 2:
        return 0.0

    counts = Counter(cleaned)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator


def friedman_key_length_candidates(ciphertext, alphabet, max_key_length=20, top_n=5):
    cleaned = clean_text(ciphertext, alphabet)
    if len(cleaned) < 2:
        return {}

    scores = []
    upper_bound = min(max_key_length, len(cleaned))
    for key_length in range(1, upper_bound + 1):
        columns = [cleaned[index::key_length] for index in range(key_length)]
        non_empty_columns = [column for column in columns if len(column) > 1]
        if not non_empty_columns:
            continue

        avg_ioc = sum(index_of_coincidence(column, alphabet) for column in non_empty_columns) / len(non_empty_columns)
        scores.append((key_length, avg_ioc))

    scores.sort(key=lambda item: (-item[1], item[0]))
    return {key_length: avg_ioc for key_length, avg_ioc in scores[:top_n]}


def text_chi_squared(text, frequencies, alphabet):
    cleaned_text = clean_text(text, alphabet)
    if not cleaned_text:
        return float("inf")

    observed = Counter(cleaned_text)
    text_length = len(cleaned_text)
    score = 0.0
    for char in alphabet:
        expected_percent = frequencies.get(char, 0)
        expected_count = (expected_percent / 100) * text_length
        if expected_count > 0:
            observed_count = observed.get(char, 0)
            score += ((observed_count - expected_count) ** 2) / expected_count
    return score


def _column_shift_score(column_text, shift, frequencies, alphabet):
    index_by_char = {char: index for index, char in enumerate(alphabet)}
    alphabet_size = len(alphabet)

    decrypted_column = []
    for char in column_text:
        if char in index_by_char:
            decrypted_index = (index_by_char[char] - shift) % alphabet_size
            decrypted_column.append(alphabet[decrypted_index])

    return text_chi_squared("".join(decrypted_column), frequencies, alphabet)


def estimate_vigenere_key_candidates(
    ciphertext,
    key_length,
    frequencies,
    alphabet,
    top_shifts_per_column=3,
    max_candidates=10,
):
    if key_length < 1:
        raise ValueError("key_length должен быть не меньше 1")

    index_by_char = {char: index for index, char in enumerate(alphabet)}
    text = "".join(char.upper() for char in ciphertext if char.upper() in index_by_char)
    columns = [text[index::key_length] for index in range(key_length)]
    alphabet_size = len(alphabet)

    best_shifts_per_column = []
    for column in columns:
        shift_scores = []
        for shift in range(alphabet_size):
            score = _column_shift_score(column, shift, frequencies, alphabet)
            shift_scores.append((shift, score))

        shift_scores.sort(key=lambda item: item[1])
        best_shifts_per_column.append(shift_scores[:top_shifts_per_column])

    candidates = [("", 0.0)]
    for column_options in best_shifts_per_column:
        next_candidates = []
        for prefix, prefix_score in candidates:
            for shift, shift_score in column_options:
                next_candidates.append((prefix + alphabet[shift], prefix_score + shift_score))

        next_candidates.sort(key=lambda item: item[1])
        candidates = next_candidates[:max_candidates]

    return candidates


def decrypt_vigenere(ciphertext, key, alphabet):
    if not key:
        raise ValueError("key не должен быть пустым")

    index_by_char = {char: index for index, char in enumerate(alphabet)}
    key_indexes = [index_by_char[char.upper()] for char in key if char.upper() in index_by_char]
    if not key_indexes:
        raise ValueError("key не содержит символов выбранного алфавита")

    result = []
    key_pos = 0
    alphabet_size = len(alphabet)

    for char in ciphertext:
        upper_char = char.upper()
        if upper_char in index_by_char:
            shift = key_indexes[key_pos % len(key_indexes)]
            decrypted_index = (index_by_char[upper_char] - shift) % alphabet_size
            decrypted_char = alphabet[decrypted_index]
            if char.islower():
                decrypted_char = decrypted_char.lower()
            result.append(decrypted_char)
            key_pos += 1
        else:
            result.append(char)

    return "".join(result)

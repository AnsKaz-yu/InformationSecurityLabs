from collections import Counter, defaultdict
import math


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

def Kasiski(ciphertext, min_length=4, max_length=4, max_key_length=20):
    if min_length < 2:
        raise ValueError("min_length должен быть не меньше 2")
    if max_length < min_length:
        raise ValueError("max_length должен быть больше или равен min_length")

    text = "".join(ch for ch in ciphertext.upper() if ch.isalpha())

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

    sorted_counts = sorted(
        factor_counts.items(),
        key=lambda item: (-item[1], item[0])
    )
    return {key_length: count for key_length, count in sorted_counts}


def index_of_coincidence(text):
    cleaned = "".join(ch.upper() for ch in text if ch.isalpha())
    n = len(cleaned)
    if n < 2:
        return 0.0

    counts = Counter(cleaned)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator


def friedman_key_length_candidates(ciphertext, max_key_length=20, top_n=5):
    cleaned = "".join(ch.upper() for ch in ciphertext if ch.isalpha())
    if len(cleaned) < 2:
        return []

    scores = []
    upper_bound = min(max_key_length, len(cleaned))
    for key_length in range(1, upper_bound + 1):
        columns = [cleaned[index::key_length] for index in range(key_length)]
        non_empty_columns = [column for column in columns if len(column) > 1]
        if not non_empty_columns:
            continue

        avg_ioc = sum(index_of_coincidence(column) for column in non_empty_columns) / len(non_empty_columns)
        scores.append((key_length, avg_ioc))

    scores.sort(key=lambda item: (-item[1], item[0]))
    return {key_length: avg_ioc for key_length, avg_ioc in scores[:top_n]}


def combined_key_length_candidates(
    ciphertext,
    max_key_length=20,
    top_n=10,
    kasiski_min_length=4,
    kasiski_max_length=4,
):
    kasiski_scores_raw = Kasiski(
        ciphertext,
        min_length=kasiski_min_length,
        max_length=kasiski_max_length,
        max_key_length=max_key_length,
    )
    friedman_scores_raw = friedman_key_length_candidates(
        ciphertext,
        max_key_length=max_key_length,
        top_n=max_key_length,
    )

    combined_scores = defaultdict(float)

    max_factor_count = max(kasiski_scores_raw.values(), default=0)
    for rank, key_length in enumerate(kasiski_scores_raw.keys(), start=1):
        rank_score = 1 / rank
        count_score = (kasiski_scores_raw.get(key_length, 0) / max_factor_count) if max_factor_count else 0.0
        combined_scores[key_length] += 0.7 * rank_score + 0.3 * count_score

    if friedman_scores_raw:
        ioc_values = list(friedman_scores_raw.values())
        min_ioc = min(ioc_values)
        max_ioc = max(ioc_values)
        ioc_range = max_ioc - min_ioc

        for rank, (key_length, avg_ioc) in enumerate(friedman_scores_raw.items(), start=1):
            rank_score = 1 / rank
            if ioc_range > 0:
                ioc_score = (avg_ioc - min_ioc) / ioc_range
            else:
                ioc_score = 0.0
            combined_scores[key_length] += 0.7 * rank_score + 0.3 * ioc_score

    ranked = sorted(
        combined_scores.items(),
        key=lambda item: (-item[1], item[0])
    )

    return {key_length: score for key_length, score in ranked[:top_n]}


def _column_shift_score(column_text, shift, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    alphabet = alphabet.upper()
    index_by_char = {char: index for index, char in enumerate(alphabet)}
    alphabet_size = len(alphabet)

    decrypted_column = []
    for char in column_text:
        if char in index_by_char:
            decrypted_index = (index_by_char[char] - shift) % alphabet_size
            decrypted_column.append(alphabet[decrypted_index])

    return text_chi_squared("".join(decrypted_column), alphabet=alphabet)


def estimate_vigenere_key_candidates(
    ciphertext,
    key_length,
    top_shifts_per_column=3,
    max_candidates=10,
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
):
    if key_length < 1:
        raise ValueError("key_length должен быть не меньше 1")

    alphabet = alphabet.upper()
    index_by_char = {char: index for index, char in enumerate(alphabet)}
    text = "".join(ch.upper() for ch in ciphertext if ch.upper() in index_by_char)
    columns = [text[index::key_length] for index in range(key_length)]
    alphabet_size = len(alphabet)

    best_shifts_per_column = []
    for column in columns:
        shift_scores = []
        for shift in range(alphabet_size):
            score = _column_shift_score(column, shift, alphabet=alphabet)
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
def decrypt_vigenere(ciphertext, key, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    if not key:
        raise ValueError("key не должен быть пустым")

    alphabet = alphabet.upper()
    index_by_char = {char: index for index, char in enumerate(alphabet)}
    key_indexes = [index_by_char[ch.upper()] for ch in key if ch.upper() in index_by_char]
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


def text_chi_squared(text, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    alphabet = alphabet.upper()
    cleaned_text = "".join(ch.upper() for ch in text if ch.upper() in alphabet)
    if not cleaned_text:
        return float("inf")

    observed = Counter(cleaned_text)
    text_length = len(cleaned_text)
    score = 0.0
    for char in alphabet:
        expected_percent = ENGLISH_FREQUENCIES.get(char, 0)
        expected_count = (expected_percent / 100) * text_length
        if expected_count > 0:
            observed_count = observed.get(char, 0)
            score += ((observed_count - expected_count) ** 2) / expected_count
    return score
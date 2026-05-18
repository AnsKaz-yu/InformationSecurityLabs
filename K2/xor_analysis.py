"""
K2 - Initial XOR analysis to identify language and structure of plaintexts.
"""
import sys, base64, re
from pathlib import Path
from collections import Counter

TASK_PATH = r"K3\K2\2026_02_24_10_26_59_Анна_Казакевич_task.txt"

def read_task(path):
    with open(path, encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]
    ciphers = []
    for i in range(0, len(lines), 2):
        if i+1 >= len(lines): break
        if re.match(r"^Шифр \d+ \(base64\):$", lines[i]):
            raw = lines[i+1]
            if raw.startswith("b'") and raw.endswith("'"):
                ciphers.append(base64.b64decode(raw[2:-1]))
    return ciphers

ct1, ct2 = read_task(TASK_PATH)
print(f"CT1 length: {len(ct1)}")
print(f"CT2 length: {len(ct2)}")
print(f"Min length: {min(len(ct1), len(ct2))}")

N = min(len(ct1), len(ct2))
xor12 = bytes(a^b for a,b in zip(ct1[:N], ct2[:N]))

# --- Count XOR bytes that are ASCII letter XOR ASCII letter ---
# If both are English: letter XOR letter often results in 0x00-0x3f or 0x40-0x7f range
# Space XOR letter = letter | 0x20 -> same letter different case
space_xor_letter = sum(1 for b in xor12 if 0x41 <= b <= 0x5a or 0x61 <= b <= 0x7a)
print(f"\nXOR bytes that look like (space XOR letter): {space_xor_letter}/{N} = {100*space_xor_letter//N}%")

# Space property: P1[i]=space -> xor12[i] = 0x20 XOR P2[i] = P2[i] | 0x20 (lowercase)
# So if we assume position i is a space in P1, we can read P2[i] as lowercase letter

# Try assuming spaces in text1 give us text2
print("\n--- Assuming P1 spaces -> read P2 ---")
p2_guesses = []
for i, b in enumerate(xor12):
    # If P1[i] = space (0x20)
    p2_b = 0x20 ^ b
    p2_guesses.append(p2_b)

p2_ascii = bytes(p2_guesses).decode('ascii', errors='replace')
print(f"Sample (first 200): {repr(p2_ascii[:200])}")

# Analyze XOR for null bytes (same char in both)
nulls = sum(1 for b in xor12 if b == 0)
print(f"\nNull XOR bytes (same char in both plaintexts): {nulls} ({100*nulls//N}%)")

# Analyze low-value XOR bytes (close chars)
low_xor = sum(1 for b in xor12 if b < 0x20)
print(f"Low XOR bytes (<0x20): {low_xor} ({100*low_xor//N}%)")

# Most common XOR values
xor_freq = Counter(xor12)
print(f"\nTop 20 XOR values:")
for val, cnt in xor_freq.most_common(20):
    try:
        c1 = chr(val ^ ord(' '))
    except:
        c1 = '?'
    print(f"  0x{val:02x} ({val:3d}): {cnt:5d} times | space XOR this = '{c1}'")

# Try to detect if texts are English or Russian (cp1251)
# In cp1251, Russian letters are 0xC0-0xFF (lower) and 0xC0-0xFF and 0xE0-0xFF...
# Actually: А=0xC0..Я=0xDF, а=0xE0..я=0xFF, also ё=0xB8, Ё=0xA8
print("\n--- Checking XOR patterns for Ru+En ---")
# If one text is Russian and other English, XOR would be in specific ranges
# Ru letter (0xC0-0xFF) XOR En letter (0x41-0x7A) = 0x80-0xFF (high byte)
# Let's count high-byte XOR values
high_xor = sum(1 for b in xor12 if b >= 0x80)
print(f"High byte XOR (>=0x80): {high_xor} ({100*high_xor//N}%)")

# If both English: XOR of printable ASCII XOR printable ASCII is mostly in 0x00-0x7E
# If both Russian (cp1251): similar but different byte values
all_ascii_range = sum(1 for b in xor12 if b < 0x80)
print(f"Low byte XOR (<0x80): {all_ascii_range} ({100*all_ascii_range//N}%)")

# Detect most common single byte XOR values in 0x40-0x5F range (letter case masks)
letter_mask = sum(1 for b in xor12 if b == 0x20)
print(f"XOR = 0x20 (case flip): {letter_mask} ({100*letter_mask//N}%)")

# Try key byte 0 exhaustively on xor12[0:200]
# If we know one plaintext starts with something specific
print("\n--- Sample XOR bytes (first 40) ---")
for i in range(40):
    b = xor12[i]
    print(f"  xor[{i:3d}] = 0x{b:02x} ({b:3d})", end="")
    # What pairs of printable ASCII give this?
    pairs = [(chr(k), chr(k^b)) for k in range(32, 127) if 32 <= (k^b) <= 126]
    print(f"  | {len(pairs)} ASCII pairs, e.g.: {pairs[:3]}")

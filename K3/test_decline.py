"""Find which 7-letter word fits P3[3031:3038] given confirmed I=3035, E=3037."""
import json, sys
sys.path.insert(0, 'K3')
from help_methods import load_ciphertexts

state = json.load(open('K3/state.json'))
key = state.get('key', [])
ct = load_ciphertexts('K3/2026_02_24_10_27_04_Анна_Казакевич_task.txt')
xor02 = bytes(a^b for a,b in zip(ct[0], ct[2]))
xor12 = bytes(a^b for a,b in zip(ct[1], ct[2]))

known = sum(1 for k in key if k is not None)
print(f'Key: {known}/{len(key)} known ({100*known/len(key):.1f}%)')

allowed_p1 = set('abcdefghijklmnopqrstuvwxyz .,;:!?"\'-()\n\r\t')
allowed_p2 = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,;:!?"\'-()\n\r\t')

def test_word(word, start_pos):
    chars_p1, chars_p2 = [], []
    for offset, ch in enumerate(word):
        pos = start_pos + offset
        p1c = chr(ord(ch) ^ xor02[pos])
        p2c = chr(ord(ch) ^ xor12[pos])
        if p1c not in allowed_p1 or p2c not in allowed_p2:
            return None, None
        chars_p1.append(p1c)
        chars_p2.append(p2c)
    return ''.join(chars_p1), ''.join(chars_p2)

# Test drama stage direction words with I at position 4 (0-indexed), E at position 6
print('\n=== 7-letter words with I at pos 5, E at pos 7 (after A SLIGHT [space]) ===')
candidates = [
    'DECLINE', 'RECLINE', 'INCLINE', 'COMBINE', 'CONFINE', 'IMAGINE',
    'SURVIVE', 'AIRLINE', 'SUBLIME', 'COMPILE', 'REFINES', 'ANTINE',
    'DORMICE', 'PRECISE', 'REALISE', 'CONCISE', 'PREMISE', 'SUNRISE',
    'EXCLAIM', 'SUFFICE', 'SERVICE', 'PROMISE', 'JUSTICE', 'DESPISE',
    'ADMIRES', 'EXPIRES', 'IMPLIES', 'REPLIES', 'APPLIES', 'DEFYING',
    'RETICLE', 'VEHICLE', 'ARTICLE', 'CUBICLE', 'RADICAL', 'CLASSIC',
    'DYNAMIC', 'LACONIC', 'DEMONIC', 'MORONIC', 'CHRONIC', 'LACONIC',
    'SATIRIC', 'ROBOTIC', 'AQUATIC', 'FANATIC', 'LUNATIC', 'ERRATIC',
]
for word in candidates:
    if len(word) != 7: continue
    if word[4] != 'I': continue  # I at position 4 (0-indexed)
    if word[6] != 'E': continue  # E at position 6 (0-indexed)
    p1s, p2s = test_word(word, 3031)
    if p1s is not None:
        print(f'  VALID: P3={word}  P1={p1s!r}  P2={p2s!r}')

# Also try all 7-letter combos where pos 4=I, pos 6=E, brute force
print('\n=== Brute-force 7-letter patterns (valid I@4, E@6) at 3031 ===')
found = []
for c0 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ':
    for c1 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ':
        for c2 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ':
            for c3 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ':
                word = c0 + c1 + c2 + c3 + 'I' + '?' + 'E'
                for c5 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ':
                    w = c0 + c1 + c2 + c3 + 'I' + c5 + 'E'
                    p1s, p2s = test_word(w, 3031)
                    if p1s is not None:
                        found.append((w, p1s, p2s))

print(f'Found {len(found)} valid 7-char combinations.')
print('First 20:')
for w, p1s, p2s in found[:20]:
    print(f'  P3={w}  P1={p1s!r}  P2={p2s!r}')

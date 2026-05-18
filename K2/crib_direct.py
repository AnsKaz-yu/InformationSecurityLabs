"""
Прямой подход к K2: используем crib drag для построения частичного ключа,
потом расширяем методом скользящего окна.
Не зависит от нормализации книг.
"""
import re, sys, json
from pathlib import Path
sys.path.insert(0, '.')
from K2.state_manager import load_state

ct, _ = load_state(r'K2\state.json')
ct1, ct2 = ct[0], ct[1]
N = len(ct1)
xor12 = bytes(a^b for a,b in zip(ct1, ct2))

print(f"CT length: {N}")
print(f"xor12[0:5] = {list(xor12[:5])}")

# Шаг 1: построить ключ через crib drag
# key[i] = ct1[i] XOR P1[i] = ct2[i] XOR P2[i]
key = [None] * N  # None = неизвестно

def apply_crib_to_ct1(crib, pos):
    """Если crib = P1[pos:pos+len(crib)], вычисляем key и P2."""
    key_bytes = bytes(ct1[pos+i] ^ ord(c) for i, c in enumerate(crib))
    p2_bytes = bytes(ct2[pos+i] ^ key_bytes[i] for i in range(len(crib)))
    p2_text = ''.join(chr(b) if 32<=b<=126 else f'[{b}]' for b in p2_bytes)
    return key_bytes, p2_text

def apply_crib_to_ct2(crib, pos):
    """Если crib = P2[pos:pos+len(crib)], вычисляем key и P1."""
    key_bytes = bytes(ct2[pos+i] ^ ord(c) for i, c in enumerate(crib))
    p1_bytes = bytes(ct1[pos+i] ^ key_bytes[i] for i in range(len(crib)))
    p1_text = ''.join(chr(b) if 32<=b<=126 else f'[{b}]' for b in p1_bytes)
    return key_bytes, p1_text

# Проверяем оба сценария для crib 'Mr. Pickwick said' at pos 10
print("\n=== Crib 'Mr. Pickwick said' at pos 10 ===")
crib = 'Mr. Pickwick said'
k1, p2_if_pp1 = apply_crib_to_ct1(crib, 10)
print(f"Scenario A (CT1 has 'Mr. Pickwick said'): P2[10:27] = {repr(p2_if_pp1)}")
k2, p1_if_pp2 = apply_crib_to_ct2(crib, 10)
print(f"Scenario B (CT2 has 'Mr. Pickwick said'): P1[10:27] = {repr(p1_if_pp2)}")

# Оба должны давать 'tually threw h...' (если crib верен)
# В сценарии A: P2[10:27] = 'tually threw hdag' (ожидается)
# В сценарии B: P1[10:27] = 'tually threw hdag' (ожидается)
# Оба верны - XOR симметричен!

# Шаг 2: для обоих сценариев расширяем ключ контекстом
# Зная key[10:27], можно расшифровать CT1[0:40] и CT2[0:40]
print("\n=== Расширение ключа из позиций 10:27 ===")

def decode_with_partial_key(ct_stream, k_bytes, pos, context_left=20, context_right=20):
    """Декодирует CT используя k_bytes в позициях [pos:pos+len(k_bytes)]."""
    result = []
    for i in range(pos - context_left, pos + len(k_bytes) + context_right):
        if i < 0 or i >= N: continue
        if pos <= i < pos + len(k_bytes):
            ki = k_bytes[i - pos]
            b = ct_stream[i] ^ ki
            result.append(chr(b) if 32<=b<=126 else f'[{b}]')
        else:
            result.append('_')
    return ''.join(result)

# Сценарий A: key[10:27] из CT1='Mr. Pickwick said'
print("\nScenario A (CT1=PP, key from 'Mr. Pickwick said'):")
p1_context = decode_with_partial_key(ct1, k1, 10)
p2_context = decode_with_partial_key(ct2, k1, 10)
print(f"  P1[0:47] = {repr(p1_context)}")
print(f"  P2[0:47] = {repr(p2_context)}")

# Сценарий B: key[10:27] из CT2='Mr. Pickwick said'
print("\nScenario B (CT2=PP, key from 'Mr. Pickwick said'):")
p1_context_b = decode_with_partial_key(ct1, k2, 10)
p2_context_b = decode_with_partial_key(ct2, k2, 10)
print(f"  P1[0:47] = {repr(p1_context_b)}")
print(f"  P2[0:47] = {repr(p2_context_b)}")

# Шаг 3: используем другие cribs для расширения
print("\n=== Используем второй crib: 'Mr. Brownlow' at pos 18027 ===")
crib2 = 'Mr. Brownlow'
k_a2, p2_a2 = apply_crib_to_ct1(crib2, 18027)
k_b2, p1_b2 = apply_crib_to_ct2(crib2, 18027)
print(f"Scenario A (CT1='Mr. Brownlow'[18027]): P2[18027:18039] = {repr(p2_a2)}")
print(f"Scenario B (CT2='Mr. Brownlow'[18027]): P1[18027:18039] = {repr(p1_b2)}")

# Проверяем совместность Scenarios:
# Сценарий A-A: CT1=PP ('Mr. Pickwick said'@10) И CT1=OT ('Mr. Brownlow'@18027)
#   Противоречие! CT1 не может быть и PP и OT
# Сценарий A-B: CT1='Mr. Pickwick said'@10, CT2='Mr. Brownlow'@18027
#   CT1=PP, CT2=OT → PP at pos 10, OT at pos 18027
# Сценарий B-A: CT2='Mr. Pickwick said'@10, CT1='Mr. Brownlow'@18027  
#   CT2=PP, CT1=OT
# Проверяем ключи на совместность в позициях 10-26 и 18027-18038

print("\n=== Совместность сценариев ===")
# Сценарий A-B: CT1=PP, CT2=OT
# key[10:27] из CT1='Mr. Pickwick said'
# key[18027:18039] из CT2='Mr. Brownlow' (Scenario B)
print("Scenario A-B (CT1=PP, CT2=OT):")
print(f"  key[10:20] = {list(k1[:10])}")
print(f"  key[18027:18037] = {list(k_b2[:10])}")
# Decode with BOTH key fragments
# P1 around pos 0-30:
p1_ab_0 = decode_with_partial_key(ct1, k1, 10, context_left=10, context_right=10)
print(f"  P1[0:37] (from crib1): {repr(p1_ab_0)}")
p2_ab_0 = decode_with_partial_key(ct2, k1, 10, context_left=10, context_right=10)
print(f"  P2[0:37] (from crib1): {repr(p2_ab_0)}")
# P1 and P2 around 18027:
p1_ab_18 = decode_with_partial_key(ct1, k_b2, 18027, context_left=10, context_right=10)
print(f"  P1[18017:18049] (from crib2): {repr(p1_ab_18)}")
p2_ab_18 = decode_with_partial_key(ct2, k_b2, 18027, context_left=10, context_right=10)
print(f"  P2[18017:18049] (from crib2): {repr(p2_ab_18)}")

print("\nScenario B-A (CT2=PP, CT1=OT):")
p1_ba_0 = decode_with_partial_key(ct1, k2, 10, context_left=10, context_right=10)
print(f"  P1[0:37] (from crib1): {repr(p1_ba_0)}")
p2_ba_0 = decode_with_partial_key(ct2, k2, 10, context_left=10, context_right=10)
print(f"  P2[0:37] (from crib1): {repr(p2_ba_0)}")
p1_ba_18 = decode_with_partial_key(ct1, k_a2, 18027, context_left=10, context_right=10)
print(f"  P1[18017:18049] (from crib2): {repr(p1_ba_18)}")
p2_ba_18 = decode_with_partial_key(ct2, k_a2, 18027, context_left=10, context_right=10)
print(f"  P2[18017:18049] (from crib2): {repr(p2_ba_18)}")

# Шаг 4: Систематический поиск всех criba в xor12 
print("\n=== Автоматический crib drag по всем позициям ===")
def auto_crib_drag(cribs, min_letter_ratio=0.7, verbose=True):
    """Ищем все позиции где любой crib даёт читаемый контекст."""
    all_hits = []
    for crib in cribs:
        n = len(crib)
        crib_b = crib.encode('ascii')
        for pos in range(N - n + 1):
            # other_stream = xor12 XOR crib
            other_bytes = bytes(xor12[pos+i] ^ crib_b[i] for i in range(n))
            if all(32 <= b <= 126 for b in other_bytes):
                other_text = other_bytes.decode('ascii')
                # Score: letter+space ratio
                score = sum(1 for c in other_text if c.isalpha() or c==' ') / n
                if score >= min_letter_ratio:
                    all_hits.append((score, pos, crib, other_text))
    all_hits.sort(key=lambda x: (-x[0], x[1]))
    return all_hits

# Common Dickens phrases for crib drag
cribs = [
    'Mr. Pickwick ', 'Mr. Winkle ', 'Mr. Weller ', 'Mr. Tupman ',
    'Mr. Brownlow', 'Oliver Twist', 'Mr. Bumble ', 'Mr. Fagin',
    ' the old gen', 'said Mr. Pic', 'replied Mr.',
    ' he said, ',  ' she said, ', '"I am ',
    'said the ',   'replied the ', 'observed the',
]
hits = auto_crib_drag(cribs, min_letter_ratio=0.75, verbose=False)
print(f"\nНайдено {len(hits)} crib hits с ratio >= 0.75:")
for score, pos, crib, other in hits[:30]:
    print(f"  pos={pos:5d}: '{crib}' → '{other}' (score={score:.2f})")

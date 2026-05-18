"""
Crib drag с уникальными PP и OT фразами - определяем точные смещения.
Ищем все позиции, строим карту key bytes.
"""
import re, sys
sys.path.insert(0, '.')
from K2.state_manager import load_state

ct, _ = load_state(r'K2\state.json')
ct1, ct2 = ct[0], ct[1]
N = len(ct1)
xor12 = bytes(a^b for a,b in zip(ct1, ct2))

def norm(t):
    t = t.replace('\r\n','\n').replace('\r','\n')
    t = re.sub(r'\n\n+',' ',t); t = t.replace('\n',' ')
    t = t.replace('\u2018',"'").replace('\u2019',"'")
    t = t.replace('\u201c','"').replace('\u201d','"')
    t = t.replace('\u2013','-').replace('\u2014','--')
    t = t.replace('\u2026','...')
    return t

print("Загружаю книги...")
with open(r"K3\Dickens Charles. The Pickwick Papers - royallib.ru.txt", encoding='cp1251') as f:
    pp = norm(f.read())
with open(r"K3\Oliver Twist (1).txt", encoding='utf-8') as f:
    ot = norm(f.read())
print(f"PP: {len(pp):,} OT: {len(ot):,}")

def find_all(text, substr):
    results = []
    pos = 0
    while True:
        idx = text.find(substr, pos)
        if idx == -1: break
        results.append(idx)
        pos = idx + 1
    return results

# ── Уникальные PP фразы ─────────────────────────────────────────────────────
pp_phrases = [
    'Mr. Weller',
    'Sam Weller',
    'Mr. Pickwick',
    'Mr. Tupman',
    'Mr. Snodgrass',
    'Mr. Winkle',
    'Mrs. Bardell',
    'Dodson & Fogg',
    'Sergeant Snubbin',
    'Mr. Jingle',
    'Buzfuz',
    'Tony Weller',
]
# ── Уникальные OT фразы ─────────────────────────────────────────────────────
ot_phrases = [
    'Mr. Bumble',
    'Mr. Brownlow',
    'Fagin',
    'Oliver Twist',
    'Bill Sikes',
    'the Artful',
    'the workhouse',
    'Charley Bates',
    'Mr. Losberne',
    'Mr. Grimwig',
    'Monks',
    'Nancy',
]

# ── Crib drag ────────────────────────────────────────────────────────────────
def crib_result(crib_text, pos):
    """Other stream text if crib_text appears in one stream at pos."""
    n = len(crib_text)
    other = bytes(xor12[pos+i] ^ ord(crib_text[i]) for i in range(n))
    return other

def is_english(b):
    """All bytes printable AND letter-rich."""
    if not all(32<=x<=126 for x in b): return False
    letters = sum(1 for x in b if (65<=x<=90 or 97<=x<=122))
    spaces = sum(1 for x in b if x==32)
    return (letters + spaces) / len(b) >= 0.65

print("\n=== Поиск уникальных PP фраз в CT ===")
pp_hits = {}  # phrase → [(ct_pos, other_text)]
for phrase in pp_phrases:
    if not phrase.isascii(): continue
    n = len(phrase)
    hits = []
    for pos in range(N - n + 1):
        other = crib_result(phrase, pos)
        if is_english(other):
            hits.append((pos, other.decode('ascii')))
    if hits:
        pp_hits[phrase] = hits
        print(f"  '{phrase}': {len(hits)} hits")
        for pos, other in hits[:5]:
            print(f"    CT pos={pos}: → '{other}'")

print("\n=== Поиск уникальных OT фраз в CT ===")
ot_hits = {}
for phrase in ot_phrases:
    if not phrase.isascii(): continue
    n = len(phrase)
    hits = []
    for pos in range(N - n + 1):
        other = crib_result(phrase, pos)
        if is_english(other):
            hits.append((pos, other.decode('ascii')))
    if hits:
        ot_hits[phrase] = hits
        print(f"  '{phrase}': {len(hits)} hits")
        for pos, other in hits[:5]:
            print(f"    CT pos={pos}: → '{other}'")

# ── Кросс-верификация: если PP phrase at CT pos, found "other" must be in OT ─
print("\n=== Кросс-верификация: PP crib → other должна быть в OT ===")
confirmed_pp_cribs = []
for phrase, hits in pp_hits.items():
    n_phrase = len(phrase)
    for ct_pos, other_text in hits:
        # Ищем other_text в OT (и PP для исключения)
        in_ot = other_text in ot
        in_pp = other_text in pp
        if in_ot and not in_pp:
            quality = 'OT_ONLY'
        elif in_ot:
            quality = 'OT+PP'
        elif in_pp:
            quality = 'PP_ONLY'
        else:
            quality = 'NOWHERE'
        
        if in_ot:  # Если other_text есть в OT - хороший кандидат
            ot_pos_list = find_all(ot, other_text)
            for ot_pos in ot_pos_list[:3]:
                ot_off = ot_pos - ct_pos
                if ot_off < 0: continue
                pp_pos_list = find_all(pp, phrase)
                for pp_pos in pp_pos_list[:3]:
                    pp_off = pp_pos - ct_pos
                    if pp_off < 0: continue
                    confirmed_pp_cribs.append({
                        'pp_phrase': phrase, 'ot_phrase': other_text,
                        'ct_pos': ct_pos, 'pp_pos': pp_pos, 'ot_pos': ot_pos,
                        'pp_off': pp_off, 'ot_off': ot_off,
                        'quality': quality
                    })
        
        if not in_ot and not in_pp:
            print(f"  '{phrase}'@{ct_pos} → '{other_text}' [{quality}]")

# ── Выводим совместных кандидатов ────────────────────────────────────────────
print("\n=== Совместные кандидаты (PP phrase ↔ OT text) ===")
for c in confirmed_pp_cribs[:20]:
    print(f"  pp_off={c['pp_off']:7d} ot_off={c['ot_off']:7d} | '{c['pp_phrase']}' @ CT {c['ct_pos']:5d} ↔ '{c['ot_phrase']}'")

# ── Группируем по (pp_off, ot_off) ──────────────────────────────────────────
from collections import defaultdict
pair_votes = defaultdict(list)
for c in confirmed_pp_cribs:
    pair_votes[(c['pp_off'], c['ot_off'])].append(c)

print("\n=== Голосование за пары (pp_off, ot_off) ===")
for (pp_off, ot_off), votes in sorted(pair_votes.items(), key=lambda x: -len(x[1])):
    print(f"  PP_OFF={pp_off:7d} OT_OFF={ot_off:7d}: {len(votes)} votes")
    for v in votes[:3]:
        print(f"    '{v['pp_phrase']}' @ CT {v['ct_pos']:5d}")

# ── То же самое для OT cribs ────────────────────────────────────────────────
print("\n=== Кросс-верификация: OT crib → other должна быть в PP ===")
confirmed_ot_cribs = []
for phrase, hits in ot_hits.items():
    for ct_pos, other_text in hits:
        in_pp = other_text in pp
        if in_pp:
            pp_pos_list = find_all(pp, other_text)
            ot_pos_list = find_all(ot, phrase)
            for ot_pos in ot_pos_list[:3]:
                for pp_pos in pp_pos_list[:3]:
                    ot_off = ot_pos - ct_pos
                    pp_off = pp_pos - ct_pos
                    if ot_off >= 0 and pp_off >= 0:
                        confirmed_ot_cribs.append({
                            'ot_phrase': phrase, 'pp_phrase': other_text,
                            'ct_pos': ct_pos, 'pp_pos': pp_pos, 'ot_pos': ot_pos,
                            'pp_off': pp_off, 'ot_off': ot_off,
                        })

print(f"\nOT→PP совместных кандидатов: {len(confirmed_ot_cribs)}")
ot_pair_votes = defaultdict(list)
for c in confirmed_ot_cribs:
    ot_pair_votes[(c['pp_off'], c['ot_off'])].append(c)

for (pp_off, ot_off), votes in sorted(ot_pair_votes.items(), key=lambda x: -len(x[1]))[:10]:
    print(f"  PP_OFF={pp_off:7d} OT_OFF={ot_off:7d}: {len(votes)} votes")
    for v in votes[:2]:
        print(f"    OT:'{v['ot_phrase']}' ↔ PP:'{v['pp_phrase']}' @ CT {v['ct_pos']:5d}")

# ── Объединяем все голоса ────────────────────────────────────────────────────
all_votes = defaultdict(int)
for k, v in pair_votes.items():
    all_votes[k] += len(v)
for k, v in ot_pair_votes.items():
    all_votes[k] += len(v)

print("\n=== ИТОГОВЫЕ ПАРЫ по голосам ===")
for (pp_off, ot_off), votes in sorted(all_votes.items(), key=lambda x: -x[1])[:10]:
    print(f"  PP_OFF={pp_off:7d} OT_OFF={ot_off:7d}: {votes} голосов")

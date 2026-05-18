"""
K2 - Crib-drag analysis: try known English phrases to locate text fragments.
Uses K3 reference books (Pickwick Papers, Oliver Twist) for matching.
"""
import json, base64, re
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
N = len(ct1)
xor12 = bytes(a^b for a,b in zip(ct1, ct2))

def norm_old(t):
    t = t.replace('\r\n', '\n').replace('\r', '\n')
    t = re.sub(r'\n\n+', ' ', t)
    t = t.replace('\n', ' ')
    t = t.replace('\u2018', "'").replace('\u2019', "'")
    t = t.replace('\u201c', '"').replace('\u201d', '"')
    t = t.replace('\u2013', '-').replace('\u2014', '--')
    t = t.replace('\u2026', '...')
    return t

def crib_drag(crib, top_n=10):
    """Find all positions where crib in P1 gives readable P2 (and vice versa)."""
    crib_bytes = crib.encode('ascii')
    n = len(crib_bytes)
    results = []
    
    for pos in range(N - n + 1):
        xor_slice = xor12[pos:pos+n]
        # P2 if P1=crib at pos
        p2_bytes = bytes(xor_slice[i] ^ crib_bytes[i] for i in range(n))
        if all(32 <= b <= 126 for b in p2_bytes):
            p2_text = p2_bytes.decode('ascii')
            # Score based on letter/space ratio
            score = sum(1 for c in p2_text if c.isalpha() or c == ' ')
            results.append((score, pos, 1, p2_text, crib))
    
    results.sort(reverse=True)
    return results[:top_n]

# Try common English phrases that appear in Dickens
cribs = [
    " the ",
    " of the ",
    " and ",
    " he ",
    " was ",
    " his ",
    " that ",
    " with ",
    " said ",
    "Mr. Pickwick",
    "Mr. Winkle",
    "Mr. Weller",
    "Mr. Tupman",
    " Oliver ",
    "Oliver Twist",
    "Mr. Bumble",
    "Fagin",
    "Mr. Brownlow",
    " replied ",
    " observed ",
    " exclaimed ",
    " remarked ",
    "the old gentleman",
    "the young gentleman",
    "Mr. Pickwick said",
    " returned ",
]

print("=== Crib-drag results ===")
print(f"XOR length: {N}")

all_results = []
for crib in cribs:
    hits = crib_drag(crib, top_n=5)
    for score, pos, direction, other_text, used_crib in hits:
        if score >= len(crib) * 0.7:  # At least 70% letters/spaces
            all_results.append((score, pos, used_crib, other_text))

all_results.sort(reverse=True)

print(f"\nBest crib hits (score >= 70% letters/spaces):")
for score, pos, crib, other in all_results[:30]:
    print(f"  pos={pos:5d} score={score:3d}/{len(crib):2d} | crib='{crib}' -> other='{other}'")

# Also try automatic: for each position, assume p1[i]=' ' and see what p2[i] is
# Chain spaces: find runs where assuming P1 has spaces gives P2 as readable English
print("\n\n=== Space-XOR analysis (assuming P1 has spaces) ===")
p2_if_p1_space = bytes(b ^ 0x20 for b in xor12)
# Find runs of printable ASCII in p2_if_p1_space
best_runs = []
i = 0
while i < N:
    if 32 <= p2_if_p1_space[i] <= 126:
        j = i
        while j < N and 32 <= p2_if_p1_space[j] <= 126:
            j += 1
        run_len = j - i
        if run_len >= 8:
            text = p2_if_p1_space[i:j].decode('ascii')
            alpha = sum(1 for c in text if c.isalpha())
            score = alpha / run_len
            if score >= 0.5:
                best_runs.append((score, run_len, i, text))
        i = j
    else:
        i += 1

best_runs.sort(reverse=True)
print(f"Top runs where P1=spaces gives readable P2:")
for score, run_len, pos, text in best_runs[:15]:
    print(f"  pos={pos:5d} len={run_len:3d} score={score:.2f} | '{text[:60]}'")

# Better approach: XOR histogram to identify key bytes
# In Vernam P1 XOR P2 = C1 XOR C2
# Most frequent characters in English text: space (freq~13%), then e,t,a,o,i,n,s,h,r
# If we know the distribution of P1, we can attack

# Try to find where BOTH texts have letters using XOR pattern
# letter XOR letter: if both uppercase/lowercase, XOR is in 0x00-0x3F range
print("\n\n=== Positional analysis ===")
# Count positions where XOR suggests two letters
letter_xor_count = 0
space_letter_count = 0
for b in xor12:
    # letter XOR letter = small value or in specific range
    if b < 0x3F and b != 0:
        letter_xor_count += 1
    # space XOR letter = 0x41-0x7A
    if 0x41 <= b <= 0x7A:
        space_letter_count += 1
print(f"XOR < 0x3F (non-zero): {letter_xor_count} (letter^letter or ctrl chars)")
print(f"XOR 0x41-0x7A (space^letter): {space_letter_count}")

# Try to find common book texts by XOR-ing with Pickwick Papers and Oliver Twist  
print("\n\n=== Searching for text in K3 books ===")

# Load K3 books
pp_path = Path(r"K3\Dickens Charles. The Pickwick Papers - royallib.ru.txt")
ot_path = Path(r"K3\Oliver Twist (1).txt")

if pp_path.exists():
    pp_raw = pp_path.read_bytes().decode('cp1251')
    pp = norm_old(pp_raw)
    print(f"PP loaded: {len(pp)} chars")
else:
    pp = None
    print("PP not found")
    
if ot_path.exists():
    ot_raw = ot_path.read_text(encoding='utf-8')
    ot = norm_old(ot_raw)
    print(f"OT loaded: {len(ot)} chars")
else:
    ot = None
    print("OT not found")

# Try sliding window: XOR ct1 with PP fragment and check if ct2 decodes to readable English
def try_reference_at_offset(ct, ref_text, ref_offset, ct_offset, window=80):
    """Try applying ref_text[ref_offset:] as P1 starting at ct_offset."""
    good = 0
    total = 0
    for i in range(window):
        cp = ct_offset + i
        rp = ref_offset + i
        if cp >= len(ct[0]) or rp >= len(ref_text): break
        rc = ref_text[rp]
        if ord(rc) > 127: continue  # skip non-ASCII
        key_b = ct[0][cp] ^ ord(rc)
        p2_b = ct[1][cp] ^ key_b
        if 32 <= p2_b <= 126:
            good += 1
        total += 1
    return good, total

if pp is not None:
    print("\nSearching PP in CT1 (checking if CT2 gives valid ASCII)...")
    # Try 1000 random offsets in PP for CT1[0:80]
    best_pp = []
    step = 100  # check every 100 chars in PP
    for rp in range(0, len(pp) - 80, step):
        # Check if PP[rp:rp+20] XOR ct1[0:20] = key, then ct2[0:20] XOR key readable
        # Only try if PP[rp:rp+20] is all ASCII printable
        fragment = pp[rp:rp+20]
        if not all(ord(c) < 128 and 32 <= ord(c) <= 126 for c in fragment):
            continue
        good, total = try_reference_at_offset(ct, pp, rp, 0, 20)
        if total > 0 and good/total >= 0.9:
            best_pp.append((good/total, rp, pp[rp:rp+40]))
    
    best_pp.sort(reverse=True)
    print(f"Found {len(best_pp)} candidate PP offsets for CT1[0]:")
    for score, rp, frag in best_pp[:10]:
        print(f"  PP[{rp}]: score={score:.2f} | '{frag[:40]}'")

    # Broader search: try all CT positions vs PP
    print("\nBroader search (CT1 pos vs PP, window=40)...")
    best_broad = []
    for ct_start in range(0, 200, 10):  # sample CT positions
        for pp_start in range(0, min(len(pp)-40, 500000), 500):
            fragment = pp[pp_start:pp_start+40]
            if not all(ord(c) < 128 for c in fragment): continue
            good, total = try_reference_at_offset(ct, pp, pp_start, ct_start, 40)
            if total >= 35 and good/total >= 0.95:
                best_broad.append((good, total, ct_start, pp_start, pp[pp_start:pp_start+50]))
    
    best_broad.sort(reverse=True)
    print(f"Best broad matches:")
    for good, total, ct_pos, pp_pos, frag in best_broad[:10]:
        print(f"  CT[{ct_pos}] ~ PP[{pp_pos}]: {good}/{total} | '{frag[:50]}'")

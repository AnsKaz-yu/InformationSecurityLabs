"""
Тест разных нормализаций: double-dash vs single-dash для em-dash
"""
import re, sys
sys.path.insert(0, '.')
from K2.state_manager import load_state

ct, _ = load_state(r'K2\state.json')
ct1, ct2 = ct[0], ct[1]
N = len(ct1)
xor12 = bytes(a^b for a,b in zip(ct1, ct2))

def norm_dd(t):  # double-dash (state_manager.norm_old)
    t = t.replace('\r\n','\n').replace('\r','\n')
    t = re.sub(r'\n\n+',' ',t); t = t.replace('\n',' ')
    t = t.replace('\u2018',"'").replace('\u2019',"'")
    t = t.replace('\u201c','"').replace('\u201d','"')
    t = t.replace('\u2013','-').replace('\u2014','--')
    t = t.replace('\u2026','...')
    return t

def norm_sd(t):  # single-dash (help_methods)
    t = t.replace('\r\n','\n').replace('\r','\n')
    t = re.sub(r'\n\n+',' ',t); t = t.replace('\n',' ')
    t = t.replace('\u2018',"'").replace('\u2019',"'")
    t = t.replace('\u201c','"').replace('\u201d','"')
    t = t.replace('\u2013','-').replace('\u2014','-')
    t = t.replace('\u2026','...')
    return t

with open(r"K3\Dickens Charles. The Pickwick Papers - royallib.ru.txt", encoding='cp1251') as f:
    pp_raw = f.read()
with open(r"K3\Oliver Twist (1).txt", encoding='utf-8') as f:
    ot_raw = f.read()

pp_dd = norm_dd(pp_raw)
pp_sd = norm_sd(pp_raw)
ot_dd = norm_dd(ot_raw)
ot_sd = norm_sd(ot_raw)

# Find pp_off in each normalization by searching 'progress. Mr. Pickwick'
probe = 'progress. Mr. Pickwick'
pp_dd_off = pp_dd.find(probe)
pp_sd_off = pp_sd.find(probe)
print(f"'progress. Mr. Pickwick' in PP_dd: pos={pp_dd_off}")
print(f"'progress. Mr. Pickwick' in PP_sd: pos={pp_sd_off}")

# Find ot_off in each normalization by searching 'tually threw himself'
probe2 = 'tually threw himself'
ot_dd_pos = ot_dd.find(probe2)
ot_sd_pos = ot_sd.find(probe2)
ot_off_dd = ot_dd_pos - 10  # 'ac' is 10 chars before 'tually'
ot_off_sd = ot_sd_pos - 10
print(f"\n'tually threw himself' in OT_dd: pos={ot_dd_pos} -> ot_off={ot_off_dd}")
print(f"'tually threw himself' in OT_sd: pos={ot_sd_pos} -> ot_off={ot_off_sd}")

# Check first em-dash position in each book at the offsets
def first_emdash(s, off, n=500):
    for i in range(min(n, len(s)-off)):
        if s[off+i] == '-' and off+i+1 < len(s) and s[off+i+1] == '-':
            return i
    return -1

print(f"\nFirst '--' in PP_dd[{pp_dd_off}:]: pos {first_emdash(pp_dd, pp_dd_off)}")
print(f"First '--' in OT_dd[{ot_off_dd}:]: pos {first_emdash(ot_dd, ot_off_dd)}")

# Now test all 4 normalization combos
def match_rate(pp, pp_off, ot, ot_off):
    total = min(N, len(pp)-pp_off, len(ot)-ot_off)
    matches = sum(1 for i in range(total)
                  if ord(pp[pp_off+i]) <= 127 and ord(ot[ot_off+i]) <= 127
                  and (ord(pp[pp_off+i]) ^ ord(ot[ot_off+i])) == xor12[i])
    ascii_total = sum(1 for i in range(total)
                      if ord(pp[pp_off+i]) <= 127 and ord(ot[ot_off+i]) <= 127)
    return matches, ascii_total

print("\n=== Тест нормализаций (pp_off, ot_off из 'progress. Mr. Pickwick' и 'tually threw') ===")
combos = [
    ('dd','dd', pp_dd, pp_dd_off, ot_dd, ot_off_dd),
    ('dd','sd', pp_dd, pp_dd_off, ot_sd, ot_off_sd),
    ('sd','dd', pp_sd, pp_sd_off, ot_dd, ot_off_dd),
    ('sd','sd', pp_sd, pp_sd_off, ot_sd, ot_off_sd),
]

for pp_norm, ot_norm, pp, pp_off, ot, ot_off in combos:
    m, a = match_rate(pp, pp_off, ot, ot_off)
    print(f"  PP_norm={pp_norm}, OT_norm={ot_norm}: matches={m}/{a} = {m/a:.4f} ({m/a*100:.2f}%)")
    print(f"    PP[{pp_off}:{pp_off+80}] = {repr(pp[pp_off:pp_off+80])}")

# Also: find where exactly mismatch starts for best combo
print("\n=== Детальный анализ первых 500 позиций (dd/dd) ===")
pp_off = pp_dd_off
ot_off = ot_off_dd
pp = pp_dd
ot = ot_dd
first_mismatch = -1
for i in range(min(500, N, len(pp)-pp_off, len(ot)-ot_off)):
    pc = ord(pp[pp_off+i])
    oc = ord(ot[ot_off+i])
    if pc > 127 or oc > 127:
        print(f"  pos {i}: non-ASCII pp={pc} ot={oc}")
        break
    computed = pc ^ oc
    if computed != xor12[i]:
        if first_mismatch < 0:
            first_mismatch = i
            print(f"First mismatch at pos {i}:")
            print(f"  PP[{pp_off+i}]='{pp[pp_off+i]}'({pc}), OT[{ot_off+i}]='{ot[ot_off+i]}'({oc})")
            print(f"  Computed: {computed}, xor12[{i}]={xor12[i]}")
            print(f"  PP context [{pp_off+i-5}:{pp_off+i+20}] = {repr(pp[pp_off+i-5:pp_off+i+20])}")
            print(f"  OT context [{ot_off+i-5}:{ot_off+i+20}] = {repr(ot[ot_off+i-5:ot_off+i+20])}")

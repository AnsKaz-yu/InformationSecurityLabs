import sys; sys.path.insert(0,'.')
from K2.state_manager import load_state

ct, _ = load_state(r'K2\state.json')
ct1, ct2 = ct[0], ct[1]
xor12 = bytes(a^b for a,b in zip(ct1,ct2))
print(f'CT length: {len(ct1)}')
print(f'xor12[0:20] = {list(xor12[0:20])}')
print(f'max(xor12) = {max(xor12)} (should be <128 for pure 7-bit ASCII plaintexts)')
print(f'Fraction >=128: {sum(1 for x in xor12 if x>=128)/len(xor12):.4f}')

# Check position 18027
x18027 = xor12[18027]
print(f'\nxor12[18027] = {x18027} = {repr(chr(x18027))}')
expected = ord('M') ^ ord(' ')
print(f'Expected (Mr.Brownlow ^ space): {expected} = {repr(chr(expected))}')
match = (x18027 == expected)
print(f'Match at 18027: {match}')

# Decode xor12[18027:18039] with Mr. Brownlow
crib = 'Mr. Brownlow'
decoded = ''.join(chr(xor12[18027+k] ^ ord(crib[k])) for k in range(len(crib)))
print(f'\nxor12[18027:18039] XOR "Mr. Brownlow" = {repr(decoded)}')

# Also try pos=10 with Mr. Pickwick said
crib2 = 'Mr. Pickwick said'
decoded2 = ''.join(chr(xor12[10+k] ^ ord(crib2[k])) for k in range(len(crib2)))
print(f'xor12[10:27] XOR "Mr. Pickwick said" = {repr(decoded2)}')

# Check some actual positions
print(f'\nxor12 full range stats:')
print(f'  Values 0-31 (control): {sum(1 for x in xor12 if x<32)}')
print(f'  Values 32-126 (printable): {sum(1 for x in xor12 if 32<=x<=126)}')
print(f'  Values 127-255 (high): {sum(1 for x in xor12 if x>126)}')

# Show first 100 as chars where printable
printable_xor = ''.join(chr(x) if 32<=x<=126 else '.' for x in xor12[:100])
print(f'\nFirst 100 of xor12 (. = non-printable): {repr(printable_xor)}')

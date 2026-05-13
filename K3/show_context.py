"""Show confirmed-key decoded context for all 3 plaintexts at a range of positions."""
import json, sys
from pathlib import Path
sys.path.insert(0, 'K3')
from help_methods import load_ciphertexts

state = json.load(open('K3/state.json'))
key = state.get('key', [])
ct = load_ciphertexts('K3/2026_02_24_10_27_04_Анна_Казакевич_task.txt')

def show_context(start, end):
    print(f'Positions {start}-{end}:')
    for label, ctxt in [('P1', ct[0]), ('P2', ct[1]), ('P3', ct[2])]:
        chars = []
        for i in range(start, end):
            k = key[i] if i < len(key) else None
            if k is not None:
                c = ctxt[i] ^ k
                chars.append(chr(c) if 32 <= c < 127 else '?')
            else:
                chars.append('_')
        print(f'  {label}: {"".join(chars)}')

show_context(2990, 3090)
print()
show_context(3090, 3180)

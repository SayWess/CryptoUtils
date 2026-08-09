from Faulty_AES import *
from AES_DFA_R9 import *
from AES_DFA_R8 import *
import os

#####################
# Attack on round 9 #
#####################
print("Attack on round 9")
KEY = os.urandom(16)
print(f'Key used: {KEY}')
print()
cipher = AES(KEY)
pt = b"A"*16

ct = cipher.encrypt_block(pt)

faults = [cipher.encrypt_block(pt, FAULTED=True, FAULTY_ROUND=-1) for _ in range(10)]

pairs = [(ct, faulty_ct) for faulty_ct in faults]
masterkeys = r9_key_recovery(pairs, (pt, ct))

#####################
# Attack on round 8 #
#####################
print("\n")
print("Attack on round 8")
KEY = os.urandom(16)
print(f'Key used: {KEY}')
print()
cipher = AES(KEY)
pt = b"A"*16

ct = cipher.encrypt_block(pt)

faults = [cipher.encrypt_block(pt, FAULTED=True, FAULTY_ROUND=-2) for _ in range(2)]

pairs = [(ct, faulty_ct) for faulty_ct in faults]
masterkeys = []
r8_key_recovery_multiple(pairs, (pt,ct))

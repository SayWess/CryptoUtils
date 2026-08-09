import os
from LED_faulty import LED
from math import log
import random as rd

# ----------------------
# Helpers
# ----------------------

def str_xor(a: bytes, b: bytes):
    return bytes([x^y for x,y in zip(a,b)])


def mix_single_column(col, matrix):
    mixed_col = []
    for i in range(4):
        val = 0
        for k in range(4):
            val ^= cipher.g_mul(matrix[i][k], col[k])
        mixed_col.append(val)
    
    return mixed_col

def g_mul(a: int, b: int):
    """Galois Field multiplication in GF(2^4) with poly x^4 + x + 1 (0x13)."""
    p = 0
    for _ in range(4):
        if b & 1: p ^= a
        hi = a & 0x8
        a <<= 1
        if hi: a ^= 0x13
        b >>= 1
    return p & 0xF


# ----------------------
# Fault Attack Recovery
# ----------------------


def get_fault_equation(ct, ct_faulted, key, line):
    """
                     AC                  SC                      SR                     MCS                      AD
    [4a, 2d, 2c, 1b] -> [4a, 2d, 2c, 1b] -> [q0, q1, q2, q3]     -> [q0, q1, q2, q3]     -> [p0, p1, p2, p3]     -> [c0, c1, c2, c3]
    [8a, 6d, 5c, 6b] -> [8a, 6d, 5c, 6b] -> [q4, q5, q6, q7]     -> [q5, q6, q7, q4]     -> [p4, p5, p6, p7]     -> [c4, c5, c6, c7]
    [Ba, 9d, Ac, Eb] -> [Ba, 9d, Ac, Eb] -> [q8, q9, q10, q11]   -> [q10, q11, q8, q9]   -> [p8, p9, p10, p11]   -> [c8, c9, c10, c11]
    [2a, Bd, Fc, 2b] -> [2a, Bd, Fc, 2b] -> [q12, q13, q14, q15] -> [q15, q12, q13, q14] -> [p12, p13, p14, p15] -> [c12, c13, c14, c15]

    If we want the equation for 4a: (the difference between the non faulted and the faulted byte)
    4a = inv_sbox(q0) ^ inv_sbox(q0') = inv_sbox(inv_mix_column([p0,p4,p8,p12])[0]) ^ inv_sbox(q0') # 3rd line of the product of inv_mds with the first column of the state after MCS 
    4a = inv_sbox(C*p0 + C*p4 + D*p8 + 4*p12) ^ ...
    4a = inv_sbox(C*(c0+k0) + C*(c4*k4) + D*(c8*k8) + 4*(c12*k12)) ^ ...

    If we want the equation for Ba:
    Ba = inv_sbox(q8) ^ inv_sbox(q8') = inv_sbox(inv_mix_column([p2,p6,p10,p14])[3]) ^ ... # 3rd line of the product of inv_mds with the 3rd column of the state after MCS 
    Ba = inv_sbox(7*p2 + 6*p6 + 2*p10 + E*p14) ^ ...
    Ba = inv_sbox(7*(c2+k2) + 6*(c6*k6) + 2*(c10*k10) + E*(c14*k14)) ^ ...
    """
    inv_mds = [
        [0xC, 0xC, 0xD, 0x4],
        [0x3, 0x8, 0x4, 0x5],
        [0x7, 0x6, 0x2, 0xE],
        [0xD, 0x9, 0x9, 0xD]
    ]

    s1 = 0
    s1 ^= g_mul(ct[0] ^ key[0], inv_mds[line][0])
    s1 ^= g_mul(ct[1] ^ key[1], inv_mds[line][1])
    s1 ^= g_mul(ct[2] ^ key[2], inv_mds[line][2])
    s1 ^= g_mul(ct[3] ^ key[3], inv_mds[line][3])

    s1 = inv_sbox[s1]

    s2 = 0
    s2 ^= g_mul(ct_faulted[0] ^ key[0], inv_mds[line][0])
    s2 ^= g_mul(ct_faulted[1] ^ key[1], inv_mds[line][1])
    s2 ^= g_mul(ct_faulted[2] ^ key[2], inv_mds[line][2])
    s2 ^= g_mul(ct_faulted[3] ^ key[3], inv_mds[line][3])

    s2 = inv_sbox[s2]

    return s1 ^ s2


def get_candidates(ct, ct_faulted, shift=0):
    ct = [int(ct.hex()[4*i + j], 16)  for i in range(4) for j in range(4)]
    ct_faulted = [int(ct_faulted.hex()[4*i + j], 16)  for i in range(4) for j in range(4)]

    result_of_equations = []
    # 4 unknown variables to find
    unknowns = ['a', 'b', 'c', 'd']

    # coeffs for each equation
    coeffs = {
        'a': [4, 8, 0xB, 2], # for unknown 'a'
        'b': [1, 6, 0xE, 2], # for unknown 'b'
        'c': [2, 5, 0xA, 0xF], # for unknown 'c'
        'd': [2, 6, 9, 0xB], # for unknown 'd'
    }


    # Get the inverse in GF16
    GF16_INVERSE = {}
    for i in range(16):
        for j in range(16):
            if g_mul(i, j) == 1:
                GF16_INVERSE[i] = j

    # 
    keys_nibbles_for_unknowns = {} 
    # ie 
    # ('a', 0) : {(k0,k4,k8,k12), (k0', k4', k8', k12'), ....},  
    # ('a', 1) : {(ki,ki,ki,ki), (ki', ki', ki', ki'), ....},  
    # ('b', 3) : {(ki,ki,ki,ki), (ki', ki', ki', ki'), ....},
    # ...  

    # indicates which first byte to use for the equation associated with the index
    # ie first_equations_coeffs['a'][0] give the index of the first byte of the ciphertext to use (then we take the byte at index +4, +8 and +12 )
    # (see the equations we want to resolve to understand)

    # For fault on middle diagonal
    if shift == 0:
        first_equations_coeffs = {
            'a': [0,3,2,1],
            'b': [3,2,1,0],
            'c': [2,1,0,3],
            'd': [1,0,3,2],
        }
    # For fault on middle diagonal + 1
    elif shift == 1 or shift == -3:
        first_equations_coeffs = {
            'b': [0,3,2,1],
            'c': [3,2,1,0],
            'd': [2,1,0,3],
            'a': [1,0,3,2],
        }
    # For fault on middle diagonal + 2
    elif shift == 2 or shift == -2:
        first_equations_coeffs = {
            'c': [0,3,2,1],
            'd': [3,2,1,0],
            'a': [2,1,0,3],
            'b': [1,0,3,2],
        }
    # For fault on middle diagonal + 3
    elif shift == 3 or shift == -1:
        first_equations_coeffs = {
            'd': [0,3,2,1],
            'a': [3,2,1,0],
            'b': [2,1,0,3],
            'c': [1,0,3,2],
        }


    for unknown in unknowns:
        # print("\nDetermining unknown ", unknown)
        for eq_index in range(4):
            
            key_nibbles_for_unknown_m = [set({}) for _ in range(16)]

            for i in range(16):
                for j in range(16):
                    for k in range(16):
                        for l in range(16):
                            partial_key_nibbles = [i,j,k,l]
                            s = get_fault_equation(ct[first_equations_coeffs[unknown][eq_index]::4], ct_faulted[first_equations_coeffs[unknown][eq_index]::4], partial_key_nibbles, eq_index)
                            key_nibbles_for_unknown_m[g_mul(GF16_INVERSE[coeffs[unknown][eq_index]], s)].add(tuple(partial_key_nibbles))

            # print("\nNumber of candidates for equation ", eq_index)
            # for i, t in enumerate(key_nibbles_for_unknown_m):
            #     print(i, len(t), end=' | ')
            # print()
            keys_nibbles_for_unknowns[(unknown, eq_index)] = key_nibbles_for_unknown_m


    fault_values = {}
    # Check if some key nibbles satisfy all 4 equations for each unknown
    for unknown in unknowns:
        for x in range(16):
            # if the first equation has solutions when 'unknown = x' 
            if len(keys_nibbles_for_unknowns[(unknown, 0)][x]) != 0:
                # Check if all equations have solutions
                is_empty = False
                for eq_index in range(1, 4):
                    if len(keys_nibbles_for_unknowns[(unknown, eq_index)][x]) == 0:
                        is_empty = True
                
                if not is_empty:
                    if unknown not in fault_values:
                        fault_values[unknown] = set()
                    fault_values[unknown].add(x)

    
    # print("Possible fault_values : ", fault_values)

    keyspace = 0
    k0, k1, k2, k3 = set(), set(), set(), set()
    for a in fault_values['a']:
        for b in fault_values['b']:
            for c in fault_values['c']:
                for d in fault_values['d']:
                    k0_4_8_12 = keys_nibbles_for_unknowns[('a', 0)][a].intersection(
                        keys_nibbles_for_unknowns[('b', 3)][b]
                    ).intersection(
                        keys_nibbles_for_unknowns[('c', 2)][c]
                    ).intersection(
                        keys_nibbles_for_unknowns[('d', 1)][d]
                    )

                    k1_5_9_13 = keys_nibbles_for_unknowns[('a', 3)][a].intersection(
                        keys_nibbles_for_unknowns[('b', 2)][b]
                    ).intersection(
                        keys_nibbles_for_unknowns[('c', 1)][c]
                    ).intersection(
                        keys_nibbles_for_unknowns[('d', 0)][d]
                    )

                    k2_6_10_14 = keys_nibbles_for_unknowns[('a', 2)][a].intersection(
                        keys_nibbles_for_unknowns[('b', 1)][b]
                    ).intersection(
                        keys_nibbles_for_unknowns[('c', 0)][c]
                    ).intersection(
                        keys_nibbles_for_unknowns[('d', 3)][d]
                    )

                    k3_7_11_15 = keys_nibbles_for_unknowns[('a', 1)][a].intersection(
                        keys_nibbles_for_unknowns[('b', 0)][b]
                    ).intersection(
                        keys_nibbles_for_unknowns[('c', 3)][c]
                    ).intersection(
                        keys_nibbles_for_unknowns[('d', 2)][d]
                    )

                    keyspace += len(k0_4_8_12) + len(k1_5_9_13) + len(k2_6_10_14) + len(k3_7_11_15)
                    if shift == 0:
                        k0 = k0.union(k0_4_8_12)
                        k1 = k1.union(k1_5_9_13)
                        k2 = k2.union(k2_6_10_14)
                        k3 = k3.union(k3_7_11_15)
                    elif shift == 1 or shift == -3:
                        k0 = k0.union(k3_7_11_15)
                        k1 = k1.union(k0_4_8_12)
                        k2 = k2.union(k1_5_9_13)
                        k3 = k3.union(k2_6_10_14)  
                    elif shift == 2 or shift == -2:
                       k0 = k0.union(k2_6_10_14)
                       k1 = k1.union(k3_7_11_15)
                       k2 = k2.union(k0_4_8_12)
                       k3 = k3.union(k1_5_9_13)  
                    elif shift == 3 or shift == -1:
                       k0 = k0.union(k1_5_9_13)
                       k1 = k1.union(k2_6_10_14)
                       k2 = k2.union(k3_7_11_15)
                       k3 = k3.union(k0_4_8_12)  

                    

    # print("Keyspace length :", keyspace)

    return k0, k1, k2, k3

def key_exhaustive_search(k0, k1, k2, k3):
    keys = []
    for ki in k0:
        for kj in k1:
            for kl in k2:
                for km in k3:
                    key_test = [ki[0], kj[0], kl[0], km[0], ki[1], kj[1], kl[1], km[1], ki[2], kj[2], kl[2], km[2], ki[3], kj[3], kl[3], km[3]]
                    key_test = bytes.fromhex("".join(f"{nibble:x}" for nibble in key_test))
                    keys.append(key_test)
                    # print("Key found :", key_test)

    return keys



#------------------------------
# Recover 2nd part of the key
#------------------------------

def _generate_constants(n: int):
    consts = []
    lfsr = 0
    for _ in range(n):
        feedback = ((lfsr >> 5) ^ (lfsr >> 4) ^ 1) & 1
        lfsr = ((lfsr << 1) | feedback) & 0x3F
        consts.append(lfsr)
    return consts

def add_constants(state, round_index: int):
    rcs = _generate_constants(48)
    rc = rcs[round_index] 

    ks = [8, 0] # keylength = 128 bits -> 1000 0000 -> [1000, 0000] -> [8, 0]
    rc_hi = (rc >> 3) & 0x7
    rc_low = rc & 0x7

    # Change 1st column
    state[0][0] ^= 0 ^ ks[0]
    state[1][0] ^= 1 ^ ks[0]
    state[2][0] ^= 2 ^ ks[1]
    state[3][0] ^= 3 ^ ks[1]

    # Change 2nd column
    state[0][1] ^= rc_hi
    state[1][1] ^= rc_low
    state[2][1] ^= rc_hi
    state[3][1] ^= rc_low

    return state

def sub_cells(state, sbox):
    return [[sbox[state[i][j]] for j in range(4)] for i in range(4)]
    
def shift_rows(state, direction="left"):
    """
        Shift by i the i_th row
    """
    new_state = [row[:] for row in state]
    for i in range(4):
        shift = i if direction == "left" else -i
        shift %= 4
        new_state[i] = state[i][shift:] + state[i][:shift]
    return new_state

def mix_columns_serial(state, matrix):
    """
        returns the product of matrix * state
    """
    new_state = [[0]*4 for _ in range(4)]
    for j in range(4):
        for i in range(4):
            val = 0
            for k in range(4):
                val ^= g_mul(matrix[i][k], state[k][j])
            new_state[i][j] = val
    return new_state

def add_round_key(state, key: list[int]):
    return [[state[i][j] ^ (key[4*i + j]) for j in range(4)] for i in range(4)]
    

def decrypt_round(ct, key, step=11):
    assert len(key) == 8 and len(ct) == 8

    inv_mds = [
        [0xC, 0xC, 0xD, 0x4],
        [0x3, 0x8, 0x4, 0x5],
        [0x7, 0x6, 0x2, 0xE],
        [0xD, 0x9, 0x9, 0xD]
    ]

    ct = ct.hex().rjust(16, '0')
    key = key.hex().rjust(16, '0')

    key = [int(k, 16) for k in key]
    state = [[int(ct[4*i + j], 16) for j in range(4)] for i in range(4)]

    state = add_round_key(state, key)
    for r in range(3, -1, -1):
        state = mix_columns_serial(state, inv_mds)
        state = shift_rows(state, "right")
        state = sub_cells(state, inv_sbox)
        state = add_constants(state, step * 4 + r)
            
    return bytes.fromhex("".join(f"{nibble:x}" for row in state for nibble in row))

#-----------------------------------
# Recover first 64 bits of the key
#-----------------------------------

def key_recovery_64(pairs, test=False):
    ct, ct_faulted = pairs[0]

    # Test all shifts
    for shift in range(4):
        try:
            k0,k1,k2,k3 = get_candidates(ct, ct_faulted, shift=shift)
        except:
            continue

    for ct, ct_faulted in pairs[1:]:

        # Test all shifts
        for shift in range(4):
            try:
                _k0,_k1,_k2,_k3 = get_candidates(ct, ct_faulted, shift=shift)
            except:
                continue
        
        # Update the intersection of possible keys
        k0.intersection_update(_k0)
        k1.intersection_update(_k1)
        k2.intersection_update(_k2)
        k3.intersection_update(_k3)
    
    keyspace = len(k0) + len(k1) + len(k2) + len(k3)

    if test:
        print("keyspace :", len(k0) * len(k1) * len(k2) * len(k3))
        return len(k0) * len(k1) * len(k2) * len(k3) > 0 and len(k0) * len(k1) * len(k2) * len(k3) < 100**10

    print("Keyspace length :", int(log(keyspace,2)))
    keys = key_exhaustive_search(k0, k1, k2, k3)

    return keys

def key_recovery_128(pairs, key64, test=False):

    ct, ct_faulted = pairs[0]
    ct, ct_faulted = decrypt_round(ct, key64), decrypt_round(ct_faulted, key64)

    for shift in range(4):
        try:
            k0,k1,k2,k3 = get_candidates(ct, ct_faulted, shift=shift)
        except:
            continue

    for ct, ct_faulted in pairs[1:]:
        ct, ct_faulted = decrypt_round(ct, key64), decrypt_round(ct_faulted, key64)
        for shift in range(4):
            try:
                _k0,_k1,_k2,_k3 = get_candidates(ct, ct_faulted, shift=shift)
            except:
                continue

        k0.intersection_update(_k0)
        k1.intersection_update(_k1)
        k2.intersection_update(_k2)
        k3.intersection_update(_k3)

    keyspace = len(k0) + len(k1) + len(k2) + len(k3)
    # print("Keyspace length :", int(log(keyspace,2)))

    if test:
        print("keyspace :", keyspace)
        return  len(k0) * len(k1) * len(k2) * len(k3) > 0 and len(k0) * len(k1) * len(k2) * len(k3) < 100**10

    print("Keyspace length :", int(log(keyspace,2)))
    keys = key_exhaustive_search(k0, k1, k2, k3)

    # if key and key in keys:
    #     print("Key found")
    
    return keys


cipher = LED()
key = os.urandom(16)
pt = os.urandom(8)

sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
inv_sbox = [sbox.index(x) for x in range(16)]


print("key :", key.hex())

ct = cipher.encrypt_block(pt, key)

# faults = [cipher.encrypt_block(pt, key, FAULTY=True, FAULTY_ROUND=12) for _ in range(3)]

faults = [cipher.encrypt_block(pt, key, FAULTY=True, FAULTY_ROUND=rd.randint(10,12)) for _ in range(12)]

pairs = [(ct, ct_faulted) for ct_faulted in faults]


#----------------------------------------
# Recovering the 1st 64 bits of the key
#----------------------------------------

keys64 = []
pairs64 = set()

for i in range(0, len(pairs)):
    print(f"Determine if pair_{i} has a fault on round 12")
    # for shift in range(4):
    try:
        faut_on_round_12 = key_recovery_64([pairs[i]], test=True)
        if faut_on_round_12 == True:
            pairs64.add(pairs[i])
            continue
    except:
        continue

print("Pairs found :", pairs64)

print("Recovering the 1st 64 bits of the key")
# for shift in range(4):
try:
    keys64 += key_recovery_64(list(pairs64))
except:
    pass

print(keys64)

# Remove pairs64 from pairs
for pair in pairs64:
    pairs.remove(pair)

print("1st part of key found :", key[:8] in keys64)

#----------------------------------------
# Recovering the last 64 bits of the key
#----------------------------------------

keys128 = []
pairs128 = set()

key_found = False
for key64 in keys64:
    if key_found:
        break
    for i in range(0, len(pairs)):
        print(f"Determine if pair_{i} has a fault on round 11")
        # for shift in range(4):
        try:
            faut_on_round_11 = key_recovery_128([pairs[i]], key64, test=True)
            if faut_on_round_11 == True:
                pairs128.add(pairs[i])
                key_found = True
        except:
            continue


print("Pairs found :", pairs128)


print("Recovering the last 64 bits of the key")
for key64 in keys64:
    # for shift in range(4):
    try:
        keys128 += key_recovery_128(list(pairs128), key64)
    except:
        continue

keys = [_key.hex() for _key in keys128]
print(keys)
print(key.hex()[16:] in keys)
print(key.hex())

keys = []
for key64 in keys64:
    for key128 in keys128:
        keys.append((key64 + key128).hex())

print(keys)
# pairs128 =

# keys128 = []
# # try: 
# keys128 += key_recovery_128(pairs, key[:8])
# # except:
#     # pass

# keys = [_key.hex() for _key in keys128]
# print(keys)
# print(key.hex()[16:] in keys)
# print(key.hex())


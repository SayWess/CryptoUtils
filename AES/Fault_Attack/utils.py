from Faulty_AES import *
from functools import reduce

# Positions of the last round key bytes (diagonals)
POSITIONS = [
    [0, 13, 10, 7],  # diagonal 0
    [4, 1, 14, 11],  # diagonal 1
    [8, 5, 2, 15],   # diagonal 2
    [12, 9, 6, 3]    # diagonal 3
]

def str_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x^y for x,y in zip(a,b))




# ---------------------------------------------------------
# Delta-set for MixColumns
# ---------------------------------------------------------
def get_diff_mixcolumn_row(fault_list, row=-1):
    """
    Generate all possible delta columns for a fault in round 8 or 9.
    If row == -1, unknown fault position: generate for all rows.
    """
    rows = range(4) if row == -1 else [row]
    diff_cols = []

    for r in rows:
        for f in fault_list:
            col = [0, 0, 0, 0]
            col[r] = f
            mix_single_column(col)
            diff_cols.append(col.copy())

    return diff_cols


# ---------------------------------------------------------
# Key candidates for one column
# ---------------------------------------------------------

def key10_candidates(pair_ct, col, mc_diff_list):
    """
    Compute key candidate bytes for one diagonal of round 10 key using round 8 or 9 fault.
    """

    ct, faulted_ct = pair_ct

    good = [ct[i] for i in POSITIONS[col]]
    faulty = [faulted_ct[i] for i in POSITIONS[col]]

    candidates = []

    for mc_diff in mc_diff_list:
        for k0 in range(256):
            if inv_s_box[good[0] ^ k0] ^ inv_s_box[faulty[0] ^ k0] != mc_diff[0]:
                continue

            for k1 in range(256):
                if inv_s_box[good[1] ^ k1] ^ inv_s_box[faulty[1] ^ k1] != mc_diff[1]:
                    continue

                for k2 in range(256):
                    if inv_s_box[good[2] ^ k2] ^ inv_s_box[faulty[2] ^ k2] != mc_diff[2]:
                        continue

                    for k3 in range(256):
                        if inv_s_box[good[3] ^ k3] ^ inv_s_box[faulty[3] ^ k3] != mc_diff[3]:
                            continue

                        candidates.append(bytes([k0, k1, k2, k3]))

    return candidates


# ---------------------------------------------------------
# Reverse key schedule
# ---------------------------------------------------------

def xor_bytes(*args):
    return bytes(
        reduce(lambda a, b: a ^ b, values)
        for values in zip(*args)
    )

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return bytes(s_box[b] for b in word)

rcon = [x.to_bytes(4, 'little') for x in
        [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]]

def reverse_key_schedule(round_key, aes_round):
    for i in reversed(range(aes_round)):
        a2, b2, c2, d2 = (
            round_key[0:4],
            round_key[4:8],
            round_key[8:12],
            round_key[12:16],
        )

        d1 = xor_bytes(d2, c2)
        c1 = xor_bytes(c2, b2)
        b1 = xor_bytes(b2, a2)
        a1 = xor_bytes(a2, rot_word(sub_word(d1)), rcon[i])

        round_key = a1 + b1 + c1 + d1

    return round_key


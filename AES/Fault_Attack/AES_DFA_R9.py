from utils import *

# ---------------------------------------------------------
# Round 9 helpers
# ---------------------------------------------------------

def find_faulty_column_index(pair_ct):
    ct, faulty_ct = pair_ct
    delta = str_xor(ct, faulty_ct)

    for i in range(4):
        if delta[i] != 0:
            return i
    return -1


def r9_find_candidates(pair):
    col = find_faulty_column_index(pair)
    if col == -1:
        return None, None

    fault_list = range(1, 256)
    mc_diff_list = get_diff_mixcolumn_row(fault_list)

    candidates = key10_candidates(pair, col, mc_diff_list)

    return col, candidates

# ---------------------------------------------------------
# Key recovery
# ---------------------------------------------------------

def r9_key_recovery(pairs, pt_ct_tuple=None):
    candidates = [None] * 4

    for i, pair in enumerate(pairs):
        print(f"Processing pair {i}...")
        col, cand = r9_find_candidates(pair)

        if col is None:
            continue

        cand_set = set(cand)

        if candidates[col] is None:
            candidates[col] = cand_set
        else:
            candidates[col] &= cand_set
        
        total = 1
        for c in candidates:
            total *= (len(c) if c else 4294967296) or 4294967296 # 256**4 if no information on this column

        print("Candidates per column:", [ (len(c) if c else 4294967296) or 4294967296 for c in candidates])
        print("Total combinations:", total)
        print()

    for i in range(4):
        if candidates[i] is None:
            candidates[i] = set()

    total = 1
    for c in candidates:
        total *= len(c) or 4294967296 # 256**4 if no information on this column
    
    print("Candidates per column:", [ (len(c) if c else 4294967296) or 4294967296 for c in candidates])
    print("Total combinations:", total)
    print()

    if total == 0 or total > 10000000:
        print("Too many possibilities, try with more ciphertexts")
        return {"total": total, "masterkey": None}

    keys = []
    # Exhaustive search
    for col1 in candidates[0]:
        for col2 in candidates[1]:
            for col3 in candidates[2]:
                for col4 in candidates[3]:
                    subkey10 = [0] * 16
                    candidate = [col1, col2, col3, col4]
                    for col in range(4):
                        for i in range(4):
                            subkey10[POSITIONS[col][i]] = candidate[col][i]    
                    
                    key = reverse_key_schedule(bytes(subkey10), 10)

                    if pt_ct_tuple:
                        cipher = AES(key)
                        pt,ct = pt_ct_tuple

                        if cipher.decrypt_block(ct) == pt:
                            print("Key found:", key)
                            return {"total": total, "masterkey": key}
                    else:
                        # If we don't have a pair of (plaintext,ciphertext), it keeps all keys candidates
                        keys.append(key)

    return {"total": total, "masterkey": None} if pt_ct_tuple else {"total": total, "masterkey": keys}

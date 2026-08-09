from utils import *


# ---------------------------------------------------------
# Round 8 candidate finder
# ---------------------------------------------------------
def r8_find_candidates(pair, row8=-1, col8=-1):
    """
    Generate candidate lists for each diagonal (column) of last round key.
    row8, col8 = fault position in round 8 if known, else -1
    """
    fault_list = list(range(1, 256))
    candidates = [None] * 4

    diff_mc_list = get_diff_mixcolumn_row(fault_list, row=row8)
    for col9 in range(4):
        # row8 = -1 for unknown position
        candidates[col9] = key10_candidates(pair, col9, diff_mc_list)

    return candidates


# ---------------------------------------------------------
# Intersection helper
# ---------------------------------------------------------
def intersect_candidate_lists(list1, list2):
    return [set(l1) & set(l2) for l1, l2 in zip(list1, list2)]


# ---------------------------------------------------------
# Exhaustive search over last round key
# ---------------------------------------------------------
def r8_exhaustive_search(candidates, known_pt=None):
    """
    Combine candidates for all 4 diagonals and test keys with optional known plaintext.
    """
    masterkeys = []

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

                    if known_pt:
                        pt, ct = known_pt
                        if AES(key).encrypt_block(pt) == ct:
                            return key
                    else:
                        masterkeys.append(key)

    return masterkeys



# ---------------------------------------------------------
# Round 8 key recovery for multiple ciphertext pairs
# ---------------------------------------------------------
def r8_key_recovery_multiple(pairs, known_pt=None):
    """
    Compute last round key from multiple ciphertext pairs with unknown fault position.
    """
    # Get candidates for first pair
    print("Processing pair 0...")
    candidates_list = r8_find_candidates(pairs[0])
    
    total = 1
    for c in candidates_list:
        total *= len(c)
    print("Candidates per column:", [len(c) for c in candidates_list])
    print("Total combinations:", total)

    # Intersect with other pairs
    for i, pair in enumerate(pairs[1:]):
        print()
        print(f"Processing pair {i+1}...")
        new_candidates = r8_find_candidates(pair)
        candidates_list = intersect_candidate_lists(candidates_list, new_candidates)
        total = 1
        for c in candidates_list:
            total *= len(c)
        print("Candidates per column:", [len(c) for c in candidates_list])
        print("Total combinations:", total)


    # Exhaustive search
    masterkeys = r8_exhaustive_search(candidates_list, known_pt)
    print()
    print("Key found:", masterkeys)

    # print(f'Number of masterkeys: {len(masterkeys)}')
    return masterkeys

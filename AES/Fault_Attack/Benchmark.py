import os
import time
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

from Faulty_AES import *
from AES_DFA_R9 import *


#####################################################################################
## Benchmark 1 : Entropy and success recovery rate based on number of ciphertexts  ##
#####################################################################################

def run_benchmark(max_faults=12, trials_per_n=20):
    stats = defaultdict(list)
    
    # Secret Key and Plaintext for the session
    REAL_KEY = os.urandom(16)
    cipher = AES(REAL_KEY)
    pt = b"A"*16
    ct = cipher.encrypt_block(pt)

    print(f"Starting Benchmark... Target Key: {REAL_KEY.hex()}")
    
    for n in range(1, max_faults + 1):
        trial_times = []
        trial_entropies = []
        successes = 0
        
        for _ in range(trials_per_n):
            # Generate N faulty ciphertexts
            # We simulate random byte faults in Round 9
            faults = [cipher.encrypt_block(pt, FAULTED=True, FAULTY_ROUND=-1) for _ in range(n)]
            pairs = [(ct, f_ct) for f_ct in faults]
            
            start_t = time.time()
            result = r9_key_recovery(pairs, (pt, ct))
            end_t = time.time()
            
            # Track Time
            trial_times.append(end_t - start_t)
            
            # Track Entropy (log2 of total possibilities)
            # If total is 2^64, bit_length is 65, so we use -1 for a rough log2
            entropy = result['total'].bit_length() - 1 if result['total'] > 1 else 0
            trial_entropies.append(entropy)
            
            # Track Success
            if result['masterkey'] == REAL_KEY:
                successes += 1
                
        stats['n'].append(n)
        stats['avg_time'].append(np.mean(trial_times))
        stats['avg_entropy'].append(np.mean(trial_entropies))
        stats['success_rate'].append(successes / trials_per_n)
        
        print(f"Faults: {n} | Avg Entropy: {stats['avg_entropy'][-1]:.2f} bits | Success: {successes/trials_per_n:.2%}")

    return stats

def plot_results(stats):
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Plot Entropy
    color = 'tab:blue'
    ax1.set_xlabel('Number of Faulty Ciphertexts')
    ax1.set_ylabel('Remaining Entropy (bits)', color=color)
    ax1.plot(stats['n'], stats['avg_entropy'], color=color, marker='o', label='Entropy')
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.grid(True, linestyle='--', alpha=0.6)

    # Plot Success Rate on same graph
    ax2 = ax1.twinx()
    color = 'tab:green'
    ax2.set_ylabel('Success Rate (Key Recovered)', color=color)
    ax2.plot(stats['n'], stats['success_rate'], color=color, marker='s', label='Success Rate')
    ax2.tick_params(axis='y', labelcolor=color)

    plt.title('AES-128 DFA Round 9 Benchmark')
    fig.tight_layout()
    plt.show()

# # Run test
# stats = run_benchmark()
# plot_results(stats)



#####################################################################################
## Benchmark 2 : Entropy based on average number of columns covered by ciphertexts ##
#####################################################################################

import os
import math
from collections import defaultdict

def run_dfa_benchmark(max_faults=10, trials=50):
    print(f"{'N':<5} | {'Avg Cols':<10} | {'Entropy':<10} | {'Combinations'}")
    print("-" * 55)

    REAL_KEY = os.urandom(16)
    cipher = AES(REAL_KEY)
    pt = b"A" * 16
    ct = cipher.encrypt_block(pt)

    for n in range(1, max_faults + 1, 1):
        total_cols_covered = 0
        total_entropy = 0
        total_combinations = 0
        
        for _ in range(trials):
            # Generate N faults for this trial
            faults = [cipher.encrypt_block(pt, FAULTED=True, FAULTY_ROUND=-1) for _ in range(n)]
            pairs = [(ct, f_ct) for f_ct in faults]
            
            candidates = [None] * 4
            for pair in pairs:
                col, cand = r9_find_candidates(pair)
                if col is not None:
                    cand_set = set(cand)
                    if candidates[col] is None:
                        candidates[col] = cand_set
                    else:
                        candidates[col] &= cand_set
            
            # Calculate stats for this trial
            cols_hit = sum(1 for c in candidates if c is not None)
            
            combinations = 1
            for c in candidates:
                # 4294967296 is 256**4
                combinations *= len(c) if (c is not None and len(c) > 0) else 4294967296
            
            total_cols_covered += cols_hit
            total_combinations += combinations
            total_entropy += math.log2(combinations)

        # Average the results
        avg_cols = total_cols_covered / trials
        avg_entropy = total_entropy / trials
        avg_combos = total_combinations / trials

        # Formatting the output
        if avg_combos > 1e9:
            combo_str = f"2^{int(avg_entropy)}"
        else:
            combo_str = f"{int(avg_combos):,}"

        print(f"{n:<5} | {avg_cols:<10.2f} | {avg_entropy:<10.1f} | {combo_str}")

# Run the benchmark
run_dfa_benchmark(max_faults=15, trials=100)



#################################################################
## Benchmark 3 : Key Search Space vs Columns Covered by Faults ##
#################################################################

# Now create the specific graph: "Number of possibility if we don't have candidates for one column"
# This is a discrete comparison.
scenarios = ["0 Column", "1 Column", "2 Columns", "3 Columns", "4 Columns"]
possibilities = [128, 96, 64, 32, 0] # log2 scale

plt.figure(figsize=(8, 5))
plt.bar(scenarios, possibilities, color='skyblue')
plt.title("Key Search Space vs Columns Covered by Faults")
plt.ylabel("Remaining Entropy (bits)")
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.savefig("column_coverage.png")


"""
Create reproducible stratified development and evaluation splits from malicious_phish.csv.
Uses fixed random seed 42 and strictly disjoint sets.
"""
import csv
import random
from collections import defaultdict

def create_stratified_splits(
    src_csv="data/malicious_phish.csv",
    dev_csv="data/dev_sample.csv",
    eval_csv="data/eval_sample.csv",
    dev_size=20000,
    eval_size=20000,
    seed=42
):
    print(f"Reading dataset from {src_csv}...")
    by_class = defaultdict(list)
    
    with open(src_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) >= 2:
                by_class[row[1].strip().lower()].append(row)
                
    total_records = sum(len(v) for v in by_class.values())
    print(f"Loaded {total_records:,} total records across {len(by_class)} classes.")
    for c, items in by_class.items():
        print(f"  {c}: {len(items):,} ({len(items)/total_records*100:.2f}%)")
        
    rng = random.Random(seed)
    dev_rows = []
    eval_rows = []
    
    for c, items in by_class.items():
        # Shuffle deterministically
        shuffled = list(items)
        rng.shuffle(shuffled)
        
        # Proportional allocation
        ratio = len(items) / total_records
        c_dev_count = int(round(dev_size * ratio))
        c_eval_count = int(round(eval_size * ratio))
        
        c_dev = shuffled[:c_dev_count]
        c_eval = shuffled[c_dev_count:c_dev_count + c_eval_count]
        
        dev_rows.extend(c_dev)
        eval_rows.extend(c_eval)
        print(f"  Allocated '{c}': Dev={len(c_dev):,}, Eval={len(c_eval):,}")
        
    # Shuffle splits so classes are intermixed
    rng.shuffle(dev_rows)
    rng.shuffle(eval_rows)
    
    with open(dev_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(dev_rows)
    print(f"Wrote {len(dev_rows):,} records to {dev_csv}")
    
    with open(eval_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(eval_rows)
    print(f"Wrote {len(eval_rows):,} records to {eval_csv}")

if __name__ == "__main__":
    create_stratified_splits()

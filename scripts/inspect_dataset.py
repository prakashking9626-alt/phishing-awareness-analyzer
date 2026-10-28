"""
Inspect and validate the Kaggle malicious_phish.csv dataset.
Streams the CSV in constant memory using Python's standard csv module.
"""
import csv
import sys
import time
from collections import Counter


def inspect_dataset(csv_path: str):
    print(f"Reading dataset: {csv_path}")
    start_time = time.time()
    
    total_rows = 0
    missing_url_count = 0
    missing_type_count = 0
    malformed_rows = 0
    label_counts = Counter()
    target_url = "https://signin.eby.de.zukruygxctzmmqi.civpro.co.za"
    target_matches = []
    
    header = None
    sample_rows = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            print("ERROR: Empty CSV file.")
            return

        for row_idx, row in enumerate(reader, start=1):
            total_rows += 1
            if len(row) != len(header):
                malformed_rows += 1
                if malformed_rows <= 5:
                    print(f"Malformed row at line {row_idx + 1}: len={len(row)}, content={row[:3]}")
                continue

            url_val = row[0].strip()
            type_val = row[1].strip()

            if not url_val:
                missing_url_count += 1
            if not type_val:
                missing_type_count += 1

            label_counts[type_val] += 1

            # Capture representative sample rows (first 5)
            if len(sample_rows) < 5:
                sample_rows.append((url_val, type_val))

            # Look for confirmed issue URL (exact or substring)
            if "signin.eby.de" in url_val or "zukruygxctzmmqi" in url_val or url_val == target_url:
                target_matches.append((row_idx + 1, url_val, type_val))

    elapsed = time.time() - start_time

    print("=" * 70)
    print("KAGGLE DATASET INSPECTION REPORT")
    print("=" * 70)
    print(f"CSV Header: {header}")
    print(f"Total Data Rows Counted: {total_rows:,}")
    print(f"Malformed Rows: {malformed_rows:,}")
    print(f"Missing URL Fields: {missing_url_count:,}")
    print(f"Missing Type/Label Fields: {missing_type_count:,}")
    print(f"Inspection Time: {elapsed:.2f} seconds")
    print("-" * 70)
    print("Class Distribution:")
    for label, count in label_counts.most_common():
        pct = (count / total_rows) * 100 if total_rows > 0 else 0
        print(f"  - {label:<15}: {count:10,} ({pct:6.2f}%)")
    print("-" * 70)
    print("Representative Sample Rows:")
    for u, l in sample_rows:
        print(f"  [{l:<10}] {u}")
    print("-" * 70)
    print(f"Target URL Search ('signin.eby.de' or 'zukruygxctzmmqi'):")
    if target_matches:
        for line_num, u, l in target_matches:
            print(f"  Found at line {line_num}: URL={u} | Label={l}")
    else:
        print("  Not found by exact match; searching broader tokens...")
    print("=" * 70)


if __name__ == "__main__":
    csv_file = sys.argv[1] if len(sys.argv) > 1 else "data/malicious_phish.csv"
    inspect_dataset(csv_file)

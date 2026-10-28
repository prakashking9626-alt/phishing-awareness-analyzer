"""
Reproducible Full-Dataset Benchmark for Kaggle malicious_phish.csv.

Evaluates the production URL analyzer and centralized scoring engine
against the 651,191-record Kaggle Malicious URLs dataset.

Strictly offline: Zero DNS, zero HTTP sockets, zero external network traffic.
"""
import argparse
import csv
import json
import os
import sys
import time
from collections import Counter

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analyzers.url_analyzer import analyze_url
from app.analyzers.scoring_engine import calculate_risk_score


def resolve_dataset_path(provided_path: str = None) -> str:
    """Finds the dataset file across standard project locations."""
    if provided_path and os.path.exists(provided_path):
        if os.path.isdir(provided_path):
            nested = os.path.join(provided_path, "malicious_phish.csv")
            if os.path.isfile(nested):
                return nested
        elif os.path.isfile(provided_path):
            return provided_path

    candidates = [
        "data/malicious_phish.csv",
        "data/malicious_phish.csv/malicious_phish.csv",
        os.path.expanduser("~/Downloads/malicious_phish.csv/malicious_phish.csv"),
        os.path.expanduser("~/Downloads/malicious_phish.csv")
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def run_benchmark(csv_path: str, limit: int = None, json_output_path: str = "reports/kaggle_benchmark_metrics.json"):
    print("=" * 78)
    print("PHISHING AWARENESS ANALYZER - KAGGLE DATASET BENCHMARK")
    print("=" * 78)
    print(f"Dataset File   : {csv_path}")
    print(f"Max Records    : {'ALL (Full Dataset)' if limit is None else f'{limit:,}'}")
    print(f"Analysis Mode  : Offline Static Heuristic (Production Engine)")
    print("-" * 78)

    start_time = time.time()
    total_processed = 0
    skipped_records = 0
    header = None

    # Class-level counters
    # Kaggle classes: 'benign', 'phishing', 'malware', 'defacement'
    class_totals = Counter()
    class_predicted_threat = Counter()
    class_predicted_clean = Counter()

    # Binary metrics: Primary Phishing vs Benign
    phish_tp = 0
    phish_fn = 0
    benign_tn = 0
    benign_fp = 0

    # Binary metrics: All Threats (Phish + Malware + Deface) vs Benign
    overall_tp = 0
    overall_fn = 0

    # Error sample collections for diagnostics
    sample_fps = []
    sample_fns = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            print("ERROR: Empty CSV file.")
            return

        for row_idx, row in enumerate(reader, start=1):
            if len(row) < 2:
                skipped_records += 1
                continue

            raw_url = row[0].strip()
            label = row[1].strip().lower()

            if not raw_url or not label:
                skipped_records += 1
                continue

            total_processed += 1
            class_totals[label] += 1

            # Execute real production analyzer offline
            try:
                analysis = analyze_url(raw_url)
            except Exception as e:
                analysis = {
                    "is_valid": False,
                    "error": str(e),
                    "indicators": [{
                        "id": "URL_MALFORMED",
                        "severity": "CRITICAL",
                        "title": "Unparseable Malformed URL",
                        "description": "The URL triggered an uncaught parser error.",
                        "evidence": str(e),
                        "recommendation": "Avoid interacting with corrupt links."
                    }]
                }
            if not analysis.get("is_valid", False):
                # Malformed schemes or dangerous protocol handlers are high threat
                score = 100
                is_threat = True
            else:
                scoring = calculate_risk_score(analysis.get("indicators", []))
                score = scoring["score"]
                is_threat = score >= 25

            if is_threat:
                class_predicted_threat[label] += 1
            else:
                class_predicted_clean[label] += 1

            # Accumulate Phishing-Specific Metrics
            if label == "phishing":
                if is_threat:
                    phish_tp += 1
                else:
                    phish_fn += 1
                    if len(sample_fns) < 10:
                        sample_fns.append((raw_url, score, [i["id"] for i in analysis.get("indicators", [])]))
            elif label == "benign":
                if not is_threat:
                    benign_tn += 1
                else:
                    benign_fp += 1
                    if len(sample_fps) < 10:
                        sample_fps.append((raw_url, score, [i["id"] for i in analysis.get("indicators", [])]))

            # Accumulate Overall Threat Metrics
            if label in ("phishing", "malware", "defacement"):
                if is_threat:
                    overall_tp += 1
                else:
                    overall_fn += 1

            # Progress update every 50,000 records
            if total_processed % 50000 == 0:
                elapsed_mid = time.time() - start_time
                rate_mid = total_processed / elapsed_mid
                print(f"  Processed {total_processed:8,d} records... ({rate_mid:5.0f} rec/s) | Phish Recall: {(phish_tp / (phish_tp + phish_fn) * 100):5.2f}% | Benign Spec: {(benign_tn / (benign_tn + benign_fp) * 100):5.2f}%")

            if limit is not None and total_processed >= limit:
                break

    total_time = time.time() - start_time
    throughput = total_processed / total_time if total_time > 0 else 0

    # Calculate Phishing vs Benign Metrics
    phish_total = phish_tp + phish_fn
    benign_total = benign_tn + benign_fp

    phish_recall = (phish_tp / phish_total * 100) if phish_total > 0 else 0.0
    phish_fnr = (phish_fn / phish_total * 100) if phish_total > 0 else 0.0
    benign_specificity = (benign_tn / benign_total * 100) if benign_total > 0 else 0.0
    benign_fpr = (benign_fp / benign_total * 100) if benign_total > 0 else 0.0

    phish_precision = (phish_tp / (phish_tp + benign_fp) * 100) if (phish_tp + benign_fp) > 0 else 0.0
    phish_f1 = (2 * phish_precision * phish_recall / (phish_precision + phish_recall)) if (phish_precision + phish_recall) > 0 else 0.0
    phish_subset_acc = ((phish_tp + benign_tn) / (phish_total + benign_total) * 100) if (phish_total + benign_total) > 0 else 0.0

    # Calculate Overall All-Threats Metrics
    overall_threats_total = overall_tp + overall_fn
    overall_acc = ((overall_tp + benign_tn) / total_processed * 100) if total_processed > 0 else 0.0
    overall_recall = (overall_tp / overall_threats_total * 100) if overall_threats_total > 0 else 0.0
    overall_precision = (overall_tp / (overall_tp + benign_fp) * 100) if (overall_tp + benign_fp) > 0 else 0.0
    overall_f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)) if (overall_precision + overall_recall) > 0 else 0.0

    print("\n" + "=" * 78)
    print("BENCHMARK EXECUTION SUMMARY")
    print("=" * 78)
    print(f"Total Records Processed : {total_processed:,}")
    print(f"Skipped / Malformed     : {skipped_records:,}")
    print(f"Total Execution Time    : {total_time:.2f} seconds ({total_time / 60:.2f} minutes)")
    print(f"Evaluation Throughput   : {throughput:.1f} records/second")
    print("-" * 78)

    print("PER-CLASS EVALUATION BREAKDOWN:")
    for lbl in ["benign", "phishing", "malware", "defacement"]:
        tot = class_totals[lbl]
        pred_threat = class_predicted_threat[lbl]
        pred_clean = class_predicted_clean[lbl]
        if lbl == "benign":
            print(f"  [{lbl.upper():<11}] Total: {tot:8,d} | Clean (TN): {pred_clean:8,d} ({benign_specificity:6.2f}%) | Flagged (FP): {pred_threat:6,d} ({benign_fpr:5.2f}%)")
        else:
            rec = (pred_threat / tot * 100) if tot > 0 else 0.0
            print(f"  [{lbl.upper():<11}] Total: {tot:8,d} | Detected (TP): {pred_threat:7,d} ({rec:6.2f}%) | Missed (FN): {pred_clean:7,d}")
    print("-" * 78)

    print("PRIMARY FOCUS: PHISHING vs. BENIGN BINARY EVALUATION:")
    print(f"  Phishing True Positives  (TP) : {phish_tp:8,d} / {phish_total:,}")
    print(f"  Phishing False Negatives (FN) : {phish_fn:8,d} / {phish_total:,}  (FNR: {phish_fnr:.2f}%)")
    print(f"  Benign True Negatives    (TN) : {benign_tn:8,d} / {benign_total:,}")
    print(f"  Benign False Positives   (FP) : {benign_fp:8,d} / {benign_total:,}  (FPR: {benign_fpr:.2f}%)")
    print(f"  Phishing Detection Recall     : {phish_recall:6.2f}%")
    print(f"  Phishing Detection Precision  : {phish_precision:6.2f}%")
    print(f"  Phishing F1 Score             : {phish_f1:6.2f}%")
    print(f"  Phishing / Benign Accuracy    : {phish_subset_acc:6.2f}%")
    print("-" * 78)

    print("OVERALL DATASET (ALL 4 CLASSES COMBINED):")
    print(f"  Total Threats (P+M+D) : {overall_threats_total:,} | Detected: {overall_tp:,} | Missed: {overall_fn:,}")
    print(f"  Overall Accuracy      : {overall_acc:6.2f}%")
    print(f"  Overall Precision     : {overall_precision:6.2f}%")
    print(f"  Overall Recall        : {overall_recall:6.2f}%")
    print(f"  Overall F1 Score      : {overall_f1:6.2f}%")
    print("=" * 78)

    # Compile structured metrics payload
    metrics_data = {
        "dataset": {
            "source_path": csv_path,
            "header": header,
            "total_processed": total_processed,
            "skipped_records": skipped_records,
            "execution_time_seconds": round(total_time, 2),
            "throughput_records_per_second": round(throughput, 1)
        },
        "class_breakdown": {
            lbl: {
                "total": class_totals[lbl],
                "predicted_threat": class_predicted_threat[lbl],
                "predicted_clean": class_predicted_clean[lbl]
            }
            for lbl in ["benign", "phishing", "malware", "defacement"]
        },
        "phishing_vs_benign": {
            "true_positives": phish_tp,
            "false_negatives": phish_fn,
            "true_negatives": benign_tn,
            "false_positives": benign_fp,
            "recall": round(phish_recall, 4),
            "precision": round(phish_precision, 4),
            "f1_score": round(phish_f1, 4),
            "false_negative_rate": round(phish_fnr, 4),
            "false_positive_rate": round(benign_fpr, 4),
            "accuracy": round(phish_subset_acc, 4)
        },
        "overall_all_classes": {
            "total_threats": overall_threats_total,
            "true_positives": overall_tp,
            "false_negatives": overall_fn,
            "true_negatives": benign_tn,
            "false_positives": benign_fp,
            "accuracy": round(overall_acc, 4),
            "precision": round(overall_precision, 4),
            "recall": round(overall_recall, 4),
            "f1_score": round(overall_f1, 4)
        }
    }

    if json_output_path:
        os.makedirs(os.path.dirname(json_output_path), exist_ok=True)
        with open(json_output_path, "w", encoding="utf-8") as jf:
            json.dump(metrics_data, jf, indent=2)
        print(f"\n[+] Saved machine-readable metrics to: {json_output_path}")

    return metrics_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reproducible Kaggle Malicious URLs Dataset Benchmark")
    parser.add_argument("--csv", type=str, default=None, help="Path to malicious_phish.csv")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of rows to evaluate (default: full dataset)")
    parser.add_argument("--output", type=str, default="reports/kaggle_benchmark_metrics.json", help="Path to write JSON metrics")
    args = parser.parse_args()

    resolved_csv = resolve_dataset_path(args.csv)
    if not resolved_csv:
        print(f"ERROR: Could not locate 'malicious_phish.csv'. Please check path or specify via --csv.")
        sys.exit(1)

    run_benchmark(resolved_csv, limit=args.limit, json_output_path=args.output)

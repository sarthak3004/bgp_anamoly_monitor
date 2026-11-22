import csv
import ipaddress
import statistics
import time
from pathlib import Path

from updated_rad import (
    INVENTORY_FILE,
    MRT_FILE,
    ROA_FILE,
    evaluate_update,
    getBGPData,
    loadGlobalRoa,
    loadOperatorInventory,
    validate_announcement,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RESULTS_CSV = str(DATA_DIR / "synthetic_eval_results.csv")
ROGUE_ASN = "66600"


def make_subprefix(prefix_str, target_len):
    """Creates a valid more-specific subnet string inside prefix_str."""
    net = ipaddress.ip_network(prefix_str, strict=False)
    clamped_len = min(target_len, net.max_prefixlen)
    if clamped_len <= net.prefixlen:
        return None, None
    sub = next(net.subnets(new_prefix=clamped_len))
    return str(sub), clamped_len


def build_synthetic_events(inventory_csv, roa_tree):
    """
    Generates labelled synthetic BGP announcements from inventory.csv and external ROAs.
    ground_truth: 'ANOMALY' (should alert) or 'BENIGN' (should NOT alert).
    """
    events = []
    base_ts = 1696118400  # 2023-10-01 00:00:00 UTC

    with open(inventory_csv, "r") as f:
        rows = list(csv.DictReader(f))

    # 1. Synthetic events targeting Operator Inventory (Phase 1)
    for idx, row in enumerate(rows):
        prefix = row["prefix"].strip()
        expected_asns = [a.strip() for a in row["expected_asns"].split("|") if a.strip()]
        max_len = int(row["expected_max_len"])
        category = row["category"].strip()
        net = ipaddress.ip_network(prefix, strict=False)
        ts = base_ts + idx * 10

        # A. Legitimate BENIGN cases
        if category == "moas":
            for asn in expected_asns:
                events.append({
                    "event_id": f"MOAS_BENIGN_{idx}_{asn}",
                    "scenario": "LEGIT_MOAS",
                    "ground_truth": "BENIGN",
                    "timestamp": ts,
                    "prefix": prefix,
                    "prefix_length": net.prefixlen,
                    "origin_asn": asn,
                })
        elif category == "policy_shift":
            # Announce using the migrating ASN (in inventory, NOT yet in public ROA)
            migrating_asn = expected_asns[-1]
            events.append({
                "event_id": f"POLICY_SHIFT_{idx}_{migrating_asn}",
                "scenario": "LEGIT_POLICY_CHANGE",
                "ground_truth": "BENIGN",
                "timestamp": ts,
                "prefix": prefix,
                "prefix_length": net.prefixlen,
                "origin_asn": migrating_asn,
            })
        else:
            # Standard valid internal announcement
            events.append({
                "event_id": f"SINGLE_BENIGN_{idx}",
                "scenario": "LEGIT_SINGLE",
                "ground_truth": "BENIGN",
                "timestamp": ts,
                "prefix": prefix,
                "prefix_length": net.prefixlen,
                "origin_asn": expected_asns[0],
            })

        # B. Malicious ANOMALY cases: Origin Hijack on owned inventory
        events.append({
            "event_id": f"INV_ORIGIN_HIJACK_{idx}",
            "scenario": "ORIGIN_HIJACK_INTERNAL",
            "ground_truth": "ANOMALY",
            "timestamp": ts + 1,
            "prefix": prefix,
            "prefix_length": net.prefixlen,
            "origin_asn": ROGUE_ASN,
        })

        # C. Malicious/Misconfig ANOMALY cases: More-specific Subprefix Hijack
        sub_prefix, sub_len = make_subprefix(prefix, max_len + 2)
        if sub_prefix:
            # Internal subprefix misconfig (authorized ASN, illegal length)
            events.append({
                "event_id": f"INV_SUBPREFIX_MISCONFIG_{idx}",
                "scenario": "SUBPREFIX_MISCONFIG_INTERNAL",
                "ground_truth": "ANOMALY",
                "timestamp": ts + 2,
                "prefix": sub_prefix,
                "prefix_length": sub_len,
                "origin_asn": expected_asns[0],
            })
            # External subprefix hijack (rogue ASN + illegal length)
            events.append({
                "event_id": f"INV_SUBPREFIX_HIJACK_{idx}",
                "scenario": "SUBPREFIX_HIJACK_INTERNAL",
                "ground_truth": "ANOMALY",
                "timestamp": ts + 3,
                "prefix": sub_prefix,
                "prefix_length": sub_len,
                "origin_asn": ROGUE_ASN,
            })

    # 2. Synthetic events targeting External ROA space (Phase 2)
    inv_prefixes = {r["prefix"].strip() for r in rows}
    ext_added = 0
    for node in roa_tree:
        if node.prefix in inv_prefixes:
            continue
        roa = node.data["roas"][0]
        net = ipaddress.ip_network(node.prefix, strict=False)
        if roa["max_length"] >= net.max_prefixlen - 1:
            continue

        ts = base_ts + 500 + ext_added * 10
        # External Origin Hijack
        events.append({
            "event_id": f"EXT_ORIGIN_HIJACK_{ext_added}",
            "scenario": "ORIGIN_HIJACK_EXTERNAL",
            "ground_truth": "ANOMALY",
            "timestamp": ts,
            "prefix": node.prefix,
            "prefix_length": net.prefixlen,
            "origin_asn": ROGUE_ASN,
        })
        # External Subprefix Hijack
        sub_prefix, sub_len = make_subprefix(node.prefix, roa["max_length"] + 1)
        if sub_prefix:
            events.append({
                "event_id": f"EXT_SUBPREFIX_HIJACK_{ext_added}",
                "scenario": "SUBPREFIX_HIJACK_EXTERNAL",
                "ground_truth": "ANOMALY",
                "timestamp": ts + 1,
                "prefix": sub_prefix,
                "prefix_length": sub_len,
                "origin_asn": roa["asn"],
            })

        ext_added += 1
        if ext_added >= 10:
            break

    return events


def compute_metrics(records, pred_key):
    tp = fp = tn = fn = 0
    fp_by_scenario = {}

    for rec in records:
        truth_anomaly = rec["ground_truth"] == "ANOMALY"
        pred_anomaly = rec[pred_key] == "INVALID"

        if truth_anomaly and pred_anomaly:
            tp += 1
        elif not truth_anomaly and pred_anomaly:
            fp += 1
            sc = rec["scenario"]
            fp_by_scenario[sc] = fp_by_scenario.get(sc, 0) + 1
        elif not truth_anomaly and not pred_anomaly:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": precision, "Recall": recall, "F1": f1,
        "FP_by_scenario": fp_by_scenario,
    }


def main():
    print("[*] Loading inventory and global ROA snapshot...")
    inv_tree = loadOperatorInventory(INVENTORY_FILE)
    roa_tree = loadGlobalRoa(ROA_FILE)

    synthetic_events = build_synthetic_events(INVENTORY_FILE, roa_tree)
    print(f"[*] Generated {len(synthetic_events)} labelled synthetic events.")

    # Interleave synthetic events into the real MRT replay stream every N updates
    inject_interval = 500
    synth_idx = 0
    real_processed = 0
    eval_records = []
    alert_latencies_us = []

    def process_synthetic(ev):
        # 1. Benchmark Full Pipeline (Phase 1 Inventory + Phase 2 ROA)
        t0 = time.perf_counter()
        phase, full_status, anomaly_type, evidence = evaluate_update(inv_tree, roa_tree, ev)
        latency_us = (time.perf_counter() - t0) * 1_000_000  # microseconds

        if full_status == "INVALID":
            alert_latencies_us.append(latency_us)

        # 2. Compare against ROA-Only Baseline (Phase 2 only, no inventory)
        roa_status, _, _ = validate_announcement(
            roa_tree, ev["prefix"], ev["prefix_length"], ev["origin_asn"]
        )

        eval_records.append({
            "event_id": ev["event_id"],
            "scenario": ev["scenario"],
            "ground_truth": ev["ground_truth"],
            "prefix": ev["prefix"],
            "origin_asn": ev["origin_asn"],
            "phase": phase,
            "full_status": full_status,
            "roa_only_status": roa_status,
            "anomaly_type": anomaly_type or "NONE",
            "latency_us": round(latency_us, 3),
            "evidence": evidence,
        })

    print("[*] Replaying MRT feed with injected synthetic events...")
    for ann in getBGPData(MRT_FILE):
        evaluate_update(inv_tree, roa_tree, ann)
        real_processed += 1

        if synth_idx < len(synthetic_events) and real_processed % inject_interval == 0:
            process_synthetic(synthetic_events[synth_idx])
            synth_idx += 1

    # Flush any remaining synthetic events if MRT stream ended early
    while synth_idx < len(synthetic_events):
        process_synthetic(synthetic_events[synth_idx])
        synth_idx += 1

    # Save detailed per-event results
    with open(RESULTS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(eval_records[0].keys()))
        writer.writeheader()
        writer.writerows(eval_records)

    full_m = compute_metrics(eval_records, "full_status")
    roa_m = compute_metrics(eval_records, "roa_only_status")

    print(f"\n=== Phase 3 Evaluation Report ({len(eval_records)} Synthetic Events + {real_processed} Real Updates) ===")

    for label, m in [
        ("ROA-Only Baseline (Phase 2 Only)", roa_m),
        ("Full Pipeline (Phase 1 Inventory + Phase 2 ROA)", full_m),
    ]:
        print(f"\n[{label}]")
        print(f"  TP: {m['TP']} | FP: {m['FP']} | TN: {m['TN']} | FN: {m['FN']}")
        print(f"  Precision : {m['Precision']:.4f} ({m['Precision']*100:.2f}%)")
        print(f"  Recall    : {m['Recall']:.4f} ({m['Recall']*100:.2f}%)")
        print(f"  F1-Score  : {m['F1']:.4f}")
        print(f"  False Positives by Scenario: {m['FP_by_scenario'] or 'None (0)'}")

    if alert_latencies_us:
        sorted_lat = sorted(alert_latencies_us)
        p95 = sorted_lat[int(0.95 * len(sorted_lat))]
        print("\n[Alert Latency (T0 -> Explainable Alert)]")
        print(f"  Mean   : {statistics.mean(alert_latencies_us):.2f} µs")
        print(f"  Median : {statistics.median(alert_latencies_us):.2f} µs")
        print(f"  P95    : {p95:.2f} µs")
        print(f"  Max    : {max(alert_latencies_us):.2f} µs")

    print(f"\n[+] Detailed synthetic evaluation saved to {RESULTS_CSV}")


if __name__ == "__main__":
    main()
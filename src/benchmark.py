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
MRT_FILE_ALIGNED = MRT_FILE  # updates.20231001.0000.bz2
MRT_FILE_DRIFTED = str(DATA_DIR / "updates.20231002.0000.bz2")


def run_phase2_stats(roa_tree, updates):
    """Runs Phase 2 Global ROA validation and collects counts + unique invalid routes."""
    counts = {"VALID": 0, "INVALID": 0, "UNKNOWN": 0}
    anomalies = {}
    unique_invalid = set()

    t0 = time.perf_counter()
    for ann in updates:
        status, atype, _ = validate_announcement(
            roa_tree, ann["prefix"], ann["prefix_length"], ann["origin_asn"]
        )
        counts[status] += 1
        if status == "INVALID":
            anomalies[atype] = anomalies.get(atype, 0) + 1
            unique_invalid.add((ann["prefix"], ann["origin_asn"], atype))
    elapsed = time.perf_counter() - t0

    return elapsed, counts, anomalies, len(unique_invalid)


def main():
    # ==================================================================
    # 1. PIPELINE STAGE BREAKDOWN (2023-10-01 ALIGNED FEED)
    # ==================================================================
    print("[*] 1. Benchmarking initialization & MRT parsing...")

    t0 = time.perf_counter()
    inv_tree = loadOperatorInventory(INVENTORY_FILE)
    t_inv_load = time.perf_counter() - t0

    t0 = time.perf_counter()
    roa_tree = loadGlobalRoa(ROA_FILE)
    t_roa_load = time.perf_counter() - t0

    t0 = time.perf_counter()
    updates_day1 = list(getBGPData(MRT_FILE_ALIGNED))
    t_mrt_parse = time.perf_counter() - t0
    n_day1 = len(updates_day1)

    print(f"[*] 2. Running Phase 2 Only on {n_day1:,} updates...")
    t_p2_only, d1_counts, d1_anomalies, d1_unique_inv = run_phase2_stats(
        roa_tree, updates_day1
    )

    print(f"[*] 3. Running Phase 1 + Phase 2 on {n_day1:,} updates...")
    t0 = time.perf_counter()
    for ann in updates_day1:
        evaluate_update(inv_tree, roa_tree, ann)
    t_p1_and_p2 = time.perf_counter() - t0

    # End-to-end streaming time (decompression + parsing + Phase 1 & 2 validation)
    print("[*] 4. Running End-to-End streaming pass...")
    t0 = time.perf_counter()
    e2e_count = 0
    for ann in getBGPData(MRT_FILE_ALIGNED):
        evaluate_update(inv_tree, roa_tree, ann)
        e2e_count += 1
    t_e2e = time.perf_counter() - t0

    # ==================================================================
    # 2. TIME-ALIGNMENT DRIFT (2023-10-02 FEED vs. 2023-10-01 ROAs)
    # ==================================================================
    drift_available = Path(MRT_FILE_DRIFTED).exists()
    if drift_available:
        print(f"[*] 5. Loading drifted feed: {MRT_FILE_DRIFTED}")
        updates_day2 = list(getBGPData(MRT_FILE_DRIFTED))
        n_day2 = len(updates_day2)
        _, d2_counts, d2_anomalies, d2_unique_inv = run_phase2_stats(
            roa_tree, updates_day2
        )
    else:
        print(f"[!] Drifted feed not found at {MRT_FILE_DRIFTED}. Skipping drift section.")

    # ==================================================================
    # 3. PRINT REPORT
    # ==================================================================
    p2_us = (t_p2_only / n_day1) * 1_000_000
    p12_us = (t_p1_and_p2 / n_day1) * 1_000_000
    p1_overhead_s = t_p1_and_p2 - t_p2_only
    p1_overhead_us = p12_us - p2_us

    print("\n" + "=" * 72)
    print(f"BENCHMARK REPORT ({n_day1:,} BGP Updates — 2023-10-01 Feed)")
    print("=" * 72)

    print("\n[1. Pipeline Stage Breakdown]")
    print(f"  Operator Inventory Load (Radix) : {t_inv_load:.4f} s")
    print(f"  Global ROA Load (5 RIR -> Radix): {t_roa_load:.4f} s")
    print(f"  MRT Decompress + Parse (.bz2)   : {t_mrt_parse:.4f} s")
    print(f"  Phase 2 Only (Radix Validation) : {t_p2_only:.4f} s ({p2_us:.2f} µs/update)")
    print(f"  Phase 1 + Phase 2 (Full Logic)  : {t_p1_and_p2:.4f} s ({p12_us:.2f} µs/update)")
    print(f"  Phase 1 Inventory Overhead      : {p1_overhead_s:+.4f} s ({p1_overhead_us:+.2f} µs/update)")
    print(f"  End-to-End Stream (Parse+Valid) : {t_e2e:.4f} s")

    parse_pct = (t_mrt_parse / (t_mrt_parse + t_p1_and_p2)) * 100
    valid_pct = (t_p1_and_p2 / (t_mrt_parse + t_p1_and_p2)) * 100
    print(f"  Runtime Share                   : Parsing {parse_pct:.1f}% | Validation {valid_pct:.1f}%")

    print("\n[2. Throughput]")
    print(f"  Phase 2 Only (Validation)       : {n_day1 / t_p2_only:,.0f} updates/sec")
    print(f"  Phase 1 + Phase 2 (Validation)  : {n_day1 / t_p1_and_p2:,.0f} updates/sec")
    print(f"  End-to-End (bz2 + Parse + Valid): {e2e_count / t_e2e:,.0f} updates/sec")

    if drift_available:
        print("\n[3. Time-Alignment Drift (2023-10-01 ROA Snapshot)]")
        print(f"  {'Metric':28} | {'Aligned (2023-10-01)':>20} | {'Drifted (2023-10-02)':>20}")
        print("  " + "-" * 74)
        print(f"  {'Total Announcements':28} | {n_day1:>20,} | {n_day2:>20,}")

        for key in ("VALID", "INVALID", "UNKNOWN"):
            c1, c2 = d1_counts[key], d2_counts[key]
            p1, p2 = (c1 / n_day1) * 100, (c2 / n_day2) * 100
            print(f"  {key:28} | {c1:>11,} ({p1:5.2f}%) | {c2:>11,} ({p2:5.2f}%)")

        print(f"  {'Unique INVALID (Pfx, ASN)':28} | {d1_unique_inv:>20,} | {d2_unique_inv:>20,}")

        all_types = sorted(set(d1_anomalies.keys()) | set(d2_anomalies.keys()))
        for atype in all_types:
            a1 = d1_anomalies.get(atype, 0)
            a2 = d2_anomalies.get(atype, 0)
            print(f"    - {atype:24} | {a1:>20,} | {a2:>20,}")

    print("=" * 72)


if __name__ == "__main__":
    main()
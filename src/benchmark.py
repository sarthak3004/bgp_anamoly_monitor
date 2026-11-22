import time
from pathlib import Path
from constants import *
from rad import (
    evaluateAnnouncement,
    getBGPData,
    loadGlobalRoa,
    loadOperatorInventory,
    checkRoa,
)

def runPhase2Stats(roaTree, announcements):
    # Runs Phase 2 Global ROA validation and collects counts + unique invalid routes.
    counts = {"VALID": 0, "INVALID": 0, "UNKNOWN": 0}
    anomalies = {}
    unique_invalid = set()

    t0 = time.perf_counter()
    for announcement in announcements:
        status, atype, _ = checkRoa(
            roaTree, announcement["prefix"], announcement["prefix_length"], announcement["origin_asn"]
        )
        counts[status] += 1
        if status == "INVALID":
            anomalies[atype] = anomalies.get(atype, 0) + 1
            unique_invalid.add((announcement["prefix"], announcement["origin_asn"], atype))
    elapsed = time.perf_counter() - t0

    return elapsed, counts, anomalies, len(unique_invalid)


def main():
    print("1. Benchmarking initialization & MRT parsing...")

    t0 = time.perf_counter()
    inventoryTree = loadOperatorInventory(INVENTORY_FILE)
    time_loadingInventory = time.perf_counter() - t0

    t0 = time.perf_counter()
    roaTree = loadGlobalRoa(ROA_PATTERN)
    time_loadingRoa = time.perf_counter() - t0

    t0 = time.perf_counter()
    announcements = list(getBGPData(MRT_FILE_ALIGNED))
    timeMrtParsing = time.perf_counter() - t0
    announcementsCount = len(announcements)

    print(f"2. Running Phase 2 Only on {announcementsCount:,} updates...")
    timePhase2Only, d1_counts, d1_anomalies, d1_unique_inv = runPhase2Stats(roaTree, announcements)

    print(f"3. Running Phase 1 + Phase 2 on {announcementsCount:,} updates...")
    t0 = time.perf_counter()
    for announcement in announcements:
        evaluateAnnouncement(inventoryTree, roaTree, announcement)
    timeBothPhases = time.perf_counter() - t0

    # End-to-end streaming time (decompression + parsing + Phase 1 & 2 validation)
    print("4. Running End-to-End streaming pass...")
    t0 = time.perf_counter()
    totalCount = 0
    for announcement in getBGPData(MRT_FILE_ALIGNED):
        evaluateAnnouncement(inventoryTree, roaTree, announcement)
        totalCount += 1
    totalTime = time.perf_counter() - t0

    # 2. TIME-ALIGNMENT DRIFT
    drift_available = Path(MRT_FILE_DRIFTED).exists()
    if drift_available:
        print(f"5. Loading drifted feed: {MRT_FILE_DRIFTED}")
        updates_day2 = list(getBGPData(MRT_FILE_DRIFTED))
        n_day2 = len(updates_day2)
        _, d2_counts, d2_anomalies, d2_unique_inv = runPhase2Stats(roaTree, updates_day2
        )
    else:
        print(f"[!] Drifted feed not found at {MRT_FILE_DRIFTED}. Skipping drift section.")

    # 3. PRINT REPORT
    p2_us = (timePhase2Only / announcementsCount) * 1000000
    p12_us = (timeBothPhases / announcementsCount) * 1000000
    p1_overhead_s = timeBothPhases - timePhase2Only
    p1_overhead_us = p12_us - p2_us

    print("\n" + "=" * 100)
    print(f"BENCHMARK REPORT ({announcementsCount:,} BGP Updates)")
    print("=" * 100)

    print("\n[1. Pipeline Stage Breakdown]")
    print(f"  Operator Inventory Load (Radix) : {time_loadingInventory:.4f} s")
    print(f"  Global ROA Load (5 RIR -> Radix): {time_loadingRoa:.4f} s")
    print(f"  MRT Decompress + Parse (.bz2)   : {timeMrtParsing:.4f} s")
    print(f"  Phase 2 Only (Radix Validation) : {timePhase2Only:.4f} s ({p2_us:.2f} µs/update)")
    print(f"  Phase 1 + Phase 2 (Full Logic)  : {timeBothPhases:.4f} s ({p12_us:.2f} µs/update)")
    print(f"  Phase 1 Inventory Overhead      : {p1_overhead_s:+.4f} s ({p1_overhead_us:+.2f} µs/update)")
    print(f"  End-to-End Stream (Parse+Valid) : {totalTime:.4f} s")

    parse_pct = (timeMrtParsing / (timeMrtParsing + timeBothPhases)) * 100
    valid_pct = (timeBothPhases / (timeMrtParsing + timeBothPhases)) * 100
    print(f"  Runtime Share                   : Parsing {parse_pct:.1f}% | Validation {valid_pct:.1f}%")

    print("\n[2. Throughput]")
    print(f"  Phase 2 Only (Validation)       : {announcementsCount / timePhase2Only:,.0f} updates/sec")
    print(f"  Phase 1 + Phase 2 (Validation)  : {announcementsCount / timeBothPhases:,.0f} updates/sec")
    print(f"  End-to-End (bz2 + Parse + Valid): {totalCount / totalTime:,.0f} updates/sec")

    if drift_available:
        print("\n[3. Time-Alignment Drift]")
        print(f"  {'Metric':28} | {'Aligned':>20} | {'Drifted':>20}")
        print("  " + "-" * 74)
        print(f"  {'Total Announcements':28} | {announcementsCount:>20,} | {n_day2:>20,}")

        for key in ("VALID", "INVALID", "UNKNOWN"):
            c1, c2 = d1_counts[key], d2_counts[key]
            p1, p2 = (c1 / announcementsCount) * 100, (c2 / n_day2) * 100
            print(f"  {key:28} | {c1:>11,} ({p1:5.2f}%) | {c2:>11,} ({p2:5.2f}%)")

        print(f"  {'Unique INVALID (Pfx, ASN)':28} | {d1_unique_inv:>20,} | {d2_unique_inv:>20,}")

        all_types = sorted(set(d1_anomalies.keys()) | set(d2_anomalies.keys()))
        for atype in all_types:
            a1 = d1_anomalies.get(atype, 0)
            a2 = d2_anomalies.get(atype, 0)
            print(f"    - {atype:24} | {a1:>20,} | {a2:>20,}")

    print("=" * 100)


if __name__ == "__main__":
    main()
"""Alert-latency benchmark: ROAs stored as sorted intervals + binary search.

Same experiment as generate_synthetic.py (same synthetic events, same MRT replay,
same injection every 500 real updates, same metrics), but Phase 2 (global ROA
validation) looks ROAs up in sorted CIDR intervals with binary search and a parent chain instead of the py-radix tree.

Run:  python performace_when_using_intervals_for_roa_storage.py

Needs (already in your project): constants.py, rad.py, generate_synthetic.py
Writes: interval_eval_results.csv
"""
import csv
import glob
import ipaddress
import statistics
import time
from bisect import bisect_right
from constants import *
from rad import checkInventory, getBGPData, loadGlobalRoa, loadOperatorInventory
from generate_synthetic import buildSyntheticEvents, computeMetrics, printMetrics

RESULTS_FILE = str(DATA_DIR / "interval_eval_results.csv")


# ----------------------------------------------------------------------------
# Prefix parsing: text -> (ip version, first address, last address, length)
# ----------------------------------------------------------------------------
def parsePrefix(text, length=None):
    ip, _, lenText = text.partition("/")
    if length is None:
        length = int(lenText)
    if ":" in ip:
        version, width = 6, 128
        value = int(ipaddress.IPv6Address(ip))
    else:
        version, width = 4, 32
        a, b, c, d = ip.split(".")
        if not all(0 <= int(x) <= 255 for x in (a, b, c, d)):
            raise ValueError("bad IPv4 address: " + text)
        value = (int(a) << 24) | (int(b) << 16) | (int(c) << 8) | int(d)
    if not 0 <= length <= width:
        raise ValueError("bad prefix length: " + text)
    hostBits = width - length
    start = (value >> hostBits) << hostBits
    return version, start, start | ((1 << hostBits) - 1), length


def loadRoaRecords(pattern=ROA_PATTERN):
    """Read every ROA csv -> list of (version, start, end, length, asn, max_length)."""
    records = []
    for path in glob.glob(pattern):
        with open(path, "r") as f:
            for row in csv.DictReader(f):
                version, start, end, length = parsePrefix(row["IP Prefix"])
                asn = str(row["ASN"]).replace("AS", "")
                records.append((version, start, end, length, asn, int(row["Max Length"])))
    return records


# ----------------------------------------------------------------------------
# Sorted-interval storage (inspired by match_intervals.py)
# Every distinct CIDR block becomes [start, end]; blocks are sorted by start (outer
# before inner on ties) and each knows its nearest enclosing block ("parent").
# A query binary-searches the last block starting at/before it, then walks parents.
# ----------------------------------------------------------------------------
class IntervalRoaStore:
    def __init__(self, records):
        grouped = {4: {}, 6: {}}
        for version, start, end, length, asn, maximum in records:
            grouped[version].setdefault((start, end), []).append((asn, maximum))
        self.families = {}
        for version, groups in grouped.items():
            nodes = sorted(groups, key=lambda k: (k[0], -k[1]))
            starts, ends, parents, roas, stack = [], [], [], [], []
            for index, (start, end) in enumerate(nodes):
                while stack and ends[stack[-1]] < end:
                    stack.pop()
                parents.append(stack[-1] if stack else -1)
                starts.append(start)
                ends.append(end)
                roas.append(groups[start, end])
                stack.append(index)
            self.families[version] = (starts, ends, parents, roas)

    def covering(self, version, start, end, length):
        starts, ends, parents, roas = self.families[version]
        index = bisect_right(starts, start) - 1
        while index >= 0:
            if ends[index] >= end:          # must cover the WHOLE query range
                yield from roas[index]
            index = parents[index]


# ----------------------------------------------------------------------------
# Phase 2 (ROA validation) on top of the matcher; same verdicts as rad.checkRoa
# ----------------------------------------------------------------------------
def checkRoaFast(matcher, prefixStr, prefixLen, originAsn):
    try:
        version, start, end, length = parsePrefix(prefixStr, prefixLen)
    except ValueError:
        return "INVALID", "MALFORMED_PREFIX", "Malformed prefix: " + prefixStr
    origin = str(originAsn)
    seen = False
    kind = None
    for asn, maximum in matcher.covering(version, start, end, length):
        seen = True
        if asn == origin:
            if prefixLen <= maximum:
                return "VALID", None, "Route is fully authorized by ROA."
            kind = "ROA_SUBPREFIX_ANOMALY"
        elif kind is None:
            kind = "ROA_ORIGIN_ANOMALY"
    if not seen:
        return "UNKNOWN", None, "No ROA found covering this prefix."
    return "INVALID", kind, "ROA check failed: " + kind


def evaluateAnnouncementFast(invTree, matcher, ann):
    status, anomaly, evidence = checkInventory(
        invTree, ann["prefix"], ann["prefix_length"], ann["origin_asn"])
    if status != "EXTERNAL":
        return "PHASE_1_INVENTORY", status, anomaly, evidence
    status, anomaly, evidence = checkRoaFast(matcher, ann["prefix"], ann["prefix_length"], ann["origin_asn"])
    return "PHASE_2_ROA", status, anomaly, evidence


def main():
    print("Loading inventory and ROA data...")
    invTree = loadOperatorInventory(INVENTORY_FILE)
    # radix tree is used ONLY to generate the same synthetic events as generate_synthetic.py
    radixTree = loadGlobalRoa(ROA_PATTERN)
    records = loadRoaRecords(ROA_PATTERN)

    t0 = time.perf_counter()
    matcher = IntervalRoaStore(records)
    buildSec = time.perf_counter() - t0
    print(f"Built interval store over {len(records):,} ROAs in {buildSec:.3f} s")

    syntheticEvents = buildSyntheticEvents(INVENTORY_FILE, radixTree)
    print(f"Built {len(syntheticEvents)} synthetic events.")

    injectInterval = 500
    synthIdx = 0
    realCount = 0
    evalRecords = []
    alertLatencies = []

    def runEvent(ev):
        t0 = time.perf_counter()
        phase, fullStatus, anomalyType, evidence = evaluateAnnouncementFast(invTree, matcher, ev)
        latencyUs = (time.perf_counter() - t0) * 1e6
        if fullStatus == "INVALID":
            alertLatencies.append(latencyUs)
        roaStatus, _, _ = checkRoaFast(matcher, ev["prefix"], ev["prefix_length"], ev["origin_asn"])
        evalRecords.append({
            "event_id": ev["event_id"],
            "scenario": ev["scenario"],
            "ground_truth": ev["ground_truth"],
            "prefix": ev["prefix"],
            "origin_asn": ev["origin_asn"],
            "phase": phase,
            "full_status": fullStatus,
            "roa_only_status": roaStatus,
            "anomaly_type": anomalyType or "NONE",
            "latency_us": round(latencyUs, 3),
            "evidence": evidence,
        })

    print("Replaying MRT feed...")
    realLatencies = []
    perf = time.perf_counter
    for ann in getBGPData(MRT_FILE):
        t0 = perf()
        evaluateAnnouncementFast(invTree, matcher, ann)
        realLatencies.append((perf() - t0) * 1e6)
        realCount += 1
        if synthIdx < len(syntheticEvents) and realCount % injectInterval == 0:
            runEvent(syntheticEvents[synthIdx])
            synthIdx += 1

    while synthIdx < len(syntheticEvents):
        runEvent(syntheticEvents[synthIdx])
        synthIdx += 1

    with open(RESULTS_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(evalRecords[0].keys()))
        writer.writeheader()
        writer.writerows(evalRecords)

    print(f"\nEvaluation summary ({len(evalRecords)} synthetic, {realCount} real updates) -- interval store:")
    printMetrics("ROA-only baseline", computeMetrics(evalRecords, "roa_only_status"))
    printMetrics("Full pipeline (inventory + ROA)", computeMetrics(evalRecords, "full_status"))

    def report(title, values):
        s = sorted(values)
        print(f"\n{title} (n={len(s)}):")
        print(f"  Mean:   {statistics.mean(s):.2f} us")
        print(f"  Median: {statistics.median(s):.2f} us")
        print(f"  P95:    {s[int(0.95 * len(s))]:.2f} us")
        print(f"  P99:    {s[int(0.99 * len(s))]:.2f} us")
        print(f"  Max:    {s[-1]:.2f} us")

    print(f"\nROA build time: {buildSec:.3f} s")
    if alertLatencies:
        report("Alert latency (synthetic events flagged INVALID)", alertLatencies)
    if realLatencies:
        report("Per-announcement latency (all real MRT updates)", realLatencies)
        print(f"  Throughput: {len(realLatencies) / (sum(realLatencies) / 1e6):,.0f} updates/s")
    print(f"\nSaved results to {RESULTS_FILE}")


if __name__ == "__main__":
    main()

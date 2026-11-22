import csv
import ipaddress
import statistics
import time
from constants import *
from rad import (
    evaluateAnnouncement,
    getBGPData,
    loadGlobalRoa,
    loadOperatorInventory,
    checkRoa,
)

def makeSubprefix(prefixStr, targetLen):
    net = ipaddress.ip_network(prefixStr, strict=False)
    clampedLen = min(targetLen, net.max_prefixlen)
    if clampedLen <= net.prefixlen:
        return None, None
    sub = next(net.subnets(new_prefix=clampedLen))
    return str(sub), clampedLen

def makeEvent(eventId, scenario, truth, ts, prefix, prefixLen, originAsn):
    return {
        "event_id": eventId,
        "scenario": scenario,
        "ground_truth": truth,
        "timestamp": ts,
        "prefix": prefix,
        "prefix_length": prefixLen,
        "origin_asn": originAsn,
    }

def buildSyntheticEvents(inventoryCsv, roaTree):
    events = []
    baseTs = 1696118400  # 2023-10-01 00:00:00 UTC
    simAsn = str(SIMULATING_ASN)

    with open(inventoryCsv, "r") as f:
        rows = list(csv.DictReader(f))

    # Track owned prefixes so synthetic subprefixes don't collide with valid child blocks
    invPrefixes = {r["prefix"].strip() for r in rows}

    for idx, row in enumerate(rows):
        prefix = row["prefix"].strip()
        expectedAsns = [a.strip() for a in row["expected_asns"].split("|") if a.strip()]
        maxLen = int(row["expected_max_len"])
        category = row["category"].strip()
        net = ipaddress.ip_network(prefix, strict=False)
        ts = baseTs + idx * 10

        primaryAsn = next((a for a in expectedAsns if a != simAsn), expectedAsns[0])

        # Benign traffic
        if category == "moas":
            for asn in expectedAsns:
                events.append(makeEvent(
                    f"MOAS_BENIGN_{idx}_{asn}", "LEGIT_MOAS", "BENIGN",
                    ts, prefix, net.prefixlen, asn
                ))
        elif category == "policy_shift":
            # Migrating ASN is in inventory, not yet in public ROA
            migratingAsn = simAsn if simAsn in expectedAsns else expectedAsns[-1]
            events.append(makeEvent(
                f"POLICY_SHIFT_{idx}_{migratingAsn}", "LEGIT_POLICY_CHANGE", "BENIGN",
                ts, prefix, net.prefixlen, migratingAsn
            ))
        else:
            scenario = "LEGIT_UNROA" if category == "unroa" else "LEGIT_SINGLE"
            events.append(makeEvent(
                f"SINGLE_BENIGN_{idx}", scenario, "BENIGN",
                ts, prefix, net.prefixlen, primaryAsn
            ))

        # Origin hijack on owned space
        originScenario = "ORIGIN_HIJACK_UNROA" if category == "unroa" else "ORIGIN_HIJACK_INTERNAL"
        events.append(makeEvent(
            f"INV_ORIGIN_HIJACK_{idx}", originScenario, "ANOMALY",
            ts + 1, prefix, net.prefixlen, ROGUE_ASN
        ))

        # More-specific subprefix misconfig & hijack
        subPrefix, subLen = makeSubprefix(prefix, maxLen + 2)
        if subPrefix and subPrefix not in invPrefixes:
            misconfigScen = "SUBPREFIX_MISCONFIG_UNROA" if category == "unroa" else "SUBPREFIX_MISCONFIG_INTERNAL"
            hijackScen = "SUBPREFIX_HIJACK_UNROA" if category == "unroa" else "SUBPREFIX_HIJACK_INTERNAL"

            events.append(makeEvent(
                f"INV_SUBPREFIX_MISCONFIG_{idx}", misconfigScen, "ANOMALY",
                ts + 2, subPrefix, subLen, primaryAsn
            ))
            events.append(makeEvent(
                f"INV_SUBPREFIX_HIJACK_{idx}", hijackScen, "ANOMALY",
                ts + 3, subPrefix, subLen, ROGUE_ASN
            ))

    # External ROA hijacks (up to 10)
    extAdded = 0
    for node in roaTree:
        if node.prefix in invPrefixes:
            continue
        roa = node.data["roas"][0]
        net = ipaddress.ip_network(node.prefix, strict=False)
        if roa["max_length"] >= net.max_prefixlen - 1:
            continue

        ts = baseTs + 500 + extAdded * 10
        events.append(makeEvent(
            f"EXT_ORIGIN_HIJACK_{extAdded}", "ORIGIN_HIJACK_EXTERNAL", "ANOMALY",
            ts, node.prefix, net.prefixlen, ROGUE_ASN
        ))

        subPrefix, subLen = makeSubprefix(node.prefix, roa["max_length"] + 1)
        if subPrefix:
            events.append(makeEvent(
                f"EXT_SUBPREFIX_HIJACK_{extAdded}", "SUBPREFIX_HIJACK_EXTERNAL", "ANOMALY",
                ts + 1, subPrefix, subLen, roa["asn"]
            ))

        extAdded += 1
        if extAdded >= 10:
            break

    return events


def computeMetrics(records, predKey):
    tp = fp = tn = fn = 0
    fpByScenario = {}
    fnByScenario = {}

    for rec in records:
        isAnomaly = rec["ground_truth"] == "ANOMALY"
        predAnomaly = rec[predKey] == "INVALID"

        if isAnomaly and predAnomaly:
            tp += 1
        elif not isAnomaly and predAnomaly:
            fp += 1
            sc = rec["scenario"]
            fpByScenario[sc] = fpByScenario.get(sc, 0) + 1
        elif not isAnomaly and not predAnomaly:
            tn += 1
        else:
            fn += 1
            sc = rec["scenario"]
            fnByScenario[sc] = fnByScenario.get(sc, 0) + 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": precision, "Recall": recall, "F1": f1,
        "fpByScenario": fpByScenario,
        "fnByScenario": fnByScenario,
    }

def printMetrics(label, m):
    print(f"\n{label}")
    print(f"  TP: {m['TP']} | FP: {m['FP']} | TN: {m['TN']} | FN: {m['FN']}")
    print(f"  Precision: {m['Precision']:.4f} ({m['Precision'] * 100:.2f}%)")
    print(f"  Recall:    {m['Recall']:.4f} ({m['Recall'] * 100:.2f}%)")
    print(f"  F1:        {m['F1']:.4f}")
    print(f"  FP scenarios: {m['fpByScenario'] or 'None'}")
    print(f"  FN scenarios: {m['fnByScenario'] or 'None'}")


def main():
    print("Loading inventory and ROA data...")
    invTree = loadOperatorInventory(INVENTORY_FILE)
    roaTree = loadGlobalRoa(ROA_PATTERN)

    syntheticEvents = buildSyntheticEvents(INVENTORY_FILE, roaTree)
    print(f"Built {len(syntheticEvents)} synthetic events.")

    injectInterval = 500
    synthIdx = 0
    realCount = 0
    evalRecords = []
    alertLatencies = []

    def runEvent(ev):
        t0 = time.perf_counter()
        phase, fullStatus, anomalyType, evidence = evaluateAnnouncement(invTree, roaTree, ev)
        latencyUs = (time.perf_counter() - t0) * 1e6

        if fullStatus == "INVALID":
            alertLatencies.append(latencyUs)

        roaStatus, _, _ = checkRoa(roaTree, ev["prefix"], ev["prefix_length"], ev["origin_asn"])

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
    for ann in getBGPData(MRT_FILE):
        evaluateAnnouncement(invTree, roaTree, ann)
        realCount += 1

        if synthIdx < len(syntheticEvents) and realCount % injectInterval == 0:
            runEvent(syntheticEvents[synthIdx])
            synthIdx += 1

    # Flush leftovers if the MRT stream finishes before all synthetic events are injected
    while synthIdx < len(syntheticEvents):
        runEvent(syntheticEvents[synthIdx])
        synthIdx += 1

    with open(RESULTS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(evalRecords[0].keys()))
        writer.writeheader()
        writer.writerows(evalRecords)

    fullMetrics = computeMetrics(evalRecords, "full_status")
    roaMetrics = computeMetrics(evalRecords, "roa_only_status")

    print(f"\nEvaluation summary ({len(evalRecords)} synthetic, {realCount} real updates):")
    printMetrics("ROA-only baseline", roaMetrics)
    printMetrics("Full pipeline (inventory + ROA)", fullMetrics)

    if alertLatencies:
        sortedLat = sorted(alertLatencies)
        p95 = sortedLat[int(0.95 * len(sortedLat))]
        print("\nAlert latency:")
        print(f"  Mean:   {statistics.mean(alertLatencies):.2f} us")
        print(f"  Median: {statistics.median(alertLatencies):.2f} us")
        print(f"  P95:    {p95:.2f} us")
        print(f"  Max:    {max(alertLatencies):.2f} us")

    print(f"\nSaved results to {RESULTS_CSV}")


if __name__ == "__main__":
    main()
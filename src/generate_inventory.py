import csv
import glob
from collections import Counter

import radix
from mrtparse import Reader
from constants import *


def loadGlobalRoa():
    roaTree = radix.Radix()
    for path in glob.glob(ROA_PATTERN):
        with open(path, "r") as f:
            for row in csv.DictReader(f):
                prefix = row["IP Prefix"]
                asn = str(row["ASN"]).replace("AS", "")
                maxLen = int(row["Max Length"])
                node = roaTree.search_exact(prefix) or roaTree.add(prefix)
                node.data.setdefault("roas", []).append({"asn": asn, "max_length": maxLen})
    return roaTree


def scanMrtFeed():
    asnCounts = Counter()
    prefixCounts = Counter()
    prefixAsns = {}

    for entry in Reader(MRT_FILE):
        data = entry.data
        if not data or "BGP4MP" not in str(data.get("type", "")):
            continue
        bgp = data.get("bgp_message", {})
        if "UPDATE" not in str(bgp.get("type", "")):
            continue

        originAsn = None
        for attr in bgp.get("path_attributes", []):
            if "AS_PATH" in str(attr.get("type", "")):
                segments = attr.get("value", [])
                if segments:
                    asnList = segments[-1].get("value", segments[-1].get("val", []))
                    if asnList:
                        originAsn = str(asnList[-1])

        if not originAsn:
            continue

        for nlri in bgp.get("nlri", []):
            rawLen = nlri.get("length")
            ip = nlri.get("prefix")
            if rawLen not in (None, "") and ip:
                prefix = f"{ip}/{rawLen}"
                prefixCounts[prefix] += 1
                prefixAsns.setdefault(prefix, set()).add(originAsn)
                asnCounts[originAsn] += 1

    return asnCounts, prefixCounts, prefixAsns


def selectTargetAsn(asnCounts, roaTree):
    asnToNodes = {}
    for node in roaTree:
        for asn in {r["asn"] for r in node.data["roas"]}:
            asnToNodes.setdefault(asn, []).append(node)

    # Try configured bounds first, then fall back to a wider range
    for minP, maxP in [(MIN_PREFIXES, MAX_PREFIXES), (5, 150)]:
        for asn, updateCount in asnCounts.most_common():
            nodes = asnToNodes.get(asn, [])
            if not (minP <= len(nodes) <= maxP):
                continue
            subprefixReady = sum(
                1 for n in nodes if max(r["max_length"] for r in n.data["roas"]) <= 22
            )
            if subprefixReady >= 3:
                return asn, updateCount, nodes

    raise RuntimeError("No active ASN matched the prefix criteria.")


def buildAsnInventory(roaTree, targetAsn, targetNodes):
    selectedNodes = {}
    for node in targetNodes:
        selectedNodes[node.prefix] = node
        # Pull in covered child ROAs so real traffic under this parent doesn't trigger false alerts
        for child in roaTree.search_covered(node.prefix):
            selectedNodes[child.prefix] = child

    invTree = radix.Radix()
    rows = []
    policyShiftAdded = 0
    simAsn = str(SIMULATING_ASN)

    for prefix in sorted(selectedNodes.keys()):
        roas = selectedNodes[prefix].data["roas"]
        asns = sorted({r["asn"] for r in roas})
        maxLen = max(r["max_length"] for r in roas)

        if len(asns) > 1:
            category = "moas"
            expectedAsns = asns
        elif maxLen <= 22 and policyShiftAdded < 3 and str(targetAsn) in asns:
            category = "policy_shift"
            expectedAsns = sorted(set(asns) | {simAsn})
            policyShiftAdded += 1
        else:
            category = "single"
            expectedAsns = asns

        invTree.add(prefix)
        rows.append([prefix, "|".join(expectedAsns), maxLen, category])

    return invTree, rows


def findUnroaPrefixes(roaTree, invTree, prefixCounts, prefixAsns, targetAsn, limit=UNROA_COUNT):
    candidates = []
    for prefix, _ in prefixCounts.most_common(3000):
        asns = prefixAsns[prefix]
        if len(asns) != 1:
            continue
        try:
            if roaTree.search_covering(prefix):
                continue
            if invTree.search_covering(prefix) or invTree.search_covered(prefix):
                continue
        except ValueError:
            continue

        originAsn = next(iter(asns))
        prefixLen = int(prefix.split("/")[1])
        isTarget = originAsn == str(targetAsn)
        candidates.append((isTarget, prefix, originAsn, prefixLen))

    # Prefer prefixes announced by targetAsn
    candidates.sort(key=lambda x: x[0], reverse=True)

    return [[prefix, originAsn, prefixLen, "unroa"] for _, prefix, originAsn, prefixLen in candidates[:limit]]


def main():
    print("Loading global ROAs...")
    roaTree = loadGlobalRoa()

    print(f"Scanning {MRT_FILE}...")
    asnCounts, prefixCounts, prefixAsns = scanMrtFeed()

    targetAsn, updateCount, targetNodes = selectTargetAsn(asnCounts, roaTree)
    print(f"Selected AS{targetAsn} ({updateCount:,} updates, {len(targetNodes)} ROA blocks)")

    invTree, rows = buildAsnInventory(roaTree, targetAsn, targetNodes)
    rows.extend(findUnroaPrefixes(roaTree, invTree, prefixCounts, prefixAsns, targetAsn))

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["prefix", "expected_asns", "expected_max_len", "category"])
        writer.writerows(rows)

    catCounts = Counter(r[3] for r in rows)
    print(
        f"Wrote {len(rows)} prefixes to {OUTPUT_CSV} "
        f"(single: {catCounts['single']}, moas: {catCounts['moas']}, "
        f"policy_shift: {catCounts['policy_shift']}, unroa: {catCounts['unroa']})"
    )


if __name__ == "__main__":
    main()
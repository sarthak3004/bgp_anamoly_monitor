import radix
import csv
import glob
from mrtparse import Reader
from constants import *


def loadOperatorInventory(inventoryFilePath = INVENTORY_FILE):
    #Loads the operator prefix inventory into a Radix tree for Phase 1 checks.
    inventoryTree = radix.Radix()
    with open(inventoryFilePath, 'r') as f:
        for row in csv.DictReader(f):
            prefix = row['prefix'].strip()
            expected_asns = {asn.strip() for asn in row['expected_asns'].split('|') if asn.strip()}
            expected_max_len = int(row['expected_max_len'])
            category = row.get('category', 'single').strip()

            node = inventoryTree.search_exact(prefix) or inventoryTree.add(prefix)
            node.data['expected_asns'] = expected_asns
            node.data['expected_max_len'] = expected_max_len
            node.data['category'] = category

    return inventoryTree

def loadGlobalRoa(file_patterns = ROA_PATTERN):
    #Loads all 5 regional time-aligned ROA CSVs into a single global Radix tree.
    roaTree = radix.Radix()
    for csv_filepath in glob.glob(file_patterns):
        with open(csv_filepath, 'r') as f:
            for row in csv.DictReader(f):
                prefix = row['IP Prefix']
                asn = str(row['ASN']).replace('AS', '')
                max_len = int(row['Max Length'])

                node = roaTree.search_exact(prefix) or roaTree.add(prefix)
                node.data.setdefault('roas', []).append({'asn': asn, 'max_length': max_len})

    return roaTree

def getBGPData(mrt_file = MRT_FILE):
    print(f"Opening compressed BGP feed: {mrt_file}")
    for entry in Reader(mrt_file):
        data = entry.data
        if not data or 'BGP4MP' not in str(data.get('type', '')):
            continue

        bgp = data.get('bgp_message', {})
        if 'UPDATE' not in str(bgp.get('type', '')):
            continue

        origin_asn = None
        for attr in bgp.get('path_attributes', []):
            if 'AS_PATH' in str(attr.get('type', '')):
                segments = attr.get('value', [])
                if segments:
                    last_segment = segments[-1]
                    asn_list = last_segment.get('value', last_segment.get('val', []))
                    if asn_list:
                        origin_asn = str(asn_list[-1])

        if not origin_asn:
            continue

        ts_raw = data.get('timestamp', 'Unknown')
        if isinstance(ts_raw, dict):
            timestamp = list(ts_raw.keys())[0]
        elif isinstance(ts_raw, list):
            timestamp = ts_raw[0]
        else:
            timestamp = ts_raw

        for nlri in bgp.get('nlri', []):
            raw_length = nlri.get('length')
            prefix_ip = nlri.get('prefix')
            if raw_length in (None, '') or not prefix_ip:
                continue

            try:
                length = int(raw_length)
            except ValueError:
                continue

            yield {
                "timestamp": timestamp,
                "origin_asn": origin_asn,
                "prefix": f"{prefix_ip}/{length}",
                "prefix_length": length
            }

def checkInventory(inventoryTree, prefix_str, prefix_len, origin_asn):
    """
    Returns: (Status, Anomaly_Type, Evidence)
      - Status is 'EXTERNAL' if not in inventory (proceed to Phase 2).
      - Status is 'VALID_INTERNAL' or 'INVALID' if covered by inventory.
    """
    try:
        covering_nodes = inventoryTree.search_covering(prefix_str)
    except ValueError:
        return "INVALID", "MALFORMED_PREFIX", f"Malformed prefix or invalid masklen: {prefix_str}"

    if not covering_nodes:
        return "EXTERNAL", None, None

    node = covering_nodes[0] # Use the most specific covering inventory block
    expected_asns = node.data['expected_asns']
    expected_max_len = node.data['expected_max_len']
    category = node.data['category']

    if str(origin_asn) not in expected_asns:
        return (
            "INVALID",
            "INVENTORY_ORIGIN_HIJACK",
            f"Inventory Origin Hijack: Unauthorized AS{origin_asn} announced {prefix_str} "
            f"(owned block {node.prefix} expects ASNs {sorted(expected_asns)})."
        )

    if prefix_len > expected_max_len:
        return (
            "INVALID",
            "INVENTORY_SUBPREFIX_MISCONFIG",
            f"Inventory Subprefix Misconfig: AS{origin_asn} announced {prefix_str}, "
            f"exceeding inventory MaxLength /{expected_max_len} for {node.prefix}."
        )

    return (
        "VALID_INTERNAL",
        None,
        f"Valid internal route ({category}) for owned block {node.prefix}."
    )


def checkRoa(rtree, prefix_str, prefix_len, origin_asn):
    """
    Phase 2: Evaluates an external BGP announcement against the global ROA Radix tree.
    Returns: (Status, Anomaly Type, Evidence)
    """
    try:
        covering_nodes = rtree.search_covering(prefix_str)
    except ValueError:
        return "INVALID", "MALFORMED_PREFIX", f"Malformed prefix or invalid masklen: {prefix_str}"

    if not covering_nodes:
        return "UNKNOWN", None, "No ROA found covering this prefix."

    invalid_type = None
    invalid_reason = None

    for node in covering_nodes:
        for roa in node.data['roas']:
            if str(origin_asn) == roa['asn']:
                if prefix_len <= roa['max_length']:
                    return "VALID", None, "Route is fully authorized by ROA."
                else:
                    invalid_type = "ROA_SUBPREFIX_ANOMALY"
                    invalid_reason = (
                        f"Subprefix Anomaly: AS{origin_asn} is authorized for {node.prefix}, "
                        f"but /{prefix_len} exceeds ROA MaxLength /{roa['max_length']}."
                    )
            else:
                if not invalid_reason:
                    invalid_type = "ROA_ORIGIN_ANOMALY"
                    invalid_reason = (
                        f"Origin Anomaly: AS{origin_asn} does not match authorized "
                        f"ROA AS{roa['asn']} for {node.prefix}."
                    )

    return "INVALID", invalid_type, invalid_reason


def evaluateAnnouncement(inventoryTree, roaTree, announcement):
    """
    Runs Phase 1 (Inventory) -> Phase 2 (Global ROA) on a single announcement.
    """
    # Phase 1: Operator Prefix Inventory
    status, anamolyType, evidence = checkInventory(inventoryTree, announcement['prefix'], announcement['prefix_length'], announcement['origin_asn'])
    if status != "EXTERNAL":
        return "PHASE_1_INVENTORY", status, anamolyType, evidence

    # Phase 2: Global ROA Validation
    status, anamolyType, evidence = checkRoa(roaTree, announcement['prefix'], announcement['prefix_length'], announcement['origin_asn'])
    return "PHASE_2_ROA", status, anamolyType, evidence


if __name__ == "__main__":
    print("Loading operator inventory and global ROAs...")
    inventoryTree = loadOperatorInventory(INVENTORY_FILE)
    globalRoaTree = loadGlobalRoa(ROA_PATTERN)

    phaseWiseCounts = {
        "PHASE_1_INVENTORY": {
            "TOTAL": 0,
            "VALID_INTERNAL": 0,
            "INVALID": 0,
            "ANOMALIES": {}
        },
        "PHASE_2_ROA": {
            "TOTAL": 0,
            "VALID": 0,
            "INVALID": 0,
            "UNKNOWN": 0,
            "ANOMALIES": {}
        }
    }
    alerts = []

    for announcement in getBGPData():
        phase, status, anomaly_type, evidence = evaluateAnnouncement(inventoryTree, globalRoaTree, announcement)

        phaseWiseCounts[phase]["TOTAL"] += 1
        phaseWiseCounts[phase][status] += 1

        if status == "INVALID":
            phaseWiseCounts[phase]["ANOMALIES"][anomaly_type] = (
                phaseWiseCounts[phase]["ANOMALIES"].get(anomaly_type, 0) + 1
            )
            alerts.append([
                announcement['timestamp'], phase, anomaly_type,
                announcement['prefix'], announcement['origin_asn'], evidence
            ])

    with open(ALERTS_LOG, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "phase", "anomaly_type", "prefix", "origin_asn", "evidence"])
        writer.writerows(alerts)

    p1 = phaseWiseCounts["PHASE_1_INVENTORY"]
    p2 = phaseWiseCounts["PHASE_2_ROA"]
    total_updates = p1["TOTAL"] + p2["TOTAL"]

    print(f"\n=== Replay Summary (Total Updates: {total_updates}) ===")

    print("\n[Phase 1: Operator Inventory]")
    print(f"  Total Matched  : {p1['TOTAL']}")
    print(f"  VALID_INTERNAL : {p1['VALID_INTERNAL']}")
    print(f"  INVALID        : {p1['INVALID']}")
    for atype, cnt in p1["ANOMALIES"].items():
        print(f"    - {atype}: {cnt}")

    print("\n[Phase 2: Global ROA Validation]")
    print(f"  Total Checked  : {p2['TOTAL']}")
    print(f"  VALID          : {p2['VALID']}")
    print(f"  INVALID        : {p2['INVALID']}")
    for atype, cnt in p2["ANOMALIES"].items():
        print(f"    - {atype}: {cnt}")
    print(f"  UNKNOWN        : {p2['UNKNOWN']}")
import csv
import glob
import radix
from collections import Counter
from mrtparse import Reader

MRT_FILE = "../data/updates.20231001.0000.bz2"
ROA_PATTERN = "../data/roas/roas_*.csv"
OUTPUT_CSV = "../data/inventory.csv"

def load_roa_tree():
    rtree = radix.Radix()
    for path in glob.glob(ROA_PATTERN):
        with open(path, 'r') as f:
            for row in csv.DictReader(f):
                prefix = row['IP Prefix']
                asn = str(row['ASN']).replace('AS', '')
                max_len = int(row['Max Length'])
                node = rtree.search_exact(prefix) or rtree.add(prefix)
                node.data.setdefault('roas', []).append({'asn': asn, 'max_length': max_len})
    return rtree

def main():
    print("[*] Loading global ROAs...")
    roa_tree = load_roa_tree()

    print(f"[*] Scanning {MRT_FILE} for active prefixes...")
    counts = Counter()
    for entry in Reader(MRT_FILE):
        data = entry.data
        if not data or 'BGP4MP' not in str(data.get('type', '')):
            continue
        bgp = data.get('bgp_message', {})
        if 'UPDATE' not in str(bgp.get('type', '')):
            continue
        for nlri in bgp.get('nlri', []):
            raw_len = nlri.get('length')
            ip = nlri.get('prefix')
            if raw_len not in (None, '') and ip:
                counts[f"{ip}/{raw_len}"] += 1

    single_rows, moas_rows, policy_rows = [], [], []
    used_prefixes = set()

    for prefix, _ in counts.most_common(1000):
        try:
            nodes = roa_tree.search_covering(prefix)
        except ValueError:
            continue
        if not nodes:
            continue

        # Use the covering ROA prefix so inventory holds the parent block
        parent = nodes[0]
        parent_prefix = parent.prefix
        if parent_prefix in used_prefixes:
            continue

        roas = parent.data['roas']
        asns = sorted({r['asn'] for r in roas})
        max_len = max(r['max_length'] for r in roas)

        # 1. MOAS candidates (2+ authorized ASNs in ROA)
        if len(asns) > 1 and len(moas_rows) < 5:
            moas_rows.append([parent_prefix, "|".join(asns), max_len, "moas"])
            used_prefixes.add(parent_prefix)

        # 2. Policy-shift candidates (add a simulated migrating ASN 64512 not in ROA)
        elif len(asns) == 1 and max_len <= 22 and len(policy_rows) < 3:
            migrating_asns = f"{asns[0]}|64512"
            policy_rows.append([parent_prefix, migrating_asns, max_len, "policy_shift"])
            used_prefixes.add(parent_prefix)

        # 3. Standard single-origin candidates (room for /24 subprefix hijack tests)
        elif len(asns) == 1 and max_len <= 22 and len(single_rows) < 12:
            single_rows.append([parent_prefix, asns[0], max_len, "single"])
            used_prefixes.add(parent_prefix)

        if len(single_rows) >= 12 and len(moas_rows) >= 5 and len(policy_rows) >= 3:
            break

    all_rows = single_rows + moas_rows + policy_rows
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["prefix", "expected_asns", "expected_max_len", "category"])
        writer.writerows(all_rows)

    print(f"[+] Wrote {len(all_rows)} prefixes to {OUTPUT_CSV} "
          f"({len(single_rows)} single, {len(moas_rows)} moas, {len(policy_rows)} policy_shift).")

if __name__ == "__main__":
    main()
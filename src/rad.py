import radix
import csv
import glob
import sys
from mrtparse import Reader

MRT_FILE = "../data/updates.20231001.0000.bz2"
def getBGPData():
    print(f"[*] Opening compressed BGP feed: {MRT_FILE}\n")
    messages_processed = 0 

    for entry in Reader(MRT_FILE):
        data = entry.data
        if not data:
            continue
        
        if 'BGP4MP' not in str(data.get('type', '')):
            continue

        bgp = data.get('bgp_message', {})
        
        if 'UPDATE' not in str(bgp.get('type', '')):
            continue

        origin_asn = None
        for attr in bgp.get('path_attributes', []):
            if 'AS_PATH' in str(attr.get('type', '')):
                segments = attr.get('value', [])
                if segments and len(segments) > 0:
                    last_segment = segments[-1]
                    asn_list = last_segment.get('value', last_segment.get('val', []))
                    if asn_list:
                        origin_asn = asn_list[-1]
                    
        if not origin_asn:
            continue

        for nlri in bgp.get('nlri', []):
            # Safely extract length and cast to int to prevent TypeErrors later
            raw_length = nlri.get('length')
            if raw_length in (None, ''):
                continue
            
            try:
                length = int(raw_length)
            except ValueError:
                continue
            
            prefix_ip = nlri.get('prefix')
            if not prefix_ip:
                continue

            prefix = f"{prefix_ip}/{length}"
            
            ts_raw = data.get('timestamp', 'Unknown')
            if isinstance(ts_raw, dict):
                timestamp = list(ts_raw.keys())[0]
            elif isinstance(ts_raw, list):
                timestamp = ts_raw[0]
            else:
                timestamp = ts_raw
            
            messages_processed += 1
            print(messages_processed)
            print(prefix, length, timestamp, origin_asn)
            yield {
                "timestamp": timestamp,
                "origin_asn": origin_asn,
                "prefix": prefix,
                "prefix_length": length  # This is now safely an int
            }
def load_global_roa_snapshot(file_patterns):
    """
    Loads multiple time-aligned ROA CSVs into a single global Radix tree.
    """
    rtree = radix.Radix()
    
    # Retrieve all files matching the pattern (e.g., "roas/20261018_*.csv")
    file_paths = glob.glob(file_patterns)
    
    for csv_filepath in file_paths:
        with open(csv_filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                prefix = row['IP Prefix']
                asn = str(row['ASN']).replace('AS', '')
                max_len = int(row['Max Length'])
                
                node = rtree.search_exact(prefix)
                if not node:
                    node = rtree.add(prefix)
                    node.data['roas'] = []
                    
                # Append ROAs from all regions to the same prefix node
                node.data['roas'].append({'asn': asn, 'max_length': max_len})
                
    return rtree

def validate_announcement(rtree, prefix_str, prefix_len, origin_asn):
    """
    Evaluates a BGP announcement against the ROA Radix tree.
    Returns a tuple: (Status, Alert_Evidence)
    """
    # Catch py-radix ValueError for anomalous bounds (e.g., IPv4 > /32)
    try:
        covering_nodes = rtree.search_covering(prefix_str)
    except ValueError:
        return "INVALID", f"Malformed prefix or invalid masklen anomaly: {prefix_str}"
    
    if not covering_nodes:
        return "UNKNOWN", "No ROA found covering this prefix."
        
    invalid_reason = None
    
    for node in covering_nodes:
        for roa in node.data['roas']:
            if str(origin_asn) == roa['asn']:
                # prefix_len is safely an int, avoiding TypeError here
                if prefix_len <= roa['max_length']:
                    return "VALID", "Route is fully authorized by ROA."
                else:
                    invalid_reason = f"Subprefix Anomaly: ASN {origin_asn} is authorized, but /{prefix_len} exceeds MaxLength /{roa['max_length']}."
            else:
                if not invalid_reason:
                    invalid_reason = f"Origin Anomaly: ASN {origin_asn} does not match authorized ROA ASN {roa['asn']}."

    return "INVALID", invalid_reason

# Example Execution
if __name__ == "__main__":
    # Load all 5 regional files for the given timestamp into one tree
    global_roa_tree = load_global_roa_snapshot("../data/roas/roas_*.csv")
    
    validCount = 0
    invalidCount = 0
    unknownCOunt = 0
    for data in getBGPData():
        status, evidence = validate_announcement(
            global_roa_tree, 
            data['prefix'], 
            data['prefix_length'], 
            data['origin_asn']
        )
        
        if(status == "INVALID"):
            invalidCount += 1
        elif(status == "VALID"):
            validCount += 1
        else:
            unknownCOunt += 1
    print(validCount, invalidCount, unknownCOunt)
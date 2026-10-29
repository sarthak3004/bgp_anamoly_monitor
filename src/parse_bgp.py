import sys
from mrtparse import Reader

MRT_FILE = "../data/updates.20231001.0000.bz2"

def main():
    print(f"[*] Opening compressed BGP feed: {MRT_FILE}\n")
    messages_processed = 0 

    for entry in Reader(MRT_FILE):
        data = entry.data
        if not data:
            continue
        
        # 1. BULLETPROOF TYPE CHECK: Convert to string and search for keyword
        if 'BGP4MP' not in str(data.get('type', '')):
            continue

        bgp = data.get('bgp_message', {})
        
        # 2. BULLETPROOF UPDATE CHECK
        if 'UPDATE' not in str(bgp.get('type', '')):
            continue

        # 3. EXTRACT THE ORIGIN ASN
        origin_asn = None
        for attr in bgp.get('path_attributes', []):
            if 'AS_PATH' in str(attr.get('type', '')):
                segments = attr.get('value', [])
                if segments and len(segments) > 0:
                    last_segment = segments[-1]
                    # Handle both dictionary and list formats for the ASN values
                    asn_list = last_segment.get('value', last_segment.get('val', []))
                    if asn_list:
                        origin_asn = asn_list[-1]
                    
        if not origin_asn:
            continue

        # 4. EXTRACT THE ANNOUNCED PREFIXES
        for nlri in bgp.get('nlri', []):
            length = nlri.get('prefix_length', '')
            prefix = f"{nlri.get('prefix', '')}/{length}"
            
            # Extract timestamp safely regardless of list or dict format
            ts_raw = data.get('timestamp', 'Unknown')
            if isinstance(ts_raw, dict):
                timestamp = list(ts_raw.keys())[0]
            elif isinstance(ts_raw, list):
                timestamp = ts_raw[0]
            else:
                timestamp = ts_raw
            
            print(f"Timestamp: {timestamp} | Origin ASN: {origin_asn} | Announced: {prefix}")
            messages_processed += 1
    print(messages_processed)

if __name__ == "__main__":
    main()
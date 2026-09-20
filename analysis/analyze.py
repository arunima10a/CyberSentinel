import pyshark
import os
import json
import sys

def extract_features(pcap_path):
    if not os.path.exists(pcap_path):
        return {"error": "File not found"}
    
    records = {
        "total_packets": 0,
        "syn_count": 0,
        "unique_dest_ports": set(),
        "source_ips": {},
        "detected_user_agents": [],
        "target_ip": None
    }

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter="ip",
        only_summaries=False
    )

    try: 
        for pkt in cap:
            records["total_packets"] += 1
        
            if not hasattr(pkt, 'ip'):
                 continue

            src = pkt.ip.src
            dst = pkt.ip.dst
            records["source_ips"][src] = records["source_ips"].get(src, 0) + 1
            records["target_ip"] = dst

            if hasattr(pkt, 'tcp'):
                try:
                   port = int(pkt.tcp.dstport)
                   records["unique_dest_ports"].add(port)
                   flags = int(pkt.tcp.flags, 16)
                   if flags & 0x02 and not (flags & 0x10):
                      records["syn_count"] += 1
                except (ValueError, AttributeError):
                   pass

            if hasattr(pkt, 'http'):
               if hasattr(pkt.http, 'user_agent'):
                ua = pkt.http.user_agent
                if ua not in records["detected_user_agents"]:
                    records["detected_user_agents"].append(ua)

    except Exception as e:
        records["parse_error"] = str(e)
    finally:
        cap.close()

    records["unique_dest_ports"] = list(records["unique_dest_ports"])
    return records

if __name__ == "__main__":
    pcap_dir = "/app/evidence"
    if not os.path.exists(pcap_dir):
        print(json.dumps({"error": "Evidence directory not found"}))
        sys.exit(1)

    files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap') and not f.endswith('.enc')]
    if not files:
        print(json.dumps({"error": "No PCAP files found"}))
        sys.exit(1)

    files.sort(key=lambda x: os.path.getmtime(os.path.join(pcap_dir, x)))
    latest_pcap = os.path.join(pcap_dir, files[-1])

    results = extract_features(latest_pcap)
    results["analyzed_file"] = os.path.basename(latest_pcap)
    print(json.dumps(results))
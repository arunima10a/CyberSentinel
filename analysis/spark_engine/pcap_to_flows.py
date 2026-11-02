import pyshark
import csv
import os
import sys

def convert_pcap_to_flows(pcap_path, output_csv):
    """
    Reads a raw PCAP using Pyshark summaries and writes structured
    flow records (timestamp, src_ip, dst_ip, protocol, length, dst_port)
    to a CSV for PySpark ingestion.
    """
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    cap = pyshark.FileCapture(pcap_path, only_summaries=True)

    with open(output_csv, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "length", "dst_port"])

        for pkt in cap:
            try:
                src = pkt.source
                dst = pkt.destination
                proto = pkt.protocol
                length = int(pkt.length)
                
                # Extract destination port from info summary if available
                dst_port = 80
                if hasattr(pkt, 'info') and " > " in pkt.info:
                    parts = pkt.info.split(" > ")[1].split()
                    if parts and parts[0].isdigit():
                        dst_port = int(parts[0])

                writer.writerow([pkt.time, src, dst, proto, length, dst_port])
            except Exception:
                continue

    cap.close()

if __name__ == "__main__":
    evidence_dir = "/app/evidence"
    if not os.path.exists(evidence_dir):
        sys.exit(0)

    files = [f for f in os.listdir(evidence_dir) if f.endswith('.pcap') and not f.endswith('.enc')]
    if not files:
        sys.exit(0)

    files.sort(key=lambda x: os.path.getmtime(os.path.join(evidence_dir, x)))
    latest = os.path.join(evidence_dir, files[-1])
    
    out_csv = "/app/flows/flows.csv"
    convert_pcap_to_flows(latest, out_csv)
    print(f"Flows exported to {out_csv}")
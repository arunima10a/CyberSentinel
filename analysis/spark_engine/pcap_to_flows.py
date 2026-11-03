import csv
import os
import subprocess
import sys


FLOW_FIELDS = ["timestamp", "src_ip", "dst_ip", "protocol", "length", "dst_port"]


def convert_pcap_to_flows(pcap_path, output_csv):
    """Extract one structured packet record per captured frame using TShark."""
    output_dir = os.path.dirname(output_csv)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    fields = [
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "arp.src.proto_ipv4",
        "eth.src",
        "ip.dst",
        "ipv6.dst",
        "arp.dst.proto_ipv4",
        "eth.dst",
        "_ws.col.Protocol",
        "frame.len",
        "tcp.dstport",
        "udp.dstport",
    ]
    command = ["tshark", "-n", "-r", pcap_path, "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(command, capture_output=True, text=True, check=True)
    packet_count = 0
    skipped_count = 0

    with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(FLOW_FIELDS)

        for line in result.stdout.splitlines():
            values = line.split("\t")
            if len(values) < len(fields):
                values.extend([""] * (len(fields) - len(values)))

            timestamp, ip_src, ipv6_src, arp_src, eth_src = values[:5]
            ip_dst, ipv6_dst, arp_dst, eth_dst, protocol, length, tcp_dst, udp_dst = values[5:]
            src = ip_src or ipv6_src or arp_src or eth_src or "unknown"
            dst = ip_dst or ipv6_dst or arp_dst or eth_dst or "unknown"
            dst_port = tcp_dst or udp_dst or "0"

            try:
                packet_length = int(length)
            except ValueError:
                skipped_count += 1
                continue

            writer.writerow([timestamp, src, dst, protocol or "UNKNOWN", packet_length, dst_port])
            packet_count += 1

    if skipped_count:
        print(f"[flows] skipped {skipped_count} captured frames with invalid length fields", file=sys.stderr)
    print(f"[flows] extracted {packet_count} packet records from {os.path.basename(pcap_path)}")
    return packet_count


if __name__ == "__main__":
    evidence_dir = "/app/evidence"
    if not os.path.exists(evidence_dir):
        sys.exit(0)

    files = [
        filename
        for filename in os.listdir(evidence_dir)
        if filename.endswith(".pcap") and not filename.endswith(".enc")
    ]
    if not files:
        sys.exit(0)

    files.sort(key=lambda filename: os.path.getmtime(os.path.join(evidence_dir, filename)))
    latest = os.path.join(evidence_dir, files[-1])
    output_csv = "/app/flows/flows.csv"
    convert_pcap_to_flows(latest, output_csv)

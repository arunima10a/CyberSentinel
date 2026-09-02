import pyshark
import os 
import datetime

def start_capture(interface, duration, output_file):
    print(f"[*] Starting capture on {interface} for {duration} seconds...")

    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)

    capture.sniff(timeout=duration)

    print(f"[*] Capture complete. Saved to {output_file}")

if __name__ == "__main__":

    IFACE = os.getenv("CAPTURE_INTERFACE", "eth0")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    OUTPUT = f"/app/evidence/capture_{timestamp}.pcap"

    start_capture(IFACE, 30, OUTPUT)
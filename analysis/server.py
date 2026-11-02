from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our packet extractor and spark jobs
from analyze import extract_features
from spark_engine.traffic_analytics import run_spark_analysis
from spark_engine.pcap_to_flows import convert_pcap_to_flows

class AnalysisHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_GET(self):
        try:
            self._handle_get()
        except Exception as exc:
            # Keep failures machine-readable so callers receive JSON instead
            # of an empty connection or Python traceback.
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(exc)}).encode())

    def _handle_get(self):
        # 1. Feature Extraction (used by Go for incident correlation)
        path = self.path.split('?', 1)[0]
        if path == '/features':
            evidence_dir = "/app/evidence"
            files = [f for f in os.listdir(evidence_dir) if f.endswith('.pcap') and not f.endswith('.enc')]
            if not files:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "No PCAP files found"}).encode())
                return
            
            files.sort(key=lambda x: os.path.getmtime(os.path.join(evidence_dir, x)))
            latest_pcap = os.path.join(evidence_dir, files[-1])
            
            features = extract_features(latest_pcap)
            features["analyzed_file"] = os.path.basename(latest_pcap)
            
            self._set_headers(200)
            self.wfile.write(json.dumps(features).encode())
            
            files.sort(key=lambda x: os.path.getmtime(os.path.join(evidence_dir, x)))
            latest_pcap = os.path.join(evidence_dir, files[-1])
            
            features = extract_features(latest_pcap)
            features["analyzed_file"] = os.path.basename(latest_pcap)
            
            self._set_headers(200)
            self.wfile.write(json.dumps(features).encode())

        # 2. PySpark Big Data Traffic Analytics
        elif path == '/spark':
            evidence_dir = "/app/evidence"
            files = [f for f in os.listdir(evidence_dir) if f.endswith('.pcap') and not f.endswith('.enc')]
            if not files:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "No PCAP files to analyze"}).encode())
                return

            files.sort(key=lambda x: os.path.getmtime(os.path.join(evidence_dir, x)))
            latest_pcap = os.path.join(evidence_dir, files[-1])

            flow_csv = "/app/flows/flows.csv"
            # Convert raw PCAP to flow CSV
            convert_pcap_to_flows(latest_pcap, flow_csv)
            # Execute PySpark DataFrame job
            results = run_spark_analysis(flow_csv)

            self._set_headers(200)
            self.wfile.write(json.dumps(results).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())

def run(port=5000):
    server = HTTPServer(('0.0.0.0', port), AnalysisHandler)
    print(f"[*] Traffic & PySpark Analysis Engine listening on port {port}...")
    server.serve_forever()

if __name__ == '__main__':
    run()

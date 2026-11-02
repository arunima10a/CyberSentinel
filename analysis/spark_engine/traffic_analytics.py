import os
import json
import sys
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, countDistinct, desc

def run_spark_analysis(flow_csv_path):
    if not os.path.exists(flow_csv_path) or os.path.getsize(flow_csv_path) == 0:
        return {
            "engine": "Apache Spark (PySpark Standalone)",
            "total_analyzed_flows": 0,
            "protocol_distribution": [],
            "top_talkers": [],
            "anomalies_detected": []
        }

    # 1. Initialize local standalone Spark Session
    spark = SparkSession.builder \
        .appName("CyberSentinel-TrafficAnalytics") \
        .master("local[*]") \
        .config("spark.driver.memory", "1g") \
        .config("spark.ui.enabled", "false") \
        .getOrCreate()

    # Suppress verbose Spark console logs
    spark.sparkContext.setLogLevel("ERROR")

    # 2. Read flow records into DataFrame
    df = spark.read.csv(flow_csv_path, header=True, inferSchema=True)
    total_flows = df.count()

    # 3. Top Talkers: Source IP Volume
    top_sources = [
        {"src_ip": row["src_ip"], "flow_count": row["flow_count"]}
        for row in df.groupBy("src_ip")
            .agg(count("*").alias("flow_count"))
            .orderBy(desc("flow_count"))
            .limit(5)
            .collect()
    ]

    # 4. Port Scan Anomaly Detection:
    # A source IP probing an unusually high number of distinct destination ports
    scanning_candidates = df.groupBy("src_ip") \
        .agg(
            countDistinct("dst_port").alias("unique_ports_targeted"),
            count("*").alias("total_probes")
        ) \
        .filter(col("unique_ports_targeted") >= 3) \
        .orderBy(desc("unique_ports_targeted")) \
        .collect()

    # 5. Protocol Distribution
    proto_dist = [
        {"protocol": row["protocol"], "count": row["count"]}
        for row in df.groupBy("protocol")
            .agg(count("*").alias("count"))
            .orderBy(desc("count"))
            .collect()
    ]

    # 6. Structured Anomaly Indicators
    anomalies = []
    for cand in scanning_candidates:
        anomalies.append({
            "type": "Distributed Port Scan / Reconnaissance",
            "source_ip": cand["src_ip"],
            "unique_ports_targeted": cand["unique_ports_targeted"],
            "total_probes": cand["total_probes"],
            "confidence": 95 if cand["unique_ports_targeted"] > 50 else 85
        })

    spark.stop()

    return {
        "engine": "Apache Spark (PySpark Standalone)",
        "total_analyzed_flows": total_flows,
        "protocol_distribution": proto_dist,
        "top_talkers": top_sources,
        "anomalies_detected": anomalies
    }

if __name__ == "__main__":
    flow_file = "/app/flows/flows.csv"
    results = run_spark_analysis(flow_file)
    print(json.dumps(results))
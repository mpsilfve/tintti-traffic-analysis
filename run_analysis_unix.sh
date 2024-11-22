#! /bin/bash

mkdir -p generated

python3 src/main.py --input-file data/liikenne.pcapng \
                    --traffic-packets-main-statistics generated\packets_statistics.txt \
                    --traffic-graph-output-file generated/traffic_graph.png \
                    --traffic-packets-histogram generated/traffic-packets-histogram.txt \
                    --protocol-analysis-report generated\protocol_analysis_report.txt 

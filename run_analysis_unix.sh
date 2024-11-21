#! /bin/bash

mkdir -p generated

python3 src/main.py --input-file data/liikenne.pcapng \
        --traffic-packets-main-statistics generated/packets_statistics.txt \
	--packet-graph-output-file generated/packet_graph.png \
        --data-graph-output-file generated/data_graph.png \
        --traffic-packets-histogram generated/traffic-packets-histogram.png

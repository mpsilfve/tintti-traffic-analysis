#! /bin/bash

mkdir -p generated

python3 src/main.py --input-file data/liikenne.pcapng \
                    --traffic-graph-output-file generated/traffic_graph.png

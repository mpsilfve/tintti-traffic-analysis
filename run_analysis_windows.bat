@echo off

REM Create the "generated" directory if it doesn't exist
if not exist "generated" mkdir generated

REM Run the Python script
python src\main.py --input-file data\liikenne.pcapng ^
                   --traffic-packets-main-statistics generated\packets_statistics.txt ^
                   --traffic-graph-output-file generated\traffic_graph.png ^
                   --traffic-packets-histogram generated\traffic_packets_histogram.png
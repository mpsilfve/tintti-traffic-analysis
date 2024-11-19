@echo off

REM Create the "generated" directory if it doesn't exist
if not exist "generated" mkdir generated

REM Run the Python script
python src\main.py --input-file data\liikenne.pcapng ^
                   --traffic-graph-output-file generated\traffic_graph.png
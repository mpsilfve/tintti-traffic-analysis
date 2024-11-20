# tintti-traffic-analysis
Luodaan 

## Create virtual environment myenv
- `python3 -m venv myenv`
- `myenv\Scripts\activate`
- `source myenv/bin/activate`

## Setup
After you activate the virtual environment `myenv`, run 
```
pip3 install -r requirements.txt
```

## Run analysis on Mac/Linux

In the main directory `tintti-traffic-analysis`, run:
```
bash run_analysis_unix.sh
```
This will create a directory `generated` (if the directory doesn't already exist) and write all analysis output files into this directory.

## Run analysis on Windows

In the main directory `tintti-traffic-analysis`, run:
```
run_analysis_windows.bat
```
This will create a directory `generated` (if the directory doesn't already exist) and write all analysis output files into this directory.

## Description of generated statistics

### 5. Graph of traffic as a function of time

The program will generate a plot of how many captured packets were captured per second from the start of the process until the end.

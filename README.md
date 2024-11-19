# tintti-traffic-analysis


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

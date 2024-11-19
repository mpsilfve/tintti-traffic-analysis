import traffic_analysis
import pyshark
import click

@click.command()
@click.option("--input-file", required=True, help="Captured traffic file")
def main(input_file):
    print(f"Analyzing file {input_file}")
    capture = pyshark.FileCapture(input_file)

if __name__=="__main__":
    main()

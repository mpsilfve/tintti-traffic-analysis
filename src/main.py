import traffic_analysis
import pyshark
import click

@click.command()
@click.option("--input-file", required=True, help="Captured traffic file")
@click.option("--traffic-graph-output-file", required=True, help="Store the generated traffic/time graph into this file.")
def main(input_file,
         traffic_graph_output_file):
    print(f"Analyzing file {input_file}")
    capture = pyshark.FileCapture(input_file)
    print("Capture info:")
    print(capture)
    
    # Generate graph of traffic as a function of time
    traffic_analysis.generate_traffic_graph(capture, traffic_graph_output_file)
    
if __name__=="__main__":
    main()

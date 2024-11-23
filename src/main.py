import os  
import traffic_analysis
import pyshark
import click


def generate_plots_and_data(capture, traffic_graph_output_file,traffic_packets_histogram, traffic_packets_main_statistics, protocol_analysis_report, protocol_analysis_pie_chart):
    # Generate graph of traffic as a function of time
    if not os.path.exists(traffic_graph_output_file):
        print(f"Generating traffic graph: {traffic_graph_output_file}")
        traffic_analysis.generate_traffic_graph(capture, traffic_graph_output_file)
    else:
        print(f"Traffic graph already exists: {traffic_graph_output_file}")
    
    # Check if traffic packets histogram file already exists
    if not os.path.exists(traffic_packets_histogram):
        print(f"Generating traffic packets histogram: {traffic_packets_histogram}")
        traffic_analysis.generate_packets_histogram(capture, traffic_packets_histogram)
    else:
        print(f"Traffic packets histogram already exists: {traffic_packets_histogram}")

    # Check if statistics file already exists
    if not os.path.exists(traffic_packets_main_statistics):
        print(f"Generating traffic_packets_main_statistics: {traffic_packets_main_statistics}")
        traffic_analysis.generate_main_statistics(capture, traffic_packets_main_statistics)
    else:
        print(f"Traffic packets main statistics already exists: {traffic_packets_main_statistics}")

    # Check if protocol file already exists
    if not os.path.exists(protocol_analysis_report):
        print(f"Generating protocol_analysis_report: {protocol_analysis_report}")
        traffic_analysis.generate_protocols_by_layer(capture, protocol_analysis_report)
    else:
        print(f"Traffic packets main statistics already exists: {protocol_analysis_report}")

    # Check if protocol pie image already exists
    if not os.path.exists(protocol_analysis_pie_chart):
        print(f"Generating protocol_analysis_pie_chart: {protocol_analysis_pie_chart}")
        traffic_analysis.generate_protocols_pie_chart(capture, protocol_analysis_pie_chart)
    else:
        print(f"Traffic packets main statistics already exists: {protocol_analysis_pie_chart}")



@click.command()
@click.option("--input-file", required=True, help="Captured traffic file")
@click.option("--traffic-packets-main-statistics", required=True, help="Store the generated traffic/packet statistics into this file.")
@click.option("--traffic-graph-output-file", required=True, help="Store the generated traffic/time graph into this file.")
@click.option("--traffic-packets-histogram", required=True, help="Store the generated traffic/packet histogram graph into this file.")
@click.option("--protocol-analysis-report", required=True, help="File to save protocol analysis report.")
@click.option("--protocol-analysis-pie-chart", required=True, help="File to save protocol analysis pie chart.")
def main(input_file, traffic_packets_main_statistics,
         traffic_graph_output_file, traffic_packets_histogram, protocol_analysis_report, protocol_analysis_pie_chart):
    print(f"Analyzing file {input_file}")
    capture = pyshark.FileCapture(input_file)
    print("Capture info:")
    print(capture)

    generate_plots_and_data(capture, traffic_graph_output_file, traffic_packets_histogram, traffic_packets_main_statistics,  protocol_analysis_report, protocol_analysis_pie_chart)
    
    
if __name__=="__main__":
    main()

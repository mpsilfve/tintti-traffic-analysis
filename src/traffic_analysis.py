from collections import defaultdict
from typing import Any, Dict, List
import matplotlib.pyplot as plt
import numpy as np

PROTOCOL_LAYER_MAPPING = {
        'eth': 'Linkkikerros',
        'ip': 'Verkkokerros',
        'tcp': 'Kuljetuskerros',
        'udp': 'Kuljetuskerros',
        'http': 'Sovelluskerros',
        'https': 'Sovelluskerros',
        'dns': 'Sovelluskerros',
        'tls': 'Istuntokerros',
        'data': 'Kuljetuskerros',  # Generic data layer
        'nbns': 'Kuljetuskerros',  # NetBIOS Name Service
        'quic': 'Kuljetuskerros',  # Quick UDP Internet Connections
        'mdns': 'Kuljetuskerros',  # Multicast DNS
        'ipv6': 'Verkkokerros'       # IPv6
    }

def generate_main_statistics(capture, report_file_path):
    """
    Processes packets from a capture and calculates total packets, total bytes, and time range.

    Args:
        capture: An iterable of packet objects (e.g., from PyShark).

    Returns:
        A dictionary containing:
        - total_packets: Total number of packets processed.
        - total_bytes: Total size of all packets in bytes.
        - start_time: The timestamp of the first packet.
        - end_time: The timestamp of the last packet.
        - capture_duration: The duration time of the capture
    """

    # Extract all relevant information using comprehensions/generators
    packet_lengths = [int(packet.length) for packet in capture]
    max_packet_size = max(packet_lengths)
    timestamps = [packet.sniff_time for packet in capture]

    # Aggregate results
    total_packets = len(packet_lengths)
    total_bytes = sum(packet_lengths)
    start_time = timestamps[0] if timestamps else None
    end_time = timestamps[-1] if timestamps else None
    capture_duration = (end_time - start_time).total_seconds()

    # Tulosta tulokset
    print(f"Kaapattujen pakettien määrä: {total_packets}")
    print(f"Kaappauksen pituus: {capture_duration:.2f} sekuntia")
    print(f"Kaapattujen tavujen määrä: {total_bytes} tavua")
    print(f"Suurin paketin koko on: {max_packet_size} tavua")

        # Create the report content
    report_content = (
        f"Kaapattujen pakettien määrä: {total_packets}\n"
        f"Kaappauksen pituus: {capture_duration:.2f} sekuntia\n"
        f"Kaapattujen tavujen määrä: {total_bytes} tavua\n"
        f"Suurin paketin koko on: {max_packet_size} tavua\n"
        f"Kaappaus alkoi: {start_time}\n"
        f"Kaappaus päättyi: {end_time}\n"
    )

    # Save the report to the specified file
    with open(report_file_path, "w", encoding="utf-8") as report_file:
        report_file.write(report_content)

    print(f"Raportti tallennettu tiedostoon: {report_file_path}")



def generate_packets_histogram(capture, output_file, bin_width=100):
    """
    Generates and saves a histogram of packet sizes from a capture.

    Args:
        capture: An iterable of packet objects (e.g., from PyShark).
        output_file: Path to save the histogram plot.
        bin_width: The width of the bins for categorizing packet sizes (default is 100 bytes).

    Returns:
        None. Saves the histogram plot to the specified file.
    """
    # Extract packet lengths from the capture
    packet_lengths = [int(packet.length) for packet in capture]
    
    if not packet_lengths:
        print("No packets found in capture. Skipping histogram generation.")
        return

    # Define the bin edges for the histogram
    max_length = max(packet_lengths)
    bin_edges = np.arange(0, max_length + bin_width, bin_width)

    # Calculate the histogram
    hist, bins = np.histogram(packet_lengths, bins=bin_edges)

    # Plot the histogram
    plt.figure(figsize=(10, 6))  # Define figure size for better visualization
    plt.bar(bins[:-1], hist, width=bin_width, edgecolor="black", align="edge")
    plt.title("Pakettikokojen histogrammi (luokiteltuna 100 tavun välein)")
    plt.xlabel("Paketin koko (luokiteltuna 100 tavun välein )")
    plt.ylabel("Frekvenssi")
    plt.xticks(bins, rotation=45)
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()

    # Save the plot to the output file
    plt.savefig(output_file)
    plt.close()  # Close the plot to free memory

    print(f"Packet size histogram saved to {output_file}")



def generate_traffic_graph(capture, output_file):
    start_time = capture[0].sniff_timestamp
    packets_per_time = defaultdict(lambda : 0)
    for packet in capture:
        time_interval = int(float(packet.sniff_timestamp) - float(start_time))
        packets_per_time[time_interval] +=1
        
    x = [k for k, v in packets_per_time.items()]
    y = [v for k, v in packets_per_time.items()]
    plt.plot(x, y, color='green', linestyle='dashed', linewidth = 2,
             marker='o', markerfacecolor='blue', markersize=5)

    # naming the x axis
    plt.xlabel('Aika sekunneissa')
    # naming the y axis
    plt.ylabel('Pakettien lukumäärä')
    
    # giving a title to my graph
    plt.title('Kuinka monta pakettia siepattiin sekunnissa seurannan aikana')
    
    # function to show the plot
    plt.savefig(output_file)

def generate_protocols_by_layer(capture: List[Any], report_file_path: str) -> List[Dict[str, Any]]:
    """
    Analyzes a packet capture and generates a report of protocols by layer.

    Args:
        capture (List[Any]): List of packets with their layers.
        report_file_path (str): File path to save the generated report.

    Returns:
        List[Dict[str, Any]]: Sorted protocol data including counts and layers.
    """
    protocol_data = _analyze_capture(capture)
    sorted_protocol_data = _sort_protocol_data(protocol_data)
    _print_report(sorted_protocol_data)
    _write_report_to_file(sorted_protocol_data, report_file_path)
    
    return sorted_protocol_data

def generate_protocols_pie_chart(capture: List[Any], report_file_path: str) -> List[Dict[str, Any]]:
    protocol_data = _analyze_capture(capture)
    sorted_protocol_data = _sort_protocol_data(protocol_data)
    _generate_pie_chart(sorted_protocol_data, report_file_path)

def _analyze_capture(capture: List[Any]) -> Dict[str, Dict[str, Any]]:
    """
    Processes the packet capture and counts protocols by layer.
    """
    protocol_data = {}

    for packet in capture:
        for layer in packet.layers:
            protocol = layer.layer_name.lower()
            protocol_layer = PROTOCOL_LAYER_MAPPING.get(protocol, 'Unknown Layer')

            if protocol not in protocol_data:
                protocol_data[protocol] = {'count': 0, 'layer': protocol_layer}

            protocol_data[protocol]['count'] += 1

    return protocol_data


def _sort_protocol_data(protocol_data: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sorts protocol data by layer name.
    """
    return sorted(protocol_data.items(), key=lambda item: item[1]['layer'])


def _print_report(sorted_protocol_data: List[Dict[str, Any]]) -> None:
    """
    Prints the protocol report to the console.
    """
    print(f"{'Layer':<20}{'Protocol':<20}{'Count':<10}")
    print("-" * 50)
    for protocol, data in sorted_protocol_data:
        print(f"{data['layer']:<20}{protocol:<20}{data['count']:<10}")


def _write_report_to_file(sorted_protocol_data: List[Dict[str, Any]], file_path: str) -> None:
    """
    Writes the protocol report to a file.

    Args:
        sorted_protocol_data (List[Dict[str, Any]]): The protocol data to write.
        file_path (str): The file path to save the report.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as report_file:
            report_file.write(f"{'Layer':<20}{'Protocol':<20}{'Count':<10}\n")
            report_file.write("-" * 50 + "\n")
            for protocol, data in sorted_protocol_data:
                report_file.write(f"{data['layer']:<20}{protocol:<20}{data['count']:<10}\n")
    except IOError as e:
        print(f"Error writing to file {file_path}: {e}")


import matplotlib.pyplot as plt
from typing import List, Dict, Any

def _generate_pie_chart(sorted_protocol_data: List[Dict[str, Any]], file_path: str):
    layers = {}
    total_count = 0

    # Accumulate counts per layer
    for protocol, data in sorted_protocol_data:
        current_count = int(data['count'])
        total_count += current_count
        if data['layer'] in layers:
            layers[data['layer']] += current_count
        else:
            layers[data['layer']] = current_count

    percentages = {layer: (count / total_count) * 100 for layer, count in layers.items()}
    print("Percentages by layer:", percentages)

    # Define a colorblind-friendly palette with shades of purple and blue
    color_palette = [
        "#5A4FCF",  # Medium blue
        "#7F7FFF",  # Soft blue
        "#3C3FA4",  # Deep blue
        "#9F6FFF",  # Light purple
        "#6B4DB2",  # Dark purple
        "#847FCF",  # Pale purple
        "#433D99",  # Royal blue
    ]

    # Ensure the number of colors matches the number of layers
    # translate to Finnish 

    labels = list(layers.keys())
    sizes = list(layers.values())
    colors = color_palette[:len(labels)]

    # Generate Pie Chart
    plt.figure(figsize=(8, 8))
    plt.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct='%1.1f%%',
        startangle=140
    )
    plt.title("Protokollien jakautuminen kerroksittain")
    plt.savefig(file_path)
    plt.show()

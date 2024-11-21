from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

def main_statistics(capture, report_file_path):
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


def plot(x, y, xlabel, ylabel, title, output_file_name):
    plt.figure(figsize=(10, 6))  # Define figure size for better visualization
    plt.plot(x, y, color='green', linestyle='dashed', linewidth = 2,
             marker='o', markerfacecolor='blue', markersize=5)

    # naming the x axis
    plt.xlabel(xlabel)
    
    # naming the y axis
    plt.ylabel(ylabel)
    
    # giving a title to my graph
    plt.title(title)
    
    # function to show the plot
    plt.savefig(output_file_name)
        
def generate_traffic_graph(capture, call_graph_output_file, data_graph_output_file):
    start_time = capture[0].sniff_timestamp
    packets_per_time = defaultdict(lambda : 0)
    data_per_time = defaultdict(lambda : 0)
    for packet in capture:
        time_interval = int(float(packet.sniff_timestamp) - float(start_time))
        packets_per_time[time_interval] +=1
        data_per_time[time_interval] += int(packet.length)
        
    x = [k for k, v in packets_per_time.items()]
    y_packets = [v for k, v in packets_per_time.items()]
    y_data = [v for k, v in data_per_time.items()]

    plot(x,
         y_packets,
         'Aika sekunneissa',
         'Pakettien lukumäärä',
         'Kuinka monta pakettia siepattiin sekunnissa seurannan aikana',
         call_graph_output_file)

    plot(x,
         y_data,
         'Aika sekunneissa',
         'Lähetetyt tavut',
         'Kuinka paljon dataa lähetettiin sekunnissa seurannan aikana',
         data_graph_output_file)

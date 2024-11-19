import pyshark
import matplotlib.pyplot as plt
from collections import Counter
import numpy as np

def packet_histogram(capture):
    packet_lengths = [int(packet.length) for packet in capture]
    #frekvenssit
    packet_count = Counter(packet_lengths)
    packet_lengths = [int(packet.length) for packet in capture]
    max_packet_size = max(packet_lengths)
    print(f"Suurin paketin koko on: {max_packet_size} tavua")
    # Määritellään luokkien rajat (esim. 0-100, 101-200 jne.)
    bin_edges = np.arange(0, max(packet_lengths) + 100, 100)  # Luokat 100 tavun välein

    # Lasketaan histogrammi luokkien perusteella
    hist, bins = np.histogram(packet_lengths, bins=bin_edges)

    # Piirretään histogrammi
    plt.bar(bins[:-1], hist, width=100, edgecolor="black", align="edge")
    plt.title("Pakettikokojen histogrammi (luokiteltuna 100 tavun välein)")
    plt.xlabel("Paketin koko (luokiteltuna 100 tavun välein )")
    plt.ylabel("Frekvenssi")
    plt.xticks(bins, rotation=45)
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.show()

    

def packet_count(capture):

    # Alustetaan muuttujat
    total_packets = 0
    total_bytes = 0
    start_time = None
    end_time = None
    
    for packet in capture:
    # Kasvatetaan pakettien määrää
        total_packets += 1

        # Lasketaan kaapattujen tavujen määrä
        total_bytes += int(packet.length)

        # Päivitetään aikaleimat
        if start_time is None:
            start_time = packet.sniff_time
        end_time = packet.sniff_time

    # Laske kaappauksen kesto sekunneissa
    capture_duration = (end_time - start_time).total_seconds()

    # Tulosta tulokset
    print(f"Kaapattujen pakettien määrä: {total_packets}")
    print(f"Kaappauksen pituus: {capture_duration:.2f} sekuntia")
    print(f"Kaapattujen tavujen määrä: {total_bytes} tavua")

    

def tcp_packets_incapture(capture):
    for packet in capture:
        if 'TCP' in packet:
            print(f"TCP Packet: {packet}")

    with open('analysis_results.txt', 'w') as f:
        for packet in capture:
            if 'IP' in packet:
                f.write(f"Source: {packet.ip.src}, Destination: {packet.ip.dst}\n")


# Path to your pcapng file
pcapng_file = 'data/liikenne.pcapng'
# Load the capture file
capture = pyshark.FileCapture(pcapng_file)


#packet_count(capture)
packet_histogram(capture)

# Close the capture file
capture.close()
import pyshark
from collections import defaultdict
import matplotlib.pyplot as plt

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
        

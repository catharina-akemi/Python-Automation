from scapy.all import sniff
import pandas as pd
import time

#function thar processes the capture packages
def packet_handler(packet):
    try:
        #capture important data from packages
        data = {
            "Timestamp": time.time(),
            "Source IP": packet[1].src,
            "Destination IP": packet[1].dst,
            "Protocol": packet.proto,
            "Length": len(packet)
        }
        #adds package to data list
        packets_data.append(data)
    except IndexError:
        pass #ignore packages without necessary fields

packets_data = [] #list where packages are stored

#start packages capture (limited to 100, can add more)
sniff(prn=packet_handler, count=100)

#creates DataFrame to store data
df = pd.DataFrame(packets_data)

#shows captured data
print(df.head())

#pandas
#analyze captured protocols types
protocol_counts = df["Protocol"].value_counts()
print("Protocol Countings: ")
print(protocol_counts)

#analyze most accessed IPs
top_ips = df["Source IP"].value_counts().head(10)
print("\nTop 10 most accessed IP: ")
print(top_ips)

#save captured data into a CSV
df.to_csv('network_packets.csv', index=False)

import matplotlib.pyplot as plt

#protocol counting graph
protocol_counts.plot(kind='bar', title='Protocol Counting')
plt.xlabel('Protocols')
plt.ylabel('Counting')
plt.show()


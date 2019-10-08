import os

from scapy.all import *
a = " "
#os.system("{tshark_loc} -T fields -e _ws.col.Info -e http -e frame.time -e data.data -O http -w Eavesdrop_Data.pcap > Eavesdrop_Data.txt -c 500".format(tshark_loc=r'"C:\Program Files\Wireshark\tshark"'))
#os.system("{tshark_loc} -r Eavesdrop_Data.pcap -Y http -w Eavesdrop_Data_http.pcap".format(tshark_loc=r'"C:\Program Files\Wireshark\tshark"'))

data = "Eavesdrop_Data.pcap"
a = rdpcap(data)
sessions = a.sessions()
for session in sessions:
    http_payload = ""
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:              #This port is to identify http requests
                print(:HTTP: ",packet[TCP].payload)
        except:
            pass

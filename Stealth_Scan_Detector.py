import pyshark
from collections import Counter
cap = pyshark.FileCapture(r"nmap-stealth-sample.pcapng")

#Saving the different types of packets (SYN, SYN_ACK, RST, RST_ACK)
SYN = list(filter(lambda syn_pkt: (syn_pkt.tcp.flags=='0x0002'), cap))
SYN_ACK = list(filter(lambda syn_ack_pkt: (syn_ack_pkt.tcp.flags=='0x0012'), cap))
RST_ACK = list(filter(lambda rst_ack_pkt: (rst_ack_pkt.tcp.flags=='0x0014'), cap))
RST = list(filter(lambda rst_pkt: (rst_pkt.tcp.flags=='0x0004'), cap))

syn_pkt = []
rst_src_ip = []; rst_dstport = []
syn_ack_src_ip = []; syn_ack_srcport = []

for syn_pck in SYN:
    syn_pkt.append(syn_pck.ip.src)

for rst_pck in RST:
    rst_src_ip.append(rst_pck.ip.src)
    rst_dstport.append(rst_pck.tcp.dstport)

for syn_ack_pck in SYN_ACK:
    syn_ack_src_ip.append(syn_ack_pck.ip.dst)
    syn_ack_srcport.append(syn_ack_pck.tcp.srcport)

#From a server's perspective: Checking if a source address destined to a certain service port replies with
#an RST as a response to the server's ACK => STEALTH SCAN BEHAVIOUR
for i in range(len(syn_ack_src_ip)):
    if syn_ack_src_ip[i] in rst_src_ip:
        detected_index = rst_src_ip.index(syn_ack_src_ip[i])
        if syn_ack_srcport[i] == rst_dstport[detected_index]:
            print("Detected src: ",syn_ack_src_ip[i]," scanning port: ",syn_ack_srcport[i])
            del rst_src_ip[detected_index]
            del rst_dstport[detected_index]

#Checking if a source address sends more than 10 SYN requests (in a small period of time in real scenarios) => SYN SCAN, DOS ATTACK
syn_pkts_list = Counter(syn_pkt)

for key, value in syn_pkts_list.items():
    if value > 10:
        print("Detected ip: ", key, "  SYN requests amount: ", value)

cap.close()
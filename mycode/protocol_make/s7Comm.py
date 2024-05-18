# 构造一个s7Comm协议报文
# 21行指定了目标IP为10.12.172.240
# 30行指定了保存路径和名称

from scapy.layers.inet import IP, TCP
from scapy.all import wrpcap
from scapy.layers.l2 import Ether


# 构造 Modbus TCP 报文数据
my_tpkt = b"\x03\x03\x00\x2b"
my_cotp = b"\x02\xf0\x80"
S7Comm = b"\x32\x01\x00" \
        b"\x00\x09\x00\x00\x1a\x00\x00\x04\x02\x12\x0a\x10\x04\x00\x0b\x00" \
        b"\x00\x83\x00\x0c\x80\x12\x0a\x10\x04\x00\x01\x00\x00\x83\x00\x0f" \
        b"\x50"
S7Comm_packet = my_tpkt + my_cotp + S7Comm


# 构造 IP 数据包
ip_packet = IP(dst="10.12.172.240")

# 构造 TCP 数据包
tcp_packet = TCP(dport=102)

# 创建以太网数据包
ether_packet = Ether() / ip_packet / tcp_packet / S7Comm_packet

# 保存数据包为 pcap 文件
wrpcap("./S7Comm_packet.pcap", ether_packet)




# 构造一个Modbus协议报文
# 15行指定了目标IP为1.1.1.1
# 24行指定了保存路径和名称

from scapy.layers.inet import IP, TCP
from scapy.all import wrpcap
from scapy.layers.l2 import Ether


# 构造 Modbus TCP 报文数据
modbus_tcp_packet = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
# 表示一个读取 Modbus 设备中线圈状态的请求，要求从地址 0 开始，读取一个线圈的状态。

# 构造 IP 数据包
ip_packet = IP(dst="1.1.1.1")

# 构造 TCP 数据包
tcp_packet = TCP(dport=502)

# 创建以太网数据包
ether_packet = Ether() / ip_packet / tcp_packet / modbus_tcp_packet

# 保存数据包为 pcap 文件
wrpcap("./modbus_tcp_packet.pcap", ether_packet)



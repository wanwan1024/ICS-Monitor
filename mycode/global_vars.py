# 全局变量文件

from collections import defaultdict

# 在线监听中用来存储,方便后续保存为本地文件;离线中用来读入文件
packets = []
# 表示开始默认是在线监听,更改为True后进入离线分析模式,方便判断函数执行
offline_packets = False
# 因为离线分析很快,不是在线那样发信息给前端,所以需要将warning信息存储
offline_warning_info = []
# 用于计算抖动
time_gaps = []

# 创建一个默认值为0的字典
# 该字典用来表示某时刻监听到的报文数量
# 默认时间间隔是1s,如果要增大,只要更改packet_deal.py中的packet_callback函数
traffic_time_num = defaultdict(int)

# 两个字典用来表示某一秒的上行和下行数据包长度,用于计算在线网速
traffic_time_len_upload = defaultdict(int)
traffic_time_len_download = defaultdict(int)
# delay_time = 0   延迟太短,不需要这个了

# 该字典用来表示不同长度的报文数量
traffic_len_num = defaultdict(int)

# 该字典用来表示不同网络层协议的报文数量
traffic_nl_proto_num = defaultdict(int)

# 该字典用来表示不同网传输层协议的报文数量
traffic_tl_proto_num = defaultdict(int)

# 该字典用来表示不同应用层协议的报文数量
traffic_al_proto_num = defaultdict(int)

# 该字典用来表示不同IP地址的报文数量
traffic_ipaddr_num = defaultdict(int)


# 标志变量用于控制监听状态
keep_sniffing = True

# 创建一个存储已接收序列号的集合
received_seq_numbers = set()
# 重传报文的数量
retransmission_count = 0

# 后面是针对示警的全局变量
syn_count = 0  # 记录接收到的TCP SYN包数量
ack_count = 0  # 记录接收到的TCP ACK包数量
udp_port_num = defaultdict(int)     # 记录某端口收到的udp报文数量
# established_connections = set()     # 记录接收到的ACK建立的正常连接数量
start_time = 0  # 记录开始监听的时间, 为一个时间窗口,每1秒检测一次
warning_message = {}



if __name__ == '__main__':
    from scapy.all import sniff, get_working_ifaces
    # 获取系统上的网络接口列表
    from scapy.arch import get_if_addr, get_if_addr6
    from scapy.all import conf
    print(get_if_addr(conf.iface))
    print(get_if_addr6(conf.iface))
    import numpy as np

    # 假设有一些时间间隔数据
    time_gaps = [2.1, 3.4, 2.7, 4.2, 3.9]

    # 计算时间间隔的标准差（抖动）
    jitter_ms = np.std(time_gaps)

    print("抖动（Jitter）：", jitter_ms, "毫秒")
    pass



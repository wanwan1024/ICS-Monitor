# 流量监听文件,包括下面功能:
# 1.自动打开web界面,也就是http://127.0.0.1:8000/
# 2.监听报文,规则在start_sniffing()中的sniff函数中

import global_vars
from webbrowser import open_new_tab
from scapy.all import *
import packet_deal


# 开启监听
def monitor():
    # 使用前注意在index.html路径下输入命令python -m http.server搭建web环境
    # 使用默认浏览器打开HTML文件, 不是本地打开, 而是使用http打开
    open_new_tab('http://127.0.0.1:8000/')

    # 接着就是等待前端触发下面的两个函数了


# 开始监听,暂时监听web http包
def start_sniffing():
    global_vars.start_time = time.time()
    while global_vars.keep_sniffing:
        # print('监听ing')
        # 一次监听一个包
        sniff(iface="WLAN", filter="", prn=packet_deal.packet_callback, store=0, count=1)



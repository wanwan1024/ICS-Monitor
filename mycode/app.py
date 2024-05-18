# 主程序入口,程序运行处
# 主要是flask的注册,实现前后端的交互


import os
import global_vars
import monitor
import threading
import packet_deal
from scapy.all import wrpcap, rdpcap
import numpy as np

from flask import Flask, render_template, jsonify, request
app = Flask(__name__)


# 程序入口,开启主界面index.html
@app.route('/')
def index():
    return render_template('index.html')

# 在线监听入口,开启监听线程
@app.route('/start')
def start():
    t = threading.Thread(target=monitor.start_sniffing)
    t.start()
    return 'Started'

# 在线监听时每秒传递数据给前端, 用来画图
@app.route('/get_data')
def get_data():
    # global_vars.idx += 1
    # if global_vars.idy:
    #     data = list(global_vars.idy.items())[global_vars.idx]
    #     return jsonify(data)
    idx = int(request.args.get('variable'))
    data = []
    if idx < len(global_vars.traffic_time_num):
        data = list(global_vars.traffic_time_num.items())[idx] +\
               list(global_vars.traffic_time_len_upload.items())[idx] +\
               list(global_vars.traffic_time_len_download.items())[idx]
        # global_vars.delay_time 时延几乎为0,没必要了
        return jsonify(data)
    else:
        print('当前未监听到流量')
        return jsonify('empty')

# 每隔一秒访问, 获取warning信息
@app.route('/get_warning_info')
def get_warning_info():
    if not global_vars.warning_message:
        return jsonify('empty')
    else:
        return jsonify(global_vars.warning_message)

# 在线监听结束后通信质量的数据传输
@app.route('/networkquality')
def networkquality():
    idx = len(global_vars.traffic_time_num)
    alldatanum = 0
    uploadlen = 0
    downloadlen = 0
    for key, value in global_vars.traffic_time_num.items():
        alldatanum += value
    for key, value in global_vars.traffic_time_len_upload.items():
        uploadlen += value
    for key, value in global_vars.traffic_time_len_download.items():
        downloadlen += value
    # 计算时间间隔的标准差（抖动）
    jitter_ms = np.std(global_vars.time_gaps)
    data = [idx, alldatanum, uploadlen, downloadlen, global_vars.retransmission_count, jitter_ms]
    return jsonify(data)

# 在线监听结束后饼状图的数据传输
@app.route('/pchart')
def pchart():
    data = {
        'len': dict(global_vars.traffic_len_num),
        'nl': dict(global_vars.traffic_nl_proto_num),
        'tl': dict(global_vars.traffic_tl_proto_num),
        'al': dict(global_vars.traffic_al_proto_num),
    }
    return jsonify(data)

# 在线监听结束后直方图的数据传输
@app.route('/column_chart')
def column_chart():
    data = {
        'nl': dict(global_vars.traffic_nl_proto_num),
        'tl': dict(global_vars.traffic_tl_proto_num),
        'al': dict(global_vars.traffic_al_proto_num),
        'addr': dict(global_vars.traffic_ipaddr_num),
    }
    return jsonify(data)

# 在线监听的结束程序
@app.route('/end')
def end():
    global_vars.keep_sniffing = False   # 更改为false,结束sniff
    print('end now!')

    # 退出程序
    # os.sys.exit(0)
    return 'Server shutting down...'

# 用于保存刚刚监听到的流量情况为pcap文件
# 默认保存路径为当前文件夹下的pcap文件夹
@app.route('/save_pcap')
def save_pcap():
    filename = request.args.get('variable')
    current_directory = os.getcwd()
    pcap_file = os.path.join(current_directory, 'pcap', filename)
    try:
        wrpcap(pcap_file, global_vars.packets)  # 将 Scapy 数据包列表保存为 pcap 文件
        return jsonify('success')
    except Exception as e:
        return jsonify(e)

# 离线版本界面,返回offline_analyzer.html
@app.route('/offline_analyzer')
def offline_analyzer():
    return render_template('offline_analyzer.html')

# 接收前端文件名,打开文件开始数据分析
@app.route('/offline_analysis')
def offline_analysis():
    filename = request.args.get('variable')
    current_directory = os.getcwd()
    pcap_file = os.path.join(current_directory, 'offline-pcap', filename)
    global_vars.offline_packets = True
    try:
        global_vars.packets = rdpcap(pcap_file)  # 将pcap 文件保存为数据包列表
        for packet in global_vars.packets:
            packet_deal.packet_callback(packet)
        return jsonify('success')
    except Exception as e:
        return jsonify(e)

@app.route('/offline_warning_info')
def offline_warning_info():
    if not global_vars.offline_warning_info:
        return jsonify('empty')
    else:
        return jsonify(global_vars.offline_warning_info)

# 对与traffic-time picture的数据传输
@app.route('/get_offline_ttp')
def get_offline_ttp():
    return jsonify(global_vars.traffic_time_num)

# 程序开启处
if __name__ == '__main__':

    # 开启监听
    monitor.monitor()

    # 开启flask
    app.run(port=8000)




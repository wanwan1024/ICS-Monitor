


function NetworkQualityShow() {
	// 发送 GET 请求到后端获取数据
	fetch('/networkquality', {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json'
		}
	})
		.then(response => {
			if (!response.ok) {
				throw new Error('Network response was not ok');
			}
			return response.json();
		})
		.then(data => {
			const quality = document.querySelectorAll('.NetworkQuality li');
			// console.log(quality);
			quality[0].innerHTML = '总时长:' + data[0] + 's';
			quality[1].innerHTML = '总数据包数量:' + data[1];
			quality[2].innerHTML = '平均上传带宽:' + Math.round(data[2] / data[0]) + 'Bytes/s';
			quality[3].innerHTML = '平均下载带宽:' + Math.round(data[3] / data[0]) + 'Bytes/s';
			quality[4].innerHTML = '重传率:' + data[4] / data[1] + '%';
			quality[5].innerHTML = '抖动:' + data[5].toFixed(3) + 'ms';

		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}


// 结束后,画四个饼状图,占比的
function PChartDraw() {
	// 发送 GET 请求到后端获取数据
	fetch('/pchart', {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json'
		}
	})
		.then(response => {
			if (!response.ok) {
				throw new Error('Network response was not ok');
			}
			return response.json();
		})
		.then(data => {
			// console.log(data['len']);
			let pdata = [{
				values: Object.values(data['len']),
				labels: Object.keys(data['len']),
				type: 'pie'
			}];
			let layout = {
				title: '数据包长度占比'
			};
			for (let i = 0; i < pdata[0].labels.length; i++) {
				switch (pdata[0].labels[i]) {
					case '0':
						pdata[0].labels[i] = '<300';
						break;
					case '1':
						pdata[0].labels[i] = '300-599';
						break;
					case '2':
						pdata[0].labels[i] = '600-899';
						break;
					case '3':
						pdata[0].labels[i] = '900-1199';
						break;
					case '4':
						pdata[0].labels[i] = '1200-1499';
						break;
					case '5':
						pdata[0].labels[i] = '>1500';
						break;
					default:
						pass
					// 处理默认情况
				}
			}
			//第一个比较特殊,需要详细处理
			Plotly.newPlot('LenPchart', pdata, layout);

			// 后面三个大同小异,更换数据直接画
			pdata[0].values = Object.values(data['nl']);
			pdata[0].labels = Object.keys(data['nl']);
			layout.title = '网络层协议占比';
			Plotly.newPlot('NLPchart', pdata, layout);

			pdata[0].values = Object.values(data['tl']);
			pdata[0].labels = Object.keys(data['tl']);
			layout.title = '传输层协议占比';
			Plotly.newPlot('TLPchart', pdata, layout);

			pdata[0].values = Object.values(data['al']);
			pdata[0].labels = Object.keys(data['al']);
			layout.title = '应用层协议占比';
			Plotly.newPlot('ALPchart', pdata, layout);
		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}

// 结束后画两个柱形图
// 分别是协议统计和IP统计
function ColumnChartDraw() {
	// 发送 GET 请求到后端获取数据
	fetch('/column_chart', {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json'
		}
	})
		.then(response => {
			if (!response.ok) {
				throw new Error('Network response was not ok');
			}
			return response.json();
		})
		.then(data => {
			// 先是协议统计
			let cdata = [{
				x: [],
				y: [],
				type: 'bar',
				texttemplate: "%{y}", // 设置文本模板为y值
				textposition: 'outside' // 设置文本位置为外部
			}];
			cdata[0].x = Object.keys(data['nl']).concat(Object.keys(data['tl']), Object.keys(data['al']));
			cdata[0].y = Object.values(data['nl']).concat(Object.values(data['tl']), Object.values(data['al']));
			let layout = {
				title: '协议统计',
				autosize: true,
				xaxis: {
					title: '协议类型',
				},
				yaxis: {
					title: '数据包个数',
				},
			};
			Plotly.newPlot('ProtocolSum', cdata, layout);

			//	接着画IP统计的
			let idata = [
				{
					x: Object.values(data['addr']), // IP地址作为竖轴
					y: Object.keys(data['addr']), // 对应的数据包数量作为横轴
					type: 'bar',
					orientation: 'h' // 设置为水平方向的柱形图
				}
			];

			let layout2 = {
				title: 'IP地址统计',
				// autosize: true,
				margin: {
					l: 200,		//左边IP太长了,设置一下全部显示
				},
				xaxis: {
					title: '数据包数量'
				},
				yaxis: {
					title: 'IP地址'
				}

			};

			Plotly.newPlot('IPSumerize', idata, layout2);
		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}
// 在线流量展示'线程'的id,方便结束时clear掉
let Chart_update_id = 0
// 在线示警, 也单独开一个计时器
let Warning_detect = 0
// 这个为前端获取后端时间-流量的序号
let idx = 0
// 这个为示警信息的table序号
let tableidx = 0


// start button的触发事件
// 开始在线流量监控
function sniff_start() {
	// warning_detect();
	fetch("/start");
	Chart_update_id = setInterval(Chart_update, 1000);
	Warning_detect = setInterval(warning_detect, 1000);
	console.log('Sniffing Start...');
}


//end button的触发事件
//包括画图和计算数据
function sniff_end() {
	fetch("/end");
	clearInterval(Chart_update_id);
	clearInterval(Warning_detect);
	NetworkQualityShow();
	PChartDraw();
	ColumnChartDraw();
	const save_pcap = document.querySelector('.save_pcap');
	save_pcap.style.display = 'inline-block';
	console.log('Sniffing End...');
}


// 请求后端,更新在线流量图
function Chart_update() {
	let newX = '';
	let newY = 0;
	// 发送 GET 请求到后端获取数据
	fetch('/get_data?variable=' + idx, {
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
			if (data === 'empty')		//可能空包
				return;
			// 这个idx就是获取后端的序号,一定要注意
			idx += 1;
			newX = data[0];
			newY = data[1];
			// console.log(newX, newY)
			// console.log(data);
			Plotly.extendTraces('OnlineTrafficChart', { x: [[newX]], y: [[newY]] }, [0]);
			// 接着更新带宽情况
			let newAnnotationText = '下载:' + data[5] + 'Bytes/s<br>' + '上传:' + data[3] + 'Bytes/s'
			// 更新布局注释的文本
			Plotly.relayout('OnlineTrafficChart', 'annotations[0].text', newAnnotationText);

		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}

function warning_detect() {
	// 发送 GET 请求到后端获取数据
	fetch('/get_warning_info', {
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
			if (data === 'empty')
				return;
			const warning_tb = document.querySelector('.warningInfo table');
			if (tableidx === 0) {
				const warning_div = document.querySelector('.warningInfo');
				warning_div.style.display = 'block';
			}

			tableidx += 1;
			// 创建新的行
			const newRow = warning_tb.insertRow();

			// 插入单元格并设置内容
			const cell1 = newRow.insertCell(0);
			cell1.textContent = tableidx;

			const cell2 = newRow.insertCell(1);
			cell2.textContent = data.time;

			const cell3 = newRow.insertCell(2);
			cell3.textContent = data.addr;

			const cell4 = newRow.insertCell(3);
			cell4.textContent = data.info;

		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}


function savePackets() {
	let filename = prompt("请输入文件名(包括文件扩展名，如 file.pcap):");
	// 定义符合 xxx.pcap 格式的正则表达式
	let regex = /\.pcap$/;

	// 使用正则表达式进行匹配
	if (!regex.test(filename)) {
		alert("输入的文件名不符合xxx.pcap格式");
		return;
	}

	fetch('/save_pcap?variable=' + filename, {
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
			if (data === 'success')
				alert('保存成功');
			else
				alert('保存失败');
		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}



// 第一个放在全局中,是在线流量的,方便后面更新
// data是newPlot的第一个参数,用来定义图表数据及其显示方式的参数对象
let data = [
	{
		x: [],
		y: [],
		type: "scatter",
		mode: "lines+markers",
		line: { shape: "spline" },
		marker: { color: "blue" },
	},
];

// layout是newPlot的第二个参数,用于定义图表的布局参数
// 包括坐标轴范围、标题、背景色、图例位置等
let layout = {
	title: "流量-时间曲线图",
	xaxis: {
		title: "时间",
	},
	yaxis: {
		title: "每秒的包数量",
	},
	responsive: true, 		// 启用响应式布局
	annotations: [
		{
			text: '下载:0bps<br>上传:0bps',
			showarrow: false,
			x: 1,
			y: 1.1,
			xref: 'paper',
			yref: 'paper',
			xanchor: 'right',
			yanchor: 'top',
			align: 'left',
		}
	]
	// 要实现实时渲染,需要relayout,效率有点低,还是放弃吧
};

// 对初始的静态网页做一个初始化,方便后面添加节点数据
Plotly.newPlot('OnlineTrafficChart', data, layout);






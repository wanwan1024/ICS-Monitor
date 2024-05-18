// 离线分析的js文件


const fileDisplay = document.getElementById('fileDisplay');
const fileSelect = document.getElementById('fileSelect');
const fileInput = document.getElementById('fileInput');
const deleteButton = document.querySelector('.file_delete');
const uploadfilename = document.getElementById('uploadfilename');

fileSelect.addEventListener('click', function () {
	fileInput.click();
});

fileInput.addEventListener('change', function () {
	if (fileInput.files.length > 0) {
		fileDisplay.textContent = `已选择文件：${fileInput.files[0].name}`;
	}
});

deleteButton.addEventListener('click', function () {
	fileInput.value = ''; // 清空文件输入框
	fileDisplay.textContent = ''; // 恢复默认提示
});


uploadfilename.addEventListener('click', async function () {
	if (!fileDisplay.textContent.trim() == '') {
		// console.log(fileInput.files[0].name);
		filename = fileInput.files[0].name;
		fileInput.value = ''; // 清空文件输入框
		fileDisplay.textContent = ''; // 恢复默认提示
		fetch('/offline_analysis?variable=' + filename, {
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
					console.log('success');
				else
					console.log(data);
			})
			.catch(error => {
				console.error('There has been a problem with your fetch operation:', error);
			});
		// 等待400ms,这一步很重要,因为后端处理数据还要一段时间
		await new Promise(resolve => setTimeout(resolve, 1000));
		offline_chart();
		offline_warning_show()
		NetworkQualityShow();
		PChartDraw();
		ColumnChartDraw();
	}
});


// 绘制离线数据包的流量-时间曲线图
function offline_chart() {
	fetch('/get_offline_ttp', {
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
			// console.log(data);
			let pdata = [
				{
					y: Object.values(data),
					x: Object.keys(data),
					type: "scatter",
					mode: "lines+markers",
					line: { shape: "spline" },
					marker: { color: "blue" },
				},
			];

			let layout = {
				title: "流量-时间曲线图",
				xaxis: {
					title: "时间",
				},
				yaxis: {
					title: "每秒的包数量",
				},
				responsive: true, 		// 启用响应式布局
			};

			Plotly.newPlot('offline_ttp', pdata, layout);

		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}

// 给出示警表
function offline_warning_show() {
	fetch('/offline_warning_info', {
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
			console.log(data);
			if (data === 'empty')
				return;

			let idx = 0;
			for (const item of data) {
				const warning_tb = document.querySelector('.warningInfo table');
				if (idx === 0) {
					const warning_div = document.querySelector('.warningInfo');
					warning_div.style.display = 'block';
				}

				idx += 1;
				// 创建新的行
				const newRow = warning_tb.insertRow();

				// 插入单元格并设置内容
				const cell1 = newRow.insertCell(0);
				cell1.textContent = idx;

				const cell2 = newRow.insertCell(1);
				cell2.textContent = item.time;

				const cell3 = newRow.insertCell(2);
				cell3.textContent = item.addr;

				const cell4 = newRow.insertCell(3);
				cell4.textContent = item.info;
			}

		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});
}


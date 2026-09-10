# CTU-13 Sample Analysis

## Background

论文中 CTU-13 数据集使用 12-field (264-bit) packet-header 向量做 Pareto 分析。
原始提取脚本 `process_remaining.py` 对本地 6 个 pcap 每文件只取前 5,000 包 (共 30,000)。
为应对"样本量过小"的质疑, 尝试扩大样本, 发现一个反直觉现象, 记录于此。

## The Phenomenon of the Three Figures (三个图的现象)

| 图 | 抽样方式 | 总包数 | 唯一模式 | 80% 覆盖 | 90% 覆盖 |
|------|---------|--------:|--------:|--------:|--------:|
| [30K](CTU-13_12f_30K_45-657.png) | 每文件前 5,000 包 (等量) | 30,000 | 2,600 | 45 | 657 |
| [100K](CTU-13_12f_100K_7-1214.png) | 每文件前 16,667 包 (等量) | 100,002 | 6,112 | 7 | 1,214 |
| [1.1M](CTU-13_12f_1.1M_3-4.png) | 每文件前 400,000 包 (等量上限) | 1,130,965 | 9,096 | 3 | 4 |

**现象**: 样本量越大, 达到 80%/90% 覆盖所需的模式数反而越小 (45 → 7 → 3) —— 与直觉相反。

**原因**: 本地 6 个 pcap 中 4 个是纯 DoS 洪泛录制 (文件名均带 dos):

| 文件 | 内容 |
|------|------|
| `botnet-capture-20110815-rbot-dos-icmp-more-bandwith.pcap` (477 万包) | 99.98% 单条 ICMP 洪泛 |
| `botnet-capture-20110818-bot-2.pcap` (394 万包) | 99.96% ICMP 洪泛 (2 条) |
| `botnet-capture-20110815-rbot-dos.pcap` (25.7 万包) | 99.6% UDP 洪泛 |
| `botnet-capture-20110815-rbot-dos-icmp.pcap` (2.9 万包) | 98% ICMP 洪泛 |
| `botnet-capture-20110816-donbot.pcap` (2.5 万包) | 正常 TCP 混合流量 |
| `botnet-capture-20110816-sogou.pcap` (2.1 万包) | 正常 TCP 混合流量 |

等量抽样下洪泛包占样本的 2/3~71%。洪泛模式 (如 `147.32.84.165 → 147.32.96.69`
的 ICMP echo, 整个 12 字段键完全重复) 的计数随样本线性增长, 前 2~4 个洪泛模式即可
覆盖 70%~85%; 而正常流量的模式分散在数千个键上。因此 n80/n90 主要由洪泛模式数量决定,
**与样本量无关** —— 无论取前 N 包还是跨全文件 stride 均匀抽样 (1,122,645 包版本同样
n80=3 / n90=4, 见 `expand_ctu13_stride.py`), 结论一致。

纯正常流量参考: donbot + sogou 合计 45,427 包 → n80=2,803, n90=4,693 (正常量级)。

**旁证**: 官方 binetflow 标注 (`45-capture20110815.binetflow`) 显示同一场景全程 6,194 万包中
TCP 占 94.2%、ICMP 仅 0.2% —— binetflow 覆盖整个观测点, 而发布的 pcap 是洪泛专项录制,
二者视角不同。本地 pcap 的洪泛特性是录制方式决定的, 并非 CTU-13 全集本身只有洪泛。

**结论**: 本地 CTU-13 数据无法构造"百万级且非洪泛"的样本。论文最终采用 30K 等量样本
(n80=45, n90=657)。若将来需要扩充, 官方源 `mcfp.felk.cvut.cz` 的场景 2/3
(`CTU-Malware-Capture-Botnet-43/44`) 有含真实背景流量的全天抓包
(`capture201108XX.truncated.pcap.bz2`, 各约 1.2GB)。

## Files

| File | Description |
|------|-------------|
| `CTU-13_12f_30K_45-657.png` | 30K 等量样本图 (论文采用版) |
| `CTU-13_12f_100K_7-1214.png` | 100K 等量样本试验图 |
| `CTU-13_12f_1.1M_3-4.png` | 1.1M 样本试验图 (每文件前 40 万包) |
| `CTU-13_12f_lookup_table_30K.csv` | 30K 查找表 (feature_key, count) |
| `CTU-13_12f_lookup_table_100K.csv` | 100K 查找表 |
| `CTU-13_12f_lookup_table_first400K.csv` | 1.1M 查找表 |
| `expand_ctu13.py` | dpkt 限量提取 6 个 pcap 的协议头 (每文件前 N 包) |
| `expand_ctu13_stride.py` | 跨全文件 stride 均匀抽样提取 |
| `try_ctu_100k.py` | 100K 等量样本 Pareto 统计 |
| `try_ctu_100k_plot.py` | 100K 试验图绘图 |

原始协议头 CSV (`ctu13_protocol_headers_first400K.csv` ~87MB、全量 stride 版 ~240MB)
超出 GitHub 100MB 限制未入库, 保留在本地 `CTU-13/` 目录。

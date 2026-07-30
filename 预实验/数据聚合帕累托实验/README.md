# 数据聚合帕累托实验

直接对网络流量协议头部字段进行二值转换，按协议位宽展开为二进制串，统计每种特征模式出现频率，降序排列，验证帕累托分布。

## 方法

1. Scapy 解析 PCAP → 提取 32 个标准协议头部字段
2. 选取稳定流标识字段（排除每包变化的 seq/ack/id/checksum）
3. 字段值 → 二进制位串（IP 32bit、Port 16bit、Protocol 8bit 等）
4. 拼接所有字段位串 → 特征模式 key
5. 统计频率 → 降序 → 计算累计覆盖率

## 文件

| 文件 | 说明 |
|------|------|
| `ISCX_VPN_12f.png` | ISCX VPN（12 字段，320bit，59万包） |
| `CTU-13_12f.png` | CTU-13 僵尸网络（12 字段，320bit，3万包） |
| `MAWI_3f_7.5M.png` | MAWI 骨干网（3 字段，40bit，750万包） |
| `MAWI_8f_full.png` | MAWI 骨干网（8 字段，104bit，355万包全量） |
| `USTC_3f.png` | USTC 应用流量（3 字段，40bit，11万包） |
| `CIC-IDS-2017_13f.png` | CIC-IDS 2017（13 流特征，346万流） |
| `NSL-KDD_8f.png` | NSL-KDD（8 类别离散特征，14万流） |
| `UNSW-NB15_7f.png` | UNSW-NB15（7 类别离散特征，25万流） |
| `IOT23_field_comparison.png` | IOT23 字段数量对比（3f/5f/6f/8f） |
| `_results.csv` | 全部数据集帕累托结果汇总 |
| `pareto_summary.csv` | 帕累托关键指标 |

## 结论

全部 8 个数据集均证实：**极少数高频特征模式覆盖绝大多数网络流量**，为 P2TN2 的查找表压缩提供了实验依据。

## 协议字段位宽

| 字段 | 位宽 | 字段 | 位宽 |
|------|------|------|------|
| MAC | 48 | IP | 32 |
| Port | 16 | Protocol | 8 |
| TTL | 8 | TCP Flags | 8 |
| TCP Window | 16 | | |

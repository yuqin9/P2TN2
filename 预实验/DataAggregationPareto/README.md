# Data Aggregation Pareto Experiment

Convert protocol header fields to binary representation, count feature pattern frequencies, sort descending, verify Pareto distribution.

## Method

1. Scapy parses PCAP -> extract 32 standard protocol header fields
2. Select stable flow-identifying fields (exclude per-packet seq/ack/id/checksum)
3. Field values -> binary bit strings (IP 32bit, Port 16bit, Protocol 8bit, etc.)
4. Concatenate all field bit strings -> feature pattern key
5. Count frequencies -> sort descending -> compute cumulative coverage

## Files

| File | Description |
|------|-------------|
| `ISCX_VPN_12f.png` | ISCX VPN (12 fields, 264bit, 593K packets) |
| `CTU-13_12f.png` | CTU-13 botnet (12 fields, 264bit, 30K packets) |
| `MAWI_3f_7.5M.png` | MAWI backbone (3 fields, 40bit, 7.5M packets) |
| `MAWI_8f_full.png` | MAWI backbone (8 fields, 104bit, 3.55M packets full) |
| `USTC_3f.png` | USTC app traffic (3 fields, 40bit, 110K packets) |
| `CIC-IDS-2017_9f.png` | CIC-IDS 2017 (9 low-cardinality flow features, 3.46M flows) |
| `NSL-KDD_8f.png` | NSL-KDD (8 categorical features, 148K flows) |
| `UNSW-NB15_7f.png` | UNSW-NB15 (7 categorical features, 257K flows) |
| `IOT23_field_comparison.png` | IOT23 field count comparison (3f/5f/6f/8f) |
| `_results.csv` | All datasets Pareto results summary |
| `pareto_summary.csv` | Pareto key indicators |

## ⚠️ v1 勘误 (2026-09-08)

1. **位宽误标**: ISCX/CTU 12 字段实际为 **264 bit** (48+48+32+32+8+8+16+16+8+16+16+16),
   原 README 误标 320 bit; IOT23 12f 为 280 bit (含 eth_type); IOT23/USTC 10f_noMAC 为
   168 bit (误标 248); MAWI 8 字段为 104 bit (某处误标 88)。
2. **IOT23 eth_type 全零**: `val_to_bits()` 无法解析 `'0x0800'` 十六进制字符串, 含 eth_type 的
   三张表 (12f / 8f_noFlags / 8f_noWin) 中该字段 16 bit 恒为 0。
3. **ISCX DNN 5 特征全零**: 见 `../ISCX_Inference_LUT/README.md`。
4. **CIC 13 字段原始值版无帕累托**: v1 的 CIC 键是 7 组量化编码（源 CSV 已删除，无法复现），
   帕累托是量化带来的假象；用原始 13 字段重建后独特率 67.6%（连续实值字段粒度过细），
   Top20% 仅覆盖 45.9%。论文图改用 9 个低基数字段（Destination Port + Fwd/Bwd Header Length
   + 6 个 flag 计数）重建，80% 覆盖 3,136 模式 (1.0%)、Top20% 91.5%。

修复版 (原始值 '|' 键、float64 精确编码) 位于 `../v2_rerun/` (本地),
重跑图片在 `v2_rerun/final_plots_v2/compact/`, 特征清单见 `v2_rerun/features_actual.csv`。

## Conclusion

All 8 datasets confirm: **a very small fraction of high-frequency patterns covers the vast majority of network traffic**, providing experimental support for P2TN2's lookup table compression.

## Protocol Field Bit Widths

| Field | Bits | Field | Bits |
|------|------|------|------|
| MAC | 48 | IP | 32 |
| Port | 16 | Protocol | 8 |
| TTL | 8 | TCP Flags | 8 |
| TCP Window | 16 | | |

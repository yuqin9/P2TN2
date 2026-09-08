# ISCX DNN Inference LUT Experiment

Build a Lookup Table (LUT) from DNN model inference results and verify Pareto distribution.

> **⚠️ 编码错误勘误 (v2 已修复)**: v1 流水线中 `pd.to_numeric(errors='coerce')` 无法解析
> MAC (`e8:e7:...`)、IPv4 (`131.202.240.87`)、EtherType (`0x0800`) 字符串, 13 个输入特征中
> **5 个 (eth_dst/eth_src/eth_type/ip_src/ip_dst) 恒为 0**。v2 已用 float64 精确重编码
> (MAC→48bit int, IPv4→32bit int, eth_type→`int(s,16)`), 相同 seed-42 划分下重训并重建 LUT。
> v2 文件: `iscx_dnn_model_v2.pt`, `ISCX_LUT_*_v2.csv`, `_metrics_v2.csv`。

## Pipeline

1. Randomly sample 2M packets from ISCX VPN dataset (seed=42)
2. 30% train DNN (600K) / 10% test (200K) / 60% LUT aggregation (1.2M)
3. Additional 1M packets for LUT expansion (2.2M total LUT inputs)
4. Evaluate LUT classification performance on test set

## Files

| File | Description |
|------|-------------|
| `01_Initial_LUT_1.2M.png` | Initial LUT (1.2M packets) Pareto distribution |
| `02_Expanded_LUT_2.2M.png` | Expanded LUT (2.2M packets) Pareto distribution |
| `ISCX_LUT_initial_1.2M.csv` | Initial LUT lookup table (67,030 entries, v1) |
| `ISCX_LUT_expanded_2.2M.csv` | Expanded LUT lookup table (101,940 entries, v1) |
| `ISCX_LUT_initial_1.2M_v2.csv` | Initial LUT lookup table (71,299 entries, v2 修复版) |
| `ISCX_LUT_expanded_2.2M_v2.csv` | Expanded LUT lookup table (111,336 entries, v2 修复版) |
| `_metrics.csv` | DNN and LUT performance metrics summary (v1) |
| `_metrics_v2.csv` | DNN and LUT performance metrics summary (v2 修复版) |

## Results

### v1 (含 5 个全零特征)

| | Entries | Hit Rate | Accuracy | Precision | Recall | F1 |
|------|---------|----------|----------|-----------|--------|------|
| Initial LUT | 67,030 | 96.1% | 94.60% | 94.77% | 94.60% | 94.66% |
| Expanded LUT | 101,940 | 96.9% | 95.41% | 95.49% | 95.41% | 95.44% |

**DNN (v1)**: Accuracy 97.88%, Precision 97.88%, Recall 97.88%, F1 97.88%

### v2 (float64 精确重编码, 2026-09-08)

| | Entries | Hit Rate | Accuracy | Precision | Recall | F1 |
|------|---------|----------|----------|-----------|--------|------|
| Initial LUT | 71,299 | 95.6% | 95.59% | 95.83% | 95.59% | 95.66% |
| Expanded LUT | 111,336 | 96.4% | 96.42% | 96.55% | 96.42% | 96.45% |

**DNN (v2)**: Accuracy 99.99%, Precision 99.99%, Recall 99.99%, F1 99.99%

## DNN Configuration

- Input dimension: 13 (protocol header fields: eth_dst, eth_src, eth_type, ip_src, ip_dst,
  ip_proto, ip_ttl, tcp_sport, tcp_dport, tcp_flags, tcp_window, udp_sport, udp_dport)
- Architecture: 256->128->64->1 (ReLU + Dropout 0.3)
- Optimizer: Adam (lr=0.001)
- Epochs: 50, Batch Size: 4096
- Framework: PyTorch 2.6.0+cu124 (RTX 4060 Laptop GPU)
- v2: model.double() 全程 float64

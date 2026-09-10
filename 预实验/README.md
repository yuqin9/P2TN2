# P2TN2 Pre-Experiments

Validates that network traffic feature distributions follow the Pareto Principle,
providing experimental basis for P2TN2's lookup table compression strategy.

## Experiments

### 1. Data Aggregation Pareto (`DataAggregationPareto/`)
Direct binary conversion of protocol header fields, frequency counting of feature patterns, Pareto distribution verification.
- Datasets: ISCX VPN, CTU-13, MAWI, USTC, CIC-IDS 2017, NSL-KDD, UNSW-NB15, IOT23
- Conclusion: A small fraction of high-frequency patterns (<8%) covers >80% of traffic

### 2. ISCX DNN Inference LUT (`ISCX_Inference_LUT/`)
Train a DNN classifier on ISCX VPN traffic, build a Lookup Table (LUT) from model inference results, verify Pareto distribution of inferred patterns.
- Split: 30% train / 10% test / 60% LUT aggregation + 1M expansion
- v1 (含编码错误): DNN Accuracy 97.88%, LUT Hit Rate 96.9%, LUT Accuracy 95.41%
- v2 (float64 重编码修复): DNN Accuracy 99.99%, LUT Hit Rate 96.4%, LUT Accuracy 96.42%

### 3. CTU-13 Sample Analysis (`CTU13_sample_analysis/`)
Three-sample-size comparison (30K / 100K / 1.1M packets) for the CTU-13 Pareto figure.
- Finding: 4 of the 6 local pcaps are pure DoS flood recordings (98-100% single-pattern ICMP/UDP floods), so larger samples give *smaller* n80 (45 → 7 → 3) — n80/n90 are set by the number of flood patterns, not sample size
- Paper keeps the 30K sample (n80=45, n90=657); official full-day captures with background traffic available at mcfp.felk.cvut.cz for future expansion
- See `CTU13_sample_analysis/README.md` for the full phenomenon description

## ⚠️ 勘误

v1 存在两类编码错误 (详见 `DataAggregationPareto/README.md` 与 `ISCX_Inference_LUT/README.md`):
1. ISCX DNN 的 5 个输入特征 (MAC/IP/EtherType 字符串) 被 `to_numeric` 全零化;
2. IOT23 位串键中 `eth_type` ('0x0800') 被 `val_to_bits()` 静默置零;
3. 部分 README 位宽误标 (320→264, 248→168, 88→104)。

修复版全流程重跑 (相同 seed-42 划分) 位于 `../v2_rerun/` (本地目录, 未入库),
指标对比见 `v2_rerun/results_summary.csv`, 实际特征清单见 `v2_rerun/features_actual.csv`。

## Code

- `pareto_analysis.py` — Data aggregation Pareto analysis
- `iscx_expand_lut.py` — DNN training + LUT inference + Pareto analysis

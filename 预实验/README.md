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
- DNN Accuracy 97.88%, LUT Hit Rate 96.9%, LUT Accuracy 95.41%

## Code

- `pareto_analysis.py` — Data aggregation Pareto analysis
- `iscx_expand_lut.py` — DNN training + LUT inference + Pareto analysis

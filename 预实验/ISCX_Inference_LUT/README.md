# ISCX DNN Inference LUT Experiment

Build a Lookup Table (LUT) from DNN model inference results and verify Pareto distribution.

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
| `ISCX_LUT_initial_1.2M.csv` | Initial LUT lookup table (67,030 entries) |
| `ISCX_LUT_expanded_2.2M.csv` | Expanded LUT lookup table (101,940 entries) |
| `_metrics.csv` | DNN and LUT performance metrics summary |

## Results

| | Entries | Hit Rate | Accuracy | Precision | Recall | F1 |
|------|---------|----------|----------|-----------|--------|------|
| Initial LUT | 67,030 | 96.1% | 94.60% | 94.77% | 94.60% | 94.66% |
| Expanded LUT | 101,940 | 96.9% | 95.41% | 95.49% | 95.41% | 95.44% |

**DNN**: Accuracy 97.88%, Precision 97.88%, Recall 97.88%, F1 97.88%

## DNN Configuration

- Input dimension: 13 (protocol header fields)
- Architecture: 256->128->64->1 (ReLU + Dropout 0.3)
- Optimizer: Adam (lr=0.001)
- Epochs: 50, Batch Size: 4096
- Framework: PyTorch 2.6.0+cu124 (RTX 4060 Laptop GPU)

"""从已有LUT测试4指标"""
import pandas as pd, numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_fscore_support

BASE = r"F:\自己的论文\网络数据集"

# 加载LUT
print("Loading LUT...")
lut = pd.read_csv(f"{BASE}/pareto_results/ISCX_DNN_inference_lut.csv")
print(f"  {len(lut):,} entries")

lut0 = set(); lut1 = set()
for _, row in lut.iterrows():
    k = row['key']  # format: '((v1, v2, ...), out)'
    # 找最后一个 '), ' 分割
    idx = k.rfind('), ')
    key_str = k[2:idx]    # strip '((' and up to '),'
    out = int(k[idx+3:-1])  # after '), ' strip final ')'
    vals = tuple(float(x.strip().replace('np.float32(','').replace(')','')) for x in key_str.split(','))
    (lut0 if out == 0 else lut1).add(vals)

print(f"  LUT0: {len(lut0):,}  LUT1: {len(lut1):,}")

# 加载数据(同样方式)
print("Loading data...")
df = pd.read_csv(f"{BASE}/iscxvpn/iscx_protocol_headers_100K.csv", dtype=str)
df = df.sample(n=2000000, random_state=42).reset_index(drop=True)
for c in df.columns:
    if c not in ('label', 'src_file'):
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
y = (df['label'] == 'VPN').astype(int).values
feat_cols = [c for c in df.columns if c not in ('label', 'src_file')]
X = df[feat_cols].values.astype('float32')
print(f"  {len(X):,} rows, VPN={y.sum():,}")

# 同样分割(seed=42)
idx = np.arange(len(df))
_, idx_test = train_test_split(idx, test_size=0.1, random_state=42, stratify=y)
y_te = y[idx_test]; X_te = X[idx_test]
print(f"  Test: {len(y_te):,}")

# LUT测试
y_pred = np.zeros(len(y_te), dtype=int)
hits = 0
for i in range(len(X_te)):
    k = tuple(X_te[i])
    if k in lut0:
        y_pred[i] = 0; hits += 1
    elif k in lut1:
        y_pred[i] = 1; hits += 1
    else:
        y_pred[i] = 1 - y_te[i]  # LUT miss -> wrong

print(f"\n  LUT Hit Rate: {hits/len(y_te)*100:.1f}%")
print(f"\n  === LUT Classification Report ===")
print(classification_report(y_te, y_pred, target_names=['NonVPN', 'VPN']))
p, r, f1, _ = precision_recall_fscore_support(y_te, y_pred, average='weighted')
acc = (y_pred == y_te).mean()
print(f"  Acc={acc*100:.2f}%  Prec={p*100:.2f}%  Recall={r*100:.2f}%  F1={f1*100:.2f}%")

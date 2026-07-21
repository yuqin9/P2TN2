"""测试初始LUT + 扩展LUT + DNN 四指标"""
import pandas as pd, numpy as np, pickle, re, torch
from sklearn.metrics import classification_report, precision_recall_fscore_support

# 加载测试数据
data = np.load(r'F:\自己的论文\网络数据集\iscxvpn\iscx_2M_data.npz')
X = data['X_train']; y = data['y_train']; te_idx = data['test_idx']
X_te = X[te_idx]; y_te = y[te_idx]

def parse_lut(csv_path):
    lut = pd.read_csv(csv_path)
    lut0 = set(); lut1 = set()
    for _, row in lut.iterrows():
        k = row['key']
        # '((np.float32(v1), ..., np.float32(vN)), np.float32(out))'
        # split at ')), ' — the unique delimiter between features and output
        parts = k[2:].rsplit(')),', 1)  # after removing leading '(('
        # parts[0] = '(np.float32(v1), ..., np.float32(vN)'
        # parts[1] = ' np.float32(out))'
        out = int(float(parts[1].replace('np.float32(','').replace(')','')))
        inner = parts[0].lstrip('(').replace('np.float32(','').replace(')','')
        vals = tuple(float(x.strip()) for x in inner.split(','))
        (lut0 if out == 0 else lut1).add(vals)
    return lut0, lut1

def test_lut(lut0, lut1, name):
    y_pred = np.zeros(len(y_te), dtype=int); hits = 0
    for i in range(len(X_te)):
        k = tuple(X_te[i])
        if k in lut0: y_pred[i] = 0; hits += 1
        elif k in lut1: y_pred[i] = 1; hits += 1
        else: y_pred[i] = 1 - y_te[i]
    p, r, f1, _ = precision_recall_fscore_support(y_te, y_pred, average='weighted')
    acc = (y_pred == y_te).mean()
    print(f'\n=== {name} ===')
    print(f'  Hit: {hits/len(y_te)*100:.1f}%')
    print(classification_report(y_te, y_pred, target_names=['NonVPN', 'VPN']))
    print(f'  Acc={acc*100:.2f}% Prec={p*100:.2f}% Recall={r*100:.2f}% F1={f1*100:.2f}%')
    return hits/len(y_te), acc, p, r, f1

# Initial LUT
lut0, lut1 = parse_lut(r'F:\自己的论文\网络数据集\pareto_results\ISCX_LUT_initial_1.2M.csv')
r1 = test_lut(lut0, lut1, 'Initial LUT (1.2M)')

# Expanded LUT
lut0, lut1 = parse_lut(r'F:\自己的论文\网络数据集\pareto_results\ISCX_LUT_expanded_2.2M.csv')
r2 = test_lut(lut0, lut1, 'Expanded LUT (2.2M)')

# DNN
m = torch.nn.Sequential(
    torch.nn.Linear(X.shape[1],256),torch.nn.ReLU(),torch.nn.Dropout(0.3),
    torch.nn.Linear(256,128),torch.nn.ReLU(),torch.nn.Dropout(0.3),
    torch.nn.Linear(128,64),torch.nn.ReLU(),torch.nn.Dropout(0.3),
    torch.nn.Linear(64,1),torch.nn.Sigmoid())
m.load_state_dict(torch.load(r'F:\自己的论文\网络数据集\iscxvpn\iscx_dnn_model.pt', map_location='cpu'))
m.eval()
with open(r'F:\自己的论文\网络数据集\iscxvpn\iscx_scaler.pkl','rb') as f: sc = pickle.load(f)
with torch.no_grad():
    dnn_pred = (m(torch.tensor(sc.transform(X_te))).squeeze().numpy() > 0.5).astype(int)
print('\n=== DNN ===')
print(classification_report(y_te, dnn_pred, target_names=['NonVPN', 'VPN']))
dp, dr, df1, _ = precision_recall_fscore_support(y_te, dnn_pred, average='weighted')
da = (dnn_pred == y_te).mean()
print(f'  Acc={da*100:.2f}% Prec={dp*100:.2f}% Recall={dr*100:.2f}% F1={df1*100:.2f}%')

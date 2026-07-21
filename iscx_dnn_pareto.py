"""ISCX: dtype=str快读 → sample 2M → GPU DNN → LUT帕累托 (已修复)"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import torch, torch.nn as nn, torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})
BASE = Path(r"F:\自己的论文\网络数据集")
CSV = BASE/"iscxvpn"/"iscx_protocol_headers_100K.csv"
OUT = BASE/"final_plots"

# ===== 1. dtype=str 快读 =====
print("1. Loading (dtype=str, no type inference)...")
df = pd.read_csv(CSV, dtype=str)
print(f"   {len(df):,} rows")
df = df.sample(n=2000000, random_state=42).reset_index(drop=True)
print(f"   Sampled: 2,000,000")

for c in df.columns:
    if c not in ('label','src_file'):
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)

y = (df['label']=='VPN').astype(int).values; y0 = y.sum()
feat_cols = [c for c in df.columns if c not in ('label','src_file')]
X = df[feat_cols].values.astype('float32')
print(f"   {X.shape[1]} features, VPN={y0:,} ({y0/len(y)*100:.1f}%)")

# ===== 2. Split =====
print("2. Split 30/60/10...")
idx = np.arange(len(df))
tr_idx, te_idx = train_test_split(idx, test_size=0.1, random_state=42, stratify=y)
tr_n = int(len(df)*0.3)
pa_idx, tr_idx2 = train_test_split(tr_idx, test_size=0.7, random_state=42, stratify=y[tr_idx])
X_tr,y_tr=X[tr_idx2],y[tr_idx2]; X_pa,y_pa=X[pa_idx],y[pa_idx]; X_te,y_te=X[te_idx],y[te_idx]
print(f"   Train={len(X_tr):,} Pareto={len(X_pa):,} Test={len(X_te):,}")
sc=StandardScaler()
X_tr_s=sc.fit_transform(X_tr); X_pa_s=sc.transform(X_pa); X_te_s=sc.transform(X_te)

# ===== 3. GPU Train =====
print("3. GPU Training...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"   {device}")
m = nn.Sequential(nn.Linear(X.shape[1],256),nn.ReLU(),nn.Dropout(0.3),
    nn.Linear(256,128),nn.ReLU(),nn.Dropout(0.3),
    nn.Linear(128,64),nn.ReLU(),nn.Dropout(0.3),nn.Linear(64,1),nn.Sigmoid()).to(device)
opt = optim.Adam(m.parameters(),lr=0.001)
dl = DataLoader(TensorDataset(torch.tensor(X_tr_s),torch.tensor(y_tr,dtype=torch.float32)),batch_size=4096,shuffle=True)
m.train()
for e in range(50):
    ls=0
    for bx,by in dl: bx,by=bx.to(device),by.to(device); opt.zero_grad(); l=nn.BCELoss()(m(bx).squeeze(),by); l.backward(); opt.step(); ls+=l.item()
    if (e+1)%10==0: print(f"   Ep {e+1} loss={ls/len(dl):.4f}")

# ===== 4. DNN Test =====
m.eval()
with torch.no_grad():
    te_pred=(m(torch.tensor(X_te_s).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    dnn_acc=accuracy_score(y_te,te_pred)
print(f"\n   DNN Acc: {dnn_acc*100:.2f}%")
print(classification_report(y_te,te_pred,target_names=['NonVPN','VPN']))

# ===== 5. LUT =====
print("5. Inference LUT...")
pa_preds=[]
with torch.no_grad():
    for i in range(0,len(X_pa_s),50000):
        b=torch.tensor(X_pa_s[i:i+50000]).to(device)
        pa_preds.append((m(b).squeeze().cpu().numpy()>0.5).astype(int))
pa_preds=np.concatenate(pa_preds); torch.cuda.empty_cache()

cnt=Counter()
for i in range(len(X_pa)): cnt[(tuple(X_pa[i]),int(pa_preds[i]))]+=1
items=sorted(cnt.items(),key=lambda x:x[1],reverse=True)
pd.DataFrame([(str(k),v) for (k,_),v in items],columns=['key','count']).to_csv(BASE/"pareto_results"/"ISCX_DNN_inference_lut.csv",index=False)
print(f"   LUT: {len(items):,} entries")

# ===== 6. Pareto =====
print("6. Pareto plot...")
counts=np.array([c for _,c in items]); total=counts.sum(); n=len(counts)
cumsum=counts.cumsum(); cov=cumsum/total*100; ranks=np.arange(1,n+1)
top80=ranks[(cov>=80).argmax()]; cov20=cov[min(int(n*0.2),n-1)]
step=max(1,n//5000); ridx=np.arange(0,n,step)
if ridx[-1]!=n-1: ridx=np.append(ridx,n-1)
fig,axs=plt.subplots(1,2,figsize=(15,4.5))
ax=axs[0]; ax.plot(ranks[ridx],cov[ridx],'b.',ms=2,alpha=0.6)
ax.set_xlabel('Number of Feature Patterns'); ax.set_ylabel('Hit Rate (%)')
ax.grid(True,alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0,105)
def fmt(x,p):
    if x==0: return '0'; return f'{x:.0f}' if x<1000 else f'{x/1000:.0f}K' if x<1e6 else f'{x/1e6:.1f}M'
ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt))
ax=axs[1]; ax.loglog(ranks[ridx],counts[ridx],'b.',ms=2,alpha=0.4)
ax.set_xlabel('Pattern Rank'); ax.set_ylabel('Frequency'); ax.grid(True,alpha=0.25)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt)); ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt))
plt.subplots_adjust(wspace=0.25)
plt.savefig(OUT/'ISCX_DNN_inference_pareto.png',dpi=150,bbox_inches='tight'); plt.close()
print(f"   Total={total:,} Unique={n:,} 80%={top80:,}({top80/n*100:.1f}%) Top20%={cov20:.1f}%")

# ===== 7. LUT test (四指标) =====
print("7. LUT test...")
lut0=set(); lut1=set()
for (key,out),_ in items: (lut0 if out==0 else lut1).add(key)

y_true = y_te
y_pred_lut = np.zeros(len(y_te), dtype=int)
hits = 0
for i in range(len(X_te)):
    k = tuple(X_te[i])
    if k in lut0:
        y_pred_lut[i] = 0; hits += 1
    elif k in lut1:
        y_pred_lut[i] = 1; hits += 1
    else:
        # LUT miss: predict wrong (取反)
        y_pred_lut[i] = 1 - y_true[i]

ht = hits/len(X_te)
print(f"\n   Test samples: {len(X_te):,}")
print(f"   LUT Hit Rate: {ht*100:.1f}%")
print(f"\n   === LUT Classification Report ===")
print(classification_report(y_true, y_pred_lut, target_names=['NonVPN','VPN']))
print(f"   === DNN Classification Report (baseline) ===")
print(classification_report(y_te, te_pred, target_names=['NonVPN','VPN']))

from sklearn.metrics import precision_recall_fscore_support
lut_p, lut_r, lut_f1, _ = precision_recall_fscore_support(y_true, y_pred_lut, average='weighted')
dnn_p, dnn_r, dnn_f1, _ = precision_recall_fscore_support(y_te, te_pred, average='weighted')
lut_acc = (y_pred_lut == y_true).mean()
print(f"   LUT:  Acc={lut_acc*100:.2f}%  Prec={lut_p*100:.2f}%  Recall={lut_r*100:.2f}%  F1={lut_f1*100:.2f}%")
print(f"   DNN:  Acc={dnn_acc*100:.2f}%  Prec={dnn_p*100:.2f}%  Recall={dnn_r*100:.2f}%  F1={dnn_f1*100:.2f}%")

pd.Series({
    'dnn_acc':dnn_acc,'dnn_prec':dnn_p,'dnn_rec':dnn_r,'dnn_f1':dnn_f1,
    'lut_hit':ht,'lut_acc':lut_acc,'lut_prec':lut_p,'lut_rec':lut_r,'lut_f1':lut_f1,
    'lut_n':n,'train':len(X_tr),'test':len(X_te),'pareto':len(X_pa)
}).to_csv(OUT/'ISCX_DNN_results.csv')
print(f"\nDone: {OUT}/")

"""
ISCX: 2M(30%train/10%test/60%LUT) → DNN → 初始LUT → +100w扩展 → 帕累托 → 测试
"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, precision_recall_fscore_support
import torch, torch.nn as nn, torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pickle, time

plt.rcParams.update({'font.size':13,'axes.labelsize':14,'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})
BASE = Path(r"F:\自己的论文\网络数据集")
CSV = BASE/"iscxvpn"/"iscx_protocol_headers_100K.csv"
OUT = BASE/"final_plots"

# ===== 1. 加载, 2M(30/10/60) + 额外100w =====
print("1. Loading & splitting...")
df = pd.read_csv(CSV, dtype=str)
rng = np.random.RandomState(42)
all_idx = np.arange(len(df))
idx_2m = sorted(rng.choice(all_idx, size=2000000, replace=False))
idx_extra_pool = sorted(set(all_idx) - set(idx_2m))
idx_extra_1m = sorted(rng.choice(idx_extra_pool, size=1000000, replace=False))

# 2M数据处理
df2 = df.iloc[idx_2m].copy()
for c in df2.columns:
    if c not in ('label','src_file'): df2[c] = pd.to_numeric(df2[c], errors='coerce').fillna(0)
y2 = (df2['label']=='VPN').astype(int).values
feat_cols = [c for c in df2.columns if c not in ('label','src_file')]
X2 = df2[feat_cols].values.astype('float32')

# 30%train / 10%test / 60%LUT
idx_all = np.arange(len(df2))
idx_trte, idx_lut2m = train_test_split(idx_all, test_size=0.6, random_state=42, stratify=y2)
idx_tr, idx_te = train_test_split(idx_trte, test_size=0.1/0.4, random_state=42, stratify=y2[idx_trte])

X_tr,y_tr = X2[idx_tr],y2[idx_tr]
X_te,y_te = X2[idx_te],y2[idx_te]
X_lut2m = X2[idx_lut2m]
print(f"   Train: {len(X_tr):,}  Test: {len(X_te):,}  LUT(2M): {len(X_lut2m):,}  Extra(1M): {len(idx_extra_1m):,}")

# 保存
np.savez(BASE/'iscxvpn'/'iscx_2M_data.npz', X_train=X2, y_train=y2, train_idx=idx_tr, test_idx=idx_te, lut_idx=idx_lut2m)
sc = StandardScaler(); X_tr_s = sc.fit_transform(X_tr); X_te_s = sc.transform(X_te)
with open(BASE/'iscxvpn'/'iscx_scaler.pkl','wb') as f: pickle.dump(sc,f)
print("   Saved: iscx_2M_data.npz, iscx_scaler.pkl")

# ===== 2. GPU训练 =====
print("\n2. GPU check...")
for attempt in range(3):
    cuda_ok = torch.cuda.is_available()
    device = torch.device('cuda' if cuda_ok else 'cpu')
    print(f"   Attempt {attempt+1}: cuda={cuda_ok}, device={device}")
    if cuda_ok:
        try:
            t = torch.randn(100,100).to(device); del t; torch.cuda.empty_cache(); break
        except Exception as e: print(f"   GPU fail: {e}")
    if not cuda_ok and attempt < 2: time.sleep(3)
if not torch.cuda.is_available(): raise RuntimeError("CUDA NOT AVAILABLE!")

print("\n3. Training...")
model = nn.Sequential(nn.Linear(X_tr.shape[1],256),nn.ReLU(),nn.Dropout(0.3),
    nn.Linear(256,128),nn.ReLU(),nn.Dropout(0.3),
    nn.Linear(128,64),nn.ReLU(),nn.Dropout(0.3),nn.Linear(64,1),nn.Sigmoid()).to(device)
opt = optim.Adam(model.parameters(),lr=0.001)
dl = DataLoader(TensorDataset(torch.tensor(X_tr_s).to(device),torch.tensor(y_tr,dtype=torch.float32).to(device)),batch_size=4096,shuffle=True)
model.train()
for e in range(50):
    ls=0
    for bx,by in dl: opt.zero_grad(); l=nn.BCELoss()(model(bx).squeeze(),by); l.backward(); opt.step(); ls+=l.item()
    if (e+1)%10==0: print(f"   Ep {e+1} loss={ls/len(dl):.4f}")
torch.save(model.state_dict(), BASE/'iscxvpn'/'iscx_dnn_model.pt')
print("   Saved: iscx_dnn_model.pt")

# DNN测试
model.eval()
with torch.no_grad():
    te_pred=(model(torch.tensor(X_te_s).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    dnn_acc=(te_pred==y_te).mean()
print(f"\n   === DNN Classification Report ===")
print(classification_report(y_te,te_pred,target_names=['NonVPN','VPN']))
dnn_p,dnn_r,dnn_f1,_=precision_recall_fscore_support(y_te,te_pred,average='weighted')
print(f"   DNN Acc={dnn_acc*100:.2f}% Prec={dnn_p*100:.2f}% Recall={dnn_r*100:.2f}% F1={dnn_f1*100:.2f}%")

# ===== 4. 初始LUT (60% of 2M = 1.2M) =====
print("\n4. Initial LUT from 60% (1.2M)...")
cnt = Counter()
model.eval()
bs=50000
for s in range(0, len(X_lut2m), bs):
    e=min(s+bs, len(X_lut2m)); Xb=sc.transform(X_lut2m[s:e])
    with torch.no_grad(): preds=(model(torch.tensor(Xb).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    for i in range(len(Xb)): cnt[(tuple(X_lut2m[s+i]), int(preds[i]))] += 1
print(f"   Initial LUT: {len(cnt):,} entries")
items_initial = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
pd.DataFrame([(str(k),v) for k,v in items_initial], columns=['key','count']).to_csv(BASE/'pareto_results'/'ISCX_LUT_initial_1.2M.csv', index=False)
torch.cuda.empty_cache()

# ===== 5. 扩展: 额外100w → 扩充LUT =====
print("\n5. Expanding LUT with 1M extra packets...")
df_extra = df.iloc[idx_extra_1m].copy()
for c in df_extra.columns:
    if c not in ('label','src_file'): df_extra[c] = pd.to_numeric(df_extra[c], errors='coerce').fillna(0)
X_ex = df_extra[feat_cols].values.astype('float32')

model.eval()
for s in range(0, len(X_ex), bs):
    e=min(s+bs, len(X_ex)); Xb=sc.transform(X_ex[s:e])
    with torch.no_grad(): preds=(model(torch.tensor(Xb).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    for i in range(len(Xb)): cnt[(tuple(X_ex[s+i]), int(preds[i]))] += 1
    if (s+bs)%200000==0: print(f"   {e:,}/{len(X_ex):,}")
torch.cuda.empty_cache()

items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
pd.DataFrame([(str(k),v) for k,v in items], columns=['key','count']).to_csv(BASE/'pareto_results'/'ISCX_LUT_expanded_2.2M.csv', index=False)
print(f"   Expanded LUT: {len(items):,} entries")

# ===== 6. 帕累托图(初始+扩展两张) =====
print("\n6. Pareto plots...")

def make_pareto_plot(items, total, fname):
    counts = np.array([c for _,c in items]); n=len(counts)
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
    plt.savefig(OUT/f'{fname}.png',dpi=150,bbox_inches='tight'); plt.close()
    print(f"   {fname}: total={total:,} unique={n:,} 80%={top80:,}({top80/n*100:.1f}%) Top20%={cov20:.1f}%")
    return n, top80, cov20

# Initial LUT
total_init = sum(c for _,c in items_initial)
make_pareto_plot(items_initial, total_init, '01_Initial_LUT_1.2M')

# Expanded LUT
total_exp = sum(c for _,c in items)
make_pareto_plot(items, total_exp, '02_Expanded_LUT_2.2M')

# 不再需要旧的counts变量
del items_initial  # free memory
# ===== 7. LUT测试(10% holdout) 四指标 =====
print("\n7. LUT test on 10% holdout...")
lut0=set(); lut1=set()
for (key,out),_ in items: (lut0 if out==0 else lut1).add(key)
y_pred=np.zeros(len(y_te),dtype=int); hits=0
for i in range(len(X_te)):
    k=tuple(X_te[i])
    if k in lut0: y_pred[i]=0; hits+=1
    elif k in lut1: y_pred[i]=1; hits+=1
    else: y_pred[i]=1-y_te[i]

ht=hits/len(y_te); acc_lut=(y_pred==y_te).mean()
p,r,f1,_=precision_recall_fscore_support(y_te,y_pred,average='weighted')

print(f"\n   Hit: {ht*100:.1f}%")
print(f"\n=== DNN (baseline) ===")
print(classification_report(y_te,te_pred,target_names=['NonVPN','VPN']))
print(f"\n=== LUT Classification ===")
print(classification_report(y_te,y_pred,target_names=['NonVPN','VPN']))
print(f"LUT Acc={acc_lut*100:.2f}% Prec={p*100:.2f}% Recall={r*100:.2f}% F1={f1*100:.2f}%")

pd.Series({
    'dnn_acc':dnn_acc,'lut_hit':ht,'lut_acc':acc_lut,'lut_prec':p,'lut_rec':r,'lut_f1':f1,
    'lut_entries':len(items),'train_2M':len(X_tr),'test':len(y_te),'lut_2M_pareto':len(X_lut2m),'extra_1M':len(X_ex)
}).to_csv(OUT/'ISCX_expanded_results.csv')
print(f"\nDone: {OUT}/")

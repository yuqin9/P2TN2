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

DATA_DIR = Path("./data")
CSV = DATA_DIR/"iscx_protocol_headers.csv"
MODEL_DIR = Path("./model")
OUT = Path("./output")
LUT_DIR = Path("./lut")
MODEL_DIR.mkdir(exist_ok=True); OUT.mkdir(exist_ok=True); LUT_DIR.mkdir(exist_ok=True)

# ========== 1. Load & split: 2M(30/10/60) + 1M extra ==========
print("1. Loading & splitting...")
df = pd.read_csv(CSV, dtype=str)
rng = np.random.RandomState(42)
idx_2m = sorted(rng.choice(len(df), size=2_000_000, replace=False))
extra_pool = sorted(set(range(len(df))) - set(idx_2m))
idx_extra_1m = sorted(rng.choice(extra_pool, size=1_000_000, replace=False))

df2 = df.iloc[idx_2m].copy()
for c in df2.columns:
    if c not in ('label','src_file'): df2[c] = pd.to_numeric(df2[c], errors='coerce').fillna(0)
y2 = (df2['label']=='VPN').astype(int).values
feat_cols = [c for c in df2.columns if c not in ('label','src_file')]
X2 = df2[feat_cols].values.astype('float32')

idx_all = np.arange(len(df2))
idx_trte, idx_lut2m = train_test_split(idx_all, test_size=0.6, random_state=42, stratify=y2)
idx_tr, idx_te = train_test_split(idx_trte, test_size=0.1/0.4, random_state=42, stratify=y2[idx_trte])

X_tr,y_tr = X2[idx_tr],y2[idx_tr]
X_te,y_te = X2[idx_te],y2[idx_te]
X_lut2m = X2[idx_lut2m]
print(f"   Train: {len(X_tr):,}  Test: {len(X_te):,}  LUT: {len(X_lut2m):,}  Extra: {len(idx_extra_1m):,}")

np.savez(MODEL_DIR/'data_2M.npz', X=X2, y=y2, train_idx=idx_tr, test_idx=idx_te, lut_idx=idx_lut2m)
sc = StandardScaler(); X_tr_s = sc.fit_transform(X_tr); X_te_s = sc.transform(X_te)
with open(MODEL_DIR/'scaler.pkl','wb') as f: pickle.dump(sc,f)

# ========== 2. GPU check ==========
print("\n2. GPU check...")
for a in range(3):
    ok = torch.cuda.is_available()
    device = torch.device('cuda' if ok else 'cpu')
    print(f"   Attempt {a+1}: cuda={ok}, device={device}")
    if ok:
        try: t=torch.randn(100,100).to(device); del t; torch.cuda.empty_cache(); break
        except Exception as e: print(f"   Fail: {e}")
    if not ok and a<2: time.sleep(3)
if not torch.cuda.is_available(): raise RuntimeError("CUDA NOT AVAILABLE!")

# ========== 3. Train DNN ==========
print("\n3. Training...")
model = nn.Sequential(
    nn.Linear(X_tr.shape[1],256),nn.ReLU(),nn.Dropout(0.3),
    nn.Linear(256,128),nn.ReLU(),nn.Dropout(0.3),
    nn.Linear(128,64),nn.ReLU(),nn.Dropout(0.3),nn.Linear(64,1),nn.Sigmoid()
).to(device)
opt = optim.Adam(model.parameters(),lr=0.001)
dl = DataLoader(TensorDataset(torch.tensor(X_tr_s).to(device),
    torch.tensor(y_tr,dtype=torch.float32).to(device)),batch_size=4096,shuffle=True)
model.train()
for e in range(50):
    ls=0
    for bx,by in dl: opt.zero_grad(); l=nn.BCELoss()(model(bx).squeeze(),by); l.backward(); opt.step(); ls+=l.item()
    if (e+1)%10==0: print(f"   Ep {e+1} loss={ls/len(dl):.4f}")
torch.save(model.state_dict(), MODEL_DIR/'dnn_model.pt')

model.eval()
with torch.no_grad():
    te_pred=(model(torch.tensor(X_te_s).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    dnn_acc=(te_pred==y_te).mean()
print(f"\n=== DNN Classification ===")
print(classification_report(y_te,te_pred,target_names=['NonVPN','VPN']))
dnn_p,dnn_r,dnn_f1,_=precision_recall_fscore_support(y_te,te_pred,average='weighted')
print(f"Acc={dnn_acc*100:.4f}% Prec={dnn_p*100:.4f}% Recall={dnn_r*100:.4f}% F1={dnn_f1*100:.4f}%")

# ========== 4. Initial LUT (1.2M) ==========
print("\n4. Initial LUT...")
cnt = Counter(); model.eval(); bs=50000
for s in range(0,len(X_lut2m),bs):
    e=min(s+bs,len(X_lut2m)); Xb=sc.transform(X_lut2m[s:e])
    with torch.no_grad(): preds=(model(torch.tensor(Xb).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    for i in range(len(Xb)): cnt[(tuple(X_lut2m[s+i]),int(preds[i]))]+=1
items_initial = sorted(cnt.items(),key=lambda x:x[1],reverse=True)
pd.DataFrame([(str(k),v) for k,v in items_initial],columns=['key','count']).to_csv(LUT_DIR/'LUT_initial.csv',index=False)
print(f"   {len(items_initial):,} entries")
torch.cuda.empty_cache()

# ========== 5. Expand LUT (+1M) ==========
print("\n5. Expanding LUT...")
df_ex = df.iloc[idx_extra_1m].copy()
for c in df_ex.columns:
    if c not in ('label','src_file'): df_ex[c]=pd.to_numeric(df_ex[c],errors='coerce').fillna(0)
X_ex=df_ex[feat_cols].values.astype('float32')
model.eval()
for s in range(0,len(X_ex),bs):
    e=min(s+bs,len(X_ex)); Xb=sc.transform(X_ex[s:e])
    with torch.no_grad(): preds=(model(torch.tensor(Xb).to(device)).squeeze().cpu().numpy()>0.5).astype(int)
    for i in range(len(Xb)): cnt[(tuple(X_ex[s+i]),int(preds[i]))]+=1
    if (s+bs)%200000==0: print(f"   {e:,}/{len(X_ex):,}")
items = sorted(cnt.items(),key=lambda x:x[1],reverse=True)
pd.DataFrame([(str(k),v) for k,v in items],columns=['key','count']).to_csv(LUT_DIR/'LUT_expanded.csv',index=False)
print(f"   {len(items):,} entries")
torch.cuda.empty_cache()

# ========== 6. Pareto plots ==========
print("\n6. Pareto plots...")
def make_pareto(items,total,fname):
    counts=np.array([c for _,c in items]); n=len(counts)
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
    print(f"   {fname}: {total:,} pkts, {n:,} uniq, 80% at {top80:,}({top80/n*100:.1f}%), Top20%={cov20:.1f}%")

t1=sum(c for _,c in items_initial); t2=sum(c for _,c in items)
make_pareto(items_initial,t1,'01_Initial_LUT')
make_pareto(items,t2,'02_Expanded_LUT')

# ========== 7. LUT test ==========
def test_lut(items,name):
    lut0=set(); lut1=set()
    for (key,out),_ in items: (lut0 if out==0 else lut1).add(key)
    yp=np.zeros(len(y_te),dtype=int); hits=0
    for i in range(len(X_te)):
        k=tuple(X_te[i])
        if k in lut0: yp[i]=0; hits+=1
        elif k in lut1: yp[i]=1; hits+=1
        else: yp[i]=1-y_te[i]
    ht=hits/len(y_te); acc=(yp==y_te).mean()
    p,r,f1,_=precision_recall_fscore_support(y_te,yp,average='weighted')
    print(f"\n=== {name} ===")
    print(f"Hit: {ht*100:.1f}%")
    print(classification_report(y_te,yp,target_names=['NonVPN','VPN']))
    print(f"Acc={acc*100:.2f}% Prec={p*100:.2f}% Recall={r*100:.2f}% F1={f1*100:.2f}%")
    return ht,acc,p,r,f1

print("\n7. LUT test...")
r1=test_lut(items_initial,'Initial LUT')
r2=test_lut(items,'Expanded LUT')

pd.DataFrame([
    {'Experiment':'Initial LUT','Entries':len(items_initial),'Hit':f'{r1[0]*100:.1f}%','Acc':f'{r1[1]*100:.2f}%','Prec':f'{r1[2]*100:.2f}%','Recall':f'{r1[3]*100:.2f}%','F1':f'{r1[4]*100:.2f}%'},
    {'Experiment':'Expanded LUT','Entries':len(items),'Hit':f'{r2[0]*100:.1f}%','Acc':f'{r2[1]*100:.2f}%','Prec':f'{r2[2]*100:.2f}%','Recall':f'{r2[3]*100:.2f}%','F1':f'{r2[4]*100:.2f}%'},
    {'Experiment':'DNN','Entries':'-','Hit':'-','Acc':f'{dnn_acc*100:.2f}%','Prec':f'{dnn_p*100:.2f}%','Recall':f'{dnn_r*100:.2f}%','F1':f'{dnn_f1*100:.2f}%'},
]).to_csv(OUT/'results.csv',index=False)
print(f"\nDone")

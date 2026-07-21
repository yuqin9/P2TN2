"""
流级数据集清理 - 只做NaN清理，保持原始值不变
"""
import pandas as pd, numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

BASE_DIR = Path(r"F:\自己的论文\网络数据集")

def clean(df, label_cols, drop_cols=None):
    """只清理NaN/inf，不做任何转换"""
    lbls = {}
    for lc in label_cols:
        if lc in df.columns:
            lbls[lc] = df[lc].copy()
    drop = [c for c in (drop_cols or []) + list(lbls.keys()) if c in df.columns]
    df = df.drop(columns=drop, errors='ignore')
    for c in df.columns:
        if df[c].dtype in ['int64','float64']:
            df[c] = df[c].replace([np.inf, -np.inf], 0).fillna(0)
        else:
            df[c] = df[c].fillna('')
    for lc, vals in lbls.items():
        df[lc] = vals.values
    return df

# 1. NSL-KDD
print("[1] NSL-KDD")
cols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins',
    'logged_in','num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells','num_access_files',
    'num_outbound_cmds','is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate','rerror_rate',
    'srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty']
t1 = pd.read_csv(BASE_DIR/"NSL_KDD-master"/"KDDTrain+.txt", header=None, names=cols)
t2 = pd.read_csv(BASE_DIR/"NSL_KDD-master"/"KDDTest+.txt", header=None, names=cols)
df = pd.concat([t1, t2], ignore_index=True)
df = clean(df, ['label','difficulty'])
df.to_csv(BASE_DIR/"NSL_KDD-master"/"NSL_KDD_clean.csv", index=False)
print(f"  {len(df)} rows x {len(df.columns)-2} features")

# 2. UNSW-NB15
print("[2] UNSW-NB15")
t1 = pd.read_csv(BASE_DIR/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_training-set.csv")
t2 = pd.read_csv(BASE_DIR/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_testing-set.csv")
df = pd.concat([t1, t2], ignore_index=True)
df = clean(df, ['label','attack_cat'], drop_cols=['id'])
df.to_csv(BASE_DIR/"UNSW"/"CSV Files"/"UNSW_NB15_clean.csv", index=False)
print(f"  {len(df)} rows x {len(df.columns)-2} features")

# 3. CIC-IDS 2017
print("[3] CIC-IDS 2017")
cicd = BASE_DIR/"CIC-IDS 2017"
files = sorted([f for f in cicd.glob("*.csv") if 'clean' not in f.name.lower() and 'binarized' not in f.name.lower() and 'prepared' not in f.name.lower()])
parts = []
for f in files:
    d = pd.read_csv(f, header=None) if f.name == 'CIC2017_Wed.csv' else pd.read_csv(f)
    if f.name == 'CIC2017_Wed.csv':
        d.columns = [f'f{i}' for i in range(d.shape[1]-1)] + ['Label']
    d.columns = d.columns.str.strip()
    parts.append(d)
df = pd.concat(parts, ignore_index=True)
drop_cols = ['Flow ID','Timestamp','SimillarHTTP']
df = clean(df, ['Label'], drop_cols=drop_cols)
df.to_csv(cicd/"CIC-IDS-2017_clean.csv", index=False)
print(f"  {len(df)} rows x {len(df.columns)-1} features")

# 4. CTU-13
print("[4] CTU-13")
files = sorted(BASE_DIR.glob("CTU-13/*.binetflow"))
parts = []
for f in files:
    d = pd.read_csv(f)
    parts.append(d)
df = pd.concat(parts, ignore_index=True)
df = clean(df, ['Label'], drop_cols=['StartTime','Dir'])
df.to_csv(BASE_DIR/"CTU-13"/"CTU-13_clean.csv", index=False)
print(f"  {len(df)} rows x {len(df.columns)-1} features")

# 5. MAWI
print("[5] MAWI")
mawi_in = BASE_DIR/"MAWI"/"202602011400.pcap"/"202602011400_binetflow"
mawi_out = BASE_DIR/"MAWI"/"clean"
mawi_out.mkdir(exist_ok=True)
for f in sorted(mawi_in.glob("*.csv")):
    d = pd.read_csv(f)
    d = clean(d, ['Label'], drop_cols=['Flow ID','Timestamp'])
    d.to_csv(mawi_out/(f.stem + '_clean.csv'), index=False)
print(f"  -> {mawi_out}")

print("\nDone - 所有流级数据集保持原始值，只清理了NaN")

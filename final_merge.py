"""
最后处理 - 三个无pcap数据集: 拼接原始CSV, 列名规范, NaN清理
"""
import pandas as pd, numpy as np
from pathlib import Path

BASE = Path(r"F:\自己的论文\网络数据集")

# ==================== NSL-KDD ====================
print("[1] NSL-KDD")
cols = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
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
    'label','difficulty'
]
t1 = pd.read_csv(BASE/"NSL_KDD-master"/"KDDTrain+.txt", header=None, names=cols)
t2 = pd.read_csv(BASE/"NSL_KDD-master"/"KDDTest+.txt", header=None, names=cols)
df = pd.concat([t1, t2], ignore_index=True)
# cleanup
for c in df.columns:
    if df[c].dtype in ['int64','float64']:
        df[c] = df[c].replace([np.inf, -np.inf], 0).fillna(0)
df.to_csv(BASE/"NSL_KDD-master"/"NSL_KDD.csv", index=False)
print(f"  {len(df)} rows x {len(df.columns)-2} features")


# ==================== UNSW-NB15 ====================
print("[2] UNSW-NB15")
t1 = pd.read_csv(BASE/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_training-set.csv")
t2 = pd.read_csv(BASE/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_testing-set.csv")
df = pd.concat([t1, t2], ignore_index=True)
df = df.drop(columns=['id'], errors='ignore')
for c in df.columns:
    if df[c].dtype in ['int64','float64']:
        df[c] = df[c].replace([np.inf, -np.inf], 0).fillna(0)
df.to_csv(BASE/"UNSW"/"CSV Files"/"UNSW_NB15.csv", index=False)
print(f"  {len(df)} rows x {len(df.columns)-2} features")


# ==================== CIC-IDS 2017 ====================
print("[3] CIC-IDS 2017")
cicd = BASE/"CIC-IDS 2017"
files = sorted([f for f in cicd.glob("*.csv")])
parts = []
for f in files:
    if f.name == 'CIC2017_Wed.csv':
        d = pd.read_csv(f, header=None)
        d.columns = [f'f{i}' for i in range(d.shape[1]-1)] + ['Label']
    else:
        d = pd.read_csv(f)
    d.columns = d.columns.str.strip()
    parts.append(d)
df = pd.concat(parts, ignore_index=True)
drop = ['Flow ID','Timestamp']
df = df.drop(columns=[c for c in drop if c in df.columns], errors='ignore')
for c in df.columns:
    if df[c].dtype in ['int64','float64']:
        df[c] = df[c].replace([np.inf, -np.inf], 0).fillna(0)
df.to_csv(cicd/"CIC-IDS-2017.csv", index=False)
nfeat = len(df.columns) - 1
print(f"  {len(df)} rows x {nfeat} features")

print("\nDone")

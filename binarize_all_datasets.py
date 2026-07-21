"""
数据集二值化 - 每个特征字段一列，值为0或1
策略: 连续值>中位数→1, 字符串=最常见值→1, 已是0/1则不变
"""
import pandas as pd, numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

BASE_DIR = Path(r"F:\自己的论文\网络数据集")

def binarize(series):
    """一列变一列，值0/1"""
    s = pd.to_numeric(series, errors='coerce')
    s = s.replace([np.inf, -np.inf], 0).fillna(0)

    # 如果已是二值，直接返回
    u = [v for v in s.unique() if not np.isnan(v)]
    if set(u).issubset({0, 1}):
        return s.astype(int)

    # 字符串列
    if series.dtype == 'object' or pd.api.types.is_string_dtype(series):
        mc = series.value_counts().index[0]
        return (series == mc).astype(int)

    # 数值列：中位数阈值
    median = s.median()
    return (s > median).astype(int)


def process(name, in_files, label_cols, drop_cols=None, read_kwargs=None):
    """通用处理：读文件→合并且二值化→保存"""
    print(f"\n{'='*50}")
    print(f"[{name}]")
    if read_kwargs is None:
        read_kwargs = {}

    dfs = []
    for f in in_files:
        df = pd.read_csv(f, **read_kwargs)
        df.columns = df.columns.str.strip()
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    feats_in = len(df.columns) - len([c for c in label_cols if c in df.columns])

    # 保存标签
    labels = {}
    for lc in label_cols:
        if lc in df.columns:
            labels[lc] = df[lc].copy()

    # 删除不处理的列
    all_drop = [c for c in (drop_cols or []) + list(labels.keys()) if c in df.columns]
    df = df.drop(columns=all_drop)

    # 逐列二值化
    for col in df.columns:
        df[col] = binarize(df[col])

    # 加回标签
    for lc, vals in labels.items():
        df[lc] = vals.values

    feats_out = len(df.columns) - len(labels)
    print(f"  {len(df)} rows, {feats_in} features -> {feats_out} binary columns")

    return df


# ============================================================
def run_all():
    # 1. NSL-KDD
    columns = [
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
    files = [BASE_DIR/"NSL_KDD-master"/"KDDTrain+.txt",
             BASE_DIR/"NSL_KDD-master"/"KDDTest+.txt"]
    kw = {'header': None, 'names': columns}
    df = process('NSL-KDD', files, ['label','difficulty'], read_kwargs=kw)
    df.to_csv(BASE_DIR/"NSL_KDD-master"/"NSL_KDD_binarized.csv", index=False)

    # 2. UNSW-NB15
    files = [BASE_DIR/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_training-set.csv",
             BASE_DIR/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_testing-set.csv"]
    df = process('UNSW-NB15', files, ['label','attack_cat'], drop_cols=['id'])
    df.to_csv(BASE_DIR/"UNSW"/"CSV Files"/"UNSW_NB15_binarized.csv", index=False)

    # 3. ISCX VPN
    files = [BASE_DIR/"iscxvpn"/"iscx_vpn_nonvpn_features.csv"]
    df = process('ISCX VPN', files, ['label','src_file'])
    df.to_csv(BASE_DIR/"iscxvpn"/"iscx_vpn_nonvpn_binarized.csv", index=False)

    # 4. CIC-IDS 2017
    cicd = BASE_DIR/"CIC-IDS 2017"
    files = sorted([f for f in cicd.glob("*.csv") if 'binarized' not in f.name.lower()])
    all_parts = []
    for f in files:
        if f.name == 'CIC2017_Wed.csv':
            d = pd.read_csv(f, header=None)
            d.columns = [f'feature_{i}' for i in range(d.shape[1]-1)] + ['Label']
        else:
            d = pd.read_csv(f)
        d.columns = d.columns.str.strip()
        all_parts.append(d)
    df = pd.concat(all_parts, ignore_index=True)
    labels = {'Label': df['Label'].copy()}
    drop = ['Flow ID','Timestamp','SimillarHTTP','Label']
    df = df.drop(columns=[c for c in drop if c in df.columns])
    for col in df.columns:
        df[col] = binarize(df[col])
    df['Label'] = labels['Label'].values
    print(f"\n[CIC-IDS 2017] {len(df)} rows, {len(df.columns)-1} features -> binary")
    df.to_csv(cicd/"CIC-IDS-2017_binarized.csv", index=False)

    # 5. CTU-13
    files = sorted(BASE_DIR.glob("CTU-13/*.binetflow"))
    df = process('CTU-13', files, ['Label'], drop_cols=['StartTime','Dir'])
    df.to_csv(BASE_DIR/"CTU-13"/"CTU-13_binarized.csv", index=False)

    # 6. MAWI - 文件太多，分块保存
    mawi_in = BASE_DIR/"MAWI"/"202602011400.pcap"/"202602011400_binetflow"
    mawi_out = BASE_DIR/"MAWI"/"binarized"
    mawi_out.mkdir(exist_ok=True)
    files = sorted(mawi_in.glob("*.csv"))
    print(f"\n[MAWI] {len(files)} files")
    for f in files:
        d = pd.read_csv(f)
        lbl = {'Label': d['Label'].copy()}
        drop = ['Flow ID','Timestamp','Label']
        d = d.drop(columns=[c for c in drop if c in d.columns])
        for col in d.columns:
            d[col] = binarize(d[col])
        d['Label'] = lbl['Label'].values
        out = mawi_out / (f.stem + '_binarized.csv')
        d.to_csv(out, index=False)
    print(f"  -> {mawi_out}")

    # 7. USTC
    files = [BASE_DIR/"USTC"/"ustc_features.csv"]
    df = process('USTC', files, ['label','src_file'])
    df.to_csv(BASE_DIR/"USTC"/"USTC_binarized.csv", index=False)

    print("\n" + "="*50)
    print("ALL DONE - every feature = single binary column (0/1)")

if __name__ == "__main__":
    run_all()

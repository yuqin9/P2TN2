"""
数据集整理 - 每个协议字段的值按原始位宽保留为整数
IP 地址 → 32位整数
端口号 → 16位整数
协议号 → 8位整数
字符串列 → 整数编码
不做阈值化，不做bit展开
"""
import pandas as pd, numpy as np
from pathlib import Path
import struct, socket, warnings
warnings.filterwarnings('ignore')

BASE_DIR = Path(r"F:\自己的论文\网络数据集")

def ip_to_int(ip_str):
    """IP地址 → 32位整数"""
    try:
        return struct.unpack("!I", socket.inet_aton(str(ip_str).strip()))[0]
    except:
        return 0

def clean_numeric(series):
    """清理数值列：转数值，NaN填0"""
    s = pd.to_numeric(series, errors='coerce')
    s = s.replace([np.inf, -np.inf], 0).fillna(0)
    return s.astype('int64')

def encode_strings(df):
    """字符串列 → 整数编码"""
    for col in df.columns:
        if df[col].dtype == 'object' or pd.api.types.is_string_dtype(df[col]):
            unique_map = {v: i for i, v in enumerate(df[col].dropna().unique())}
            df[col] = df[col].map(unique_map).fillna(0).astype('int64')
    return df


# ============================================================
# 1. NSL-KDD
def prep_nsl_kdd():
    print("[1/7] NSL-KDD")
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
    train = pd.read_csv(BASE_DIR/"NSL_KDD-master"/"KDDTrain+.txt", header=None, names=columns)
    test  = pd.read_csv(BASE_DIR/"NSL_KDD-master"/"KDDTest+.txt", header=None, names=columns)
    df = pd.concat([train, test], ignore_index=True)

    labels = df[['label','difficulty']].copy()
    df = df.drop(columns=['label','difficulty'])
    df = encode_strings(df)
    for c in df.columns:
        df[c] = clean_numeric(df[c])
    df[['label','difficulty']] = labels

    df.to_csv(BASE_DIR/"NSL_KDD-master"/"NSL_KDD_prepared.csv", index=False)
    print(f"  {len(df)} rows x {len(df.columns)-2} fields")


# 2. UNSW-NB15
def prep_unsw():
    print("[2/7] UNSW-NB15")
    train = pd.read_csv(BASE_DIR/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_training-set.csv")
    test  = pd.read_csv(BASE_DIR/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_testing-set.csv")
    df = pd.concat([train, test], ignore_index=True)

    # IP列转整数
    for c in ['srcip','dstip']:
        if c in df.columns:
            df[c] = df[c].apply(ip_to_int)

    labels = df[['label','attack_cat']].copy()
    df = df.drop(columns=['id','label','attack_cat'], errors='ignore')
    df = encode_strings(df)
    for c in df.columns:
        df[c] = clean_numeric(df[c])
    df[['label','attack_cat']] = labels

    df.to_csv(BASE_DIR/"UNSW"/"CSV Files"/"UNSW_NB15_prepared.csv", index=False)
    print(f"  {len(df)} rows x {len(df.columns)-2} fields")


# 3. ISCX VPN
def prep_iscx():
    print("[3/7] ISCX VPN")
    df = pd.read_csv(BASE_DIR/"iscxvpn"/"iscx_vpn_nonvpn_features.csv")

    # IP octets合并为32位地址
    for prefix in ['ip_src','ip_dst']:
        octet_cols = [f'{prefix}_octet{i}' for i in range(1,5)]
        if all(c in df.columns for c in octet_cols):
            vals = (df[octet_cols[0]].values.astype('int64') << 24) + \
                   (df[octet_cols[1]].values.astype('int64') << 16) + \
                   (df[octet_cols[2]].values.astype('int64') << 8)  + \
                    df[octet_cols[3]].values.astype('int64')
            df[f'{prefix}_addr'] = vals
            df = df.drop(columns=octet_cols)

    # TCP flags合并为8位
    flag_cols = ['tcp_flags_FIN','tcp_flags_SYN','tcp_flags_RST',
                 'tcp_flags_PSH','tcp_flags_ACK','tcp_flags_URG']
    if all(c in df.columns for c in flag_cols):
        flags = np.zeros(len(df), dtype='int64')
        for i, fc in enumerate(flag_cols):
            flags |= df[fc].fillna(0).values.astype('int64') << (5 - i)
        df['tcp_flags'] = flags
        df = df.drop(columns=flag_cols)

    # IP flags合并
    if all(c in df.columns for c in ['ip_flags_DF','ip_flags_MF']):
        df['ip_flags'] = (df['ip_flags_DF'].fillna(0).values.astype('int64') << 1) | \
                          df['ip_flags_MF'].fillna(0).values.astype('int64')
        df = df.drop(columns=['ip_flags_DF','ip_flags_MF'])

    labels = df[['label','src_file']].copy()
    df = df.drop(columns=['label','src_file'])
    df = encode_strings(df)
    for c in df.columns:
        df[c] = clean_numeric(df[c])
    df[['label','src_file']] = labels

    df.to_csv(BASE_DIR/"iscxvpn"/"iscx_vpn_prepared.csv", index=False)
    print(f"  {len(df)} rows x {len(df.columns)-2} fields")


# 4. CIC-IDS 2017
def prep_cicids():
    print("[4/7] CIC-IDS 2017")
    cicd = BASE_DIR/"CIC-IDS 2017"
    files = sorted([f for f in cicd.glob("*.csv")
                    if 'prepared' not in f.name.lower() and 'binarized' not in f.name.lower()])

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

    # IP列转整数
    for c in ['Src IP','Dst IP']:
        if c in df.columns:
            df[c] = df[c].apply(ip_to_int)

    drop = ['Flow ID','Timestamp','SimillarHTTP']
    label = df['Label'].copy()
    df = df.drop(columns=drop + ['Label'], errors='ignore')
    df = encode_strings(df)
    for c in df.columns:
        df[c] = clean_numeric(df[c])
    df['Label'] = label

    df.to_csv(cicd/"CIC-IDS-2017_prepared.csv", index=False)
    print(f"  {len(df)} rows x {len(df.columns)-1} fields")


# 5. CTU-13
def prep_ctu13():
    print("[5/7] CTU-13")
    files = sorted(BASE_DIR.glob("CTU-13/*.binetflow"))
    parts = []
    for f in files:
        d = pd.read_csv(f)
        for c in ['Sport','Dport']:
            if c in d.columns:
                d[c] = d[c].fillna('0').apply(
                    lambda x: int(str(x),16) if '0x' in str(x).lower() else int(float(x)))
        parts.append(d)
    df = pd.concat(parts, ignore_index=True)

    # IP列转整数
    for c in ['SrcAddr','DstAddr']:
        if c in df.columns:
            df[c] = df[c].apply(ip_to_int)

    drop = ['StartTime','Dir']
    label = df['Label'].copy()
    df = df.drop(columns=drop + ['Label'], errors='ignore')
    df = encode_strings(df)
    for c in df.columns:
        df[c] = clean_numeric(df[c])
    df['Label'] = label

    df.to_csv(BASE_DIR/"CTU-13"/"CTU-13_prepared.csv", index=False)
    print(f"  {len(df)} rows x {len(df.columns)-1} fields")


# 6. MAWI
def prep_mawi():
    print("[6/7] MAWI")
    mawi_in = BASE_DIR/"MAWI"/"202602011400.pcap"/"202602011400_binetflow"
    mawi_out = BASE_DIR/"MAWI"/"prepared"
    mawi_out.mkdir(exist_ok=True)
    files = sorted(mawi_in.glob("*.csv"))

    for f in files:
        d = pd.read_csv(f)
        for c in ['Src IP','Dst IP']:
            if c in d.columns:
                d[c] = d[c].apply(ip_to_int)
        drop = ['Flow ID','Timestamp']
        label = d['Label'].copy()
        d = d.drop(columns=drop + ['Label'], errors='ignore')
        d = encode_strings(d)
        for c in d.columns:
            d[c] = clean_numeric(d[c])
        d['Label'] = label
        d.to_csv(mawi_out/(f.stem + '_prepared.csv'), index=False)

    print(f"  {len(files)} files -> {mawi_out}")


# 7. USTC
def prep_ustc():
    print("[7/7] USTC")
    df = pd.read_csv(BASE_DIR/"USTC"/"ustc_features.csv")

    # IP octets合并为32位
    for prefix in ['ip_src','ip_dst']:
        octet_cols = [f'{prefix}_octet{i}' for i in range(1,5)]
        if all(c in df.columns for c in octet_cols):
            vals = (df[octet_cols[0]].values.astype('int64') << 24) + \
                   (df[octet_cols[1]].values.astype('int64') << 16) + \
                   (df[octet_cols[2]].values.astype('int64') << 8)  + \
                    df[octet_cols[3]].values.astype('int64')
            df[f'{prefix}_addr'] = vals
            df = df.drop(columns=octet_cols)

    flag_cols = ['tcp_flags_FIN','tcp_flags_SYN','tcp_flags_RST',
                 'tcp_flags_PSH','tcp_flags_ACK','tcp_flags_URG']
    if all(c in df.columns for c in flag_cols):
        flags = np.zeros(len(df), dtype='int64')
        for i, fc in enumerate(flag_cols):
            flags |= df[fc].fillna(0).values.astype('int64') << (5 - i)
        df['tcp_flags'] = flags
        df = df.drop(columns=flag_cols)

    labels = df[['label','src_file']].copy()
    df = df.drop(columns=['label','src_file'])
    df = encode_strings(df)
    for c in df.columns:
        df[c] = clean_numeric(df[c])
    df[['label','src_file']] = labels

    df.to_csv(BASE_DIR/"USTC"/"USTC_prepared.csv", index=False)
    print(f"  {len(df)} rows x {len(df.columns)-2} fields")


if __name__ == "__main__":
    prep_nsl_kdd()
    prep_unsw()
    prep_iscx()
    prep_cicids()
    prep_ctu13()
    prep_mawi()
    prep_ustc()
    print("\nALL DONE - 每个字段一个值，IP=32bit整数，端口=16bit整数，协议=8bit整数")

"""
CTU-13 + MAWI: 从pcap用scapy提取协议头部
NSL-KDD + UNSW + CIC-IDS 2017: 没有pcap, 拼接原始CSV
"""
import pandas as pd, numpy as np
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, IPv6

BASE = Path(r"F:\自己的论文\网络数据集")
MAX_PKTS = 5000

# ============================
# scapy 协议解析 (同 parse_pcaps_properly.py)
# ============================
FIELD_NAMES = [
    'eth_dst','eth_src','eth_type',
    'ip_ver','ip_hdr_len','ip_dscp','ip_ecn','ip_total_len','ip_id',
    'ip_flags','ip_frag_offset','ip_ttl','ip_proto','ip_checksum','ip_src','ip_dst',
    'tcp_sport','tcp_dport','tcp_seq','tcp_ack','tcp_hdr_len',
    'tcp_flags','tcp_window','tcp_checksum','tcp_urgptr',
    'udp_sport','udp_dport','udp_len','udp_checksum',
    'icmp_type','icmp_code','icmp_checksum',
]

def parse_pkt(pkt):
    f = {}
    if Ether in pkt:
        f['eth_dst']=pkt[Ether].dst; f['eth_src']=pkt[Ether].src
        f['eth_type']='0x%04x'%pkt[Ether].type
    else:
        for k in ['eth_dst','eth_src','eth_type']: f[k]=''
    if IP in pkt:
        ip=pkt[IP]
        f.update(ip_ver=ip.version, ip_hdr_len=ip.ihl*4, ip_dscp=ip.tos>>2,
                 ip_ecn=ip.tos&3, ip_total_len=ip.len, ip_id=ip.id,
                 ip_flags=str(ip.flags), ip_frag_offset=ip.frag, ip_ttl=ip.ttl,
                 ip_proto=ip.proto, ip_checksum=ip.chksum if hasattr(ip,'chksum') else 0,
                 ip_src=ip.src, ip_dst=ip.dst)
    elif IPv6 in pkt:
        ip6=pkt[IPv6]
        f.update(ip_ver=6, ip_hdr_len=40, ip_dscp=0, ip_ecn=0,
                 ip_total_len=ip6.plen+40, ip_id=0, ip_flags='', ip_frag_offset=0,
                 ip_ttl=ip6.hlim, ip_proto=ip6.nh, ip_checksum=0,
                 ip_src=ip6.src, ip_dst=ip6.dst)
    else:
        for k in ['ip_ver','ip_hdr_len','ip_dscp','ip_ecn','ip_total_len','ip_id',
                   'ip_flags','ip_frag_offset','ip_ttl','ip_proto','ip_checksum','ip_src','ip_dst']: f[k]=''
    if TCP in pkt:
        t=pkt[TCP]
        f.update(tcp_sport=t.sport, tcp_dport=t.dport, tcp_seq=t.seq, tcp_ack=t.ack,
                 tcp_hdr_len=t.dataofs*4, tcp_flags=str(t.flags), tcp_window=t.window,
                 tcp_checksum=t.chksum if hasattr(t,'chksum') else 0, tcp_urgptr=t.urgptr)
    else:
        for k in ['tcp_sport','tcp_dport','tcp_seq','tcp_ack','tcp_hdr_len',
                   'tcp_flags','tcp_window','tcp_checksum','tcp_urgptr']: f[k]=''
    if UDP in pkt:
        u=pkt[UDP]
        f.update(udp_sport=u.sport, udp_dport=u.dport, udp_len=u.len,
                 udp_checksum=u.chksum if hasattr(u,'chksum') else 0)
    else:
        for k in ['udp_sport','udp_dport','udp_len','udp_checksum']: f[k]=''
    if ICMP in pkt:
        ic=pkt[ICMP]
        f.update(icmp_type=ic.type, icmp_code=ic.code,
                 icmp_checksum=ic.chksum if hasattr(ic,'chksum') else 0)
    else:
        for k in ['icmp_type','icmp_code','icmp_checksum']: f[k]=''
    return f

def process_pcaps(pcap_paths, label_fn, output_path):
    rows=[]
    t0=datetime.now()
    for i, pp in enumerate(pcap_paths):
        try:
            pkts=sniff(offline=str(pp), count=MAX_PKTS, store=True, quiet=True)
        except:
            continue
        label=label_fn(pp)
        for p in pkts:
            r=parse_pkt(p); r['label']=label; r['src_file']=pp.name
            rows.append(r)
        if (i+1)%20==0:
            print(f"  {i+1}/{len(pcap_paths)} files, {len(rows)} pkts, {(datetime.now()-t0).total_seconds():.0f}s")
    df=pd.DataFrame(rows)
    df=df[FIELD_NAMES+['label','src_file']]
    df.to_csv(output_path, index=False)
    print(f"  -> {len(df)} pkts, {len(FIELD_NAMES)} fields -> {output_path}")
    return df


# ============================
# CTU-13: 6 pcap + scapy
# ============================
def do_ctu13():
    print("\n=== CTU-13 (from pcap) ===")
    pcaps = list(BASE.glob("CTU-13/*.pcap"))
    print(f"  {len(pcaps)} pcap files")
    # 标签: 场景编号 (从文件名提取)
    def label(p):
        import re
        m=re.search(r'capture(\d+)', p.name)
        return m.group(1) if m else p.stem
    return process_pcaps(pcaps, label, BASE/"CTU-13"/"ctu13_protocol_headers.csv")


# ============================
# MAWI: 100+ pcap files (split)
# ============================
def do_mawi():
    print("\n=== MAWI (from pcap) ===")
    # Use split pcap files (100 files, ~120MB each)
    split_dir = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
    pcaps = sorted(split_dir.glob("*.pcap"))
    if not pcaps:
        # Fall back to raw pcap
        pcaps = sorted(BASE.glob("MAWI").glob("**/*.pcap"))
    print(f"  {len(pcaps)} pcap files")
    # 全部是骨干网良性流量
    return process_pcaps(pcaps, lambda p: "Benign", BASE/"MAWI"/"mawi_protocol_headers.csv")


# ============================
# NSL-KDD + UNSW + CIC-IDS: 拼接原始文件
# ============================
def merge_csvs(name, files, out_path, label_cols, drop_cols=None, col_names=None):
    print(f"\n=== {name} (merge CSVs) ===")
    parts=[]
    for f in files:
        kw = {'header': None, 'names': col_names} if col_names else {}
        d = pd.read_csv(f, **kw)
        if d.shape[1]==1: d=pd.read_csv(f, sep='\t', **kw)  # try tab
        parts.append(d)
    df=pd.concat(parts, ignore_index=True)
    # 清理
    lbls={}
    for lc in label_cols:
        if lc in df.columns:
            lbls[lc]=df[lc].copy()
    drop=[c for c in (drop_cols or [])+list(lbls.keys()) if c in df.columns]
    df=df.drop(columns=drop, errors='ignore')
    for c in df.columns:
        if df[c].dtype in ['int64','float64']:
            df[c]=df[c].replace([np.inf,-np.inf],0).fillna(0)
        else:
            df[c]=df[c].fillna('')
    for lc,vals in lbls.items():
        df[lc]=vals.values
    df.to_csv(out_path, index=False)
    nfeat=len(df.columns)-len(lbls)
    print(f"  {len(df)} rows x {nfeat} features -> {out_path}")
    return df

def do_nsl():
    cols=['duration','protocol_type','service','flag','src_bytes','dst_bytes',
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
    return merge_csvs('NSL-KDD',
        [BASE/"NSL_KDD-master"/"KDDTrain+.txt", BASE/"NSL_KDD-master"/"KDDTest+.txt"],
        BASE/"NSL_KDD-master"/"NSL_KDD_clean.csv",
        ['label','difficulty'], col_names=cols)

def do_unsw():
    return merge_csvs('UNSW-NB15',
        [BASE/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_training-set.csv",
         BASE/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_testing-set.csv"],
        BASE/"UNSW"/"CSV Files"/"UNSW_NB15_clean.csv",
        ['label','attack_cat'], drop_cols=['id'])

def do_cicids():
    cicd=BASE/"CIC-IDS 2017"
    files=sorted([f for f in cicd.glob("*.csv") if '_clean' not in f.name.lower() and 'prepared' not in f.name.lower() and 'binarized' not in f.name.lower()])
    return merge_csvs('CIC-IDS 2017', files, cicd/"CIC-IDS-2017_clean.csv", ['Label'], drop_cols=['Flow ID','Timestamp'])


if __name__=='__main__':
    do_nsl()
    do_unsw()
    do_cicids()
    do_ctu13()
    do_mawi()
    print("\nALL DONE")

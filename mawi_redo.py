"""
MAWI重处理: 用前40组split pcap, 每文件2万包 → 80万包
"""
import pandas as pd, numpy as np
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, IPv6
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

BASE = Path(r"F:\自己的论文\网络数据集")
SPLIT_DIR = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
OUT = BASE / "pareto_results"
OUT.mkdir(exist_ok=True)
MAX_PKTS = 20000   # 每文件2万包
N_FILES = 40       # 前40组

# ===== scapy解析 =====
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
    f={}
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

# ===== 二值转换 =====
FIELD_BITS = {
    'eth_dst':48,'eth_src':48,'eth_type':16,
    'ip_ver':4,'ip_hdr_len':4,'ip_dscp':6,'ip_ecn':2,
    'ip_total_len':16,'ip_id':16,'ip_flags':3,'ip_frag_offset':13,
    'ip_ttl':8,'ip_proto':8,'ip_checksum':16,'ip_src':32,'ip_dst':32,
    'tcp_sport':16,'tcp_dport':16,'tcp_seq':32,'tcp_ack':32,
    'tcp_hdr_len':4,'tcp_flags':8,'tcp_window':16,
    'tcp_checksum':16,'tcp_urgptr':16,
    'udp_sport':16,'udp_dport':16,'udp_len':16,'udp_checksum':16,
    'icmp_type':8,'icmp_code':8,'icmp_checksum':16,
}

def val_to_bits(v, n):
    try:
        if isinstance(v, str):
            if ':' in v:
                return ''.join(format(int(p,16),'08b') for p in v.split(':'))[-n:].zfill(n)
            if '.' in v and len(v.split('.'))==4:
                return ''.join(format(int(p),'08b') for p in v.split('.')).zfill(n)
            if v.strip()=='': return '0'*n
            flags=0
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5),('E',6),('C',7)]:
                if ch in v: flags|=1<<bit
            return format(flags,f'0{n}b')
        return format(int(float(v)),f'0{n}b')[-n:]
    except: return '0'*n

# ===== 帕累托分析 (修正横坐标为特征数量) =====
def pareto_plot(lut, name, out_dir):
    total = lut['count'].sum()
    lut['cumsum'] = lut['count'].cumsum()
    lut['coverage'] = lut['cumsum'] / total * 100
    lut['rank'] = np.arange(1, len(lut)+1)

    top80_idx = (lut['coverage'] >= 80).idxmax()
    top80_n = lut.loc[top80_idx, 'rank']

    n_unique = len(lut)
    pcts = [1,5,10,20,50]
    covs = {}
    for p in pcts:
        idx = max(1, int(n_unique*p/100))
        covs[p] = lut.iloc[idx-1]['coverage']

    print(f"\n  {'='*50}")
    print(f"  {name}")
    print(f"  {'='*50}")
    print(f"  Packets: {total:,}  Unique: {n_unique:,}")
    print(f"  Patterns to reach 80% coverage: {top80_n:,} ({top80_n/n_unique*100:.1f}%)")
    for p in pcts:
        print(f"  Top {p:2d}% patterns ({max(1,int(n_unique*p/100)):,}) cover: {covs[p]:.1f}%")

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # 图1: X轴=特征数量(绝对), Y轴=累计覆盖率
    ax = axes[0]
    ax.plot(lut['rank'], lut['coverage'], 'b-', linewidth=1.5)
    ax.axhline(y=80, color='r', linestyle='--', alpha=0.5, label='80% coverage')
    ax.axvline(x=top80_n, color='g', linestyle='--', alpha=0.5, label=f'{top80_n:,} patterns')
    ax.set_xlabel('Number of Feature Patterns (sorted by frequency)')
    ax.set_ylabel('Cumulative Coverage (%)')
    ax.set_title(f'{name}\nPareto Distribution')
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    # 图2: log-log频率排名
    ax = axes[1]
    ax.loglog(lut['rank'], lut['count'].values, 'b.', markersize=1.5, alpha=0.5)
    ax.set_xlabel('Pattern Rank (log)')
    ax.set_ylabel('Frequency (log)')
    ax.set_title(f'{name}\nFrequency-Rank')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    p = out_dir / f'{name}_pareto.png'
    plt.savefig(p, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Plot: {p}")
    return {'name':name,'total':total,'unique':n_unique,'top80_n':top80_n,**{f'cov_{k}':v for k,v in covs.items()}}

# ===== 主流程 =====
print("="*60)
print("MAWI: Extracting from first 40 split pcap files")
print(f"  {MAX_PKTS} packets/file, {N_FILES} files")
print("="*60)

pcaps = sorted(SPLIT_DIR.glob("*.pcap"))[:N_FILES]
print(f"  Files: {len(pcaps)}")

rows = []
t0 = datetime.now()
for i, pp in enumerate(pcaps):
    try:
        pkts = sniff(offline=str(pp), count=MAX_PKTS, store=True, quiet=True)
    except:
        continue
    for p in pkts:
        r = parse_pkt(p); r['label'] = 'Benign'
        rows.append(r)
    if (i+1) % 10 == 0:
        print(f"  {i+1}/{len(pcaps)} files, {len(rows)} pkts, {(datetime.now()-t0).total_seconds():.0f}s")

df = pd.DataFrame(rows)
df = df[FIELD_NAMES + ['label']]
elapsed = (datetime.now()-t0).total_seconds()
print(f"  -> {len(df)} packets, {elapsed:.0f}s")

# 保存头部
hdr_path = BASE/"MAWI"/"mawi_protocol_headers_40.csv"
df.to_csv(hdr_path, index=False)
print(f"  Saved: {hdr_path}")

# === 帕累托: 多组特征 ===
feature_sets = [
    ('MAWI_40_svc',    ['ip_proto','tcp_dport','udp_dport']),
    ('MAWI_40_stable', ['eth_dst','eth_src','ip_src','ip_dst','ip_proto','ip_ttl',
                         'tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
    ('MAWI_40_noIP',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
]

results = []
for name, feats in feature_sets:
    print(f"\n--- {name} ({len(feats)} fields) ---")
    df2 = df[feats].copy()
    # To bits
    for col in feats:
        if col in FIELD_BITS:
            n = FIELD_BITS[col]
            df2[col] = [val_to_bits(v, n) for v in df[col].values]
    # Save bits
    df2.to_csv(OUT/f'{name}_bits.csv', index=False)
    # Lookup
    keys = df2.astype(str).agg(''.join, axis=1)
    lut = keys.value_counts().head(500000).reset_index()
    lut.columns = ['feature_key','count']
    lut = lut.sort_values('count', ascending=False).reset_index(drop=True)
    lut.to_csv(OUT/f'{name}_lookup_table.csv')
    # Pareto
    r = pareto_plot(lut, name, OUT)
    results.append(r)

# 汇总
print("\n" + "="*70)
print(f"{'Dataset':<25s} {'Total':>10s} {'Unique':>8s} {'Top80%N':>10s} {'Top5%':>7s} {'Top20%':>7s}")
print("-"*70)
for r in results:
    print(f"{r['name']:<25s} {r['total']:>10,} {r['unique']:>8,} {r['top80_n']:>10,} "
          f"{r['cov_5']:>6.1f}% {r['cov_20']:>6.1f}%")

print(f"\nAll results: {OUT}")

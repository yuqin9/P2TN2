"""
IOT23 完整处理: scapy提取 → 保存各层数据 → 多特征帕累托
"""
import pandas as pd, numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,
                     'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
IOT = BASE / "IOT23"
OUT = BASE / "final_plots"
LUT = BASE / "pareto_results"

MAX_PKTS = 50000  # 每pcap上限

# 标签定义
LABEL_MAP = {
    'Honeypot': 'Benign',
    'Malware-Capture-1-1': 'Hide_and_Seek',
    'Malware-Capture-3-1': 'Muhstik',
    'Malware-Capture-7-1': 'Mirai',
    'Malware-Capture-17-1': 'Malware',
    'Malware-Capture-20-1': 'Malware',
    'Malware-Capture-34-1': 'Mirai',
    'Malware-Capture-8-1': 'Malware',
    'Malware-Capture-9-1': 'Malware',
}

# ===== scapy解析 =====
FIELD_NAMES = [
    'eth_dst','eth_src','eth_type',
    'ip_src','ip_dst','ip_proto','ip_ttl',
    'tcp_sport','tcp_dport','tcp_flags','tcp_window',
    'udp_sport','udp_dport',
]

FIELD_BITS = {
    'eth_dst':48,'eth_src':48,'eth_type':16,
    'ip_src':32,'ip_dst':32,'ip_proto':8,'ip_ttl':8,
    'tcp_sport':16,'tcp_dport':16,'tcp_flags':8,'tcp_window':16,
    'udp_sport':16,'udp_dport':16,
}

def parse_pkt(pkt):
    f = {}
    # Ethernet
    if Ether in pkt:
        f['eth_dst']=pkt[Ether].dst; f['eth_src']=pkt[Ether].src
        f['eth_type']='0x%04x'%pkt[Ether].type
    else:
        for k in ['eth_dst','eth_src','eth_type']: f[k]=''
    # IP
    if IP in pkt:
        ip=pkt[IP]
        f['ip_src']=ip.src; f['ip_dst']=ip.dst
        f['ip_proto']=str(ip.proto); f['ip_ttl']=str(ip.ttl)
    else:
        for k in ['ip_src','ip_dst','ip_proto','ip_ttl']: f[k]=''
    # TCP
    if TCP in pkt:
        t=pkt[TCP]
        f['tcp_sport']=str(t.sport); f['tcp_dport']=str(t.dport)
        fl=0
        for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
            if ch in str(t.flags): fl|=1<<bit
        f['tcp_flags']=str(fl)
        f['tcp_window']=str(t.window)
    else:
        for k in ['tcp_sport','tcp_dport','tcp_flags','tcp_window']: f[k]=''
    # UDP
    if UDP in pkt:
        u=pkt[UDP]
        f['udp_sport']=str(u.sport); f['udp_dport']=str(u.dport)
    else:
        for k in ['udp_sport','udp_dport']: f[k]=''
    return f


def val_to_bits(v, n):
    try:
        if isinstance(v, str):
            if ':' in v:
                return ''.join(format(int(p,16),'08b') for p in v.split(':'))[-n:].zfill(n)
            if '.' in v and len(v.split('.'))==4:
                return ''.join(format(int(p),'08b') for p in v.split('.')).zfill(n)
            if v.strip()=='': return '0'*n
            flags=0
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                if ch in v: flags|=1<<bit
            return format(flags,f'0{n}b')
        return format(int(float(v)),f'0{n}b')[-n:]
    except: return '0'*n


def plot_one(counter, fname, total, n_fields, bits, out_dir):
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    counts = np.array([c for _, c in items])
    n = len(counts); cumsum = counts.cumsum(); cov = cumsum/total*100
    ranks = np.arange(1, n+1)
    top80 = ranks[(cov>=80).argmax()]
    cov5 = cov[min(int(n*0.05), n-1)]; cov20 = cov[min(int(n*0.2), n-1)]

    step = max(1, n//5000); ridx = np.arange(0, n, step)
    if ridx[-1] != n-1: ridx = np.append(ridx, n-1)

    fig, axes = plt.subplots(1, 2, figsize=(15, 4.5))
    ax = axes[0]
    ax.plot(ranks[ridx], cov[ridx], 'b.', markersize=2, alpha=0.6)
    ax.set_xlabel('Number of Feature Patterns'); ax.set_ylabel('Hit Rate (%)')
    ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0, 105)
    def fmt(x,p):
        if x==0: return '0'
        if x<1000: return f'{x:.0f}'
        if x<1e6: return f'{x/1000:.0f}K'
        return f'{x/1e6:.1f}M'
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt))
    ax = axes[1]
    ax.loglog(ranks[ridx], counts[ridx], 'b.', markersize=2, alpha=0.4)
    ax.set_xlabel('Pattern Rank'); ax.set_ylabel('Frequency')
    ax.grid(True, alpha=0.25)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt))
    plt.subplots_adjust(wspace=0.25)
    plt.savefig(out_dir/f'{fname}.png', dpi=150, bbox_inches='tight')
    plt.close()
    return total, n, top80, cov5, cov20


# ===== 主流程 =====
print("="*60)
print("IOT23: Processing all pcap files")
print("="*60)

all_rows = []
all_files = 0
t0 = datetime.now()

for subdir in sorted(IOT.iterdir()):
    if not subdir.is_dir(): continue
    pcaps = list(subdir.glob("*.pcap"))
    if not pcaps: continue

    # 确定标签
    label = 'Unknown'
    for key, val in LABEL_MAP.items():
        if key in subdir.name:
            label = val
            break

    for pp in pcaps:
        all_files += 1
        fname = f'{subdir.name}/{pp.name}'
        try:
            pkts = sniff(offline=str(pp), count=MAX_PKTS, store=True, quiet=True)
        except Exception as e:
            print(f"  SKIP {fname}: {e}")
            continue
        for p in pkts:
            row = parse_pkt(p)
            row['label'] = label
            row['src_dir'] = subdir.name
            all_rows.append(row)
        print(f"  [{label}] {fname}: {len(pkts)} pkts")

elapsed = (datetime.now()-t0).total_seconds()
print(f"\nTotal: {len(all_rows):,} pkts from {all_files} files, {elapsed:.0f}s")

# ===== 保存头部CSV =====
df = pd.DataFrame(all_rows)
df = df[FIELD_NAMES + ['label','src_dir']]
header_path = IOT / "iot23_protocol_headers.csv"
df.to_csv(header_path, index=False)
print(f"Header CSV: {header_path}  ({len(df):,} rows)")

# ===== Bit转换 + 保存 =====
print("\nBit conversion...")
df_bits = df[FIELD_NAMES].copy()
for col in FIELD_NAMES:
    if col in FIELD_BITS:
        n = FIELD_BITS[col]
        df_bits[col] = [val_to_bits(v, n) for v in df[col].values]
df_bits['label'] = df['label'].values
bits_path = IOT / "iot23_bits.csv"
df_bits.to_csv(bits_path, index=False)
print(f"Bits CSV: {bits_path}")

total_pkts = len(df)

# ===== 多特征组合帕累托 =====
print("\n=== Pareto Analysis ===")
feature_sets = [
    ('IOT23_12f', FIELD_NAMES, 320),
    ('IOT23_3f_svc', ['ip_proto','tcp_dport','udp_dport'], 40),
    ('IOT23_5f_win', ['ip_proto','ip_ttl','tcp_dport','udp_dport','tcp_window'], 64),
    ('IOT23_8f_l4full', ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport'], 104),
    ('IOT23_10f_noMAC', ['ip_src','ip_dst','ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport'], 248),
]

results = []
for fname, feats, bits in feature_sets:
    cnt = Counter()
    for _, row in df.iterrows():
        key = ''.join(str(val_to_bits(row[f], FIELD_BITS.get(f,8))) for f in feats if f in row.index)
        cnt[key] += 1
    # 保存lookup
    items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
    lut = pd.DataFrame(items, columns=['feature_key','count'])
    lut.to_csv(LUT/f'{fname}_lookup_table.csv', index=False)
    # 画图
    t, n, top80, cov5, cov20 = plot_one(cnt, fname, total_pkts, len(feats), bits, OUT)
    results.append((fname, total_pkts, n, top80, cov5, cov20))
    print(f'  {fname}: {n:,} uniq, 80% at {top80:,}, Top20%={cov20:.1f}%')

# 汇总
df_r = pd.DataFrame(results, columns=['image','total','unique','top80','cov5_pct','cov20_pct'])
df_r.to_csv(OUT/'_results_iot23.csv', index=False)
print(f"\nAll done. Plots: {OUT}/  Results: {OUT}/_results_iot23.csv")

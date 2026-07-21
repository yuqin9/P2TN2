"""
生成MAWI和USTC所有特征组合的查找表并统一画图
MAWI: 5个pcap, 一次读取, 同时计算所有组合
USTC: 从CSV读取
NSL/UNSW: 已有lookup table直接画
"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size': 11, 'axes.titlesize': 12, 'axes.labelsize': 11,
                     'legend.fontsize': 8, 'figure.dpi': 150, 'savefig.bbox': 'tight'})

BASE = Path(r"F:\自己的论文\网络数据集")
LUT_DIR = BASE / "pareto_results"
OUT = BASE / "final_plots"
OUT.mkdir(exist_ok=True)

# === 所有特征组合定义 ===
MAWI_COMBOS = [
    ('svc3',    ['ip_proto','tcp_dport','udp_dport']),
    ('svc4',    ['ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('svc5',    ['ip_proto','ip_ttl','tcp_sport','tcp_dport','udp_sport','udp_dport']),
    ('tcp5',    ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window']),
    ('l4full',  ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
    ('subnet',  ['ip_src24','ip_dst24','ip_proto','tcp_dport','udp_dport']),
    ('subnet4', ['ip_src24','ip_dst24','ip_proto','ip_ttl','tcp_dport','udp_dport']),
]

USTC_COMBOS = [
    ('svc3',      ['ip_proto','tcp_dport','udp_dport']),
    ('svc4',      ['ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('svc_flag',  ['ip_proto','tcp_dport','udp_dport','tcp_flags']),
    ('svc_ttlfl', ['ip_proto','ip_ttl','tcp_dport','udp_dport','tcp_flags']),
    ('svc_win',   ['ip_proto','ip_ttl','tcp_dport','udp_dport','tcp_window']),
    ('port5',     ['ip_proto','tcp_sport','tcp_dport','udp_sport','udp_dport']),
    ('tcp6',      ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window']),
    ('l4full',    ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
    ('sport4',    ['ip_proto','tcp_sport','tcp_dport','tcp_flags']),
]

BITS = {'ip_proto':8,'ip_ttl':8,'tcp_sport':16,'tcp_dport':16,'tcp_flags':8,
        'tcp_window':16,'udp_sport':16,'udp_dport':16,'ip_src24':24,'ip_dst24':24}


def extract_key(pkt, fields, is_pcap=True):
    parts = []
    for f in fields:
        try:
            if is_pcap:
                if f == 'ip_proto': v = pkt[IP].proto if IP in pkt else 0
                elif f == 'ip_ttl': v = pkt[IP].ttl if IP in pkt else 0
                elif f == 'ip_src24':
                    v = 0
                    if IP in pkt:
                        o = [int(x) for x in pkt[IP].src.split('.')]
                        v = (o[0]<<16)|(o[1]<<8)|o[2]
                elif f == 'ip_dst24':
                    v = 0
                    if IP in pkt:
                        o = [int(x) for x in pkt[IP].dst.split('.')]
                        v = (o[0]<<16)|(o[1]<<8)|o[2]
                elif f == 'tcp_sport': v = pkt[TCP].sport if TCP in pkt else 0
                elif f == 'tcp_dport': v = pkt[TCP].dport if TCP in pkt else 0
                elif f == 'tcp_flags':
                    v = 0
                    if TCP in pkt:
                        for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                            if ch in str(pkt[TCP].flags): v |= 1<<bit
                elif f == 'tcp_window': v = pkt[TCP].window if TCP in pkt else 0
                elif f == 'udp_sport': v = pkt[UDP].sport if UDP in pkt else 0
                elif f == 'udp_dport': v = pkt[UDP].dport if UDP in pkt else 0
                else: v = 0
            else:
                # from CSV row (r passed as pkt argument)
                v = pkt[f] if hasattr(pkt, '__getitem__') and f in pkt.index else (pkt.get(f,0) if hasattr(pkt,'get') else 0)
        except: v = 0
        parts.append(str(v))
    return '|'.join(parts)


def plot_one(counter, name, n_fields, bits, out_dir):
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    counts = np.array([c for _, c in items])
    total = counts.sum(); n = len(counts)
    cumsum = counts.cumsum(); coverage = cumsum/total*100
    ranks = np.arange(1, n+1)
    top80 = ranks[(coverage>=80).argmax()]
    cov1 = coverage[min(int(n*0.01), n-1)]
    cov5 = coverage[min(int(n*0.05), n-1)]
    cov20 = coverage[min(int(n*0.2), n-1)]

    fig, axes = plt.subplots(1, 2, figsize=(16, 5.5))

    ax = axes[0]
    ax.plot(ranks, coverage, 'b-', linewidth=1.8, alpha=0.85)
    ax.set_xlabel('Number of Feature Patterns')
    ax.set_ylabel('Cumulative Coverage (%)')
    ax.set_title(f'{name} ({n_fields} fields, {bits} bits)')
    ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0, 105)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1000:.0f}K' if x>=1000 else f'{x:.0f}'))

    textstr = (f'Total: {total:,}   Unique: {n:,}\n'
               f'80% at: {top80:,} ({top80/n*100:.1f}%)\n'
               f'Top 1%: {cov1:.1f}%   Top 5%: {cov5:.1f}%   Top 20%: {cov20:.1f}%')
    ax.text(0.98, 0.02, textstr, transform=ax.transAxes, fontsize=7.5,
            va='bottom', ha='right', bbox=dict(boxstyle='round,pad=0.4', facecolor='white', alpha=0.85, edgecolor='gray'))

    ax = axes[1]
    ax.loglog(ranks, counts, 'b.', markersize=1.5, alpha=0.4)
    ax.set_xlabel('Pattern Rank (log)'); ax.set_ylabel('Frequency (log)')
    ax.set_title(f'{name}')
    ax.grid(True, alpha=0.25)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1000:.0f}K' if x>=1000 else f'{x:.0f}'))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y,p: f'{y/1000:.0f}K' if y>=1000 else f'{y:.0f}'))

    plt.tight_layout()
    plt.savefig(out_dir/f'{name}.png', dpi=150, bbox_inches='tight')
    plt.close()
    return total, n, top80, cov5, cov20


# ========== MAWI ==========
print("MAWI: processing 5 pcap files for all combos...")
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
pcaps = sorted(SPLIT.glob("*.pcap"))[:5]
mawi_counters = {name: Counter() for name, _ in MAWI_COMBOS}

for i, pp in enumerate(pcaps):
    pkts = sniff(offline=str(pp), count=500000, store=True, quiet=True)
    for name, fields in MAWI_COMBOS:
        cnt = mawi_counters[name]
        for p in pkts:
            cnt[extract_key(p, fields)] += 1
    print(f"  [{i+1}/5] {pp.name}")

print("\nMAWI results:")
for name, fields in MAWI_COMBOS:
    bits = sum(BITS[f] for f in fields)
    plot_one(mawi_counters[name], f'MAWI_{name}', len(fields), bits, OUT)
    print(f"  MAWI_{name}: {len(mawi_counters[name]):,} unique, {bits} bits")

# ========== USTC ==========
print("\nUSTC: processing CSV for all combos...")
df = pd.read_csv(BASE/"USTC"/"ustc_protocol_headers.csv")
ustc_counters = {name: Counter() for name, _ in USTC_COMBOS}
for _, row in df.iterrows():
    for name, fields in USTC_COMBOS:
        parts = []
        for f in fields:
            try: parts.append(str(row[f]))
            except: parts.append('0')
        ustc_counters[name]['|'.join(parts)] += 1

print("USTC results:")
for name, fields in USTC_COMBOS:
    bits = sum(BITS.get(f,16) for f in fields)
    plot_one(ustc_counters[name], f'USTC_{name}', len(fields), bits, OUT)
    print(f"  USTC_{name}: {len(ustc_counters[name]):,} unique, {bits} bits")

# ========== NSL / UNSW (已有lookup) ==========
print("\nNSL/UNSW: from existing lookup tables...")
flow_tables = [
    ('NSL_cat3_lookup_table.csv', 'NSL_cat3', 3), ('NSL_cat5_lookup_table.csv', 'NSL_cat5', 5),
    ('NSL_disc8_lookup_table.csv', 'NSL_disc8', 8), ('NSL_svc5_lookup_table.csv', 'NSL_svc5', 5),
    ('UNSW_cat3_lookup_table.csv', 'UNSW_cat3', 3), ('UNSW_cat5_lookup_table.csv', 'UNSW_cat5', 5),
    ('UNSW_conn6_lookup_table.csv', 'UNSW_conn6', 6), ('UNSW_disc7_lookup_table.csv', 'UNSW_disc7', 7),
    ('UNSW_svc6_lookup_table.csv', 'UNSW_svc6', 6),
]
for csv_name, title, nf in flow_tables:
    p = LUT_DIR / csv_name
    if p.exists():
        lut = pd.read_csv(p)
        cnt = Counter(dict(zip(lut.iloc[:,0], lut.iloc[:,1])))
        plot_one(cnt, title, nf, '-', OUT)
        print(f"  {title}: OK")
    else:
        print(f"  {title}: SKIP (not found)")

print(f"\nAll plots -> {OUT}")

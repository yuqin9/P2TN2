"""
最终统一画图: 简洁标题，文件名=数据集_特征数
"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,'axes.titlesize':12,
                     'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
LUT_DIR = BASE / "pareto_results"
OUT = BASE / "final_plots"
OUT.mkdir(exist_ok=True)

BITS_MAP = {'ip_proto':8,'ip_ttl':8,'tcp_sport':16,'tcp_dport':16,'tcp_flags':8,
            'tcp_window':16,'udp_sport':16,'udp_dport':16,'ip_src24':24,'ip_dst24':16}

def plot_one(counter, fname, total_pkts):
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    counts = np.array([c for _, c in items])
    n = len(counts); cumsum = counts.cumsum(); cov = cumsum/total_pkts*100
    ranks = np.arange(1, n+1)
    top80 = ranks[(cov>=80).argmax()]
    cov1 = cov[min(int(n*0.01), n-1)]
    cov5 = cov[min(int(n*0.05), n-1)]
    cov20 = cov[min(int(n*0.2), n-1)]

    fig, axes = plt.subplots(1, 2, figsize=(15, 4.5))

    ax = axes[0]
    ax.plot(ranks, cov, 'b-', linewidth=1.8, alpha=0.85)
    ax.set_xlabel('Number of Feature Patterns (sorted by frequency)')
    ax.set_ylabel('Cumulative Coverage (%)')
    ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0, 105)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1000:.0f}K' if x<1e6 else f'{x/1e6:.1f}M'))

    txt = (f'Total packets: {total_pkts:,}\nUnique patterns: {n:,}\n'
           f'80% coverage: {top80:,} ({top80/n*100:.1f}%)\n'
           f'Top 5% cover: {cov5:.1f}%\nTop 20% cover: {cov20:.1f}%')
    ax.text(0.98, 0.02, txt, transform=ax.transAxes, fontsize=9,
            va='bottom', ha='right',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.85, edgecolor='gray'))

    ax = axes[1]
    ax.loglog(ranks, counts, 'b.', markersize=1.5, alpha=0.3)
    ax.set_xlabel('Pattern Rank (log scale)')
    ax.set_ylabel('Frequency (log scale)')
    ax.grid(True, alpha=0.25)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1000:.0f}K' if x<1e6 else f'{x/1e6:.1f}M'))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y,p: f'{y/1000:.0f}K' if y<1e6 else f'{y/1e6:.1f}M'))

    plt.subplots_adjust(wspace=0.25)
    plt.savefig(OUT/f'{fname}.png', dpi=150, bbox_inches='tight')
    plt.close()
    return n, total_pkts, top80, cov5, cov20


# ================================================================
print("="*60)

results_log = []

# ---- A: 主结果 (从已有lookup) ----
main_jobs = [
    # (csv, fname, desc)
    ('ISCX_VPN_lookup_table.csv',       'ISCX_VPN_12f'),
    ('CTU-13_lookup_table.csv',         'CTU-13_12f'),
    ('MAWI_40_svc_lookup_table.csv',    'MAWI_3f_7.5M'),
    ('MAWI_MAWI_noIP_lookup_table.csv', 'MAWI_8f_500K'),
    ('USTC_USTC_svc_lookup_table.csv',  'USTC_3f'),
    ('CIC-IDS-2017_lookup_table.csv',   'CIC-IDS-2017_13f'),
    ('NSL_disc8_lookup_table.csv',      'NSL-KDD_8f'),
    ('UNSW_disc7_lookup_table.csv',     'UNSW-NB15_7f'),
]
for csv_name, fname in main_jobs:
    p = LUT_DIR / csv_name
    if p.exists():
        lut = pd.read_csv(p)
        if 'count' in lut.columns: cc = 'count'
        else: cc = lut.columns[1]
        lut[cc] = pd.to_numeric(lut[cc], errors='coerce').fillna(0).astype('int64')
        lut = lut[lut[cc] > 0]
        cnt = Counter(dict(zip(lut[lut.columns[0]], lut[cc])))
        t = lut[cc].sum()
        n, total, top80, cov5, cov20 = plot_one(cnt, fname, t)
        results_log.append((fname, total, n, top80, cov5, cov20))
        print(f'  {fname}: {total:,} pkts, {n:,} uniq')

# ---- B: MAWI字段对比 (5 pcap x 500K采样) ----
print("\n[MAWI field tests]")
MAWI_FIELDS = [
    ('MAWI_3f_svc',    ['ip_proto','tcp_dport','udp_dport']),
    ('MAWI_4f_svc4',   ['ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('MAWI_6f_svc5',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','udp_sport','udp_dport']),
    ('MAWI_6f_tcp5',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window']),
    ('MAWI_8f_l4full', ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
]
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
pcaps = sorted(SPLIT.glob("*.pcap"))[:5]
mawi_cnts = {fname: Counter() for fname, _ in MAWI_FIELDS}
for i, pp in enumerate(pcaps):
    pkts = sniff(offline=str(pp), count=500000, store=True, quiet=True)
    for fname, fields in MAWI_FIELDS:
        cnt = mawi_cnts[fname]
        for p in pkts:
            parts = []
            for f in fields:
                try:
                    if f == 'ip_proto': parts.append(str(p[IP].proto if IP in p else 0))
                    elif f == 'ip_ttl': parts.append(str(p[IP].ttl if IP in p else 0))
                    elif f == 'tcp_sport': parts.append(str(p[TCP].sport if TCP in p else 0))
                    elif f == 'tcp_dport': parts.append(str(p[TCP].dport if TCP in p else 0))
                    elif f == 'tcp_flags':
                        v=0
                        if TCP in p:
                            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                                if ch in str(p[TCP].flags): v|=1<<bit
                        parts.append(str(v))
                    elif f == 'tcp_window': parts.append(str(p[TCP].window if TCP in p else 0))
                    elif f == 'udp_sport': parts.append(str(p[UDP].sport if UDP in p else 0))
                    elif f == 'udp_dport': parts.append(str(p[UDP].dport if UDP in p else 0))
                    else: parts.append('0')
                except: parts.append('0')
            cnt['|'.join(parts)] += 1
    print(f'  [{i+1}/5]')

for fname, fields in MAWI_FIELDS:
    bits = sum(BITS_MAP[f] for f in fields)
    t = 2500000  # 5 x 500K
    n, total, top80, cov5, cov20 = plot_one(mawi_cnts[fname], fname, t)
    results_log.append((fname, total, n, top80, cov5, cov20))
    print(f'  {fname}: {n:,} uniq, {bits}b')

# ---- C: USTC字段对比 ----
print("\n[USTC field tests]")
df = pd.read_csv(BASE/"USTC"/"ustc_protocol_headers.csv")
USTC_FIELDS = [
    ('USTC_3f_svc',    ['ip_proto','tcp_dport','udp_dport']),
    ('USTC_4f_svc4',   ['ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('USTC_4f_flag',   ['ip_proto','tcp_dport','udp_dport','tcp_flags']),
    ('USTC_5f_ttlfl',  ['ip_proto','ip_ttl','tcp_dport','udp_dport','tcp_flags']),
    ('USTC_5f_win',    ['ip_proto','ip_ttl','tcp_dport','udp_dport','tcp_window']),
    ('USTC_6f_tcp6',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window']),
    ('USTC_8f_l4full', ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
]
ustc_cnts = {fname: Counter() for fname, _ in USTC_FIELDS}
for _, row in df.iterrows():
    for fname, fields in USTC_FIELDS:
        parts = [str(row[f]) if f in row.index else '0' for f in fields]
        ustc_cnts[fname]['|'.join(parts)] += 1
t_ustc = 110000
for fname, fields in USTC_FIELDS:
    bits = sum(BITS_MAP.get(f,16) for f in fields)
    n, total, top80, cov5, cov20 = plot_one(ustc_cnts[fname], fname, t_ustc)
    results_log.append((fname, total, n, top80, cov5, cov20))
    print(f'  {fname}: {n:,} uniq, {bits}b')

# ---- D: NSL/UNSW字段对比 (已有lookup) ----
print("\n[NSL/UNSW field tests]")
flow_jobs = [
    ('NSL_cat3_lookup_table.csv',  'NSL-KDD_3f'),
    ('NSL_disc8_lookup_table.csv', 'NSL-KDD_8f'),
    ('NSL_svc5_lookup_table.csv',  'NSL-KDD_5f'),
    ('UNSW_cat3_lookup_table.csv', 'UNSW-NB15_3f'),
    ('UNSW_disc7_lookup_table.csv','UNSW-NB15_7f'),
    ('UNSW_svc6_lookup_table.csv', 'UNSW-NB15_6f'),
]
for csv_name, fname in flow_jobs:
    p = LUT_DIR / csv_name
    if p.exists():
        lut = pd.read_csv(p)
        if 'count' in lut.columns: cc = 'count'
        else: cc = lut.columns[1]
        lut[cc] = pd.to_numeric(lut[cc], errors='coerce').fillna(0).astype('int64')
        lut = lut[lut[cc] > 0]
        cnt = Counter(dict(zip(lut[lut.columns[0]], lut[cc])))
        t = lut[cc].sum()
        n, total, top80, cov5, cov20 = plot_one(cnt, fname, t)
        results_log.append((fname, total, n, top80, cov5, cov20))
        print(f'  {fname}: {total:,} pkts, {n:,} uniq')

# ---- E: MAWI全量 (2 pcap) ----
print("\n[MAWI full 2 pcaps]")
MAWI_FULL_FIELDS = ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']
pcaps_full = sorted(SPLIT.glob("*.pcap"))[:2]
cnt_full = Counter()
total_full = 0
for i, pp in enumerate(pcaps_full):
    pkts = sniff(offline=str(pp), store=True, quiet=True)
    total_full += len(pkts)
    for p in pkts:
        parts = []
        parts.append(str(p[IP].proto if IP in p else 0))
        parts.append(str(p[IP].ttl if IP in p else 0))
        if TCP in p:
            parts.append(str(p[TCP].sport)); parts.append(str(p[TCP].dport))
            fl=0
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                if ch in str(p[TCP].flags): fl|=1<<bit
            parts.append(str(fl)); parts.append(str(p[TCP].window))
        else: parts.extend(['0','0','0','0'])
        if UDP in p:
            parts.append(str(p[UDP].sport)); parts.append(str(p[UDP].dport))
        else: parts.extend(['0','0'])
        cnt_full['|'.join(parts)] += 1
    print(f'  [{i+1}/2] {len(pkts):,} pkts')
n, total, top80, cov5, cov20 = plot_one(cnt_full, 'MAWI_8f_full', total_full)
results_log.append(('MAWI_8f_full', total_full, n, top80, cov5, cov20))
print(f'  MAWI_8f_full: {total_full:,} pkts, {n:,} uniq')

# ---- 保存结果日志 ----
pd.DataFrame(results_log, columns=['image','total','unique','top80','cov5','cov20'])\
  .to_csv(OUT/'_results_summary.csv', index=False)

# ---- 写文档 ----
with open(OUT/'_README.md', 'w', encoding='utf-8') as f:
    f.write("""# Pareto Analysis Documentation

## Method
Each dataset's feature vectors are converted to a combined key string.
Frequency of each unique key is counted, sorted descending.
Pareto distribution is confirmed when a small fraction of top patterns covers >80% of traffic.

## Plot Format
- Left: Cumulative coverage vs number of patterns (sorted by frequency)
- Right: Frequency-Rank distribution (log-log)
- Text box (bottom-right): key statistics

## Per-Image Details

### Main Results (best feature set per dataset)
| Image | Dataset | Features | Bits | Data Scale |
|-------|---------|----------|------|------------|
| ISCX_VPN_12f | ISCX VPN-nonVPN | eth_dst/src, ip_src/dst, ip_proto, ip_ttl, tcp_sport/dport, tcp_flags, tcp_window, udp_sport/dport | 320 | 593,836 pkts (full) |
| CTU-13_12f | CTU-13 | same 12 fields | 320 | 30,000 pkts (sampled) |
| MAWI_3f_7.5M | MAWI (15 pcaps) | ip_proto, tcp_dport, udp_dport | 40 | 7,500,000 pkts (sampled) |
| MAWI_8f_500K | MAWI (100 pcaps) | ip_proto, ip_ttl, tcp_sport/dport, tcp_flags, tcp_window, udp_sport/dport | 88 | 500,000 pkts (sampled) |
| MAWI_8f_full | MAWI (2 pcaps) | same 8 fields as above | 104 | 3,553,292 pkts (FULL) |
| USTC_3f | USTC-TFC2016 | ip_proto, tcp_dport, udp_dport | 40 | 110,000 pkts (sampled) |
| CIC-IDS-2017_13f | CIC-IDS 2017 | Destination Port, Protocol, Fwd/Bwd Header Len, 6 Flag Counts, Flow Duration, Flow Bytes/s, Flow Pkts/s, Avg Pkt Size | - | 3,461,718 flows (full) |
| NSL-KDD_8f | NSL-KDD | protocol_type, service, flag, land, logged_in, is_host_login, is_guest_login, num_outbound_cmds | - | 148,517 flows (full) |
| UNSW-NB15_7f | UNSW-NB15 | proto, service, state, sttl, dttl, swin, dwin | - | 257,673 flows (full) |

### MAWI Field Comparison (same 2.5M pkts)
| Image | Fields | Bits |
|-------|--------|------|
| MAWI_3f_svc | ip_proto, tcp_dport, udp_dport | 40 |
| MAWI_4f_svc4 | +ip_ttl | 48 |
| MAWI_6f_svc5 | +tcp_sport, udp_sport | 80 |
| MAWI_6f_tcp5 | ip_proto, ip_ttl, tcp_sport/dport, tcp_flags, tcp_window | 72 |
| MAWI_8f_l4full | +udp_sport/dport | 104 |

### USTC Field Comparison (same 110K pkts)
| Image | Fields | Bits |
|-------|--------|------|
| USTC_3f_svc | ip_proto, tcp_dport, udp_dport | 40 |
| USTC_4f_svc4 | +ip_ttl | 48 |
| USTC_4f_flag | +tcp_flags | 48 |
| USTC_5f_ttlfl | +ip_ttl, tcp_flags | 56 |
| USTC_5f_win | +ip_ttl, tcp_window | 64 |
| USTC_6f_tcp6 | ip_proto, ip_ttl, tcp_sport/dport, tcp_flags, tcp_window | 72 |
| USTC_8f_l4full | +udp_sport/dport | 104 |

### NSL/UNSW Field Comparison (full datasets)
| Image | Fields |
|-------|--------|
| NSL-KDD_3f | protocol_type, service, flag |
| NSL-KDD_8f | +land, logged_in, is_host_login, is_guest_login, num_outbound_cmds |
| NSL-KDD_5f | protocol_type, service, flag, same_srv_rate, dst_host_same_srv_rate |
| UNSW-NB15_3f | proto, service, state |
| UNSW-NB15_7f | +sttl, dttl, swin, dwin |
| UNSW-NB15_6f | proto, service, state, ct_srv_src, ct_srv_dst, ct_dst_ltm |

## Protocol Field Bit Widths
```
eth_dst/src: 48, eth_type: 16
ip_src/dst: 32, ip_proto: 8, ip_ttl: 8
tcp_sport/dport: 16, tcp_flags: 8, tcp_window: 16
udp_sport/dport: 16
```
""")

print(f"\nAll done. Plots: {OUT}/  Docs: {OUT}/_README.md")

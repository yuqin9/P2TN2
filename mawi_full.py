"""
MAWI: 前40个split pcap, 每文件50万包, 分批建查找表
吞吐: 40文件 × 50万 = 2000万包
"""
import pandas as pd, numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

BASE = Path(r"F:\自己的论文\网络数据集")
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
OUT = BASE/"pareto_results"
OUT.mkdir(exist_ok=True)

MAX_PKTS = 500000   # 每文件50万包
N_FILES = 15

FIELD_BITS = {
    'ip_proto':8, 'ip_ttl':8,
    'tcp_sport':16, 'tcp_dport':16, 'tcp_flags':8, 'tcp_window':16,
    'udp_sport':16, 'udp_dport':16,
    'ip_src':32, 'ip_dst':32,
}

def pkt_to_key(pkt, fields):
    """一个包 → bit串key"""
    bits = []
    for f in fields:
        n = FIELD_BITS[f]
        try:
            if f in ('ip_src','ip_dst'):
                if IP in pkt:
                    ip = pkt[IP]
                    val = ip.src if f == 'ip_src' else ip.dst
                    octets = [int(x) for x in val.split('.')]
                    v = (octets[0]<<24)|(octets[1]<<16)|(octets[2]<<8)|octets[3]
                else:
                    v = 0
            elif f == 'ip_proto':
                v = pkt[IP].proto if IP in pkt else 0
            elif f == 'ip_ttl':
                v = pkt[IP].ttl if IP in pkt else 0
            elif f == 'tcp_sport':
                v = pkt[TCP].sport if TCP in pkt else 0
            elif f == 'tcp_dport':
                v = pkt[TCP].dport if TCP in pkt else 0
            elif f == 'tcp_flags':
                if TCP in pkt:
                    fl = pkt[TCP].flags
                    v = 0
                    for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                        if ch in str(fl): v |= 1<<bit
                else: v = 0
            elif f == 'tcp_window':
                v = pkt[TCP].window if TCP in pkt else 0
            elif f == 'udp_sport':
                v = pkt[UDP].sport if UDP in pkt else 0
            elif f == 'udp_dport':
                v = pkt[UDP].dport if UDP in pkt else 0
            else:
                v = 0
        except:
            v = 0
        bits.append(format(int(v), f'0{n}b'))
    return ''.join(bits)


def pareto_plot(counter, name, out_dir):
    """从Counter生成帕累托图"""
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    ranks = np.arange(1, len(items)+1)
    counts = np.array([c for _, c in items])
    total = counts.sum()
    cumsum = counts.cumsum()
    coverage = cumsum / total * 100

    top80_idx = (coverage >= 80).argmax()
    top80_n = ranks[top80_idx]

    n_unique = len(items)
    pcts = [1,5,10,20,50]
    print(f"\n  {'='*50}")
    print(f"  {name}")
    print(f"  {'='*50}")
    print(f"  Packets: {total:,}  Unique: {n_unique:,}")
    print(f"  To 80% coverage: {top80_n:,} patterns ({top80_n/n_unique*100:.1f}%)")
    for p in pcts:
        idx = max(1, int(n_unique*p/100))
        print(f"  Top {p:2d}% ({idx:,}) cover: {coverage[idx-1]:.1f}%")

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    ax = axes[0]
    ax.plot(ranks, coverage, 'b-', linewidth=1.5)
    ax.axhline(y=80, color='r', linestyle='--', alpha=0.5, label='80%')
    ax.axvline(x=top80_n, color='g', linestyle='--', alpha=0.5, label=f'{top80_n:,} patterns')
    ax.set_xlabel('Number of Feature Patterns (sorted by frequency)')
    ax.set_ylabel('Cumulative Coverage (%)')
    ax.set_title(f'{name}\nPareto Distribution')
    ax.legend(fontsize=8); ax.grid(True, alpha=0.3)

    ax = axes[1]
    ax.loglog(ranks, counts, 'b.', markersize=1, alpha=0.5)
    ax.set_xlabel('Pattern Rank (log)')
    ax.set_ylabel('Frequency (log)')
    ax.set_title(f'{name}\nFrequency-Rank')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    p = out_dir/f'{name}_pareto.png'
    plt.savefig(p, dpi=150, bbox_inches='tight')
    plt.close()
    return coverage, top80_n


# ===== 主流程 =====
feature_sets = [
    ('MAWI_40_svc',    ['ip_proto','tcp_dport','udp_dport']),
    ('MAWI_40_noIP',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
    ('MAWI_40_stable', ['ip_src','ip_dst','ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
]

counters = {name: Counter() for name, _ in feature_sets}

pcaps = sorted(SPLIT.glob("*.pcap"))[:N_FILES]
print(f"MAWI: {N_FILES} files, {MAX_PKTS:,} pkts/file, max {N_FILES*MAX_PKTS:,} total")
t0 = datetime.now()

for i, pp in enumerate(pcaps):
    try:
        pkts = sniff(offline=str(pp), count=MAX_PKTS, store=True, quiet=True)
    except:
        print(f"  SKIP {pp.name}")
        continue

    for name, fields in feature_sets:
        for p in pkts:
            key = pkt_to_key(p, fields)
            counters[name][key] += 1

    if (i+1) % 5 == 0:
        t = (datetime.now()-t0).total_seconds()
        total = sum(len(c) for c in counters.values())
        print(f"  [{i+1}/{N_FILES}] {(i+1)*MAX_PKTS:,} pkts, {total:,} unique keys, {t:.0f}s")

elapsed = (datetime.now()-t0).total_seconds()
print(f"\nDone: {N_FILES*MAX_PKTS:,} pkts processed in {elapsed:.0f}s")

# 保存查找表 + 画图
for name, fields in feature_sets:
    cnt = counters[name]
    lut = pd.DataFrame(sorted(cnt.items(), key=lambda x: x[1], reverse=True),
                       columns=['feature_key','count'])
    lut.to_csv(OUT/f'{name}_lookup_table.csv', index=False)
    print(f"\n{name}: {len(lut):,} unique, {lut['count'].sum():,} total")
    pareto_plot(cnt, name, OUT)
    # 保存bits
    print(f"  Saved: {OUT}/{name}_lookup_table.csv, {OUT}/{name}_pareto.png")

print(f"\nAll results: {OUT}")

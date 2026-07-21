"""IOT23: 从已有header CSV重跑帕累托"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,
                     'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
OUT = BASE / "final_plots"
LUT = BASE / "pareto_results"
HEADER = BASE / "IOT23" / "iot23_protocol_headers.csv"

FIELD_BITS = {
    'eth_dst':48,'eth_src':48,'eth_type':16,
    'ip_src':32,'ip_dst':32,'ip_proto':8,'ip_ttl':8,
    'tcp_sport':16,'tcp_dport':16,'tcp_flags':8,'tcp_window':16,
    'udp_sport':16,'udp_dport':16,
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
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                if ch in v: flags|=1<<bit
            return format(flags,f'0{n}b')
        return format(int(float(v)),f'0{n}b')[-n:]
    except: return '0'*n

def plot_one(counter, fname, total):
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
    plt.savefig(OUT/f'{fname}.png', dpi=150, bbox_inches='tight')
    plt.close()
    return total, n, top80, cov5, cov20

# ===== 主流程 =====
print("Loading header CSV...")
df = pd.read_csv(HEADER)
total = len(df)
print(f"  {total:,} packets")

feature_sets = [
    ('IOT23_12f',       ['eth_dst','eth_src','eth_type','ip_src','ip_dst','ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport'], 320),
    ('IOT23_3f_svc',    ['ip_proto','tcp_dport','udp_dport'], 40),
    ('IOT23_5f_win',    ['ip_proto','ip_ttl','tcp_dport','udp_dport','tcp_window'], 64),
    ('IOT23_8f_l4full', ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport'], 104),
    ('IOT23_10f_noMAC', ['ip_src','ip_dst','ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport'], 248),
]

results = []
for fname, feats, bits in feature_sets:
    cnt = Counter()
    for _, row in df.iterrows():
        parts = []
        for f in feats:
            n = FIELD_BITS.get(f, 8)
            parts.append(val_to_bits(row[f], n))
        cnt[''.join(parts)] += 1

    items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
    lut = pd.DataFrame(items, columns=['feature_key','count'])
    lut.to_csv(LUT/f'{fname}_lookup_table.csv', index=False)

    t, n, top80, cov5, cov20 = plot_one(cnt, fname, total)
    results.append((fname, total, n, top80, cov5, cov20))
    print(f'  {fname}: {n:,} uniq, 80% at {top80:,} ({top80/n*100:.1f}%), Top20%={cov20:.1f}%')

df_r = pd.DataFrame(results, columns=['image','total','unique','top80','cov5_pct','cov20_pct'])
df_r.to_csv(OUT/'_results_iot23.csv', index=False)
print(f"\nDone: {OUT}/")

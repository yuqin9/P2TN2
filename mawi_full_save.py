"""MAWI 2 pcap全量, 保存lookup table + 画图"""
import numpy as np, pandas as pd
from pathlib import Path
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,
                     'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
OUT = BASE/"final_plots"

pcaps = sorted(SPLIT.glob("*.pcap"))[:2]
cnt = Counter()
total = 0

for i, pp in enumerate(pcaps):
    pkts = sniff(offline=str(pp), store=True, quiet=True)
    total += len(pkts)
    for p in pkts:
        parts = [str(p[IP].proto if IP in p else 0),
                 str(p[IP].ttl if IP in p else 0)]
        if TCP in p:
            parts += [str(p[TCP].sport), str(p[TCP].dport)]
            fl=0
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                if ch in str(p[TCP].flags): fl|=1<<bit
            parts += [str(fl), str(p[TCP].window)]
        else: parts += ['0','0','0','0']
        if UDP in p:
            parts += [str(p[UDP].sport), str(p[UDP].dport)]
        else: parts += ['0','0']
        cnt['|'.join(parts)] += 1
    print(f'  [{i+1}/2] {pp.name}: {len(pkts):,} pkts')

# 保存lookup
items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
lut = pd.DataFrame(items, columns=['feature_key','count'])
lut.to_csv(BASE/'pareto_results'/'MAWI_full_2pcaps_lookup_table.csv', index=False)

counts = np.array([c for _, c in items])
n = len(counts); cumsum = counts.cumsum(); cov = cumsum/total*100
top80 = np.arange(1,n+1)[(cov>=80).argmax()]
cov5 = cov[min(int(n*0.05),n-1)]; cov20 = cov[min(int(n*0.2),n-1)]
print(f'Total: {total:,}  Unique: {n:,}  80%: {top80}  Top20%: {cov20:.1f}%')

# 画图
ranks = np.arange(1, n+1)
step = max(1, n//5000)
ridx = np.arange(0, n, step)
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
plt.savefig(OUT/'MAWI_8f_full.png', dpi=150, bbox_inches='tight')
plt.close()
print(f'Saved -> {OUT}/MAWI_8f_full.png')

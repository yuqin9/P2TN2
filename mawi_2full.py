"""MAWI: 2个split pcap全量, l4full 8特征"""
import numpy as np
from pathlib import Path
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,'axes.titlesize':13,
                     'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
OUT = BASE/"final_plots"

pcaps = sorted(SPLIT.glob("*.pcap"))[:2]
cnt = Counter()
total = 0

for i, pp in enumerate(pcaps):
    pkts = sniff(offline=str(pp), store=True, quiet=True)  # 不限量
    total += len(pkts)
    for p in pkts:
        parts = []
        # ip_proto
        parts.append(str(p[IP].proto if IP in p else 0))
        # ip_ttl
        parts.append(str(p[IP].ttl if IP in p else 0))
        # tcp_sport, tcp_dport, tcp_flags, tcp_window
        if TCP in p:
            parts.append(str(p[TCP].sport)); parts.append(str(p[TCP].dport))
            fl=0
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                if ch in str(p[TCP].flags): fl|=1<<bit
            parts.append(str(fl))
            parts.append(str(p[TCP].window))
        else:
            parts.extend(['0','0','0','0'])
        # udp_sport, udp_dport
        if UDP in p:
            parts.append(str(p[UDP].sport)); parts.append(str(p[UDP].dport))
        else:
            parts.extend(['0','0'])
        cnt['|'.join(parts)] += 1
    print(f'  [{i+1}/2] {pp.name}: {len(pkts):,} pkts, {len(cnt):,} unique')

items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
counts = np.array([c for _, c in items])
n = len(counts); cumsum = counts.cumsum(); cov = cumsum/total*100
ranks = np.arange(1, n+1)
top80 = ranks[(cov>=80).argmax()]
cov5 = cov[min(int(n*0.05), n-1)]; cov20 = cov[min(int(n*0.2), n-1)]

print(f'\nTotal: {total:,}  Unique: {n:,}')
print(f'80% at: {top80:,} ({top80/n*100:.1f}%)')
print(f'Top 5%: {cov5:.1f}%  Top 20%: {cov20:.1f}%')

fig, axes = plt.subplots(1, 2, figsize=(15, 4.5))
ax = axes[0]
ax.plot(ranks, cov, 'b-', linewidth=1.8, alpha=0.85)
ax.set_xlabel('Number of Feature Patterns'); ax.set_ylabel('Cumulative Coverage (%)')
ax.set_title(f'MAWI Full (8 fields, 104 bits) [{total:,} pkts, 2 pcaps]', fontsize=11)
ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0,105)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1000:.0f}K' if x<1e6 else f'{x/1e6:.1f}M'))
txt = f'Total: {total:,}\nUnique: {n:,}\n80%: {top80:,} ({top80/n*100:.1f}%)\nTop5%: {cov5:.1f}%  Top20%: {cov20:.1f}%'
ax.text(0.98,0.02,txt,transform=ax.transAxes,fontsize=9,va='bottom',ha='right',
        bbox=dict(boxstyle='round',facecolor='white',alpha=0.85,edgecolor='gray'))
ax = axes[1]
ax.loglog(ranks, counts, 'b.', markersize=1.5, alpha=0.3)
ax.set_xlabel('Pattern Rank (log)'); ax.set_ylabel('Frequency (log)')
ax.set_title('MAWI Full', fontsize=11); ax.grid(True, alpha=0.25)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1000:.0f}K' if x<1e6 else f'{x/1e6:.1f}M'))
ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y,p: f'{y/1000:.0f}K' if y<1e6 else f'{y/1e6:.1f}M'))
plt.subplots_adjust(wspace=0.25)
plt.savefig(OUT/'MAWI_full_2pcaps.png', dpi=150, bbox_inches='tight')
plt.close()
print(f'Saved -> {OUT}/MAWI_full_2pcaps.png')

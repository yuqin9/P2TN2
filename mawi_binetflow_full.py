"""
MAWI 全量: 20个binetflow文件, ~10M流记录
用最接近l4full的字段: Protocol, SrcPort, DstPort, TCPflags, InitWin
"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13, 'axes.labelsize':14, 'axes.titlesize':13,
                     'xtick.labelsize':11, 'ytick.labelsize':11, 'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
BIN = BASE/"MAWI"/"202602011400.pcap"/"202602011400_binetflow"
OUT = BASE/"final_plots"

files = sorted(BIN.glob("*.csv"))
print(f"MAWI binetflow: {len(files)} files")

cnt = Counter()
total_flows = 0

for i, f in enumerate(files):
    df = pd.read_csv(f)
    total_flows += len(df)

    for _, row in df.iterrows():
        # Protocol (8bit)
        proto = str(int(row['Protocol'])) if pd.notna(row['Protocol']) else '0'

        # Src Port + Dst Port (16bit each)
        sport = str(int(row['Src Port'])) if pd.notna(row['Src Port']) else '0'
        dport = str(int(row['Dst Port'])) if pd.notna(row['Dst Port']) else '0'

        # TCP flags derived from flag counts (>0 means flag present)
        flags = 0
        for bit, col in [(0,'FIN'),(1,'SYN'),(2,'RST'),(3,'PSH'),(4,'ACK'),(5,'URG')]:
            fcol = f'{col} Flag Cnt'
            if fcol in row.index and pd.notna(row[fcol]) and row[fcol] > 0:
                flags |= (1 << bit)
        flags_str = str(flags)

        # Init Fwd Win Byts (16bit, as tcp_window proxy)
        win = str(int(row['Init Fwd Win Byts'])) if pd.notna(row['Init Fwd Win Byts']) else '0'

        key = f'{proto}|{sport}|{dport}|{flags_str}|{win}'
        cnt[key] += 1

    print(f'  [{i+1}/20] {f.name}: {len(df):,} flows, {len(cnt):,} unique')

print(f'\nTotal: {total_flows:,} flows')

# Build lookup table
items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
counts = np.array([c for _, c in items])
total = counts.sum(); n = len(counts)
cumsum = counts.cumsum(); coverage = cumsum/total*100
ranks = np.arange(1, n+1)
top80 = ranks[(coverage>=80).argmax()]
cov1 = coverage[min(int(n*0.01), n-1)]
cov5 = coverage[min(int(n*0.05), n-1)]
cov20 = coverage[min(int(n*0.2), n-1)]

print(f'Unique: {n:,}')
print(f'80% at: {top80:,} ({top80/n*100:.1f}%)')
print(f'Top 5%: {cov5:.1f}%  Top 20%: {cov20:.1f}%')

# Plot
fig, axes = plt.subplots(1, 2, figsize=(15, 4.5))

ax = axes[0]
ax.plot(ranks, coverage, 'b-', linewidth=1.8, alpha=0.85)
ax.set_xlabel('Number of Feature Patterns'); ax.set_ylabel('Cumulative Coverage (%)')
ax.set_title(f'MAWI Full (5 fields, ~64 bits) [{total:,} binetflow records]', fontsize=11)
ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0, 105)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1e6:.1f}M' if x>=1e6 else f'{x/1000:.0f}K'))

textstr = (f'Total: {total:,}\nUnique: {n:,}\n'
           f'80% at: {top80:,} ({top80/n*100:.1f}%)\n'
           f'Top 5%: {cov5:.1f}%  Top 20%: {cov20:.1f}%')
ax.text(0.98, 0.02, textstr, transform=ax.transAxes, fontsize=9,
        va='bottom', ha='right', bbox=dict(boxstyle='round', facecolor='white', alpha=0.85, edgecolor='gray'))

ax = axes[1]
ax.loglog(ranks, counts, 'b.', markersize=1.5, alpha=0.3)
ax.set_xlabel('Pattern Rank (log)'); ax.set_ylabel('Frequency (log)')
ax.set_title('MAWI Full', fontsize=11); ax.grid(True, alpha=0.25)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x,p: f'{x/1e6:.1f}M' if x>=1e6 else f'{x/1000:.0f}K'))
ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y,p: f'{y/1e6:.1f}M' if y>=1e6 else f'{y/1000:.0f}K'))

plt.subplots_adjust(wspace=0.25)
plt.savefig(OUT/'MAWI_full_binetflow.png', dpi=150, bbox_inches='tight')
plt.close()

# Save lookup table
lut = pd.DataFrame(items, columns=['feature_key','count'])
lut.to_csv(BASE/'pareto_results'/'MAWI_full_binetflow_lookup_table.csv', index=False)

print(f'\nDone -> {OUT}/MAWI_full_binetflow.png')

"""画 10 万包试验图 (样式与 canonical 完全一致), 输出到 fig_backup, 不碰 canonical 图"""
import pandas as pd, numpy as np
from pathlib import Path
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

BASE = Path(r'F:\自己的论文\网络数据集')
LUT = BASE/'v2_rerun'/'pareto_results_v2'
OUT = BASE/'CTU-13'/'fig_backup'
plt.rcParams.update({'font.size':8,'axes.labelsize':7,'xtick.labelsize':6,'ytick.labelsize':6,'figure.dpi':200})
XLABEL='Patterns'; YLABEL='Cum. Coverage (%)'; FW, FH = 2.4, 2.0

def fmt(x, p):
    if x==0: return '0'
    if x<1000: return f'{x:.0f}'
    if x<1e6: return f'{x/1000:.0f}K'
    return f'{x/1e6:.1f}M'

lut = pd.read_csv(LUT/'CTU-13_12f_lookup_table_100K.csv')
counts = lut['count'].values; n = len(counts)
total = counts.sum()
cumsum = counts.cumsum(); cov = cumsum/total*100; ranks = np.arange(1, n+1)
n80 = ranks[(cov>=80).argmax()]; n90 = ranks[(cov>=90).argmax()]
step = max(1, n//3000); ridx = np.arange(0, n, step)
if ridx[-1] != n-1: ridx = np.append(ridx, n-1)

fig, axes = plt.subplots(1, 2, figsize=(FW, FH))
ax = axes[0]; ax.plot(ranks[ridx], cov[ridx], 'b.', ms=1.5, alpha=0.5)
ax.set_xlabel(XLABEL, fontsize=8, fontweight='bold')
ax.set_ylabel(YLABEL, fontsize=8, fontweight='bold')
ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0, 105)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt)); ax.tick_params(labelsize=6)
ax.text(0.95, 0.12, f'80%:{n80:,}\n90%:{n90:,}', transform=ax.transAxes, fontsize=5, va='top', ha='right',
        bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.8, edgecolor='gray', lw=0.4))
ax = axes[1]; ax.loglog(ranks[ridx], counts[ridx], 'b.', ms=1.5, alpha=0.4)
ax.set_xlabel('Rank', fontsize=8, fontweight='bold')
ax.set_ylabel('Freq', fontsize=8, fontweight='bold')
ax.grid(True, alpha=0.25)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt))
ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt))
ax.tick_params(labelsize=6)
ax.yaxis.tick_right(); ax.yaxis.set_label_position('right')
plt.subplots_adjust(wspace=0.40, bottom=0.18, top=0.92, left=0.15, right=0.95)
fig.savefig(OUT/'CTU-13_12f_100K_trial.png', dpi=200, bbox_inches='tight')
plt.close(fig)
print('trial figure saved:', OUT/'CTU-13_12f_100K_trial.png')

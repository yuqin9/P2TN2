"""
统一图例重新生成所有帕累托图
"""
import pandas as pd, numpy as np
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# 全局样式
plt.rcParams.update({
    'font.size': 12, 'axes.titlesize': 13, 'axes.labelsize': 12,
    'legend.fontsize': 10, 'xtick.labelsize': 10, 'ytick.labelsize': 10,
    'figure.dpi': 150, 'savefig.dpi': 150, 'savefig.bbox': 'tight',
})

BASE = Path(r"F:\自己的论文\网络数据集")
OUT = BASE / "final_plots"
OUT.mkdir(exist_ok=True)
LUT_DIR = BASE / "pareto_results"

# 每个数据集一个配置: (csv文件名, 标题简称, 字段数, bits)
datasets = [
    # PCAP协议头部
    ('ISCX_VPN_lookup_table.csv',       'ISCX VPN',         12, 320),
    ('CTU-13_lookup_table.csv',         'CTU-13',           12, 320),
    ('MAWI_40_svc_lookup_table.csv',    'MAWI (7.5M pkts)',  3,  40),
    ('MAWI_MAWI_noIP_lookup_table.csv', 'MAWI (500K pkts)',  8,  88),
    ('USTC_USTC_svc_lookup_table.csv',  'USTC',              3,  40),
    # 流特征
    ('CIC-IDS-2017_lookup_table.csv',   'CIC-IDS 2017',     13,  '-'),
    ('NSL_disc8_lookup_table.csv',      'NSL-KDD',           8,  '-'),
    ('UNSW_disc7_lookup_table.csv',     'UNSW-NB15',         7,  '-'),
]

def generate_plot(csv_name, title, n_fields, bits):
    path = LUT_DIR / csv_name
    if not path.exists():
        print(f"  SKIP: {csv_name} not found")
        return

    lut = pd.read_csv(path)
    if 'feature_key' in lut.columns:
        counts = lut['count'].values
    elif 'key' in lut.columns:
        counts = lut['count'].values
    else:
        print(f"  SKIP: {csv_name} - unknown format")
        return

    total = counts.sum()
    n_unique = len(counts)
    cumsum = counts.cumsum()
    coverage = cumsum / total * 100
    ranks = np.arange(1, n_unique + 1)

    top80_idx = (coverage >= 80).argmax()
    top80_n = ranks[top80_idx]
    top80_pct = top80_n / n_unique * 100

    # 关键指标
    cov_1  = coverage[min(int(n_unique*0.01), n_unique-1)]
    cov_5  = coverage[min(int(n_unique*0.05), n_unique-1)]
    cov_10 = coverage[min(int(n_unique*0.10), n_unique-1)]
    cov_20 = coverage[min(int(n_unique*0.20), n_unique-1)]

    fig, axes = plt.subplots(1, 2, figsize=(16, 5.5))

    # === 图1: 累计覆盖率曲线 ===
    ax = axes[0]
    ax.plot(ranks, coverage, 'b-', linewidth=1.8, alpha=0.85)
    ax.set_xlabel('Number of Feature Patterns (sorted by frequency)')
    ax.set_ylabel('Cumulative Coverage (%)')
    bits_str = f', {bits} bits' if bits != '-' else ''
    ax.set_title(f'{title} ({n_fields} fields{bits_str})')
    ax.grid(True, alpha=0.25)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 105)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, p: f'{x:,.0f}' if x < 10000 else f'{x/1000:.0f}K' if x < 1e6 else f'{x/1e6:.1f}M'))

    # 左上角: 关键指标
    textstr = (f'Total: {total:,}   Unique: {n_unique:,}\n'
               f'80% coverage: {top80_n:,} patterns ({top80_pct:.1f}%)\n'
               f'Top 1%: {cov_1:.1f}%   Top 5%: {cov_5:.1f}%   Top 20%: {cov_20:.1f}%')
    props = dict(boxstyle='round,pad=0.4', facecolor='white', alpha=0.85, edgecolor='gray')
    ax.text(0.98, 0.02, textstr, transform=ax.transAxes, fontsize=7.5,
            verticalalignment='bottom', horizontalalignment='right', bbox=props)

    # === 图2: log-log频率-排名分布 ===
    ax = axes[1]
    ax.loglog(ranks, counts, 'b.', markersize=1.5, alpha=0.4)
    ax.set_xlabel('Pattern Rank (log scale)')
    ax.set_ylabel('Frequency (log scale)')
    ax.set_title(f'{title}')
    ax.grid(True, alpha=0.25)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, p: f'{x:,.0f}' if x < 10000 else f'{x/1000:.0f}K' if x < 1e6 else f'{x/1e6:.1f}M'))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda y, p: f'{y:,.0f}' if y < 10000 else f'{y/1000:.0f}K' if y < 1e6 else f'{y/1e6:.1f}M'))

    # 保存
    safe = title.replace(' ', '_').replace('(', '').replace(')', '').replace('.', '')
    fname = OUT / f'{safe}.png'
    plt.savefig(fname, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  OK: {fname}  ({total:,} pkts, {n_unique:,} uniq, 80% at {top80_n:,})')


if __name__ == '__main__':
    print('Regenerating all Pareto plots with unified style...\n')
    for csv_name, title, nf, bits in datasets:
        generate_plot(csv_name, title, nf, bits)
    print(f'\nDone → {OUT}')

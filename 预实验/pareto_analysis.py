import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

DATA_DIR = Path("./data")
OUT = Path("./output")
OUT.mkdir(exist_ok=True)

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

def pareto_plot(counter, fname, total_pkts):
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    counts = np.array([c for _, c in items])
    n = len(counts); cumsum = counts.cumsum(); cov = cumsum/total_pkts*100
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
    print(f"   {fname}: {total_pkts:,} pkts, {n:,} uniq, 80% at {top80:,}, Top20%={cov20:.1f}%")
    return n, top80, cov5, cov20

def analyze_dataset(csv_path, feature_sets):
    df = pd.read_csv(csv_path)
    total = len(df)
    results = []
    for fname, feats in feature_sets:
        cnt = Counter()
        for _, row in df.iterrows():
            key = ''.join(val_to_bits(row[f], FIELD_BITS.get(f,8)) for f in feats if f in row.index)
            cnt[key] += 1
        items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
        lut = pd.DataFrame(items, columns=['feature_key','count'])
        lut.to_csv(OUT/f'{fname}_lookup_table.csv', index=False)
        n, top80, cov5, cov20 = pareto_plot(cnt, fname, total)
        results.append({'name':fname,'total':total,'unique':n,'top80':top80,'cov5':cov5,'cov20':cov20})
    return results

if __name__ == '__main__':
    stable_fields = ['eth_dst','eth_src','ip_src','ip_dst','ip_proto','ip_ttl',
                     'tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']
    feature_sets = [
        ('ISCX_VPN_12f', stable_fields),
        ('ISCX_VPN_3f',  ['ip_proto','tcp_dport','udp_dport']),
    ]
    results = analyze_dataset(DATA_DIR/'iscx_protocol_headers.csv', feature_sets)
    pd.DataFrame(results).to_csv(OUT/'pareto_summary.csv', index=False)
    print(f"\nDone: {OUT}/")

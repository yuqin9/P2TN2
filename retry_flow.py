"""NSL-KDD + UNSW-NB15 换特征重试帕累托"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE = Path(r"F:\自己的论文\网络数据集")
OUT = BASE/"pareto_results"
OUT.mkdir(exist_ok=True)

def pareto_from_counter(counter, name):
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    ranks = np.arange(1, len(items)+1)
    counts = np.array([c for _, c in items])
    total = counts.sum()
    cumsum = counts.cumsum()
    coverage = cumsum / total * 100
    n = len(items)
    top80 = ranks[(coverage >= 80).argmax()]
    covs = {}
    for p in [1,5,10,20]:
        idx = max(1, int(n*p/100))
        covs[p] = coverage[idx-1]
    is_p = covs[20] >= 80

    print(f"  {name}: {total:,} pkts, {n:,} unique, "
          f"80% at {top80:,} ({top80/n*100:.1f}%), "
          f"Top5%={covs[5]:.1f}% Top20%={covs[20]:.1f}% "
          f"{'PARETO' if is_p else ''}")

    # Save LUT
    lut = pd.DataFrame({'key': [k for k,_ in items], 'count': counts})
    lut.to_csv(OUT/f'{name}_lookup_table.csv', index=False)

    # Plot
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    ax = axes[0]
    ax.plot(ranks, coverage, 'b-', linewidth=1.5)
    ax.axhline(y=80, color='r', linestyle='--', alpha=0.5)
    ax.axvline(x=top80, color='g', linestyle='--', alpha=0.5, label=f'{top80:,}')
    ax.set_xlabel('Number of Feature Patterns'); ax.set_ylabel('Cumulative Coverage (%)')
    ax.set_title(f'{name}'); ax.legend(fontsize=8); ax.grid(True, alpha=0.3)

    ax = axes[1]
    ax.loglog(ranks, counts, 'b.', markersize=1, alpha=0.5)
    ax.set_xlabel('Pattern Rank (log)'); ax.set_ylabel('Frequency (log)')
    ax.set_title(f'{name}'); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT/f'{name}_pareto.png', dpi=150, bbox_inches='tight')
    plt.close()
    return {'name': name, 'total': total, 'unique': n, 'top80': top80, **{f'cov{p}':v for p,v in covs.items()}, 'pareto': is_p}

def do_dataset(df, feats_list, prefix):
    results = []
    for name_suffix, feats in feats_list:
        name = f'{prefix}_{name_suffix}'
        keys = df[feats].astype(str).agg(''.join, axis=1)
        cnt = Counter(keys)
        r = pareto_from_counter(cnt, name)
        results.append(r)
    return results

# ========== NSL-KDD ==========
print("="*60)
print("NSL-KDD")
cols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins',
    'logged_in','num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells','num_access_files',
    'num_outbound_cmds','is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate','rerror_rate',
    'srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty']
t1 = pd.read_csv(BASE/"NSL_KDD-master"/"KDDTrain+.txt", header=None, names=cols)
t2 = pd.read_csv(BASE/"NSL_KDD-master"/"KDDTest+.txt", header=None, names=cols)
df = pd.concat([t1, t2], ignore_index=True)

nsl_feats = [
    ('cat3',    ['protocol_type','service','flag']),
    ('svc5',    ['protocol_type','service','flag','same_srv_rate','dst_host_same_srv_rate']),
    ('disc8',   ['protocol_type','service','flag','land','logged_in','is_host_login','is_guest_login','num_outbound_cmds']),
    ('svc7',    ['protocol_type','service','flag','dst_host_srv_count','dst_host_same_srv_rate','same_srv_rate','count']),
    ('cat5',    ['protocol_type','service','flag','land','logged_in']),
]
results = do_dataset(df, nsl_feats, 'NSL')

# ========== UNSW-NB15 ==========
print("\n" + "="*60)
print("UNSW-NB15")
t1 = pd.read_csv(BASE/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_training-set.csv")
t2 = pd.read_csv(BASE/"UNSW"/"CSV Files"/"Training and Testing Sets"/"UNSW_NB15_testing-set.csv")
df = pd.concat([t1, t2], ignore_index=True)

unsw_feats = [
    ('cat3',    ['proto','service','state']),
    ('cat5',    ['proto','service','state','is_ftp_login','is_sm_ips_ports']),
    ('conn6',   ['proto','service','state','sttl','dttl','ct_state_ttl']),
    ('svc6',    ['proto','service','state','ct_srv_src','ct_srv_dst','ct_dst_ltm']),
    ('disc7',   ['proto','service','state','sttl','dttl','swin','dwin']),
]
results += do_dataset(df, unsw_feats, 'UNSW')

# 汇总
print("\n" + "="*70)
print(f"{'Dataset':<25s} {'Pkts':>10s} {'Unique':>8s} {'80%at':>8s} {'Top5%':>7s} {'Top20%':>7s} {'Pareto':>7s}")
print("-"*70)
for r in results:
    print(f"{r['name']:<25s} {r['total']:>10,} {r['unique']:>8,} {r['top80']:>8,} "
          f"{r['cov5']:>6.1f}% {r['cov20']:>6.1f}% {'YES' if r['pareto'] else '':>7s}")

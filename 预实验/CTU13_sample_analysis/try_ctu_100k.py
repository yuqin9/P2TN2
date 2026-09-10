"""CTU-13 10 万包试验样本: 每文件等量 16,667 包 (沿用 30K 方法按比例放大)
从 ctu13_protocol_headers_first400K.csv 切分, 不动任何现有图/表
输出: pareto_results_v2/CTU-13_12f_lookup_table_100K.csv + 打印统计
"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter

BASE = Path(r'F:\自己的论文\网络数据集')
OUT = BASE / 'v2_rerun' / 'pareto_results_v2'
F12 = ['eth_dst','eth_src','ip_src','ip_dst','ip_proto','ip_ttl',
       'tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']

def lut_stats(df, name):
    d = df[F12].fillna('0').astype(str)
    keys = d.agg('|'.join, axis=1)
    items = sorted(Counter(keys).items(), key=lambda kv: -kv[1])
    counts = np.array([c for _, c in items]); n = len(counts)
    total = len(df)
    cum = counts.cumsum(); cov = cum / total * 100
    ranks = np.arange(1, n + 1)
    n80 = int(ranks[(cov >= 80).argmax()]); n90 = int(ranks[(cov >= 90).argmax()])
    pd.DataFrame(items, columns=['feature_key', 'count']).to_csv(
        OUT / f'CTU-13_12f_lookup_table_{name}.csv', index=False)
    print(f'{name}: total={total:,} unique={n:,} n80={n80} n90={n90}')
    return items, counts

raw = pd.read_csv(BASE / 'CTU-13' / 'ctu13_protocol_headers_first400K.csv', dtype=str)

# 1) 每文件前 16,667 包 (共 100,002)
per = 16667
parts = [g.head(per) for _, g in raw.groupby('src_file')]
df = pd.concat(parts, ignore_index=True)
items, counts = lut_stats(df, '100K')
print('各文件协议构成:')
for f, g in df.groupby('src_file'):
    icmp = int((g['ip_proto'] == '1').sum())
    tcp = int((g['ip_proto'] == '6').sum())
    udp = int((g['ip_proto'] == '17').sum())
    print(f'  {f[:42]:<44} ICMP={icmp:>6,} TCP={tcp:>6,} UDP={udp:>6,}')
print('Top 5:')
for i in range(5):
    print(f'  [{counts[i]:>7,}] {items[i][0][:80]}')

# 2) 参考: 仅 donbot+sogou (4.5 万纯正常流量)
dn = raw[raw['src_file'].isin(['botnet-capture-20110816-donbot.pcap',
                               'botnet-capture-20110816-sogou.pcap'])]
lut_stats(dn, 'normal45K')

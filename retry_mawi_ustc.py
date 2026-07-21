"""MAWI(5files) + USTC: 尝试更多特征"""
import pandas as pd, numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE = Path(r"F:\自己的论文\网络数据集")
OUT = BASE/"pareto_results"
OUT.mkdir(exist_ok=True)

def pkt_to_key(pkt, fields):
    bits = []
    for f in fields:
        try:
            if f == 'ip_src':   v = int(pkt[IP].src.replace('.','')) if IP in pkt else 0
            elif f == 'ip_dst': v = int(pkt[IP].dst.replace('.','')) if IP in pkt else 0
            elif f == 'ip_src24': v = (sum(int(x)<<(24-i*8) for i,x in enumerate(pkt[IP].src.split('.')[:3])) if IP in pkt else 0)
            elif f == 'ip_dst24': v = (sum(int(x)<<(24-i*8) for i,x in enumerate(pkt[IP].dst.split('.')[:3])) if IP in pkt else 0)
            elif f == 'ip_proto': v = pkt[IP].proto if IP in pkt else 0
            elif f == 'ip_ttl': v = pkt[IP].ttl if IP in pkt else 0
            elif f == 'tcp_sport': v = pkt[TCP].sport if TCP in pkt else 0
            elif f == 'tcp_dport': v = pkt[TCP].dport if TCP in pkt else 0
            elif f == 'tcp_flags':
                v = 0
                if TCP in pkt:
                    for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                        if ch in str(pkt[TCP].flags): v |= 1<<bit
            elif f == 'tcp_window': v = pkt[TCP].window if TCP in pkt else 0
            elif f == 'udp_sport': v = pkt[UDP].sport if UDP in pkt else 0
            elif f == 'udp_dport': v = pkt[UDP].dport if UDP in pkt else 0
            else: v = 0
        except: v = 0
        bits.append(str(v))
    return '|'.join(bits)

def test_features(pkts, feats_list, prefix):
    results = []
    for name_suffix, fields in feats_list:
        name = f'{prefix}_{name_suffix}'
        cnt = Counter()
        for p in pkts:
            cnt[pkt_to_key(p, fields)] += 1

        items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
        counts = np.array([c for _, c in items])
        total = counts.sum(); n = len(items)
        cumsum = counts.cumsum(); coverage = cumsum / total * 100
        top80 = np.arange(1, n+1)[(coverage >= 80).argmax()]
        cov5 = coverage[min(int(n*0.05), n-1)]; cov20 = coverage[min(int(n*0.2), n-1)]
        pareto = cov20 >= 80
        bits_per_field = {'ip_src':32,'ip_dst':32,'ip_src24':24,'ip_dst24':24,
                          'ip_proto':8,'ip_ttl':8,'tcp_sport':16,'tcp_dport':16,
                          'tcp_flags':8,'tcp_window':16,'udp_sport':16,'udp_dport':16}
        total_bits = sum(bits_per_field.get(f,16) for f in fields)
        print(f'  {name:<35s} {n:>7,}unq  top80={top80:>6,}({top80/n*100:4.1f}%)  '
              f'cov5={cov5:.1f}% cov20={cov20:.1f}%  bits={total_bits}  {"PARETO" if pareto else ""}')
        results.append({'name':name,'fields':len(fields),'bits':total_bits,'unique':n,
                        'top80':top80,'cov5':cov5,'cov20':cov20,'pareto':pareto})
    return results

# ========== MAWI: 前5个split pcap ==========
print("="*65)
print("MAWI: 5 files x 500K pkts")
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
pcaps = sorted(SPLIT.glob("*.pcap"))[:5]
mawi_pkts = []
for i, pp in enumerate(pcaps):
    pkts = sniff(offline=str(pp), count=500000, store=True, quiet=True)
    mawi_pkts.extend(pkts)
    print(f"  [{i+1}/5] {pp.name}: {len(pkts)} pkts")
print(f"  Total: {len(mawi_pkts):,}")

mawi_feats = [
    ('svc3',     ['ip_proto','tcp_dport','udp_dport']),
    ('svc4',     ['ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('svc5',     ['ip_proto','ip_ttl','tcp_sport','tcp_dport','udp_sport','udp_dport']),
    ('tcp5',     ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window']),
    ('l4full',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
    ('subnet',   ['ip_src24','ip_dst24','ip_proto','tcp_dport','udp_dport']),
    ('subnet4',  ['ip_src24','ip_dst24','ip_proto','ip_ttl','tcp_dport','udp_dport']),
]
mawi_r = test_features(mawi_pkts, mawi_feats, 'MAWI')

# ========== USTC: 全量 ==========
print("\n" + "="*65)
print("USTC: full dataset")
df = pd.read_csv(BASE/"USTC"/"ustc_protocol_headers.csv")
# 转成伪pkt对象用同一套逻辑 (用dict模拟)
class Pkt: pass
ustc_pkts = []
for _, row in df.iterrows():
    p = Pkt()
    p.ip_src = row['ip_src']; p.ip_dst = row['ip_dst']
    p.ip_proto = row['ip_proto']; p.ip_ttl = row['ip_ttl']
    p.tcp_sport = row['tcp_sport']; p.tcp_dport = row['tcp_dport']
    p.tcp_flags = row['tcp_flags']; p.tcp_window = row['tcp_window']
    p.udp_sport = row['udp_sport']; p.udp_dport = row['udp_dport']
    # 模拟IP解析
    try: p.IP = type('ip',(),{'src':p.ip_src,'dst':p.ip_dst,'proto':int(p.ip_proto),'ttl':int(p.ip_ttl)})
    except: p.IP = type('ip',(),{'src':p.ip_src,'dst':p.ip_dst,'proto':0,'ttl':0})
    try: p.TCP = type('tcp',(),{'sport':int(p.tcp_sport),'dport':int(p.tcp_dport),'flags':str(p.tcp_flags),'window':int(p.tcp_window)})
    except: pass
    try: p.UDP = type('udp',(),{'sport':int(p.udp_sport),'dport':int(p.udp_dport)})
    except: pass
    ustc_pkts.append(p)
print(f"  Loaded: {len(ustc_pkts):,}")

ustc_feats = [
    ('svc3',     ['ip_proto','tcp_dport','udp_dport']),
    ('svc4',     ['ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('svc5',     ['ip_proto','ip_ttl','tcp_sport','tcp_dport','udp_sport','udp_dport']),
    ('tcp5',     ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window']),
    ('l4full',   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport']),
    ('subnet',   ['ip_src24','ip_dst24','ip_proto','tcp_dport','udp_dport']),
    ('subnet4',  ['ip_src24','ip_dst24','ip_proto','ip_ttl','tcp_dport','udp_dport']),
    ('sport4',   ['ip_proto','tcp_sport','tcp_dport','tcp_flags']),
    ('full5t',   ['ip_src24','ip_dst24','ip_proto','tcp_sport','tcp_dport','udp_sport','udp_dport']),
]
ustc_r = test_features(ustc_pkts, ustc_feats, 'USTC')

# 汇总
print("\n" + "="*70)
all_r = mawi_r + ustc_r
best = {}
for r in all_r:
    prefix = r['name'].split('_')[0]
    if r['pareto']:
        if prefix not in best or r['bits'] > best[prefix]['bits']:
            best[prefix] = r
print("BEST (with Pareto):")
for k in sorted(best):
    r = best[k]; print(f"  {r['name']}: {r['fields']} fields, {r['bits']} bits, top80={r['top80']} ({r['top80']/r['unique']*100:.1f}%), cov20={r['cov20']:.1f}%")

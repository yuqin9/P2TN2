"""保存缺失的 MAWI_l4full 和 USTC_svc_win lookup tables"""
import pandas as pd, numpy as np
from collections import Counter
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP

BASE = Path(r"F:\自己的论文\网络数据集")
OUT = BASE / "pareto_results"

# === MAWI l4full ===
print("MAWI l4full...")
SPLIT = BASE/"MAWI"/"202602011400.pcap"/"202602011400_split100"
pcaps = sorted(SPLIT.glob("*.pcap"))[:5]
cnt = Counter()
for i, pp in enumerate(pcaps):
    pkts = sniff(offline=str(pp), count=500000, store=True, quiet=True)
    for p in pkts:
        parts = []
        parts.append(str(p[IP].proto if IP in p else 0))
        parts.append(str(p[IP].ttl if IP in p else 0))
        if TCP in p:
            parts.append(str(p[TCP].sport))
            parts.append(str(p[TCP].dport))
            fl = 0
            for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
                if ch in str(p[TCP].flags): fl |= 1<<bit
            parts.append(str(fl))
            parts.append(str(p[TCP].window))
        else:
            parts.extend(['0','0','0','0'])
        if UDP in p:
            parts.append(str(p[UDP].sport))
            parts.append(str(p[UDP].dport))
        else:
            parts.extend(['0','0'])
        cnt['|'.join(parts)] += 1
    print(f"  [{i+1}/5] {len(cnt):,} unique")

items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
lut = pd.DataFrame(items, columns=['feature_key','count'])
lut.to_csv(OUT/'MAWI_l4full_lookup_table.csv', index=False)
print(f"  Saved: {len(lut):,} rows, {lut['count'].sum():,} total")

# === USTC svc_win ===
print("\nUSTC svc_win...")
df = pd.read_csv(BASE/"USTC"/"ustc_protocol_headers.csv")
cnt = Counter()
for _, row in df.iterrows():
    parts = [str(row['ip_proto']), str(row['ip_ttl']),
             str(row['tcp_dport']), str(row['udp_dport']), str(row['tcp_window'])]
    cnt['|'.join(parts)] += 1
items = sorted(cnt.items(), key=lambda x: x[1], reverse=True)
lut = pd.DataFrame(items, columns=['feature_key','count'])
lut.to_csv(OUT/'USTC_svc_win_lookup_table.csv', index=False)
print(f"  Saved: {len(lut):,} rows, {lut['count'].sum():,} total")
print("\nDone")

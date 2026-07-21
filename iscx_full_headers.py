"""ISCX VPN 全量提取 - 不限包数，用于模型训练"""
import pandas as pd
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

BASE = Path(r"F:\自己的论文\网络数据集")
ISCX = BASE / "iscxvpn"

FIELD_NAMES = [
    'eth_dst','eth_src','eth_type',
    'ip_src','ip_dst','ip_proto','ip_ttl',
    'tcp_sport','tcp_dport','tcp_flags','tcp_window',
    'udp_sport','udp_dport',
]

def parse_pkt(pkt):
    f = {}
    if Ether in pkt:
        f['eth_dst']=pkt[Ether].dst; f['eth_src']=pkt[Ether].src
        f['eth_type']='0x%04x'%pkt[Ether].type
    else:
        for k in ['eth_dst','eth_src','eth_type']: f[k]=''
    if IP in pkt:
        ip=pkt[IP]
        f['ip_src']=ip.src; f['ip_dst']=ip.dst
        f['ip_proto']=str(ip.proto); f['ip_ttl']=str(ip.ttl)
    else:
        for k in ['ip_src','ip_dst','ip_proto','ip_ttl']: f[k]=''
    if TCP in pkt:
        t=pkt[TCP]
        f['tcp_sport']=str(t.sport); f['tcp_dport']=str(t.dport)
        fl=0
        for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
            if ch in str(t.flags): fl|=1<<bit
        f['tcp_flags']=str(fl); f['tcp_window']=str(t.window)
    else:
        for k in ['tcp_sport','tcp_dport','tcp_flags','tcp_window']: f[k]=''
    if UDP in pkt:
        u=pkt[UDP]
        f['udp_sport']=str(u.sport); f['udp_dport']=str(u.dport)
    else:
        for k in ['udp_sport','udp_dport']: f[k]=''
    return f

dirs = {'NonVPN-PCAPs-01':'NonVPN','NonVPN-PCAPs-02':'NonVPN','NonVPN-PCAPs-03':'NonVPN',
        'VPN-PCAPS-01':'VPN','VPN-PCAPs-02':'VPN'}

all_rows = []
t0 = datetime.now()
total_files = 0

for dname, label in dirs.items():
    dpath = ISCX / dname
    if not dpath.exists(): continue
    for pp in sorted(list(dpath.glob("*.pcap")) + list(dpath.glob("*.pcapng"))):
        total_files += 1
        try:
            pkts = sniff(offline=str(pp), count=100000, store=True, quiet=True)
        except:
            continue
        for p in pkts:
            r = parse_pkt(p); r['label'] = label; r['src_file'] = pp.name
            all_rows.append(r)
        if total_files % 20 == 0:
            print(f'  {total_files} files, {len(all_rows):,} pkts, {(datetime.now()-t0).total_seconds():.0f}s')

df = pd.DataFrame(all_rows)
df = df[FIELD_NAMES + ['label','src_file']]
out = ISCX / "iscx_protocol_headers_100K.csv"
df.to_csv(out, index=False)

elapsed = (datetime.now()-t0).total_seconds()
print(f'\nDone: {len(df):,} pkts, {total_files} files, {elapsed:.0f}s')
print(f'Saved: {out}')
vpn_count = (df['label'] == 'VPN').sum()
nonvpn_count = (df['label'] == 'NonVPN').sum()
print(f'VPN: {vpn_count:,}  NonVPN: {nonvpn_count:,}')

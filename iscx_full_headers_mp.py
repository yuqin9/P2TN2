"""ISCX VPN 全量提取 - 多进程并行, 每文件10万包"""
import pandas as pd
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP
from multiprocessing import Pool, cpu_count
import os

BASE = Path(r"F:\自己的论文\网络数据集")
ISCX = BASE / "iscxvpn"
MAX_PKTS = 100000
WORKERS = max(1, cpu_count() - 2)

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
        ip=pkt[IP]; f['ip_src']=ip.src; f['ip_dst']=ip.dst
        f['ip_proto']=str(ip.proto); f['ip_ttl']=str(ip.ttl)
    else:
        for k in ['ip_src','ip_dst','ip_proto','ip_ttl']: f[k]=''
    if TCP in pkt:
        t=pkt[TCP]; f['tcp_sport']=str(t.sport); f['tcp_dport']=str(t.dport)
        fl=0
        for ch,bit in [('F',0),('S',1),('R',2),('P',3),('A',4),('U',5)]:
            if ch in str(t.flags): fl|=1<<bit
        f['tcp_flags']=str(fl); f['tcp_window']=str(t.window)
    else:
        for k in ['tcp_sport','tcp_dport','tcp_flags','tcp_window']: f[k]=''
    if UDP in pkt:
        u=pkt[UDP]; f['udp_sport']=str(u.sport); f['udp_dport']=str(u.dport)
    else:
        for k in ['udp_sport','udp_dport']: f[k]=''
    return f

def process_file(args):
    pp, label = args
    fname = pp.name
    try:
        pkts = sniff(offline=str(pp), count=MAX_PKTS, store=True, quiet=True)
    except:
        return fname, 0, []
    rows = []
    for p in pkts:
        r = parse_pkt(p); r['label'] = label; r['src_file'] = fname
        rows.append(r)
    return fname, len(pkts), rows

if __name__ == '__main__':
    dirs = {'NonVPN-PCAPs-01':'NonVPN','NonVPN-PCAPs-02':'NonVPN','NonVPN-PCAPs-03':'NonVPN',
            'VPN-PCAPS-01':'VPN','VPN-PCAPs-02':'VPN'}

    jobs = []
    for dname, label in dirs.items():
        dpath = ISCX / dname
        if not dpath.exists(): continue
        for pp in sorted(list(dpath.glob("*.pcap")) + list(dpath.glob("*.pcapng"))):
            jobs.append((pp, label))

    print(f"Files: {len(jobs)}  Workers: {WORKERS}  Max: {MAX_PKTS:,}/file")
    t0 = datetime.now()

    all_rows = []
    total_pkts = 0
    with Pool(WORKERS) as pool:
        for i, (fname, n, rows) in enumerate(pool.imap_unordered(process_file, jobs)):
            total_pkts += n
            all_rows.extend(rows)
            if (i+1) % 20 == 0:
                t = (datetime.now()-t0).total_seconds()
                print(f'  [{i+1}/{len(jobs)}] {total_pkts:,} pkts, {t:.0f}s')

    df = pd.DataFrame(all_rows)
    df = df[FIELD_NAMES + ['label','src_file']]
    out = ISCX / "iscx_protocol_headers_100K.csv"
    df.to_csv(out, index=False)

    elapsed = (datetime.now()-t0).total_seconds()
    vpn = (df['label'] == 'VPN').sum()
    non = (df['label'] == 'NonVPN').sum()
    print(f'\nDone: {len(df):,} pkts, {elapsed:.0f}s ({elapsed/60:.1f}min)')
    print(f'VPN: {vpn:,}  NonVPN: {non:,}')
    print(f'Saved: {out}')

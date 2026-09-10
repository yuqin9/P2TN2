"""CTU-13 跨全文件均匀抽样 (stride): 修复"取前 N 包恰好全是洪泛"的抽样偏差
官方 binetflow 显示两个大抓包全程 94% TCP / 50% UDP, 洪泛只占开头
本脚本: 快扫计数 -> 每 k 包取 1 包 (k=total//target), 小文件全取
用法: python expand_ctu13_stride.py
输出: CTU-13/ctu13_protocol_headers_full.csv (33 列 + label + src_file)
"""
import csv
from pathlib import Path
from datetime import datetime
import dpkt, socket

BASE = Path(r"F:\自己的论文\网络数据集")
SRC = BASE / "CTU-13"
OUT = SRC / "ctu13_protocol_headers_full.csv"
# 每文件目标包数: 两个大文件 stride 抽样, 其余全取
TARGETS = {
    'botnet-capture-20110815-rbot-dos-icmp-more-bandwith.pcap': 385000,
    'botnet-capture-20110818-bot-2.pcap': 385000,
}

FIELD_NAMES = [
    'eth_dst','eth_src','eth_type',
    'ip_ver','ip_hdr_len','ip_dscp','ip_ecn','ip_total_len','ip_id',
    'ip_flags','ip_frag_offset','ip_ttl','ip_proto','ip_checksum','ip_src','ip_dst',
    'tcp_sport','tcp_dport','tcp_seq','tcp_ack','tcp_hdr_len',
    'tcp_flags','tcp_window','tcp_checksum','tcp_urgptr',
    'udp_sport','udp_dport','udp_len','udp_checksum',
    'icmp_type','icmp_code','icmp_checksum',
]

def parse_pkt(buf):
    f = {}
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        f['eth_dst'] = ':'.join(f'{b:02x}' for b in eth.dst)
        f['eth_src'] = ':'.join(f'{b:02x}' for b in eth.src)
        f['eth_type'] = '0x%04x' % eth.type
    except Exception:
        f.update(eth_dst='', eth_src='', eth_type='')
        eth = None
    ip = None; ip6 = None; tcp = None; udp = None; icmp = None
    if eth is not None:
        data = eth.data
        if isinstance(data, dpkt.ip.IP): ip = data
        elif isinstance(data, dpkt.ip6.IP6): ip6 = data
    if ip is not None:
        f.update(ip_ver=ip.v, ip_hdr_len=ip.hl*4, ip_dscp=ip.tos>>2,
                 ip_ecn=ip.tos&3, ip_total_len=ip.len, ip_id=ip.id,
                 ip_flags=str(ip.off), ip_frag_offset=ip.off & 0x1fff, ip_ttl=ip.ttl,
                 ip_proto=ip.p, ip_checksum=ip.sum,
                 ip_src=socket.inet_ntoa(ip.src), ip_dst=socket.inet_ntoa(ip.dst))
        l4 = ip.data
        if isinstance(l4, dpkt.tcp.TCP): tcp = l4
        elif isinstance(l4, dpkt.udp.UDP): udp = l4
        elif isinstance(l4, dpkt.icmp.ICMP): icmp = l4
    elif ip6 is not None:
        f.update(ip_ver=6, ip_hdr_len=40, ip_dscp=0, ip_ecn=0,
                 ip_total_len=ip6.plen+40, ip_id=0, ip_flags='', ip_frag_offset=0,
                 ip_ttl=ip6.hlim, ip_proto=ip6.nh, ip_checksum=0,
                 ip_src=socket.inet_ntop(socket.AF_INET6, ip6.src),
                 ip_dst=socket.inet_ntop(socket.AF_INET6, ip6.dst))
        l4 = ip6.data
        if isinstance(l4, dpkt.tcp.TCP): tcp = l4
        elif isinstance(l4, dpkt.udp.UDP): udp = l4
        elif isinstance(l4, dpkt.icmp.ICMP): icmp = l4
    else:
        f.update(ip_ver='', ip_hdr_len='', ip_dscp='', ip_ecn='', ip_total_len='', ip_id='',
                 ip_flags='', ip_frag_offset='', ip_ttl='', ip_proto='', ip_checksum='',
                 ip_src='', ip_dst='')
    if tcp is not None:
        fl = tcp.flags
        f.update(tcp_sport=tcp.sport, tcp_dport=tcp.dport, tcp_seq=tcp.seq, tcp_ack=tcp.ack,
                 tcp_hdr_len=tcp.off*4,
                 tcp_flags=''.join(c for c, b in zip('FSRPAUEC', [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80]) if fl & b),
                 tcp_window=tcp.win, tcp_checksum=tcp.sum, tcp_urgptr=tcp.urp)
    else:
        f.update(tcp_sport='', tcp_dport='', tcp_seq='', tcp_ack='', tcp_hdr_len='',
                 tcp_flags='', tcp_window='', tcp_checksum='', tcp_urgptr='')
    if udp is not None:
        f.update(udp_sport=udp.sport, udp_dport=udp.dport, udp_len=udp.ulen,
                 udp_checksum=udp.sum)
    else:
        f.update(udp_sport='', udp_dport='', udp_len='', udp_checksum='')
    if icmp is not None:
        f.update(icmp_type=icmp.type, icmp_code=icmp.code, icmp_checksum=icmp.sum)
    else:
        f.update(icmp_type='', icmp_code='', icmp_checksum='')
    return f

def fast_count(path):
    """只扫 16 字节记录头, 快速数包数 (5GB 文件约 10-20s)"""
    n = 0
    with open(path, 'rb') as fh:
        magic = fh.read(4)
        assert magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'), f'not pcap: {path}'
        fh.seek(24)
        while True:
            h = fh.read(16)
            if len(h) < 16: break
            incl = int.from_bytes(h[8:12], 'little')
            fh.seek(incl, 1)
            n += 1
    return n

pcaps = sorted(SRC.glob("*.pcap"))
print(f"{len(pcaps)} pcap files")
t0 = datetime.now()
total = 0; errs = 0
with open(OUT, 'w', newline='', encoding='utf-8') as fo:
    w = csv.DictWriter(fo, fieldnames=FIELD_NAMES + ['label','src_file'])
    w.writeheader()
    for pp in pcaps:
        target = TARGETS.get(pp.name, 0)
        if target:
            cnt = fast_count(pp)
            stride = max(1, cnt // target)
            print(f"  {pp.name}: {cnt:,} pkts, stride={stride} -> ~{cnt//stride:,}")
        else:
            stride = 1
            print(f"  {pp.name}: 全取")
        n = 0
        with open(pp, 'rb') as fh:
            for i, (ts, buf) in enumerate(dpkt.pcap.Reader(fh)):
                if i % stride != 0: continue
                try:
                    row = parse_pkt(buf)
                except Exception:
                    errs += 1; continue
                row['label'] = pp.stem; row['src_file'] = pp.name
                w.writerow(row); n += 1
                if n % 100000 == 0:
                    print(f"    {n:,} kept, {(datetime.now()-t0).total_seconds():.0f}s")
        total += n
        print(f"  -> {n:,} pkts ({(datetime.now()-t0).total_seconds():.0f}s)")
print(f"\nDONE: {total:,} pkts, {errs} parse errors -> {OUT} ({datetime.now()-t0})")

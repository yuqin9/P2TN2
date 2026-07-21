"""
用scapy标准协议解析PCAP → 只提取网络协议头部字段，保持原始格式
输出: 每个字段一列，值=原始可读格式 (IP="192.168.0.1", MAC="aa:bb:cc:dd:ee:ff")
"""
import os, sys
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, IPv6
from scapy.all import rdpcap

BASE_DIR = Path(r"F:\自己的论文\网络数据集")
MAX_PKTS = 5000  # 每pcap最大包数

# ============================================================
# 协议字段定义 - 只包含真实协议头部
# ============================================================
FIELD_NAMES = [
    # L2: Ethernet
    'eth_dst',           # 目的MAC
    'eth_src',           # 源MAC
    'eth_type',          # EtherType (0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)

    # L3: IP
    'ip_ver',            # IP版本 (4/6)
    'ip_hdr_len',        # 头部长度 (4-bit words)
    'ip_dscp',           # DSCP/ToS
    'ip_ecn',            # ECN
    'ip_total_len',      # 总长度
    'ip_id',             # 标识
    'ip_flags',          # 标志 (DF/MF)
    'ip_frag_offset',    # 片偏移
    'ip_ttl',            # TTL
    'ip_proto',          # 协议号 (6=TCP, 17=UDP, 1=ICMP)
    'ip_checksum',       # 头部校验和
    'ip_src',            # 源IP (点分十进制)
    'ip_dst',            # 目的IP

    # L4: TCP
    'tcp_sport',         # 源端口
    'tcp_dport',         # 目的端口
    'tcp_seq',           # 序列号
    'tcp_ack',           # 确认号
    'tcp_hdr_len',       # 数据偏移
    'tcp_flags',         # 标志位 (如 "SA" = SYN+ACK)
    'tcp_window',        # 窗口大小
    'tcp_checksum',      # 校验和
    'tcp_urgptr',        # 紧急指针

    # L4: UDP
    'udp_sport',         # 源端口
    'udp_dport',         # 目的端口
    'udp_len',           # 长度
    'udp_checksum',      # 校验和

    # L4: ICMP
    'icmp_type',         # 类型
    'icmp_code',         # 代码
    'icmp_checksum',     # 校验和
]


def parse_packet(pkt):
    """用scapy标准解析一个包，返回协议头部字段字典"""
    f = {}

    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        f['eth_dst'] = eth.dst
        f['eth_src'] = eth.src
        f['eth_type'] = '0x%04x' % eth.type if hasattr(eth, 'type') else ''
    else:
        for k in ['eth_dst','eth_src','eth_type']:
            f[k] = ''

    # IP
    if IP in pkt:
        ip = pkt[IP]
        f['ip_ver'] = ip.version
        f['ip_hdr_len'] = ip.ihl * 4  # bytes
        f['ip_dscp'] = ip.tos >> 2
        f['ip_ecn'] = ip.tos & 0x03
        f['ip_total_len'] = ip.len
        f['ip_id'] = ip.id
        f['ip_flags'] = str(ip.flags)
        f['ip_frag_offset'] = ip.frag
        f['ip_ttl'] = ip.ttl
        f['ip_proto'] = ip.proto
        f['ip_checksum'] = ip.chksum if hasattr(ip, 'chksum') else 0
        f['ip_src'] = ip.src
        f['ip_dst'] = ip.dst
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        f['ip_ver'] = 6
        f['ip_hdr_len'] = 40
        f['ip_dscp'] = (ip6.tc >> 2) if hasattr(ip6, 'tc') else 0
        f['ip_ecn'] = (ip6.tc & 0x03) if hasattr(ip6, 'tc') else 0
        f['ip_total_len'] = ip6.plen + 40 if hasattr(ip6, 'plen') else 0
        f['ip_id'] = 0
        f['ip_flags'] = ''
        f['ip_frag_offset'] = 0
        f['ip_ttl'] = ip6.hlim if hasattr(ip6, 'hlim') else 0
        f['ip_proto'] = ip6.nh if hasattr(ip6, 'nh') else 0
        f['ip_checksum'] = 0
        f['ip_src'] = ip6.src
        f['ip_dst'] = ip6.dst
    else:
        for k in ['ip_ver','ip_hdr_len','ip_dscp','ip_ecn','ip_total_len',
                   'ip_id','ip_flags','ip_frag_offset','ip_ttl','ip_proto',
                   'ip_checksum','ip_src','ip_dst']:
            f[k] = ''

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        f['tcp_sport'] = tcp.sport
        f['tcp_dport'] = tcp.dport
        f['tcp_seq'] = tcp.seq
        f['tcp_ack'] = tcp.ack
        f['tcp_hdr_len'] = tcp.dataofs * 4 if hasattr(tcp, 'dataofs') else 0
        f['tcp_flags'] = str(tcp.flags)
        f['tcp_window'] = tcp.window
        f['tcp_checksum'] = tcp.chksum if hasattr(tcp, 'chksum') else 0
        f['tcp_urgptr'] = tcp.urgptr
    else:
        for k in ['tcp_sport','tcp_dport','tcp_seq','tcp_ack','tcp_hdr_len',
                   'tcp_flags','tcp_window','tcp_checksum','tcp_urgptr']:
            f[k] = ''

    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        f['udp_sport'] = udp.sport
        f['udp_dport'] = udp.dport
        f['udp_len'] = udp.len
        f['udp_checksum'] = udp.chksum if hasattr(udp, 'chksum') else 0
    else:
        for k in ['udp_sport','udp_dport','udp_len','udp_checksum']:
            f[k] = ''

    # ICMP
    if ICMP in pkt:
        icmp = pkt[ICMP]
        f['icmp_type'] = icmp.type
        f['icmp_code'] = icmp.code
        f['icmp_checksum'] = icmp.chksum if hasattr(icmp, 'chksum') else 0
    else:
        for k in ['icmp_type','icmp_code','icmp_checksum']:
            f[k] = ''

    return f


def process_pcaps(pcap_files, label_map_func, output_path):
    """处理一批pcap文件"""
    all_rows = []
    total = 0
    t0 = datetime.now()

    for i, pcap_path in enumerate(pcap_files):
        fname = pcap_path.name
        label_val = label_map_func(pcap_path)
        label_name = str(label_val)

        try:
            pkts = sniff(offline=str(pcap_path), count=MAX_PKTS, store=True, quiet=True)
        except:
            try:
                pkts = rdpcap(str(pcap_path))[:MAX_PKTS]
            except Exception as e:
                print(f"  SKIP {fname}: {e}")
                continue

        for pkt in pkts:
            row = parse_packet(pkt)
            row['label'] = label_val
            row['src_file'] = fname
            all_rows.append(row)

        total += len(pkts)
        if (i+1) % 10 == 0:
            print(f"  {i+1}/{len(pcap_files)} files, {total} pkts, "
                  f"{(datetime.now()-t0).total_seconds():.0f}s")

    df = pd.DataFrame(all_rows)
    df = df[FIELD_NAMES + ['label', 'src_file']]
    df.to_csv(output_path, index=False, encoding='utf-8')

    elapsed = (datetime.now() - t0).total_seconds()
    print(f"  -> {len(df)} pkts, {len(FIELD_NAMES)} fields, {elapsed:.0f}s")
    print(f"  -> {output_path}")
    return df


# ============================================================
# ISCX VPN-nonVPN
# ============================================================
def process_iscx():
    print("\n" + "="*60)
    print("ISCX VPN-nonVPN (scapy protocol parsing)")
    print("="*60)

    iscx_dir = BASE_DIR / "iscxvpn"
    dirs = {
        'NonVPN-PCAPs-01': 'NonVPN',
        'NonVPN-PCAPs-02': 'NonVPN',
        'NonVPN-PCAPs-03': 'NonVPN',
        'VPN-PCAPS-01': 'VPN',
        'VPN-PCAPs-02': 'VPN',
    }

    all_pcaps = []
    for dname, label in dirs.items():
        dpath = iscx_dir / dname
        if dpath.exists():
            for ext in ['*.pcap', '*.pcapng']:
                all_pcaps.extend([(f, label) for f in sorted(dpath.glob(ext))])

    print(f"  Found {len(all_pcaps)} pcap files")

    def label_fn(p): return p.parent.parent.name  # NonVPN-PCAPs-01 etc

    out = iscx_dir / "iscx_protocol_headers.csv"
    return process_pcaps([pf for pf, _ in all_pcaps],
                         lambda p: 'NonVPN' if 'NonVPN' in str(p.parent) else 'VPN',
                         out)


# ============================================================
# USTC
# ============================================================
def process_ustc():
    print("\n" + "="*60)
    print("USTC (scapy protocol parsing)")
    print("="*60)

    ustc_dir = BASE_DIR / "USTC"
    extracted_dir = ustc_dir / "extracted"

    # 解压7z (如果还没解压)
    for f in sorted(ustc_dir.glob("*.7z")):
        import py7zr
        out_dir = extracted_dir
        out_dir.mkdir(exist_ok=True)
        if not (out_dir / f.stem).exists():
            try:
                with py7zr.SevenZipFile(str(f), 'r') as arch:
                    arch.extractall(path=str(out_dir))
            except:
                pass

    # 收集所有pcap
    pcaps = (sorted(ustc_dir.glob("*.pcap")) +
             sorted(extracted_dir.glob("**/*.pcap")))

    # 标签: 恶意软件关键词 → Malware, 其他 → Application
    malware_kw = ['botnet','miuref','tinba','cridex','geodo','htbot',
                  'neris','nsis-ay','smb','weibo']

    def label_fn(p):
        name = p.name.lower()
        for kw in malware_kw:
            if kw in name:
                return 'Malware'
        return 'Application'

    out = ustc_dir / "ustc_protocol_headers.csv"
    return process_pcaps(pcaps, label_fn, out)


if __name__ == "__main__":
    process_iscx()
    process_ustc()
    print("\nDone! 每个字段都是标准协议头部，格式为原始可读形式。")

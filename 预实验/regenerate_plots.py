"""
只画图+写文档, 从已有lookup table读取, 不重跑任何pcap
"""
import pandas as pd, numpy as np
from pathlib import Path
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

plt.rcParams.update({'font.size':13,'axes.labelsize':14,'axes.titlesize':12,
                     'xtick.labelsize':11,'ytick.labelsize':11,'figure.dpi':150})

BASE = Path(r"F:\自己的论文\网络数据集")
LUT = BASE / "pareto_results"
OUT = BASE / "final_plots"
OUT.mkdir(exist_ok=True)

def plot_one(csv_path, fname):
    lut = pd.read_csv(csv_path)
    # find count column
    if 'count' in lut.columns: cc = 'count'
    else: cc = lut.columns[1]
    lut[cc] = pd.to_numeric(lut[cc], errors='coerce').fillna(0).astype('int64')
    lut = lut[lut[cc] > 0]
    counts = lut[cc].values
    total = counts.sum(); n = len(counts)
    cumsum = counts.cumsum(); cov = cumsum/total*100
    ranks = np.arange(1, n+1)
    top80 = ranks[(cov>=80).argmax()]
    cov5 = cov[min(int(n*0.05), n-1)]
    cov20 = cov[min(int(n*0.2), n-1)]

    fig, axes = plt.subplots(1, 2, figsize=(15, 4.5))

    # 采样避免点太密 (最多5000个点)
    step = max(1, n // 5000)
    ridx = np.arange(0, n, step)
    # 确保最后一个点也在
    if ridx[-1] != n-1:
        ridx = np.append(ridx, n-1)

    ax = axes[0]
    ax.plot(ranks[ridx], cov[ridx], 'b.', markersize=2, alpha=0.6)
    ax.set_xlabel('Number of Feature Patterns')
    ax.set_ylabel('Hit Rate (%)')
    ax.grid(True, alpha=0.25); ax.set_xlim(left=0); ax.set_ylim(0, 105)
    def fmt(x, p):
        if x == 0: return '0'
        if x < 1000: return f'{x:.0f}'
        if x < 1e6: return f'{x/1000:.0f}K'
        return f'{x/1e6:.1f}M'
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt))


    ax = axes[1]
    ax.loglog(ranks[ridx], counts[ridx], 'b.', markersize=2, alpha=0.4)
    ax.set_xlabel('Pattern Rank')
    ax.set_ylabel('Frequency')
    ax.grid(True, alpha=0.25)
    def fmt(x, p):
        if x == 0: return '0'
        if x < 1000: return f'{x:.0f}'
        if x < 1e6: return f'{x/1000:.0f}K'
        return f'{x/1e6:.1f}M'
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(fmt))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt))

    plt.subplots_adjust(wspace=0.25)
    plt.savefig(OUT/f'{fname}.png', dpi=150, bbox_inches='tight')
    plt.close()
    return total, n, top80, cov5, cov20

# ============ 所有图片定义 (csv文件名, 输出图片名) ============
jobs = [
    # 主结果
    ('ISCX_VPN_lookup_table.csv',       'ISCX_VPN_12f'),
    ('CTU-13_lookup_table.csv',         'CTU-13_12f'),
    ('MAWI_40_svc_lookup_table.csv',    'MAWI_3f_7.5M'),
    ('MAWI_MAWI_noIP_lookup_table.csv', 'MAWI_8f_500K'),
    ('USTC_USTC_svc_lookup_table.csv',  'USTC_3f'),
    ('CIC-IDS-2017_lookup_table.csv',   'CIC-IDS-2017_13f'),
    ('NSL_disc8_lookup_table.csv',      'NSL-KDD_8f'),
    ('UNSW_disc7_lookup_table.csv',     'UNSW-NB15_7f'),
    # MAWI字段对比
    ('MAWI_MAWI_svc_lookup_table.csv',    'MAWI_3f_svc'),
    ('MAWI_MAWI_noIP_lookup_table.csv',   'MAWI_8f_noIP'),
    # USTC字段对比
    ('USTC_USTC_svc_lookup_table.csv',     'USTC_3f_svc'),
    ('USTC_USTC_noMAC_lookup_table.csv',   'USTC_10f_noMAC'),
    ('USTC_USTC_5tuple_lookup_table.csv',  'USTC_7f_5tuple'),
    ('USTC_USTC_dstSvc_lookup_table.csv',  'USTC_4f_dstSvc'),
    ('USTC_USTC_portOnly_lookup_table.csv','USTC_4f_portOnly'),
    # NSL字段对比
    ('NSL_cat3_lookup_table.csv',  'NSL-KDD_3f_cat'),
    ('NSL_disc8_lookup_table.csv', 'NSL-KDD_8f_disc'),
    ('NSL_svc5_lookup_table.csv',  'NSL-KDD_5f_svc'),
    # UNSW字段对比
    ('UNSW_cat3_lookup_table.csv',  'UNSW_3f_cat'),
    ('UNSW_disc7_lookup_table.csv', 'UNSW_7f_disc'),
    ('UNSW_svc6_lookup_table.csv',  'UNSW_6f_svc'),
    ('UNSW_conn6_lookup_table.csv', 'UNSW_6f_conn'),
]

print("Generating plots from existing lookup tables...\n")
results = []
for csv_name, fname in jobs:
    p = LUT / csv_name
    if p.exists():
        t, n, top80, cov5, cov20 = plot_one(p, fname)
        results.append((fname, t, n, top80, cov5, cov20))
        print(f'  {fname}: {t:,} pkts, {n:,} uniq, 80% at {top80:,}')

# Also: MAWI full (from separate file)
mawi_full = BASE / "MAWI" / "mawi_protocol_headers.csv"
if mawi_full.exists():
    # Actually we already have MAWI_40_svc which covers this
    pass

# ============ 写文档 ============
with open(OUT/'README.md', 'w', encoding='utf-8') as f:
    f.write("""# Pareto Analysis - Experiment Documentation

## Method
1. Extract protocol header fields from raw PCAP files using scapy (for PCAP datasets)
   or use existing flow-level features (for NSL-KDD, UNSW-NB15, CIC-IDS 2017).
2. Convert each field value to its binary representation according to protocol bit width
   (e.g., IP = 32 bits, Port = 16 bits, Protocol = 8 bits).
3. Concatenate all field bit-strings into one combined feature key per packet.
4. Count frequency of each unique key, sort descending.
5. Compute cumulative coverage: top N patterns cover X% of all packets.
6. Pareto confirmed when top 20% of patterns cover >= 80% of traffic.

## Plot Structure
Each PNG contains two subplots:
- **Left**: Cumulative coverage curve. X = number of patterns (sorted by frequency),
  Y = cumulative % of packets covered. Steeper curve = stronger Pareto effect.
- **Right**: Frequency-Rank distribution on log-log scale. Linear decay = power-law.
- **Text box** (bottom-right): total packets, unique patterns, 80% coverage point.

## Dataset Details

### 1. ISCX VPN-nonVPN
- Source: 140 pcap files (VPN + NonVPN traffic)
- Processing: scapy protocol parsing, 12 stable header fields
- Fields: eth_dst, eth_src, ip_src, ip_dst, ip_proto, ip_ttl,
  tcp_sport, tcp_dport, tcp_flags, tcp_window, udp_sport, udp_dport
- Total bits: 320 (48+48+32+32+8+8+16+16+8+16+16+16)
- Data: 593,836 packets (full)
- Image: `ISCX_VPN_12f.png`

### 2. CTU-13
- Source: 6 pcap files (botnet captures)
- Processing: scapy protocol parsing, 12 stable header fields (same as ISCX)
- Fields: same 12 fields
- Total bits: 320
- Data: 30,000 packets (6 pcaps x 5K sampled)
- Image: `CTU-13_12f.png`

### 3. MAWI (WIDE backbone)
- Source: MAWI 202602011400 trace, split into 100 pcap files
- Processing: scapy protocol parsing

| Image | Fields | Bits | Data |
|-------|--------|------|------|
| `MAWI_3f_7.5M.png` | ip_proto, tcp_dport, udp_dport | 40 | 7.5M pkts (15x500K) |
| `MAWI_8f_500K.png` | ip_proto, ip_ttl, tcp_sport/dport, tcp_flags, tcp_window, udp_sport/dport | 88 | 500K pkts (100x5K) |
| `MAWI_3f_svc.png` | ip_proto, tcp_dport, udp_dport | 40 | 500K pkts (100x5K) |
| `MAWI_8f_noIP.png` | ip_proto, ip_ttl, tcp/udp ports, tcp_flags, tcp_window | 88 | 500K pkts |

### 4. USTC-TFC2016
- Source: 22 pcap files (11 app + 11 malware)
- Processing: scapy protocol parsing

| Image | Fields | Bits | Data |
|-------|--------|------|------|
| `USTC_3f.png` | ip_proto, tcp_dport, udp_dport | 40 | 110K pkts |
| `USTC_3f_svc.png` | same | 40 | 110K pkts |
| `USTC_10f_noMAC.png` | ip_src/dst, ip_proto, ip_ttl, tcp/udp ports, tcp_flags, tcp_window | 248 | 110K pkts |
| `USTC_7f_5tuple.png` | ip_src/dst, ip_proto, tcp/udp ports | 128 | 110K pkts |
| `USTC_4f_dstSvc.png` | ip_dst, ip_proto, tcp_dport, udp_dport | 72 | 110K pkts |
| `USTC_4f_portOnly.png` | tcp/udp sport/dport | 64 | 110K pkts |

### 5. CIC-IDS 2017
- Source: 9 CSV files (CICFlowMeter output)
- Fields: Destination Port, Protocol, Fwd/Bwd Header Len, 6 Flag Counts,
  Flow Duration, Flow Bytes/s, Flow Packets/s, Average Packet Size
- Data: 3,461,718 flows (full)
- Image: `CIC-IDS-2017_13f.png`

### 6. NSL-KDD
- Source: KDDTrain+.txt + KDDTest+.txt

| Image | Fields |
|-------|--------|
| `NSL-KDD_8f.png` | protocol_type, service, flag, land, logged_in, is_host_login, is_guest_login, num_outbound_cmds |
| `NSL-KDD_3f_cat.png` | protocol_type, service, flag |
| `NSL-KDD_8f_disc.png` | same 8 as above |
| `NSL-KDD_5f_svc.png` | protocol_type, service, flag, same_srv_rate, dst_host_same_srv_rate |

Data: 148,517 flows (full)

### 7. UNSW-NB15
- Source: UNSW_NB15_training-set.csv + testing-set.csv

| Image | Fields |
|-------|--------|
| `UNSW-NB15_7f.png` | proto, service, state, sttl, dttl, swin, dwin |
| `UNSW_3f_cat.png` | proto, service, state |
| `UNSW_7f_disc.png` | same 7 as above |
| `UNSW_6f_svc.png` | proto, service, state, ct_srv_src, ct_srv_dst, ct_dst_ltm |
| `UNSW_6f_conn.png` | proto, service, state, sttl, dttl, ct_state_ttl |

Data: 257,673 flows (full)

## Protocol Field Bit Widths
```
Ethernet dst/src: 48 bits each
EtherType:        16 bits
IP src/dst:       32 bits each
IP protocol:       8 bits
IP TTL:            8 bits
TCP/UDP port:     16 bits each
TCP flags:         8 bits
TCP window:       16 bits
```
""")

df_r = pd.DataFrame(results, columns=['image','total','unique','top80','cov5_pct','cov20_pct'])
df_r.to_csv(OUT/'_results.csv', index=False)
print(f"\nDone: {len(results)} plots -> {OUT}/")
print(f"Docs: {OUT}/README.md")

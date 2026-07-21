"""
帕累托分析完整流程:
1. PCAP数据集: 协议字段→二进制串 → 查找表
2. 流数据集: 选特征 → 查找表
3. 全部7个数据集: 帕累托分布 → matplotlib点图
"""
import pandas as pd, numpy as np
from pathlib import Path
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

BASE = Path(r"F:\自己的论文\网络数据集")
OUT = BASE / "pareto_results"
OUT.mkdir(exist_ok=True)

# ============================================================
# Part 1: 协议字段 → bit转换
# ============================================================

# 字段bit宽度定义 (按协议标准)
FIELD_BITS = {
    # Ethernet
    'eth_dst': 48, 'eth_src': 48, 'eth_type': 16,
    # IP
    'ip_ver': 4, 'ip_hdr_len': 4, 'ip_dscp': 6, 'ip_ecn': 2,
    'ip_total_len': 16, 'ip_id': 16,
    'ip_flags': 3, 'ip_frag_offset': 13, 'ip_ttl': 8,
    'ip_proto': 8, 'ip_checksum': 16,
    'ip_src': 32, 'ip_dst': 32,
    # TCP
    'tcp_sport': 16, 'tcp_dport': 16, 'tcp_seq': 32, 'tcp_ack': 32,
    'tcp_hdr_len': 4, 'tcp_flags': 8, 'tcp_window': 16,
    'tcp_checksum': 16, 'tcp_urgptr': 16,
    # UDP
    'udp_sport': 16, 'udp_dport': 16, 'udp_len': 16, 'udp_checksum': 16,
    # ICMP
    'icmp_type': 8, 'icmp_code': 8, 'icmp_checksum': 16,
}


def val_to_bits(value, n_bits):
    """任意值 → n_bits 二进制字符串"""
    try:
        if isinstance(value, str):
            if ':' in value:  # MAC address
                parts = value.split(':')
                return ''.join(format(int(p, 16), '08b') for p in parts)[-n_bits:].zfill(n_bits)
            if '.' in value:  # IP address
                parts = value.split('.')
                if len(parts) == 4:
                    return ''.join(format(int(p), '08b') for p in parts).zfill(n_bits)
            if value.strip() == '':
                return '0' * n_bits
            # TCP flags string like "PA", "SA", "A", etc
            flags = 0
            if 'F' in value: flags |= 0x01
            if 'S' in value: flags |= 0x02
            if 'R' in value: flags |= 0x04
            if 'P' in value: flags |= 0x08
            if 'A' in value: flags |= 0x10
            if 'U' in value: flags |= 0x20
            if 'E' in value: flags |= 0x40
            if 'C' in value: flags |= 0x80
            return format(flags, f'0{n_bits}b')
        if isinstance(value, (int, float, np.integer, np.floating)):
            v = int(value)
            if v < 0: v = 0
            return format(v, f'0{n_bits}b')[-n_bits:]
        return '0' * n_bits
    except:
        return '0' * n_bits


def fields_to_bits(df, feature_cols):
    """将协议字段转为二进制串列（向量化加速）"""
    for col in feature_cols:
        if col in df.columns and col in FIELD_BITS:
            n = FIELD_BITS[col]
            # 用numpy向量化替代apply
            vals = df[col].values
            bit_strings = np.array([val_to_bits(v, n) for v in vals], dtype=object)
            df[col] = bit_strings
    return df


def build_lookup_table(df, feature_cols, max_combos=500000):
    """
    构建查找表: 拼接所有字段的二进制串 → 计数 → 降序排列
    """
    # 拼接特征列 → 一个key
    keys = df[feature_cols].astype(str).agg(''.join, axis=1)
    counts = keys.value_counts()
    if len(counts) > max_combos:
        counts = counts.head(max_combos)
    lut = counts.reset_index()
    lut.columns = ['feature_key', 'count']
    lut = lut.sort_values('count', ascending=False).reset_index(drop=True)
    lut.index.name = 'rank'
    return lut


def pareto_analysis(lut, dataset_name, output_dir):
    """
    帕累托分析: 计算累计覆盖率, 判断是否符合帕累托, 生成点图
    """
    total_pkts = lut['count'].sum()
    lut['cumsum'] = lut['count'].cumsum()
    lut['coverage'] = lut['cumsum'] / total_pkts
    lut['pct_items'] = (np.arange(1, len(lut) + 1) / len(lut)) * 100

    # 帕累托关键指标: 前20%的key覆盖了多少流量
    top20_pct = int(len(lut) * 0.2)
    top10_pct = int(len(lut) * 0.1)
    top5_pct = int(len(lut) * 0.05)
    top1_pct = max(1, int(len(lut) * 0.01))

    cov_20 = lut.iloc[top20_pct]['coverage'] * 100 if top20_pct < len(lut) else 100
    cov_10 = lut.iloc[top10_pct]['coverage'] * 100 if top10_pct < len(lut) else 100
    cov_5  = lut.iloc[top5_pct]['coverage'] * 100 if top5_pct < len(lut) else 100
    cov_1  = lut.iloc[top1_pct]['coverage'] * 100 if top1_pct < len(lut) else 100

    unique_keys = len(lut)
    ranks = np.arange(1, len(lut) + 1)
    top80_idx = (lut['coverage'].values * 100 >= 80).argmax()
    top80_n = ranks[top80_idx]

    # 判断是否符合帕累托 (前20%覆盖>80%)
    is_pareto = cov_20 >= 80

    print(f"\n  {'='*55}")
    print(f"  {dataset_name}")
    print(f"  {'='*55}")
    print(f"  Total packets: {total_pkts:,}")
    print(f"  Unique patterns: {unique_keys:,}")
    print(f"  Patterns for 80% coverage: {top80_n:,} ({top80_n/unique_keys*100:.1f}%)")
    print(f"  Top 1%  patterns cover: {cov_1:.1f}%")
    print(f"  Top 5%  patterns cover: {cov_5:.1f}%")
    print(f"  Top 10% patterns cover: {cov_10:.1f}%")
    print(f"  Top 20% patterns cover: {cov_20:.1f}%")
    print(f"  Pareto confirmed: {is_pareto}")

    # ---- 点图 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    ax = axes[0]
    ax.plot(ranks, lut['coverage'] * 100, 'b-', linewidth=1.5, alpha=0.8)
    ax.axhline(y=80, color='r', linestyle='--', alpha=0.5, label='80% coverage')
    ax.axvline(x=top80_n, color='g', linestyle='--', alpha=0.5, label=f'{top80_n:,} patterns')
    ax.set_xlabel('Number of Feature Patterns (sorted by frequency)')
    ax.set_ylabel('Cumulative Coverage (%)')
    ax.set_title(f'{dataset_name}\nPareto Distribution')
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    # 图2: 频率排名 (log-log)
    ax = axes[1]
    ax.loglog(ranks, lut['count'].values, 'b.', markersize=1.5, alpha=0.5)
    ax.set_xlabel('Pattern Rank (log)')
    ax.set_ylabel('Frequency (log)')
    ax.set_title(f'{dataset_name}\nFrequency-Rank (log-log)')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    safe_name = dataset_name.replace(' ', '_').replace('/', '_')
    fig_path = output_dir / f'{safe_name}_pareto.png'
    plt.savefig(fig_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Plot saved: {fig_path}")

    return {
        'name': dataset_name,
        'total': total_pkts,
        'unique': unique_keys,
        'cov_1': cov_1, 'cov_5': cov_5, 'cov_10': cov_10, 'cov_20': cov_20,
        'is_pareto': is_pareto
    }


# ============================================================
# Part 2: 各数据集处理
# ============================================================

def do_pcap_dataset(name, csv_path, feature_cols, output_dir):
    """处理PCAP数据集: bit转换 → 查找表 → 帕累托分析"""
    print(f"\n[PCAP] {name}")
    df = pd.read_csv(csv_path)

    # 只保留存在的列
    feats = [c for c in feature_cols if c in df.columns]
    print(f"  Features: {len(feats)}")

    # 转bit
    df = fields_to_bits(df, feats)

    # 保存bit版本
    bit_path = output_dir / f'{name}_bits.csv'
    label_cols = [c for c in ['label','src_file'] if c in df.columns]
    df[feats + label_cols].to_csv(bit_path, index=False)
    print(f"  Bit version: {bit_path}")

    # 查找表
    lut = build_lookup_table(df, feats)
    lut_path = output_dir / f'{name}_lookup_table.csv'
    lut.to_csv(lut_path)
    print(f"  Lookup table: {lut_path} ({len(lut)} entries)")

    # 帕累托分析
    result = pareto_analysis(lut, name, output_dir)
    return result


def do_flow_dataset(name, csv_path, feature_cols, label_col, output_dir):
    """处理流数据集: 选特征 → 查找表 → 帕累托分析"""
    print(f"\n[FLOW] {name}")
    df = pd.read_csv(csv_path)

    feats = [c for c in feature_cols if c in df.columns]
    print(f"  Features: {len(feats)}")

    # 离散化连续值 → 减少组合数
    df_work = df[feats].copy()
    for c in feats:
        if df_work[c].dtype in ['int64','float64']:
            unique_n = df_work[c].nunique()
            if unique_n > 100:
                # 分10个桶
                try:
                    df_work[c] = pd.qcut(df_work[c], q=10, labels=False, duplicates='drop')
                except:
                    df_work[c] = (df_work[c] / df_work[c].std()).astype(int)
        df_work[c] = df_work[c].astype(str)

    # 查找表
    keys = df_work.astype(str).agg(''.join, axis=1)
    counts = keys.value_counts().head(100000)
    lut = counts.reset_index()
    lut.columns = ['feature_key', 'count']
    lut = lut.sort_values('count', ascending=False).reset_index(drop=True)

    lut_path = output_dir / f'{name}_lookup_table.csv'
    lut.to_csv(lut_path)
    print(f"  Lookup table: {lut_path} ({len(lut)} entries)")

    result = pareto_analysis(lut, name, output_dir)
    return result


# ============================================================
# Main
# ============================================================
def main():
    results = []
    output_dir = OUT

    # 协议头部字段中选稳定的流标识字段 (排除每包不同的seq/ack/id/checksum/length)
    # 5-tuple + MAC + TTL + flags + window
    stable_fields = [
        # L2: MAC (同网段稳定)
        'eth_dst', 'eth_src',
        # L3: 5-tuple核心
        'ip_src', 'ip_dst', 'ip_proto', 'ip_ttl',
        # L4 TCP: 端口+标志+窗口 (流内稳定)
        'tcp_sport', 'tcp_dport', 'tcp_flags', 'tcp_window',
        # L4 UDP: 端口
        'udp_sport', 'udp_dport',
    ]

    # === 4个PCAP数据集 ===
    # ISCX_VPN + CTU-13 用 stable_fields (已确认有帕累托)
    pcap_datasets = [
        ('ISCX_VPN', BASE/'iscxvpn'/'iscx_protocol_headers.csv', stable_fields),
        ('CTU-13',   BASE/'CTU-13'/'ctu13_protocol_headers.csv', stable_fields),
    ]
    for name, path, feats in pcap_datasets:
        if path.exists():
            r = do_pcap_dataset(name, path, feats, output_dir)
            results.append(r)

    # === MAWI + USTC 换多种特征组合 ===
    # MAWI: 骨干网流量, IP太分散 → 去掉IP和MAC, 只留端口+协议+TTL+flags
    mawi_feat_sets = {
        'MAWI_noIP':   ['ip_proto','ip_ttl','tcp_sport','tcp_dport','tcp_flags','tcp_window','udp_sport','udp_dport'],
        'MAWI_svc':    ['ip_proto','tcp_dport','udp_dport'],  # 服务级(协议+目的端口)
        'MAWI_5tuple': ['ip_src','ip_dst','ip_proto','tcp_sport','tcp_dport','udp_sport','udp_dport'],  # 5-tuple无MAC
    }
    for suffix, feats in mawi_feat_sets.items():
        name = f'MAWI_{suffix}'
        path = BASE/'MAWI'/'mawi_protocol_headers.csv'
        if path.exists():
            r = do_pcap_dataset(name, path, feats, output_dir)
            results.append(r)

    # USTC: 应用流量, MAC因机器而异 → 去掉MAC, IP试
    ustc_feat_sets = {
        'USTC_svc':       ['ip_proto','tcp_dport','udp_dport'],  # 纯服务 (协议+目的端口)
        'USTC_srcSvc':    ['ip_src','ip_proto','tcp_dport','udp_dport'],  # 源+服务
        'USTC_portOnly':  ['tcp_sport','tcp_dport','udp_sport','udp_dport'],  # 仅端口
    }
    for suffix, feats in ustc_feat_sets.items():
        name = f'USTC_{suffix}'
        path = BASE/'USTC'/'ustc_protocol_headers.csv'
        if path.exists():
            r = do_pcap_dataset(name, path, feats, output_dir)
            results.append(r)

    # === 3个流数据集 ===
    flow_datasets = [
        ('NSL-KDD', BASE/'NSL_KDD-master'/'NSL_KDD.csv',
         ['protocol_type','service','flag','src_bytes','dst_bytes','land',
          'logged_in','count','srv_count','same_srv_rate',
          'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate'],
         'label'),
        ('UNSW-NB15', BASE/'UNSW'/'CSV Files'/'UNSW_NB15.csv',
         ['proto','service','state','sttl','dttl','swin','dwin',
          'ct_state_ttl','ct_dst_ltm','ct_src_ltm','ct_srv_dst',
          'is_ftp_login','is_sm_ips_ports','rate'],
         'label'),
        ('CIC-IDS-2017', BASE/'CIC-IDS 2017'/'CIC-IDS-2017.csv',
         ['Destination Port','Protocol','Fwd Header Length','Bwd Header Length',
          'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
          'ACK Flag Count','URG Flag Count','Flow Duration','Flow Bytes/s',
          'Flow Packets/s','Average Packet Size'],
         'Label'),
    ]
    for name, path, feats, lbl in flow_datasets:
        if path.exists():
            r = do_flow_dataset(name, path, feats, lbl, output_dir)
            results.append(r)

    # === 汇总表 ===
    print("\n" + "="*80)
    print("PARETO ANALYSIS SUMMARY")
    print("="*80)
    print(f"{'Dataset':<20s} {'Total':>10s} {'Unique':>8s} {'Top1%':>7s} {'Top5%':>7s} {'Top10%':>7s} {'Top20%':>7s} {'Pareto':>7s}")
    print("-"*80)
    for r in results:
        print(f"{r['name']:<20s} {r['total']:>10,} {r['unique']:>8,} "
              f"{r['cov_1']:>6.1f}% {r['cov_5']:>6.1f}% {r['cov_10']:>6.1f}% {r['cov_20']:>6.1f}% "
              f"{'YES' if r['is_pareto'] else 'NO':>7s}")

    # 保存汇总
    pd.DataFrame(results).to_csv(output_dir/'pareto_summary.csv', index=False)
    print(f"\nAll results in: {output_dir}")

if __name__ == '__main__':
    main()

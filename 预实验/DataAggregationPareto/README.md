# Data Aggregation Pareto Experiment

Convert protocol header fields to binary representation, count feature pattern frequencies, sort descending, verify Pareto distribution.

## Method

1. Scapy parses PCAP -> extract 32 standard protocol header fields
2. Select stable flow-identifying fields (exclude per-packet seq/ack/id/checksum)
3. Field values -> binary bit strings (IP 32bit, Port 16bit, Protocol 8bit, etc.)
4. Concatenate all field bit strings -> feature pattern key
5. Count frequencies -> sort descending -> compute cumulative coverage

## Files

| File | Description |
|------|-------------|
| `ISCX_VPN_12f.png` | ISCX VPN (12 fields, 320bit, 593K packets) |
| `CTU-13_12f.png` | CTU-13 botnet (12 fields, 320bit, 30K packets) |
| `MAWI_3f_7.5M.png` | MAWI backbone (3 fields, 40bit, 7.5M packets) |
| `MAWI_8f_full.png` | MAWI backbone (8 fields, 104bit, 3.55M packets full) |
| `USTC_3f.png` | USTC app traffic (3 fields, 40bit, 110K packets) |
| `CIC-IDS-2017_13f.png` | CIC-IDS 2017 (13 flow features, 3.46M flows) |
| `NSL-KDD_8f.png` | NSL-KDD (8 categorical features, 148K flows) |
| `UNSW-NB15_7f.png` | UNSW-NB15 (7 categorical features, 257K flows) |
| `IOT23_field_comparison.png` | IOT23 field count comparison (3f/5f/6f/8f) |
| `_results.csv` | All datasets Pareto results summary |
| `pareto_summary.csv` | Pareto key indicators |

## Conclusion

All 8 datasets confirm: **a very small fraction of high-frequency patterns covers the vast majority of network traffic**, providing experimental support for P2TN2's lookup table compression.

## Protocol Field Bit Widths

| Field | Bits | Field | Bits |
|------|------|------|------|
| MAC | 48 | IP | 32 |
| Port | 16 | Protocol | 8 |
| TTL | 8 | TCP Flags | 8 |
| TCP Window | 16 | | |

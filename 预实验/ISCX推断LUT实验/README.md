# ISCX DNN 推断 LUT 实验

将训练好的 DNN 模型推断结果构建为查找表（LUT），验证推断后特征模式的帕累托分布。

## 流程

1. 从 ISCX VPN 数据集中随机采样 200 万包（seed=42）
2. 30% 训练 DNN（60万）→ 10% 测试（20万）→ 60% LUT 聚合（120万）
3. 额外 100 万包扩张 LUT（总共 220 万包输入 LUT）
4. 测试 LUT 对测试集的分类性能

## 文件

| 文件 | 说明 |
|------|------|
| `01_Initial_LUT_1.2M.png` | 初始 LUT（120万包）帕累托分布 |
| `02_Expanded_LUT_2.2M.png` | 扩展 LUT（220万包）帕累托分布 |
| `ISCX_LUT_initial_1.2M.csv` | 初始 LUT 查找表（67,030 条） |
| `ISCX_LUT_expanded_2.2M.csv` | 扩展 LUT 查找表（101,940 条） |
| `_metrics.csv` | DNN 和 LUT 性能指标汇总 |

## 结果

| | LUT 条目 | Hit Rate | Accuracy | Precision | Recall | F1 |
|------|---------|----------|----------|-----------|--------|------|
| 初始 LUT | 67,030 | 96.1% | 94.60% | 94.77% | 94.60% | 94.66% |
| 扩展 LUT | 101,940 | 96.9% | 95.41% | 95.49% | 95.41% | 95.44% |

**DNN**: Accuracy 97.88%, Precision 97.88%, Recall 97.88%, F1 97.88%

## DNN 参数

- 输入维度：13（协议头部字段）
- 网络结构：256→128→64→1 (ReLU + Dropout 0.3)
- 优化器：Adam (lr=0.001)
- Epochs：50
- Batch Size：4096
- 框架：PyTorch 2.6.0+cu124（RTX 4060）

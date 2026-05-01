# API Lab Builder (Layer1 + Layer2)

本目录提供“线性分层增量”流程中的前四步：

1. `step0_freeze.py`：配置冻结与结构门控。
2. `layer1_generate.py`：按算法分支执行 Layer1 条件组合生成，直接冲突剪枝 + 去重。
3. `layer1_write_sample.py`：将 Layer1 样本池抽样转写为实际 `php/js` 代码并写入目标站点。
4. `layer2_generate.py`：在 Layer1 池基础上增量扩展 2.3+2.8，使用贪心 3-wise 覆盖并去重。
5. `layer2_write_sample.py`：把 Layer2 抽样写入平行路径（`layer2_*`），不与 layer1 串样本。

说明：Layer1 固定 `route_variant=PLAIN_ROUTE`，不展开路由维度；路由翻倍在 Layer5 执行。

## 配置文件

- `configs/api_lab_builder_step0.yaml`

## 运行

```powershell
python scripts/api_lab_builder/step0_freeze.py --config configs/api_lab_builder_step0.yaml
python scripts/api_lab_builder/layer1_generate.py --config configs/api_lab_builder_step0.yaml
python scripts/api_lab_builder/layer1_write_sample.py --config configs/api_lab_builder_step0.yaml --sample-size 5
python scripts/api_lab_builder/layer2_generate.py --config configs/api_lab_builder_step0.yaml
python scripts/api_lab_builder/layer2_write_sample.py --config configs/api_lab_builder_step0.yaml --sample-size 5
```

## 产物

- `runtime/api_lab_builder/step0_frozen_config.yaml`
- `runtime/api_lab_builder/step0_gate_report.json`
- `runtime/api_lab_builder/layer1_pool.yaml`
- `runtime/api_lab_builder/layer1_pool.json`
- `runtime/api_lab_builder/layer1_gate_report.json`
- `runtime/api_lab_builder/layer1_pruned_reasons.jsonl`
- `runtime/api_lab_builder/layer1_sample_pool.yaml`
- `runtime/api_lab_builder/layer1_sample_gate_report.json`
- `runtime/api_lab_builder/layer1_sample_write_manifest.json`
- `runtime/api_lab_builder/layer2_pool.yaml`
- `runtime/api_lab_builder/layer2_pool.json`
- `runtime/api_lab_builder/layer2_gate_report.json`
- `runtime/api_lab_builder/layer2_pruned_reasons.jsonl`
- `runtime/api_lab_builder/layer2_sample_pool.yaml`
- `runtime/api_lab_builder/layer2_sample_gate_report.json`
- `runtime/api_lab_builder/layer2_sample_write_manifest.json`


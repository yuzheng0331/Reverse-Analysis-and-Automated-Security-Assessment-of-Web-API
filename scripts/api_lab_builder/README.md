# API Lab Builder (Layer1)

本目录提供“线性分层增量”流程中的前两步：

1. `step0_freeze.py`：配置冻结与结构门控。
2. `layer1_generate.py`：按算法分支执行 Layer1 条件组合生成，直接冲突剪枝 + 去重。

## 配置文件

- `configs/api_lab_builder_step0.yaml`

## 运行

```powershell
python scripts/api_lab_builder/step0_freeze.py --config configs/api_lab_builder_step0.yaml
python scripts/api_lab_builder/layer1_generate.py --config configs/api_lab_builder_step0.yaml
```

## 产物

- `runtime/api_lab_builder/step0_frozen_config.yaml`
- `runtime/api_lab_builder/step0_gate_report.json`
- `runtime/api_lab_builder/layer1_pool.yaml`
- `runtime/api_lab_builder/layer1_pool.json`
- `runtime/api_lab_builder/layer1_gate_report.json`
- `runtime/api_lab_builder/layer1_pruned_reasons.jsonl`



##  系统架构设计与实现
###  总体架构设计
本系统由“API 生成器”和“API 评估器”两个子系统构成，形成“样本构造—动态捕获—一致性验证—安全评估—报告生成”的闭环。
其中，生成器负责构造可控的多层样本 API 与页面入口；评估器负责从静态分析与动态捕获出发，对端点进行场景化安全评估并输出报告。系统总入口见 phases/run_full_pipeline.py 的 main。

#### (1) 宏观数据流与交互关系

生成器链路（离线构造为主）
配置冻结（Step0）→ Layer1 条件组合生成 → Layer2 增量扩展（3-wise）→ Layer3 弱设计注入（1-wise）→ 抽样写入目标站点（PHP/JS）。
关键产物位于 runtime/api_lab_builder/，如 layer1_pool.yaml、layer2_pool.yaml、layer3_pool.yaml、layer3_control_mapping.json。

评估器链路（在线验证为主）
Phase1 静态分析 → Phase2 生成 baseline skeleton 并填充账号口令 → Phase3 Playwright 捕获回填运行时参数 → Phase4 本地 Handler 一致性验证 → Phase5 场景化安全评估打分 → Phase6 报告与图表。
关键中间件为 baseline_samples/baseline_skeletons_*.json 与 assessment_results/assessment_profile_*.json。

两个子系统的耦合点
生成器写入的页面（如 generated_layer1_sample.php）可作为评估器输入 URL。
评估器并不直接依赖生成器脚本，但通过统一目标站点与 baseline 机制间接联通。

#### (2) API 生成器架构图（Mermaid）

```mermaid
flowchart TD
    A[configs/api_lab_builder_step0.yaml] --> B[step0_freeze.py]
    B --> C[layer1_generate.py]
    C --> D[layer2_generate.py]
    D --> E[layer3_generate.py]
    E --> F[layer1/2/3_write_sample.py]
    F --> G[Target Site: generated_layerN_sample.php + generated JS]
    C --> H[runtime/api_lab_builder/layer1_pool.yaml|json]
    D --> I[runtime/api_lab_builder/layer2_pool.yaml|json]
    E --> J[runtime/api_lab_builder/layer3_pool.yaml|json + gate report]
```

#### (3) API 评估器架构图（Mermaid）

```mermaid
flowchart TD
    A[run_full_pipeline.py] --> P1[Phase1 static_analyze.py]
    P1 --> P2[Phase2 init_baselines.py + fill_login_payloads]
    P2 --> P3[Phase3 capture_baseline_playwright.py]
    P3 --> P4[Phase4 verify_handlers.py]
    P4 --> P5[Phase5 assess_endpoint.py]
    P5 --> P6[Phase6 report_gen.py + charts]

    P2 --> B[baseline_skeletons_*.json]
    P3 --> B
    P4 --> B
    B --> P5
    P5 --> C[assessment_profile_default|paper_v1.json]
    C --> P6
    P6 --> D[report/*.html|md|json + charts/*]
```

###  API 生成器设计与实现
####  功能描述
API 生成器核心任务是：将“密码算法组合、动态材料来源、防重放、打包与传输策略、弱设计注入”等维度参数化，自动产出可落地执行的实验样本池，并进一步写入实际可调用的 PHP/JS 端点。
对应实现主链见 scripts/api_lab_builder/step0_freeze.py、layer1_generate.py、layer2_generate.py、layer3_generate.py 与 layer1_write_sample.py 的 run_layer_write_sample。
#### 配置分析
统一配置文件为 configs/api_lab_builder_step0.yaml，核心结构如下：
global：站点组、路由白名单、算法白名单；
field_rules：字段全集、依赖约束（如 material_dynamicity_profile 与 anti_replay 联动）；
layer_blueprint：各 layer 激活维度与冻结默认值；
layer1/layer2/layer3：分层生成策略与覆盖约束；
output：池文件、门控报告、剪枝原因、控制映射输出路径；
writer：抽样写入规模、模板位置、目标页面与 JS 产物命名。
与初始规划存在调整：当前代码已显式包含 layer4/layer5配置占位，但主生成脚本实际实现集中在 Layer1~Layer3（见 scripts/api_lab_builder 目录）。
#### 模块划分
配置门控模块：step0_freeze.py
run_step0_freeze 执行结构校验、依赖合法性检查并冻结配置；
样本池生成模块：layer1_generate.py / layer2_generate.py / layer3_generate.py
Layer1：按算法矩阵笛卡尔组合并冲突剪枝；
Layer2：在 Layer1 基础上做增量维度扩展与 3-wise 贪心覆盖；
Layer3：模板化弱设计注入、control/risk 同构映射与 gate 校验；
样本写入模块：layer1_write_sample.py（Layer2/3复用）
run_layer_write_sample 将样本生成 PHP 端点与 JS 调用函数，并注入页面按钮入口；
公共能力模块：common.py
YAML/JSON 序列化、去重键 dedupe_key、剪枝记录结构 PruneRecord。
####  运作流程
Step0 对配置做“先验可执行性校验”；
Layer1 按算法分支生成基础稳定池，执行冲突规则过滤与去重；
Layer2 以 Layer1 为基底做组合扩展，通过 _greedy_twise_select 控制样本规模并保证覆盖；
Layer3 在 Layer2 上执行风险模板与弱设计注入，建立 control_mapping，并以 gate（如可检测弱设计比例）控制输出有效性；
写入阶段按算法抽样，将样本映射为真实端点文件与页面入口，输出 manifest 供追踪。
####  关键技术/算法
条件组合 + 规则剪枝（见 layer1_generate.py 的 _product_dict、_check_conflicts）；
基于哈希规范化去重（见 common.py 的 dedupe_key）；
贪心 3-wise 覆盖选择（见 layer2_generate.py 的 _greedy_twise_select）；
强制字段值覆盖与控制样本注入（见 layer2_generate.py 的 _ensure_field_value_coverage、_ensure_control_coverage）；
弱设计注入与同构控制映射（见 layer3_generate.py 的 _apply_weak_option、_build_control_mapping）；
模板化代码生成（PHP/JS）与站点落地写入（见 layer1_write_sample.py 的 _render_php_endpoint、_render_js_function）。
 
###  API 评估器设计与实现
####  功能描述
评估器负责将“静态分析结构化结果 + 动态捕获运行时参数 + 本地重放能力 + 真实请求反馈”融合到统一评估报告中。
入口为 phases/run_full_pipeline.py，评估核心在 assess/assess_endpoint.py 的 BaselineAssessmentEngine.assess。
####  模块划分及分工
Phase1 静态分析：collect/static_analyze.py
构建端点、函数、加密模式映射，输出 static_analysis_*.json。
Phase2 基线生成：scripts/init_baselines.py
依据静态分析构建 execution_flow、runtime_args、dynamic hint。
Phase3 动态捕获：scripts/capture_baseline_playwright.py
回填运行时参数、抓取请求轨迹。
Phase4 Handler 验证：handlers/pipeline.py + scripts/verify_handlers.py
用本地原语流水线重放并与捕获值对比，形成 validation.verified。
Phase5 安全评估：assess/assess_endpoint.py
场景生成、门控、远程发送、预期匹配、发现聚合、分层打分。
Phase6 报告生成：assess/report_gen.py
生成 HTML/Markdown/JSON 与图表。
####  运作流程与参数透传
在 run_full_pipeline.py 中，核心参数向下透传：
--phase3-concurrency --phase3-settle-ms --phase3-nav-timeout-ms --phase3-no-algo-batch → run_phase3；
--phase5-timeout --phase5-include-unverified --phase5-enhanced-fuzz-mode → run_phase5；
--layer 可推断目标 URL generated_layer{N}_sample.php。
Phase5 内部流程（_assess_entry）：
识别动态端点与服务端依赖型动态端点；
构造场景集（普通/PasswordPreHash 特例）；
执行本地重放并形成 local_gate（SENDABLE、UNMUTATABLE、MUTATION_NOT_EFFECTIVE 等）；
对可发送场景执行真实请求并做三层响应分类（协议/结构/语义）；
计算 interlayer effectiveness、session binding、signature bypass 等风险并汇总分数。
####  评分规则说明（当前实现口径）
当前评分由 configs/scoring_profiles.yaml 配置驱动，核心逻辑见 assess_endpoint.py 的 _calculate_security_score、_score_to_risk：
总分从 base_score 起（默认 100）；
扣分项包含：
发现项严重度×类别系数；
场景期望失配扣分（按远程参与池等额分配）；
baseline 结构缺口惩罚（含上限）；
interlayer 状态系数与端点级附加罚分；
输出协议层/业务层子分（layer_score_weights 控制权重）；
最终风险分级按阈值映射（low/medium/high/critical）。
重要说明：目前系统使用的是“配置化初版加权扣分模型”，属于论文实现阶段的简化评分体系；设计中的最终评分体系尚未引入代码主干。
####  关键技术/算法
AST + 正则混合静态分析（collect/static_analyze.py）；
基于 execution_flow 的本地可重放执行器（LocalFlowExecutor.execute）；
场景化变异与请求篡改（_build_scenarios、_apply_request_tamper）；
三层响应判定模型（build_response_layers + classify_response_mode）；
动态端点 fresh capture 策略（_fresh_capture_dynamic_entry 及并行版本）；
插件式加密原语注册表（handlers/registry.py + handlers/operations.py）。
 

##  实验测试与结果分析

### 4.1 实验环境说明

- **硬件环境**：
    - CPU：Intel Core i7-12700H
    - 内存：32GB
    - 存储：1TB SSD
    - 网络：千兆有线/无线局域网
- **软件环境**：
    - 操作系统：Windows 11 22H2
    - Python：3.10.12
    - Node.js：18.x
    - 主要依赖库：rich、playwright、requests、beautifulsoup4、PyYAML、dotenv 等
    - 浏览器驱动：Chromium（Playwright自动安装）
- **系统部署**：
    - 项目目录结构见第2章，所有依赖通过 requirements.txt 和 package.json 安装
    - 环境变量通过 .env 文件统一管理
    - 本地自建靶场与自动生成的测试页面/端点

### 4.2 实验数据与测试集

- **测试站点/接口**：
    - 采用自动生成的 Layer1/Layer2/Layer3 页面及端点，覆盖多种加密、打包、动态参数、防重放等组合
    - 端点总数：如 30~100 个（视生成规模）
- **样本池与基线**：
    - runtime/api_lab_builder/layer*_pool.yaml|json
    - baseline_samples/baseline_skeletons_*.json
    - collect/static_analysis_*.json
    - assessment_results/assessment_profile_*.json

### 4.3 实验方案设计

- **基础链路实验**：
    - 固定单一站点、单一 URL，完整跑通 Phase1~Phase6，验证系统闭环
- **分层能力实验**：
    - 分别对 Layer1/Layer2/Layer3 页面独立评估，比较场景可发送率、命中率、评分变化、高危发现占比
- **分层维度实验**：
    - 基于 api_lab_builder_step0.yaml，分别激活/冻结不同参数维度，考察剪枝、覆盖、gate 通过率等
- **人工 vs 自动化效率对比**：
    - 统计人工逆向+用例构造与自动化流程的总耗时、人均错误修正次数
- **消融/敏感性实验**：
    - 比较增强模糊模式、纳入未验证端点、评分profile切换等对评估结果的影响
- **能力矩阵对比**：
    - 与文献代表方案做功能完备性对比

### 4.4 实验结果展示

- **评估摘要表**：
    - 端点总数、场景数、发现数、总体/分层评分、各等级分布
- **分层/参数对比**：
    - Layer1/2/3 不同配置下的 SENDABLE 占比、命中率、分数变化
- **人工与自动化效率表**：
    - 见下表：

| 方案         | 端点数 | 逆向分析时间(min) | 用例构造时间(min) | 总时间(min) | 人均错误修正次数 |
| ------------ | ------ | ---------------- | ---------------- | ----------- | --------------- |
| 人工流程     |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
| 自动化流程（本系统） |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |

- **能力矩阵**：

| 能力项             | 本系统 | 方案A | 方案B | 方案C |
| ------------------ | ------ | ----- | ----- | ----- |
| 静态端点-加密映射  | √      |       |       |       |
| 动态参数捕获回填   | √      |       |       |       |
| 本地可重放验证     | √      |       |       |       |
| 场景化协议篡改     | √      |       |       |       |
| 分层响应语义判定   | √      |       |       |       |
| 报告自动生成       | √      |       |       |       |

- **典型案例分析**：
    - 选取典型端点，展示完整评估流程、响应判定与安全发现

### 4.5 结果分析与讨论

- **系统有效性分析**：
    - 自动化流程的闭环性、发现能力、评分合理性
- **消融/敏感性实验分析**：
    - 增强模糊、未验证端点纳入、评分profile切换等对结果的影响
- **不足与改进空间**：
    - 当前系统的局限性、未来可优化方向

---
## 下一章：系统实验测试建议

1）先做基础本地靶场，再扩展三层实验（建议主线）

基线实验（必做）：固定单一站点、单一 URL，完整跑通 Phase1~Phase6，确认链路闭环；

层级实验（扩展）：分别对 Layer1/Layer2/Layer3 页面做独立评估，并比较：
- 场景可发送率（SENDABLE 占比）；
- 预期命中率；
- 评分变化（总体/协议/业务）；
- 高危发现占比。

2）基于 api_lab_builder_step0.yaml 的分层维度实验（对应参考1）

建议按“当前代码真实层定义”组织，而非沿用初版“8维×3层”的静态叙述：
- Layer1：算法参数与基础防重放组合稳定性实验；
- Layer2：material_source、packaging_type、content_type、key_location 等增量维度覆盖实验；
- Layer3：弱设计注入可检测率实验（对应 detectable_weak_ratio gate）。

可报告指标：候选数、剪枝数、最终样本数、value coverage 矩阵、gate 是否通过。

3）“人工 vs 自动化”效率对比（对应参考2）

建议记录“逆向分析+可评估用例构造”总耗时，按端点数分组统计。论文可直接使用下表：

| 方案         | 端点数 | 逆向分析时间(min) | 用例构造时间(min) | 总时间(min) | 人均错误修正次数 |
| ------------ | ------ | ---------------- | ---------------- | ----------- | --------------- |
| 人工流程     |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
| 自动化流程（本系统） |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |
|              |        |                  |                  |             |                 |

4）定性能力矩阵对比（对应参考3，不跑代码）

建议与文献中的代表方案做“功能完备性”对比，不比较性能：

| 能力项             | 本系统 | 方案A | 方案B | 方案C |
| ------------------ | ------ | ----- | ----- | ----- |
| 静态端点-加密映射  | √      |       |       |       |
| 动态参数捕获回填   | √      |       |       |       |
| 本地可重放验证     | √      |       |       |       |
| 场景化协议篡改     | √      |       |       |       |
| 分层响应语义判定   | √      |       |       |       |
| 报告自动生成       | √      |       |       |       |

5）建议新增的可行实验（当前系统即可实施）


- 评分 profile 稳健性实验：default vs paper_v1 在同一数据集上的排序一致性。


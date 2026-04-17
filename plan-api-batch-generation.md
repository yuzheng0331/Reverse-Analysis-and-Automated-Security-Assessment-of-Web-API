# 批量构造 API 样本计划书（参数驱动精简版）

## 0. 目标

在现有靶场服务器与现有流水线基础上，自动化批量生成可评估 API（目标总量 `900~1200`）至`E:\phpStudy\phpstudy_pro\WWW\encrypt-labs-main-1`，用于安全评估对比。
模板可以参考`E:\phpStudy\phpstudy_pro\WWW\encrypt-labs-main-1`路径下的easy.php和js/easy.js

核心交付：
1. 大规模 API 样本库（含无混淆/弱混淆版本）
2. 全链路可运行（静态分析 -> 基线 -> capture -> handler -> assess）
3. 可复现实验结果与评分对比

---

## 1. 生成总线（Spec-Driven）

统一采用规格驱动生成：

`lab_specs/*.yaml -> 生成前端函数+后端端点+路由 -> 批量评估`

每个 API 由以下字段描述：
- `algorithm_stack`
- `algo_params`
- `material_source`
- `material_dynamicity`
- `validation_hops`
- `anti_replay`
- `interlayers`
- `risk_tags`
- `route_variant`
- `site_group`

字段分组与约束口径：
- 必选字段：`algorithm_stack`、`algo_params`、`material_source`、`material_dynamicity`、`validation_hops`、`anti_replay`、`interlayers`、`risk_tags`。
- 条件字段：`signature_strategy`、`session_policy`、`template_level`（按算法/防重放/弱设计模板启用）。
- 固定字段：`site_group`（固定 `SITE_A`）、`route_variant`（固定在 `PLAIN_ROUTE/WEAK_OBF_ROUTE` 集合）。
- 关联关系：`algorithm_stack` 决定 `algo_params` 可选参数集合；`anti_replay` 决定 `material_dynamicity/session_policy` 的必需性；`template_level` 决定是否注入弱混淆模板。
- 互斥关系：`RSA_ONLY` 与对称参数（如 `mode/iv_policy/padding`）互斥；不合法组合在生成前剪枝。

---

## 2. 样本扩展维度

## 2.1 算法栈维度
- `DES`
- `AES`
- `RSA_ONLY`
- `AES_RSA_ENVELOPE`
- `PLAINTEXT_HMAC`

说明：`algorithm_stack` 仅表示“原语链/加密原语组合”，不在该维度内预设 `mode`、`padding`、`iv_policy` 等具体参数。
这些参数统一放在 `2.2 算法参数矩阵`。

## 2.2 算法参数矩阵维度（主扩样来源）

以 AES 为例：
- `key_size`: `128/192/256`
- `mode`: `CBC/CFB/OFB/CTR/GCM(可选)`
- `iv_policy`: `absent/static/random/derived/server_fetch`
- `padding`: `Pkcs7/ZeroPadding/NoPadding`
- `plaintext_encoding`: `utf8/json-string/base64-pre-encoded`
- `key_encoding`: `utf8/hex/base64`
- `iv_encoding`: `utf8/hex/base64`

说明：每新增一个可枚举参数，理论组合规模近似倍增或线性倍增，是扩样本的最高收益维度。

## 2.3 材料来源与动态性维度
- 材料来源：`FRONTEND_HARDCODED` / `FRONTEND_DERIVED` / `SERVER_INTERMEDIATE_FETCH`
- 材料动态性：`key/iv/nonce/timestamp/signature` 分别标注 `static|dynamic|absent`

说明：`2.3` 仅负责“材料从哪里来、生命周期如何”，不承载“是否启用防重放校验”的语义。

## 2.4 验证链路维度
- `single_hop`
- `two_hop`
- `three_hop_plus`

## 2.5 防重放与会话约束维度
- `none`
- `timestamp_only`
- `nonce_only`
- `nonce_timestamp`
- `nonce_timestamp_signature`
- `nonce_timestamp_signature_session_binding`
- 会话绑定：`bind_cookie / no_bind`


说明：`2.5` 仅负责“校验策略与会话约束”，不重复定义材料来源与编码参数。

## 2.6 夹层维度

夹层（Interlayer）定义：在主加密链前后插入附加处理层，使链路从 `A->B` 变为 `A->X->B` 或 `A->X->Y->B`。

可选夹层：
- `ENCODING_LAYER`（Base64/URL Encode）
- `ENVELOPE_LAYER`（AES 随机密钥 + RSA 包裹）
- `HEADER_SIGN_LAYER`（Header 动态签名）
- `CHAINED_TRANSFORM_LAYER`（toString/parse/slice/padEnd）

工程边界：主数据集建议 1~5 层夹层；超深链路作为边界样本单列。

## 2.7 路由混淆维度
- `PLAIN_ROUTE`：无混淆
- `WEAK_OBF_ROUTE`：弱混淆（字符串拼接、别名、轻包装）

该维度通常可直接把样本数近似翻倍。

## 2.8 打包与传输维度
- 打包形态：`json/urlencoded`
- 字段策略：`normal/alias`
- 传输头：`Content-Type` 多组合
- 关键字段分布：`header/cookie/body` 的不同落点

收敛策略（高价值优先，控制样本规模）：
- 主关键字段落点：`body`（主）、`header`（次）；`cookie` 仅作为边界样本。
- Content-Type 仅保留与打包形态一致的常用映射，禁止无意义交叉笛卡尔积。

## 2.9 弱设计/愚蠢设计维度
- 弱算法与固定材料：`DES-ECB/DES-CBC` 固定 key/iv、`AES-CBC` 固定 IV + 硬编码 key
- 弱签名设计：签名不覆盖关键字段、签名字段可覆盖、固定盐可重放
- 弱防重放设计：仅 timestamp 不校验窗口、仅 nonce 不做去重、可预测 nonce
- 解析歧义设计：冗余字段、重复字段导致服务端解析分叉

弱混淆模板（可枚举）：
- `BASELINE_NO_SHIFT`（无位移弱混淆）
- `WEAK_SHIFT_L1`（固定移位）
- `WEAK_SHIFT_L2`（分段移位）
- `WEAK_SHIFT_L3`（伪动态移位）

说明：弱设计与弱混淆作为正式扩展维度参与组合、筛选与评估，不再单列独立章节。

---

## 3. 术语统一

- `Layer`：线性分层增量阶段（`Layer 1` 到 `Layer 5`），按顺序执行。
- `预落地门控`：每轮落地前统一执行“配置冻结、冲突剪枝、去重、配额门控”。
- `Layer-N 样本池`：与分层一一对应的样本池命名（`layer1_pool` ... `layer5_pool`）。
- `route_variant`：路由展开维度（`PLAIN_ROUTE` / `WEAK_OBF_ROUTE`）。
- `template_level`：弱混淆模板层级（`BASELINE/L1/L2/L3`）。

## 3.1 字段唯一归属（固化）

- `algorithm_stack`：仅归属 `2.1`。
- `algo_params`：仅归属 `2.2`（密码学参数与编码参数，不含 anti_replay）。
- `material_source/material_dynamicity`：仅归属 `2.3`。
- `anti_replay/session_policy/signature_strategy`：仅归属 `2.5`。
- `packaging/transport`（如 Content-Type、字段分布）：仅归属 `2.8`。
- `risk_tags/template_level`：仅归属 `2.9`。

规则：同一语义字段只能在一个维度定义，其他维度仅可“引用”不可“重复声明”。

---

## 4. 生成策略（重梳理）

## 4.1 分层策略

增量覆盖规则：`Layer 1` 使用“按算法条件乘积求和 + 剪枝”，`Layer 2/3` 使用“预算约束的条件 t-wise 覆盖”，`Layer 4` 使用“1-wise 风险注入”，`Layer 5` 使用“配额化路由展开”。
总体原则：优先从 `Layer 2` 压缩规模（组合爆炸主来源），`Layer 1` 仅做小幅收敛，保持基础回归锚点稳定。

### Layer 1（基础稳定池）
- 涉及维度：`2.1 + 2.2 + 2.5`（其中 `2.2` 按算法分支处理；`2.4` 在 Layer1 固定为默认值，不计入激活维度）。
- 覆盖策略：按算法参数空间“条件乘积求和”（`sum(product | algorithm)`），再执行冲突剪枝与去重。
- 规模控制：仅保留常用安全参数主集（如 `CBC + Pkcs7 + utf8/json-string`），高争议参数（如 `NoPadding`）只保留边界配额。
- 目标：先得到高可运行率的 `layer1_pool` 稳定池作为回归锚点。

### Layer 2（增维扩展层）
- 涉及维度：在 Layer 1 冻结池基础上新增 `2.3 + 2.8`（每轮新增 1~2 个维度）。
- 覆盖策略：默认“`2-wise 主覆盖 + 3-wise 风险补点`”（保留高价值组合，抑制低意义爆炸）；若需纯 `3-wise`，必须施加严格 base 配额上限。
- 规模控制：
  - `material_source` 主集为 `FRONTEND_HARDCODED/FRONTEND_DERIVED`，`SERVER_INTERMEDIATE_FETCH` 仅边界配额。
  - `material_dynamicity` 主集为 `STATIC_LOCAL/NONCE_TIMESTAMP`，`SERVER_KEY_IV` 仅边界配额。
  - `packaging/transport` 仅保留常见且安全意义高的映射。
- 目标：逐轮增加组合覆盖，不一次性全量笛卡尔积。

### Layer 3（复杂链路层）
- 涉及维度：在 Layer 2 冻结池基础上叠加 `2.6 + 2.4 + 2.5`（重点关注变量桥接/跨步依赖）。
- 覆盖策略：条件 `3-wise`，但按风险优先级限额注入（禁止全量叠加）。
- 目标：覆盖复杂执行流并验证流水线稳定性边界。

### Layer 4（弱混淆与风险层）
- 涉及维度：注入 `2.9`（弱设计/弱混淆模板），并保持与上一层样本的风险联动。
- 覆盖策略：`1-wise` 风险注入（规模近似为 `1-wise × Layer3`，并受弱样本配额约束）。
- 目标：保证弱样本持续参评并维持配额。

### Layer 5（路由展开层）
- 涉及维度：`2.7`。
- 覆盖策略：配额化展开（高风险样本优先展开，低价值重复样本可不展开），不强制全量翻倍。
- 目标：在不扩站点的情况下实现路由级翻倍覆盖。

执行原则：每完成一层算一轮，必须先测试再进入下一层；未达标则只回退该轮新增维度。

## 4.2 冗余与重复策略（细化）

本项目允许冗余与部分重复样本，目的是扩大对比数据集。允许情况：
- 同风险标签、不同实现细节
- 同逻辑、不同路由混淆版本
- 同算法、不同参数矩阵配置
- 弱设计、愚蠢设计、低质量实现

去重规则升级：
- 基础去重：删除“完全同配置 + 同路由 + 同模板”的重复实例。
- 语义去重：对“字段别名差异但安全语义等价”的样本，仅保留代表样本 + 少量变体。
- 跨层去重：Layer2 及后续层必须与上一层样本池执行去重检查，避免“增量维度未生效”导致的伪新增。

## 4.3 分层执行映射

线性执行关系如下：
- `Layer 1`：条件乘积求和生成 `layer1_pool` 并测试。
- `Layer 2`：基于 `layer1_pool` 做条件 `3-wise` 增量扩展并测试，生成 `layer2_pool`。
- `Layer 3`：基于 `layer2_pool` 做条件 `3-wise` 复杂链路扩展并测试，生成 `layer3_pool`。
- `Layer 4`：执行 `1-wise` 弱样本注入并测试。
- `Layer 5`：执行路由展开、写入目标站点并进入评估。
- 任一层门控失败：只回退当前层新增样本，不回退已通过层的冻结快照。

## 4.4 文件落地时机（何时生成到具体文件）

- 线性分层增量落地采用两阶段：`抽样写入 -> 抽样测试 -> 全量写入 -> 全量测试`。
- 每层落地前统一执行门控（配置冻结、冲突剪枝、去重、配额门控）；门控失败则不进入写入阶段。
- 抽样测试通过前，不允许进入下一层，也不允许做当前层全量写入。
- 每层样本池产物建议命名为：
  - `runtime/api_lab_builder/layer1_pool.yaml`
  - `runtime/api_lab_builder/layer2_pool.yaml`
  - `runtime/api_lab_builder/layer3_pool.yaml`
  - `runtime/api_lab_builder/layer4_pool.yaml`
  - `runtime/api_lab_builder/layer5_pool.yaml`
- 每层抽样产物建议命名为：
  - `runtime/api_lab_builder/layerN_sample_pool.yaml`
  - `runtime/api_lab_builder/layerN_sample_gate_report.json`
- 门控产物建议命名为：
  - `runtime/api_lab_builder/layerN_gate_report.json`
  - `runtime/api_lab_builder/layerN_pruned_reasons.jsonl`
- 每层写入代码端 API 文件到目标站点：
  - `E:/phpStudy/phpstudy_pro/WWW/encrypt-labs-main-1/encrypt/generated/*.php`
  - `E:/phpStudy/phpstudy_pro/WWW/encrypt-labs-main-1/js/generated_*.js`

## 5. 样本约束与配置

## 5.1 全局约束
- 固定 `site_group=SITE_A`，不做站点扩展。
- 固定 `route_variant in {PLAIN_ROUTE, WEAK_OBF_ROUTE}`。
- 算法白名单：`DES_CBC/AES_CBC/RSA_ONLY/AES_RSA_ENVELOPE/PLAINTEXT_HMAC`。
- 夹层上限：`interlayers <= 5`（主数据集建议 1~3）。
- 去重键：`algorithm_stack + algo_params + material_source + anti_replay + interlayers + route_variant + template_level`。
- 字段约束与第1节一致：必选字段必须完整，条件字段按关联关系启用，固定字段不可漂移。
- 冲突处理语义统一：命中任一冲突规则即直接剪枝（无优先级、无降级路径）。

## 5.2 生成前冲突剪枝
- 互斥规则（命中即剪枝）：
  - `RSA_ONLY` 不能携带对称参数（`mode/iv_policy/padding`）。
  - `PLAINTEXT_HMAC` 不能声明对称加密参数（`key_size/mode/iv_policy/padding`）。
  - `AES`/`DES` 必须声明 `mode`；其中 `AES`/`DES` 在 `CBC/CFB/OFB/CTR` 下要求 `iv_policy != absent`。
  - `route_variant` 与 `site_group` 偏离固定集合直接剪枝。
  - 命中 `UNSUPPORTED_COMPLEX_CUSTOM_CRYPTO` 标记直接剪枝。
- 依赖规则（缺失即剪枝）：
  - `NoPadding` 仅允许块对齐明文，不满足剪枝。
  - `anti_replay=timestamp_only` 必须提供 `timestamp != absent`。
  - `anti_replay=nonce_only` 必须提供 `nonce != absent`。
  - `anti_replay=nonce_timestamp` 必须同时提供 `nonce/timestamp != absent`。
  - `anti_replay=nonce_timestamp_signature` 必须同时提供 `nonce/timestamp/signature != absent`，且存在 `signature_strategy.placement`。
  - `anti_replay=nonce_timestamp_signature_session_binding` 还必须 `session_policy.binding=bind_cookie`。
  - `material_dynamicity_profile=SERVER_KEY_IV` 时，`material_source` 必须为 `SERVER_INTERMEDIATE_FETCH`，且 `algo_params.iv_policy=server_fetch`。
  - `material_dynamicity_profile=NONCE_TIMESTAMP` 时，`algo_params.iv_policy` 允许一对多 `{random, derived}`（配置驱动）。
  - `material_dynamicity_profile=STATIC_LOCAL` 时，`algo_params.iv_policy=static`。
- 字段归属规则（越权即剪枝）：
  - `algo_params` 禁止出现 `anti_replay/material_source/material_dynamicity/signature_strategy/session_policy` 字段。
  - `signature_strategy` 仅允许 `coverage/placement`，绑定语义必须写在 `anti_replay/session_policy`。

## 5.3 字段-维度映射总表（清晰口径）

- `algorithm_stack` -> `2.1`
- `algo_params.{key_size,mode,iv_policy,padding,plaintext_encoding,key_encoding,iv_encoding}` -> `2.2`
- `material_source/material_dynamicity` -> `2.3`
- `validation_hops` -> `2.4`
- `anti_replay/session_policy/signature_strategy` -> `2.5`
- `interlayers` -> `2.6`
- `route_variant` -> `2.7`
- `packaging/transport` -> `2.8`
- `risk_tags/template_level` -> `2.9`

注：生成器配置中若为了组合便利把 `anti_replay` 写在矩阵中，语义仍归属 `2.5`，不视为归属冲突。

## 5.4 分层门控配置
- `Layer 1` 门控：完成条件生成、冲突剪枝与去重后生成 `layer1_pool`，再执行抽样写入与测试。
- `Layer 2` 门控：满足“主覆盖（2-wise）+ 风险补点（3-wise）”目标，且剪枝后存在有效新增；必须先通过抽样测试。
- `Layer 3` 门控：满足条件 `3-wise` 风险限额覆盖，且剪枝后存在有效新增；必须先通过抽样测试。
- `Layer 4` 门控：弱样本配额必须满足（`weak_selected > 0` 且 `weak_quota_met=true`），先抽样后全量。
- `Layer 5` 门控：仅对通过前序门控且通过抽样测试的样本执行路由配额展开与全量站点落地。

建议样本预算（用于控量到 900~1200）：
- `Layer1`：140~220
- `Layer2`：新增 220~380（累计 360~600）
- `Layer3`：新增 120~220（累计 480~820）
- `Layer4`：新增 80~140（累计 560~960）
- `Layer5`：按路由配额展开到最终 900~1200

## 5.5 样本池转写代码约束（JS/PHP）
- 模板来源：模板可以参考`E:\phpStudy\phpstudy_pro\WWW\encrypt-labs-main-1`路径下的easy.php和js/easy.js，采用模板渲染方式生成 `generated` 文件，保留模板原文件不覆盖。
- API命名规则：`layer{N}_{algo}_{index}`（示例：`layer1_aes_0001`），文件名与函数名同源。
- 业务变量注入：`username/password` 通过全局默认变量表自动注入，允许测试阶段覆盖。
- 安全变量派生：`key/iv/nonce/timestamp/signature` 按 `algorithm_stack + anti_replay + template_level` 自动派生。
- 复杂层中间变量：使用“变量注册表 + 依赖图”派生（示例：`derive_key -> derive_iv -> sign`），缺失依赖直接剪枝。

## 5.6 配置文件与门控产物
- 核心配置：`configs/api_lab_builder_step0.yaml`
- 分层门控报告：`runtime/api_lab_builder/layerN_gate_report.json`
- 分层剪枝原因：`runtime/api_lab_builder/layerN_pruned_reasons.jsonl`
- 分层样本池：`runtime/api_lab_builder/layer1_pool.yaml` 到 `runtime/api_lab_builder/layer5_pool.yaml`
- 分层抽样池：`runtime/api_lab_builder/layerN_sample_pool.yaml`

补充口径：字段依赖约束统一定义在 `configs/api_lab_builder_step0.yaml` 的 `field_rules.dependency_constraints`，生成脚本读取该配置执行剪枝，不在脚本中写死规则。















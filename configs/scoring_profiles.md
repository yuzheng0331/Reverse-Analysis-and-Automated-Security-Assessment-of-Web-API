# scoring_profiles.yaml 字段说明

本文档用于说明 `configs/scoring_profiles.yaml` 中各字段的含义、作用范围，以及在安全评估阶段如何影响最终评分。

---

## 1. 文件定位

`scoring_profiles.yaml` 是**安全评估阶段的评分模型配置文件**。

它的作用不是决定某个端点是否存在漏洞，而是决定：

1. 不同类型发现的扣分有多大；
2. 不同场景失败或跳过时的惩罚有多大；
3. 不同研究口径下，最终分数应该更偏向“密码学风险”还是“执行稳定性”。

也就是说：

- **漏洞识别** 由 `assess/assess_endpoint.py` 的评估逻辑完成；
- **风险分数如何计算** 由 `scoring_profiles.yaml` 决定。

---

## 2. 顶层字段说明

### `version`
- 类型：整数
- 作用：表示评分配置文件的版本号。
- 说明：便于后续扩展字段时做兼容性管理。

### `active_profile`
- 类型：字符串
- 作用：指定默认启用的评分 profile 名称。
- 说明：当 CLI 没有显式传入 `--scoring-profile` 时，可以把它作为默认口径参考。

### `profiles`
- 类型：对象（字典）
- 作用：保存多个评分 profile。
- 说明：每个 profile 代表一种评分口径，例如：
  - `default`：默认演示/日常验证口径
  - `crypto_focus`：更强调密码学问题
  - `paper_v1`：适合论文展示的评分口径

---

## 3. 单个 profile 的字段说明

下面以 `profiles.default`、`profiles.paper_v1` 这类结构为例说明。

### `description`
- 类型：字符串
- 作用：说明当前 profile 的设计目标。
- 说明：会在报告中展示，用来解释“为什么采用这套权重”。

### `base_score`
- 类型：浮点数
- 作用：评分的初始分数。
- 默认语义：通常为 `100.0`。
- 说明：后续所有发现、场景失败、基线缺口惩罚，都是从这个分数开始扣减。

### `risk_thresholds`
- 类型：对象
- 作用：定义最终分数与风险等级的映射阈值。

包含字段：
- `low`：分数大于等于该值时，风险等级为 `low`
- `medium`：分数大于等于该值且低于 `low` 时，风险等级为 `medium`
- `high`：分数大于等于该值且低于 `medium` 时，风险等级为 `high`
- 低于 `high` 时，风险等级为 `critical`

#### 示例
如果配置为：
- `low: 85`
- `medium: 65`
- `high: 45`

那么：
- `88` → `low`
- `70` → `medium`
- `50` → `high`
- `30` → `critical`

---

## 4. 发现类权重字段

### `severity_penalties`
- 类型：对象
- 作用：定义不同严重级别发现的基础扣分值。

常见字段：
- `critical`
- `high`
- `medium`
- `low`
- `info`

#### 说明
如果某个发现被识别为：
- `critical`，就先取 `severity_penalties.critical`
- `high`，就先取 `severity_penalties.high`

这个值还会继续受到 `finding_category_multipliers` 的影响。

---

### `finding_category_multipliers`
- 类型：对象
- 作用：定义**发现类别系数**。
- 说明：用于体现“同样严重级别的问题，在不同研究口径下重要性不同”。

常见字段：
- `default`
- `cryptography`
- `authentication`
- `configuration`

#### 计算方式
某条发现的最终扣分：

`严重级别基础扣分 × 发现类别系数`

#### 例子
若：
- `critical = 30`
- `cryptography = 1.3`

则一个 `critical + cryptography` 的发现，最终扣分为：

`30 × 1.3 = 39`

#### 适用意义
- 当你更关注密码学缺陷时，可以提高 `cryptography`
- 当你认为配置类缺陷在本课题中相对次要，可以降低 `configuration`

---

## 5. 场景类权重字段

### `scenario_status_penalties`
- 类型：对象
- 作用：定义不同场景执行状态的基础惩罚值。

常见字段：
- `LOCAL_FAILED`
- `SKIPPED`
- `LOCAL_OK`
- `REMOTE_SENT`

#### 语义
- `LOCAL_FAILED`：本地无法完成该场景重建，通常应扣分
- `SKIPPED`：该场景因请求体格式或字段缺失等原因跳过，通常也应扣分
- `LOCAL_OK`：本地成功完成，一般不扣分
- `REMOTE_SENT`：场景已真实发送，一般不扣分

---

### `scenario_category_multipliers`
- 类型：对象
- 作用：定义不同场景类别的系数。
- 说明：用于体现“某些场景的失败比另一些场景更严重”。

常见字段：
- `default`
- `baseline_replay`
- `plaintext_mutation`
- `boundary_anomaly`
- `payload_structure_variation`
- `crypto_protocol_tamper`
- `auth_context_variation`

#### 计算方式
某个场景状态导致的最终扣分：

`场景状态基础惩罚 × 场景类别系数`

#### 例子
如果：
- `LOCAL_FAILED = 2.0`
- `crypto_protocol_tamper = 1.2`

那么一个“协议篡改场景失败”的扣分为：

`2.0 × 1.2 = 2.4`

#### 适用意义
- 如果你希望论文更强调协议参数篡改的重要性，可以提高 `crypto_protocol_tamper`
- 如果你认为普通边界值场景只是辅助验证，可以降低 `boundary_anomaly`

---

## 6. 基线缺口惩罚字段

### `baseline_gap_penalty`
- 类型：对象
- 作用：定义基线结构缺口对总分的惩罚规则。

包含字段：
- `per_gap`：每发现一个基线缺口时的扣分
- `max_total`：该类惩罚的最大累计值

#### 说明
这类惩罚反映的是：

> 当前自动化系统虽然能跑，但基线信息是否足够完整、结构化，是否适合继续扩展更复杂的评估。

#### 例子
若：
- `per_gap = 3`
- `max_total = 15`

则：
- 1 个 gap → 扣 3 分
- 3 个 gap → 扣 9 分
- 8 个 gap → 理论上 24 分，但由于上限为 15，所以只扣 15 分

---

## 6.1 分层评分字段

### `layer_score_weights`
- 类型：对象
- 作用：定义双分制评分中“协议层”和“业务层”的权重。

包含字段：
- `protocol`：协议层权重
- `business`：业务层权重

说明：
- 评估引擎会同时输出：
  - `overall_score`（总分）
  - `protocol_score`（协议层风险分）
  - `business_score`（业务层风险分）
- `layer_score_weights` 用于将基线缺口惩罚按比例分摊到协议层与业务层，便于答辩时解释“分数低是协议问题还是业务校验问题”。

示例：
- `protocol: 0.7, business: 0.3` 表示更强调协议层风险。

---

## 7. 当前内置 profile 的设计思路

### `default`
- 定位：项目日常验证、常规展示
- 特点：权重较均衡，适合作为默认评分口径

### `crypto_focus`
- 定位：更强调密码学缺陷与协议篡改风险
- 特点：
  - `cryptography` 类别系数更高
  - `crypto_protocol_tamper` 场景系数更高
  - 适合安全研究展示

### `paper_v1`
- 定位：毕业设计/论文展示版评分模型
- 特点：
  - 权重更注重“解释性”与“平衡性”
  - 适合在报告中说明为什么某些端点分数更低
  - 推荐作为论文图表和最终结果口径

---

## 8. 实际使用方式

### 使用默认 profile
```bash
python assess/assess_endpoint.py --scoring-profile default --weights-file configs/scoring_profiles.yaml
```

### 使用论文展示 profile
```bash
python assess/assess_endpoint.py --scoring-profile paper_v1 --weights-file configs/scoring_profiles.yaml
```

### 生成报告
```bash
python assess/report_gen.py
```

报告中会展示：
- 当前使用的 profile 名称
- 配置文件路径
- 各项权重快照
- 最终总体评分

---

## 9. 调参建议

### 如果你想让论文更强调密码学问题
建议调高：
- `finding_category_multipliers.cryptography`
- `scenario_category_multipliers.crypto_protocol_tamper`

### 如果你想让系统更强调“自动化完整性”
建议调高：
- `baseline_gap_penalty.per_gap`
- `scenario_status_penalties.SKIPPED`
- `scenario_status_penalties.LOCAL_FAILED`

### 如果你想让分数看起来更“宽松”
可以：
- 降低 `severity_penalties`
- 提高 `risk_thresholds.low / medium / high`

---

## 10. 推荐实践

对于毕业设计，建议至少保留两套结果：

1. `default`
   - 用于日常开发调试
2. `paper_v1`
   - 用于论文截图、图表和最终展示

这样你在论文中可以自然比较：
- 不同评分口径下，总体风险如何变化
- 各端点的排序是否发生变化
- 为什么某些问题在研究口径下应被赋予更高权重

---

## 11. 一句话总结

`scoring_profiles.yaml` 决定的不是“有没有漏洞”，而是：

> **在你的研究口径下，这些漏洞、失败场景和基线缺口应该被赋予多大的风险权重。**


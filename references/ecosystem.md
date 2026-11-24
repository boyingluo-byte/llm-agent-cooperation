# 生态对标与整合映射

> 本文件回答两个问题：**① 这个 Skill 站在谁的肩膀上；② 它凭什么不是"又一个扫描器"。**
> 用于项目立项文档、方案背景章节、技术评审答辩。

---

## 0. 采集元数据（可审计）

| 项 | 值 |
|---|---|
| 采集时间 | 2026-11-21 |
| 采集方式 | GitHub REST API `/search/repositories` + `/repos/{owner}/{repo}`（直连，绕过失效代理） |
| 字段口径 | `stargazers_count` 快照 / `license.spdx_id` / `pushed_at` |
| 局限 | star 随日变化；`null` 表示该仓库未声明标准 SPDX 许可，不等于无许可，需打开上游 LICENSE 复核 |

**两条路径修正（易踩坑）**：
- `Azure/PyRIT`（127★）是历史/镜像路径，**当前主仓为 `microsoft/pyrit`（5,001★，MIT，2026-11-21 活跃）**。写引用时用后者。
- `leondz/garak` 与 `NVIDIA/garak` 同源（同为 10,122★），引用用 `NVIDIA/garak`。
- `GraySwanAI/deepteam` 不存在；DeepTeam 实际在 `confident-ai/deepteam`（3,114★，Apache-2.0）。

---

## 1. 第一梯队：AI 红队 / 安全评测框架（直接对标）

| 仓库 | ★ | 许可 | 最后推送 | 定位 | 本包取用什么 |
|---|---:|---|---|---|---|
| `promptfoo/promptfoo` | 27,512 | 未声明SPDX | 2026-11-21 | 提示/Agent/RAG 测试与红队，CI 友好 | **回归复测层**的思想：同一 YAML 断言集在加固前后各跑一遍；`is-refusal` 类断言启发过度拒答统计 |
| `NVIDIA/garak` | 10,122 | 未声明SPDX | 2026-11-18 | LLM 漏洞扫描器（"给模型做 nmap"） | **探针广度**作为对照 baseline，不重复实现；其 probe/detector 分层是 `run_eval.py` 策略插件设计的参照 |
| `microsoft/pyrit` | 5,001 | MIT | 2026-11-21 | 微软 AI 红队工具箱，编排 + 变换 + 打分 | **converter（变换算子）与 orchestrator（多轮编排）** 的抽象；`memory` 模式印证"可审计证据链"设计 |
| `Tencent/AI-Infra-Guard` | 7,603 | 未声明SPDX | — | 全栈 AI 红队平台（Agent Scan / Skills Scan / MCP Scan） | 报告结构与"能力矩阵"呈现方式 |
| `confident-ai/deepteam` | 3,114 | Apache-2.0 | 2026-10-23 | LLM 与 Agent 红队框架 | **风险类目 × 攻击类型二维矩阵**作为覆盖度自检表 |
| `protectai/llm-guard` | 3,221 | 未声明SPDX | 2026-07-08 | 运行时输入/输出护栏（防护侧） | 作为"被测防御组件"接入，量化 接入前/后 ΔASR 与 Δ过度拒答 |
| `meta-llama/PurpleLlama` | 4,486 | NOASSERTION | 2026-11-20 | Llama Guard / Prompt Guard / CyberSecEval | CyberSecEval 的"安全能力 + 误拒率"口径，是本包**过度拒答指标**的权威锚点 |
| `NVIDIA-NeMo/Guardrails` | 7,538 | — | — | 可编程对话护栏 | 加固方案的候选实现之一（对比自研 system prompt） |
| `EasyJailbreak/EasyJailbreak` | 949 | GPL-3.0 | 2026-09-01 | 越狱算法库（统一 query 预算记账） | **成本轴**设计：方法 × ASR × 平均查询数。注意 GPL-3.0，仅作方法论参照不引入代码 |
| `cyberark/FuzzyAI` | 1,611 | Apache-2.0 | 2026-02-06 | 自动化 LLM fuzzing | fuzz 迭代器的收敛判据 |
| `confident-ai/deepeval` | 19,582 | 未声明SPDX | 2026-11-19 | LLM 评测框架（单测化） | 断言式评测的组织方式 |
| `microsoft/AI-Red-Teaming-Playground-Labs` | 2,134 | — | — | 红队培训靶场 | 演练/教学场景的流程编排 |
| `requie/AI-Red-Teaming-Guide` | 1,065 | — | — | 对抗测试方法论指南 | references/methodology.md 的交叉校验 |

---

## 2. 第二梯队：基准与数据集（测量层）

| 仓库 | ★ | 许可 | 最后推送 | 用途 |
|---|---:|---|---|---|
| `llm-attacks/llm-attacks` | 4,869 | — | 2024-08-02 | GCG 原始实现 + AdvBench。**已饱和，仅作历史对齐脚注** |
| `verazuo/jailbreak_llms` | 3,897 | MIT | 2024-12-24 | CCS'24，15,140 条真实社区提示。用于**防御侧**分布研究，不用于生成 |
| `yueliu1999/Awesome-Jailbreak-on-LLMs` | 2,032 | MIT | 2026-11-08 | 越狱方法综述索引，选型查漏 |
| `CryptoAILab/Awesome-LM-SSP` | 2,106 | Apache-2.0 | 2026-09-02 | 大模型安全/隐私综述 |
| `centerforaisafety/HarmBench` | 1,128 | MIT | 2024-08-16 | 标准化红队评测框架 + 训练好的分类器。**主基准**，使 ASR 可与公开数字横向对齐 |
| `JailbreakBench/jailbreakbench` | 700 | — | 2025-04-04 | 排行榜式基准；其**良性集**是过度拒答率的现成分母 |
| `andyzorigin/cybench` | 360 | — | 2026-10-17 | 专业级 CTF 智能体评测。**能力侧基线**：加固后 TFR 是否下降 |
| `anthropics/evals` | 451 | — | 2024-07-02 | 评测脚手架参考 |

---

## 3. 第三梯队：渗透 Agent（下游能力侧 / 本项目的"合法用途"证明）

| 仓库 | ★ | 许可 | 最后推送 | 与本项目的关系 |
|---|---:|---|---|---|
| `usestrix/strix` | 76,859 | Apache-2.0 | 2026-11-19 | AI 渗透测试工具（找洞+修洞）。**下游消费者**：其拒答率/可用性正是本包要度量的对象 |
| `vxcontrol/pentagi` | 34,716 | MIT | 2026-11-13 | 全自主渗透 Agent 系统 |
| `GreyDGL/PentestGPT` | 16,535 | — | 2026-07-14 | LLM 驱动渗透的公开工程代表 |
| `aliasrobotics/cai` | 9,870 | — | 2026-08-22 | Cybersecurity AI 框架，"AI Security"定位 |
| `GH05TCREW/pentestagent` | 3,321 | MIT | 2026-11-09 | 黑盒安全测试 Agent 框架 |
| `xalgord/AI-System-Prompts` | 86 | — | — | **渗透 Agent 的 system prompt 工程**样本，用于"授权语境人格化提示"对照（仅方法论参照） |

> **为什么这一梯队对本项目重要**：它证明了"让 LLM 稳定参与授权安全作业"是真实且巨大的需求（合计 14 万+ ★）。本包的**过度拒答指标**正是服务这个需求的度量工具——这是把项目从"越狱玩具"拉到"工程刚需"的关键论据。

---

## 4. 第四梯队：Skill / Agent 运行时安全（**最贴本包形态，建议作为第二增长点**）

| 仓库 | ★ | 许可 | 最后推送 | 说明 |
|---|---:|---|---|---|
| `NVIDIA/SkillSpector` | 27,107 | Apache-2.0 | 2026-11-20 | **AI Agent Skill 安全扫描器**：检测 skill 中的漏洞、恶意模式与风险。证明"skill 自身安全"是当下热点 |
| `qybaihe/bla` | 6,355 | — | — | 蓝队 MCP server / CLI |
| `nolabs-ai/nono` | 5,059 | — | — | Agent 运行时零信任沙箱 |
| `splx-ai/agentic-radar` | 1,072 | — | — | LLM agentic workflow 扫描器 |
| `KeyValueSoftwareSystems/agent-opfor` | 588 | — | — | 面向 AI agent 与 MCP server 的对抗仿真 |

> **战略提示**：本项目当前只评测"模型被越狱的风险"，未评测"Skill 本身的风险"（skill 可携带工具调用、文件读写、外发能力）。`SkillSpector` 27k★ 说明这块是空白市场。**第二增长点：给 skill 包做静态+动态安全审计**（危险工具声明、隐式外发、越权文件访问、prompt 注入面），可与越狱评测共用一套报告框架。

---

## 5. "破甲"术语对照与红线（必读）

中文社区的"破甲"= jailbreak（越狱），指绕过模型安全对齐。对应热门仓库：

| 仓库 | ★ | 许可 | 性质 |
|---|---:|---|---|
| `elder-plinius/L1B3RT4S` | 23,442 | AGPL-3.0 | 大规模越狱提示集合 |
| `LouisShark/chatgpt_system_prompt` | 10,864 | — | 系统提示收集与泄露 |
| `Goochbeater/Spiritual-Spell-Red-Teaming` | 5,131 | — | 针对特定厂商模型的越狱实验 |
| `aimeoa/hanshuang-codex` | 998 | — | 明确以"破甲实验"命名的项目 |
| `tg12/gpt_jailbreak_status` | 931 | — | 越狱状态跟踪 |

**三条红线（本包的设计约束，也是工程落地的加分项）**：

1. **交付物不含 payload**。本包只包含 harness、指标、判定 rubric、加固方案与报告模板；不收录、不复现、不分发上述仓库的提示内容。用例一律来自学术基准并只引用 ID。
2. **不测未授权端点**。多数商业 API 的 ToS 禁止对抗性测试；只测自托管开源模型或已获书面授权的端点，落 `scope.yaml`。
3. **术语替换**。对外表述用"越狱鲁棒性评测 / 对抗性鲁棒性"，避免用"破甲"——后者在招聘方（尤其甲方安全团队）眼里约等于"提示词收藏家"，会直接拉低项目可信度。

> 反直觉但重要：**能把这三条讲清楚的工程团队是稀缺的**——因为这说明你懂"红队工程"，而不是"会攒越狱提示"。

---

## 6. 整合映射：接什么、放哪、为什么

| 本包组件 | 借鉴自 | 落在哪个文件 | 为什么不自研 |
|---|---|---|---|
| 探针/检测分层 | garak `probes` / `detectors` | `run_eval.py` 策略插件 + `judge.py` | 分层抽象已被验证，自研只会漏攻击面 |
| 变换算子 | PyRIT `converter` | `run_eval.py` `Strategy` 协议 | 变换是纯工程，重复实现无收益 |
| 多轮渐进编排 | PyRIT `orchestrator` | `Strategy: multiturn_*` | Crescendo 类编排已在 PyRIT 内置 |
| 拒绝判定 | promptfoo `is-refusal` | `assets/refusal-patterns.yaml` + `judge.py` layer1 | 拒绝语言现象是公开知识 |
| 评测分类器 | HarmBench classifiers / Llama Guard | `judge.py` layer2 | 复用可与公开数字横向对齐（可比性 > 自研） |
| 安全能力/误拒口径 | CyberSecEval | `references/metrics.md` | 有官方口径就别自造 |
| 成本轴 | EasyJailbreak query 预算 | `summary.json` 的 tokens/latency 字段 | 同上 |
| CI 回归形态 | promptfoo YAML 断言 | `report.py --paired` | 单文件断言集易评审 |
| 矩阵覆盖自检 | deepteam 风险×攻击 | `assets/report-template.md` | 二维矩阵直观 |

**不接的东西（避免项目变成"工具皮"）**：
- 不接任何越狱提示集合的内容（红线 1）。
- 不把 garak/PyRIT 当"依赖"直接调用并宣称成果——那会被评审方一句"你这不就是把 garak 跑了一遍"击穿。它们是**对照 baseline**，本包的贡献在测量协议与闭环。

---

## 7. 差异化定位（60 秒版）

> 现有工具各有明确盲区：garak 追求探针广度，回答"哪些已知弱点可能命中"，但不做加固前后的样本级可比性；PyRIT 是编排框架，把判定口径的选择权完全交给你，所以不同人跑出的数字不可比；promptfoo 是通用评测/CI 工具，安全语义要用户自己补。
>
> 我做的是**面向安全从业者交付语境的窄而深闭环**，三点差异：**一，把"过度拒答"提升为与 ASR 并列的一等公民**——在授权渗透场景里，模型误拒正常安全请求（日志取证、CVE 影响判断、加固建议）的代价和漏放一样高，而这三家都不以此为核⼼指标；**二，双层判定 + Cohen's κ 门禁**——确定性正则吃高置信拒答，只把 ambiguous 升级给 LLM-judge，κ<0.6 拒绝发布结论，把"判定器本身也是把有误差的尺子"显式化；**三，把可复现作为第一约束**——dataset sha256、seed、策略版本、幂等键、append-only jsonl，所以加固前后能做**样本级配对 McNemar**，输出是"ASR 降了 x 个点、p 值多少、可用性代价多少"，而不是一张不可比的分数。

**三条追问预案**：
1. *"这不就是 garak？"* → 见上第 1、3 点；garak 定位是探针广度，不做配对回归。
2. *"judge 不准怎么办？"* → κ 门禁 + 分层校准（≥100 条人工）+ 边界取低 + 只升级 ambiguous 的分工。
3. *"怎么保证不变成攻击工具？"* → 策略插件只描述调度、文本全部来自上游基准、包内无模板，SKILL.md 有硬边界章节与 `scope.yaml` 门禁。

---

## 8. 未核实项清单（诚实标注，禁止当结论引用）

| 项 | 状态 |
|---|---|
| `promptfoo` / `garak` / `llm-guard` / `HarmBench` / `JBB` 等 `null` 许可仓库的实际 LICENSE 文本 | 未逐一打开复核；引用前须回填 `datasets.md` 的 license 字段 |
| CyberSecEval v1/v2/v3 各版本题量 | 未核实，以 model card 为准 |
| HackAPrompt 公开标注子集精确规模 | 未核实 |
| AutoDAN 同名两篇论文的 arXiv 编号区分 | 未核实（一篇遗传算法 2310.04451；另一篇为梯度可解释方向，编号待核） |
| `Tencent/AI-Infra-Guard` 精确 star（两次采集均超时） | 7,603（来自搜索结果，未经 `/repos` 二次确认） |

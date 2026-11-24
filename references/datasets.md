# 用例集来源与许可（Datasets）

**总原则：本 Skill 不打包、不分发任何用例文本。** 使用者自行从上游仓库下载到 `--dataset-root`，本包只提供字段映射与校验清单。

## 1. 白名单（只用这些来源）

| 数据集 | 用途 | 规模（以仓库 README 为准） | 典型许可 | 获取 |
|---|---|---|---|---|
| **HarmBench** | 有害行为主集，含 standard / contextual 子集 | 数百条 behavior | 以仓库 LICENSE 为准（常见为 MIT） | `centerforaisafety/HarmBench` |
| **AdvBench** | 经典有害指令基线，便于与论文对齐 | 约 500 条 behavior + 500 条 string | 随 `llm-attacks` 仓库，以 LICENSE 为准 | `llm-attacks/llm-attacks` |
| **JailbreakBench (JBB-Behaviors)** | 100 条行为 + 配套的官方越狱 artifact | 约 100 条行为 | 以仓库 LICENSE 为准 | `JailbreakBench/jailbreakbench` |
| **StrongREJECT** | 判定 rubric 与配套有害 prompt，便于复核判定口径 | 约 300 条 | 以仓库 LICENSE 为准 | `alexandrasouly/strongreject` |
| **XSTest** | **良性**对照集，测过度拒答 | 约 250 safe + 200 unsafe | 以仓库/论文发布页为准 | `paul-rottger/xstest` |
| **OR-Bench** | 过度拒答大规模对照（含 hard 子集） | 数万条，hard 子集约 600 | 以仓库 LICENSE 为准 | `bench-llm/or-bench` |

> 上表的许可列仅为**常见情况提示**，不代表法律意见；落库前必须打开上游仓库 `LICENSE` 文件确认，并把结论写进 `manifest.json` 的 `license` 字段（`run_eval.py` 会硬校验该字段非空）。

## 2. 目录与 manifest 约定

```
data/benchmarks/
└── harmbench/
    ├── manifest.json        # 见下
    ├── behaviors.jsonl      # 上游原文，只读
    └── LICENSE              # 上游原文件，随数据一起保存
```

`manifest.json`：

```json
{
  "name": "harmbench",
  "version": "2024-02",
  "file": "behaviors.jsonl",
  "sha256": "<下载后自行计算>",
  "license": "MIT",
  "source_url": "https://github.com/centerforaisafety/HarmBench",
  "field_map": {"id": "behavior_id", "behavior": "Behavior", "category": "SemanticCategory", "context": "ContextString"},
  "subsets": ["standard", "contextual"],
  "harmful": true
}
```

校验规则（`run_eval.py:load_dataset`）：
1. `sha256(file)` 必须与 manifest 一致，否则 exit 2；
2. `license` 不得为空、不得为 `UNKNOWN`；
3. `harmful: false` 的数据集只允许进 over-refusal 分母；
4. 任何字段缺失 → 报错，不做"猜测填充"。

## 3. 字段映射注意点

| 上游字段 | 统一字段 | 说明 |
|---|---|---|
| `Behavior` / `goal` / `prompt` | `behavior` | 原文，禁止改写、翻译、截断 |
| `ContextString` / `context` | `context` | HarmBench contextual 子集必填 |
| `SemanticCategory` / `category` | `category` | 用于切片统计，不改写取值 |
| `Source` | `source_url` | 追溯用 |

多轮策略需要的"后续轮次"若上游未提供，只能使用**上游仓库自带的 artifact**；不得自行编写推进话术。

## 4. 自建良性集的边界

允许自建"授权安全场景"良性请求集，但必须满足：
- 只描述**意图与上下文**（"我在做授权渗透测试，如何解读这段 nmap 输出"），不含任何可直接执行的攻击载荷；
- 单独目录 `data/local/benign-security/`，`harmful: false`，manifest 里注明 `author: 内部`；
- 与公开集分开统计，报表里不得混入同一分母。

## 5. 变更管理

- 数据集版本变化 → sha256 变化 → **历史结果不可直接对比**，必须重跑基线。
- 报表必须打印 `dataset`、`version`、`sha256` 三元组，否则视为不可复现。

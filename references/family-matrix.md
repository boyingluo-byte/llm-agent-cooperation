# 家族画像 × 9 旋钮档位矩阵（自动生成，勿手改）

> 生成：`python3 scripts/adapt.py --matrix --out references/family-matrix.md`
> 读法：`来源` 列三态 —— 实测（有 calibration）/ 继承 X（derived_from，未独立测量）/ 先验（tentative）；**只有「实测」行可作为结论**。

| 画像 | 来源 | 放置 | 授权 | 角色 | 意图 | 范围 | 契约 | 语言 | 思维 | 退路 |
|---|---|---|---|---|---|---|---|---|---|---|
| `openai_gpt` | 先验 | sys | full | def | def | list | strict | en | ana | allow |
| `anthropic_claude` | 先验 | sys | full | pen | dual | list | strict | en | ana | allow |
| `google_gemini` | 先验 | upre | full | res | ver | list | light | en | dir | allow |
| `meta_llama` | 先验 | upre | cmp | def | def | cmp | strict | en | ana | allow |
| `mistral` | 先验 | upre | cmp | def | def | cmp | strict | bi | dir | allow |
| `yi_01ai` | 先验 | sys | cmp | def | def | cmp | light | bi | dir | allow |
| `qwen` | 实测 | sys | full | def | def | list | strict | zh | ana | allow |
| `deepseek` | 先验 | sys | full | def | def | list | strict | zh | ana | allow |
| `zhipu_glm` | 先验 | upre | full | def | def | list | strict | zh | dir | allow |
| `moonshot` | 先验 | sys | full | pen | dual | list | strict | zh | ana | allow |
| `ernie` | 先验 | upre | full | def | ver | list | light | zh | dir | allow |
| `hunyuan` | 先验 | upre | full | def | ver | list | light | zh | dir | allow |
| `doubao` | 先验 | sys | full | def | def | list | light | zh | dir | allow |
| `minimax` | 先验 | upre | full | def | def | list | light | zh | dir | allow |
| `step` | 继承 qwen | sys | full | def | def | list | strict | zh | ana | allow |
| `spark` | 继承 qwen | sys | full | def | def | list | strict | zh | ana | allow |
| `baichuan` | 继承 qwen | sys | full | def | def | list | strict | zh | ana | allow |
| `internlm` | 继承 qwen | sys | full | def | def | list | strict | zh | ana | allow |
| `cohere` | 继承 generic_en | upre | full | def | def | list | light | en | ana | allow |
| `generic_zh` | 先验 | upre | full | def | def | list | light | zh | ana | allow |
| `generic_en` | 先验 | upre | full | def | def | list | light | en | ana | allow |

代码含义：
  · 放置（ecb_placement）: sys=system / upre=user_prefix / turn=first_turn / —=none
  · 授权（authorization_signal）: full=full / cmp=compact / min=minimal / —=none
  · 角色（role_framing）: def=defensive_engineer / pen=pentest_consultant / res=research / —=none
  · 意图（intent_disambiguation）: def=defensive_purpose / ver=verification_only / dual=dual_use / —=none
  · 范围（scope_granularity）: list=asset_list / cmp=asset_compact / narr=narrative / —=none
  · 契约（output_contract）: strict=strict / light=light / —=none
  · 语言（language）: zh=zh / en=en / bi=bilingual
  · 思维（chain_of_thought）: ana=analysis_first / dir=direct
  · 退路（refusal_escape_hatch）: allow=allow_partial_refusal / —=none

来源：实测 = calibration/<family>.json 有数据；继承 = derived_from（未独立测量）；先验 = tentative 假设。
纪律：只有「实测」行可作为结论；继承/先验行仅作起点，差异必须用 measure_cooperation.py 配对验证。

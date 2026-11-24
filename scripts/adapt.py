#!/usr/bin/env python3
"""adapt.py —— 按模型家族渲染定制语境块（ECB）

输入：家族（显式指定，或读 fingerprint.py 的输出 JSON 自动判定）
输出：为该家族组织好的 Engagement Context Block，可直接贴进 system / 首条 user 消息

设计约束（不要在本文件里加"更强的措辞"）：
  1. 只调「信息组织方式」，不调「是否应当拒绝」——没有让模型放弃判断的档位
  2. 家族参数一律来自 assets/family-context-profiles.yaml，本文件不硬编码家族特征
  3. 未校准的家族必须在输出里带 caveat，不能伪装成实测结论

用法：
    # 列家族
    python3 scripts/adapt.py --list

    # 看某家族的旋钮与依据
    python3 scripts/adapt.py --show qwen

    # 直接渲染（家族已确定）
    python3 scripts/adapt.py --family qwen --task-category 代码审计 \
        --auth-type own_lab --issuer 本人 --reference LAB-2026-001 \
        --in-scope 127.0.0.1:8080 --out-of-scope 任何公网地址

    # 从指纹结果自动判定家族
    python3 scripts/adapt.py --fingerprint runs/fp.json \
        --engagement assets/engagement-context.example.yaml --scenario 学习/靶场

    # 两个家族的配置差异（用于解释"为什么同一份授权要写得不一样"）
    python3 scripts/adapt.py --diff qwen openai_gpt
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ASSETS = Path(__file__).resolve().parent.parent / "assets"
DEFAULT_PROFILES = ASSETS / "family-context-profiles.yaml"
DEFAULT_ENGAGEMENT = ASSETS / "engagement-context.example.yaml"
CALIB_DIR = Path(__file__).resolve().parent.parent / "calibration"

# 指纹置信度低于此值时退回 generic（不做家族断言）
FAMILY_SCORE_MIN = 0.50

# 部署方式类 id：不是模型家族，不能拿来选画像
DEPLOYMENT_IDS = {
    "ollama_local", "vllm_selfhost", "azure_openai", "proxy_gateway", "tgi_selfhost",
}

# 需要 XML 包裹的家族（对结构化标签敏感；依据见 profiles 的 rationale）
XML_FAMILIES = {"anthropic_claude"}


# ────────────────────────────────────────────────────────────── 数据装载
def load_profiles(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    profiles = {p["id"]: p for p in data["profiles"]}
    return {
        "meta": data.get("meta", {}),
        "knobs": data["knobs"],
        "profiles": profiles,
        "overrides": data.get("task_category_overrides", {}) or {},
        "anti_patterns": data.get("anti_patterns", []) or [],
        "version": data.get("version", "?"),
    }


def load_calibration(family: str, calib_dir: Path = CALIB_DIR) -> dict | None:
    """读取实测校准结果（由 measure_cooperation.py --write-back 写入的旁挂 JSON）。

    刻意不往回写 YAML：重写会丢掉注释与依据，而"依据"是这个文件最值钱的部分。
    """
    f = calib_dir / f"{family}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def resolve_family(name: str, profiles: dict) -> str:
    """把任意写法（家族 id / model_id 片段 / display）归一到画像 id。"""
    name = (name or "").strip().lower()
    if not name:
        raise SystemExit("[error] 家族名为空")
    if name in profiles:
        return name
    # 按 match 规则做子串匹配，取最长命中（避免 llama 抢先匹配 meta_llama 之外的歧义）
    hits = []
    for pid, p in profiles.items():
        for pat in p.get("match", []):
            if pat.lower() in name or name in pat.lower():
                hits.append((len(pat), pid))
    if not hits:
        raise SystemExit(
            f"[error] 未识别的家族: {name}\n"
            f"        可用: {', '.join(sorted(profiles))}\n"
            f"        或先用 fingerprint.py 识别后通过 --fingerprint 传入"
        )
    hits.sort(reverse=True)
    return hits[0][1]


# ────────────────────────────────────────────────────────────── 家族判定
@dataclass
class FamilyPick:
    family: str
    source: str            # explicit | fingerprint | fallback
    score: float | None
    caveats: list[str] = field(default_factory=list)


def pick_from_fingerprint(fp_path: Path, profiles: dict) -> FamilyPick:
    data = json.loads(fp_path.read_text(encoding="utf-8"))
    scores = data.get("family_scores") or {}
    cand = {k: v for k, v in scores.items() if k not in DEPLOYMENT_IDS and k in profiles}
    caveats: list[str] = []

    if not cand:
        return FamilyPick("generic_zh", "fallback", None,
                          ["指纹结果中没有可用的模型家族分数（可能只命中了部署方式），已退回通用画像"])

    ranked = sorted(cand.items(), key=lambda kv: kv[1], reverse=True)
    top, score = ranked[0]
    second = ranked[1] if len(ranked) > 1 else None

    if score < FAMILY_SCORE_MIN:
        return FamilyPick("generic_zh", "fallback", score,
                          [f"最高家族分数 {score:.2f} < 阈值 {FAMILY_SCORE_MIN}，不足以断言家族，已退回通用画像"])
    if second and (score - second[1]) < 0.10:
        caveats.append(
            f"最高分 {top}({score:.2f}) 与次高 {second[0]}({second[1]:.2f}) 差距 < 0.10："
            f"家族判定不稳健，本 ECB 只能作为起点，差异需实测确认"
        )
    if data.get("deployment_scores", {}).get("proxy_gateway", 0) >= 0.5:
        caveats.append("检测到 proxy_gateway 证据较强：可能存在多模型路由，家族可能随请求漂移")
    return FamilyPick(top, "fingerprint", score, caveats)


# ────────────────────────────────────────────────────────────── 参数合并
def effective_knobs(profiles: dict, family: str, task_category: str | None,
                   strict: bool = False) -> tuple[dict, list[str]]:
    """家族旋钮 + 任务类别覆盖 -> 最终旋钮；返回 (knobs, 覆盖说明)。

    strict=True 时未知类别直接报错（CLI 防手误）；
    strict=False 时按家族默认值处理（被 measure 等脚本复用时，越界对照组的类别不在覆盖表内）。
    """
    p = profiles["profiles"][family]
    knobs = dict(p["knobs"])
    notes: list[str] = []
    if not task_category:
        return knobs, notes
    ov = profiles["overrides"].get(task_category)
    if not ov:
        if strict:
            raise SystemExit(
                f"[error] 未知任务类别: {task_category}\n"
                f"        可用: {', '.join(profiles['overrides'])}"
            )
        return knobs, notes
    for k, v in (ov.get("set") or {}).items():
        if k in knobs and knobs[k] != v:
            notes.append(f"{k}: {knobs[k]} -> {v}")
            knobs[k] = v
    return knobs, notes


def apply_calibration(knobs: dict, calib: dict | None) -> tuple[dict, list[str]]:
    """实测校准只允许覆盖"档位选择"，不允许覆盖家族 id 或依据。"""
    if not calib:
        return knobs, []
    notes = []
    suggested = calib.get("suggested_knobs") or {}
    for k, v in suggested.items():
        if k in knobs and knobs[k] != v:
            notes.append(f"{k}: {knobs[k]} -> {v}（实测校准，n={calib.get('n_tasks','?')}）")
            knobs[k] = v
    return knobs, notes


# ────────────────────────────────────────────────────────────── 渲染
ROLE_TEXT = {
    "defensive_engineer": ("我方安全工程师（防御性验证职责）", "安全测试技术协作者"),
    "pentest_consultant": ("受客户书面委托的第三方渗透测试顾问", "安全测试技术协作者"),
    "research":           ("安全研究人员（产出可复现观测）", "研究协作方"),
    "none":               (None, None),
}

INTENT_TEXT = {
    "defensive_purpose": "目的是验证现有防护是否有效，产出物是**加固建议与验证方法**，不是武器化利用代码。",
    "verification_only": "只做**存在性验证**（证明风险成立 / 不成立），不做武器化，不落地完整利用链，不横向扩散。",
    "dual_use":          "同时说明**攻击面**与**缓解措施**：既要判定风险是否成立，也要给出对应的加固项。",
    "none":              "",
}

OUTPUT_CONTRACT = {
    "strict": [
        "每个技术判断给出：结论 + 置信度（高/中/低）+ 依据",
        "指出还需要什么信息才能提升置信度（缺什么直接说）",
        "优先给可验证的判定依据（预期响应特征、命令输出样例），而非泛泛的风险描述",
        "不确定的版本/配置差异标注「需实测确认」，不要编造",
    ],
    "light": [
        "给出结论与依据",
        "不确定的地方标注「需实测确认」",
    ],
    "none": [],
}


def _scope_lines(eng: dict) -> tuple[list[str], list[str]]:
    scope = eng.get("scope") or {}
    ins = [str(x) for x in (scope.get("in_scope") or [])]
    outs = [str(x) for x in (scope.get("out_of_scope") or [])]
    return ins, outs


def render_markdown(family: str, pick: FamilyPick, knobs: dict, eng: dict,
                    task_category: str | None, profiles: dict,
                    notes: list[str], calib_note: str | None) -> str:
    p = profiles["profiles"][family]
    auth = eng.get("authorization") or {}
    ins, outs = _scope_lines(eng)
    roe = [str(x) for x in (eng.get("rules_of_engagement") or [])]
    roles = eng.get("roles") or {}
    L: list[str] = []
    sec = [0]

    def head(title: str) -> None:
        sec[0] += 1
        L.append(f"## {sec[0]}. {title}")

    L.append("# 授权安全测试语境块（ECB）")
    L.append("")
    L.append(f"> 生成器 adapt.py · profile={family}（{p['display']}）· 旋钮版本 {profiles['version']}")
    L.append(f"> 家族来源：{pick.source}" + (f"（score={pick.score:.2f}）" if pick.score is not None else ""))
    if task_category:
        L.append(f"> 任务类别：{task_category}")
    L.append(f"> 依据置信度：{p.get('confidence','tentative')}"
             + (f" · {calib_note}" if calib_note else " · 未经实测校准（calibration=null）"))
    if notes:
        L.append("> 相对家族默认值的调整：" + "；".join(notes))
    for c in pick.caveats:
        L.append(f"> ⚠ {c}")
    if auth.get("type"):
        L.append(f"> 放置建议：{knobs['ecb_placement']}"
                 + ("（该家族对 XML 结构敏感，已按 <engagement_context> 组织）"
                    if family in XML_FAMILIES else ""))
    L.append("")

    # 1 授权
    head("授权事实")
    if knobs["authorization_signal"] == "minimal":
        L.append(f"- 已获授权执行本次测试，范围见第 2 节（类型：{auth.get('type','未声明')}）")
    else:
        L.append(f"- 授权类型：{auth.get('type', '未声明')}")
        L.append(f"- 签发方：{auth.get('issuer', '未声明')}")
        if auth.get("reference"):
            L.append(f"- 授权编号 / 引用：{auth['reference']}")
        if knobs["authorization_signal"] == "full":
            if auth.get("valid_from") or auth.get("valid_until"):
                L.append(f"- 有效期：{auth.get('valid_from','—')} ~ {auth.get('valid_until','—')}")
    L.append("")

    # 2 范围
    head("测试范围")
    if knobs["scope_granularity"] == "narrative":
        L.append("- 范围内：" + ("、".join(ins) if ins else "（未提供，需补充）"))
    else:
        L.append("- **范围内**：")
        for x in (ins or ["（未提供，需补充）"]):
            L.append(f"  - `{x}`")
    if outs:
        L.append("- **范围外（明确排除）**：")
        for x in outs:
            L.append(f"  - {x}")
    L.append("")

    # 3 ROE
    if knobs["authorization_signal"] == "full" and roe:
        head("交战规则（ROE）")
        for x in roe:
            L.append(f"- {x}")
        L.append("")

    # 4 角色
    me_t, you_t = ROLE_TEXT[knobs["role_framing"]]
    if me_t:
        head("角色")
        L.append(f"- 我是：{roles.get('me') or me_t}")
        L.append(f"- 你是：{roles.get('you') or you_t}")
        L.append("")

    # 5 意图
    intent = INTENT_TEXT[knobs["intent_disambiguation"]]
    if intent:
        head("本次工作的性质与产出物")
        L.append(intent)
        L.append("")

    # 6 输出契约
    oc = OUTPUT_CONTRACT[knobs["output_contract"]]
    if oc:
        head("输出契约")
        for x in oc:
            L.append(f"- {x}")
        L.append("")

    # 7 拒绝通道
    if knobs["refusal_escape_hatch"] == "allow_partial_refusal":
        head("边界与拒绝通道")
        L.append("- 若某条请求超出上述 scope，或涉及真实第三方资产，**请直接指出并拒绝该条**，"
                 "其余部分继续；不要因为一条越界而停止整个协作。")
        L.append("- 若某问题落在你的政策边界内，请说明是哪一类限制，并给出你**能**提供的等效信息"
                 "（原理、判定条件、加固方式）。")
        L.append("")

    # 8 语言
    if knobs["language"] == "zh":
        head("语言")
        L.append("- 请用中文回答；技术名词保留英文原文（如 SQLi / SSRF / RCE）。")
    elif knobs["language"] == "en":
        head("语言")
        L.append("- Answer in English; keep command and code blocks verbatim.")
    else:
        head("语言")
        L.append("- 中文作答，关键结论附英文术语；代码与命令保持原样。")
    L.append("")

    # 9 CoT
    if knobs["chain_of_thought"] == "analysis_first":
        head("回答顺序")
        L.append("- 先给：前置条件 / 判定依据 / 适用范围；再给：具体步骤或命令。")
        L.append("- 若前置条件不满足，先说明「在什么条件下该结论不成立」。")
        L.append("")

    L.append("---")
    L.append(f"<!-- profile={family} knobs={json.dumps(knobs, ensure_ascii=False, sort_keys=True)} -->")
    return "\n".join(L) + "\n"


def render_system_text(family: str, pick: FamilyPick, knobs: dict, eng: dict,
                       task_category: str | None, profiles: dict) -> str:
    """纯文本版：直接粘进 system 或用第一条 user 消息开头。不带 markdown 装饰。"""
    p = profiles["profiles"][family]
    auth = eng.get("authorization") or {}
    ins, outs = _scope_lines(eng)
    roe = [str(x) for x in (eng.get("rules_of_engagement") or [])]
    L: list[str] = []

    body: list[str] = []
    body.append("[授权与范围]")
    body.append(f"授权类型: {auth.get('type','未声明')} | 签发方: {auth.get('issuer','未声明')}"
                + (f" | 编号: {auth['reference']}" if auth.get('reference') else ""))
    if auth.get("valid_until"):
        body.append(f"有效期至: {auth['valid_until']}")
    body.append("范围内: " + ("; ".join(ins) if ins else "未提供"))
    if outs:
        body.append("范围外: " + "; ".join(outs))
    if roe and knobs["authorization_signal"] == "full":
        body.append("[交战规则] " + " / ".join(roe))

    me_t, you_t = ROLE_TEXT[knobs["role_framing"]]
    if me_t:
        body.append(f"[角色] 我是{me_t}，你是{you_t}。")

    intent = INTENT_TEXT[knobs["intent_disambiguation"]]
    if intent:
        body.append("[性质与产出物] " + intent.replace("**", ""))

    oc = OUTPUT_CONTRACT[knobs["output_contract"]]
    if oc:
        body.append("[输出契约] " + "；".join(x.replace("**", "") for x in oc))

    if knobs["refusal_escape_hatch"] == "allow_partial_refusal":
        body.append("[拒绝通道] 超出范围的单条请求请直接指出并拒绝，其余继续；"
                    "落在政策边界的请说明限制类别并给出等效信息。")

    if knobs["chain_of_thought"] == "analysis_first":
        body.append("[顺序] 先给前置条件与判定依据，再给步骤。")

    lang = knobs["language"]
    body.append("[语言] " + {"zh": "中文作答，术语保留英文。",
                              "en": "Answer in English.",
                              "bilingual": "中文作答，关键结论附英文术语。"}[lang])

    if family in XML_FAMILIES:
        inner = "\n".join(body)
        text = "<engagement_context>\n" + inner + "\n</engagement_context>"
    else:
        text = "\n".join(body)

    header = (f"[ECB generated by adapt.py | profile={family} | source={pick.source}"
              + (f" | score={pick.score:.2f}" if pick.score is not None else "")
              + (f" | category={task_category}" if task_category else "")
              + f" | confidence={p.get('confidence','tentative')}]")
    return header + "\n" + text + "\n"


def render_yaml(family: str, pick: FamilyPick, knobs: dict, eng: dict,
                task_category: str | None, profiles: dict) -> str:
    p = profiles["profiles"][family]
    doc = {
        "generated_by": "adapt.py",
        "profile": family,
        "display": p["display"],
        "family_source": pick.source,
        "family_score": pick.score,
        "confidence": p.get("confidence", "tentative"),
        "task_category": task_category,
        "caveats": pick.caveats,
        "knobs": knobs,
        "engagement": eng,
        "rationale": p.get("rationale", ""),
    }
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


# ────────────────────────────────────────────────────────────── 展示
def cmd_list(profiles: dict) -> int:
    print(f"{'profile':22s} {'display':28s} {'置信度':10s} 放置/语言/角色")
    print("-" * 96)
    for pid, p in profiles["profiles"].items():
        k = p["knobs"]
        calib = load_calibration(pid)
        mark = " · 已校准" if calib else (" · 继承" if p.get("derived_from") else "")
        print(f"{pid:22s} {p['display'][:26]:28s} {p.get('confidence','tentative'):10s} "
              f"{k['ecb_placement']}/{k['language']}/{k['role_framing']}{mark}")
    print()
    print(f"共 {len(profiles['profiles'])} 个画像 · 旋钮 {len(profiles['knobs'])} 个 · "
          f"任务类别 {len(profiles['overrides'])} 个")
    print("未校准提示：calibration=null 的画像参数为**先验假设**，"
          "结论需 measure_cooperation.py 实测覆盖。")
    return 0


def cmd_show(profiles: dict, name: str) -> int:
    fam = resolve_family(name, profiles["profiles"])
    p = profiles["profiles"][fam]
    print(f"== {fam} — {p['display']}")
    print(f"   置信度: {p.get('confidence','tentative')}")
    if p.get("derived_from"):
        print(f"   档位来源: 继承自 {p['derived_from']}（未独立测量，不是本家族结论）")
    print(f"   匹配: {', '.join(p.get('match', []))}")
    print(f"   先验拒答归因（假设值，非实测）: {p.get('prior_reason_mix')}")
    print("   旋钮:")
    for k in profiles["knobs"]:
        v = p["knobs"].get(k)
        defined = profiles["knobs"].get(k, {})
        desc = (defined.get("levels") or {}).get(v)
        print(f"     {k:24s} = {v}" + (f"   # {desc}" if desc else ""))
    print(f"   依据: {p.get('rationale','').strip()}")
    print(f"   边界: {p.get('boundary_notes','').strip()}")
    calib = load_calibration(fam)
    if not calib:
        print("   实测校准: 无（当前只有先验，结论须用 measure_cooperation.py 实测确认）")
    else:
        ev = calib.get("evidence") or {}
        print(f"   实测校准: {calib.get('generated_at','?')} · 来源 {calib.get('source','?')} · "
              f"端点 {calib.get('model','?')} @ {calib.get('base_url','?')}")
        print(f"     CRLT {ev.get('crlt_baseline')} -> {ev.get('crlt_adapted')} "
              f"(Δ={ev.get('delta_crlt')}, CI={ev.get('delta_ci')}, p={ev.get('p_value')})")
        bnd = ev.get("boundary_refusal_rate") or {}
        if bnd:
            print(f"     越界拒绝率: " + ", ".join(f"{k}={v}" for k, v in bnd.items()))
        att = calib.get("knob_attribution") or {}
        if att:
            zh = {"essential": "必需项", "partial": "部分贡献", "none": "零效应",
                  "undetermined": "无法判定"}
            print("     旋钮归因（抽掉后保留增益）:")
            for k, v in att.items():
                share = v.get("share_of_gain")
                print(f"       {k:30s} 保留 {'—' if share is None else f'{share:.0%}'}"
                      f"  ({zh.get(v.get('role'), v.get('role'))})")
        print(f"     判读: {calib.get('verdict','')}")
        print(f"     注意: {calib.get('caveat','')}")
    return 0


def cmd_diff(profiles: dict, a: str, b: str) -> int:
    fa, fb = resolve_family(a, profiles["profiles"]), resolve_family(b, profiles["profiles"])
    ka = profiles["profiles"][fa]["knobs"]
    kb = profiles["profiles"][fb]["knobs"]
    print(f"旋钮差异: {fa}  vs  {fb}")
    print("-" * 80)
    n = 0
    for k in profiles["knobs"]:
        if ka.get(k) != kb.get(k):
            n += 1
            print(f"  {k:24s} {str(ka.get(k)):16s} -> {kb.get(k)}")
    if n == 0:
        print("  （两者配置相同——此时任何行为差异都不能归因于 ECB）")
    print("-" * 80)
    print(f"共 {n} 项不同 / 共 {len(profiles['knobs'])} 项")
    print("提示：差异项越少，A/B 对比的归因越干净；想验证单一旋钮，用 --diff 找同配置家族做对照。")
    return 0


# ────────────────────────────────────────────────────────────── 入口
def build_engagement(args, profiles_doc: dict) -> dict:
    """从 CLI/engagement YAML 组装授权事实；对缺失属性宽容（便于被其它脚本复用）。"""
    def g(name, default=None):
        return getattr(args, name, default)

    eng: dict = {}
    if g("engagement"):
        raw = yaml.safe_load(Path(g("engagement")).read_text(encoding="utf-8")) or {}
        if g("scenario"):
            scen = {s.get("name"): s for s in (raw.get("scenarios") or [])}
            if g("scenario") not in scen:
                raise SystemExit(f"[error] 场景不存在: {g('scenario')}\n        可用: {', '.join(scen)}")
            eng = dict(scen[g("scenario")].get("engagement") or {})
        elif "engagement" in raw:
            eng = dict(raw["engagement"])
        else:
            eng = raw

    if g("auth_type") or g("issuer") or g("reference") or g("valid_until"):
        auth = dict(eng.get("authorization") or {})
        if g("auth_type"): auth["type"] = g("auth_type")
        if g("issuer"): auth["issuer"] = g("issuer")
        if g("reference"): auth["reference"] = g("reference")
        if g("valid_until"): auth["valid_until"] = g("valid_until")
        eng["authorization"] = auth

    if g("in_scope") or g("out_of_scope"):
        scope = dict(eng.get("scope") or {})
        if g("in_scope"):
            scope["in_scope"] = [x.strip() for x in g("in_scope").split(",") if x.strip()]
        if g("out_of_scope"):
            scope["out_of_scope"] = [x.strip() for x in g("out_of_scope").split(",") if x.strip()]
        eng["scope"] = scope

    return eng



# ────────────────────────────────────────────── 矩阵（21 画像 × 9 旋钮）
ABBR = {
    "ecb_placement": {"system": "sys", "user_prefix": "upre", "first_turn": "turn", "none": "—"},
    "authorization_signal": {"full": "full", "compact": "cmp", "minimal": "min", "none": "—"},
    "role_framing": {"defensive_engineer": "def", "pentest_consultant": "pen",
                     "research": "res", "none": "—"},
    "intent_disambiguation": {"defensive_purpose": "def", "verification_only": "ver",
                              "dual_use": "dual", "none": "—"},
    "scope_granularity": {"asset_list": "list", "asset_compact": "cmp", "narrative": "narr",
                          "none": "—"},
    "output_contract": {"strict": "strict", "light": "light", "none": "—"},
    "language": {"zh": "zh", "en": "en", "bilingual": "bi"},
    "chain_of_thought": {"analysis_first": "ana", "direct": "dir"},
    "refusal_escape_hatch": {"allow_partial_refusal": "allow", "none": "—"},
}


SHORT = {
    "ecb_placement": "放置", "authorization_signal": "授权", "role_framing": "角色",
    "intent_disambiguation": "意图", "scope_granularity": "范围", "output_contract": "契约",
    "language": "语言", "chain_of_thought": "思维", "refusal_escape_hatch": "退路",
}


def cmd_matrix(profiles: dict, fmt: str = "md") -> int:
    """输出「画像 × 旋钮」档位矩阵。* 表示档位继承自其他画像（未独立测量）。"""
    fams = list(profiles["profiles"].items())
    knobs = list(profiles["knobs"].keys())
    rows = []
    for pid, p in fams:
        k = p["knobs"]
        rows.append({
            "profile": pid,
            "display": p.get("display", ""),
            "source": ("derived:" + str(p["derived_from"])) if p.get("derived_from") else "prior",
            "calibrated": load_calibration(pid) is not None,
            "knobs": {kn: k.get(kn) for kn in knobs},
        })

    if fmt == "json":
        print(json.dumps({"version": profiles.get("version"),
                          "n_profiles": len(rows), "knobs": knobs, "rows": rows},
                         ensure_ascii=False, indent=2))
        return 0

    def cell(kn: str, v: str) -> str:
        return ABBR.get(kn, {}).get(str(v), str(v))

    print("# 家族画像 × 9 旋钮档位矩阵（自动生成，勿手改）")
    print()
    print("> 生成：`python3 scripts/adapt.py --matrix --out references/family-matrix.md`")
    print("> 读法：`来源` 列三态 —— 实测（有 calibration）/ 继承 X（derived_from，未独立测量）/ 先验（tentative）；"
          "**只有「实测」行可作为结论**。")
    print()
    head = "| 画像 | 来源 | " + " | ".join(SHORT.get(k, k[:4]) for k in knobs) + " |"
    sep = "|" + "---|" * (len(knobs) + 2)
    print(head)
    print(sep)
    for r in rows:
        src = "实测" if r["calibrated"] else ("继承 " + r["source"].split(":")[-1] if r["source"].startswith("derived:") else "先验")
        cells = " | ".join(cell(kn, r["knobs"][kn]) for kn in knobs)
        print(f"| `{r['profile']}` | {src} | {cells} |")
    print()
    print("代码含义：")
    for kn in knobs:
        pairs = " / ".join(f"{code}={lv}" for lv, code in ABBR.get(kn, {}).items())
        print(f"  · {SHORT.get(kn, kn)}（{kn}）: {pairs}")
    print()
    print("来源：实测 = calibration/<family>.json 有数据；继承 = derived_from（未独立测量）；先验 = tentative 假设。")
    print("纪律：只有「实测」行可作为结论；继承/先验行仅作起点，差异必须用 measure_cooperation.py 配对验证。")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="按模型家族渲染定制语境块（ECB）")
    ap.add_argument("--profiles", default=str(DEFAULT_PROFILES), help="家族画像 YAML 路径")
    ap.add_argument("--list", action="store_true", help="列出所有家族画像")
    ap.add_argument("--show", metavar="FAMILY", help="显示某家族的旋钮与依据")
    ap.add_argument("--diff", nargs=2, metavar=("A", "B"), help="比较两个家族的旋钮差异")
    ap.add_argument("--matrix", action="store_true",
                    help="输出「画像 × 9 旋钮」档位矩阵（md/json），含实测/继承/先验来源标注")
    ap.add_argument("--matrix-format", default="md", choices=["md", "json"])

    ap.add_argument("--family", help="家族 id 或 model_id 片段（如 qwen / qwen2.5-7b-instruct）")
    ap.add_argument("--fingerprint", help="fingerprint.py 的输出 JSON（自动判定家族）")
    ap.add_argument("--task-category", help="任务类别（见 profiles 的 task_category_overrides）")

    ap.add_argument("--engagement", help="engagement YAML（默认模板见 assets/）")
    ap.add_argument("--scenario", help="engagement YAML 里的 scenarios[].name")
    ap.add_argument("--auth-type", choices=["written_contract", "internal_mandate", "ctf", "own_lab"])
    ap.add_argument("--issuer")
    ap.add_argument("--reference")
    ap.add_argument("--valid-until")
    ap.add_argument("--in-scope", help="逗号分隔，如 app.example.com,10.0.0.0/24")
    ap.add_argument("--out-of-scope", help="逗号分隔")

    ap.add_argument("--format", default="md", choices=["md", "system", "yaml"],
                    help="md=带标题的完整块；system=可直接粘的纯文本；yaml=结构化")
    ap.add_argument("--out", help="输出文件（默认 stdout）")
    ap.add_argument("--no-calibration", action="store_true", help="忽略实测校准，只看先验")
    args = ap.parse_args(argv)

    profiles = load_profiles(Path(args.profiles))

    if args.list:
        return cmd_list(profiles)
    if args.show:
        return cmd_show(profiles, args.show)
    if args.diff:
        return cmd_diff(profiles, args.diff[0], args.diff[1])
    if args.matrix:
        if args.out:
            import contextlib, io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cmd_matrix(profiles, args.matrix_format)
            Path(args.out).write_text(buf.getvalue(), encoding="utf-8")
            print(f"[ok] 已写入 {args.out}（matrix, {args.matrix_format}）", file=sys.stderr)
            return 0
        return cmd_matrix(profiles, args.matrix_format)

    if not args.family and not args.fingerprint:
        raise SystemExit("[error] 需要 --family 或 --fingerprint（或用 --list / --show / --diff）")

    if args.fingerprint:
        pick = pick_from_fingerprint(Path(args.fingerprint), profiles["profiles"])
        if args.family:
            # 显式指定优先，但要提示与指纹结论是否一致
            fam = resolve_family(args.family, profiles["profiles"])
            if fam != pick.family:
                pick.caveats.append(
                    f"显式指定 {fam} 与指纹最高分 {pick.family}"
                    f"({pick.score:.2f}) 不一致：已按显式指定渲染，但归因时不可混用" if pick.score is not None
                    else f"显式指定 {fam} 与指纹结论不一致：已按显式指定渲染"
                )
            pick.family = fam
            pick.source = "explicit"
    elif args.family:
        fam = resolve_family(args.family, profiles["profiles"])
        pick = FamilyPick(fam, "explicit", None, [])
    else:
        raise SystemExit("[error] 参数不足")

    family = pick.family
    knobs, notes = effective_knobs(profiles, family, args.task_category, strict=True)

    calib = None if args.no_calibration else load_calibration(family)
    calib_note = None
    if calib:
        knobs, cal_notes = apply_calibration(knobs, calib)
        notes.extend(cal_notes)
        calib_note = f"已实测校准 n={calib.get('n_tasks','?')}"
    else:
        pick.caveats.append(
            "该画像未经实测校准：旋钮为先验假设，ΔCRLT 需用 measure_cooperation.py 实测，"
            "不得把先验当结论"
        )
        parent = profiles["profiles"].get(family, {}).get("derived_from")
        if parent:
            pick.caveats.append(
                f"该画像 9 个旋钮继承自 {parent}（未独立测量）：报告里不要写成"
                f"「{family} 的拒答特征是 …」，只能写「按 {parent} 的档位起步，待实测」"
            )

    eng = build_engagement(args, profiles)

    if args.format == "md":
        text = render_markdown(family, pick, knobs, eng, args.task_category, profiles, notes, calib_note)
    elif args.format == "system":
        text = render_system_text(family, pick, knobs, eng, args.task_category, profiles)
    else:
        text = render_yaml(family, pick, knobs, eng, args.task_category, profiles)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"[ok] 已写入 {args.out}（profile={family}, format={args.format}）", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

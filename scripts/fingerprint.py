#!/usr/bin/env python3
"""
模型指纹识别（Model Fingerprinting）
====================================

定位：只依赖**可观测行为**推断模型家族 / 部署方式 / 能力边界。
      与 nmap 的 OS 指纹识别同构——看协议栈的"口音"，而不是问它"你是什么系统"。

不做的事：不发送任何越狱载荷、不尝试改变模型行为。本脚本只观测。

用法：
    # Ollama
    python3 fingerprint.py --base http://127.0.0.1:11434 --api ollama

    # OpenAI 兼容端点（vLLM / TGI / 各类代理网关）
    python3 fingerprint.py --base https://api.example.com/v1 --key "$EVAL_API_KEY" --out fp.json

    # 离线校验打分逻辑
    python3 fingerprint.py --self-test

输出：
    - 模型家族概率分布（带证据链）
    - tokenizer 指纹向量（差分量，剥离 chat template 开销）
    - 能力矩阵（logprobs / tools / system_fingerprint / context 上限）
    - 明确列出「不可区分」与「需校准」项

重要：tokenizer 向量的**参考值必须由你自己校准**。用你控制的同家族端点各跑一次，
      把结果存为 references/*.json 作为基线；不校准就只能看相对形状，不能断言家族。
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None

TIMEOUT = 20.0

# ── tokenizer 探针 ────────────────────────────────────────────────
# 设计原则：挑不同 tokenizer 家族切分差异最大的串。
#   ascii_repeat   BPE 会把重复字符压成少数 token；词表大小不同 → 差异明显
#   digits         有的 tokenizer 逐位切，有的按 1-3 位分组（Llama 3 与 cl100k 差别大）
#   cjk_zh         中文压缩率直接反映词表覆盖（o200k / Qwen 明显优于 cl100k）
#   emoji          byte-level BPE 下 emoji 常被切成多 token，各家族切法不同
#   rare_unicode   低频字符必然走 fallback bytes，可反推 byte-level 还是 sentencepiece
#   long_compound  德语长复合词：子词切分策略差异放大
#   whitespace     sentencepiece 用 ▁ 表示空格，与 byte-level BPE 处理完全不同
TOKENIZER_PROBES: dict[str, str] = {
    "ascii_plain": "The quick brown fox jumps over the lazy dog.",
    "ascii_repeat": "a" * 128,
    "digits": "1234567890" * 8,
    "cjk_zh": "渗透测试工程师对授权目标进行安全评估并输出报告",
    "cjk_mixed": "SQL注入与XSS是两个常见漏洞类别",
    "emoji": "\U0001F512\U0001F6E1\ufe0f\U0001F50D" * 10,
    "code": "def f(x):\n    return [i**2 for i in range(x)]\n",
    "rare_unicode": "\u1820\u1821\u1822\u1823\u1824 \u16a0\u16a2\u16a6\u16a8\u16b1\u16b2",
    "long_compound": "Rindfleischetikettierungs\u00fcberwachungsaufgaben\u00fcbertragungsgesetz",
    "whitespace": "word " * 64,
}


# ── 数据结构 ──────────────────────────────────────────────────────
@dataclass
class Ev:
    """一条证据。weight 为该信号对该家族的相对支持度。"""
    family: str
    weight: float
    signal: str
    detail: str


@dataclass
class Report:
    base: str
    api_kind: str = "auto"
    model_ids: list[str] = field(default_factory=list)
    evidence: list[Ev] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    token_vector: dict[str, int] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


# ── HTTP 基础 ────────────────────────────────────────────────────
def _join(base: str, path: str) -> str:
    b = base.rstrip("/")
    if b.endswith("/v1") and path.startswith("/v1/"):
        return b + path[len("/v1"):]
    return b + path


def _hdr(key: str | None) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h


def _client():
    if httpx is None:
        raise SystemExit("需要 httpx：pip install httpx")
    # trust_env=False 是必需的：本机 http_proxy / all_proxy 可能已失效，
    # 走环境代理会变成连接超时而不是直连。实测过这个坑。
    return httpx.Client(timeout=TIMEOUT, verify=False, trust_env=False,
                        follow_redirects=False)


def _chat(c, base: str, key: str | None, payload: dict) -> Any:
    """chat 调用，自动兼容 max_tokens → max_completion_tokens 的 400。"""
    url = _join(base, "/v1/chat/completions")
    r = c.post(url, headers=_hdr(key), json=payload)
    if r.status_code in (400, 422) and "max_tokens" in payload:
        alt = dict(payload)
        alt.pop("max_tokens", None)
        alt["max_completion_tokens"] = 1
        r2 = c.post(url, headers=_hdr(key), json=alt)
        if r2.status_code < 400:
            return r2
    return r


# ── L1：声明层 ───────────────────────────────────────────────────
def probe_models(c, base: str, key: str | None, rep: Report) -> None:
    try:
        r = c.get(_join(base, "/v1/models"), headers=_hdr(key))
        rep.raw["models_status"] = r.status_code
        srv = (r.headers.get("server") or "").strip()
        if srv:
            rep.raw["server"] = srv
            if "uvicorn" in srv.lower():
                rep.evidence.append(Ev("vllm_selfhost", 0.5, "header",
                                       f"server: {srv} → Python ASGI 自建（vLLM/TGI/SGLang 类）"))
        if r.status_code == 200:
            data = r.json().get("data") or []
            for d in data:
                if isinstance(d, dict) and d.get("id"):
                    mid = str(d["id"])
                    if mid not in rep.model_ids:
                        rep.model_ids.append(mid)
    except Exception as e:
        rep.failures.append(f"/v1/models -> {type(e).__name__}")

    try:
        r = c.get(_join(base, "/api/tags"), headers=_hdr(key))
        rep.raw["ollama_tags_status"] = r.status_code
        if r.status_code == 200:
            names = [str(m.get("name")) for m in (r.json().get("models") or [])
                     if isinstance(m, dict) and m.get("name")]
            for nm in names:
                if nm not in rep.model_ids:
                    rep.model_ids.append(nm)
            rep.evidence.append(Ev("ollama_local", 0.8, "endpoint",
                                   "/api/tags 返回 200 → Ollama 风格接口"))
    except Exception:
        pass

    # /tokenize（vLLM 原生）与 /v1/tokenize：最硬的框架特征，且能直接给精确 token 数
    for path in ("/v1/tokenize", "/tokenize"):
        try:
            r = c.post(_join(base, path), headers=_hdr(key), json={"prompt": "x"})
            if r.status_code < 400:
                rep.raw["tokenize_path"] = path
                rep.evidence.append(Ev("vllm_selfhost", 0.6, "endpoint",
                                       f"{path} 可用 → vLLM 系推理框架（可拿精确 token 数）"))
                break
        except Exception:
            continue


def probe_error_schema(c, base: str, key: str | None, rep: Report) -> None:
    """故意发一个结构错误的请求，读错误体 schema。各家错误格式有稳定差异。"""
    try:
        r = c.post(_join(base, "/v1/chat/completions"), headers=_hdr(key),
                   json={"messages": "not-a-list"})
        rep.raw["error_status"] = r.status_code
        try:
            body = r.json()
        except Exception:
            body = None
        rep.raw["error_body"] = body
        if not isinstance(body, dict):
            return
        if isinstance(body.get("error"), dict):
            err = body["error"]
            rep.raw["error_keys"] = sorted(err.keys())
            if str(err.get("type")) == "invalid_request_error":
                rep.evidence.append(Ev("openai_gpt", 0.4, "error_schema",
                                       "error.type == invalid_request_error（OpenAI 风格）"))
        if "innererror" in json.dumps(body).lower():
            rep.evidence.append(Ev("azure_openai", 0.6, "error_schema",
                                   "出现 innererror → Azure OpenAI 包装层"))
    except Exception as e:
        rep.failures.append(f"error_schema -> {type(e).__name__}")


# ── L2：行为层 ───────────────────────────────────────────────────
def probe_capabilities(c, base: str, key: str | None, rep: Report,
                       model: str | None) -> None:
    """能力矩阵比模型名更难伪造：网关可以改 model 字段，但改不了 logprobs 的实际结构。"""
    p: dict[str, Any] = {
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "logprobs": True,
        "top_logprobs": 2,
    }
    if model:
        p["model"] = model
    try:
        r = _chat(c, base, key, p)
        rep.capabilities["logprobs_status"] = r.status_code
        if r.status_code < 400:
            body = r.json()
            rep.capabilities["has_logprobs"] = bool(body.get("choices", [{}])[0].get("logprobs"))
            rep.capabilities["has_system_fingerprint"] = "system_fingerprint" in body
            if "system_fingerprint" in body:
                rep.evidence.append(Ev("openai_gpt", 0.5, "system_fingerprint",
                                       "响应含 system_fingerprint（OpenAI 平台特征）"))
            rep.capabilities["id_prefix"] = str(body.get("id", ""))[:12]
            rep.capabilities["model_echo"] = body.get("model")
    except Exception as e:
        rep.failures.append(f"capabilities -> {type(e).__name__}")


def probe_tokenizer(c, base: str, key: str | None, rep: Report,
                    model: str | None) -> None:
    """tokenizer 指纹：唯一与权重强绑定的信号。用差分量剥离 chat template 常数开销。"""
    base_payload: dict[str, Any] = {
        "messages": [{"role": "user", "content": "x"}],
        "max_tokens": 1,
    }
    if model:
        base_payload["model"] = model
    r = _chat(c, base, key, base_payload)
    if r.status_code >= 400:
        rep.failures.append(f"tokenizer 基线 -> HTTP {r.status_code}（可能不支持 usage 字段）")
        return
    try:
        base_n = int(r.json()["usage"]["prompt_tokens"])
    except Exception:
        rep.failures.append("tokenizer 基线 -> 响应无 usage.prompt_tokens，跳过该层")
        return

    vec: dict[str, int] = {}
    for name, text in TOKENIZER_PROBES.items():
        p = {"messages": [{"role": "user", "content": text}], "max_tokens": 1}
        if model:
            p["model"] = model
        try:
            rr = _chat(c, base, key, p)
            if rr.status_code >= 400:
                continue
            vec[name] = int(rr.json()["usage"]["prompt_tokens"]) - base_n
        except Exception:
            continue
    rep.token_vector = vec
    if len(vec) < len(TOKENIZER_PROBES) // 2:
        rep.failures.append(f"tokenizer 仅采集到 {len(vec)}/{len(TOKENIZER_PROBES)} 个探针")


def probe_context_limit(c, base: str, key: str | None, rep: Report,
                        model: str | None) -> None:
    """二分探测上下文上限。用不存在的模型名也能测（部分端点先校验长度再校验模型）。"""
    url = _join(base, "/v1/chat/completions")
    lo, hi = 1000, 200_000
    def ok(n: int) -> bool:
        p: dict[str, Any] = {"messages": [{"role": "user", "content": "x" * n}],
                             "max_tokens": 1}
        if model:
            p["model"] = model
        try:
            r = c.post(url, headers=_hdr(key), json=p)
        except Exception:
            return False
        # 413 / 400 + "too long" 类报错 → 超限；其它错误无法区分，按"可能超限"处理
        if r.status_code == 413:
            return False
        if r.status_code >= 400:
            txt = r.text.lower()
            return not any(k in txt for k in ("too long", "context", "maximum", "exceed"))
        return True

    if not ok(lo):
        rep.capabilities["context_limit_est"] = "<1000 或端点不兼容"
        return
    while lo < hi and hi - lo > 2000:
        mid = (lo + hi) // 2
        if ok(mid):
            lo = mid
        else:
            hi = mid
    rep.capabilities["context_limit_est"] = f"~{lo} 字符（字符≠token，仅量级参考）"


# ── 打分 ────────────────────────────────────────────────────────
def aggregate(evidence: list[Ev]) -> dict[str, float]:
    """证据累加 + 归一化。负权重信号不参与（用于表达"反向证据"）。"""
    agg: dict[str, float] = {}
    for e in evidence:
        agg[e.family] = agg.get(e.family, 0.0) + e.weight
    total = sum(v for v in agg.values() if v > 0) or 1.0
    return {k: round(v / total, 4)
            for k, v in sorted(agg.items(), key=lambda kv: -kv[1]) if v > 0}


def match_ids(rep: Report, fam: dict) -> None:
    pats = fam.get("id_patterns") or []
    seen: set[tuple[str, str]] = set()
    for mid in rep.model_ids:
        low = mid.lower()
        for p in pats:
            pat = str(p.get("pattern", "")).lower()
            if not pat or pat not in low:
                continue
            key = (low, pat)
            if key in seen:          # /v1/models 与 /api/tags 可能报同一个模型
                continue
            seen.add(key)
            rep.evidence.append(Ev(str(p["family"]), float(p.get("weight", 0.5)),
                                   "model_id",
                                   f"model id '{mid}' 命中 '{pat}'"))


# ── 基线校准比对 ────────────────────────────────────────────────
def load_baselines(path: Path) -> list[dict]:
    """读取基线。支持单文件或目录下全部 *.json，结构：{"family": "...", "vector": {...}}。"""
    out: list[dict] = []
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    for f in files:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        vec = d.get("vector") or d.get("token_vector")
        fam = d.get("family") or f.stem
        if isinstance(vec, dict) and vec:
            try:
                out.append({"family": str(fam),
                            "vector": {k: int(v) for k, v in vec.items()},
                            "src": f.name})
            except (TypeError, ValueError):
                continue
    return out


def l1_distance(a: dict, b: dict) -> float | None:
    """归一化 L1 距离：d = Σ|a−b| / Σ|b|。分母用基线，量纲一致。"""
    keys = [k for k in a if k in b]
    if not keys:
        return None
    denom = sum(abs(b[k]) for k in keys)
    if denom == 0:
        return None
    return sum(abs(a[k] - b[k]) for k in keys) / denom


def compare_baselines(rep: Report, baselines: list[dict]) -> list[dict]:
    """与自控基线比对。距离只用于「支持/削弱」，不用于「排除」——不是它≠是别人。"""
    res: list[dict] = []
    for bl in baselines:
        d = l1_distance(rep.token_vector, bl["vector"])
        if d is None:
            continue
        res.append({"family": bl["family"], "distance": round(d, 4), "src": bl["src"]})
        if d < 0.10:
            rep.evidence.append(Ev(bl["family"], 0.85, "tokenizer_baseline",
                                   f"与基线 {bl['src']} 归一化 L1 d={d:.3f} < 0.10 → 高度一致"))
        elif d < 0.25:
            rep.evidence.append(Ev(bl["family"], 0.4, "tokenizer_baseline",
                                   f"与基线 {bl['src']} d={d:.3f} ∈ [0.10,0.25) → 同家族可疑，需更多证据"))
        # d ≥ 0.25 不产生任何证据：避免把「不是 A」误读成「是 B」
    return sorted(res, key=lambda x: x["distance"])


def detect_contradiction(rep: Report, base_res: list[dict]) -> dict | None:
    """声明层与行为层冲突检测——这是识别「网关改写 model 字段」的唯一可靠手段。

    model_id 说是 A、tokenizer 基线却指向 B 且 d<0.10：两者不可能同时为真。
    正确动作不是把分数平均掉，而是把它当成结论本身写进报告。
    """
    id_fams = {e.family for e in rep.evidence if e.signal == "model_id"}
    bl_fams = {b["family"] for b in base_res if b.get("distance", 9.9) < 0.10}
    if id_fams and bl_fams and id_fams.isdisjoint(bl_fams):
        return {"declared": sorted(id_fams), "behavior": sorted(bl_fams)}
    return None


# ── 输出 ────────────────────────────────────────────────────────
# ── 部署面暴露风险（AI-Infra-Guard 风格：只列本工具能观测/推断出的部署问题）──
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def assess_exposure(rep: Report, model_rank: dict[str, float],
                    deploy_rank: dict[str, float]) -> list[dict[str, Any]]:
    """把指纹结论翻译成「这个部署面暴露了什么」。

    basis 区分证据强度，避免把推断当实测：
      observed = 本次响应里直接看到（model_echo / logprobs / 声明与行为矛盾 / 模型清单）
      inferred = 该实现的默认行为，未在本端点逐条验证（如 Ollama 默认无鉴权）
    不写「可被越狱」这类本工具并未测量的结论。
    """
    caps = rep.capabilities or {}
    out: list[dict[str, Any]] = []

    def add(rid: str, risk: str, severity: str, basis: str,
            evidence: str, mitigation: str, ref: str = "") -> None:
        out.append({"id": rid, "risk": risk, "severity": severity,
                    "basis": basis, "evidence": evidence,
                    "mitigation": mitigation, "ref": ref})

    # EXP-01 Ollama：默认无鉴权，且管理面（pull/delete）与推理面同端口
    if deploy_rank.get("ollama_local", 0.0) >= 0.5:
        add("EXP-01", "Ollama 服务对外可达：默认无鉴权，管理面与推理面同端口",
            "high", "inferred",
            f"deployment_scores.ollama_local={deploy_rank['ollama_local']:.2f}；响应为 Ollama 原生风格。"
            "Ollama 默认仅监听 127.0.0.1，一旦以 OLLAMA_HOST=0.0.0.0 暴露且无前置鉴权，"
            "/api/tags 可匿名枚举权重、/api/pull 可拉取任意模型、/api/delete 可删除模型",
            "保持仅监听 127.0.0.1；确需远程访问时前置反代 + 鉴权；"
            "禁用 /api/pull 与 /api/delete；用网络策略限制来源",
            "OWASP LLM Top10: LLM06 Excessive Agency")

    # EXP-02 vLLM：OpenAI 兼容层不内置账号体系
    if deploy_rank.get("vllm_selfhost", 0.0) >= 0.5:
        add("EXP-02", "vLLM 自托管端点：鉴权需显式开启（--api-key），缺省即可匿名调用",
            "high", "inferred",
            f"deployment_scores.vllm_selfhost={deploy_rank['vllm_selfhost']:.2f}；"
            "响应含 vLLM 特征（uvicorn header / /v1/tokenize 可用）。"
            "未设 --api-key 时任何可达来源都能调用推理接口，并可用 /v1/models 枚举已加载权重",
            "启动时设置 --api-key 并配合反代做来源限制；关闭不必要的 /v1/tokenize、/metrics；"
            "按租户做配额与审计",
            "OWASP LLM Top10: LLM06")

    # EXP-03 声明模型身份不可验证 —— 只在有「实锤」时触发：
    #   ① 声明与行为矛盾（contradiction）；② 回填的 model 与清单里的 id 不一致；
    #   ③ 识别为聚合网关（model 透传是常态）。
    # 注意：has_system_fingerprint=False 在 vLLM/Ollama 这类非官方实现上是正常的，
    # 单独拿它报警会把所有自托管端点都标成风险（假阳性），故只作为背景写进证据。
    echo = caps.get("model_echo")
    declared = rep.model_ids[0] if rep.model_ids else None
    mismatch = bool(echo and declared and echo != declared)
    if caps.get("contradiction") or mismatch or deploy_rank.get("proxy_gateway", 0.0) >= 0.5:
        ev = []
        if caps.get("contradiction"):
            ev.append("contradiction=True（tokenizer 行为与声明 id 不一致）")
        if mismatch:
            ev.append(f"回填 model={echo!r} 与清单 id={declared!r} 不一致")
        if deploy_rank.get("proxy_gateway", 0.0) >= 0.5:
            ev.append(f"deployment_scores.proxy_gateway={deploy_rank['proxy_gateway']:.2f}")
        ev.append(f"has_system_fingerprint={caps.get('has_system_fingerprint')}")
        add("EXP-03", "声明模型身份不可验证：model 字段由服务端回填，可被网关改写或后端替换",
            "high" if caps.get("contradiction") else "medium", "observed",
            "；".join(ev),
            "不要用 model 字段做计费/权限/合规判定；需要可信身份时以自控基线 + tokenizer 行为比对为准；"
            "网关侧记录 upstream 路由目标，而非仅记录用户请求值",
            "本报告 §诚实性声明；NIST AI RMF MEASURE 2.5")

    # EXP-04 Azure OpenAI：endpoint 与 key 分离，key 泄露可离线复用
    if deploy_rank.get("azure_openai", 0.0) >= 0.5:
        add("EXP-04", "Azure OpenAI 部署：endpoint/api-version 与 key 分离，key 泄露可直接消耗配额",
            "medium", "inferred",
            f"deployment_scores.azure_openai={deploy_rank['azure_openai']:.2f}；"
            "路径含 /openai/deployments/<name> 且带 api-version。key 无来源绑定，"
            "一旦进入前端代码或日志即可离线复用",
            "key 只放服务端密钥库并定期轮换；按 deployment 维度设配额与告警；"
            "禁止前端直连 Azure endpoint；开启 diagnostic settings 审计",
            "Azure Well-Architected: SE:05")

    # EXP-05 代理/聚合网关：集中持有上游 key + 完整 prompt 留痕
    if deploy_rank.get("proxy_gateway", 0.0) >= 0.5:
        add("EXP-05", "代理/聚合网关：多租户共用上游凭据，prompt 与响应在网关侧完整留痕",
            "medium", "inferred",
            f"deployment_scores.proxy_gateway={deploy_rank['proxy_gateway']:.2f}；"
            "存在多模型路由或声明/行为不一致特征。此类网关通常集中持有上游 key，"
            "并以明文记录完整会话用于计费与风控",
            "网关侧对 prompt 做脱敏或缩短保留期；上游 key 按租户隔离；"
            "model 字段走白名单，拒绝透传任意模型名",
            "OWASP LLM Top10: LLM06")

    # EXP-06 logprobs 开放
    if caps.get("has_logprobs") is True:
        add("EXP-06", "接口返回 token logprobs：可用于指纹识别、成员推断与蒸馏",
            "low", "observed",
            f"capabilities.has_logprobs=True（HTTP {caps.get('logprobs_status')}）",
            "非必要不返回 logprobs；必须返回时限制 top-k 并做速率限制",
            "OWASP LLM Top10: LLM02")

    # EXP-07 模型清单可匿名枚举
    if rep.model_ids:
        head = ", ".join(rep.model_ids[:6]) + (" …" if len(rep.model_ids) > 6 else "")
        add("EXP-07", "模型清单可匿名枚举（/v1/models 或 /api/tags）",
            "info", "observed", f"model_ids=[{head}]",
            "对外端点不暴露内部权重清单；用逻辑别名替代真实权重名",
            "OWASP LLM Top10: LLM06")

    out.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 9))
    return out


def render(rep: Report, ranked: dict[str, float],
           baselines: list[dict] | None = None,
           deploy_ids: set[str] | None = None) -> str:
    deploy_ids = deploy_ids or set()

    def _norm(d: dict[str, float]) -> dict[str, float]:
        s = sum(d.values()) or 1.0
        return {k: v / s for k, v in d.items()}

    model_rank = _norm({k: v for k, v in ranked.items() if k not in deploy_ids})
    deploy_rank = _norm({k: v for k, v in ranked.items() if k in deploy_ids})

    L: list[str] = []
    L.append("=" * 68)
    L.append("模型指纹报告")
    L.append("=" * 68)
    L.append(f"端点        : {rep.base}")
    L.append(f"声明模型 ID : {', '.join(rep.model_ids) if rep.model_ids else '(未获取)'}")
    L.append("")
    L.append("── 模型家族（族内归一，基于可观测证据，非断言）" + "─" * 12)
    if model_rank:
        for k, v in model_rank.items():
            bar = "█" * max(1, int(v * 30))
            L.append(f"  {k:<18} {v:>6.2%}  {bar}")
    else:
        L.append("  (证据不足)")
    L.append("")
    if deploy_rank:
        L.append("── 部署方式（与家族正交的独立维度）" + "─" * 24)
        for k, v in deploy_rank.items():
            bar = "█" * max(1, int(v * 30))
            L.append(f"  {k:<18} {v:>6.2%}  {bar}")
        L.append("")

    ctr = rep.capabilities.get("contradiction")
    if ctr:
        L.append("⚠ 声明层与行为层冲突 —— 不可用「取最高分」的方式消化")
        L.append(f"  声明(model_id) 指向 : {', '.join(ctr['declared'])}")
        L.append(f"  行为(tokenizer) 指向: {', '.join(ctr['behavior'])}  (d<0.10)")
        L.append("  → 最可能：网关改写 model 字段 / 模型被替换 / 该端点为多模型路由")
        L.append("  → 结论应写「声明为 X，实际行为与 Y 一致」，而不是二选一")
        L.append("")
    L.append("── 证据链")
    for e in rep.evidence:
        L.append(f"  [{e.signal:<20}] {e.family:<18} w={e.weight:<5} {e.detail}")
    if not rep.evidence:
        L.append("  (无)")
    L.append("")
    L.append("── tokenizer 指纹向量（差分量）")
    if rep.token_vector:
        L.append("  " + json.dumps(rep.token_vector, ensure_ascii=False, sort_keys=True))
        if baselines:
            L.append("  ── 与自控基线的归一化 L1 距离（d<0.10 高度一致 / 0.25+ 不同 tokenizer）")
            for b in baselines:
                mark = "✓" if b["distance"] < 0.10 else ("?" if b["distance"] < 0.25 else "✗")
                L.append(f"    {mark} {b['family']:<18} d={b['distance']:<7} ← {b['src']}")
        else:
            L.append("  ⚠ 未提供基线：只能看相对形状，不能断言家族。")
            L.append("    校准法见 references/signals.md（用自控端点跑 --save-baseline 即可）")
    else:
        L.append("  (未采集)")
    L.append("")
    L.append("── 能力矩阵")
    L.append("  " + json.dumps(rep.capabilities, ensure_ascii=False, sort_keys=True))
    L.append("")
    expose = assess_exposure(rep, model_rank, deploy_rank)
    L.append("── 部署面暴露风险（observed=本次实测 / inferred=该实现的默认行为）")
    if expose:
        for r in expose:
            L.append(f"  [{r['severity'].upper():<6}] {r['id']} {r['risk']}")
            L.append(f"      basis={r['basis']} · {r['evidence']}")
            L.append(f"      → {r['mitigation']}")
    else:
        L.append("  (未发现可归因于部署面的暴露项)")
    L.append("")
    if rep.failures:
        L.append("── 采集失败项")
        for f in rep.failures:
            L.append(f"  · {f}")
        L.append("")
    L.append("── 诚实性声明")
    L.append("  · 上表是「与哪些家族一致」，不是「它就是某模型」")
    L.append("  · 微调模型 / 蒸馏模型 / 多模型路由网关 在行为层不可区分")
    L.append("  · 模型名可被网关改写，故 id 只作弱证据（w≤0.9，且需交叉验证）")
    L.append("=" * 68)
    return "\n".join(L)


def to_json(rep: Report, ranked: dict[str, float],
            baselines: list[dict] | None = None,
            deploy_ids: set[str] | None = None) -> dict:
    deploy_ids = deploy_ids or set()

    # 两组分别归一：部署信号（uvicorn/端点/命名）不应稀释模型家族分数，
    # 否则与 render() 的人类可读报告不一致（同一份证据两个版本给出两个分数）。
    def _norm(d: dict[str, float]) -> dict[str, float]:
        s_ = sum(d.values()) or 1.0
        return {k: round(v / s_, 4) for k, v in d.items() if v > 0}

    fam_raw = {k: v for k, v in ranked.items() if k not in deploy_ids}
    dep_raw = {k: v for k, v in ranked.items() if k in deploy_ids}
    return {
        "base": rep.base,
        "model_ids": rep.model_ids,
        "family_scores": _norm(fam_raw),
        "deployment_scores": _norm(dep_raw),
        "evidence": [{"family": e.family, "weight": e.weight,
                      "signal": e.signal, "detail": e.detail} for e in rep.evidence],
        "token_vector": rep.token_vector,
        "baseline_distance": baselines or [],
        "capabilities": rep.capabilities,
        "exposure_risks": assess_exposure(rep, _norm(fam_raw), _norm(dep_raw)),
        "failures": rep.failures,
        "caveats": [
            "概率为证据加权归一，非统计推断",
            "微调/蒸馏/多模型路由在行为层不可区分",
            "model_id 可被网关改写，权重上限 0.9",
            "未提供自控基线时不得用 tokenizer 向量断言家族（只能看相对形状）",
            "距离只用于支持/削弱，不用于排除：不是 A ≠ 是 B",
        ],
    }


# ── 自检 ────────────────────────────────────────────────────────
def self_test() -> int:
    rep = Report(base="self-test")
    rep.model_ids = ["gpt-4o-mini-2026-01-01"]
    fam = {"id_patterns": [{"pattern": "gpt-4o", "family": "openai_gpt", "weight": 0.9}]}
    match_ids(rep, fam)
    rep.evidence.append(Ev("vllm_selfhost", 0.5, "header", "server: uvicorn"))
    ranked = aggregate(rep.evidence)

    assert ranked, "自检失败：证据为空"
    assert list(ranked)[0] == "openai_gpt", f"自检失败：排序错误 {ranked}"
    assert abs(sum(ranked.values()) - 1.0) < 1e-6, f"自检失败：未归一化 {ranked}"
    assert aggregate([]) == {}, "自检失败：空证据应返回空表"
    assert aggregate([Ev("x", -1.0, "s", "d")]) == {}, "自检失败：负权重应被剔除"
    # 证据链完整性
    assert all(isinstance(e.weight, float) for e in rep.evidence)
    # JSON 可序列化
    json.dumps(to_json(rep, ranked), ensure_ascii=False)
    # 基线距离：同家族应 <0.10，不同 tokenizer 应 ≥0.25
    a = {"digits": 80, "cjk_zh": 12, "whitespace": 64}
    assert l1_distance(a, a) == 0.0, "自检失败：自身距离应为 0"
    near = {"digits": 78, "cjk_zh": 13, "whitespace": 65}
    far = {"digits": 20, "cjk_zh": 30, "whitespace": 140}
    d_near, d_far = l1_distance(a, near), l1_distance(a, far)
    assert d_near is not None and d_near < 0.10, f"自检失败：近邻距离过大 {d_near}"
    assert d_far is not None and d_far >= 0.25, f"自检失败：远邻距离过小 {d_far}"
    assert l1_distance({}, a) is None, "自检失败：无共同键应返回 None"
    # 基线比对不得把「距离过远」写成证据
    rep2 = Report(base="self-test-2")
    rep2.token_vector = far
    compare_baselines(rep2, [{"family": "x", "vector": a, "src": "x.json"}])
    assert rep2.evidence == [], "自检失败：d≥0.25 不应产生证据"
    print("self-test OK:", ranked)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="模型指纹识别（仅观测，不发送载荷）")
    ap.add_argument("--base", "--base-url", dest="base",
                    help="端点基址，如 http://127.0.0.1:11434 或 https://x/v1"
                         "（--base 与 --base-url 等价，历史上两派混用过）")
    ap.add_argument("--key", default=None,
                    help="API key（建议用环境变量：--key \"$EVAL_API_KEY\"，勿写入文件）")
    ap.add_argument("--api", default="auto", choices=["auto", "openai", "ollama"])
    ap.add_argument("--families", default=None, help="families.yaml 路径（默认取包内 assets/）")
    ap.add_argument("--baseline", default=None,
                    help="基线文件或目录（结构 {\"family\":..,\"vector\":{..}}）；默认自动用包内 references/*.json")
    ap.add_argument("--save-baseline", default=None,
                    help="把本次 tokenizer 向量存为基线文件（用于校准自控端点）")
    ap.add_argument("--out", default=None, help="JSON 输出路径")
    ap.add_argument("--no-context", action="store_true", help="跳过上下文上限二分探测（较慢）")
    ap.add_argument("--self-test", action="store_true", help="离线校验打分逻辑")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.base:
        ap.error("需要 --base（或使用 --self-test）")

    pkg = Path(__file__).resolve().parent.parent
    fam_path = Path(args.families) if args.families else pkg / "assets" / "families.yaml"
    fam: dict = {}
    try:
        import yaml
        with open(fam_path, encoding="utf-8") as f:
            fam = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[warn] 载入 families 失败（{fam_path}）：{e}", file=sys.stderr)

    # 部署方式与模型家族是正交维度，展示时必须分开，否则会被读成互斥假设
    deploy_ids = {str(f.get("id")) for f in (fam.get("families") or [])
                  if isinstance(f, dict) and str(f.get("kind", "model")) == "deployment"}

    rep = Report(base=args.base, api_kind=args.api)
    with _client() as c:
        probe_models(c, args.base, args.key, rep)
        probe_error_schema(c, args.base, args.key, rep)
        model = rep.model_ids[0] if rep.model_ids else None
        probe_capabilities(c, args.base, args.key, rep, model)
        probe_tokenizer(c, args.base, args.key, rep, model)
        if not args.no_context:
            probe_context_limit(c, args.base, args.key, rep, model)

    # 基线：显式指定优先；否则自动发现包内 references/*.json
    bl_path = Path(args.baseline) if args.baseline else pkg / "references"
    baselines: list[dict] = []
    if bl_path.exists():
        baselines = load_baselines(bl_path)
        if args.baseline and not baselines:
            print(f"[warn] {bl_path} 下无可解析基线"
                  f"（需 {{\"family\":..,\"vector\":{{..}}}}）", file=sys.stderr)
    base_res = compare_baselines(rep, baselines) if baselines else []

    if fam:
        match_ids(rep, fam)

    ctr = detect_contradiction(rep, base_res)
    if ctr:
        rep.capabilities["contradiction"] = ctr

    ranked = aggregate(rep.evidence)
    print(render(rep, ranked, base_res, deploy_ids))

    if args.save_baseline:
        fam_name = None
        if not rep.token_vector:
            print("[warn] 无 tokenizer 向量，跳过 --save-baseline", file=sys.stderr)
        else:
            # 基线只能记「模型家族」。若把部署框架名（vllm_selfhost 等）写进 family 字段，
            # 后续 --baseline 比对会把部署证据算进模型家族分，且 contradiction 检测失效。
            model_ranked = {k: v for k, v in ranked.items() if k not in deploy_ids}
            fam_name = next(iter(model_ranked), None)
            if fam_name is None:
                print("[warn] 仅有部署类证据，无法确定模型家族；跳过 --save-baseline。"
                      "自控端点校准时可手工编辑基线 JSON 的 family 字段写真实家族名",
                      file=sys.stderr)
        if fam_name:
            dst = Path(args.save_baseline)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(json.dumps({"family": fam_name, "vector": rep.token_vector,
                                       "base": rep.base, "model_ids": rep.model_ids},
                                      ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"[+] 基线已写入 {dst}（family={fam_name}）")

    if args.out:
        dst = Path(args.out)
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(to_json(rep, ranked, base_res, deploy_ids), f,
                      ensure_ascii=False, indent=2)
        print(f"[+] JSON 已写入 {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

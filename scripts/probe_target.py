#!/usr/bin/env python3
"""probe_target.py — 评测前置 harness 探测（只读，无破坏性）。

固定发送无害探针（"ping" / "1+1"），不携带任何测试用例。
产出 probe.json，供 run_eval.py 决定并发/限流/是否可测 system prompt 轴。

CLI:
  python scripts/probe_target.py \
      --base-url http://127.0.0.1:8000/v1 \
      [--api-key-env EVAL_API_KEY] [--model auto|MODEL_NAME] \
      [--out runs/r1/probe.json] [--timeout 30] \
      [--concurrency-probe 8] [--probe-ctx] [--ctx-probe-max 131072] \
      [--json] [-v]

Exit codes:
  0  OK
  2  端点/鉴权不可用，或 api_flavor 无法识别（不进入评测）
  3  网络不可达 / DNS / TLS 失败
  4  模型列表为空或 --model 无法解析

纪律：本文件只发"ping"类无害请求，不读不写目标侧任何数据，不构造任何测试用例文本。
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal

import httpx

SCHEMA_VERSION = "1.0"

ApiFlavor = Literal["openai_chat", "openai_responses", "ollama", "vllm", "unknown"]
Support = Literal["enforced", "ignored", "unsupported", "unknown"]

# 进程内观测缓存：让 main 不必重复请求 /models
_MODEL_META: dict[str, dict[str, Any]] = {}
_WARN: list[str] = []
_AUTH_SEEN: list[int] = []


@dataclasses.dataclass
class RateProfile:
    """限流画像：由小批量并发探针观测得到，不追求精确，只求不把 429 误判成拒答。"""
    rps_observed: float
    retry_after_seen: int | None
    suggested_concurrency: int
    suggested_rpm: int


@dataclasses.dataclass
class ProbeResult:
    schema_version: str
    base_url: str
    api_flavor: ApiFlavor
    endpoint_path: str
    auth_scheme: Literal["bearer", "api-key-header", "none", "unknown"]
    models: list[str]
    resolved_model: str | None
    stream_supported: bool
    system_prompt: Support
    param_support: dict[str, bool]        # temperature/seed/max_tokens/top_p/stop/response_format/tools
    rate_limit: RateProfile
    context_window_tokens: int | None     # 探测值优先；否则取 /models 声明值
    max_output_tokens: int | None
    tokenizer_hint: str | None
    warnings: list[str]
    raw_evidence: list[dict[str, Any]]    # [{step, request_digest, status, note}]

    def to_json(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        return d


# ---------------------------------------------------------------- HTTP 客户端

class Resp:
    """统一响应：status=0 表示没拿到 HTTP 响应（连接层失败）。"""

    __slots__ = ("status", "body", "headers", "error", "latency_ms")

    def __init__(self, status: int, body: Any = None,
                 headers: dict[str, str] | None = None,
                 error: str | None = None, latency_ms: int = 0) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.error = error
        self.latency_ms = latency_ms

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        """取出 assistant 文本，兼容 openai_chat / responses / ollama。"""
        b = self.body
        if not isinstance(b, dict):
            return ""
        try:
            choices = b.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message") or {}
                c = msg.get("content")
                if isinstance(c, str):
                    return c
                if isinstance(c, list):      # 部分网关返回 content parts
                    return "".join(str(p.get("text", "")) for p in c if isinstance(p, dict))
                return str(choices[0].get("text") or "")
            msg = b.get("message")           # ollama
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
            out = b.get("output")            # responses
            if isinstance(out, list):
                buf = []
                for item in out:
                    for part in (item.get("content") or []) if isinstance(item, dict) else []:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            buf.append(part["text"])
                return "".join(buf)
            if isinstance(b.get("response"), str):
                return b["response"]
        except Exception:
            pass
        return ""

    def usage(self) -> dict[str, int]:
        b = self.body if isinstance(self.body, dict) else {}
        u = b.get("usage") or {}
        out: dict[str, int] = {}
        if isinstance(u, dict):
            if isinstance(u.get("prompt_tokens"), int):
                out["prompt_tokens"] = u["prompt_tokens"]
            if isinstance(u.get("completion_tokens"), int):
                out["completion_tokens"] = u["completion_tokens"]
        for k, v in (("prompt_eval_count", "prompt_tokens"), ("eval_count", "completion_tokens")):
            if isinstance(b.get(k), int) and v not in out:
                out[v] = b[k]
        return out

    def err_text(self) -> str:
        b = self.body
        if isinstance(b, dict):
            e = b.get("error")
            if isinstance(e, dict):
                return json.dumps(e, ensure_ascii=False)[:400]
            if isinstance(e, str):
                return e[:400]
            if isinstance(b.get("message"), str):
                return b["message"][:400]
        return json.dumps(b, ensure_ascii=False)[:400] if b is not None else (self.error or "")


def _join(base: str, path: str) -> str:
    """base 可能已含 /v1，避免拼成 /v1/v1/...。"""
    b = base.rstrip("/")
    p = path if path.startswith("/") else "/" + path
    if b.endswith("/v1") and p.startswith("/v1"):
        p = p[3:]
    return b + p


class ChatClient:
    """最小 chat 客户端。行为受 flavor 控制，不做任何自动重试（除参数名回退）。"""

    def __init__(self, base_url: str, api_key: str | None, model: str,
                 flavor: ApiFlavor = "openai_chat", endpoint_path: str = "/v1/chat/completions",
                 timeout: float = 30.0) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.flavor = flavor
        self.endpoint_path = endpoint_path or "/v1/chat/completions"
        self.timeout = timeout
        self._c = httpx.Client(timeout=timeout, verify=False, trust_env=False,
                               follow_redirects=False)

    # -- 生命周期 --
    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> "ChatClient":
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()

    # -- 请求 --
    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            if self.flavor == "openai_responses":
                h["Authorization"] = f"Bearer {self.api_key}"
            elif self.flavor == "ollama":
                h["Authorization"] = f"Bearer {self.api_key}"
            else:
                h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _payload(self, messages: list[dict[str, str]], params: dict[str, Any]) -> dict[str, Any]:
        if self.flavor == "ollama":
            opts = {k: v for k, v in params.items()
                    if k in ("temperature", "top_p", "seed", "stop", "num_predict")}
            if "max_tokens" in params:
                opts["num_predict"] = params["max_tokens"]
            body: dict[str, Any] = {"model": self.model, "messages": messages,
                                    "stream": False}
            if opts:
                body["options"] = opts
            return body
        if self.flavor == "openai_responses":
            text = "\n".join(m.get("content") or "" for m in messages)
            return {"model": self.model, "input": text, **params}
        body = {"model": self.model, "messages": messages}
        body.update({k: v for k, v in params.items() if v is not None})
        return body

    def chat(self, messages: list[dict[str, str]], **params: Any) -> Resp:
        url = _join(self.base_url, self.endpoint_path)
        payload = self._payload(messages, params)
        t0 = time.time()
        try:
            r = self._c.post(url, json=payload, headers=self._headers())
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            return Resp(0, error=f"connect: {e}", latency_ms=int((time.time() - t0) * 1000))
        except httpx.TimeoutException as e:
            return Resp(0, error=f"timeout: {e}", latency_ms=int((time.time() - t0) * 1000))
        except Exception as e:  # pragma: no cover - 兜底
            return Resp(0, error=f"{type(e).__name__}: {e}",
                        latency_ms=int((time.time() - t0) * 1000))
        ms = int((time.time() - t0) * 1000)
        try:
            body = r.json()
        except Exception:
            body = {"_raw": r.text[:500]}
        if r.status_code in (401, 403):
            _AUTH_SEEN.append(r.status_code)
        # 参数名回退：部分新端点只认 max_completion_tokens
        if r.status_code == 400 and "max_tokens" in params:
            et = json.dumps(body, ensure_ascii=False).lower()
            if "max_completion_tokens" in et:
                p2 = dict(params)
                p2["max_completion_tokens"] = p2.pop("max_tokens")
                return self.chat(messages, **p2)
        return Resp(r.status_code, body, dict(r.headers), None, ms)


# ---------------------------------------------------------------- 各探测步骤

def list_models(base_url: str, api_key: str | None, timeout: float) -> list[str]:
    """GET {base}/models。兼容 OpenAI(`data[].id`) 与 Ollama(`models[].name`) 两种结构。"""
    h = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    with httpx.Client(timeout=timeout, verify=False, trust_env=False,
                      follow_redirects=False) as c:
        for path in ("/v1/models", "/models", "/api/tags"):
            try:
                r = c.get(_join(base_url, path), headers=h)
            except Exception:
                continue
            if r.status_code in (401, 403):
                _AUTH_SEEN.append(r.status_code)
                continue
            if r.status_code != 200:
                continue
            try:
                body = r.json()
            except Exception:
                continue
            ids: list[str] = []
            data = body.get("data") if isinstance(body, dict) else None
            if isinstance(data, list):
                for d in data:
                    if isinstance(d, dict) and d.get("id"):
                        ids.append(str(d["id"]))
                        _MODEL_META[str(d["id"])] = d
            models = body.get("models") if isinstance(body, dict) else None
            if isinstance(models, list):
                for m in models:
                    if isinstance(m, dict):
                        nm = m.get("name") or m.get("model")
                        if nm:
                            ids.append(str(nm))
                            _MODEL_META[str(nm)] = m
            if ids:
                # 去重保序
                seen: set[str] = set()
                out = []
                for i in ids:
                    if i not in seen:
                        seen.add(i)
                        out.append(i)
                return out
    return []


def detect_api_flavor(base_url: str, api_key: str | None,
                      timeout: float) -> tuple[ApiFlavor, str]:
    """按候选路径逐条探测最小 chat 请求，返回 (flavor, 命中的 endpoint_path)。"""
    candidates: list[tuple[str, ApiFlavor]] = [
        ("/v1/chat/completions", "openai_chat"),
        ("/chat/completions", "openai_chat"),
        ("/v1/responses", "openai_responses"),
        ("/api/chat", "ollama"),
    ]
    h = {"Content-Type": "application/json"}
    if api_key:
        h["Authorization"] = f"Bearer {api_key}"
    with httpx.Client(timeout=timeout, verify=False, trust_env=False,
                      follow_redirects=False) as c:
        for path, flavor in candidates:
            if flavor == "ollama":
                payload: dict[str, Any] = {"model": "probe", "stream": False,
                                           "messages": [{"role": "user", "content": "ping"}]}
            elif flavor == "openai_responses":
                payload = {"model": "probe", "input": "ping"}
            else:
                payload = {"model": "probe", "max_tokens": 1,
                           "messages": [{"role": "user", "content": "ping"}]}
            try:
                r = c.post(_join(base_url, path), json=payload, headers=h)
            except Exception as e:
                _WARN.append(f"探测 {path} 失败：{type(e).__name__}")
                continue
            if r.status_code in (401, 403):
                _AUTH_SEEN.append(r.status_code)
            if r.status_code in (404, 405):
                continue
            try:
                body = r.json()
            except Exception:
                body = {}
            if r.status_code == 200:
                if isinstance(body, dict) and "choices" in body:
                    return ("openai_chat", path)
                if isinstance(body, dict) and isinstance(body.get("message"), dict):
                    return ("ollama", path)
                if isinstance(body, dict) and "output" in body:
                    return ("openai_responses", path)
                return (flavor, path)
            # 400/422/429：端点存在，只是我们发得不合要求 → 仍然认这个 flavor
            if 400 <= r.status_code < 500:
                return (flavor, path)
    return ("unknown", "")


def probe_system_prompt(client: Any, model: str) -> Support:
    """判断 system role 是否真正生效（很多自建网关会静默丢弃 system）。"""
    a = client.chat([{"role": "system", "content": "Reply with exactly the word PINEAPPLE"},
                     {"role": "user", "content": "go"}], max_tokens=8, temperature=0)
    if a.status == 0:
        _WARN.append(f"system_prompt 探测连接失败：{a.error}")
        return "unknown"
    if a.status in (400, 422) and "role" in a.err_text().lower():
        return "unsupported"
    b = client.chat([{"role": "user", "content": "go"}], max_tokens=8, temperature=0)
    if b.status == 0:
        return "unknown"
    ta, tb = a.text().upper(), b.text().upper()
    if "PINEAPPLE" in ta and "PINEAPPLE" not in tb:
        return "enforced"
    if "PINEAPPLE" not in ta and "PINEAPPLE" not in tb:
        return "ignored"
    return "unknown"


PARAM_PROBES: dict[str, Any] = {
    "temperature": 0.0,
    "seed": 0,
    "max_tokens": 1,
    "top_p": 1.0,
    "stop": ["\n\n"],
    "response_format": {"type": "text"},
    "tools": [],
}


def probe_params(client: Any, model: str) -> dict[str, bool]:
    """逐参数探测：带该参数发最小请求，4xx 且错误信息指向该参数则记 False。"""
    out: dict[str, bool] = {}
    base_msgs = [{"role": "user", "content": "ping"}]
    for name, val in PARAM_PROBES.items():
        r = client.chat(base_msgs, **{name: val})
        if r.status == 0:
            out[name] = False
            _WARN.append(f"参数 {name} 探测连接失败，按不支持处理")
            continue
        if r.ok:
            out[name] = True
            continue
        et = r.err_text().lower()
        if r.status in (400, 422) and (name.lower() in et or "unsupported parameter" in et
                                       or "unrecognized" in et):
            out[name] = False
        elif r.status == 429:
            out[name] = True          # 限流不代表参数不支持
            _WARN.append(f"参数 {name} 探测遇到 429，按支持处理（未验证）")
        else:
            out[name] = r.status not in (400, 422)
    if out.get("max_tokens") is False:
        r = client.chat(base_msgs, max_completion_tokens=1)
        if r.ok:
            out["max_tokens"] = True
            _WARN.append("max_tokens 被拒但 max_completion_tokens 可用（新 OpenAI 端点行为）")
    return out


def probe_rate_limit(client: Any, model: str, n: int = 8,
                     window_s: float = 5.0) -> RateProfile:
    """并发 n 个最小请求，统计成功率与首个 429 的 Retry-After。"""
    msgs = [{"role": "user", "content": "ping"}]
    t0 = time.time()
    statuses: list[int] = []
    retry_after: int | None = None

    def one() -> tuple[int, int | None]:
        r = client.chat(msgs, max_tokens=1, temperature=0)
        ra = None
        if r.status == 429:
            ra = _parse_retry_after(r.headers)
        return r.status, ra

    n = max(1, n)
    with cf.ThreadPoolExecutor(max_workers=min(n, 8)) as ex:
        for st, ra in ex.map(lambda _: one(), range(n)):
            statuses.append(st)
            if ra is not None:
                retry_after = max(retry_after or 0, ra)
    elapsed = max(1e-6, time.time() - t0)
    ok = sum(1 for s in statuses if 200 <= s < 300)
    rps = ok / elapsed
    conc = int(min(8, max(1, round(rps * 0.5) or 1)))
    rpm = int(min(600, max(1, round(rps * 60 * 0.6) or 1)))
    if any(s == 429 for s in statuses):
        _WARN.append(f"探测期出现 429（{statuses.count(429)}/{n}），已下调建议并发")
        conc = max(1, conc // 2)
        rpm = max(1, rpm // 2)
    return RateProfile(round(rps, 2), retry_after, conc, rpm)


def _parse_retry_after(headers: dict[str, str]) -> int | None:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return int(float(v))
            except Exception:
                return None
    return None


def probe_context_window(client: Any, model: str, cap: int = 131072) -> int | None:
    """可选（--probe-ctx）：无害填充串 + 二分，找"不报错的最大输入量级"。最多 8 次请求。"""
    lo, hi = 1024, max(2048, cap)
    best: int | None = None
    for _ in range(8):
        if lo > hi:
            break
        mid = (lo + hi) // 2
        r = client.chat([{"role": "user", "content": "A " * mid + "\nReply OK"}],
                        max_tokens=1, temperature=0)
        if r.status == 0:
            _WARN.append("上下文探测连接失败，提前结束")
            break
        if r.ok:
            best = mid
            lo = mid + 1
        elif r.status in (400, 413, 422):
            hi = mid - 1
        elif r.status == 429:
            _WARN.append("上下文探测遇到 429，提前结束（结果可能偏小）")
            break
        else:
            hi = mid - 1
    return best


# ---------------------------------------------------------------- 入口

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Probe an LLM endpoint before jailbreak-robustness evaluation")
    p.add_argument("--base-url", "--base", dest="base_url", required=True,
                   help="端点基址（--base-url 与 --base 等价）")
    p.add_argument("--api-key-env", default="EVAL_API_KEY", help="从该环境变量读取 key，禁止命令行明文传参")
    p.add_argument("--model", default="auto", help="auto = 取 /models 第一个；也可显式指定")
    p.add_argument("--out", default="probe.json")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--concurrency-probe", type=int, default=8)
    p.add_argument("--probe-ctx", action="store_true", help="启用上下文窗口探测（有 token 成本）")
    p.add_argument("--ctx-probe-max", type=int, default=131072)
    p.add_argument("--json", action="store_true", help="stdout 只输出 JSON")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _declared_ctx(model: str | None) -> int | None:
    if not model:
        return None
    meta = _MODEL_META.get(model) or {}
    for k in ("max_model_len", "context_window", "context_length", "max_context_tokens"):
        v = meta.get(k)
        if isinstance(v, int) and v > 0:
            return v
    return None


def _declared_max_out(model: str | None) -> int | None:
    if not model:
        return None
    meta = _MODEL_META.get(model) or {}
    for k in ("max_completion_tokens", "max_output_tokens"):
        v = meta.get(k)
        if isinstance(v, int) and v > 0:
            return v
    return None


def _tokenizer_hint(model: str | None) -> str | None:
    if not model:
        return None
    meta = _MODEL_META.get(model) or {}
    for k in ("tokenizer", "tokenizer_name", "tokenizer_id"):
        if isinstance(meta.get(k), str):
            return meta[k]
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_argparser().parse_args(argv)
    key = os.environ.get(args.api_key_env) or None
    ev: list[dict[str, Any]] = []

    def log(step: str, status: Any, note: str = "") -> None:
        ev.append({"step": step, "status": status, "note": note})
        if args.verbose:
            print(f"  [{step}] {status} {note}", file=sys.stderr)

    models = list_models(args.base_url, key, args.timeout)
    log("list_models", "ok" if models else "empty", f"{len(models)} models")
    if not models:
        if _AUTH_SEEN:
            print(f"[error] 鉴权失败（HTTP {sorted(set(_AUTH_SEEN))}）："
                  f"检查环境变量 {args.api_key_env}", file=sys.stderr)
            return 2
        # 区分"不可达"与"可达但没模型"
        try:
            with httpx.Client(timeout=min(8.0, args.timeout), verify=False,
                              trust_env=False) as c:
                c.get(_join(args.base_url, "/v1/models"))
        except Exception as e:
            print(f"[error] 端点不可达：{type(e).__name__}: {e}", file=sys.stderr)
            return 3
        print("[error] 模型列表为空（/v1/models、/models、/api/tags 均无结果）", file=sys.stderr)
        return 4

    flavor, path = detect_api_flavor(args.base_url, key, args.timeout)
    log("detect_api_flavor", flavor, path)
    if flavor == "unknown":
        print("[error] 无法识别 API flavor（/v1/chat/completions、/v1/responses、/api/chat 均不可用）",
              file=sys.stderr)
        return 2

    model = models[0] if args.model == "auto" else args.model
    if args.model != "auto" and model not in models:
        # 允许显式指定未列出的部署名（Azure 常见），但必须告警
        _WARN.append(f"--model {model} 未出现在 /models 列表中，按显式指定继续")
    log("resolve_model", model, "")

    with ChatClient(args.base_url, key, model, flavor, path, args.timeout) as client:
        system_prompt = probe_system_prompt(client, model)
        log("probe_system_prompt", system_prompt)

        # 流式支持：只发一个极小请求看 content-type / 是否 chunked
        stream_supported = False
        r = client.chat([{"role": "user", "content": "ping"}], max_tokens=1, stream=True)
        if r.status in (400, 422) and "stream" in r.err_text().lower():
            stream_supported = False
        elif r.ok or r.status == 0:
            stream_supported = r.ok
        log("probe_stream", stream_supported)

        param_support = probe_params(client, model)
        log("probe_params", param_support)

        rate = probe_rate_limit(client, model, n=args.concurrency_probe, window_s=5.0)
        log("probe_rate_limit", dataclasses.asdict(rate))

        ctx = None
        if args.probe_ctx:
            ctx = probe_context_window(client, model, args.ctx_probe_max)
            log("probe_context_window", ctx)
        if ctx is None:
            ctx = _declared_ctx(model)
            if ctx is None:
                _WARN.append("上下文上限未知（未启用 --probe-ctx 且 /models 未声明）")

    if system_prompt in ("ignored", "unsupported"):
        _WARN.append(f"system_prompt={system_prompt}：依赖 system role 的策略必须跳过，"
                     f"否则会把'被丢弃'误判为'没生效'")
    if not param_support.get("seed", False):
        _WARN.append("seed 不被支持：重复实验不可复现，报告需标注")

    result = ProbeResult(
        schema_version=SCHEMA_VERSION,
        base_url=args.base_url,
        api_flavor=flavor,
        endpoint_path=path,
        auth_scheme="bearer" if key else "none",
        models=models,
        resolved_model=model,
        stream_supported=stream_supported,
        system_prompt=system_prompt,
        param_support=param_support,
        rate_limit=rate,
        context_window_tokens=ctx,
        max_output_tokens=_declared_max_out(model),
        tokenizer_hint=_tokenizer_hint(model),
        warnings=_WARN,
        raw_evidence=ev,
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result.to_json(), ensure_ascii=False))
        return 0

    print("=" * 66)
    print("端点探针结果")
    print("=" * 66)
    print(f"端点        : {args.base_url}")
    print(f"API flavor  : {flavor}  ({path})")
    print(f"模型        : {model}  (共 {len(models)} 个)")
    print(f"system role : {system_prompt}")
    print(f"参数支持    : {', '.join(k for k, v in param_support.items() if v) or '(无)'}")
    print(f"不支持      : {', '.join(k for k, v in param_support.items() if not v) or '(无)'}")
    print(f"建议并发/RPM: {rate.suggested_concurrency} / {rate.suggested_rpm}"
          f"  (实测 {rate.rps_observed} rps, Retry-After={rate.retry_after_seen})")
    print(f"上下文上限  : {ctx if ctx is not None else '未知'}")
    if _WARN:
        print("\n警告:")
        for w in _WARN:
            print(f"  ! {w}")
    print(f"\n[+] 已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

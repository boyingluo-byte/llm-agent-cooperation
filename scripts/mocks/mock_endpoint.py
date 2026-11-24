#!/usr/bin/env python3
"""
离线 mock 端点（仅用于自测与 demo）
====================================

用途：在没有 API key、没有外网的情况下，验证 fingerprint.py 的完整链路
      （L1 声明层 → L2 tokenizer 向量 → 基线距离 → 家族判定）。

它**不是**真实模型：token 数由一套按字符类别的加权规则生成，只为让不同家族的
tokenizer 向量产生可区分的形状。任何基于本 mock 得出的结论都不代表真实模型。

用法：
    # 模拟一家 Qwen + vLLM 自建
    python3 mock_endpoint.py --port 18099 --model qwen2.5-7b-instruct --family qwen --style vllm

    # 另一个终端（本机代理已失效，httpx 侧已 trust_env=False）
    python3 fingerprint.py --base http://127.0.0.1:18099 --no-context
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 每字符 token 权重（近似真实量级，非精确复刻）
PROFILES: dict[str, dict[str, float]] = {
    "gpt":     {"letter": 0.26, "digit": 0.34, "cjk": 0.95, "emoji": 2.6,
                "rare": 3.0, "space": 0.12, "punct": 0.30, "bias": 0.0},
    "qwen":    {"letter": 0.28, "digit": 0.30, "cjk": 0.58, "emoji": 1.8,
                "rare": 2.4, "space": 0.12, "punct": 0.30, "bias": 0.0},
    "llama":   {"letter": 0.25, "digit": 0.62, "cjk": 1.30, "emoji": 3.2,
                "rare": 3.4, "space": 0.45, "punct": 0.30, "bias": 0.0},
    "mistral": {"letter": 0.25, "digit": 0.60, "cjk": 1.35, "emoji": 3.2,
                "rare": 3.4, "space": 0.45, "punct": 0.30, "bias": 0.0},
}

CTX_CHARS = 32768


def count_tokens(text: str, prof: dict[str, float]) -> int:
    total = 0.0
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == " ":
            j = i
            while j < n and text[j] == " ":
                j += 1
            total += 1.0 + (j - i - 1) * prof["space"]
            i = j
            continue
        o = ord(ch)
        if ch.isdigit():
            total += prof["digit"]
        elif 0x4E00 <= o <= 0x9FFF or 0x3040 <= o <= 0x30FF or 0xAC00 <= o <= 0xD7AF:
            total += prof["cjk"]
        elif o >= 0x1F000 or 0x2600 <= o <= 0x27BF:
            total += prof["emoji"]
        elif o > 0x2500:
            total += prof["rare"]
        elif ch.isalpha():
            total += prof["letter"]
        else:
            total += prof["punct"]
        i += 1
    return max(1, int(round(total)))


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-llm/1.0"
    sys_version = ""

    # ── 由 main 注入的配置 ──
    model = "mock-model"
    family = "gpt"
    style = "openai"
    api_key: str | None = None

    def log_message(self, fmt: str, *a) -> None:  # 静音
        pass

    # ── 工具 ──
    def _send(self, code: int, obj: dict, extra: dict[str, str] | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.style == "vllm":
            self.send_header("server", "uvicorn")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code: int, msg: str, etype: str = "invalid_request_error") -> None:
        err: dict = {"message": msg, "type": etype, "param": None, "code": None}
        if self.style == "azure":
            err["innererror"] = {"code": "BadRequest", "message": msg}
        self._send(code, {"error": err})

    def _body(self) -> dict | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return None

    def _auth_ok(self) -> bool:
        if not self.api_key:
            return True
        h = self.headers.get("Authorization") or ""
        return h == f"Bearer {self.api_key}"

    # ── GET ──
    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/v1/models", "/models"):
            self._send(200, {"object": "list", "data": [
                {"id": self.model, "object": "model", "owned_by": self.family}]})
        elif self.path.rstrip("/") in ("/api/tags", "/api/version") and self.style == "ollama":
            self._send(200, {"models": [{"name": self.model, "model": self.model,
                                         "size": 4_000_000_000,
                                         "details": {"family": self.family}}]})
        else:
            self._send(404, {"error": {"message": "not found", "type": "not_found_error"}})

    # ── POST ──
    def do_POST(self) -> None:
        path = self.path.rstrip("/").split("?")[0]
        body = self._body()
        if body is None:
            return self._err(400, "invalid JSON")
        if not self._auth_ok():
            return self._err(401, "invalid api key", "authentication_error")

        if path in ("/v1/tokenize", "/tokenize") and self.style == "vllm":
            prompt = str(body.get("prompt") or "")
            return self._send(200, {"count": count_tokens(prompt, PROFILES[self.family]),
                                    "max_model_len": CTX_CHARS,
                                    "tokens": [], "model": self.model})

        if path == "/api/chat" and self.style == "ollama":
            msgs = body.get("messages")
            if not isinstance(msgs, list):
                return self._err(400, "messages must be an array")
            text = "".join(str(m.get("content") or "") for m in msgs if isinstance(m, dict))
            pt = count_tokens(text, PROFILES[self.family])
            return self._send(200, {
                "model": self.model, "created_at": "2026-01-01T00:00:00Z",
                "message": {"role": "assistant", "content": "ok"},
                "done": True, "done_reason": "length",
                "total_duration": 12345678, "load_duration": 123456,
                "prompt_eval_count": pt, "eval_count": 1,
            })

        if path not in ("/v1/chat/completions", "/chat/completions"):
            return self._send(404, {"error": {"message": "not found", "type": "not_found_error"}})

        msgs = body.get("messages")
        if not isinstance(msgs, list):
            return self._err(400, "'messages' must be an array of message objects")
        text = "".join(str(m.get("content") or "") for m in msgs if isinstance(m, dict))
        if len(text) > CTX_CHARS:
            return self._err(400, f"maximum context length is {CTX_CHARS} characters")
        if self.style == "gpt-unsupported" and "max_tokens" in body:
            return self._err(400, "Unsupported parameter: 'max_tokens' is not supported. "
                                  "Use 'max_completion_tokens' instead.")

        pt = count_tokens(text, PROFILES[self.family])
        choice: dict = {
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "length",
        }
        if body.get("logprobs"):
            choice["logprobs"] = {"content": [{"token": "ok", "logprob": -0.12,
                                               "bytes": [111, 107],
                                               "top_logprobs": [
                                                   {"token": "ok", "logprob": -0.12,
                                                    "bytes": [111, 107]},
                                                   {"token": "yes", "logprob": -2.3,
                                                    "bytes": [121, 101, 115]}]}]}
        resp: dict = {
            "id": f"chatcmpl-{random.randint(10**9, 10**10)}",
            "object": "chat.completion",
            "created": 1767225600,
            "model": self.model,
            "choices": [choice],
            "usage": {"prompt_tokens": pt, "completion_tokens": 1,
                      "total_tokens": pt + 1},
        }
        if self.family == "gpt":
            resp["system_fingerprint"] = "fp_mock_2026"
        self._send(200, resp)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="离线 mock LLM 端点（仅自测/demo）")
    ap.add_argument("--port", type=int, default=18099)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--family", default="gpt", choices=sorted(PROFILES))
    ap.add_argument("--style", default="openai",
                    choices=["openai", "vllm", "ollama", "azure", "gpt-unsupported"])
    ap.add_argument("--key", default=None, help="若设置，则要求 Authorization: Bearer <key>")
    ap.add_argument("--ctx-chars", type=int, default=32768)
    args = ap.parse_args(argv)

    global CTX_CHARS
    CTX_CHARS = args.ctx_chars
    Handler.model = args.model
    Handler.family = args.family
    Handler.style = args.style
    Handler.api_key = args.key

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock 端点已启动 http://{args.host}:{args.port}  "
          f"model={args.model} family={args.family} style={args.style}")
    print("仅用于自测/demo，非真实模型；结论不可外推到生产", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

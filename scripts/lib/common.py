"""共享契约与统计工具（供 probe/run_eval/judge/report 复用）。

只放"稳定且无副作用"的东西：数据结构、jsonl 原子读写、幂等键、区间与配对检验。
不做任何网络调用、不做任何 prompt 构造。
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------- 幂等键

def params_hash(*parts: Any) -> str:
    """把 (strategy, version, seed, repeat, model, template_rev) 压成稳定短哈希。

    同一 sample 在同参数下重复执行 -> 同 hash -> --resume 可跳过。
    """
    raw = "|".join(str(p) for p in parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def prompt_sha256(messages: list[dict[str, str]]) -> str:
    """记录 prompt 指纹，便于事后证明"跑的是哪一份用例文本"。"""
    raw = json.dumps(messages, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- jsonl IO

def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    """整体重写（用于 labels.jsonl 这类派生文件）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """容忍末尾半行（中断产物）：解析失败的最后一行直接丢弃并告警。"""
    out: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out

# ---------------------------------------------------------------- 统计
# 实现在 lib/stats.py（合并后唯一一份，带数值 self-test）。
# 这里 re-export，保持 `from lib.common import wilson_ci` 的历史调用点不必改动。
from lib.stats import (  # noqa: E402  (放在文件末尾，避免循环导入)
    EXACT_MCNEMAR_MAX_DISCORDANT,
    bootstrap_mean_ci,
    mcnemar_exact,
    mcnemar_normal,
    mcnemar_p,
    wilson_ci,
)

__all__ = [
    "SCHEMA_VERSION",
    "params_hash",
    "prompt_sha256",
    "write_jsonl",
    "read_jsonl",
    "wilson_ci",
    "mcnemar_exact",
    "mcnemar_normal",
    "mcnemar_p",
    "bootstrap_mean_ci",
    "EXACT_MCNEMAR_MAX_DISCORDANT",
]

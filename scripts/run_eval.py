#!/usr/bin/env python3
"""run_eval.py — 装配执行计划 + 批量执行 + 断点续跑。

设计要点:
  * 两段式: --dry-run 只装配 plan.json（算预算），不带 --dry-run 才真跑。
  * 结果 append-only jsonl，一行一个 attempt；行级原子写 + fsync，Ctrl-C 可安全中断。
  * 幂等键 (sample_id, strategy, params_hash)：--resume 只补缺失键，重复跑不产生重复行。
  * 策略只描述"怎么用"，不携带"说什么"：文本一律取自 Sample.behavior（上游基准原文）。

CLI:
  python scripts/run_eval.py \
      --probe runs/r1/probe.json \
      --dataset harmbench[:subset] --dataset-root data/benchmarks \
      --strategies direct,benign_control \
      --seed 42 --limit 200 --repeat 1 \
      --out runs/r1/results.jsonl --plan runs/r1/plan.json \
      --concurrency 4 --rpm 60 --budget-requests 2000 \
      [--dry-run] [--resume] [--on-error skip|abort] [--max-turns 5] [-v]

Exit codes:
  0 完成（含部分完成，errors 已落库）
  2 计划超预算 / 数据集校验失败 / 策略不可用
  3 端点不可达（执行中断，可用 --resume 续跑）
  130 用户中断（已落盘部分有效）

合规边界（重要，勿改）:
  本构建只内置 `direct`（原样单轮）与 `benign_control`（良性对照，用于测过度拒答）两个策略。
  任何越狱/绕过类策略（prefix_injection、multiturn_crescendo、role_play ...）都**不在本构建内**，
  传入即 exit 2 并提示"未实现"，绝不静默降级成 direct —— 否则会把 0% 误报成"模型很安全"。
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import dataclasses
import hashlib
import json
import os
import random
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Literal, Protocol

from lib.common import SCHEMA_VERSION, params_hash, prompt_sha256, read_jsonl, write_jsonl

PKG = Path(__file__).resolve().parent.parent
ASSETS = PKG / "assets"

Label = Literal["jailbroken", "refused", "partial", "error", "skipped"]

# 只允许"可再分发且基准原文"的许可；不在白名单一律拒绝（合规要求）
LICENSE_WHITELIST = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-SA-4.0", "public-domain",
}


class DatasetIntegrityError(RuntimeError):
    pass


class LicenseError(RuntimeError):
    pass


class StrategyUnavailable(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Sample:
    """来自公开基准的一条用例：behavior 文本 + 元数据。不在此处做任何改写。"""
    sample_id: str
    dataset: str
    category: str
    behavior: str            # 上游原文，只读
    context: str | None      # 上游提供的上下文/目标（如 HarmBench 的 context）
    license: str
    source_url: str
    harmful: bool = True     # 是否属于"有害请求"侧（决定进 ASR 还是进 over-refusal 分母）
    placeholder: bool = False  # demo 占位行：无真实文本，summary 必须打 caveat


@dataclasses.dataclass(frozen=True)
class PlannedItem:
    sample_id: str
    strategy: str
    params_hash: str         # sha256(strategy_params + seed + model + prompt_template_version)[:16]
    est_tokens: int
    repeat_index: int = 0    # 第几次重复（0-based）；报告的可复现性区块靠它反推 repeat 次数


class Strategy(Protocol):
    """策略插件协议：只描述"怎么用"，不携带"说什么"。

    具体文本一律取自 Sample.behavior（上游数据集）；插件只负责轮次、位置、包装顺序。
    """
    name: str
    version: str
    requires: list[str]      # 依赖的能力: system_prompt / multiturn / json_mode
    params_schema: dict[str, Any]

    def build(self, sample: Sample, probe: dict, rng: Any) -> list[list[dict[str, str]]]:
        """返回 N 个 conversation（N = 该策略的采样变体数），每个是 messages 列表。"""


# ---------------------------------------------------------------- 内置策略

@dataclasses.dataclass
class _Passthrough:
    """原样单轮：唯一做的事是把上游 behavior 放到 user 位置，不做任何包装。"""
    name: str = "direct"
    version: str = "1.0.0"
    requires: list[str] = dataclasses.field(default_factory=list)
    params_schema: dict[str, Any] = dataclasses.field(
        default_factory=lambda: {"temperature": "float", "max_tokens": "int"})
    keyword: str = "direct"

    def build(self, sample: Sample, probe: dict, rng: Any) -> list[list[dict[str, str]]]:
        content = sample.behavior
        if sample.context:
            # 上游给了 context 就原样前置，仍不做改写
            content = f"{sample.context}\n\n{sample.behavior}"
        return [[{"role": "user", "content": content}]]


def _builtin_strategies() -> dict[str, _Passthrough]:
    return {
        "direct": _Passthrough(name="direct", keyword="direct"),
        "benign_control": _Passthrough(name="benign_control", keyword="benign_control"),
    }


# 显式列出"已知但本构建不提供"的越狱策略，给出可执行的错误信息（而不是"未知策略"）
KNOWN_UNSUPPORTED = {
    "prefix_injection": "前缀注入",
    "multiturn_crescendo": "多轮渐进",
    "role_play": "角色扮演",
    "refusal_suppression": "拒答抑制",
    "encoding_obfuscation": "编码混淆",
    "many_shot": "少样本堆叠",
}


# ---------------------------------------------------------------- 装配

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rows_to_samples(rows: list[dict[str, Any]], name: str,
                     fmap: dict[str, str] | None = None) -> list[Sample]:
    fm = {"sample_id": "sample_id", "behavior": "behavior", "category": "category",
          "context": "context", "license": "license", "source_url": "source_url",
          "harmful": "harmful", "placeholder": "placeholder"}
    fm.update(fmap or {})
    out: list[Sample] = []
    for i, r in enumerate(rows):
        beh = r.get(fm["behavior"]) or r.get("behavior_text") or r.get("prompt")
        if not beh:
            continue
        sid = str(r.get(fm["sample_id"]) or r.get("id") or f"{name}-{i:05d}")
        harm = r.get(fm["harmful"])
        harmful = True if harm is None else bool(harm)
        out.append(Sample(
            sample_id=sid,
            dataset=name,
            category=str(r.get(fm["category"]) or r.get("category_id") or "uncategorized"),
            behavior=str(beh),
            context=(str(r[fm["context"]]) if r.get(fm["context"]) else None),
            license=str(r.get(fm["license"]) or "unknown"),
            source_url=str(r.get(fm["source_url"]) or ""),
            harmful=harmful,
            placeholder=bool(r.get(fm["placeholder"]) or False),
        ))
    return out


def load_dataset(spec: str, root: Path) -> list[Sample]:
    """spec = "name" 或 "name:subset"。校验 manifest 中的 sha256 与 license 字段。

    内置 `demo` 不需要外部文件（离线自测用）：只含良性样本 + 无实质文本的占位行。
    """
    name, _, subset = spec.partition(":")
    if name == "demo":
        path = ASSETS / "demo-dataset.jsonl"
        if not path.exists():
            raise DatasetIntegrityError(f"内置 demo 数据集缺失: {path}")
        samples = _rows_to_samples(read_jsonl(path), "demo")
    else:
        d = Path(root) / name
        man_p = d / "manifest.json"
        if not man_p.exists():
            raise DatasetIntegrityError(
                f"找不到 {man_p}。请按 references/datasets.md 转换上游基准并生成 manifest.json"
                f"（或用 --dataset demo 做离线自测）")
        man = json.loads(man_p.read_text(encoding="utf-8"))
        fname = man.get("file")
        if not fname:
            raise DatasetIntegrityError(f"{man_p} 缺少 file 字段")
        data_p = d / fname
        if not data_p.exists():
            raise DatasetIntegrityError(f"manifest 指向的数据文件不存在: {data_p}")

        lic = str(man.get("license") or "unknown")
        if lic not in LICENSE_WHITELIST:
            raise LicenseError(
                f"数据集 {name} 的 license={lic!r} 不在白名单 {sorted(LICENSE_WHITELIST)} 内。"
                f"基准原文可再分发是硬要求，请换基准或改用 manifest 声明正确许可")

        want = man.get("sha256")
        if not want:
            raise DatasetIntegrityError(f"{man_p} 缺少 sha256（无法证明跑的是同一份用例文本）")
        got = _sha256_file(data_p)
        if got.lower() != str(want).lower():
            raise DatasetIntegrityError(
                f"数据集 {name} 完整性校验失败\n  manifest sha256={want}\n  实际      sha256={got}")

        if fname.endswith(".csv"):
            with data_p.open("r", encoding="utf-8", newline="") as fh:
                rows: list[dict[str, Any]] = list(csv.DictReader(fh))
        else:
            rows = read_jsonl(data_p)
        subset_field = man.get("subset_field", "subset")
        if subset:
            rows = [r for r in rows if str(r.get(subset_field) or "") == subset]
        samples = _rows_to_samples(rows, name, man.get("field_map"))
        if not samples:
            raise DatasetIntegrityError(f"数据集 {name}{':' + subset if subset else ''} 无有效样本")

    # demo 的 subset 走 category 过滤（真实数据集已在 manifest 的 subset_field 上过滤过）
    if subset and name == "demo":
        samples = [s for s in samples if str(s.category) == subset]
    if not samples:
        raise DatasetIntegrityError(f"数据集 {spec} 过滤后无有效样本")
    return samples


def load_strategies(names: list[str], allow: set[str] | None = None) -> list[Strategy]:
    """从内置注册表加载策略插件；未知策略 -> exit 2（不静默跳过）。"""
    builtin = _builtin_strategies()
    out: list[Strategy] = []
    for raw in names:
        n = raw.strip()
        if not n:
            continue
        if allow is not None and n not in allow:
            raise StrategyUnavailable(
                f"策略 {n} 不在本次评测的评审白名单 {sorted(allow)} 内（合规限制）")
        if n in builtin:
            out.append(builtin[n])
            continue
        if n in KNOWN_UNSUPPORTED:
            raise StrategyUnavailable(
                f"策略 {n}（{KNOWN_UNSUPPORTED[n]}）未实现：本构建只提供原样直问类策略，"
                f"不内置任何越狱/绕过包装。若需要，请自行实现为受评审的插件并显式传入 --allow-strategies。")
        raise StrategyUnavailable(
            f"未知策略 {n}：可选 {sorted(builtin)}；本构建不提供越狱策略插件")
    if not out:
        raise StrategyUnavailable("未指定任何可用策略")
    return out


def build_plan(samples: list[Sample], strategies: list[Strategy], seed: int,
               repeat: int, limit: int | None) -> list[PlannedItem]:
    """笛卡尔展开 + 确定性采样。"""
    rng = random.Random(seed)
    picked = list(samples)
    if limit is not None and 0 < limit < len(picked):
        picked = rng.sample(picked, limit)
        picked.sort(key=lambda s: s.sample_id)
    items: list[PlannedItem] = []
    for s in picked:
        for st in strategies:
            for r in range(max(1, repeat)):
                ph = params_hash(st.name, getattr(st, "version", "0"), seed, r, "tpl-v1")
                est = max(32, len(s.behavior) // 3 + 64)
                items.append(PlannedItem(s.sample_id, st.name, ph, est, r))
    return sorted(items, key=lambda i: (i.strategy, i.sample_id, i.params_hash))


def plan_key(item: PlannedItem | dict[str, Any]) -> tuple[str, str, str]:
    if isinstance(item, dict):
        return (str(item["sample_id"]), str(item["strategy"]), str(item["params_hash"]))
    return (item.sample_id, item.strategy, item.params_hash)


# ---------------------------------------------------------------- 执行

def resume_scan(jsonl_path: Path) -> set[tuple[str, str, str]]:
    """扫已完成文件的尾部，返回已存在的幂等键集合（跳过末尾不完整行）。

    只有 error 为空的记录算"已完成"；失败记录会在 --resume 时重跑。
    """
    done: set[tuple[str, str, str]] = set()
    if not jsonl_path.exists():
        return done
    for row in read_jsonl(jsonl_path):
        if row.get("error"):
            continue
        try:
            done.add(plan_key(row))
        except KeyError:
            continue
    return done


@dataclasses.dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_sleep: float = 1.0
    max_sleep: float = 8.0


def _needs_retry(status: int) -> bool:
    return status == 0 or status == 429 or 500 <= status < 600


def execute_one(client: Any, item: PlannedItem, sample: Sample, strategy: Strategy,
                rng: Any, retry_policy: Any, probe: dict | None = None,
                params: dict[str, Any] | None = None) -> dict[str, Any]:
    """执行一条计划项，返回 Record dict（无论成败都返回，不抛异常给上层）。"""
    probe = probe or {}
    req_ids: list[str] = []
    usage: dict[str, int] = {}
    t_start = time.time()

    rec: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sample_id": item.sample_id,
        "strategy": item.strategy,
        "params_hash": item.params_hash,
        "model": getattr(client, "model", None),
        "dataset": sample.dataset,
        "category": sample.category,
        "harmful": sample.harmful,
        "placeholder": sample.placeholder,
        "behavior_sha256": hashlib.sha256(sample.behavior.encode("utf-8")).hexdigest()[:32],
        "turns": 0,
        "response": "",
        "request_ids": req_ids,
        "latency_ms": 0,
        "usage": usage,
        "error": None,
        "skipped_reason": None,
        "params": dict(params or {}),
        "repeat_index": item.repeat_index,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # 依赖能力检查：system_prompt 被网关丢弃时，依赖它的策略必须 skip 而不是假装跑过
    req = getattr(strategy, "requires", []) or []
    if "system_prompt" in req and str(probe.get("system_prompt")) in ("ignored", "unsupported"):
        rec["skipped_reason"] = f"strategy requires system_prompt, probe={probe.get('system_prompt')}"
        rec["latency_ms"] = int((time.time() - t_start) * 1000)
        return rec

    try:
        convs = strategy.build(sample, probe, rng)
    except Exception as e:
        rec["error"] = f"build_failed: {type(e).__name__}: {e}"
        return rec
    if not convs:
        rec["error"] = "build_empty"
        return rec
    if len(convs) > 1:
        rec["warn"] = f"strategy returned {len(convs)} variants; only [0] executed in this build"

    msgs = convs[0]
    rec["prompt_sha256"] = prompt_sha256(msgs)
    rec["turns"] = sum(1 for m in msgs if m.get("role") == "user")
    send_params = dict(params or {})

    last_err = "retry_exhausted"
    for attempt in range(max(1, int(getattr(retry_policy, "max_attempts", 1)))):
        r = client.chat(msgs, **send_params)
        status = getattr(r, "status", 0)
        if status and status not in (429,) and status < 500:
            rid = None
            hdrs = getattr(r, "headers", {}) or {}
            for k, v in hdrs.items():
                if k.lower() in ("x-request-id", "request-id", "x-amzn-requestid"):
                    rid = str(v)
            if rid:
                req_ids.append(rid)
        if status == 429 or 500 <= status < 600 or status == 0:
            last_err = getattr(r, "error", None) or f"http_{status}: {r.err_text()[:200]}"
            if attempt + 1 < int(getattr(retry_policy, "max_attempts", 1)):
                sleep_s = min(float(getattr(retry_policy, "max_sleep", 8.0)),
                              float(getattr(retry_policy, "base_sleep", 1.0)) * (2 ** attempt))
                ra = None
                for k, v in (getattr(r, "headers", {}) or {}).items():
                    if k.lower() == "retry-after":
                        try:
                            ra = float(v)
                        except Exception:
                            ra = None
                time.sleep(min(ra, 30.0) if ra else sleep_s)
                continue
            rec["error"] = last_err
            rec["latency_ms"] = int((time.time() - t_start) * 1000)
            return rec
        # 成功或不可重试的 4xx
        rec["latency_ms"] = int((time.time() - t_start) * 1000)
        rec["response"] = r.text()
        try:
            usage.update(r.usage())
        except Exception:
            pass
        if not (200 <= status < 300):
            rec["error"] = f"http_{status}: {r.err_text()[:300]}"
        if not rec["response"] and not rec["error"]:
            rec["error"] = "empty_response"
        return rec

    rec["error"] = last_err
    rec["latency_ms"] = int((time.time() - t_start) * 1000)
    return rec


class JsonlWriter:
    """append-only 写入器：单行 JSON + "\\n"，flush + os.fsync，保证中断不产生半行。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self.n = 0

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self.n += 1

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


class Pacer:
    """令牌桶的简化版：只保证平均 RPM 不超，不做突发。"""

    def __init__(self, rpm: int) -> None:
        self.interval = (60.0 / rpm) if rpm and rpm > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.time()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - time.time()
        if delay > 0:
            time.sleep(delay)


def run(items: Iterable[PlannedItem], *, client: Any, samples: dict[str, Sample],
        strategies: dict[str, Strategy], out: JsonlWriter, concurrency: int = 4,
        rpm: int = 60, probe: dict | None = None, retry_policy: RetryPolicy | None = None,
        on_error: str = "skip", seed: int = 42, params: dict[str, Any] | None = None,
        verbose: bool = False, progress_every: int = 20) -> dict[str, int]:
    """线程池执行；rpm 用令牌桶限速；每完成 N 条打印进度并落盘。返回计数统计。"""
    rp = retry_policy or RetryPolicy()
    pacer = Pacer(rpm)
    stats = {"planned": 0, "ok": 0, "error": 0, "skipped": 0, "connect_fail": 0}
    abort_flag = threading.Event()
    lock = threading.Lock()

    def task(item: PlannedItem) -> dict[str, Any]:
        if abort_flag.is_set():
            return {"sample_id": item.sample_id, "strategy": item.strategy,
                    "params_hash": item.params_hash, "error": "aborted",
                    "skipped_reason": "aborted_by_on_error"}
        sample = samples[item.sample_id]
        st = strategies[item.strategy]
        rng = random.Random(f"{seed}:{item.sample_id}:{item.strategy}:{item.params_hash}")
        pacer.wait()
        rec = execute_one(client, item, sample, st, rng, rp, probe, params)
        rec["seed"] = seed          # 落库：报告要说清"哪个 seed 跑出来的"
        return rec

    todo = list(items)
    stats["planned"] = len(todo)
    with cf.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futures = {ex.submit(task, it): it for it in todo}
        for fut in cf.as_completed(futures):
            try:
                rec = fut.result()
            except Exception as e:  # 兜底：任何线程内未捕获异常也要落库
                it = futures[fut]
                rec = {"sample_id": it.sample_id, "strategy": it.strategy,
                       "params_hash": it.params_hash, "error": f"worker_crash: {e}",
                       "skipped_reason": None, "response": "", "latency_ms": 0}
            out.write(rec)
            with lock:
                if rec.get("skipped_reason"):
                    stats["skipped"] += 1
                elif rec.get("error"):
                    stats["error"] += 1
                    if "connect" in str(rec.get("error")) or "timeout" in str(rec.get("error")).lower():
                        stats["connect_fail"] += 1
                    if on_error == "abort":
                        abort_flag.set()
                else:
                    stats["ok"] += 1
                done = stats["ok"] + stats["error"] + stats["skipped"]
            if verbose or (progress_every and done % progress_every == 0):
                print(f"  [{done}/{stats['planned']}] ok={stats['ok']} err={stats['error']} "
                      f"skip={stats['skipped']}", file=sys.stderr)
    return stats


# ---------------------------------------------------------------- 入口

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Assemble and execute jailbreak-robustness evaluation")
    p.add_argument("--probe", required=True, help="probe_target.py 产物")
    p.add_argument("--dataset", required=True, help="name[:subset]")
    p.add_argument("--dataset-root", default="data/benchmarks")
    p.add_argument("--strategies", required=True, help="逗号分隔，见 references/methodology.md")
    p.add_argument("--out", default="results.jsonl")
    p.add_argument("--plan", default="plan.json")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--repeat", type=int, default=1, help="同一样本重复次数，用于估计抖动")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--rpm", type=int, default=60)
    p.add_argument("--max-turns", type=int, default=5)
    p.add_argument("--budget-requests", type=int, default=2000)
    p.add_argument("--on-error", choices=["skip", "abort"], default="skip")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--allow-strategies", default=None,
                   help="逗号分隔的评审白名单；设置后只允许跑其中策略")
    p.add_argument("--max-tokens", type=int, default=None, help="透传给目标的 max_tokens")
    p.add_argument("--temperature", type=float, default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _load_probe(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"[error] 找不到 probe 文件 {p}；先跑 scripts/probe_target.py")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = build_argparser().parse_args(argv)

    probe = _load_probe(args.probe)
    try:
        samples = load_dataset(args.dataset, Path(args.dataset_root))
    except (DatasetIntegrityError, LicenseError) as e:
        print(f"[error] 数据集不可用：{e}", file=sys.stderr)
        return 2

    allow = {s.strip() for s in args.allow_strategies.split(",")} if args.allow_strategies else None
    try:
        strategies = load_strategies(args.strategies.split(","), allow)
    except StrategyUnavailable as e:
        print(f"[error] 策略不可用：{e}", file=sys.stderr)
        return 2

    plan = build_plan(samples, strategies, args.seed, args.repeat, args.limit)
    est_tokens = sum(i.est_tokens for i in plan)
    plan_out = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": args.dataset, "seed": args.seed, "repeat": args.repeat,
        "limit": args.limit, "n_samples": len(samples), "n_items": len(plan),
        "est_tokens": est_tokens, "model": probe.get("resolved_model"),
        "items": [dataclasses.asdict(i) for i in plan],
    }
    Path(args.plan).parent.mkdir(parents=True, exist_ok=True)
    Path(args.plan).write_text(json.dumps(plan_out, ensure_ascii=False, indent=2), encoding="utf-8")

    n_placeholder = sum(1 for s in samples if s.placeholder)
    print(f"[plan] {len(plan)} 请求 / {len(samples)} 样本 / 策略 "
          f"{[s.name for s in strategies]} / 预估 {est_tokens} tokens", file=sys.stderr)
    if n_placeholder:
        print(f"[warn] 数据集中含 {n_placeholder} 条 placeholder 占位行（无真实文本），"
              f"本次结果不得用于对外结论", file=sys.stderr)

    if len(plan) > args.budget_requests:
        print(f"[error] 计划 {len(plan)} 请求超过预算 {args.budget_requests}；"
              f"调小 --limit 或提高 --budget-requests 后重试", file=sys.stderr)
        return 2

    if args.dry_run:
        print(json.dumps({k: v for k, v in plan_out.items() if k != "items"},
                         ensure_ascii=False, indent=2))
        return 0

    # 追加写会把两次运行的记录混在同一文件里（同 key 重复），judge 端分母会虚增。
    # 要续跑就显式 --resume；否则必须换 --out 或先删旧文件。
    out_p = Path(args.out)
    if out_p.exists() and out_p.stat().st_size > 0 and not args.resume:
        print(f"[error] {out_p} 已存在且非空。续跑请加 --resume（只补跑缺失项）；"
              f"重跑请换 --out 或先删除该文件（避免同 key 重复行污染分母）", file=sys.stderr)
        return 2

    params: dict[str, Any] = {}
    if args.max_tokens is not None:
        params["max_tokens"] = args.max_tokens
    if args.temperature is not None:
        params["temperature"] = args.temperature
    if not probe.get("param_support", {}).get("temperature", True) and "temperature" in params:
        print("[warn] 目标不支持 temperature，已从请求中剔除", file=sys.stderr)
        params.pop("temperature")

    # 复用 probe 的客户端实现，保证两处对 flavor/端点的理解一致
    from probe_target import ChatClient  # 延迟导入：--dry-run 不需要

    client = ChatClient(
        base_url=probe["base_url"],
        api_key=os.environ.get("EVAL_API_KEY") or None,
        model=probe.get("resolved_model") or "unknown",
        flavor=probe.get("api_flavor", "openai_chat"),
        endpoint_path=probe.get("endpoint_path", "/v1/chat/completions"),
        timeout=60.0,
    )

    done = resume_scan(Path(args.out)) if args.resume else set()
    todo = [i for i in plan if plan_key(i) not in done]
    if args.resume:
        print(f"[resume] 已有 {len(done)} 条完成记录，本次补跑 {len(todo)} 条", file=sys.stderr)

    writer = JsonlWriter(Path(args.out))
    try:
        stats = run(todo, client=client, samples={s.sample_id: s for s in samples},
                    strategies={s.name: s for s in strategies}, out=writer,
                    concurrency=args.concurrency, rpm=args.rpm, probe=probe,
                    on_error=args.on_error, seed=args.seed, params=params,
                    verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[interrupt] 已落盘部分结果，可用 --resume 续跑", file=sys.stderr)
        return 130
    finally:
        writer.close()
        client.close()

    print(json.dumps(stats, ensure_ascii=False))
    if stats["planned"] > 0 and stats["ok"] == 0 and stats["error"] == stats["planned"]:
        print("[error] 全部请求失败，端点可能不可达（可用 --resume 续跑）", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

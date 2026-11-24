"""统一统计工具（合并后唯一实现，消除三份重复）。

合并前分散在：
  - lib/common.py            wilson_ci / mcnemar_exact
  - report.py                _wilson_ci / _mcnemar_exact / _mcnemar_normal / _mcnemar_p / _bootstrap_*
  - measure_cooperation.py   mcnemar_exact / bootstrap_ci_paired

这里只放"纯数学 + 无副作用"的函数：不做 IO、不做网络、不读配置。
每个函数都被 self-test 钉住数值，任何公式漂移都会立刻失败。

约定：
  - 比率一律 0..1（不是百分数）
  - p 值双侧，裁剪到 [0, 1]
  - n == 0 一律退化为"无信息"（(0,0) 或 p=1.0），绝不抛异常、绝不返回 NaN

自检：python3 lib/stats.py
"""
from __future__ import annotations

import math
import random

__all__ = [
    "wilson_ci",
    "mcnemar_exact",
    "mcnemar_normal",
    "mcnemar_p",
    "bootstrap_mean_ci",
    "EXACT_MCNEMAR_MAX_DISCORDANT",
]

#: b+c 超过此值改用带连续性校正的正态近似（与 report.py 历史阈值一致）
EXACT_MCNEMAR_MAX_DISCORDANT = 200


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval（双侧，默认 95%）。

    比 Wald 正态近似稳：p 接近 0 或 1、n 很小时不会给出负下界或超 1 上界。
    区间端点已裁剪到 [0, 1]。
    """
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / denom
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def mcnemar_exact(b: int, c: int) -> float:
    """精确 McNemar 检验（双侧二项检验），b/c 为两个方向的不一致计数。

    例：护栏加固后 24 条从"配合"变成"拒答"、0 条反向 -> b=24,c=0
        -> p = 2/2^24 ≈ 1.19e-07，说明劣化极显著。
    """
    n = b + c
    if n <= 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / float(2 ** n)
    return min(1.0, 2.0 * tail)


def mcnemar_normal(b: int, c: int) -> float:
    """带连续性校正的正态近似（b+c 很大时的兜底，小样本请用 exact）。"""
    n = b + c
    if n <= 0:
        return 1.0
    z = (abs(b - c) - 1.0) / math.sqrt(n)
    if z <= 0:
        return 1.0
    return min(1.0, math.erfc(z / math.sqrt(2.0)))


def mcnemar_p(b: int, c: int, exact_max: int = EXACT_MCNEMAR_MAX_DISCORDANT) -> tuple[float, str]:
    """按不一致对数自动选算法，返回 (双侧 p, 方法说明)。

    方法说明会原样写进报告 JSON（`test_orr` / `test`），
    让读者知道这个 p 是精确算的还是近似的——不隐藏方法差异。
    """
    if b + c <= exact_max:
        return mcnemar_exact(b, c), "exact-binomial"
    return mcnemar_normal(b, c), "normal-approx(continuity-corrected)"


def bootstrap_mean_ci(
    values: list[float],
    *,
    seed: int,
    rounds: int,
    alpha: float = 0.05,
    mode: str = "round",
) -> tuple[float, float, float]:
    """配对差值的百分位 bootstrap，返回 (mean, lo, hi)。

    mode 用于兼容历史两套分位索引口径（避免重构改变既有报告数字）：
      - "round"：报告口径 int(round(q * (N-1)))，见 report.py._bootstrap_ci
      - "floor"：实测口径 int(q * N)，见 measure_cooperation.bootstrap_ci_paired
    """
    n = len(values)
    if n == 0 or rounds <= 0:
        return (0.0, 0.0, 0.0)
    mean = sum(values) / n
    rng = random.Random(seed)
    boot: list[float] = []
    for _ in range(rounds):
        s = 0.0
        for _ in range(n):
            s += values[rng.randrange(n)]
        boot.append(s / n)
    boot.sort()
    if mode == "round":
        lo_i = max(0, int(round((alpha / 2.0) * (len(boot) - 1))))
        hi_i = min(len(boot) - 1, int(round((1.0 - alpha / 2.0) * (len(boot) - 1))))
    elif mode == "floor":
        lo_i = max(0, int((alpha / 2.0) * rounds))
        hi_i = min(len(boot) - 1, int((1.0 - alpha / 2.0) * rounds))
    else:
        raise ValueError(f"unknown mode: {mode!r} (expected 'round' or 'floor')")
    return (mean, boot[lo_i], boot[hi_i])


# ---------------------------------------------------------------- 自检

def _self_test() -> int:
    fails: list[str] = []

    def chk(name: str, got, want, tol: float = 1e-9) -> None:
        if isinstance(want, tuple):
            ok = all(abs(a - b) <= tol for a, b in zip(got, want)) and len(got) == len(want)
        elif isinstance(want, float):
            ok = abs(got - want) <= tol
        else:
            ok = got == want
        if not ok:
            fails.append(f"{name}: got={got!r} want={want!r}")

    # 退化输入：绝不抛异常、绝不 NaN
    chk("wilson(0,0)", wilson_ci(0, 0), (0.0, 0.0))
    chk("mcnemar_exact(0,0)", mcnemar_exact(0, 0), 1.0)
    chk("mcnemar_normal(0,0)", mcnemar_normal(0, 0), 1.0)
    chk("bootstrap([])", bootstrap_mean_ci([], seed=1, rounds=100), (0.0, 0.0, 0.0))

    # Wilson：全通过时下界应显著低于 1（小样本惩罚），上界被裁剪到 1
    lo, hi = wilson_ci(12, 12)
    chk("wilson(12,12).lo", lo, 0.7575, 1e-3)
    chk("wilson(12,12).hi", hi, 1.0, 1e-9)
    # 对称性：wilson(k,n).lo <= k/n <= wilson(k,n).hi
    for k, n in [(0, 10), (3, 10), (9, 10), (24, 24)]:
        a, b = wilson_ci(k, n)
        if not (a <= k / n <= b):
            fails.append(f"wilson({k},{n}) 未包含点估计 {k/n}: {(a, b)}")

    # McNemar 精确值：2/2^15 与 2/2^24（本项目实测两个 p 值）
    chk("mcnemar_exact(0,15)", mcnemar_exact(0, 15), 6.103515625e-05)
    chk("mcnemar_exact(15,0)", mcnemar_exact(15, 0), 6.103515625e-05)
    chk("mcnemar_exact(0,24)", mcnemar_exact(0, 24), 2.0 / (2 ** 24))
    # 对称 + 双侧 + 全一致时 p=1
    chk("mcnemar_exact(5,5)", mcnemar_exact(5, 5), 1.0)
    chk("mcnemar_exact 对称", mcnemar_exact(3, 9), mcnemar_exact(9, 3))

    # 自动选算法：阈值内 exact、阈值外 normal，且方法名如实返回
    p, m = mcnemar_p(0, 24, exact_max=200)
    chk("mcnemar_p(0,24).method", m, "exact-binomial")
    chk("mcnemar_p(0,24).p", p, 2.0 / (2 ** 24))
    p2, m2 = mcnemar_p(5, 5, exact_max=4)
    chk("mcnemar_p 超阈值走 normal", m2, "normal-approx(continuity-corrected)")
    chk("mcnemar_p 超阈值 p=1.0", p2, 1.0)

    # bootstrap：全 1 差值 -> CI 收成 [1,1]；seed 固定 -> 可复现
    a = bootstrap_mean_ci([1.0] * 15, seed=20260101, rounds=200)
    chk("bootstrap 全1", a, (1.0, 1.0, 1.0))
    b1 = bootstrap_mean_ci([0.0, 1.0] * 8, seed=7, rounds=300, mode="round")
    b2 = bootstrap_mean_ci([0.0, 1.0] * 8, seed=7, rounds=300, mode="round")
    chk("bootstrap 可复现", b1, b2)
    if not (b1[1] <= b1[0] <= b1[2]):
        fails.append(f"bootstrap CI 未包含均值: {b1}")
    # 两种历史口径应当接近（允许 1 个索引的抖动，但不允许量级差异）
    c1 = bootstrap_mean_ci([0.0] * 8 + [1.0] * 8, seed=3, rounds=400, mode="round")
    c2 = bootstrap_mean_ci([0.0] * 8 + [1.0] * 8, seed=3, rounds=400, mode="floor")
    if abs(c1[1] - c2[1]) > 0.06 or abs(c1[2] - c2[2]) > 0.06:
        fails.append(f"两种分位口径差异过大: round={c1} floor={c2}")

    if fails:
        print(f"lib/stats.py self-test FAILED ({len(fails)})")
        for f in fails:
            print("  -", f)
        return 1
    print("lib/stats.py self-test OK (6 组断言：退化输入 / Wilson / McNemar / 算法选择 / bootstrap / 口径一致)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

"""
denet.report: Generate a static HTML report from a denet JSONL file.

Renders CPU, memory, and network timelines with Altair/Vega-Lite, plus a
header stating which optional capabilities (eBPF, PSI, perf counters) the
run had. Requires the ``report`` extra: ``pip install denet[report]``.

Usage:
    python -m denet.report metrics.jsonl -o report.html
"""

import argparse
import json
from pathlib import Path
from typing import Any

MAX_SLOTS = 512  # ponytail: fixed slot budget; make it a CLI flag if someone needs finer resolution


def _load_records(path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a denet JSONL file into (metadata, sample rows).

    Handles both kind-tagged and legacy untagged files. Each row is the
    aggregated metrics of a tree record (falling back to parent), or the
    sample itself in single-process mode.
    """
    meta: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    ebpf_seen = False

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue

            kind = rec.get("kind")
            if kind is None:  # legacy untagged: infer from shape
                if "cmd" in rec:
                    kind = "metadata"
                elif "aggregated" in rec or "children" in rec:
                    kind = "tree"
                elif "cpu_usage" in rec:
                    kind = "sample"
                else:
                    continue  # env record, stats tail, unknown

            if kind == "metadata":
                meta = rec
            elif kind == "tree":
                m = rec.get("aggregated") or rec.get("parent")
                if m:
                    ebpf_seen = ebpf_seen or "ebpf" in m
                    rows.append({**m, "ts_ms": rec["ts_ms"]})
            elif kind == "sample":
                ebpf_seen = ebpf_seen or "ebpf" in rec
                rows.append(rec)

    meta["_ebpf_seen"] = ebpf_seen
    return meta, rows


def _to_frame(rows: list[dict[str, Any]]):
    """Build a DataFrame with elapsed seconds and per-second rates."""
    import pandas as pd

    def net(m: dict[str, Any], direction: str) -> int:
        # sys_net_* with legacy net_* alias
        v = m.get(f"sys_net_{direction}_bytes")
        return v if v is not None else m.get(f"net_{direction}_bytes", 0)

    def ebpf_net(m: dict[str, Any], direction: str):
        return ((m.get("ebpf") or {}).get("network") or {}).get(f"{direction}_bytes")

    df = pd.DataFrame(
        {
            "ts_ms": m["ts_ms"],
            "cpu": m.get("cpu_usage", 0.0),
            "mem_mib": m.get("mem_rss_kb", 0) / 1024.0,
            "rx": net(m, "rx"),
            "tx": net(m, "tx"),
            "ebpf_rx": ebpf_net(m, "rx"),
            "ebpf_tx": ebpf_net(m, "tx"),
        }
        for m in rows
    )
    df["t"] = (df["ts_ms"] - df["ts_ms"].iloc[0]) / 1000.0

    # Per-process eBPF bytes when available, system-wide otherwise.
    per_process = df["ebpf_rx"].notna().any()
    rx, tx = ("ebpf_rx", "ebpf_tx") if per_process else ("rx", "tx")
    # Counters are cumulative; diff to per-sample deltas, then to bytes/s.
    dt = df["t"].diff()
    df["rx_rate"] = (df[rx].diff().clip(lower=0) / dt).fillna(0)
    df["tx_rate"] = (df[tx].diff().clip(lower=0) / dt).fillna(0)
    return df, per_process


def _slotted(df):
    """Aggregate into at most MAX_SLOTS time slots (mean gauges, max rates)."""
    if len(df) <= MAX_SLOTS or df["t"].iloc[-1] <= 0:
        return df
    slot = df["t"].iloc[-1] / MAX_SLOTS
    return (
        df.groupby((df["t"] // slot) * slot)
        .agg({"cpu": "mean", "mem_mib": "mean", "rx_rate": "max", "tx_rate": "max"})
        .rename_axis("t")
        .reset_index()
    )


def _detect_regimes(df, max_regimes: int = 6) -> list[dict[str, Any]]:
    """Segment the run into piecewise-constant regimes via binary segmentation.

    Runs on the slotted series (<= MAX_SLOTS points), jointly over the z-scored
    CPU / memory / network signals. Splits are accepted while the SSE gain beats
    a BIC-style penalty; caps at ``max_regimes``. Returns [] for short runs.
    """
    import numpy as np

    cols = [c for c in ("cpu", "mem_mib", "rx_rate", "tx_rate") if c in df.columns]
    n = len(df)
    if n < 8 or not cols:
        return []

    x = df[cols].to_numpy(dtype=float)
    std = x.std(axis=0)
    std[std == 0] = 1.0
    z = (x - x.mean(axis=0)) / std
    # prefix sums so any segment's SSE is O(1)
    p1 = np.vstack([np.zeros(z.shape[1]), np.cumsum(z, axis=0)])
    p2 = np.vstack([np.zeros(z.shape[1]), np.cumsum(z * z, axis=0)])

    def sse(a: int, b: int) -> float:  # SSE of z[a:b] under a constant mean
        s1, s2 = p1[b] - p1[a], p2[b] - p2[a]
        return float(np.sum(s2 - (s1 * s1) / (b - a)))

    min_size = max(2, n // 50)
    penalty = len(cols) * float(np.log(n))  # ponytail: BIC-ish stop rule; tune if it over/under-splits real runs
    segs = [(0, n)]
    while len(segs) < max_regimes:
        best = None  # (gain, seg_index, split_point)
        for i, (a, b) in enumerate(segs):
            if b - a < 2 * min_size:
                continue
            base = sse(a, b)
            for k in range(a + min_size, b - min_size + 1):
                gain = base - sse(a, k) - sse(k, b)
                if best is None or gain > best[0]:
                    best = (gain, i, k)
        if best is None or best[0] < penalty:
            break
        _, i, k = best
        a, b = segs[i]
        segs[i : i + 1] = [(a, k), (k, b)]

    # logical z-signals for the "dominant activity" label (net = mean of rx/tx z)
    zc = {c: z[:, i] for i, c in enumerate(cols)}
    signals = {"cpu": zc.get("cpu"), "memory": zc.get("mem_mib")}
    if "rx_rate" in zc and "tx_rate" in zc:
        signals["network"] = (zc["rx_rate"] + zc["tx_rate"]) / 2

    segs.sort()
    t = df["t"].to_numpy()
    regimes = []
    for a, b in segs:
        # dominant = signal most elevated above the run's own average in this regime;
        # if none rises meaningfully above average, it's an idle/low phase.
        means = {k: float(v[a:b].mean()) for k, v in signals.items() if v is not None}
        top = max(means, key=means.get)
        regimes.append(
            {
                "t0": float(t[a]),
                "t1": float(t[b - 1]),
                "cpu": float(df["cpu"].iloc[a:b].mean()),
                "mem_mib": float(df["mem_mib"].iloc[a:b].mean()),
                "dominant": top if means[top] > 0.3 else "idle/low",
            }
        )
    return regimes


def _syscall_frame(rows: list[dict[str, Any]]):
    """Frame of eBPF syscall counts per category over time, or None.

    Time base matches `_to_frame` (first row). Each sample's counts are the sum
    over the currently-alive monitored PIDs, so the totals rise and fall as
    short-lived children come and go (not a clean cumulative counter).
    """
    import pandas as pd

    cats: set[str] = set()
    for m in rows:
        sc = ((m.get("ebpf") or {}).get("syscalls") or {}).get("by_category") or {}
        cats.update(sc)
    if not cats:
        return None

    base = rows[0]["ts_ms"]
    recs = []
    for m in rows:
        sc = ((m.get("ebpf") or {}).get("syscalls") or {}).get("by_category") or {}
        recs.append({"t": (m["ts_ms"] - base) / 1000.0, **{c: sc.get(c, 0) for c in cats}})
    return pd.DataFrame(recs)


def _syscalls_per_regime(sc_df, regimes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mean per-sample syscall counts per category within each regime → [{regime, category, count}].

    The underlying counts are alive-PID snapshots (see `_syscall_frame`), not
    clean per-window deltas, so the mean of the snapshots in a regime is used as
    a proxy for that phase's typical syscall mix. Because the chart normalizes
    each regime's bar, mean vs sum yields identical proportions.
    """
    spans = regimes or [{"t0": float(sc_df["t"].min()), "t1": float(sc_df["t"].max())}]
    cats = [c for c in sc_df.columns if c != "t"]
    out = []
    for i, r in enumerate(spans):
        span = sc_df[(sc_df["t"] >= r["t0"]) & (sc_df["t"] <= r["t1"])]
        if span.empty:
            continue
        for c in cats:
            val = float(span[c].mean())
            if val > 0:
                out.append({"regime": f"R{i + 1}", "category": c, "count": val})
    return out


def _syscall_chart(alt, breakdown: list[dict[str, Any]], width: int, regime_labels: list[str]):
    """Normalized stacked bar of syscall category mix per regime, or None.

    All regimes stay on the axis (via the y-scale domain) so the rows line up
    with the regime table; a regime with no syscalls shows as an empty row.
    """
    import pandas as pd

    if not breakdown:
        return None
    return (
        alt.Chart(pd.DataFrame(breakdown))
        .mark_bar()
        .encode(
            y=alt.Y("regime:N", title=None, sort=regime_labels, scale=alt.Scale(domain=regime_labels)),
            x=alt.X("count:Q", stack="normalize", title="syscall mix (share of calls)"),
            color=alt.Color("category:N", title="syscall category"),
            order=alt.Order("category:N"),
            tooltip=["regime:N", "category:N", "count:Q"],
        )
        .properties(width=width, height=34 * len(regime_labels) + 10, title="Syscalls by category, per regime (eBPF)")
    )


def _psi_frame(rows: list[dict[str, Any]]):
    """Frame of memory-pressure (PSI) percentages over time, or None.

    Shown whenever PSI was recorded (a flat-zero trace is a meaningful "no
    memory pressure" reading, and matches the PSI capability in the header).
    Returns None only when no `psi_mem` is present at all.
    """
    import pandas as pd

    if not any("psi_mem" in m for m in rows):
        return None
    base = rows[0]["ts_ms"]
    recs = []
    for m in rows:
        p = m.get("psi_mem") or {}
        recs.append(
            {
                "t": (m["ts_ms"] - base) / 1000.0,
                "some": p.get("some_avg10", 0.0),
                "full": p.get("full_avg10", 0.0),
            }
        )
    return pd.DataFrame(recs)


def _capability_line(meta: dict[str, Any], per_process_net: bool) -> str:
    caps = meta.get("capabilities") or {}

    def avail(name: str, *keys: str) -> str:
        # perf_hw uses {available}; psi uses {system, per_process}. Any truthy key counts.
        c = caps.get(name) or {}
        return "yes" if any(c.get(k) for k in keys) else "no"

    net_src = "per-process (eBPF)" if per_process_net else "system-wide approximation"
    ebpf = "yes" if meta.get("_ebpf_seen") else "no"
    psi = avail("psi", "available", "system", "per_process")
    perf = avail("perf_hw", "available")
    return f"eBPF: {ebpf} | network: {net_src} | PSI: {psi} | perf counters: {perf}"


def _regime_table(alt, regimes: list[dict[str, Any]], width: int):
    """Render the detected regimes as a compact text-grid table, or None."""
    import pandas as pd

    if not regimes:
        return None
    cells = []
    for i, r in enumerate(regimes):
        vals = {
            "span (s)": f"{r['t0']:.1f}–{r['t1']:.1f}",
            "mean CPU %": f"{r['cpu']:.0f}",
            "mean RSS MiB": f"{r['mem_mib']:.0f}",
            "dominant": r["dominant"],
        }
        for col, val in vals.items():
            cells.append({"regime": f"R{i + 1}", "metric": col, "value": val})
    order = ["span (s)", "mean CPU %", "mean RSS MiB", "dominant"]
    return (
        alt.Chart(pd.DataFrame(cells))
        .mark_text()
        .encode(
            x=alt.X("metric:N", sort=order, axis=alt.Axis(orient="top", labelAngle=0), title=None),
            y=alt.Y("regime:N", title=None),
            text="value:N",
        )
        .properties(width=width, height=22 * len(regimes) + 10, title="Detected regimes")
    )


def generate_report(input_path: str, output_path: str | None = None, fmt: str | None = None) -> str:
    """Generate a report from a denet JSONL file.

    fmt is one of "html" (default; interactive, self-contained), "png", or "svg"
    (both static, no JS). When fmt is None it is inferred from output_path's
    extension, falling back to html. Returns the path of the written file.
    """
    try:
        import altair as alt
    except ImportError as e:
        raise ImportError("The report feature needs extra dependencies: pip install denet[report]") from e

    meta, rows = _load_records(input_path)
    if not rows:
        raise ValueError(f"No metric records found in {input_path}")

    df, per_process_net = _to_frame(rows)
    duration = df["t"].iloc[-1]
    df = _slotted(df)
    regimes = _detect_regimes(df)

    x = alt.X("t:Q", title="elapsed (s)")
    width, height = 700, 150

    def bands():
        # shade alternating regimes so phase boundaries are visible under every timeline
        import pandas as pd

        odd = [{"t0": r["t0"], "t1": r["t1"]} for r in regimes[1::2]]
        if not odd:
            return None
        return alt.Chart(pd.DataFrame(odd)).mark_rect(opacity=0.10, color="#888").encode(x="t0:Q", x2="t1:Q")

    band = bands()

    def timeline(chart):
        return alt.layer(band, chart) if band is not None else chart

    # point=True so a 1-2 sample run still shows a visible dot (a line through one point draws nothing)
    cpu = timeline(alt.Chart(df).mark_line(point=True).encode(x=x, y=alt.Y("cpu:Q", title="CPU (%)"))).properties(
        width=width, height=height
    )
    mem = timeline(alt.Chart(df).mark_line(point=True).encode(x=x, y=alt.Y("mem_mib:Q", title="RSS (MiB)"))).properties(
        width=width, height=height
    )
    net_df = df.melt(id_vars="t", value_vars=["rx_rate", "tx_rate"], var_name="dir", value_name="rate")
    net_df["dir"] = net_df["dir"].str.removesuffix("_rate")
    net = timeline(
        alt.Chart(net_df)
        .mark_line(point=True)
        .encode(x=x, y=alt.Y("rate:Q", title="network (bytes/s)"), color=alt.Color("dir:N", title=None))
    ).properties(width=width, height=height)

    panels = [cpu, mem, net]

    # memory-pressure (PSI) timeline — only when there was actual pressure
    psi_df = _psi_frame(rows)
    if psi_df is not None:
        psi_long = psi_df.melt(id_vars="t", value_vars=["some", "full"], var_name="scope", value_name="pct")
        panels.append(
            timeline(
                alt.Chart(psi_long)
                .mark_line(point=True)
                .encode(
                    x=x,
                    y=alt.Y("pct:Q", title="mem stall (% / 10s)"),
                    color=alt.Color("scope:N", title="PSI"),
                )
            ).properties(width=width, height=height)
        )

    table = _regime_table(alt, regimes, width)
    if table is not None:
        panels.append(table)

    # eBPF-only: syscall category mix per regime
    sc_df = _syscall_frame(rows)
    if sc_df is not None:
        labels = [f"R{i + 1}" for i in range(len(regimes))] or ["R1"]
        sc_chart = _syscall_chart(alt, _syscalls_per_regime(sc_df, regimes), width, labels)
        if sc_chart is not None:
            panels.append(sc_chart)

    # collapse whitespace (a -c script can embed newlines that break the title) and cap length
    cmd = " ".join(" ".join(meta.get("cmd", [])).split()) or "(unknown command)"
    if len(cmd) > 90:
        cmd = cmd[:87] + "..."
    subtitle = [f"{len(rows)} samples over {duration:.1f}s", _capability_line(meta, per_process_net)]
    if len(rows) < 3:
        subtitle.append("warning: too few samples for a timeline — did the process exit early?")
    chart = (
        alt.vconcat(*panels)
        .resolve_scale(color="independent")  # keep net rx/tx and syscall-category legends separate
        .properties(title=alt.TitleParams(text=f"denet report: {cmd}", subtitle=subtitle, anchor="start"))
    )

    # format: explicit arg > -o extension > html. png/svg are fully static (no JS).
    if fmt is None:
        ext = Path(output_path).suffix.lower().lstrip(".") if output_path else ""
        fmt = ext if ext in ("html", "png", "svg") else "html"
    out = output_path or str(Path(input_path).with_suffix("." + fmt))
    if fmt == "html":
        try:
            chart.save(out, inline=True)  # self-contained, needs vl-convert-python
        except (ImportError, ValueError):
            chart.save(out)  # falls back to CDN-loaded vega scripts
    elif fmt == "png":
        chart.save(out, scale_factor=2)  # vl-convert renders a static raster
    else:  # svg — static vector
        chart.save(out)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="denet-report",
        description="Generate a report (CPU/memory/network timelines, regime detection, "
        "and eBPF syscall breakdown) from a denet JSONL metrics file.",
        epilog=(
            "formats:\n"
            "  html  interactive, self-contained (JavaScript); the default. Open in a browser.\n"
            "  png   static raster image; opens in any viewer, editor preview, or GitHub.\n"
            "  svg   static vector image; no JavaScript.\n\n"
            "examples:\n"
            "  denet-report metrics.jsonl                 # -> metrics.html (interactive)\n"
            "  denet-report metrics.jsonl -o out.png      # static PNG (format from extension)\n"
            "  denet-report metrics.jsonl -f svg -o r.svg # static SVG"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="denet JSONL metrics file")
    parser.add_argument("-o", "--output", help="output path (default: <input>.<format>)")
    parser.add_argument(
        "-f",
        "--format",
        choices=["html", "png", "svg"],
        help="output format. Default: inferred from -o's extension, else html. "
        "html is interactive (JS); png and svg are static.",
    )
    args = parser.parse_args()
    try:
        print(generate_report(args.input, args.output, args.format))
    except (ImportError, ValueError, FileNotFoundError) as e:
        raise SystemExit(f"denet-report: {e}")


if __name__ == "__main__":
    main()

"""Tests for denet.report HTML report generation."""

import json
from pathlib import Path

import pytest

pytest.importorskip("altair")
pytest.importorskip("pandas")

from denet.report import (
    _detect_regimes,
    _load_records,
    _psi_frame,
    _slotted,
    _syscall_chart,
    _syscall_frame,
    _syscalls_per_regime,
    _to_frame,
    generate_report,
)


def _write_jsonl(path, lines):
    path.write_text("\n".join(json.dumps(rec) for rec in lines) + "\n")


def _tree_record(ts_ms, cpu, rx, ebpf=False):
    m = {
        "ts_ms": ts_ms,
        "cpu_usage": cpu,
        "mem_rss_kb": 1024,
        "mem_vms_kb": 4096,
        "disk_read_bytes": 0,
        "disk_write_bytes": 0,
        "sys_net_rx_bytes": rx,
        "sys_net_tx_bytes": rx // 2,
        "thread_count": 1,
        "process_count": 1,
        "uptime_secs": ts_ms // 1000,
    }
    if ebpf:
        m["ebpf"] = {"network": {"rx_bytes": rx * 10, "tx_bytes": rx * 5}}
    return {"kind": "tree", "ts_ms": ts_ms, "parent": m, "children": [], "aggregated": m}


def test_generate_report(tmp_path):
    records = [
        {
            "kind": "metadata",
            "pid": 1,
            "cmd": ["sleep", "5"],
            "executable": "/bin/sleep",
            "t0_ms": 0,
            # psi uses {system, per_process}; perf_hw uses {available} — different shapes on purpose
            "capabilities": {
                "psi": {"system": True, "per_process": False},
                "perf_hw": {"available": False, "reason": "paranoid"},
            },
        }
    ]
    records += [_tree_record(i * 100, cpu=50.0, rx=i * 1000) for i in range(20)]
    src = tmp_path / "metrics.jsonl"
    _write_jsonl(src, records)

    out = generate_report(str(src))

    html = (tmp_path / "metrics.html").read_text()
    assert out == str(tmp_path / "metrics.html")
    assert "vega" in html.lower()
    assert "sleep 5" in html
    assert "eBPF: no | network: system-wide approximation | PSI: yes | perf counters: no" in html


def test_legacy_untagged_records_and_net_alias(tmp_path):
    records = [{"pid": 1, "cmd": ["a.out"], "executable": "a.out", "t0_ms": 0}]
    for i in range(5):
        m = {"ts_ms": i * 100, "cpu_usage": 1.0, "mem_rss_kb": 100, "net_rx_bytes": i * 10, "net_tx_bytes": i * 5}
        records.append({"ts_ms": i * 100, "parent": m, "children": [], "aggregated": m})
    src = tmp_path / "legacy.jsonl"
    _write_jsonl(src, records)

    meta, rows = _load_records(str(src))
    assert meta["cmd"] == ["a.out"]
    assert len(rows) == 5
    df, per_process = _to_frame(rows)
    assert not per_process
    assert df["rx"].iloc[-1] == 40

    out = generate_report(str(src), str(tmp_path / "r.html"))
    assert (tmp_path / "r.html").exists()
    assert out == str(tmp_path / "r.html")


def test_ebpf_net_preferred(tmp_path):
    records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
    records += [_tree_record(i * 100, cpu=10.0, rx=i * 100, ebpf=True) for i in range(5)]
    src = tmp_path / "ebpf.jsonl"
    _write_jsonl(src, records)

    meta, rows = _load_records(str(src))
    assert meta["_ebpf_seen"]
    df, per_process = _to_frame(rows)
    assert per_process
    # rates come from the eBPF counters (1000 bytes per 0.1 s step)
    assert df["rx_rate"].iloc[-1] == pytest.approx(10000)

    generate_report(str(src), str(tmp_path / "r.html"))
    assert "per-process (eBPF)" in (tmp_path / "r.html").read_text()


def test_sparse_run_warns_and_still_renders(tmp_path):
    # a process that exited early yields ~1 sample; the report must not be blank
    records = [
        {"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0},
        _tree_record(0, cpu=0.0, rx=0),
    ]
    src = tmp_path / "sparse.jsonl"
    _write_jsonl(src, records)
    generate_report(str(src), str(tmp_path / "r.html"))
    html = (tmp_path / "r.html").read_text()
    assert "too few samples" in html


def test_detect_regimes_finds_phases(tmp_path):
    # idle -> cpu-bound -> memory-growth; expect ~3 regimes with matching dominant labels
    records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
    ts = 0
    for _ in range(15):  # idle
        records.append(_tree_record(ts, cpu=0.0, rx=0))
        ts += 100
    for _ in range(15):  # cpu-bound
        records.append(_tree_record(ts, cpu=100.0, rx=0))
        ts += 100
    for i in range(15):  # memory growth
        r = _tree_record(ts, cpu=1.0, rx=0)
        r["aggregated"]["mem_rss_kb"] = r["parent"]["mem_rss_kb"] = 1024 * (i + 1) * 50
        records.append(r)
        ts += 100
    src = tmp_path / "phases.jsonl"
    _write_jsonl(src, records)

    df, _ = _to_frame(_load_records(str(src))[1])
    regimes = _detect_regimes(_slotted(df))
    labels = [r["dominant"] for r in regimes]
    assert len(regimes) >= 3
    assert "cpu" in labels and "memory" in labels and "idle/low" in labels

    generate_report(str(src), str(tmp_path / "r.html"))
    assert "Detected regimes" in (tmp_path / "r.html").read_text()


def test_detect_regimes_short_run_empty(tmp_path):
    records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
    records += [_tree_record(i * 100, cpu=10.0, rx=0) for i in range(4)]
    df, _ = _to_frame(_load_records_rows(tmp_path, records))
    assert _detect_regimes(df) == []


def _load_records_rows(tmp_path, records):
    src = tmp_path / "short.jsonl"
    _write_jsonl(src, records)
    return _load_records(str(src))[1]


def _tree_record_syscalls(ts_ms, cpu, by_category):
    r = _tree_record(ts_ms, cpu=cpu, rx=0)
    for m in (r["parent"], r["aggregated"]):
        m["ebpf"] = {"syscalls": {"total": sum(by_category.values()), "by_category": by_category}}
    return r


def test_syscalls_per_regime(tmp_path):
    # per-sample snapshots (not cumulative): phase 1 is file_io-heavy, phase 2 memory-heavy
    records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
    ts = 0
    for _ in range(15):  # phase 1: file_io heavy
        records.append(_tree_record_syscalls(ts, cpu=90.0, by_category={"file_io": 100, "memory": 5}))
        ts += 100
    for _ in range(15):  # phase 2: memory heavy
        records.append(_tree_record_syscalls(ts, cpu=5.0, by_category={"file_io": 2, "memory": 100}))
        ts += 100
    src = tmp_path / "sc.jsonl"
    _write_jsonl(src, records)

    _, rows = _load_records(str(src))
    df, _ = _to_frame(rows)
    regimes = _detect_regimes(_slotted(df))
    breakdown = _syscalls_per_regime(_syscall_frame(rows), regimes)

    by_regime = {}
    for b in breakdown:
        by_regime.setdefault(b["regime"], {})[b["category"]] = b["count"]
    # first regime should be dominated by file_io, a later one by memory
    assert by_regime["R1"]["file_io"] > by_regime["R1"].get("memory", 0)
    last = by_regime[max(by_regime)]
    assert last.get("memory", 0) > last.get("file_io", 0)

    generate_report(str(src), str(tmp_path / "r.html"))
    assert "Syscalls by category" in (tmp_path / "r.html").read_text()


def test_syscall_chart_keeps_every_regime_on_axis():
    # a regime with no syscalls must still appear (empty row), so the chart aligns
    # with the regime table above it
    import altair as alt

    breakdown = [
        {"regime": "R1", "category": "file_io", "count": 10.0},
        {"regime": "R3", "category": "memory", "count": 5.0},
    ]
    spec = _syscall_chart(alt, breakdown, 700, ["R1", "R2", "R3"]).to_dict()
    assert spec["encoding"]["y"]["scale"]["domain"] == ["R1", "R2", "R3"]  # R2 kept despite no data


def test_psi_panel_shown_when_present(tmp_path):
    def make(with_psi, psi_some=lambda i: 0.0):
        records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
        for i in range(12):
            r = _tree_record(i * 100, cpu=10.0, rx=0)
            if with_psi:
                some = psi_some(i)
                for m in (r["parent"], r["aggregated"]):
                    m["psi_mem"] = {"some_avg10": some, "full_avg10": some / 3}
            records.append(r)
        return records

    # PSI present (even flat zero) -> panel rendered
    for label, some_fn in (("pressured", lambda i: 0.0 if i < 4 else 20.0), ("flat", lambda i: 0.0)):
        src = tmp_path / f"{label}.jsonl"
        _write_jsonl(src, make(True, some_fn))
        _, rows = _load_records(str(src))
        assert _psi_frame(rows) is not None
        generate_report(str(src), str(tmp_path / f"{label}.html"))
        assert "mem stall" in (tmp_path / f"{label}.html").read_text()

    # no psi_mem at all -> no panel
    none_src = tmp_path / "nopsi.jsonl"
    _write_jsonl(none_src, make(False))
    _, rows2 = _load_records(str(none_src))
    assert _psi_frame(rows2) is None
    generate_report(str(none_src), str(tmp_path / "nopsi.html"))
    assert "mem stall" not in (tmp_path / "nopsi.html").read_text()


def test_no_syscall_chart_without_ebpf(tmp_path):
    records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
    records += [_tree_record(i * 100, cpu=10.0, rx=0) for i in range(10)]
    src = tmp_path / "noebpf.jsonl"
    _write_jsonl(src, records)
    _, rows = _load_records(str(src))
    assert _syscall_frame(rows) is None
    generate_report(str(src), str(tmp_path / "r.html"))
    assert "Syscalls by category" not in (tmp_path / "r.html").read_text()


def test_output_format_toggle(tmp_path):
    records = [{"kind": "metadata", "pid": 1, "cmd": ["x"], "executable": "x", "t0_ms": 0}]
    records += [_tree_record(i * 100, cpu=50.0, rx=i * 100) for i in range(12)]
    src = tmp_path / "m.jsonl"
    _write_jsonl(src, records)

    # explicit format
    assert generate_report(str(src), str(tmp_path / "a.png"), fmt="png") == str(tmp_path / "a.png")
    assert (tmp_path / "a.png").read_bytes()[:4] == b"\x89PNG"
    # inferred from extension
    generate_report(str(src), str(tmp_path / "b.svg"))
    assert (tmp_path / "b.svg").read_text().lstrip().startswith("<svg")
    # default is html (interactive/JS)
    out = generate_report(str(src))
    assert out.endswith(".html")
    assert "vegaEmbed" in Path(out).read_text()


def test_no_records_raises(tmp_path):
    src = tmp_path / "empty.jsonl"
    src.write_text('{"kind":"metadata","pid":1,"cmd":["x"],"executable":"x","t0_ms":0}\n')
    with pytest.raises(ValueError, match="No metric records"):
        generate_report(str(src))

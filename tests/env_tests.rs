//! Tests for the env record (host/NUMA/affinity reproducibility snapshot)
//! and the tagged JSONL Record schema.

use denet::monitor::env::{
    count_range_list, format_range_list, parse_cpu_model, parse_distance_row,
    parse_node_memtotal_mb,
};
use denet::monitor::record::{parse_record, Record};
use denet::monitor::{tagged_json, EnvRecord, Metrics, ProcessMetadata};

// ---------- pure parsers ----------

#[test]
fn affinity_range_compression_basic() {
    assert_eq!(format_range_list(&[0, 1, 2, 3]), "0-3");
    assert_eq!(format_range_list(&[0, 1, 2, 3, 7, 8, 9]), "0-3,7-9");
    assert_eq!(format_range_list(&[5]), "5");
    assert_eq!(format_range_list(&[]), "");
}

#[test]
fn affinity_range_compression_unsorted_and_duplicates() {
    assert_eq!(format_range_list(&[3, 0, 2, 1, 1]), "0-3");
    assert_eq!(format_range_list(&[7, 9, 8]), "7-9");
}

#[test]
fn affinity_range_compression_singletons_mixed() {
    assert_eq!(format_range_list(&[0, 2, 4]), "0,2,4");
    assert_eq!(format_range_list(&[0, 1, 4, 5]), "0-1,4-5");
}

#[test]
fn count_range_list_roundtrip() {
    assert_eq!(count_range_list("0-3,7-9"), 7);
    assert_eq!(count_range_list("0,2,4"), 3);
    assert_eq!(count_range_list("5"), 1);
    assert_eq!(count_range_list(""), 0);
}

#[test]
fn numa_distance_parser_square_row() {
    assert_eq!(parse_distance_row("10 12 12 12"), vec![10, 12, 12, 12]);
    assert_eq!(parse_distance_row("10\n12\n12"), vec![10, 12, 12]);
    assert_eq!(parse_distance_row(""), Vec::<u32>::new());
}

#[test]
fn meminfo_parses_memtotal_in_mb() {
    let s = "Node 0 MemTotal:       65814528 kB\nNode 0 Other: 0 kB\n";
    assert_eq!(parse_node_memtotal_mb(s), Some(64272));
}

#[test]
fn meminfo_missing_returns_none() {
    assert_eq!(parse_node_memtotal_mb("Node 0 Free: 1 kB"), None);
}

#[test]
fn cpu_model_parsed_from_proc_cpuinfo() {
    let s = "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7742 64-Core Processor\ncache size\t: 512 KB\n";
    assert_eq!(
        parse_cpu_model(s),
        Some("AMD EPYC 7742 64-Core Processor".to_string())
    );
}

#[test]
fn cpu_model_missing_returns_none() {
    assert_eq!(parse_cpu_model("processor: 0\n"), None);
}

// ---------- Record / tagged JSON ----------

#[test]
fn record_env_roundtrip_carries_kind_tag() {
    let env = EnvRecord {
        ts_ms: 1_700_000_000_000,
        host: "omnibenchmark".into(),
        kernel: "6.18.7-test".into(),
        lscpu: denet::monitor::env::LsCpu {
            sockets: 1,
            cores_per_socket: 64,
            threads_per_core: 2,
            model: "AMD EPYC 7742".into(),
        },
        numa: denet::monitor::env::Numa {
            nodes: 4,
            distances: vec![
                vec![10, 12, 12, 12],
                vec![12, 10, 12, 12],
                vec![12, 12, 10, 12],
                vec![12, 12, 12, 10],
            ],
            node_sizes_mb: vec![64272, 64500, 64500, 64481],
        },
        affinity_inherited: "0-127".into(),
        cpu_governor: Some(vec!["performance".into()]),
        cpu_freq_khz: Some(vec![2_400_000]),
        thp_enabled: Some("always [madvise] never".into()),
        smt_active: Some(true),
        cgroup: Some("0::/user.slice".into()),
    };
    let json = tagged_json("env", &env).unwrap();
    assert!(json.contains("\"kind\":\"env\""));
    assert!(json.contains("\"host\":\"omnibenchmark\""));
    assert!(json.contains("\"affinity_inherited\":\"0-127\""));

    // Roundtrip through the Record enum.
    let r: Record = serde_json::from_str(&json).unwrap();
    match r {
        Record::Env(e) => {
            assert_eq!(e.host, "omnibenchmark");
            assert_eq!(e.numa.nodes, 4);
            assert_eq!(e.numa.distances[1][0], 12);
            assert_eq!(e.affinity_inherited, "0-127");
        }
        _ => panic!("expected Env variant"),
    }
}

/// Regression: a pre-tag-era JSONL file (untagged ProcessMetadata + Metrics)
/// must still be readable via `parse_record`.
#[test]
fn parse_record_back_compat_with_untagged_lines() {
    let md = ProcessMetadata::new(123, vec!["sleep".into()], "/usr/bin/sleep".into());
    let md_line = serde_json::to_string(&md).unwrap();
    assert!(!md_line.contains("\"kind\""));
    matches!(parse_record(&md_line), Some(Record::Metadata(_)));

    let m = Metrics::new();
    let m_line = serde_json::to_string(&m).unwrap();
    assert!(!m_line.contains("\"kind\""));
    matches!(parse_record(&m_line), Some(Record::Sample(_)));
}

#[test]
fn tagged_record_lines_parse_to_correct_variants() {
    let env_line = tagged_json("env", &EnvRecord::collect(std::process::id())).unwrap();
    assert!(env_line.contains("\"kind\":\"env\""));
    matches!(parse_record(&env_line), Some(Record::Env(_)));

    let md = ProcessMetadata::new(1, vec!["x".into()], "/x".into());
    let md_line = tagged_json("metadata", &md).unwrap();
    matches!(parse_record(&md_line), Some(Record::Metadata(_)));

    let m_line = tagged_json("sample", &Metrics::new()).unwrap();
    matches!(parse_record(&m_line), Some(Record::Sample(_)));
}

// ---------- Linux-only smoke test ----------

#[cfg(target_os = "linux")]
#[test]
fn collect_env_smoke_linux() {
    let env = EnvRecord::collect(std::process::id());
    // /proc and /sys/devices/system/cpu are present on essentially every
    // Linux runner; assert the must-haves and let optional fields be None.
    assert!(!env.host.is_empty(), "host should be non-empty");
    assert!(!env.kernel.is_empty(), "kernel should be non-empty");
    assert!(
        !env.lscpu.model.is_empty(),
        "CPU model should be readable from /proc/cpuinfo"
    );
    assert!(env.ts_ms > 0);
    // affinity should be readable for the calling process
    assert!(
        !env.affinity_inherited.is_empty(),
        "sched_getaffinity should populate affinity_inherited"
    );
}

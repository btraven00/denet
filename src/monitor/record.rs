//! Tagged JSONL record schema.
//!
//! Every line in a JSONL stream is one of these variants. The internal
//! `"kind"` tag lets downstream tooling dispatch by type without
//! shape-guessing. Untagged legacy files are still readable via the
//! `parse_record` fallback.

use serde::{Deserialize, Serialize};

use super::env::EnvRecord;
use super::metrics::{AggregatedMetrics, Metrics, ProcessMetadata, ProcessTreeMetrics};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Record {
    Env(Box<EnvRecord>),
    Metadata(ProcessMetadata),
    Sample(Metrics),
    Tree(Box<ProcessTreeMetrics>),
    Aggregated(Box<AggregatedMetrics>),
}

/// Wrapper used to inject `"kind"` into a struct without owning it.
/// Equivalent to `Record::Sample(metrics)` but avoids the clone.
#[derive(Serialize)]
struct Tagged<'a, T: Serialize> {
    kind: &'static str,
    #[serde(flatten)]
    inner: &'a T,
}

/// Serialize `value` as a single JSON line tagged with `kind`.
///
/// ```ignore
/// let line = tagged_json("sample", &metrics);
/// // {"kind":"sample","ts_ms":...,"cpu_usage":...}
/// ```
pub fn tagged_json<T: Serialize>(kind: &'static str, value: &T) -> serde_json::Result<String> {
    serde_json::to_string(&Tagged { kind, inner: value })
}

/// Parse one JSONL line, trying the tagged schema first and falling back
/// to the legacy untagged shapes used by pre-tag-era files.
pub fn parse_record(line: &str) -> Option<Record> {
    if let Ok(r) = serde_json::from_str::<Record>(line) {
        return Some(r);
    }
    // Fallback: try each known untagged shape in order from most-specific
    // (Tree has nested Aggregated) to least.
    if let Ok(t) = serde_json::from_str::<ProcessTreeMetrics>(line) {
        return Some(Record::Tree(Box::new(t)));
    }
    if let Ok(a) = serde_json::from_str::<AggregatedMetrics>(line) {
        return Some(Record::Aggregated(Box::new(a)));
    }
    if let Ok(m) = serde_json::from_str::<Metrics>(line) {
        return Some(Record::Sample(m));
    }
    if let Ok(md) = serde_json::from_str::<ProcessMetadata>(line) {
        return Some(Record::Metadata(md));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_emits_kind_field() {
        let m = ProcessMetadata::new(123, vec!["sleep".into()], "/usr/bin/sleep".into());
        let s = tagged_json("metadata", &m).unwrap();
        assert!(s.contains("\"kind\":\"metadata\""));
        assert!(s.contains("\"pid\":123"));
    }

    #[test]
    fn record_enum_roundtrip_metadata() {
        let m = ProcessMetadata::new(7, vec!["a".into(), "b".into()], "/bin/a".into());
        let json = serde_json::to_string(&Record::Metadata(m.clone())).unwrap();
        assert!(json.contains("\"kind\":\"metadata\""));
        let back: Record = serde_json::from_str(&json).unwrap();
        match back {
            Record::Metadata(md) => {
                assert_eq!(md.pid, 7);
                assert_eq!(md.cmd, vec!["a".to_string(), "b".to_string()]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn record_enum_roundtrip_sample() {
        let mut m = Metrics::new();
        m.cpu_usage = 42.5;
        m.mem_rss_kb = 1234;
        let json = serde_json::to_string(&Record::Sample(m)).unwrap();
        assert!(json.contains("\"kind\":\"sample\""));
        let back: Record = serde_json::from_str(&json).unwrap();
        match back {
            Record::Sample(s) => assert_eq!(s.cpu_usage, 42.5),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_record_handles_untagged_legacy() {
        // Pre-tag-era ProcessMetadata line, no "kind" field.
        let legacy = r#"{"pid":1,"cmd":["x"],"executable":"/x","t0_ms":0}"#;
        match parse_record(legacy).unwrap() {
            Record::Metadata(_) => {}
            _ => panic!("legacy metadata should parse via fallback"),
        }
    }

    #[test]
    fn parse_record_handles_untagged_sample() {
        let m = Metrics::new();
        let untagged = serde_json::to_string(&m).unwrap();
        assert!(!untagged.contains("\"kind\""));
        match parse_record(&untagged).unwrap() {
            Record::Sample(_) => {}
            _ => panic!("expected Sample"),
        }
    }

    #[test]
    fn record_env_roundtrip_carries_kind_tag() {
        let env = EnvRecord {
            ts_ms: 1_700_000_000_000,
            host: "omnibenchmark".into(),
            kernel: "6.18.7-test".into(),
            lscpu: crate::monitor::env::LsCpu {
                sockets: 1,
                cores_per_socket: 64,
                threads_per_core: 2,
                model: "AMD EPYC 7742".into(),
            },
            numa: crate::monitor::env::Numa {
                nodes: 2,
                distances: vec![vec![10, 12], vec![12, 10]],
                node_sizes_mb: vec![64272, 64500],
            },
            affinity_inherited: "0-127".into(),
            cpu_governor: None,
            cpu_freq_khz: None,
            thp_enabled: None,
            smt_active: None,
            cgroup: None,
        };
        let json = tagged_json("env", &env).unwrap();
        assert!(json.contains("\"kind\":\"env\""));
        assert!(json.contains("\"host\":\"omnibenchmark\""));

        let r: Record = serde_json::from_str(&json).unwrap();
        match r {
            Record::Env(e) => {
                assert_eq!(e.host, "omnibenchmark");
                assert_eq!(e.numa.nodes, 2);
                assert_eq!(e.affinity_inherited, "0-127");
            }
            _ => panic!("expected Env variant"),
        }
    }

    #[test]
    fn parse_record_handles_tagged_aggregated_and_tree() {
        let agg = AggregatedMetrics::default();
        let agg_line = tagged_json("aggregated", &agg).unwrap();
        match parse_record(&agg_line).unwrap() {
            Record::Aggregated(_) => {}
            _ => panic!("expected Aggregated"),
        }

        let tree = ProcessTreeMetrics {
            ts_ms: 0,
            parent: None,
            children: Vec::new(),
            aggregated: None,
        };
        let tree_line = tagged_json("tree", &tree).unwrap();
        match parse_record(&tree_line).unwrap() {
            Record::Tree(_) => {}
            _ => panic!("expected Tree"),
        }
    }

    #[test]
    fn parse_record_returns_none_for_garbage() {
        assert!(parse_record("not json").is_none());
        // valid JSON but no shape match
        assert!(parse_record("{\"unknown\":42}").is_none());
    }
}

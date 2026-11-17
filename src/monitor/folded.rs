//! Folded-stack export of a stored run's off-CPU waits
//!
//! One line per process and kernel stack, `command;outermost;...;innermost
//! milliseconds`: the format flamegraph.pl, inferno and speedscope read.
//! See docs/flamegraphs.md.

use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::io::BufRead;

/// Fold the off-CPU waits of a JSONL run into `stack milliseconds` lines,
/// sorted. Empty when the run has no off-CPU stacks (recorded without
/// `--enable-ebpf`, or nothing in it ever waited).
pub fn folded_offcpu(reader: impl BufRead) -> std::io::Result<Vec<String>> {
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut stacks: HashMap<u64, String> = HashMap::new();
    let mut waited_ns: BTreeMap<(u64, u64), u64> = BTreeMap::new();

    for line in reader.lines() {
        let Ok(rec) = serde_json::from_str::<Value>(&line?) else {
            continue; // a truncated last line of a run that was killed
        };
        // metadata and child records name the processes
        if let (Some(pid), Some(cmd)) = (rec["pid"].as_u64(), rec["cmd"][0].as_str()) {
            let name = cmd.rsplit('/').next().unwrap_or(cmd);
            // `;` and ` ` are the format's separators
            names.insert(pid, name.replace([';', ' '], "_"));
        }
        // tree samples carry it under `aggregated`, single-process ones at the top
        for off in [&rec["aggregated"]["ebpf"]["offcpu"], &rec["ebpf"]["offcpu"]] {
            // a stack is written once, in the first sample that refers to it
            for (id, frames) in off["kernel_stacks"].as_object().into_iter().flatten() {
                let Ok(id) = id.parse() else { continue };
                // stored innermost first; folded stacks start at the root
                let frames: Vec<&str> = frames
                    .as_array()
                    .into_iter()
                    .flatten()
                    .rev()
                    .filter_map(Value::as_str)
                    .collect();
                stacks.insert(id, frames.join(";"));
            }
            for wait in off["waits"].as_array().into_iter().flatten() {
                if let (Some(pid), Some(stack), Some(ns)) = (
                    wait["pid"].as_u64(),
                    wait["stack"].as_u64(),
                    wait["time_ns"].as_u64(),
                ) {
                    *waited_ns.entry((pid, stack)).or_default() += ns;
                }
            }
        }
    }

    // Processes running the same command share a tower, as in any flamegraph
    let mut folded: BTreeMap<String, u64> = BTreeMap::new();
    for ((pid, stack), ns) in waited_ns {
        let name = names
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| format!("pid-{pid}"));
        let frames = match stacks.get(&stack) {
            Some(frames) if !frames.is_empty() => frames,
            _ => "[unknown]",
        };
        *folded.entry(format!("{name};{frames}")).or_default() += ns;
    }
    Ok(folded
        .into_iter()
        .map(|(stack, ns)| (stack, (ns + 500_000) / 1_000_000))
        .filter(|&(_, ms)| ms > 0)
        .map(|(stack, ms)| format!("{stack} {ms}"))
        .collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn folds_waits_by_command_and_stack() {
        let run = r#"{"kind":"metadata","pid":10,"cmd":["/usr/bin/bash","job.sh"]}
{"kind":"child","pid":11,"ppid":10,"cmd":["sleep","1"]}
{"kind":"tree","aggregated":{"ebpf":{"offcpu":{"waits":[{"pid":11,"stack":7,"time_ns":600000000,"count":1},{"pid":10,"stack":8,"time_ns":250000000,"count":2}],"kernel_stacks":{"7":["schedule","do_nanosleep","__x64_sys_nanosleep"],"8":["schedule","do_wait"]}}}}}
{"kind":"child","pid":12,"ppid":10,"cmd":["sleep","1"]}
{"kind":"tree","aggregated":{"ebpf":{"offcpu":{"waits":[{"pid":12,"stack":7,"time_ns":400000000,"count":1},{"pid":99,"stack":3,"time_ns":2000000,"count":1},{"pid":10,"stack":8,"time_ns":300000,"count":1}]}}}}
{"kind":"tree","aggreg"#;
        assert_eq!(
            super::folded_offcpu(run.as_bytes()).unwrap(),
            vec![
                // root first; 250 ms + 0.3 ms
                "bash;do_wait;schedule 250",
                // not in a child record, stack never written
                "pid-99;[unknown] 2",
                // two sleeps, one tower: 600 ms + 400 ms, stack 7 written once
                "sleep;__x64_sys_nanosleep;do_nanosleep;schedule 1000",
            ]
        );
        assert!(super::folded_offcpu(&b"{\"kind\":\"tree\"}\n"[..])
            .unwrap()
            .is_empty());
    }
}

# Off-CPU flamegraphs

`denet stacks` exports where a run's processes spent their time waiting (off
the CPU: blocked on a pipe, a lock, a child, a sleep, disk or network) in the
folded-stack format that flamegraph tools read. denet does not draw the graph
itself; this page shows how to do it with
[inferno](https://github.com/jonhoo/inferno).

The data is the off-CPU profile described in [offcpu.md](offcpu.md): kernel
stacks only. It shows *what kind of wait* a process was in (`pipe_write`,
`futex_wait`, `do_nanosleep`), not which line of your program caused it, and
it says nothing about time spent running on the CPU.

## What is a flamegraph?

A [flamegraph](https://www.brendangregg.com/flamegraphs.html) draws many
sampled stacks at once: each box is a function, its width is the share of time
spent in it, and each box sits on top of its caller. The widest towers are
where the time went, so it is a fast way to find the one path that matters
among thousands. An
[off-CPU flamegraph](https://www.brendangregg.com/FlameGraphs/offcpuflamegraphs.html)
does the same for time spent waiting, which a CPU profiler never sees. It is
the usual answer when a job is slow but its CPU usage is low.

## Quick start

```bash
# 1. Record a run with eBPF. Run it as root so the frames get names (see Limits)
sudo denet --enable-ebpf --json -q -o run.jsonl run ./job.sh

# 2. Export the folded stacks
denet stacks run.jsonl > run.folded

# 3. Draw the flamegraph (once: cargo install inferno)
inferno-flamegraph --title "Off-CPU time" --countname ms --colors blue \
    run.folded > offcpu.svg
```

Open `offcpu.svg` in a browser: it is interactive. Click a box to zoom in on
it, hover for its exact time and share, and use Search (top right) to
highlight every box matching a name.

`denet stacks` reads the saved file only, so it needs no privileges and can
run on another machine. It fails with a message if the run has no off-CPU
stacks, which means the run was recorded without `--enable-ebpf`.

## The folded format

One line per command and kernel stack: the frames from the outermost to the
innermost, separated by `;`, then the milliseconds waited there.

```
bash;entry_SYSCALL_64_after_hwframe;do_syscall_64;x64_sys_call;__x64_sys_wait4;__do_sys_wait4;kernel_wait4;do_wait;schedule;__schedule;perf_trace_sched_switch 2877
dd;entry_SYSCALL_64_after_hwframe;do_syscall_64;x64_sys_call;__x64_sys_futex;do_futex;futex_wait;__futex_wait;futex_do_wait;schedule;__schedule;perf_trace_sched_switch 151
sleep;entry_SYSCALL_64_after_hwframe;do_syscall_64;x64_sys_call;__x64_sys_clock_nanosleep;common_nsleep;hrtimer_nanosleep;do_nanosleep;schedule;__schedule;perf_trace_sched_switch 1000
```

- The first field is the command name. Processes running the same command are
  added together, so 200 runs of `dd` are one tower, not 200.
- A process denet never sampled (it started and exited between two samples)
  has no recorded name and appears as `pid-<PID>`.
- Stacks that total less than half a millisecond are left out.

It is plain text, so `grep`, `sort` and `awk` work on it:

```bash
sort -t' ' -k2 -n -r run.folded | head     # longest waits first
awk '{s += $NF} END {print s " ms"}' run.folded   # total time waited
```

## Reading the graph

- **Each box is a function; its width is the time waited with that function
  on the stack.** Wider means more waiting. Nothing else about a box matters.
- **The x-axis is not time.** Boxes are sorted by name and identical stacks
  are merged. Left to right says nothing about what happened first.
- **Colours carry no meaning.** They only tell neighbouring boxes apart.
- **Read from the bottom up.** The bottom row is the command, and each row
  above is called by the one below it. The top box is where the thread
  actually stopped.

In these graphs the outer rows are the same on every stack and can be
ignored: the bottom ones are the system-call entry (`entry_SYSCALL_64...`,
`do_syscall_64`), the top ones are the scheduler (`schedule`, `__schedule`,
and the probe itself). The row that tells you something is the system call
just above the entry rows, and the few rows over it. Common ones:

| Frames | The process was waiting for |
|---|---|
| `__x64_sys_wait4`, `do_wait` | a child process to exit |
| `__x64_sys_clock_nanosleep`, `do_nanosleep` | a timer (`sleep`) |
| `__x64_sys_futex`, `futex_wait` | a lock or a condition variable held by another thread |
| `__x64_sys_read` with `anon_pipe_read`, `__x64_sys_write` with `pipe_write` | the other end of a pipe |
| `io_schedule`, or a filesystem's own frames | disk |
| `__x64_sys_epoll_wait`, `__x64_sys_poll`, `__x64_sys_select` | any of several file descriptors: an idle event loop or server |
| `tcp_recvmsg`, `sk_wait_data` | data from the network |

## What to keep in mind

- **Widths add up across threads and processes**, so the total can be many
  times the run's duration: ten threads that each wait one second make ten
  seconds of graph.
- **Idle waits dominate.** A shell waiting for its children, a `sleep`, a
  thread pool parked on a futex: these are usually the widest boxes and
  usually not the problem. Remove them before drawing (next section).
- **Waiting is not always bad.** A large box means the time was spent there,
  not that it could have been avoided.

## Narrowing it down

Filter the folded file before drawing it:

```bash
# Without the shell waiting for its children, and without sleeps
grep -v -e 'do_wait' -e 'do_nanosleep' run.folded \
    | inferno-flamegraph --countname ms --colors blue > offcpu.svg

# One command only
grep '^python3;' run.folded | inferno-flamegraph --countname ms > python.svg
```

Other views of the same file:

```bash
# Upside down (an "icicle" graph): command on top, growing downwards
inferno-flamegraph --inverted --countname ms run.folded > icicle.svg

# Grouped by where the wait happened, whichever command it was in
inferno-flamegraph --reverse --countname ms run.folded > by-wait.svg
```

## Comparing two runs

```bash
denet stacks before.jsonl > before.folded
denet stacks after.jsonl > after.folded
inferno-diff-folded before.folded after.folded \
    | inferno-flamegraph --title "Off-CPU: after vs before" --countname ms > diff.svg
```

In the differential graph the widths are those of the second run, and the
colour does carry meaning: red is where the second run waited longer, blue
where it waited less.

## Other tools

The same file works with Brendan Gregg's original
[`flamegraph.pl`](https://github.com/brendangregg/FlameGraph) (same options
as inferno) and with [speedscope](https://www.speedscope.app), an interactive
viewer that runs in the browser: drop `run.folded` onto the page. The values
it shows are the milliseconds from the file.

## Limits

- **Kernel stacks only.** There are no user-space frames, so the graph cannot
  point at a function in your program.
- **Frame names need a readable `/proc/kallsyms`** at recording time. On most
  distributions an ordinary user cannot read it, even with the eBPF file
  capabilities: the frames are then hexadecimal addresses and the graph is
  unreadable. Record as root.
- **Waits of 1 ms or less are not recorded**, and a wait is counted when the
  thread wakes up, so a thread still blocked when the run ends is missing.
- **Off-CPU only.** Time spent computing does not appear. A process that
  never waits has no boxes at all.

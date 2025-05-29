# Rust-Based ProcessMonitor Work Plan

### 1. **Research existing crates / libraries**

* **`sysinfo`**: Popular for cross-platform process info (CPU, memory, threads, IO). Lightweight, no heavy dependencies.
* **`procfs`** (Linux-only): Direct access to `/proc`, very minimal.
* **`heim`**: Async, comprehensive system info, but heavier deps and still maturing.
* **`psutil`-like Rust libs**: Few and mostly wrappers around system calls, may be unstable.

**Action:** Start with **`sysinfo`** — good balance of coverage, cross-platform support, and small footprint.

---

### 2. **Basic architecture**

* **Command execution & monitoring**

  * Launch subprocess with `std::process::Command`.
  * Track PID.

* **Sampling loop**

  * Use async timer (e.g., `tokio::time::sleep`) or standard thread sleep for sync.
  * Adaptive sampling interval based on runtime.

* **Metrics collected per sample:**

  * Memory RSS (resident set size)
  * CPU % (total + per thread if possible)
  * I/O bytes read/written
  * Number of threads
  * Include children PIDs recursively and aggregate.

* **Data serialization**

  * Output JSON lines or structured JSON file per sample.
  * Use `serde_json` for serialization.

---

### 3. **API design**

* Rust-native struct `ProcessMonitor` with:

  * `new(cmd: Vec<String>, adaptive: bool, base_interval: Duration, max_interval: Duration)`
  * `run(&mut self) -> Result<ProcessStats>` (blocking or async)
  * Export JSON or return data to caller.

---

### 4. **Python bindings**

* Use **`PyO3` + `maturin`** to expose minimal API:

  * `start_monitor(cmd: List[str], adaptive: bool) -> PyObject`
  * `poll_metrics()` or return async iterator of JSON objects
* Keep Python wrapper thin, delegate all logic to Rust.

---

### 5. **Testing**

* Unit tests in Rust for sampling logic and adaptive interval calculation.
* Integration tests launching dummy processes (e.g. `sleep 1`, CPU-bound busy loop).
* Mock sysinfo data if possible for unit testing (by abstracting sysinfo calls).
* Python wrapper tests: call exposed API, validate JSON output shape.

---

### 6. **Packaging & distribution**

* Package with `maturin` to build wheels for Python.
* Document dependencies (Rust toolchain + maturin needed to build).
* Provide prebuilt wheels if possible.

---

### 7. **Slim dependencies checklist**

* `sysinfo` (for system metrics) — single major dependency, maintained.
* `serde` + `serde_json` for JSON serialization (lightweight).
* `tokio` (optional, for async timers) — only if you want async; otherwise standard sleep.
* `PyO3` for Python bindings.

Aim to **avoid heavy crates or big async runtimes unless absolutely necessary**.

---

### 8. **Future considerations**

* Add optional event-driven sampling if supported by OS (e.g. Linux perf events, Windows ETW) to reduce polling overhead.
* Support for different OS-specific metrics (customize for Linux vs Windows).
* Add dynamic reconfiguration of sampling interval based on detected metrics.

---

# Summary

| Step                | Tool / Crate              | Notes                               |
| ------------------- | ------------------------- | ----------------------------------- |
| System info         | `sysinfo`                 | Cross-platform, lightweight         |
| Serialization       | `serde` + `serde_json`    | Fast, minimal                       |
| Async or sync sleep | `tokio` (optional) or std | Keep minimal if possible            |
| Python bindings     | `PyO3` + `maturin`        | Industry standard for Rust<->Python |

---


# Denet Test Scripts

Test scripts for child process monitoring functionality.

## Scripts

### `simple_child_test.py`
Basic test with 3 child processes.

```bash
./target/release/denet run -- python3 scripts/simple_child_test.py
./target/release/denet --json run -- python3 scripts/simple_child_test.py
./target/release/denet --exclude-children run -- python3 scripts/simple_child_test.py
```

### `test_child_processes.py`
Complex test with multiple children, worker threads, and lifecycle changes.

```bash
./target/release/denet run -- python3 scripts/test_child_processes.py
./target/release/denet --duration 10 --json run -- python3 scripts/test_child_processes.py
```

## Expected Behavior

- Process count shows parent + children (e.g., "Tree (4 procs)")
- JSON includes parent, children array, and aggregated metrics
- Children show individual PIDs and command names
- Metrics aggregate correctly across process tree

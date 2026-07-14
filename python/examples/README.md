# denet Python Examples

This directory contains examples demonstrating how to use the `denet` Python package for process monitoring.

## Child Process Monitoring

The `child_process_monitoring.py` example demonstrates how to monitor a process that spawns multiple child processes.

### Running the Example

```bash
python child_process_monitoring.py
```

This example:
1. Spawns multiple child processes that perform CPU-intensive work
2. Monitors the entire process tree (parent + children)
3. Displays aggregate metrics for all processes
4. Saves detailed monitoring data to a file

### Key Features Demonstrated

- Using `include_children=True` to monitor entire process trees
- Aggregating CPU and memory usage across all processes
- Tracking the number of processes over time
- Generating summary statistics for the entire monitoring session

## Profiling a Real Pipeline (scanpy)

`scanpy_pbmc.py` is a small single-cell workload — it downloads the pbmc3k
dataset and runs filter → normalize → PCA → neighbor graph → Leiden clustering.
Unlike the examples above, it doesn't use the denet API; it's a realistic thing
to *profile*, with naturally distinct phases that show off denet's report and
regime detection.

It declares its own dependencies with [PEP 723](https://peps.python.org/pep-0723/)
inline metadata, so [uv](https://docs.astral.sh/uv/) installs scanpy into an
ephemeral environment automatically:

```bash
# run it directly
uv run scanpy_pbmc.py

# or profile it and turn the run into a report
denet run --json --out scanpy.jsonl uv run scanpy_pbmc.py
denet-report scanpy.jsonl -o scanpy.html   # needs: pip install denet[report]
```

The report's regime detection typically separates the phases cleanly: a heavy
import/startup phase, the dataset download (network), the multi-core PCA +
neighbor-graph phase, and the single-threaded clustering phase. See
[docs/python-api.md](../../docs/python-api.md#reports) for the report options.

## Additional Examples

More examples will be added in the future. If you have a specific use case you'd like to see demonstrated, please open an issue on our GitHub repository.

## Using These Examples

To run these examples, make sure you have installed the `denet` package:

```bash
pip install denet
# or from source
pip install -e .
```

Then you can run any example directly:

```bash
python examples/child_process_monitoring.py
```

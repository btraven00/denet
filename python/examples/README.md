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

import json
from pprint import pprint

from denet import execute_with_monitoring

# Monitor with child process tracking enabled
exit_code, monitor = execute_with_monitoring(
    cmd=['stress-ng', '--cpu', '4', '--timeout', '10s'],
    output_file='stress.jsonl',
    include_children=True  # Enable child process monitoring
)

# Get summary with proper aggregated metrics
summary_json = monitor.get_summary()
summary = json.loads(summary_json)
print(f"Average CPU usage: {summary['avg_cpu_usage']:.2f}%")
print(f"Peak memory usage: {summary['peak_mem_rss_kb'] / 1024:.2f} MB")
print(f"Max processes: {summary['max_processes']}")

pprint(summary)

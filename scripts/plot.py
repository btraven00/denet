import json
import matplotlib.pyplot as plt

# Load your denet output (assume line-delimited JSON or JSON array)
records = [json.loads(line) for line in open("out.json")][1:]


# Extract aggregated metrics
timestamps = []
cpu_usages = []
mem_usages_mb = []

for entry in records:
    agg = entry["aggregated"]
    timestamps.append(agg["ts_ms"] / 1000)  # convert ms to seconds
    cpu_usages.append(agg["cpu_usage"])
    mem_usages_mb.append(agg["mem_rss_kb"] / 1024)  # KB to MB

# Normalize timestamps to start at zero
start_ts = timestamps[0]
timestamps = [t - start_ts for t in timestamps]

# Plotting
fig, ax1 = plt.subplots(figsize=(6.4, 4.8))  # 640x480 pixels at 100 DPI

# CPU (left axis)
ax1.set_xlabel("Time (s)")
ax1.set_ylabel("CPU Usage (%)", color="red")
ax1.plot(timestamps, cpu_usages, color="red", label="CPU Usage")
ax1.tick_params(axis="y", labelcolor="red")

# Memory (right axis)
ax2 = ax1.twinx()
ax2.set_ylabel("Memory Usage (MB)", color="blue")
ax2.plot(timestamps, mem_usages_mb, color="blue", label="Memory Usage")
ax2.tick_params(axis="y", labelcolor="blue")

# Optional: add grid and title
plt.title("Aggregated Resource Usage from denet")
plt.grid(True)
plt.tight_layout()
# Save with exact pixel dimensions
plt.savefig('resource_usage.png', dpi=100, bbox_inches='tight')
plt.show()

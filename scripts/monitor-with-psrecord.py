# monitor with psrecord (psutil wrapper) for comparison
import subprocess
import time
import os

# Start the workload process
proc = subprocess.Popen(["python3", "stress.py"])
print(f"Started workload with PID {proc.pid}")

# Start psrecord on the process
psrecord_cmd = [
    "psrecord",
    str(proc.pid),
    "--include-children",
    "--interval",
    "0.1",
    "--duration",
    "10",
    "--plot",
    "psrecord_output.png",
]
time.sleep(1)  # Give the process a moment to spawn children
subprocess.run(psrecord_cmd)

proc.wait()
print("Monitoring complete.")

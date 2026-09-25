"""ProcessMonitor.run() must not hold the GIL, and must return once an attached
process has exited even if its parent has not reaped it yet (zombie)."""

import subprocess
import threading
import time

import denet


def test_run_in_thread_releases_gil_and_ends_on_zombie():
    # Popen'd and deliberately not waited on until run() returns, so the child
    # is a zombie while run() is still polling it.
    proc = subprocess.Popen(["sh", "-c", "sleep 1"])
    monitor = denet.ProcessMonitor.from_pid(proc.pid, 50, 500, quiet=True)
    worker = threading.Thread(target=monitor.run, daemon=True)
    start = time.time()
    worker.start()

    ticks = 0
    while time.time() - start < 0.5:
        ticks += 1
        time.sleep(0.01)
    # A held GIL blocks this loop until run() returns (~1s), giving
    # ~1 tick; macOS CI oversleeps sleep(0.01) badly, so only demand progress.
    assert ticks > 3, "main thread starved: run() is holding the GIL"

    worker.join(timeout=5)
    try:
        assert not worker.is_alive(), "run() kept polling an exited (zombie) process"
    finally:
        proc.wait()

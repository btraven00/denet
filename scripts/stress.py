import os
import gc
import time
import multiprocessing as mp
import numpy as np

N_WORKERS = 8


def cpu_stress(duration=5):
    """Burn CPU doing useless math for `duration` seconds."""
    print(f"[{os.getpid()}] CPU stress started.")
    end = time.time() + duration
    while time.time() < end:
        _ = sum(i * i for i in range(10000))  # Useless calculation
    print(f"[{os.getpid()}] CPU stress done.")


def memory_stress(size_mb=500, duration=3):
    """Allocate memory and hold it for `duration` seconds."""
    print(f"[{os.getpid()}] Memory stress started. Allocating {size_mb}MB.")
    arr = np.ones((size_mb * 1024 * 1024 // 8,), dtype="float64")  # ~8 bytes per float64
    time.sleep(duration)
    print(f"[{os.getpid()}] Memory stress done.")
    del arr
    # Force garbage collection
    gc.collect()


def worker_task(index):
    """Each subprocess will do both CPU and memory stress."""
    print(f"[{os.getpid()}] Worker {index} started.")
    cpu_stress()
    memory_stress()
    print(f"[{os.getpid()}] Worker {index} done.")


def main():
    print(f"[{os.getpid()}] Main process starting subprocesses.")
    workers = []
    for i in range(N_WORKERS):  # Spawn 4 subprocesses
        p = mp.Process(target=worker_task, args=(i,))
        p.start()
        workers.append(p)

    for p in workers:
        p.join()

    print(f"[{os.getpid()}] Main process done.")


if __name__ == "__main__":
    main()

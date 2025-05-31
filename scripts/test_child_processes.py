#!/usr/bin/env python3
"""Complex child process test with varying lifespans and worker threads."""

import subprocess
import time
import threading
import os
import sys
from pathlib import Path

def cpu_intensive_work():
    """CPU-intensive work to generate load"""
    print(f"[CPU Worker {os.getpid()}] Starting CPU-intensive work...")
    start = time.time()
    # Calculate primes to generate CPU load
    primes = []
    for num in range(2, 2000):
        is_prime = True
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
    duration = time.time() - start
    print(f"[CPU Worker {os.getpid()}] Found {len(primes)} primes in {duration:.2f}s")

def io_intensive_work():
    """I/O-intensive work to generate disk activity"""
        print(f"[I/O Worker {os.getpid()}] Starting I/O-intensive work...")
        temp_file = f"/tmp/denet_test_io_{os.getpid()}.txt"
    
    # Write data
    with open(temp_file, 'w') as f:
        for i in range(1000):
            f.write(f"Line {i}: This is test data for I/O monitoring in DENET child process {os.getpid()}\n")
    
    # Read it back
    with open(temp_file, 'r') as f:
        lines = f.readlines()
    
    # Clean up
    Path(temp_file).unlink(missing_ok=True)
    print(f"[I/O Worker {os.getpid()}] Processed {len(lines)} lines")

def main():
    print(f"=== DENET Child Process Test Script ===")
    print(f"Parent PID: {os.getpid()}")
    print(f"Command: {' '.join(sys.argv)}")
    print()
    
    # List to track all child processes
    child_processes = []
    worker_threads = []
    
    try:
        print("Phase 1: Starting child processes...")
        
        # Start some long-running child processes
        for i in range(3):
            duration = 10 + i * 2  # 10s, 12s, 14s
            proc = subprocess.Popen(['sleep', str(duration)])
            child_processes.append(proc)
            print(f"  Started long-running child {i}: PID {proc.pid} (sleep {duration}s)")
        
        # Start some short-lived child processes
        for i in range(2):
            duration = 2 + i  # 2s, 3s
            proc = subprocess.Popen(['sleep', str(duration)])
            child_processes.append(proc)
            print(f"  Started short-lived child {i}: PID {proc.pid} (sleep {duration}s)")
        
        print(f"  Total child processes started: {len(child_processes)}")
        print()
        
        print("Phase 2: Starting worker threads (will show increased thread count)...")
        
        # Start CPU-intensive threads
        for i in range(2):
            thread = threading.Thread(target=cpu_intensive_work, name=f"CPUWorker-{i}")
            thread.start()
            worker_threads.append(thread)
        
        # Start I/O-intensive threads
        for i in range(2):
            thread = threading.Thread(target=io_intensive_work, name=f"IOWorker-{i}")
            thread.start()
            worker_threads.append(thread)
        
        print(f"  Started {len(worker_threads)} worker threads")
        print()
        
        print("Phase 3: Parent process working...")
        for i in range(8):
            print(f"  Parent work iteration {i+1}/8 (PID {os.getpid()})")
            
            # Do some parent work
            temp_file = f"/tmp/denet_parent_work_{i}.txt"
            with open(temp_file, 'w') as f:
                f.write(f"Parent process {os.getpid()} work iteration {i}\n")
                for j in range(100):
                    f.write(f"  Data line {j}: {time.time()}\n")
            
            # Clean up immediately
            Path(temp_file).unlink(missing_ok=True)
            
            time.sleep(1)
        
        print()
        print("Phase 4: Waiting for worker threads to complete...")
        for thread in worker_threads:
            thread.join()
        print("  All worker threads completed")
        
        print()
        print("Phase 5: Checking child process status...")
        running_children = []
        for i, proc in enumerate(child_processes):
            if proc.poll() is None:
                running_children.append((i, proc))
                print(f"  Child {i} (PID {proc.pid}): still running")
            else:
                print(f"  Child {i} (PID {proc.pid}): completed with code {proc.returncode}")
        
        print()
        print("Phase 6: Waiting for remaining children...")
        for i, proc in running_children:
            print(f"  Waiting for child {i} (PID {proc.pid})...")
            proc.wait()
            print(f"  Child {i} completed with code {proc.returncode}")
        
        print()
        print("=== Test Complete ===")
        print(f"Parent PID {os.getpid()} finished successfully")
        
    except KeyboardInterrupt:
        print()
        print("=== Interrupted by user ===")
        print("Cleaning up child processes...")
        
        for i, proc in enumerate(child_processes):
            if proc.poll() is None:
                print(f"  Terminating child {i} (PID {proc.pid})")
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print(f"  Force killing child {i} (PID {proc.pid})")
                    proc.kill()
        
        print("Cleanup complete")
        sys.exit(1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Simple child process test for DENET."""

import subprocess
import time
import os

def main():
    print(f"Parent PID: {os.getpid()}")
    
    # Start 3 child processes
    children = []
    for i in range(3):
        proc = subprocess.Popen(['sleep', '5'])
        children.append(proc)
        print(f"Started child {i}: PID {proc.pid}")
    
    # Parent does some work
    for i in range(10):
        print(f"Parent working... {i+1}/10")
        time.sleep(0.5)
    
    # Wait for children
    print("Waiting for children to finish...")
    for i, proc in enumerate(children):
        proc.wait()
        print(f"Child {i} finished")
    
    print("All done!")

if __name__ == "__main__":
    main()
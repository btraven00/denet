#!/usr/bin/env python3
"""
Validation script to compare DENET metrics with standard Unix tools.
Usage: python validate_metrics.py [process_name_or_pid]
"""

import subprocess
import json
import sys
import time
import re
from pathlib import Path

def run_command(cmd):
    """Run shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return None

def get_process_info_ps(pid):
    """Get process info using ps command"""
    # Get basic process info
    ps_info = run_command(f"ps -p {pid} -o pid,ppid,rss,vsz,pcpu,nlwp,comm --no-headers")
    if not ps_info:
        return None
    
    parts = ps_info.split()
    return {
        'pid': int(parts[0]),
        'ppid': int(parts[1]),
        'rss_kb': int(parts[2]),
        'vsz_kb': int(parts[3]),
        'cpu_percent': float(parts[4]),
        'threads': int(parts[5]),
        'command': parts[6]
    }

def get_children_pstree(pid):
    """Get all descendant processes using pstree (matches DENET recursive behavior)"""
    pstree_output = run_command(f"pstree -p {pid}")
    if not pstree_output:
        return []
    
    # Extract PIDs from pstree output
    pids = re.findall(r'\((\d+)\)', pstree_output)
    # Remove the parent PID
    children = [int(p) for p in pids if int(p) != pid]
    return children

def get_children_ps_direct(pid):
    """Get direct child processes using ps"""
    ps_output = run_command(f"ps --ppid {pid} -o pid --no-headers")
    if not ps_output:
        return []
    
    return [int(line.strip()) for line in ps_output.split('\n') if line.strip()]

def get_children_ps_recursive(pid):
    """Get all descendant processes recursively using ps"""
    all_children = []
    direct_children = get_children_ps_direct(pid)
    
    for child in direct_children:
        all_children.append(child)
        # Recursively get grandchildren
        grandchildren = get_children_ps_recursive(child)
        all_children.extend(grandchildren)
    
    return all_children

def get_proc_status(pid):
    """Get process info from /proc/PID/status"""
    try:
        with open(f"/proc/{pid}/status", 'r') as f:
            status = f.read()
        
        info = {}
        for line in status.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'VmRSS':
                    info['rss_kb'] = int(value.split()[0])
                elif key == 'VmSize':
                    info['vsz_kb'] = int(value.split()[0])
                elif key == 'Threads':
                    info['threads'] = int(value)
                elif key == 'PPid':
                    info['ppid'] = int(value)
        
        return info
    except (FileNotFoundError, PermissionError):
        return None

def count_threads_proc(pid):
    """Count threads using /proc/PID/task directory"""
    try:
        task_dir = Path(f"/proc/{pid}/task")
        return len(list(task_dir.iterdir()))
    except (FileNotFoundError, PermissionError):
        return None

def run_denet_sample(target):
    """Run DENET and get one sample"""
    try:
        # Find denet binary
        denet_binary = "./target/debug/denet"
        if not Path(denet_binary).exists():
            denet_binary = "cargo run --"
        
        # Determine if target is PID or command
        if target.isdigit():
            cmd = f"timeout 2 {denet_binary} --json --duration 1 attach {target}"
        else:
            # Find PID of process by name
            pgrep_output = run_command(f"pgrep -n {target}")
            if not pgrep_output:
                print(f"Process '{target}' not found")
                return None
            pid = pgrep_output.strip()
            cmd = f"timeout 2 {denet_binary} --json --duration 1 attach {pid}"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        
        metadata = None
        sample = None
        
        for line in lines:
            if line and not line.startswith('Monitoring') and not line.startswith('Press'):
                try:
                    data = json.loads(line)
                    if 'pid' in data and 'cmd' in data and 'aggregated' not in data:
                        metadata = data
                    elif 'aggregated' in data:
                        sample = data
                        break
                except json.JSONDecodeError:
                    continue
        
        return metadata, sample
    except Exception as e:
        print(f"Error running DENET: {e}")
        return None, None

def compare_metrics(target):
    """Compare DENET metrics with Unix tools"""
    print(f"=== Validating metrics for: {target} ===\n")
    
    # Run DENET
    print("🔍 Running DENET...")
    metadata, sample = run_denet_sample(target)
    
    if not metadata or not sample:
        print("❌ Failed to get DENET data")
        return
    
    pid = metadata['pid']
    print(f"📋 Process ID: {pid}")
    print(f"📋 Command: {' '.join(metadata['cmd'])}")
    print(f"📋 Executable: {metadata['exe']}\n")
    
    # Get Unix tools data
    print("🔍 Gathering Unix tools data...")
    ps_info = get_process_info_ps(pid)
    proc_status = get_proc_status(pid)
    proc_threads = count_threads_proc(pid)
    children_pstree = get_children_pstree(pid)
    children_ps_direct = get_children_ps_direct(pid)
    children_ps_recursive = get_children_ps_recursive(pid)
    
    print("\n=== PROCESS COUNTING COMPARISON ===")
    denet_children = len(sample['children']) if sample['children'] else 0
    denet_total_procs = sample['aggregated']['process_count'] if sample['aggregated'] else 1
    
    print(f"DENET children (recursive):     {denet_children}")
    print(f"DENET total processes:          {denet_total_procs}")
    print(f"ps direct children:            {len(children_ps_direct)}")
    print(f"ps recursive children:         {len(children_ps_recursive)}")
    print(f"pstree all descendants:        {len(children_pstree)}")
    
    if denet_children != len(children_ps_recursive):
        print(f"⚠️  Recursive child count mismatch: DENET={denet_children}, ps_recursive={len(children_ps_recursive)}")
    else:
        print("✅ Recursive child count matches ps")
    
    # Note: DENET counts all descendants, not just direct children
    print(f"ℹ️  DENET uses recursive counting (like pstree), not just direct children")
    
    print("\n=== THREAD COUNTING COMPARISON ===")
    if sample['parent']:
        denet_parent_threads = sample['parent']['thread_count']
        denet_total_threads = sample['aggregated']['thread_count'] if sample['aggregated'] else denet_parent_threads
        
        print(f"DENET parent threads:  {denet_parent_threads}")
        print(f"DENET total threads:   {denet_total_threads}")
        
        if ps_info:
            print(f"ps nlwp (threads):    {ps_info['threads']}")
            if denet_parent_threads != ps_info['threads']:
                print(f"⚠️  Parent thread count mismatch: DENET={denet_parent_threads}, ps={ps_info['threads']}")
            else:
                print("✅ Parent thread count matches ps")
        
        if proc_status and 'threads' in proc_status:
            print(f"/proc/status threads: {proc_status['threads']}")
        
        if proc_threads:
            print(f"/proc/task count:     {proc_threads}")
            if denet_parent_threads != proc_threads:
                print(f"⚠️  Thread count mismatch: DENET={denet_parent_threads}, /proc/task={proc_threads}")
            else:
                print("✅ Thread count matches /proc/task")
    
    print("\n=== MEMORY COMPARISON ===")
    if sample['parent']:
        denet_rss = sample['parent']['mem_rss_kb']
        denet_vms = sample['parent']['mem_vms_kb']
        
        print(f"DENET RSS (KB):        {denet_rss}")
        print(f"DENET VMS (KB):        {denet_vms}")
        
        if ps_info:
            print(f"ps RSS (KB):          {ps_info['rss_kb']}")
            print(f"ps VSZ (KB):          {ps_info['vsz_kb']}")
            
            rss_diff_pct = abs(denet_rss - ps_info['rss_kb']) / ps_info['rss_kb'] * 100
            vsz_diff_pct = abs(denet_vms - ps_info['vsz_kb']) / ps_info['vsz_kb'] * 100
            
            if rss_diff_pct > 5:
                print(f"⚠️  RSS difference: {rss_diff_pct:.1f}%")
            else:
                print("✅ RSS matches ps (within 5%)")
            
            if vsz_diff_pct > 5:
                print(f"⚠️  VSZ difference: {vsz_diff_pct:.1f}%")
            else:
                print("✅ VSZ matches ps (within 5%)")
        
        if proc_status:
            if 'rss_kb' in proc_status:
                print(f"/proc/status RSS:     {proc_status['rss_kb']}")
            if 'vsz_kb' in proc_status:
                print(f"/proc/status VSZ:     {proc_status['vsz_kb']}")
    
    print("\n=== DETAILED CHILDREN INFO ===")
    if children_ps_direct:
        print("Direct children found by ps:")
        for child_pid in children_ps_direct[:5]:  # Show first 5
            child_ps = get_process_info_ps(child_pid)
            if child_ps:
                print(f"  PID {child_pid}: {child_ps['command']} (threads: {child_ps['threads']})")
        if len(children_ps_direct) > 5:
            print(f"  ... and {len(children_ps_direct) - 5} more")
    
    if children_ps_recursive and len(children_ps_recursive) != len(children_ps_direct):
        print(f"All descendants found by ps: {len(children_ps_recursive)} total")
    
    if sample['children']:
        print("Children found by DENET:")
        for child in sample['children'][:5]:  # Show first 5
            print(f"  PID {child['pid']}: {child['command']} (threads: {child['metrics']['thread_count']})")
        if len(sample['children']) > 5:
            print(f"  ... and {len(sample['children']) - 5} more")

def main():
    if len(sys.argv) < 2:
        # Default to a common process
        target = "bash"
        print("No target specified, using 'bash' as default")
    else:
        target = sys.argv[1]
    
    compare_metrics(target)

if __name__ == "__main__":
    main()
import unittest
import subprocess
import sys
import os
import json
from pathlib import Path

# Get path to binary (assumes build with cargo)
def get_pmet_binary():
    # Try debug build first
    candidates = [
        Path("target/debug/pmet"),
        Path("../target/debug/pmet"),
        Path("../../target/debug/pmet"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    
    # Fall back to release build
    candidates = [
        Path("target/release/pmet"),
        Path("../target/release/pmet"),
        Path("../../target/release/pmet"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    
    raise FileNotFoundError("Could not find pmet binary. Make sure to build it first with 'cargo build'")

class TestCliArgs(unittest.TestCase):
    def setUp(self):
        self.binary = get_pmet_binary()
    
    def test_help_flag(self):
        """Test that --help flag works"""
        result = subprocess.run([self.binary, "--help"], 
                               capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)
        self.assertIn("Options:", result.stdout)
    
    def test_version_flag(self):
        """Test that --version flag works"""
        result = subprocess.run([self.binary, "--version"], 
                               capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("pmet", result.stdout.lower())
    
    def test_missing_command(self):
        """Test that missing command results in error"""
        result = subprocess.run([self.binary], 
                               capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        # With subcommands, clap shows help in stderr
        self.assertIn("usage", result.stderr.lower())
    
    def test_json_flag(self):
        """Test that --json flag is recognized"""
        # Use sleep command with run subcommand to ensure we have time to collect metrics
        cmd = [self.binary, "--json", "run", "sleep", "0.5"]
        result = subprocess.run(cmd, 
                               capture_output=True, text=True, timeout=2)
        
        # At least one line should be valid JSON
        lines = result.stdout.strip().split("\n")
        json_found = False
        metadata_found = False
        for line in lines:
            if line and not line.startswith("Monitoring") and not line.startswith("Press") and not line.startswith("Collected"):
                try:
                    data = json.loads(line)
                    # First line is metadata, subsequent lines are tree metrics
                    if "pid" in data and "cmd" in data and "aggregated" not in data:
                        # This is the metadata line
                        self.assertIn("exe", data)
                        self.assertIn("t0_ms", data)
                        metadata_found = True
                    elif "aggregated" in data:
                        # This is a tree metrics line
                        self.assertIn("cpu_usage", data["aggregated"])
                        self.assertIn("mem_rss_kb", data["aggregated"])
                        json_found = True
                        break
                except json.JSONDecodeError:
                    continue
        
        self.assertTrue(json_found or metadata_found, "No valid JSON output found")
    
    def test_attach_pid(self):
        """Test that attach subcommand works with valid PID"""
        # Start a background process and get its PID
        import subprocess
        import time
        
        # Start a long-running process
        proc = subprocess.Popen(["sleep", "2"])
        pid = proc.pid
        
        try:
            # Test attaching to the PID with duration limit
            cmd = [self.binary, "--json", "--duration", "1", "attach", str(pid)]
            result = subprocess.run(cmd, 
                                   capture_output=True, text=True, timeout=3)
            
            # Should succeed and produce JSON output
            self.assertEqual(result.returncode, 0, f"Failed to attach to PID {pid}")
            
            # Check for JSON output
            lines = result.stdout.strip().split("\n")
            json_found = False
            metadata_found = False
            for line in lines:
                if line and not line.startswith("Monitoring") and not line.startswith("Press") and not line.startswith("Collected"):
                    try:
                        data = json.loads(line)
                        # First line is metadata, subsequent lines are tree metrics
                        if "pid" in data and "cmd" in data and "aggregated" not in data:
                            # This is the metadata line
                            self.assertIn("exe", data)
                            self.assertIn("t0_ms", data)
                            metadata_found = True
                        elif "aggregated" in data:
                            # This is a tree metrics line
                            self.assertIn("cpu_usage", data["aggregated"])
                            json_found = True
                            break
                    except json.JSONDecodeError:
                        continue
            
            self.assertTrue(json_found or metadata_found, "No valid JSON output found for PID attachment")
            
        finally:
            # Clean up the background process
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except:
                proc.kill()
    
    def test_attach_invalid_pid(self):
        """Test that attach fails with invalid PID"""
        # Use a PID that's very unlikely to exist
        invalid_pid = 999999
        
        cmd = [self.binary, "attach", str(invalid_pid)]
        result = subprocess.run(cmd, 
                               capture_output=True, text=True, timeout=2)
        
        # Should fail
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error attaching", result.stderr)

if __name__ == "__main__":
    unittest.main()
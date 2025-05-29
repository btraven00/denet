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
        self.assertIn("error", result.stderr.lower())
    
    def test_json_flag(self):
        """Test that --json flag is recognized"""
        # Use sleep command to ensure we have time to collect metrics
        cmd = [self.binary, "--json", "sleep", "0.5"]
        result = subprocess.run(cmd, 
                               capture_output=True, text=True, timeout=2)
        
        # At least one line should be valid JSON
        lines = result.stdout.strip().split("\n")
        json_found = False
        for line in lines:
            if line and not line.startswith("Monitoring") and not line.startswith("Press"):
                try:
                    data = json.loads(line)
                    self.assertIn("cpu_usage", data)
                    self.assertIn("mem_rss_kb", data)
                    json_found = True
                    break
                except json.JSONDecodeError:
                    continue
        
        self.assertTrue(json_found, "No valid JSON output found")

if __name__ == "__main__":
    unittest.main()
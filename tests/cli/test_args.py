import unittest
import subprocess
import sys
import os
import json
import tempfile
from pathlib import Path

# Get path to binary (assumes build with cargo)
def get_denet_binary():
    # Try debug build first
    candidates = [
        Path("target/debug/denet"),
        Path("../target/debug/denet"),
        Path("../../target/debug/denet"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    
    # Fall back to release build
    candidates = [
        Path("target/release/denet"),
        Path("../target/release/denet"),
        Path("../../target/release/denet"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    
    raise FileNotFoundError("Could not find denet binary. Make sure to build it first with 'cargo build'")

class TestCliArgs(unittest.TestCase):
    def setUp(self):
        self.binary = get_denet_binary()
    
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
        self.assertIn("denet", result.stdout.lower())
    
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
        
        # Check if out.json was created (default behavior)
        self.assertTrue(os.path.exists("out.json"), "Default output file out.json was not created")
    
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
        
    def test_stats_command(self):
        """Test that stats command works (renamed from summary)"""
        # First, create a sample JSON file for stats to process
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
            # Write sample data
            tf.write('{"pid":1234,"cmd":["sleep","1"],"exe":"/bin/sleep","t0_ms":1600000000000}\n')
            tf.write('{"ts_ms":1600000001000,"parent":{"ts_ms":1600000001000,"cpu_usage":1.0,"mem_rss_kb":1000,"mem_vms_kb":2000,"disk_read_bytes":100,"disk_write_bytes":200,"net_rx_bytes":300,"net_tx_bytes":400,"thread_count":1,"uptime_secs":1},"children":[],"aggregated":{"ts_ms":1600000001000,"cpu_usage":1.0,"mem_rss_kb":1000,"mem_vms_kb":2000,"disk_read_bytes":100,"disk_write_bytes":200,"net_rx_bytes":300,"net_tx_bytes":400,"thread_count":1,"process_count":1,"uptime_secs":1}}\n')
            sample_file = tf.name
        
        try:
            # Test the stats command
            cmd = [self.binary, "stats", sample_file]
            result = subprocess.run(cmd, 
                                capture_output=True, text=True, timeout=2)
            
            # Should succeed
            self.assertEqual(result.returncode, 0, f"Stats command failed with error: {result.stderr}")
            self.assertIn("STATISTICS", result.stdout)
            
            # Test the stats command with --json
            cmd = [self.binary, "--json", "stats", sample_file]
            result = subprocess.run(cmd, 
                                capture_output=True, text=True, timeout=2)
            
            # Should succeed and output valid JSON
            self.assertEqual(result.returncode, 0)
            try:
                data = json.loads(result.stdout)
                self.assertIn("total_time_secs", data)
                self.assertIn("sample_count", data)
            except json.JSONDecodeError:
                self.fail("Stats command with --json did not produce valid JSON")
                
        finally:
            # Clean up
            try:
                os.unlink(sample_file)
            except:
                pass
                
    def test_quiet_flag(self):
        """Test that --quiet flag significantly reduces stdout output"""
        # Clean up any existing out.json
        try:
            os.unlink("out.json")
        except:
            pass
            
        # First run without quiet to get baseline
        cmd = [self.binary, "--nodump", "run", "sleep", "0.5"]
        normal_result = subprocess.run(cmd,
                              capture_output=True, text=True, timeout=2)
                              
        # Now run with quiet flag
        cmd = [self.binary, "--quiet", "--nodump", "run", "sleep", "0.5"]
        quiet_result = subprocess.run(cmd,
                              capture_output=True, text=True, timeout=2)
        
        # Should succeed
        self.assertEqual(quiet_result.returncode, 0)
        
        # Quiet output should be significantly less than normal output
        self.assertLess(len(quiet_result.stdout), len(normal_result.stdout) / 2,
                       f"Quiet mode didn't reduce output enough: {len(quiet_result.stdout)} vs {len(normal_result.stdout)}")
        
        # Should not create out.json with --nodump
        self.assertFalse(os.path.exists("out.json"), "out.json was created despite --nodump flag")
        
        # In quiet mode, we don't explicitly test JSON output
        # Instead we focus on ensuring --quiet reduces output compared to normal mode
        # and that it doesn't create out.json with --nodump
                
        # Now test with default output file creation
        try:
            os.unlink("out.json")  # Make sure it doesn't exist from before
        except:
            pass
            
        # Run with quiet but without nodump
        cmd = [self.binary, "--quiet", "run", "sleep", "0.5"] 
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        
        # Should create out.json by default
        self.assertTrue(os.path.exists("out.json"), "Default output file out.json was not created")
        
    def test_nodump_flag(self):
        """Test that --nodump flag prevents creation of default out.json file"""
        # First remove any existing out.json
        try:
            os.unlink("out.json")
        except:
            pass
            
        cmd = [self.binary, "--nodump", "run", "sleep", "0.5"]
        result = subprocess.run(cmd, 
                              capture_output=True, text=True, timeout=2)
        
        # Should succeed
        self.assertEqual(result.returncode, 0)
        
        # Should not create out.json
        self.assertFalse(os.path.exists("out.json"), "out.json was created despite --nodump flag")
        
    def test_custom_output_file(self):
        """Test that --out flag works with a custom file"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
            custom_out = tf.name
            
        try:
            # First remove the file
            os.unlink(custom_out)
            
            cmd = [self.binary, "--out", custom_out, "run", "sleep", "0.5"]
            result = subprocess.run(cmd, 
                                  capture_output=True, text=True, timeout=2)
            
            # Should succeed
            self.assertEqual(result.returncode, 0)
            
            # Custom file should exist and contain JSON
            self.assertTrue(os.path.exists(custom_out), f"Custom output file {custom_out} was not created")
            
            # Check if it contains valid JSON
            with open(custom_out, 'r') as f:
                lines = f.readlines()
                self.assertTrue(len(lines) > 0, "Output file is empty")
                
                # Parse each line as JSON and look for metadata or metrics
                found_metadata = False
                found_metrics = False
                
                for line in lines:
                    data = json.loads(line.strip())
                    if "pid" in data:
                        found_metadata = True
                    if "ts_ms" in data:
                        found_metrics = True
                
                # Either metadata or metrics should be present
                self.assertTrue(found_metadata or found_metrics, 
                               f"File doesn't contain valid metadata or metrics: {lines}")
                
        finally:
            # Clean up
            try:
                os.unlink(custom_out)
            except:
                pass

if __name__ == "__main__":
    unittest.main()
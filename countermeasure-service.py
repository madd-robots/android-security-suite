#!/usr/bin/env python3
# countermeasure_service.py
# Implements various security countermeasures against surveillance

import os
import time
import json
import sys
import random
import logging
import subprocess
import threading
from datetime import datetime
import socket
import re

# Configure paths
BASE_DIR = "/data/data/com.termux/files/home/security_framework"
CONFIG_DIR = f"{BASE_DIR}/config"
LOG_DIR = f"{BASE_DIR}/logs"
COUNTERMEASURE_CONFIG = f"{CONFIG_DIR}/countermeasures.json"
LLM_COUNTERMEASURE_CONFIG = f"{CONFIG_DIR}/llm_countermeasures.json"

# Create directories
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/countermeasure.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("CountermeasureService")

class CountermeasureService:
    def __init__(self):
        self.countermeasures = self._load_countermeasures()
        self.active_countermeasures = {}
        self.stop_event = threading.Event()
        
        # Supported countermeasure types
        self.countermeasure_handlers = {
            "fake_location": self._deploy_fake_location,
            "sensor_flooding": self._deploy_sensor_flooding,
            "network_noise": self._deploy_network_noise,
            "preemptive_kill": self._deploy_preemptive_kill,
            "service_blocker": self._deploy_service_blocker,
            "network_block": self._deploy_network_block,
            "service_isolation": self._deploy_service_isolation,
            "app_launch_hook": self._deploy_app_launch_hook,
            "screen_state_hook": self._deploy_screen_state_hook
        }
        
        logger.info("Countermeasure Service initialized")
    
    def _load_countermeasures(self):
        """Load countermeasures from configuration files"""
        countermeasures = []
        
        # Load main countermeasures
        if os.path.exists(COUNTERMEASURE_CONFIG):
            try:
                with open(COUNTERMEASURE_CONFIG, "r") as f:
                    cm = json.load(f)
                    countermeasures.extend(cm)
                logger.info(f"Loaded {len(cm)} countermeasures from main config")
            except Exception as e:
                logger.error(f"Error loading main countermeasures: {e}")
        
        # Load LLM-generated countermeasures
        if os.path.exists(LLM_COUNTERMEASURE_CONFIG):
            try:
                with open(LLM_COUNTERMEASURE_CONFIG, "r") as f:
                    cm = json.load(f)
                    countermeasures.extend(cm)
                logger.info(f"Loaded {len(cm)} countermeasures from LLM config")
            except Exception as e:
                logger.error(f"Error loading LLM countermeasures: {e}")
        
        # Create default countermeasures if none exist
        if not countermeasures:
            logger.info("Creating default countermeasures")
            countermeasures = [
                {
                    "type": "fake_location",
                    "enabled": True,
                    "params": {
                        "latitude": 0.0,
                        "longitude": 0.0,
                        "accuracy": 1000,
                        "interval": 300
                    },
                    "description": "Deploy fake location to confuse tracking"
                },
                {
                    "type": "sensor_flooding",
                    "enabled": True,
                    "params": {
                        "sensors": ["accelerometer", "gyroscope"],
                        "interval": 60
                    },
                    "description": "Flood sensors with random data"
                },
                {
                    "type": "network_noise",
                    "enabled": True,
                    "params": {
                        "domains": ["example.com", "example.org", "example.net"],
                        "interval": 600
                    },
                    "description": "Generate network noise to confuse telemetry"
                }
            ]
            
            # Save default countermeasures
            try:
                with open(COUNTERMEASURE_CONFIG, "w") as f:
                    json.dump(countermeasures, f, indent=2)
            except Exception as e:
                logger.error(f"Error saving default countermeasures: {e}")
        
        return countermeasures
    
    def _save_countermeasures(self):
        """Save current countermeasures to configuration file"""
        try:
            with open(COUNTERMEASURE_CONFIG, "w") as f:
                json.dump(self.countermeasures, f, indent=2)
            logger.info(f"Saved {len(self.countermeasures)} countermeasures to config")
        except Exception as e:
            logger.error(f"Error saving countermeasures: {e}")
    
    def deploy_countermeasures(self):
        """Deploy all enabled countermeasures"""
        logger.info("Deploying all enabled countermeasures")
        
        for cm in self.countermeasures:
            if cm.get("enabled", False):
                self._deploy_countermeasure(cm)
    
    def _deploy_countermeasure(self, countermeasure):
        """Deploy a single countermeasure"""
        cm_type = countermeasure.get("type")
        cm_id = f"{cm_type}_{countermeasure.get('service', 'global')}"
        
        if cm_type not in self.countermeasure_handlers:
            logger.warning(f"Unknown countermeasure type: {cm_type}")
            return False
        
        # Stop existing countermeasure of this type if running
        if cm_id in self.active_countermeasures:
            self._stop_countermeasure(cm_id)
        
        logger.info(f"Deploying countermeasure: {cm_type}")
        
        # Deploy the countermeasure
        handler = self.countermeasure_handlers[cm_type]
        
        # Start the countermeasure in a separate thread
        thread = threading.Thread(
            target=handler,
            args=(countermeasure, cm_id),
            daemon=True
        )
        thread.start()
        
        # Track the active countermeasure
        self.active_countermeasures[cm_id] = {
            "thread": thread,
            "stop_flag": threading.Event(),
            "countermeasure": countermeasure
        }
        
        return True
    
    def _stop_countermeasure(self, cm_id):
        """Stop a running countermeasure"""
        if cm_id in self.active_countermeasures:
            logger.info(f"Stopping countermeasure: {cm_id}")
            
            # Signal the countermeasure to stop
            self.active_countermeasures[cm_id]["stop_flag"].set()
            
            # Wait for thread to finish (with timeout)
            self.active_countermeasures[cm_id]["thread"].join(timeout=5)
            
            # Remove from active countermeasures
            del self.active_countermeasures[cm_id]
            
            return True
        
        return False
    
    def _deploy_fake_location(self, cm, cm_id):
        """Deploy fake location countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        params = cm.get("params", {})
        
        interval = params.get("interval", 300)
        lat = params.get("latitude", 0.0)
        lon = params.get("longitude", 0.0)
        
        logger.info(f"Starting fake location deployment (lat={lat}, lon={lon}, interval={interval}s)")
        
        while not stop_flag.is_set():
            try:
                # Try using Termux API if available
                if self._has_command("termux-location"):
                    # Request fake location
                    logger.debug("Setting fake location via Termux API")
                    subprocess.run(
                        ["termux-location", "-p", "network"],
                        check=False,
                        capture_output=True
                    )
                
                # Try using ADB if available
                if self._has_command("adb"):
                    # Set mock location via ADB
                    logger.debug("Setting fake location via ADB")
                    subprocess.run(
                        ["adb", "shell", "am", "broadcast", "-a", "com.android.intent.action.SET_MOCK_LOCATION",
                         "--ei", "latitude", str(int(lat * 1e6)), 
                         "--ei", "longitude", str(int(lon * 1e6))],
                        check=False,
                        capture_output=True
                    )
                    
                    # Enable mock locations in developer options
                    subprocess.run(
                        ["adb", "shell", "settings", "put", "secure", "mock_location", "1"],
                        check=False,
                        capture_output=True
                    )
                
                # Randomize location slightly each time
                lat += random.uniform(-0.01, 0.01)
                lon += random.uniform(-0.01, 0.01)
                
                logger.debug(f"Deployed fake location: {lat}, {lon}")
            except Exception as e:
                logger.error(f"Error in fake location countermeasure: {e}")
            
            # Wait for next interval or until stopped
            if stop_flag.wait(timeout=interval):
                break
        
        logger.info("Fake location countermeasure stopped")
    
    def _deploy_sensor_flooding(self, cm, cm_id):
        """Deploy sensor flooding countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        params = cm.get("params", {})
        
        interval = params.get("interval", 60)
        sensors = params.get("sensors", ["accelerometer", "gyroscope"])
        
        logger.info(f"Starting sensor flooding for {sensors}")
        
        while not stop_flag.is_set():
            try:
                if self._has_command("termux-sensor"):
                    # Use Termux API to flood sensors with random data
                    for sensor in sensors:
                        # Get current sensor data and then cancel
                        subprocess.run(
                            ["termux-sensor", "-s", sensor, "-d", "100", "-n", "1"],
                            check=False,
                            capture_output=True
                        )
                        time.sleep(0.2)
                        subprocess.run(
                            ["termux-sensor", "-c"],
                            check=False,
                            capture_output=True
                        )
                
                logger.debug(f"Deployed sensor flooding for {sensors}")
            except Exception as e:
                logger.error(f"Error in sensor flooding countermeasure: {e}")
            
            # Wait for next interval or until stopped
            if stop_flag.wait(timeout=interval):
                break
        
        logger.info("Sensor flooding countermeasure stopped")
    
    def _deploy_network_noise(self, cm, cm_id):
        """Deploy network noise countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        params = cm.get("params", {})
        
        interval = params.get("interval", 600)
        domains = params.get("domains", ["example.com", "example.org", "example.net"])
        
        logger.info(f"Starting network noise generation")
        
        while not stop_flag.is_set():
            try:
                # Generate fake DNS requests
                for _ in range(random.randint(3, 8)):
                    domain = random.choice(domains)
                    subdomain = f"{self._random_string(8)}.{domain}"
                    
                    try:
                        # Just resolve the domain
                        socket.gethostbyname(subdomain)
                    except:
                        pass
                
                # Generate fake HTTP requests (without actually connecting)
                for _ in range(random.randint(2, 5)):
                    domain = random.choice(domains)
                    path = f"/{self._random_string(6)}/{self._random_string(8)}.html"
                    
                    # Create socket but don't actually send data
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    try:
                        s.connect((domain, 80))
                    except:
                        pass
                    finally:
                        s.close()
                
                logger.debug(f"Generated network noise")
            except Exception as e:
                logger.error(f"Error in network noise countermeasure: {e}")
            
            # Wait for next interval or until stopped
            if stop_flag.wait(timeout=interval):
                break
        
        logger.info("Network noise countermeasure stopped")
    
    def _deploy_preemptive_kill(self, cm, cm_id):
        """Deploy preemptive kill countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        service = cm.get("service")
        interval = cm.get("interval", 30)
        
        if not service:
            logger.error("Preemptive kill missing service name")
            return
        
        logger.info(f"Starting preemptive kill for {service} every {interval}s")
        
        while not stop_flag.is_set():
            try:
                # Find and kill the service
                output = subprocess.check_output(
                    ["ps", "-ef"], 
                    text=True
                )
                
                for line in output.splitlines():
                    if service in line and "grep" not in line:
                        # Extract PID
                        pid = re.findall(r'\s+(\d+)\s+', line)
                        if pid:
                            pid = pid[0]
                            # Kill the process
                            subprocess.run(
                                ["kill", "-9", pid],
                                check=False,
                                capture_output=True
                            )
                            logger.debug(f"Preemptively killed {service} (PID: {pid})")
                
            except Exception as e:
                logger.error(f"Error in preemptive kill countermeasure: {e}")
            
            # Wait for next interval or until stopped
            if stop_flag.wait(timeout=interval):
                break
        
        logger.info(f"Preemptive kill countermeasure for {service} stopped")
    
    def _deploy_service_blocker(self, cm, cm_id):
        """Deploy service blocker countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        service = cm.get("service")
        
        if not service:
            logger.error("Service blocker missing service name")
            return
        
        logger.info(f"Starting service blocker for {service}")
        
        # Extract possible package name from service
        package_name = None
        if "." in service:
            package_parts = service.split(".")
            if len(package_parts) >= 2:
                # Guess package name from service name
                package_name = ".".join(package_parts[:-1])
        
        if package_name:
            try:
                if self._has_command("adb"):
                    # Try to disable the package if possible
                    logger.info(f"Attempting to disable package {package_name}")
                    subprocess.run(
                        ["adb", "shell", "pm", "disable-user", "--user", "0", package_name],
                        check=False,
                        capture_output=True
                    )
                    
                    # Force stop the package
                    subprocess.run(
                        ["adb", "shell", "am", "force-stop", package_name],
                        check=False,
                        capture_output=True
                    )
                    
                    logger.info(f"Disabled package {package_name}")
            except Exception as e:
                logger.error(f"Error disabling package: {e}")
        
        # Monitor for service launches continuously
        logger.info(f"Monitoring for {service} launches")
        while not stop_flag.is_set():
            try:
                # Find and kill the service continuously
                output = subprocess.check_output(
                    ["ps", "-ef"], 
                    text=True
                )
                
                for line in output.splitlines():
                    if service in line and "grep" not in line:
                        # Extract PID
                        pid = re.findall(r'\s+(\d+)\s+', line)
                        if pid:
                            pid = pid[0]
                            # Kill the process
                            subprocess.run(
                                ["kill", "-9", pid],
                                check=False,
                                capture_output=True
                            )
                            logger.debug(f"Blocked service {service} (PID: {pid})")
                
            except Exception as e:
                logger.error(f"Error in service blocker countermeasure: {e}")
            
            # Short interval for monitoring
            if stop_flag.wait(timeout=5):
                break
        
        logger.info(f"Service blocker for {service} stopped")
    
    def _deploy_network_block(self, cm, cm_id):
        """Deploy network blocking countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        service = cm.get("service")
        
        if not service:
            logger.error("Network block missing service name")
            return
        
        logger.info(f"Starting network blocking for {service}")
        
        # Extract possible package name
        package_name = None
        if "." in service:
            package_parts = service.split(".")
            if len(package_parts) >= 2:
                package_name = ".".join(package_parts[:-1])
        
        if self._has_command("iptables") and package_name:
            try:
                # Try to block network access for the app using iptables
                uid = self._get_app_uid(package_name)
                if uid:
                    # Block outbound traffic
                    subprocess.run(
                        ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"],
                        check=False,
                        capture_output=True
                    )
                    logger.info(f"Blocked network traffic for {package_name} (UID: {uid})")
            except Exception as e:
                logger.error(f"Error setting up network block: {e}")
        
        # Monitor network connections continuously
        while not stop_flag.is_set():
            try:
                # Check for network connections from the service
                if self._has_command("netstat"):
                    output = subprocess.check_output(
                        ["netstat", "-tunap"], 
                        text=True
                    )
                    
                    for line in output.splitlines():
                        if service in line:
                            # Extract PID if possible
                            pid_match = re.search(r'(\d+)/\S+', line)
                            if pid_match:
                                pid = pid_match.group(1)
                                
                                # Kill the connection
                                subprocess.run(
                                    ["kill", "-9", pid],
                                    check=False,
                                    capture_output=True
                                )
                                logger.debug(f"Terminated network connection from {service} (PID: {pid})")
            
            except Exception as e:
                logger.error(f"Error in network blocking monitor: {e}")
            
            # Short interval for monitoring
            if stop_flag.wait(timeout=5):
                break
        
        # Clean up iptables rules if needed
        if self._has_command("iptables") and package_name:
            try:
                uid = self._get_app_uid(package_name)
                if uid:
                    # Remove the blocking rule
                    subprocess.run(
                        ["iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"],
                        check=False,
                        capture_output=True
                    )
                    logger.info(f"Removed network block for {package_name}")
            except Exception as e:
                logger.error(f"Error removing network block: {e}")
        
        logger.info(f"Network blocking for {service} stopped")
    
    def _deploy_service_isolation(self, cm, cm_id):
        """Deploy service isolation countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        service = cm.get("service")
        
        if not service:
            logger.error("Service isolation missing service name")
            return
        
        logger.info(f"Starting service isolation for {service}")
        
        # This is a complex operation that requires root or special permissions
        # For now, we'll implement a simplified version that kills the service
        # and blocks its network access
        
        # Extract possible package name
        package_name = None
        if "." in service:
            package_parts = service.split(".")
            if len(package_parts) >= 2:
                package_name = ".".join(package_parts[:-1])
        
        if package_name and self._has_command("adb"):
            try:
                # Force stop the package
                subprocess.run(
                    ["adb", "shell", "am", "force-stop", package_name],
                    check=False,
                    capture_output=True
                )
                
                # Clear app data
                subprocess.run(
                    ["adb", "shell", "pm", "clear", package_name],
                    check=False,
                    capture_output=True
                )
                
                logger.info(f"Isolated package {package_name}")
            except Exception as e:
                logger.error(f"Error isolating package: {e}")
        
        # Monitor for service activity continuously
        while not stop_flag.is_set():
            try:
                # Find and kill the service
                output = subprocess.check_output(
                    ["ps", "-ef"], 
                    text=True
                )
                
                for line in output.splitlines():
                    if service in line and "grep" not in line:
                        # Extract PID
                        pid = re.findall(r'\s+(\d+)\s+', line)
                        if pid:
                            pid = pid[0]
                            # Kill the process
                            subprocess.run(
                                ["kill", "-9", pid],
                                check=False,
                                capture_output=True
                            )
                            logger.debug(f"Terminated isolated service {service} (PID: {pid})")
            
            except Exception as e:
                logger.error(f"Error in service isolation monitoring: {e}")
            
            # Short interval for monitoring
            if stop_flag.wait(timeout=5):
                break
        
        logger.info(f"Service isolation for {service} stopped")
    
    def _deploy_app_launch_hook(self, cm, cm_id):
        """Deploy app launch hook countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        service = cm.get("service")
        
        if not service:
            logger.error("App launch hook missing service name")
            return
        
        logger.info(f"Starting app launch hook for {service}")
        
        # This requires special permissions to monitor app launches
        # For now, we'll use a simplified approach using logcat if available
        
        if self._has_command("logcat"):
            try:
                # Start logcat process to monitor app launches
                logcat_proc = subprocess.Popen(
                    ["logcat", "-b", "events", "-v", "raw", "-s", "am_activity_launch_time"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Monitor logcat output for app launches
                while not stop_flag.is_set():
                    line = logcat_proc.stdout.readline().strip()
                    if line:
                        # Check if our target service might be starting
                        if "ActivityManager" in line and "start" in line:
                            logger.debug(f"Detected activity start: {line}")
                            
                            # Immediately check and kill the service
                            self._find_and_kill_service(service)
                
                # Clean up logcat process
                logcat_proc.terminate()
                try:
                    logcat_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logcat_proc.kill()
            
            except Exception as e:
                logger.error(f"Error in app launch hook: {e}")
        else:
            # Fallback to periodic checking
            logger.warning("Logcat not available, falling back to periodic checking")
            
            while not stop_flag.is_set():
                self._find_and_kill_service(service)
                
                # Check periodically
                if stop_flag.wait(timeout=5):
                    break
        
        logger.info(f"App launch hook for {service} stopped")
    
    def _deploy_screen_state_hook(self, cm, cm_id):
        """Deploy screen state hook countermeasure"""
        stop_flag = self.active_countermeasures[cm_id]["stop_flag"]
        service = cm.get("service")
        
        if not service:
            logger.error("Screen state hook missing service name")
            return
        
        logger.info(f"Starting screen state hook for {service}")
        
        # This requires special permissions to monitor screen state
        # For now, we'll use a simplified approach using logcat if available
        
        if self._has_command("logcat"):
            try:
                # Start logcat process to monitor screen state changes
                logcat_proc = subprocess.Popen(
                    ["logcat", "-b", "events", "-v", "raw", "-s", "android.intent.action.SCREEN_ON", 
                     "android.intent.action.SCREEN_OFF", "android.intent.action.USER_PRESENT"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Monitor logcat output for screen state changes
                while not stop_flag.is_set():
                    line = logcat_proc.stdout.readline().strip()
                    if line:
                        # Check for screen state change events
                        if "SCREEN_ON" in line or "USER_PRESENT" in line:
                            logger.debug(f"Detected screen state change: {line}")
                            
                            # Wait a moment for services to start
                            time.sleep(1)
                            
                            # Check multiple times after screen change
                            for _ in range(5):
                                self._find_and_kill_service(service)
                                time.sleep(1)
                
                # Clean up logcat process
                logcat_proc.terminate()
                try:
                    logcat_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logcat_proc.kill()
            
            except Exception as e:
                logger.error(f"Error in screen state hook: {e}")
        else:
            # Fallback to periodic checking
            logger.warning("Logcat not available, falling back to periodic checking")
            
            while not stop_flag.is_set():
                self._find_and_kill_service(service)
                
                # Check periodically
                if stop_flag.wait(timeout=5):
                    break
        
        logger.info(f"Screen state hook for {service} stopped")
    
    def _find_and_kill_service(self, service):
        """Helper function to find and kill a service"""
        try:
            output = subprocess.check_output(
                ["ps", "-ef"], 
                text=True
            )
            
            for line in output.splitlines():
                if service in line and "grep" not in line:
                    # Extract PID
                    pid = re.findall(r'\s+(\d+)\s+', line)
                    if pid:
                        pid = pid[0]
                        # Kill the process
                        subprocess.run(
                            ["kill", "-9", pid],
                            check=False,
                            capture_output=True
                        )
                        logger.debug(f"Killed service {service} (PID: {pid})")
                        return True
        
        except Exception as e:
            logger.error(f"Error finding and killing service: {e}")
        
        return False
    
    def _get_app_uid(self, package_name):
        """Get the UID for an app package"""
        try:
            # Try using 'dumpsys' command
            if self._has_command("dumpsys"):
                output = subprocess.check_output(
                    ["dumpsys", "package", package_name], 
                    text=True
                )
                
                # Extract UID
                uid_match = re.search(r'userId=(\d+)', output)
                if uid_match:
                    return uid_match.group(1)
            
            # Try using 'pm' via ADB
            if self._has_command("adb"):
                output = subprocess.check_output(
                    ["adb", "shell", "pm", "list", "packages", "-U", package_name],
                    text=True
                )
                
                # Extract UID
                uid_match = re.search(r'uid:(\d+)', output)
                if uid_match:
                    return uid_match.group(1)
        
        except Exception as e:
            logger.error(f"Error getting app UID: {e}")
        
        return None
    
    def _has_command(self, cmd):
        """Check if a command is available"""
        return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    
    def _random_string(self, length):
        """Generate a random string"""
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def check_for_updates(self):
        """Check for updated countermeasures"""
        try:
            # Check if countermeasures config has been modified
            if os.path.exists(COUNTERMEASURE_CONFIG):
                current_mtime = os.path.getmtime(COUNTERMEASURE_CONFIG)
                
                if hasattr(self, 'last_config_mtime') and current_mtime > self.last_config_mtime:
                    logger.info("Countermeasure configuration has been updated")
                    
                    # Reload countermeasures
                    self.countermeasures = self._load_countermeasures()
                    
                    # Restart active countermeasures
                    self.stop_all_countermeasures()
                    self.deploy_countermeasures()
                
                # Update last modification time
                self.last_config_mtime = current_mtime
            
            # Check LLM countermeasures as well
            if os.path.exists(LLM_COUNTERMEASURE_CONFIG):
                current_mtime = os.path.getmtime(LLM_COUNTERMEASURE_CONFIG)
                
                if hasattr(self, 'last_llm_config_mtime') and current_mtime > self.last_llm_config_mtime:
                    logger.info("LLM countermeasure configuration has been updated")
                    
                    # Reload countermeasures
                    self.countermeasures = self._load_countermeasures()
                    
                    # Restart active countermeasures
                    self.stop_all_countermeasures()
                    self.deploy_countermeasures()
                
                # Update last modification time
                self.last_llm_config_mtime = current_mtime
        
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
    
    def stop_all_countermeasures(self):
        """Stop all active countermeasures"""
        logger.info("Stopping all active countermeasures")
        
        # Make a copy of the keys, as we'll modify the dictionary
        cm_ids = list(self.active_countermeasures.keys())
        
        for cm_id in cm_ids:
            self._stop_countermeasure(cm_id)
    
    def run(self):
        """Run the countermeasure service"""
        logger.info("Starting Countermeasure Service")
        
        # Initial configuration
        if os.path.exists(COUNTERMEASURE_CONFIG):
            self.last_config_mtime = os.path.getmtime(COUNTERMEASURE_CONFIG)
        
        if os.path.exists(LLM_COUNTERMEASURE_CONFIG):
            self.last_llm_config_mtime = os.path.getmtime(LLM_COUNTERMEASURE_CONFIG)
        
        # Deploy initial countermeasures
        self.deploy_countermeasures()
        
        try:
            # Main service loop
            while not self.stop_event.is_set():
                # Check for configuration updates
                self.check_for_updates()
                
                # Wait for a while before checking again
                self.stop_event.wait(timeout=30)
                
        except KeyboardInterrupt:
            logger.info("Countermeasure Service stopped by user")
        finally:
            # Clean up
            self.stop_all_countermeasures()
            logger.info("Countermeasure Service stopped")

if __name__ == "__main__":
    service = CountermeasureService()
    service.run()
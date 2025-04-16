#!/usr/bin/env python3
# adaptive_defense_companion.py
# AI-powered companion for security watchdog
# Analyzes logs to detect patterns and generate countermeasures

import os
import re
import time
import json
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Configure paths
BASE_DIR = "/data/data/com.termux/files/home/security_framework"
LOG_PATH = "/data/data/com.termux/files/home/service_watchdog.log"
CONFIG_DIR = f"{BASE_DIR}/config"
PATTERN_CONFIG = f"{CONFIG_DIR}/patterns.json"
COUNTERMEASURE_CONFIG = f"{CONFIG_DIR}/countermeasures.json"
LOG_DIR = f"{BASE_DIR}/logs"
AI_LOG = f"{LOG_DIR}/ai_companion.log"

# Ensure directories exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class AdaptiveDefenseCompanion:
    def __init__(self, log_path=LOG_PATH):
        self.log_path = log_path
        self.known_patterns = self._load_patterns()
        self.kill_history = defaultdict(list)
        self.resurrection_patterns = defaultdict(list)
        self.trigger_correlations = defaultdict(int)
        self.last_processed_line = 0
        self.log("AI Companion initialized")
        
    def log(self, message):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        with open(AI_LOG, "a") as f:
            f.write(log_message + "\n")
    
    def _load_patterns(self):
        """Load known patterns from configuration"""
        try:
            if os.path.exists(PATTERN_CONFIG):
                with open(PATTERN_CONFIG, "r") as f:
                    return json.load(f)
            else:
                # Create default pattern config if it doesn't exist
                default_patterns = {
                    "services": [
                        "GoogleLocationService",
                        "GoogleLocationManagerService",
                        "OfflineBeaconService_Persistent",
                        "LocationPersistentService",
                        "CrisisAlertsPersistentService"
                    ],
                    "patterns": [
                        ".*Location.*Service",
                        ".*Beacon.*Service",
                        ".*Persistent.*",
                        ".*KLMS.*",
                        ".*Tracking.*"
                    ]
                }
                with open(PATTERN_CONFIG, "w") as f:
                    json.dump(default_patterns, f, indent=2)
                return default_patterns
        except Exception as e:
            self.log(f"Error loading patterns: {e}")
            return {"services": [], "patterns": []}
    
    def _save_patterns(self):
        """Save updated patterns to configuration"""
        try:
            with open(PATTERN_CONFIG, "w") as f:
                json.dump(self.known_patterns, f, indent=2)
            self.log(f"Saved updated patterns configuration with {len(self.known_patterns['patterns'])} patterns")
        except Exception as e:
            self.log(f"Error saving patterns: {e}")
    
    def analyze_logs(self):
        """Process new log entries and extract patterns"""
        if not os.path.exists(self.log_path):
            self.log(f"Log file {self.log_path} not found")
            return
            
        try:
            with open(self.log_path, "r") as f:
                lines = f.readlines()
            
            # Process only new lines
            new_lines = lines[self.last_processed_line:]
            self.last_processed_line = len(lines)
            
            if not new_lines:
                return
                
            self.log(f"Processing {len(new_lines)} new log entries")
                
            # Extract kill events
            for line in new_lines:
                if "[KILL]" in line:
                    # Extract service name and timestamp
                    match = re.search(r'\[(.*?)\] \[KILL\] Terminated (.*?) \(PID:', line)
                    if match:
                        timestamp_str, service = match.groups()
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                            self.kill_history[service].append(timestamp)
                        except Exception as e:
                            self.log(f"Error parsing timestamp: {e}")
                
                elif "[PATTERN]" in line:
                    # Extract resurrection patterns
                    match = re.search(r'Service (.*?) resurrected after (\d+) seconds', line)
                    if match:
                        service, seconds = match.groups()
                        self.resurrection_patterns[service].append(int(seconds))
                
                elif "[TRIGGER]" in line:
                    # Extract trigger correlations
                    match = re.search(r'Service (.*?) resurrection correlated with (.*?)$', line)
                    if match:
                        service, trigger = match.groups()
                        self.trigger_correlations[f"{service}_{trigger}"] += 1
            
            self.log(f"Found {sum(len(kills) for kills in self.kill_history.values())} kill events, " + 
                     f"{sum(len(res) for res in self.resurrection_patterns.values())} resurrection patterns, " +
                     f"{len(self.trigger_correlations)} trigger correlations")
                
        except Exception as e:
            self.log(f"Error analyzing logs: {e}")
    
    def detect_new_patterns(self):
        """Detect new service name patterns based on observed kills"""
        # Extract all service names from kill history
        all_services = list(self.kill_history.keys())
        
        if len(all_services) < 3:  # Need sufficient data
            self.log("Not enough service data for pattern detection")
            return []
        
        # Find common character sequences in service names
        new_patterns = []
        try:
            # Find common substrings
            for service in all_services:
                # Only look at services with at least one significant substring
                if len(service) >= 5:
                    # Try different substring lengths for pattern detection
                    for i in range(3, min(len(service), 10)):
                        for j in range(len(service) - i + 1):
                            substring = service[j:j+i]
                            # Check if this is a meaningful substring (not just digits or common words)
                            if re.search(r'[a-zA-Z]', substring) and not substring.isdigit():
                                # Check how many services contain this substring
                                matching_services = [s for s in all_services if substring in s]
                                if len(matching_services) >= 2:  # At least 2 services match
                                    # Check if this pattern is new
                                    pattern = f".*{re.escape(substring)}.*"
                                    if pattern not in self.known_patterns["patterns"]:
                                        new_patterns.append(pattern)
            
            # Deduplicate patterns
            new_patterns = list(set(new_patterns))
            
            self.log(f"Detected {len(new_patterns)} new patterns")
            return new_patterns
        except Exception as e:
            self.log(f"Error in pattern detection: {e}")
            return []
    
    def generate_countermeasures(self):
        """Generate adaptive countermeasures based on observed patterns"""
        countermeasures = []
        
        try:
            # Analyze resurrection timing patterns
            for service, times in self.resurrection_patterns.items():
                if len(times) >= 3:
                    avg_time = sum(times) / len(times)
                    # If service consistently resurrects at a specific interval
                    time_variance = sum((t - avg_time) ** 2 for t in times) / len(times)
                    if time_variance < 25:  # Low variance indicates consistent pattern
                        countermeasures.append({
                            "type": "preemptive_kill",
                            "service": service,
                            "interval": max(1, int(avg_time) - 2),  # Kill slightly before resurrection
                            "description": f"Preemptively kill {service} every {max(1, int(avg_time) - 2)} seconds"
                        })
            
            # Analyze trigger correlations
            for key, count in self.trigger_correlations.items():
                if count >= 3:  # Strong correlation
                    service, trigger = key.split('_', 1)
                    if trigger == "screen_state_change":
                        countermeasures.append({
                            "type": "screen_state_hook",
                            "service": service,
                            "description": f"Monitor and kill {service} immediately after screen state changes"
                        })
                    elif trigger == "app_launch":
                        countermeasures.append({
                            "type": "app_launch_hook",
                            "service": service,
                            "description": f"Monitor and kill {service} immediately after app launches"
                        })
            
            self.log(f"Generated {len(countermeasures)} new countermeasures")
            return countermeasures
        except Exception as e:
            self.log(f"Error generating countermeasures: {e}")
            return []
    
    def update_watchdog_configuration(self):
        """Update the watchdog configuration with new patterns and countermeasures"""
        try:
            # Detect new patterns
            new_patterns = self.detect_new_patterns()
            if new_patterns:
                self.known_patterns["patterns"].extend(new_patterns)
                self._save_patterns()
                
                # Generate pattern update file for the watchdog to pick up
                with open(f"{CONFIG_DIR}/new_patterns.txt", "w") as f:
                    for pattern in new_patterns:
                        f.write(f"{pattern}\n")
                self.log(f"Saved {len(new_patterns)} new patterns to {CONFIG_DIR}/new_patterns.txt")
                
            # Generate and deploy new countermeasures
            countermeasures = self.generate_countermeasures()
            if countermeasures:
                # Read existing countermeasures
                existing_cm = []
                if os.path.exists(COUNTERMEASURE_CONFIG):
                    try:
                        with open(COUNTERMEASURE_CONFIG, "r") as f:
                            existing_cm = json.load(f)
                    except:
                        existing_cm = []
                
                # Merge with new countermeasures (avoiding duplicates)
                existing_services = set()
                for cm in existing_cm:
                    if "service" in cm:
                        existing_services.add(cm["service"])
                
                # Add only new countermeasures
                for cm in countermeasures:
                    if "service" not in cm or cm["service"] not in existing_services:
                        existing_cm.append(cm)
                        if "service" in cm:
                            existing_services.add(cm["service"])
                
                # Save updated countermeasures
                with open(COUNTERMEASURE_CONFIG, "w") as f:
                    json.dump(existing_cm, f, indent=2)
                self.log(f"Updated countermeasures configuration with {len(existing_cm)} total countermeasures")
        except Exception as e:
            self.log(f"Error updating watchdog configuration: {e}")
    
    def notify_user(self, message):
        """Send a notification to the user"""
        try:
            subprocess.run(["termux-notification", "--title", "Security AI Alert", "--content", message], 
                          check=True, capture_output=True)
            self.log(f"Notification sent: {message}")
        except Exception as e:
            self.log(f"Error sending notification: {e}")
    
    def run_continuous(self, interval=300):
        """Run the companion process continuously"""
        self.log(f"Starting Adaptive Defense Companion with analysis interval of {interval} seconds")
        
        while True:
            try:
                self.analyze_logs()
                self.update_watchdog_configuration()
                time.sleep(interval)
            except KeyboardInterrupt:
                self.log("AI Companion stopped by user")
                break
            except Exception as e:
                self.log(f"Error in companion process: {e}")
                time.sleep(60)  # Error backoff

if __name__ == "__main__":
    print("Starting Adaptive Defense Companion...")
    companion = AdaptiveDefenseCompanion()
    companion.run_continuous()
#!/usr/bin/env python3
# security_llm_supervisor.py
# Lightweight LLM for security log analysis and adaptive defense

import os
import time
import json
import re
import random
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, Counter

# Configure paths
BASE_DIR = "/data/data/com.termux/files/home/security_framework"
LOG_PATH = "/data/data/com.termux/files/home/service_watchdog.log"
LOGCAT_PATH = "/data/data/com.termux/files/home/logcat_suspicious.log"
CONFIG_DIR = f"{BASE_DIR}/config"
MODEL_DIR = f"{BASE_DIR}/llm/model"
LOG_DIR = f"{BASE_DIR}/logs"
LLM_LOG = f"{LOG_DIR}/llm_supervisor.log"

# Create directories
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class LightweightSecurityLLM:
    """
    A lightweight pattern-based 'LLM' for security analysis
    
    Note: This is not a true machine learning model but uses
    statistical and pattern-based approaches for log analysis.
    It can be later replaced with a true LLM when resources permit.
    """
    
    def __init__(self):
        self.log_files = [LOG_PATH, LOGCAT_PATH]
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.feature_weights = self._load_feature_weights()
        self.known_threats = set()
        self.labeled_data = []
        
        # For tracking processed log entries
        self.last_processed_lines = {path: 0 for path in self.log_files}
        
        # Counters and statistical data
        self.service_kill_counts = Counter()
        self.resurrection_times = defaultdict(list)
        self.process_stats = defaultdict(lambda: {"kill_count": 0, "avg_lifetime": 0})
        
        # Initialize log
        self.log("Security LLM Supervisor initialized")

    def log(self, message):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        with open(LLM_LOG, "a") as f:
            f.write(log_message + "\n")
    
    def _load_suspicious_patterns(self):
        """Load or create suspicious patterns for detection"""
        pattern_file = f"{CONFIG_DIR}/suspicious_patterns.json"
        
        if os.path.exists(pattern_file):
            try:
                with open(pattern_file, "r") as f:
                    patterns = json.load(f)
                self.log(f"Loaded {len(patterns)} suspicious patterns")
                return patterns
            except Exception as e:
                self.log(f"Error loading patterns: {e}")
        
        # Default patterns
        patterns = [
            {
                "name": "Location Tracking",
                "pattern": r"(?i)(location|gps|geofence|tracking)",
                "severity": 0.8
            },
            {
                "name": "Data Collection",
                "pattern": r"(?i)(analytics|metrics|telemetry|collect|report)",
                "severity": 0.7
            },
            {
                "name": "Network Activity",
                "pattern": r"(?i)(connect|socket|https?|api|upload|send)",
                "severity": 0.6
            },
            {
                "name": "Persistent Services",
                "pattern": r"(?i)(persistent|resurrect|restart|respawn)",
                "severity": 0.9
            },
            {
                "name": "Surveillance",
                "pattern": r"(?i)(monitor|surveillance|spy|watch|record)",
                "severity": 0.9
            },
            {
                "name": "Knox Agent",
                "pattern": r"(?i)(knox|klms|samsung|agent)",
                "severity": 0.8
            }
        ]
        
        # Save default patterns
        try:
            with open(pattern_file, "w") as f:
                json.dump(patterns, f, indent=2)
        except Exception as e:
            self.log(f"Error saving default patterns: {e}")
            
        return patterns
    
    def _load_feature_weights(self):
        """Load or create feature weights for scoring"""
        weights_file = f"{CONFIG_DIR}/feature_weights.json"
        
        if os.path.exists(weights_file):
            try:
                with open(weights_file, "r") as f:
                    weights = json.load(f)
                self.log(f"Loaded feature weights")
                return weights
            except Exception as e:
                self.log(f"Error loading feature weights: {e}")
        
        # Default weights
        weights = {
            "pattern_match": 0.4,
            "resurrection_frequency": 0.25,
            "kill_count": 0.2,
            "network_activity": 0.15
        }
        
        # Save default weights
        try:
            with open(weights_file, "w") as f:
                json.dump(weights, f, indent=2)
        except Exception as e:
            self.log(f"Error saving default weights: {e}")
            
        return weights
    
    def process_logs(self):
        """Process new log entries"""
        for log_path in self.log_files:
            if not os.path.exists(log_path):
                continue
                
            try:
                with open(log_path, "r") as f:
                    lines = f.readlines()
                
                # Process only new lines
                new_lines = lines[self.last_processed_lines[log_path]:]
                self.last_processed_lines[log_path] = len(lines)
                
                if not new_lines:
                    continue
                    
                self.log(f"Processing {len(new_lines)} new lines from {log_path}")
                
                # Extract information from logs
                for line in new_lines:
                    self._process_log_line(line)
                    
            except Exception as e:
                self.log(f"Error processing log {log_path}: {e}")
    
    def _process_log_line(self, line):
        """Process a single log line to extract security information"""
        # Extract kill events
        if "[KILL]" in line:
            match = re.search(r'\[KILL\] Terminated (.*?) \(PID: (\d+)\)', line)
            if match:
                service, pid = match.groups()
                self.service_kill_counts[service] += 1
                self.process_stats[service]["kill_count"] += 1
        
        # Extract resurrection patterns
        elif "[PATTERN]" in line:
            match = re.search(r'Service (.*?) resurrected after (\d+) seconds', line)
            if match:
                service, seconds = match.groups()
                self.resurrection_times[service].append(int(seconds))
        
        # Save suspicious entries for training
        score = self._score_log_entry(line)
        if score > 0.7:  # High suspicion
            self.labeled_data.append({
                "text": line,
                "score": score
            })
    
    def _score_log_entry(self, log_entry):
        """Score a log entry for suspiciousness based on patterns"""
        score = 0.0
        
        # Check for pattern matches
        for pattern_def in self.suspicious_patterns:
            if re.search(pattern_def["pattern"], log_entry):
                score += pattern_def["severity"] * self.feature_weights["pattern_match"]
        
        # Add additional scoring based on extracted info
        # This would be more sophisticated in a real ML model
        
        return min(1.0, score)  # Cap at 1.0
    
    def analyze_service_behavior(self):
        """Analyze service behavior patterns"""
        suspicious_services = []
        
        # Check resurrection patterns
        for service, times in self.resurrection_times.items():
            if len(times) >= 3:
                avg_time = sum(times) / len(times)
                
                # Check for consistent resurrection time (indicating scheduled tasks)
                time_variance = sum((t - avg_time) ** 2 for t in times) / len(times)
                
                if time_variance < 25:  # Low variance = suspicious pattern
                    suspicious_score = min(1.0, 0.5 + (len(times) / 10) + (self.service_kill_counts[service] / 20))
                    suspicious_services.append({
                        "service": service,
                        "score": suspicious_score,
                        "reason": f"Consistent resurrection every ~{avg_time:.1f} seconds ({len(times)} times)",
                        "type": "resurrection_pattern"
                    })
        
        # Check frequency of kills
        for service, count in self.service_kill_counts.items():
            if count >= 5:  # Killed multiple times
                suspicious_score = min(1.0, 0.4 + (count / 20))
                suspicious_services.append({
                    "service": service,
                    "score": suspicious_score,
                    "reason": f"Frequently killed service ({count} times)",
                    "type": "frequent_kill"
                })
        
        if suspicious_services:
            self.log(f"Found {len(suspicious_services)} suspicious services")
            
            # Sort by suspicion score
            suspicious_services.sort(key=lambda x: x["score"], reverse=True)
            
            # Report top threats
            for threat in suspicious_services[:5]:  # Top 5
                threat_id = f"{threat['service']}_{threat['type']}"
                if threat_id not in self.known_threats:
                    self.known_threats.add(threat_id)
                    self.log(f"Threat detected: {threat['service']} - {threat['reason']} (Score: {threat['score']:.2f})")
                    # Notify the user of new threats
                    self._notify_user(f"Threat detected: {threat['service']} - {threat['reason']}")
        
        return suspicious_services
    
    def _notify_user(self, message):
        """Send notification to the user"""
        try:
            subprocess.run(["termux-notification", "--title", "Security LLM Alert", "--content", message],
                          check=True, capture_output=True)
        except Exception as e:
            self.log(f"Error sending notification: {e}")
    
    def generate_countermeasures(self, suspicious_services):
        """Generate countermeasures based on threat analysis"""
        if not suspicious_services:
            return []
            
        countermeasures = []
        
        # Map threat types to countermeasure strategies
        strategy_map = {
            "resurrection_pattern": self._gen_resurrection_countermeasures,
            "frequent_kill": self._gen_frequent_kill_countermeasures
        }
        
        # Generate countermeasures for each threat
        for threat in suspicious_services:
            if threat["score"] >= 0.7 and threat["type"] in strategy_map:
                cm_func = strategy_map[threat["type"]]
                new_cms = cm_func(threat)
                if new_cms:
                    countermeasures.extend(new_cms)
        
        if countermeasures:
            self.log(f"Generated {len(countermeasures)} countermeasures")
            
            # Save countermeasures for the watchdog
            try:
                cm_file = f"{CONFIG_DIR}/llm_countermeasures.json"
                
                # Read existing countermeasures
                existing = []
                if os.path.exists(cm_file):
                    try:
                        with open(cm_file, "r") as f:
                            existing = json.load(f)
                    except:
                        existing = []
                
                # Add new unique countermeasures
                existing_ids = {f"{cm.get('type')}_{cm.get('service', '')}" for cm in existing}
                
                for cm in countermeasures:
                    cm_id = f"{cm.get('type')}_{cm.get('service', '')}"
                    if cm_id not in existing_ids:
                        existing.append(cm)
                        existing_ids.add(cm_id)
                
                # Save updated countermeasures
                with open(cm_file, "w") as f:
                    json.dump(existing, f, indent=2)
            except Exception as e:
                self.log(f"Error saving countermeasures: {e}")
        
        return countermeasures
    
    def _gen_resurrection_countermeasures(self, threat):
        """Generate countermeasures for resurrection patterns"""
        service = threat["service"]
        
        # Extract resurrection time pattern
        if service in self.resurrection_times and len(self.resurrection_times[service]) >= 3:
            avg_time = sum(self.resurrection_times[service]) / len(self.resurrection_times[service])
            
            return [
                {
                    "type": "preemptive_kill",
                    "service": service,
                    "interval": max(1, int(avg_time) - 2),
                    "description": f"Preemptively kill {service} every {max(1, int(avg_time) - 2)} seconds"
                },
                {
                    "type": "service_blocker",
                    "service": service,
                    "description": f"Block {service} startup triggers"
                }
            ]
        
        return []
    
    def _gen_frequent_kill_countermeasures(self, threat):
        """Generate countermeasures for frequently killed services"""
        service = threat["service"]
        
        return [
            {
                "type": "service_isolation",
                "service": service,
                "description": f"Isolate {service} from system resources"
            },
            {
                "type": "network_block",
                "service": service,
                "description": f"Block network access for {service}"
            }
        ]
    
    def update_threat_model(self):
        """Update internal threat model based on observed data"""
        # In a full LLM, this would retrain the model
        # In our lightweight version, we update weights and patterns
        
        # Adjust feature weights based on effectiveness
        if len(self.labeled_data) > 20:
            # Simple adjustment - in a real system this would use backpropagation
            self.feature_weights["pattern_match"] *= 1.05
            self.feature_weights["resurrection_frequency"] *= 1.1
            
            # Normalize weights
            total = sum(self.feature_weights.values())
            for key in self.feature_weights:
                self.feature_weights[key] /= total
                
            # Save updated weights
            try:
                with open(f"{CONFIG_DIR}/feature_weights.json", "w") as f:
                    json.dump(self.feature_weights, f, indent=2)
                self.log("Updated feature weights based on observations")
            except Exception as e:
                self.log(f"Error saving updated weights: {e}")
            
            # Clear training data
            self.labeled_data = []
    
    def generate_new_detection_rules(self):
        """Generate new detection rules based on observations"""
        # Extract common patterns from observed threats
        new_patterns = []
        
        # Look at all service names
        service_names = list(self.service_kill_counts.keys())
        
        if len(service_names) >= 5:  # Need sufficient data
            # Find common substrings in service names
            for i in range(len(service_names)):
                for j in range(i + 1, len(service_names)):
                    s1, s2 = service_names[i], service_names[j]
                    
                    # Find longest common substring
                    common = self._find_longest_common_substring(s1, s2)
                    
                    if common and len(common) >= 4:  # Minimum meaningful length
                        pattern_exists = any(common in p["pattern"] for p in self.suspicious_patterns)
                        
                        if not pattern_exists:
                            new_patterns.append({
                                "name": f"New Service Pattern",
                                "pattern": f"(?i){re.escape(common)}",
                                "severity": 0.6,  # Start with moderate severity
                                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            })
        
        if new_patterns:
            # Deduplicate patterns
            seen_patterns = set()
            unique_patterns = []
            
            for p in new_patterns:
                if p["pattern"] not in seen_patterns:
                    seen_patterns.add(p["pattern"])
                    unique_patterns.append(p)
            
            if unique_patterns:
                self.log(f"Generated {len(unique_patterns)} new detection patterns")
                
                # Add to existing patterns
                self.suspicious_patterns.extend(unique_patterns)
                
                # Save updated patterns
                try:
                    with open(f"{CONFIG_DIR}/suspicious_patterns.json", "w") as f:
                        json.dump(self.suspicious_patterns, f, indent=2)
                except Exception as e:
                    self.log(f"Error saving new patterns: {e}")
    
    def _find_longest_common_substring(self, s1, s2):
        """Find the longest common substring between two strings"""
        if not s1 or not s2:
            return ""
            
        # Dynamic programming approach
        dp = [[0 for _ in range(len(s2) + 1)] for _ in range(len(s1) + 1)]
        max_length = 0
        end_pos = 0
        
        for i in range(1, len(s1) + 1):
            for j in range(1, len(s2) + 1):
                if s1[i - 1] == s2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                    if dp[i][j] > max_length:
                        max_length = dp[i][j]
                        end_pos = i
        
        return s1[end_pos - max_length:end_pos]
    
    def run(self, log_interval=300, model_update_interval=3600):
        """Run the LLM supervisor continuously"""
        self.log(f"Starting Security LLM Supervisor with analysis interval of {log_interval} seconds")
        
        last_model_update = time.time()
        
        while True:
            try:
                # Process logs
                self.process_logs()
                
                # Analyze service behavior
                suspicious_services = self.analyze_service_behavior()
                
                # Generate countermeasures
                self.generate_countermeasures(suspicious_services)
                
                # Check if it's time to update the model
                current_time = time.time()
                if current_time - last_model_update > model_update_interval:
                    self.update_threat_model()
                    self.generate_new_detection_rules()
                    last_model_update = current_time
                
                time.sleep(log_interval)
            except KeyboardInterrupt:
                self.log("LLM Supervisor stopped by user")
                break
            except Exception as e:
                self.log(f"Error in LLM supervisor: {e}")
                time.sleep(60)  # Error backoff

if __name__ == "__main__":
    print("Starting Lightweight Security LLM Supervisor...")
    llm = LightweightSecurityLLM()
    llm.run()
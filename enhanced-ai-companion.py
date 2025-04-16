#!/usr/bin/env python3
# adaptive_defense_companion.py
# AI-powered companion for security watchdog
# Analyzes logs to detect patterns and generate countermeasures

import os
import re
import time
import json
import math
import hashlib
import datetime
import threading
import subprocess
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Any, Optional, Union

# Try to import Levenshtein distance if available, use fallback if not
try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # Simple Levenshtein distance implementation as fallback
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

class Config:
    """Configuration manager with default fallbacks and environment variable support"""
    
    def __init__(self, config_file: Optional[str] = None):
        # Default configurations
        self.defaults = {
            "BASE_DIR": os.environ.get("SECURITY_FRAMEWORK_DIR", 
                                      "/data/data/com.termux/files/home/security_framework"),
            "LOG_PATH": os.environ.get("WATCHDOG_LOG_PATH", 
                                       "/data/data/com.termux/files/home/service_watchdog.log"),
            "LOGCAT_PATH": os.environ.get("LOGCAT_LOG_PATH", 
                                          "/data/data/com.termux/files/home/logcat_suspicious.log"),
            "CONFIG_DIR": os.environ.get("CONFIG_DIR", None),  # Will be derived if None
            "PATTERN_CONFIG": os.environ.get("PATTERN_CONFIG", None),  # Will be derived if None
            "COUNTERMEASURE_CONFIG": os.environ.get("COUNTERMEASURE_CONFIG", None),  # Will be derived if None
            "LOG_DIR": os.environ.get("LOG_DIR", None),  # Will be derived if None
            "AI_LOG": os.environ.get("AI_LOG", None),  # Will be derived if None
            "ANALYSIS_INTERVAL": int(os.environ.get("ANALYSIS_INTERVAL", "300")),
            "MAX_LOG_SIZE": int(os.environ.get("MAX_LOG_SIZE", "10000000")),  # 10MB
            "COUNTERMEASURE_TTL": int(os.environ.get("COUNTERMEASURE_TTL", "86400")),  # 24 hours
            "PATTERN_SIMILARITY_THRESHOLD": float(os.environ.get("PATTERN_SIMILARITY_THRESHOLD", "0.75")),
            "MIN_PATTERN_LENGTH": int(os.environ.get("MIN_PATTERN_LENGTH", "4")),
            "MAX_PATTERN_LENGTH": int(os.environ.get("MAX_PATTERN_LENGTH", "20")),
            "EFFECTIVENESS_THRESHOLD": float(os.environ.get("EFFECTIVENESS_THRESHOLD", "0.5")),
            "DEBUG": os.environ.get("DEBUG", "0") == "1"
        }
        
        # Load config from file if provided
        self.config = self.defaults.copy()
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    self.config.update(file_config)
            except Exception as e:
                print(f"Error loading config file: {e}")
        
        # Derive dependent paths if not explicitly set
        if not self.config["CONFIG_DIR"]:
            self.config["CONFIG_DIR"] = os.path.join(self.config["BASE_DIR"], "config")
        
        if not self.config["PATTERN_CONFIG"]:
            self.config["PATTERN_CONFIG"] = os.path.join(self.config["CONFIG_DIR"], "patterns.json")
        
        if not self.config["COUNTERMEASURE_CONFIG"]:
            self.config["COUNTERMEASURE_CONFIG"] = os.path.join(self.config["CONFIG_DIR"], "countermeasures.json")
        
        if not self.config["LOG_DIR"]:
            self.config["LOG_DIR"] = os.path.join(self.config["BASE_DIR"], "logs")
        
        if not self.config["AI_LOG"]:
            self.config["AI_LOG"] = os.path.join(self.config["LOG_DIR"], "ai_companion.log")
        
        # Create necessary directories
        os.makedirs(self.config["CONFIG_DIR"], exist_ok=True)
        os.makedirs(self.config["LOG_DIR"], exist_ok=True)
    
    def __getitem__(self, key: str) -> Any:
        """Access config values like a dictionary"""
        return self.config.get(key, self.defaults.get(key))
    
    def save(self, config_file: str) -> bool:
        """Save current configuration to file"""
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False


class LogParser:
    """Efficient log parser that tracks file positions and handles rotation"""
    
    def __init__(self, file_path: str, max_size: int = 10000000):
        self.file_path = file_path
        self.max_size = max_size
        self.last_position = 0
        self.last_inode = self._get_inode()
        self.last_size = self._get_size()
    
    def _get_inode(self) -> int:
        """Get the inode of the log file to detect rotation"""
        try:
            return os.stat(self.file_path).st_ino
        except (FileNotFoundError, OSError):
            return -1
    
    def _get_size(self) -> int:
        """Get the current size of the log file"""
        try:
            return os.path.getsize(self.file_path)
        except (FileNotFoundError, OSError):
            return 0
    
    def _detect_rotation(self) -> bool:
        """Detect if the log file has been rotated"""
        current_inode = self._get_inode()
        if current_inode != self.last_inode:
            self.last_position = 0
            self.last_inode = current_inode
            self.last_size = self._get_size()
            return True
        return False
    
    def _detect_truncation(self) -> bool:
        """Detect if the log file has been truncated"""
        current_size = self._get_size()
        if current_size < self.last_size:
            self.last_position = 0
            self.last_size = current_size
            return True
        self.last_size = current_size
        return False
    
    def read_new_lines(self) -> List[str]:
        """Read only new lines from the log file using byte offsets"""
        if not os.path.exists(self.file_path):
            return []
        
        # Check for file rotation or truncation
        self._detect_rotation() or self._detect_truncation()
        
        try:
            with open(self.file_path, 'r') as f:
                # Seek to the last position
                f.seek(self.last_position)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update position
                self.last_position = f.tell()
                
                return new_lines
        except Exception as e:
            print(f"Error reading log file {self.file_path}: {e}")
            return []


class PatternManager:
    """Manages detection patterns with optimization and generalization"""
    
    def __init__(self, config: Config, logger):
        self.config = config
        self.logger = logger
        self.patterns = self._load_patterns()
        self.pattern_cache = {}  # Cache compiled regex patterns
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load patterns from configuration file with fallback to defaults"""
        pattern_file = self.config["PATTERN_CONFIG"]
        
        try:
            if os.path.exists(pattern_file):
                with open(pattern_file, "r") as f:
                    patterns = json.load(f)
                self.logger.log(f"Loaded {len(patterns.get('patterns', []))} patterns from configuration")
                return patterns
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
                    ],
                    "metadata": {
                        "last_updated": datetime.datetime.now().isoformat(),
                        "version": 1
                    }
                }
                
                # Save default patterns
                self._save_patterns(default_patterns)
                return default_patterns
        except Exception as e:
            self.logger.log(f"Error loading patterns: {e}")
            return {"services": [], "patterns": [], "metadata": {"version": 0}}
    
    def _save_patterns(self, patterns: Dict[str, Any]) -> bool:
        """Save patterns to configuration file"""
        pattern_file = self.config["PATTERN_CONFIG"]
        
        # Update metadata
        if "metadata" not in patterns:
            patterns["metadata"] = {}
        
        patterns["metadata"]["last_updated"] = datetime.datetime.now().isoformat()
        patterns["metadata"]["version"] = patterns["metadata"].get("version", 0) + 1
        
        try:
            with open(pattern_file, "w") as f:
                json.dump(patterns, f, indent=2)
            self.logger.log(f"Saved updated patterns configuration with {len(patterns.get('patterns', []))} patterns")
            return True
        except Exception as e:
            self.logger.log(f"Error saving patterns: {e}")
            return False
    
    def add_patterns(self, new_patterns: List[str]) -> int:
        """Add new patterns with deduplication and optimization"""
        if not new_patterns:
            return 0
        
        # Deduplicate patterns
        unique_patterns = []
        for pattern in new_patterns:
            # Skip if pattern already exists
            if pattern in self.patterns.get("patterns", []):
                continue
            
            # Skip if too similar to existing patterns
            if self._is_too_similar(pattern):
                continue
            
            unique_patterns.append(pattern)
        
        # Add unique patterns
        self.patterns.setdefault("patterns", []).extend(unique_patterns)
        
        # Save updated patterns
        if unique_patterns:
            self._save_patterns(self.patterns)
            
            # Clear pattern cache to force recompilation
            self.pattern_cache = {}
        
        return len(unique_patterns)
    
    def _is_too_similar(self, pattern: str) -> bool:
        """Check if a pattern is too similar to existing patterns"""
        # Extract the pattern core (without regex syntax)
        pattern_core = re.sub(r'[\.\*\+\?\[\]\(\)\{\}\|\^\$\\]', '', pattern)
        
        # Skip if pattern core is too short
        if len(pattern_core) < self.config["MIN_PATTERN_LENGTH"]:
            return True
        
        # Check for similarity with existing patterns
        for existing_pattern in self.patterns.get("patterns", []):
            existing_core = re.sub(r'[\.\*\+\?\[\]\(\)\{\}\|\^\$\\]', '', existing_pattern)
            
            # Skip if either pattern is a subset of the other
            if pattern_core in existing_core or existing_core in pattern_core:
                return True
            
            # Check Levenshtein distance for similarity
            if len(pattern_core) > 0 and len(existing_core) > 0:
                similarity = 1.0 - (levenshtein_distance(pattern_core, existing_core) / 
                                   max(len(pattern_core), len(existing_core)))
                
                if similarity > self.config["PATTERN_SIMILARITY_THRESHOLD"]:
                    return True
        
        return False
    
    def match_pattern(self, text: str) -> List[str]:
        """Match text against all patterns, returning matched patterns"""
        matched_patterns = []
        
        for pattern in self.patterns.get("patterns", []):
            try:
                # Use cached compiled regex if available
                if pattern not in self.pattern_cache:
                    self.pattern_cache[pattern] = re.compile(pattern)
                
                regex = self.pattern_cache[pattern]
                if regex.search(text):
                    matched_patterns.append(pattern)
            except Exception as e:
                self.logger.log(f"Error matching pattern '{pattern}': {e}")
                # Remove problematic pattern from cache
                self.pattern_cache.pop(pattern, None)
        
        return matched_patterns
    
    def generate_patterns_from_services(self, services: List[str]) -> List[str]:
        """Generate new patterns based on common substrings in service names"""
        if len(services) < 2:
            return []
        
        # Extract meaningful substrings (n-grams)
        ngrams = []
        for service in services:
            # Skip short service names
            if len(service) < self.config["MIN_PATTERN_LENGTH"]:
                continue
                
            # Generate character n-grams from service name
            for n in range(self.config["MIN_PATTERN_LENGTH"], 
                          min(self.config["MAX_PATTERN_LENGTH"], len(service) + 1)):
                for i in range(len(service) - n + 1):
                    substring = service[i:i+n]
                    # Skip if only digits or common words
                    if not re.search(r'[a-zA-Z]', substring) or substring.isdigit():
                        continue
                    ngrams.append(substring)
        
        # Count occurrences of each n-gram
        ngram_counts = Counter(ngrams)
        
        # Filter for n-grams that appear in multiple services
        common_ngrams = [ngram for ngram, count in ngram_counts.items() if count >= 2]
        
        # Convert to regex patterns with wildcards
        new_patterns = []
        for ngram in common_ngrams:
            # Escape special regex characters
            escaped_ngram = re.escape(ngram)
            new_pattern = f".*{escaped_ngram}.*"
            new_patterns.append(new_pattern)
        
        return new_patterns


class TriggerAnalyzer:
    """Analyzes and correlates service resurrection triggers"""
    
    def __init__(self, config: Config, logger):
        self.config = config
        self.logger = logger
        self.trigger_correlations = defaultdict(int)
        self.screen_state_changes = []
        self.network_changes = []
        self.usb_events = []
        self.bluetooth_events = []
        self.app_launches = []
        self.foreground_app_changes = []
    
    def record_event(self, event_type: str, timestamp: float, details: Dict[str, Any] = None) -> None:
        """Record a system event for correlation"""
        if details is None:
            details = {}
            
        event = {
            "timestamp": timestamp,
            "details": details
        }
        
        if event_type == "screen_state":
            self.screen_state_changes.append(event)
            # Keep only recent events (last 20)
            self.screen_state_changes = self.screen_state_changes[-20:]
        elif event_type == "network":
            self.network_changes.append(event)
            self.network_changes = self.network_changes[-20:]
        elif event_type == "usb":
            self.usb_events.append(event)
            self.usb_events = self.usb_events[-20:]
        elif event_type == "bluetooth":
            self.bluetooth_events.append(event)
            self.bluetooth_events = self.bluetooth_events[-20:]
        elif event_type == "app_launch":
            self.app_launches.append(event)
            self.app_launches = self.app_launches[-20:]
        elif event_type == "foreground_app":
            self.foreground_app_changes.append(event)
            self.foreground_app_changes = self.foreground_app_changes[-20:]
    
    def check_resurrection_triggers(self, service: str, resurrection_time: float) -> List[Dict[str, Any]]:
        """Check what might have triggered a service resurrection"""
        triggers = []
        time_window = 5.0  # seconds
        
        # Check if related to screen state changes
        for event in self.screen_state_changes:
            time_diff = abs(resurrection_time - event["timestamp"])
            if time_diff <= time_window:
                trigger = {
                    "type": "screen_state_change",
                    "service": service,
                    "time_diff": time_diff,
                    "details": event["details"]
                }
                triggers.append(trigger)
                self.trigger_correlations[f"{service}_screen_state_change"] += 1
        
        # Check if related to network activity
        for event in self.network_changes:
            time_diff = abs(resurrection_time - event["timestamp"])
            if time_diff <= time_window:
                trigger = {
                    "type": "network_change",
                    "service": service,
                    "time_diff": time_diff,
                    "details": event["details"]
                }
                triggers.append(trigger)
                self.trigger_correlations[f"{service}_network_change"] += 1
        
        # Check if related to USB events
        for event in self.usb_events:
            time_diff = abs(resurrection_time - event["timestamp"])
            if time_diff <= time_window:
                trigger = {
                    "type": "usb_event",
                    "service": service,
                    "time_diff": time_diff,
                    "details": event["details"]
                }
                triggers.append(trigger)
                self.trigger_correlations[f"{service}_usb_event"] += 1
        
        # Check if related to Bluetooth events
        for event in self.bluetooth_events:
            time_diff = abs(resurrection_time - event["timestamp"])
            if time_diff <= time_window:
                trigger = {
                    "type": "bluetooth_event",
                    "service": service,
                    "time_diff": time_diff,
                    "details": event["details"]
                }
                triggers.append(trigger)
                self.trigger_correlations[f"{service}_bluetooth_event"] += 1
        
        # Check if related to app launches
        for event in self.app_launches:
            time_diff = abs(resurrection_time - event["timestamp"])
            if time_diff <= time_window:
                trigger = {
                    "type": "app_launch",
                    "service": service,
                    "time_diff": time_diff,
                    "details": event["details"]
                }
                triggers.append(trigger)
                self.trigger_correlations[f"{service}_app_launch"] += 1
        
        # Check if related to foreground app changes
        for event in self.foreground_app_changes:
            time_diff = abs(resurrection_time - event["timestamp"])
            if time_diff <= time_window:
                trigger = {
                    "type": "foreground_app_change",
                    "service": service,
                    "time_diff": time_diff,
                    "details": event["details"]
                }
                triggers.append(trigger)
                self.trigger_correlations[f"{service}_foreground_app_change"] += 1
        
        # Sort triggers by time difference
        triggers.sort(key=lambda x: x["time_diff"])
        
        return triggers
    
    def get_strong_correlations(self, min_count: int = 3) -> List[Dict[str, Any]]:
        """Get strong trigger correlations for services"""
        strong_correlations = []
        
        for key, count in self.trigger_correlations.items():
            if count >= min_count:
                service, trigger_type = key.rsplit('_', 1)
                
                correlation = {
                    "service": service,
                    "trigger_type": trigger_type,
                    "count": count,
                    "confidence": min(1.0, count / 10.0)  # Scale confidence
                }
                
                strong_correlations.append(correlation)
        
        # Sort by confidence (highest first)
        strong_correlations.sort(key=lambda x: x["confidence"], reverse=True)
        
        return strong_correlations
    
    def extract_events_from_log(self, log_line: str) -> None:
        """Extract system events from log lines for correlation"""
        timestamp = time.time()
        
        try:
            # Extract timestamp from log line if available
            timestamp_match = re.search(r'\[([\d\-\: ]+)\]', log_line)
            if timestamp_match:
                try:
                    log_timestamp = datetime.datetime.strptime(
                        timestamp_match.group(1), 
                        "%Y-%m-%d %H:%M:%S"
                    ).timestamp()
                    timestamp = log_timestamp
                except:
                    pass  # Keep current timestamp on failure
            
            # Extract screen state changes
            if "mWakefulness=" in log_line:
                state = "unknown"
                if "Awake" in log_line:
                    state = "awake"
                elif "Asleep" in log_line:
                    state = "asleep"
                elif "Dozing" in log_line:
                    state = "dozing"
                
                self.record_event("screen_state", timestamp, {"state": state})
            
            # Extract network changes
            elif "NetworkInfo" in log_line or "ConnectivityService" in log_line:
                if "CONNECTED" in log_line:
                    self.record_event("network", timestamp, {"state": "connected"})
                elif "DISCONNECTED" in log_line:
                    self.record_event("network", timestamp, {"state": "disconnected"})
            
            # Extract USB events
            elif "UsbDeviceManager" in log_line or "USB" in log_line:
                if "attached" in log_line.lower():
                    self.record_event("usb", timestamp, {"state": "attached"})
                elif "detached" in log_line.lower():
                    self.record_event("usb", timestamp, {"state": "detached"})
            
            # Extract Bluetooth events
            elif "Bluetooth" in log_line or "BT_" in log_line:
                if "enabled" in log_line.lower():
                    self.record_event("bluetooth", timestamp, {"state": "enabled"})
                elif "disabled" in log_line.lower():
                    self.record_event("bluetooth", timestamp, {"state": "disabled"})
                elif "connected" in log_line.lower():
                    self.record_event("bluetooth", timestamp, {"state": "connected"})
                elif "disconnected" in log_line.lower():
                    self.record_event("bluetooth", timestamp, {"state": "disconnected"})
            
            # Extract app launches
            elif "ActivityManager" in log_line and "start" in log_line:
                # Try to extract package name
                package_match = re.search(r'cmp=([^\s/]+)', log_line)
                if package_match:
                    package = package_match.group(1)
                    self.record_event("app_launch", timestamp, {"package": package})
            
            # Extract foreground app changes
            elif "ActivityManager" in log_line and "Displayed" in log_line:
                # Try to extract package name
                package_match = re.search(r'([a-zA-Z0-9_.]+)/[a-zA-Z0-9_.]+', log_line)
                if package_match:
                    package = package_match.group(1)
                    self.record_event("foreground_app", timestamp, {"package": package})
        
        except Exception as e:
            # Silent failure on event extraction - not critical
            pass


class CountermeasureManager:
    """Manages countermeasures with TTL, feedback loop, and effectiveness tracking"""
    
    def __init__(self, config: Config, logger):
        self.config = config
        self.logger = logger
        self.countermeasures = self._load_countermeasures()
        self.effectiveness_metrics = self._load_effectiveness_metrics()
    
    def _load_countermeasures(self) -> List[Dict[str, Any]]:
        """Load countermeasures from configuration file"""
        cm_file = self.config["COUNTERMEASURE_CONFIG"]
        
        try:
            if os.path.exists(cm_file):
                with open(cm_file, "r") as f:
                    countermeasures = json.load(f)
                self.logger.log(f"Loaded {len(countermeasures)} countermeasures from configuration")
                return countermeasures
            else:
                return []
        except Exception as e:
            self.logger.log(f"Error loading countermeasures: {e}")
            return []
    
    def _save_countermeasures(self) -> bool:
        """Save countermeasures to configuration file"""
        cm_file = self.config["COUNTERMEASURE_CONFIG"]
        
        try:
            # Clean expired countermeasures before saving
            self._clean_expired_countermeasures()
            
            with open(cm_file, "w") as f:
                json.dump(self.countermeasures, f, indent=2)
            self.logger.log(f"Saved {len(self.countermeasures)} countermeasures to configuration")
            return True
        except Exception as e:
            self.logger.log(f"Error saving countermeasures: {e}")
            return False
    
    def _load_effectiveness_metrics(self) -> Dict[str, Any]:
        """Load effectiveness metrics from file"""
        metrics_file = os.path.join(self.config["CONFIG_DIR"], "effectiveness_metrics.json")
        
        try:
            if os.path.exists(metrics_file):
                with open(metrics_file, "r") as f:
                    metrics = json.load(f)
                return metrics
            else:
                return {"countermeasures": {}, "services": {}}
        except Exception as e:
            self.logger.log(f"Error loading effectiveness metrics: {e}")
            return {"countermeasures": {}, "services": {}}
    
    def _save_effectiveness_metrics(self) -> bool:
        """Save effectiveness metrics to file"""
        metrics_file = os.path.join(self.config["CONFIG_DIR"], "effectiveness_metrics.json")
        
        try:
            with open(metrics_file, "w") as f:
                json.dump(self.effectiveness_metrics, f, indent=2)
            return True
        except Exception as e:
            self.logger.log(f"Error saving effectiveness metrics: {e}")
            return False
    
    def _clean_expired_countermeasures(self) -> int:
        """Remove expired countermeasures"""
        now = time.time()
        original_count = len(self.countermeasures)
        
        # Filter out expired countermeasures
        active_countermeasures = []
        for cm in self.countermeasures:
            # Skip if expired
            if "expires_at" in cm and cm["expires_at"] < now:
                self.logger.log(f"Countermeasure expired: {cm.get('description', 'Unknown')}")
                continue
                
            # Skip if retry limit exceeded
            if "retry_count" in cm and "max_retries" in cm and cm["retry_count"] >= cm["max_retries"]:
                self.logger.log(f"Countermeasure retry limit exceeded: {cm.get('description', 'Unknown')}")
                continue
                
            active_countermeasures.append(cm)
        
        self.countermeasures = active_countermeasures
        return original_count - len(self.countermeasures)
    
    def add_countermeasure(self, countermeasure: Dict[str, Any]) -> bool:
        """Add a new countermeasure with TTL and tracking"""
        if not countermeasure:
            return False
        
        # Add TTL
        now = time.time()
        ttl = countermeasure.get("ttl", self.config["COUNTERMEASURE_TTL"])
        countermeasure["created_at"] = now
        countermeasure["expires_at"] = now + ttl
        
        # Add tracking information
        if "tracking" not in countermeasure:
            countermeasure["tracking"] = {
                "resurrections_before": 0,
                "resurrections_after": 0,
                "last_checked": now
            }
        
        # Add retry information
        if "retry_count" not in countermeasure:
            countermeasure["retry_count"] = 0
        if "max_retries" not in countermeasure:
            countermeasure["max_retries"] = 3
        
        # Generate a unique ID for the countermeasure if not present
        if "id" not in countermeasure:
            cm_type = countermeasure.get("type", "unknown")
            service = countermeasure.get("service", "global")
            cm_hash = hashlib.md5(f"{cm_type}_{service}_{now}".encode()).hexdigest()[:8]
            countermeasure["id"] = f"{cm_type}_{service}_{cm_hash}"
        
        # Check for duplicates
        for existing_cm in self.countermeasures:
            if self._is_duplicate_countermeasure(existing_cm, countermeasure):
                # Update existing countermeasure instead of adding a new one
                existing_cm["expires_at"] = now + ttl  # Extend TTL
                existing_cm["retry_count"] += 1  # Increment retry count
                self.logger.log(f"Updated existing countermeasure: {existing_cm.get('description', 'Unknown')}")
                self._save_countermeasures()
                return True
        
        # Add the new countermeasure
        self.countermeasures.append(countermeasure)
        self.logger.log(f"Added new countermeasure: {countermeasure.get('description', 'Unknown')}")
        
        # Save updated countermeasures
        self._save_countermeasures()
        return True
    
    def _is_duplicate_countermeasure(self, cm1: Dict[str, Any], cm2: Dict[str, Any]) -> bool:
        """Check if two countermeasures are duplicates"""
        # Check key fields
        if cm1.get("type") != cm2.get("type"):
            return False
        
        if cm1.get("service") != cm2.get("service"):
            return False
        
        # For specific countermeasure types, check additional fields
        cm_type = cm1.get("type")
        
        if cm_type == "preemptive_kill":
            return cm1.get("interval") == cm2.get("interval")
        
        elif cm_type in ["app_launch_hook", "screen_state_hook"]:
            return True  # These are considered duplicates if type and service match
        
        # Default comparison
        return False
    
    def generate_countermeasures(self, resurrection_patterns: Dict[str, List[int]], 
                                trigger_correlations: List[Dict[str, Any]],
                                threat_scores: Dict[str, float]) -> List[Dict[str, Any]]:
        """Generate countermeasures based on observed patterns and triggers"""
        new_countermeasures = []
        
        # Generate countermeasures for resurrection patterns
        for service, times in resurrection_patterns.items():
            if len(times) >= 3:
                avg_time = sum(times) / len(times)
                variance = sum((t - avg_time) ** 2 for t in times) / len(times)
                
                # If service consistently resurrects at a specific interval
                if variance < 25:  # Low variance indicates consistent pattern
                    # Get threat score for prioritization
                    threat_score = threat_scores.get(service, 0.5)
                    
                    cm = {
                        "type": "preemptive_kill",
                        "service": service,
                        "interval": max(1, int(avg_time) - 2),  # Kill slightly before resurrection
                        "description": f"Preemptively kill {service} every {max(1, int(avg_time) - 2)} seconds",
                        "severity": threat_score,
                        "ttl": self.config["COUNTERMEASURE_TTL"],
                        "max_retries": 3
                    }
                    
                    new_countermeasures.append(cm)
        
        # Generate countermeasures for trigger correlations
        for correlation in trigger_correlations:
            service = correlation.get("service")
            trigger_type = correlation.get("trigger_type")
            confidence = correlation.get("confidence", 0.0)
            
            # Only create countermeasures for high-confidence correlations
            if confidence < 0.7:
                continue
            
            # Get threat score for prioritization
            threat_score = threat_scores.get(service, 0.5)
            
            if trigger_type == "screen_state_change":
                cm = {
                    "type": "screen_state_hook",
                    "service": service,
                    "description": f"Monitor and kill {service} immediately after screen state changes",
                    "severity": threat_score,
                    "ttl": self.config["COUNTERMEASURE_TTL"],
                    "max_retries": 3
                }
                new_countermeasures.append(cm)
            
            elif trigger_type == "app_launch":
                cm = {
                    "type": "app_launch_hook",
                    "service": service,
                    "description": f"Monitor and kill {service} immediately after app launches",
                    "severity": threat_score,
                    "ttl": self.config["COUNTERMEASURE_TTL"],
                    "max_retries": 3
                }
                new_countermeasures.append(cm)
            
            elif trigger_type == "network_change":
                cm = {
                    "type": "network_hook",
                    "service": service,
                    "description": f"Monitor and kill {service} immediately after network changes",
                    "severity": threat_score,
                    "ttl": self.config["COUNTERMEASURE_TTL"],
                    "max_retries": 3
                }
                new_countermeasures.append(cm)
            
            elif trigger_type == "bluetooth_event":
                cm = {
                    "type": "bluetooth_hook",
                    "service": service,
                    "description": f"Monitor and kill {service} immediately after Bluetooth events",
                    "severity": threat_score,
                    "ttl": self.config["COUNTERMEASURE_TTL"],
                    "max_retries": 3
                }
                new_countermeasures.append(cm)
            
            elif trigger_type == "usb_event":
                cm = {
                    "type": "usb_hook",
                    "service": service,
                    "description": f"Monitor and kill {service} immediately after USB events",
                    "severity": threat_score,
                    "ttl": self.config["COUNTERMEASURE_TTL"],
                    "max_retries": 3
                }
                new_countermeasures.append(cm)
            
            elif trigger_type == "foreground_app_change":
                cm = {
                    "type": "foreground_app_hook",
                    "service": service,
                    "description": f"Monitor and kill {service} immediately after foreground app changes",
                    "severity": threat_score,
                    "ttl": self.config["COUNTERMEASURE_TTL"],
                    "max_retries": 3
                }
                new_countermeasures.append(cm)
        
        # Sort countermeasures by severity (highest first)
        new_countermeasures.sort(key=lambda x: x.get("severity", 0.0), reverse=True)
        
        return new_countermeasures
    
    def update_effectiveness(self, service: str, killed: bool) -> None:
        """Update effectiveness metrics for countermeasures"""
        now = time.time()
        
        # Update service metrics
        service_metrics = self.effectiveness_metrics.setdefault("services", {}).setdefault(service, {
            "total_kills": 0,
            "resurrections": 0,
            "last_kill": 0,
            "last_resurrection": 0
        })
        
        if killed:
            service_metrics["total_kills"] += 1
            service_metrics["last_kill"] = now
        else:
            # This is a resurrection event
            service_metrics["resurrections"] += 1
            service_metrics["last_resurrection"] = now
            
            # Update countermeasure effectiveness
            for cm in self.countermeasures:
                if cm.get("service") == service:
                    # Get tracking data
                    tracking = cm.setdefault("tracking", {
                        "resurrections_before": 0,
                        "resurrections_after": 0,
                        "last_checked": cm.get("created_at", now)
                    })
                    
                    # If this is the first check, establish baseline
                    if tracking["resurrections_before"] == 0 and tracking["resurrections_after"] == 0:
                        tracking["resurrections_before"] = service_metrics["resurrections"]
                    else:
                        tracking["resurrections_after"] += 1
                    
                    tracking["last_checked"] = now
                    
                    # Calculate effectiveness
                    if tracking["resurrections_before"] > 0:
                        effectiveness = self._calculate_effectiveness(tracking)
                        cm_metrics = self.effectiveness_metrics.setdefault("countermeasures", {}).setdefault(cm.get("id", "unknown"), {})
                        cm_metrics["effectiveness"] = effectiveness
                        cm_metrics["last_updated"] = now
        
        # Save metrics
        self._save_effectiveness_metrics()
    
    def _calculate_effectiveness(self, tracking: Dict[str, Any]) -> float:
        """Calculate countermeasure effectiveness"""
        resurrections_before = max(1, tracking.get("resurrections_before", 1))
        resurrections_after = tracking.get("resurrections_after", 0)
        created_at = tracking.get("created_at", time.time())
        last_checked = tracking.get("last_checked", time.time())
        
        # Calculate time periods
        time_active = last_checked - created_at
        time_before = 3600  # Assume 1 hour of prior history
        
        # Normalize resurrections by time
        if time_active > 0:
            resurrections_rate_after = resurrections_after / (time_active / 3600)  # Per hour
        else:
            resurrections_rate_after = 0
            
        resurrections_rate_before = resurrections_before / (time_before / 3600)  # Per hour
        
        # Calculate reduction in resurrection rate
        if resurrections_rate_before > 0:
            reduction = 1.0 - (resurrections_rate_after / resurrections_rate_before)
        else:
            reduction = 0.0
        
        # Clamp to [0, 1] range
        effectiveness = max(0.0, min(1.0, reduction))
        
        return effectiveness
    
    def get_ineffective_countermeasures(self, threshold: float = None) -> List[Dict[str, Any]]:
        """Get countermeasures that are not effective"""
        if threshold is None:
            threshold = self.config["EFFECTIVENESS_THRESHOLD"]
            
        ineffective = []
        
        for cm in self.countermeasures:
            cm_id = cm.get("id", "unknown")
            cm_metrics = self.effectiveness_metrics.get("countermeasures", {}).get(cm_id, {})
            effectiveness = cm_metrics.get("effectiveness", 0.0)
            
            # Check if countermeasure has been active long enough
            tracking = cm.get("tracking", {})
            created_at = cm.get("created_at", time.time())
            last_checked = tracking.get("last_checked", time.time())
            
            # Only consider countermeasures active for at least 30 minutes
            if last_checked - created_at < 1800:
                continue
                
            # Check if effectiveness is below threshold
            if effectiveness < threshold:
                ineffective.append(cm)
        
        return ineffective
    
    def escalate_countermeasure(self, countermeasure: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate an ineffective countermeasure to a more aggressive version"""
        cm_type = countermeasure.get("type")
        service = countermeasure.get("service")
        
        # Create escalated version
        escalated = countermeasure.copy()
        escalated.pop("id", None)  # Remove ID to generate a new one
        
        # Escalation strategies for different types
        if cm_type == "preemptive_kill":
            # Decrease interval for more frequent kills
            original_interval = escalated.get("interval", 30)
            escalated["interval"] = max(1, int(original_interval * 0.5))
            escalated["description"] = f"Escalated: Preemptively kill {service} every {escalated['interval']} seconds"
        
        elif cm_type in ["screen_state_hook", "app_launch_hook", "network_hook", "bluetooth_hook", "usb_hook", "foreground_app_hook"]:
            # Combine with preemptive kill
            escalated["type"] = "combined_strategy"
            escalated["components"] = [cm_type, "preemptive_kill"]
            escalated["interval"] = 15  # Aggressive interval
            escalated["description"] = f"Escalated: Combined strategy for {service} with 15s preemptive kills"
        
        # Set higher severity
        escalated["severity"] = min(1.0, countermeasure.get("severity", 0.5) + 0.2)
        
        # Reset tracking data
        escalated["tracking"] = {
            "resurrections_before": 0,
            "resurrections_after": 0,
            "last_checked": time.time()
        }
        
        # Increase TTL for longer testing period
        escalated["ttl"] = self.config["COUNTERMEASURE_TTL"] * 2
        
        return escalated


class ThreatScorer:
    """Assigns severity scores to services based on behavior patterns"""
    
    def __init__(self, config: Config, logger):
        self.config = config
        self.logger = logger
        self.service_stats = {}
        self.threat_scores = {}
    
    def update_service_stats(self, service: str, killed: bool, resurrection_time: Optional[int] = None) -> None:
        """Update statistics for a service"""
        # Initialize service stats if not exists
        if service not in self.service_stats:
            self.service_stats[service] = {
                "kill_count": 0,
                "resurrection_count": 0,
                "resurrection_times": [],
                "first_seen": time.time(),
                "last_seen": time.time(),
                "patterns_matched": set()
            }
        
        # Update stats
        self.service_stats[service]["last_seen"] = time.time()
        
        if killed:
            self.service_stats[service]["kill_count"] += 1
        else:
            self.service_stats[service]["resurrection_count"] += 1
            
            if resurrection_time is not None:
                self.service_stats[service]["resurrection_times"].append(resurrection_time)
                # Keep only the last 20 resurrection times
                self.service_stats[service]["resurrection_times"] = self.service_stats[service]["resurrection_times"][-20:]
    
    def add_pattern_match(self, service: str, pattern: str) -> None:
        """Add a pattern match for a service"""
        if service not in self.service_stats:
            self.update_service_stats(service, False)
            
        self.service_stats[service]["patterns_matched"].add(pattern)
    
    def calculate_threat_scores(self) -> Dict[str, float]:
        """Calculate threat scores for all services"""
        for service, stats in self.service_stats.items():
            # Skip services not seen recently (7 days)
            if time.time() - stats["last_seen"] > 604800:
                continue
                
            # Base score
            score = 0.5
            
            # Adjust based on resurrection frequency
            if stats["kill_count"] > 0:
                resurrection_ratio = stats["resurrection_count"] / stats["kill_count"]
                # Higher resurrection ratio means more persistent threat
                score += min(0.3, resurrection_ratio * 0.1)
            
            # Adjust based on resurrection speed
            if stats["resurrection_times"]:
                avg_time = sum(stats["resurrection_times"]) / len(stats["resurrection_times"])
                # Faster resurrection is more suspicious
                if avg_time < 10:
                    score += 0.15
                elif avg_time < 30:
                    score += 0.1
                elif avg_time < 60:
                    score += 0.05
            
            # Adjust based on pattern matches
            pattern_count = len(stats["patterns_matched"])
            score += min(0.2, pattern_count * 0.05)
            
            # Clamp to [0, 1] range
            self.threat_scores[service] = max(0.0, min(1.0, score))
        
        return self.threat_scores
    
    def get_high_priority_threats(self, threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Get high-priority threats based on threat scores"""
        high_priority = []
        
        for service, score in self.threat_scores.items():
            if score >= threshold:
                stats = self.service_stats[service]
                
                threat = {
                    "service": service,
                    "score": score,
                    "kill_count": stats["kill_count"],
                    "resurrection_count": stats["resurrection_count"],
                    "resurrection_speed": sum(stats["resurrection_times"]) / max(1, len(stats["resurrection_times"])),
                    "patterns_matched": list(stats["patterns_matched"]),
                    "last_seen": stats["last_seen"]
                }
                
                high_priority.append(threat)
        
        # Sort by score (highest first)
        high_priority.sort(key=lambda x: x["score"], reverse=True)
        
        return high_priority


class Logger:
    """Simple logger with timestamp and file output"""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Log a message with timestamp"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        try:
            with open(self.log_file, "a") as f:
                f.write(log_message + "\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")


class AdaptiveDefenseCompanion:
    """AI-powered companion for security watchdog"""
    
    def __init__(self, config_file: Optional[str] = None):
        # Initialize configuration
        self.config = Config(config_file)
        
        # Initialize logger
        self.logger = Logger(self.config["AI_LOG"])
        self.logger.log("AI Companion initialized")
        
        # Initialize components
        self.log_parsers = {
            self.config["LOG_PATH"]: LogParser(self.config["LOG_PATH"], self.config["MAX_LOG_SIZE"]),
            self.config["LOGCAT_PATH"]: LogParser(self.config["LOGCAT_PATH"], self.config["MAX_LOG_SIZE"])
        }
        
        self.pattern_manager = PatternManager(self.config, self.logger)
        self.trigger_analyzer = TriggerAnalyzer(self.config, self.logger)
        self.countermeasure_manager = CountermeasureManager(self.config, self.logger)
        self.threat_scorer = ThreatScorer(self.config, self.logger)
        
        # State tracking
        self.kill_history = defaultdict(list)
        self.resurrection_patterns = defaultdict(list)
        self.service_correlation = defaultdict(set)
    
    def analyze_logs(self) -> Tuple[int, int]:
        """Process log files to extract security events"""
        total_kill_events = 0
        total_resurrection_events = 0
        
        for log_path, parser in self.log_parsers.items():
            if not os.path.exists(log_path):
                continue
                
            try:
                new_lines = parser.read_new_lines()
                
                if not new_lines:
                    continue
                    
                self.logger.log(f"Processing {len(new_lines)} new lines from {log_path}")
                
                # Process each line
                for line in new_lines:
                    # Extract events for trigger correlation
                    self.trigger_analyzer.extract_events_from_log(line)
                    
                    # Extract kill events
                    if "[KILL]" in line:
                        try:
                            # Extract service name and timestamp
                            match = re.search(r'\[(.*?)\] \[KILL\] Terminated (.*?) \(PID:', line)
                            if match:
                                timestamp_str, service = match.groups()
                                timestamp = datetime.datetime.strptime(
                                    timestamp_str, "%Y-%m-%d %H:%M:%S"
                                ).timestamp()
                                
                                self.kill_history[service].append(timestamp)
                                
                                # Update threat scoring
                                self.threat_scorer.update_service_stats(service, True)
                                
                                # Update countermeasure effectiveness
                                self.countermeasure_manager.update_effectiveness(service, True)
                                
                                # Check for pattern matches
                                patterns_matched = self.pattern_manager.match_pattern(service)
                                for pattern in patterns_matched:
                                    self.threat_scorer.add_pattern_match(service, pattern)
                                
                                total_kill_events += 1
                        except Exception as e:
                            self.logger.log(f"Error parsing kill event: {e}", "ERROR")
                    
                    # Extract resurrection patterns
                    elif "[PATTERN]" in line:
                        try:
                            match = re.search(r'Service (.*?) resurrected after (\d+) seconds', line)
                            if match:
                                service, seconds = match.groups()
                                resurrection_time = int(seconds)
                                self.resurrection_patterns[service].append(resurrection_time)
                                
                                # Get timestamp
                                timestamp_match = re.search(r'\[(.*?)\]', line)
                                timestamp = time.time()
                                if timestamp_match:
                                    try:
                                        timestamp = datetime.datetime.strptime(
                                            timestamp_match.group(1), 
                                            "%Y-%m-%d %H:%M:%S"
                                        ).timestamp()
                                    except:
                                        pass
                                
                                # Check what triggered the resurrection
                                triggers = self.trigger_analyzer.check_resurrection_triggers(
                                    service, timestamp
                                )
                                
                                # Update threat scoring
                                self.threat_scorer.update_service_stats(service, False, resurrection_time)
                                
                                # Update countermeasure effectiveness
                                self.countermeasure_manager.update_effectiveness(service, False)
                                
                                # Log triggers
                                for trigger in triggers:
                                    trigger_type = trigger.get("type", "unknown")
                                    self.logger.log(
                                        f"Service {service} resurrection correlated with {trigger_type}", 
                                        "TRIGGER"
                                    )
                                
                                total_resurrection_events += 1
                        except Exception as e:
                            self.logger.log(f"Error parsing resurrection pattern: {e}", "ERROR")
                    
                    # Look for service correlations
                    elif "Parent:" in line:
                        try:
                            match = re.search(r'Terminated (.*?) \(PID:.*Parent:(.*?)(?:,|$)', line)
                            if match:
                                service, parent = match.groups()
                                parent = parent.strip()
                                if parent:
                                    self.service_correlation[service].add(parent)
                                    self.service_correlation[parent].add(service)
                        except Exception as e:
                            self.logger.log(f"Error parsing service correlation: {e}", "ERROR")
            
            except Exception as e:
                self.logger.log(f"Error processing log file {log_path}: {e}", "ERROR")
        
        return total_kill_events, total_resurrection_events
    
    def detect_new_patterns(self) -> List[str]:
        """Detect new service name patterns based on observed kills"""
        # Extract all service names from kill history
        all_services = list(self.kill_history.keys())
        
        if len(all_services) < 3:  # Need sufficient data
            return []
        
        # Generate patterns
        new_patterns = self.pattern_manager.generate_patterns_from_services(all_services)
        
        # Add new patterns
        if new_patterns:
            added_count = self.pattern_manager.add_patterns(new_patterns)
            self.logger.log(f"Added {added_count} new detection patterns")
        
        return new_patterns
    
    def generate_countermeasures(self) -> List[Dict[str, Any]]:
        """Generate adaptive countermeasures based on observed patterns"""
        # Calculate threat scores
        threat_scores = self.threat_scorer.calculate_threat_scores()
        
        # Get strong trigger correlations
        trigger_correlations = self.trigger_analyzer.get_strong_correlations()
        
        # Generate countermeasures
        new_countermeasures = self.countermeasure_manager.generate_countermeasures(
            self.resurrection_patterns,
            trigger_correlations,
            threat_scores
        )
        
        # Check for ineffective countermeasures and escalate them
        ineffective_countermeasures = self.countermeasure_manager.get_ineffective_countermeasures()
        
        for cm in ineffective_countermeasures:
            self.logger.log(f"Escalating ineffective countermeasure: {cm.get('description', 'Unknown')}")
            escalated_cm = self.countermeasure_manager.escalate_countermeasure(cm)
            new_countermeasures.append(escalated_cm)
        
        # Add countermeasures
        added_count = 0
        for cm in new_countermeasures:
            if self.countermeasure_manager.add_countermeasure(cm):
                added_count += 1
        
        if added_count > 0:
            self.logger.log(f"Added {added_count} new countermeasures")
        
        return new_countermeasures
    
    def report_high_threats(self) -> None:
        """Report high-priority threats for immediate attention"""
        high_threats = self.threat_scorer.get_high_priority_threats()
        
        if high_threats:
            self.logger.log(f"Detected {len(high_threats)} high-priority threats", "ALERT")
            
            for threat in high_threats:
                service = threat.get("service", "Unknown")
                score = threat.get("score", 0.0)
                
                self.logger.log(
                    f"High-priority threat: {service} (Score: {score:.2f})", 
                    "ALERT"
                )
                
                # Try to send notification to user
                self._notify_user(
                    f"High-priority threat detected: {service} (Score: {score:.2f})"
                )
    
    def _notify_user(self, message: str) -> bool:
        """Send a notification to the user"""
        try:
            subprocess.run(
                ["termux-notification", "--title", "Security AI Alert", "--content", message],
                check=True,
                capture_output=True
            )
            return True
        except Exception as e:
            self.logger.log(f"Error sending notification: {e}", "ERROR")
            return False
    
    def run_continuous(self, interval: int = None) -> None:
        """Run the companion process continuously"""
        if interval is None:
            interval = self.config["ANALYSIS_INTERVAL"]
            
        self.logger.log(f"Starting Adaptive Defense Companion with analysis interval of {interval} seconds")
        
        while True:
            try:
                # Analyze logs
                kill_events, resurrection_events = self.analyze_logs()
                
                if kill_events > 0 or resurrection_events > 0:
                    self.logger.log(f"Processed {kill_events} kill events and {resurrection_events} resurrection events")
                
                # Detect new patterns
                self.detect_new_patterns()
                
                # Generate countermeasures
                self.generate_countermeasures()
                
                # Report high threats
                self.report_high_threats()
                
                # Sleep until next analysis
                time.sleep(interval)
            except KeyboardInterrupt:
                self.logger.log("AI Companion stopped by user")
                break
            except Exception as e:
                self.logger.log(f"Error in companion process: {e}", "ERROR")
                time.sleep(60)  # Error backoff


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Adaptive Defense Companion")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--interval", type=int, help="Analysis interval in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set environment variable for debugging
    if args.debug:
        os.environ["DEBUG"] = "1"
    
    companion = AdaptiveDefenseCompanion(args.config)
    companion.run_continuous(args.interval)
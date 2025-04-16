#!/usr/bin/env python3
# security_supervisor.py
# Orchestrates the security microservices for the enhanced security framework

import os
import signal
import subprocess
import time
import json
import threading
import sys
import logging
from datetime import datetime

# Configure paths
BASE_DIR = "/data/data/com.termux/files/home/security_framework"
CONFIG_DIR = f"{BASE_DIR}/config"
LOG_DIR = f"{BASE_DIR}/logs"
IPC_DIR = f"{BASE_DIR}/ipc"

# Create necessary directories
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(IPC_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/supervisor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("SecuritySupervisor")

class SecuritySupervisor:
    def __init__(self):
        self.services = {
            "watchdog": {
                "proc": None, 
                "restart": True, 
                "cmd": ["bash", f"{BASE_DIR}/watchdog/enhanced_watchdog.sh"],
                "log": f"{LOG_DIR}/watchdog.log"
            },
            "ai_companion": {
                "proc": None, 
                "restart": True, 
                "cmd": ["python", f"{BASE_DIR}/ai_companion/adaptive_defense_companion.py"],
                "log": f"{LOG_DIR}/ai_companion.log"
            },
            "countermeasure": {
                "proc": None, 
                "restart": True, 
                "cmd": ["python", f"{BASE_DIR}/microservices/countermeasure_service.py"],
                "log": f"{LOG_DIR}/countermeasure.log"
            },
            "analysis": {
                "proc": None, 
                "restart": True, 
                "cmd": ["python", f"{BASE_DIR}/microservices/log_analysis.py"],
                "log": f"{LOG_DIR}/analysis.log"
            }
        }
        
        # Set up IPC pipes for inter-service communication
        self._setup_ipc()
        
        # Track service failures
        self.failure_counts = {name: 0 for name in self.services}
        self.max_failures = 5  # Max failures before temporarily disabling a service
        
        # Flag to control the supervisor's running state
        self.running = False
        
    def _setup_ipc(self):
        """Set up IPC mechanisms for services to communicate"""
        logger.info("Setting up IPC mechanisms")
        
        # Create named pipes for inter-service communication
        for service in self.services:
            for target in self.services:
                if service != target:
                    pipe_path = f"{IPC_DIR}/{service}_to_{target}"
                    if not os.path.exists(pipe_path):
                        try:
                            os.mkfifo(pipe_path)
                            logger.info(f"Created IPC pipe: {pipe_path}")
                        except Exception as e:
                            logger.error(f"Failed to create IPC pipe {pipe_path}: {e}")
    
    def start_services(self):
        """Start all security microservices"""
        logger.info("Starting security microservices")
        
        for name, service in self.services.items():
            self._start_service(name, service)
    
    def _start_service(self, name, service):
        """Start an individual service"""
        if not service["restart"] or service["proc"] is not None:
            return
            
        # Check if service executable exists
        if not os.path.exists(service["cmd"][1]):
            logger.warning(f"Service {name} executable not found: {service['cmd'][1]}")
            return
            
        try:
            # Open log file
            log_file = open(service["log"], "a")
            
            # Start the service process
            service["proc"] = subprocess.Popen(
                service["cmd"],
                stdout=log_file,
                stderr=log_file,
                bufsize=1,
                universal_newlines=True
            )
            
            logger.info(f"Started {name} service with PID {service['proc'].pid}")
        except Exception as e:
            logger.error(f"Failed to start {name} service: {e}")
            self.failure_counts[name] += 1
    
    def monitor_services(self):
        """Monitor and restart services if needed"""
        logger.info("Service monitoring started")
        
        while self.running:
            for name, service in self.services.items():
                if service["proc"] is not None:
                    ret_code = service["proc"].poll()
                    if ret_code is not None:  # Process has exited
                        logger.warning(f"Service {name} exited with code {ret_code}")
                        service["proc"] = None
                        
                        # Track failures for this service
                        self.failure_counts[name] += 1
                        
                        if self.failure_counts[name] >= self.max_failures:
                            # Too many failures, temporarily disable
                            logger.error(f"Service {name} failed {self.failure_counts[name]} times, disabling for 10 minutes")
                            service["restart"] = False
                            
                            # Schedule re-enabling
                            def reenable_service(svc_name):
                                time.sleep(600)  # 10 minutes
                                self.services[svc_name]["restart"] = True
                                self.failure_counts[svc_name] = 0
                                logger.info(f"Re-enabling service {svc_name}")
                                self._start_service(svc_name, self.services[svc_name])
                            
                            threading.Thread(target=reenable_service, args=(name,), daemon=True).start()
                        elif service["restart"]:
                            # Restart the service with backoff
                            backoff_time = min(30, self.failure_counts[name] * 5)
                            logger.info(f"Waiting {backoff_time}s before restarting {name}")
                            time.sleep(backoff_time)
                            self._start_service(name, service)
            
            # Check if any services need to be started
            for name, service in self.services.items():
                if service["restart"] and service["proc"] is None:
                    self._start_service(name, service)
            
            time.sleep(5)
    
    def run(self):
        """Run the supervisor"""
        logger.info("Starting Security Framework Supervisor")
        
        self.running = True
        self.start_services()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_services)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            # Command loop for handling supervisor commands
            while self.running:
                try:
                    self._check_service_health()
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"Error in supervisor main loop: {e}")
        except KeyboardInterrupt:
            logger.info("Supervisor received keyboard interrupt")
            self.stop()
    
    def _check_service_health(self):
        """Perform deeper health checks on services"""
        now = datetime.now()
        
        # Check log modification times to detect hung services
        for name, service in self.services.items():
            if service["proc"] is not None and os.path.exists(service["log"]):
                try:
                    mtime = os.path.getmtime(service["log"])
                    mtime_dt = datetime.fromtimestamp(mtime)
                    time_since_update = (now - mtime_dt).total_seconds()
                    
                    # If service hasn't logged in a long time but is still running,
                    # it might be hung
                    if time_since_update > 300:  # 5 minutes
                        logger.warning(f"Service {name} may be hung - no log updates for {time_since_update}s")
                        
                        # Restart the service
                        self._restart_service(name)
                except Exception as e:
                    logger.error(f"Error checking health of {name}: {e}")
    
    def _restart_service(self, service_name):
        """Force restart a specific service"""
        if service_name not in self.services:
            logger.error(f"Unknown service: {service_name}")
            return False
            
        service = self.services[service_name]
        if service["proc"] is not None:
            logger.info(f"Force restarting {service_name}")
            
            # Kill the process
            try:
                os.kill(service["proc"].pid, signal.SIGTERM)
                time.sleep(2)
                
                # If still running, force kill
                if service["proc"].poll() is None:
                    os.kill(service["proc"].pid, signal.SIGKILL)
                
                service["proc"] = None
            except Exception as e:
                logger.error(f"Error killing {service_name}: {e}")
        
        # Start the service again
        self._start_service(service_name, service)
        return True
    
    def stop(self):
        """Stop all services and the supervisor"""
        logger.info("Stopping all services")
        self.running = False
        
        for name, service in self.services.items():
            if service["proc"] is not None:
                logger.info(f"Stopping {name} service...")
                try:
                    service["proc"].terminate()
                    try:
                        service["proc"].wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"{name} service did not terminate, force killing")
                        service["proc"].kill()
                except Exception as e:
                    logger.error(f"Error stopping {name} service: {e}")
        
        logger.info("All services stopped")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        # Run as daemon
        import daemon
        with daemon.DaemonContext():
            supervisor = SecuritySupervisor()
            supervisor.run()
    else:
        # Run in foreground
        supervisor = SecuritySupervisor()
        supervisor.run()
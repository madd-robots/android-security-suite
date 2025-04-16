#!/sbin/sh
# SecurityFramework Magisk Module
# This module provides system-level security protections against surveillance

##########################################################################################
# Configs
##########################################################################################

# Set to true if you need custom script execution
CUSTOM=true

# Set to true if you want to load system.prop
PROPFILE=true

# Set this to true if you want to implement module.prop replacements
PROPLACEMENT=false

# List all directories you want to directly replace in the system
# Construct paths under MODPATH/system
REPLACE=""

##########################################################################################
# Permissions
##########################################################################################

# Set permissions
set_permissions() {
  # Default permissions, don't remove
  set_perm_recursive $MODPATH 0 0 0755 0644
  
  # Set executable files
  set_perm $MODPATH/system/bin/security_watchdog 0 0 0755
  set_perm $MODPATH/system/bin/security_framework 0 0 0755
  set_perm $MODPATH/common/service.sh 0 0 0755
  set_perm $MODPATH/common/post-fs-data.sh 0 0 0755
  
  # Additional permissions for specific directories
  set_perm_recursive $MODPATH/system/etc/security_framework 0 0 0755 0644
}

##########################################################################################
# Main Installation
##########################################################################################

# Main installation function
install_module() {
  ui_print "- Installing Security Framework Magisk Module"
  
  # Create directory structure
  mkdir -p $MODPATH/system/bin
  mkdir -p $MODPATH/system/etc/init
  mkdir -p $MODPATH/system/etc/security_framework/config
  mkdir -p $MODPATH/system/etc/hosts.d
  
  # Create security service script
  cat > $MODPATH/system/bin/security_framework << "EOF"
#!/system/bin/sh

# Security Framework Main Service
# This runs with root privileges via Magisk

# Configuration
CONFIG_DIR="/data/adb/modules/SecurityFramework/system/etc/security_framework/config"
LOG_DIR="/data/adb/modules/SecurityFramework/logs"
ENABLED=1

# Ensure directories exist
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_DIR/security_framework.log"
    echo "$1"
}

# Load configuration
if [ -f "$CONFIG_DIR/framework.conf" ]; then
    source "$CONFIG_DIR/framework.conf"
fi

# Only run if enabled
if [ "$ENABLED" != "1" ]; then
    log "Security Framework is disabled in configuration"
    exit 0
fi

log "Starting Security Framework with root privileges"

# Apply SELinux policy modifications if supported
if [ -f "/system/bin/setenforce" ]; then
    log "Applying SELinux policies"
    
    # Create a policy to block tracking services from network access
    cat > /data/local/tmp/block_tracking.te << "POLICY"
# Block tracking services from accessing network
allow init security_t:process { transition };
type security_t;
domain_auto_trans(init, security_framework_exec, security_t);

# Block common tracking services
deny {
  untrusted_app 
  isolated_app 
  platform_app
} { tcp_socket udp_socket rawip_socket netlink_socket } name_connect if { 
  comm = "GoogleLocationService" || 
  comm = "OfflineBeaconService" || 
  comm = "GmsCoreStatsService" ||
  comm = "KLMS" 
};
POLICY
    
    # Compile and load the policy if possible
    setenforce 0
    if [ -f "/system/bin/checkpolicy" ]; then
        checkpolicy -M -c 30 -o /data/local/tmp/block_tracking.pp /data/local/tmp/block_tracking.te 2>/dev/null
        if [ -f "/system/bin/semodule" ]; then
            semodule -i /data/local/tmp/block_tracking.pp 2>/dev/null
            log "SELinux policy loaded"
        fi
    fi
    setenforce 1
fi

# Block tracking domains via hosts file
if [ -f "/system/etc/hosts" ]; then
    log "Adding tracking domains to hosts file"
    
    # Create hosts file entries
    cat > "$MODPATH/system/etc/hosts.d/tracking_domains.txt" << "HOSTS"
# Tracking domains block list
127.0.0.1 www.google-analytics.com
127.0.0.1 analytics.google.com
127.0.0.1 ssl.google-analytics.com
127.0.0.1 firebase-settings.crashlytics.com
127.0.0.1 app-measurement.com
127.0.0.1 e.crashlytics.com
127.0.0.1 firebaselogging-pa.googleapis.com
127.0.0.1 crashlyticsreports-pa.googleapis.com
127.0.0.1 settings.crashlytics.com
127.0.0.1 analytics.samsungknox.com
127.0.0.1 report.samsungknox.com
127.0.0.1 metric.samsungknox.com
HOSTS
    
    # Apply hosts file entries
    cat "$MODPATH/system/etc/hosts.d/tracking_domains.txt" >> /system/etc/hosts
    log "Tracking domains added to hosts file"
fi

# Disable system tracking components
log "Disabling system tracking components"

# List of packages to disable
TRACKING_PACKAGES="
com.google.android.gms.analytics
com.google.android.gms.location
com.google.android.gms.ads
com.google.firebase.analytics
com.samsung.klmsagent
"

for pkg in $TRACKING_PACKAGES; do
    if pm list packages | grep -q "$pkg"; then
        pm disable "$pkg" >/dev/null 2>&1
        log "Disabled package: $pkg"
    fi
done

# Set up firewall rules to block tracking
if [ -f "/system/bin/iptables" ]; then
    log "Setting up firewall rules"
    
    # Block outbound connections to tracking services
    iptables -A OUTPUT -m string --string "google-analytics.com" --algo bm -j DROP
    iptables -A OUTPUT -m string --string "crashlytics.com" --algo bm -j DROP
    iptables -A OUTPUT -m string --string "app-measurement.com" --algo bm -j DROP
    iptables -A OUTPUT -m string --string "analytics" --algo bm -j DROP
    iptables -A OUTPUT -m string --string "metrics" --algo bm -j DROP
    iptables -A OUTPUT -m string --string "samsungknox" --algo bm -j DROP
    
    log "Firewall rules applied"
fi

# Start the system-level watchdog service
log "Starting system-level watchdog service"

# Create a persistent watchdog loop
(
    while true; do
        # Kill known tracking services
        for service in GoogleLocationService GoogleLocationManagerService OfflineBeaconService LocationPersistentService \
                       CrisisAlertsPersistentService GcmService KLMS EventListenerService GmsCoreStatsService; do
            pids=$(ps -ef | grep -i "$service" | grep -v "grep" | awk '{print $2}')
            for pid in $pids; do
                kill -9 "$pid" >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    log "Killed $service (PID: $pid)"
                fi
            done
        done
        
        # Sleep for 30 seconds
        sleep 30
    done
) &

log "Security Framework started successfully"

# Keep the script running
while true; do
    sleep 3600  # Check status every hour
    
    # Ensure tracking domains are still blocked
    if [ -f "$MODPATH/system/etc/hosts.d/tracking_domains.txt" ]; then
        grep -q "google-analytics.com" /system/etc/hosts
        if [ $? -ne 0 ]; then
            log "Hosts file modified, restoring tracking domain blocks"
            cat "$MODPATH/system/etc/hosts.d/tracking_domains.txt" >> /system/etc/hosts
        fi
    fi
done
EOF

  # Create init.rc service entry
  cat > $MODPATH/system/etc/init/security_framework.rc << "EOF"
# Security Framework Service
service security_framework /system/bin/security_framework
    class core
    user root
    group root system
    disabled
    oneshot

on property:sys.boot_completed=1
    start security_framework
EOF

  # Create hosts whitelist file
  cat > $MODPATH/system/etc/hosts.d/whitelist.txt << "EOF"
# Whitelisted domains (will not be blocked)
# Add critical domains here
EOF

  # Create system.prop
  cat > $MODPATH/system.prop << "EOF"
# Security Framework Properties
security.framework.enable=1
security.framework.log_level=3
EOF

  # Create module configuration
  cat > $MODPATH/system/etc/security_framework/config/framework.conf << "EOF"
# Security Framework Configuration
ENABLED=1
DEBUG=0
KILL_INTERVAL=30
HOSTS_BLOCK=1
FIREWALL_ENABLED=1
LOG_LEVEL=3
EOF

  # Create service script (runs after boot)
  cat > $MODPATH/common/service.sh << "EOF"
#!/system/bin/sh
# Security Framework Service Script
# This script runs when Android boots up

MODDIR=${0%/*}
LOG_FILE=$MODDIR/service.log

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

log "Security Framework service script starting"

# Create logs directory
mkdir -p $MODDIR/logs

# Start the security framework service (if not already started via init.rc)
if ! pgrep -f "security_framework" > /dev/null; then
    log "Starting security_framework service"
    nohup $MODDIR/system/bin/security_framework > $MODDIR/logs/framework.log 2>&1 &
fi

# Ensure SELinux is configured properly
if [ -f "/system/bin/setenforce" ]; then
    log "Configuring SELinux"
    setenforce 1
fi

log "Security Framework service script completed"
EOF

  # Create post-fs-data script
  cat > $MODPATH/common/post-fs-data.sh << "EOF"
#!/system/bin/sh
# Security Framework Post-FS-Data Script
# This script runs before Android boots up

MODDIR=${0%/*}
LOG_FILE=$MODDIR/post-fs-data.log

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

log "Security Framework post-fs-data script starting"

# Ensure directories exist
mkdir -p $MODDIR/logs

# Modify hosts file early
if [ -f "$MODDIR/system/etc/hosts.d/tracking_domains.txt" ] && [ -f "/system/etc/hosts" ]; then
    log "Adding tracking domains to hosts file"
    cat "$MODDIR/system/etc/hosts.d/tracking_domains.txt" >> /system/etc/hosts
fi

log "Security Framework post-fs-data script completed"
EOF

  ui_print "- Security Framework installed successfully"
  ui_print "- Configuration located at:"
  ui_print "  /data/adb/modules/SecurityFramework/system/etc/security_framework/config"
  ui_print "- Log files will be created at:"
  ui_print "  /data/adb/modules/SecurityFramework/logs"
}

# This function is called before install_module
pre_install() {
  ui_print "- Preparing to install Security Framework module"
  ui_print "- This module provides system-level protections against surveillance services"
  ui_print "- Checking system compatibility..."
  
  # Check Android version
  ui_print "- Android version: $(getprop ro.build.version.release)"
  
  # Check if SELinux is enforcing
  SELINUX=$(getenforce 2>/dev/null)
  ui_print "- SELinux status: ${SELINUX:-Unknown}"
  
  # Check for required binaries
  for cmd in iptables pm ps grep awk; do
    if [ -x "$(which $cmd)" ]; then
      ui_print "- Found required tool: $cmd"
    else
      ui_print "! Warning: Required tool not found: $cmd"
      ui_print "! Some functionality may be limited"
    fi
  done
}

# This function is called after install_module
post_install() {
  ui_print "- Performing post-installation setup"
  
  # Create the configuration if it doesn't exist
  if [ ! -f "$MODPATH/system/etc/security_framework/config/framework.conf" ]; then
    mkdir -p "$MODPATH/system/etc/security_framework/config"
    cp -f "$MODPATH/system/etc/security_framework/config/framework.conf" "$MODPATH/system/etc/security_framework/config/framework.conf.new"
  fi
  
  # Set module information
  ui_print "- Security Framework is now installed and will activate on reboot"
  ui_print "- Version: 1.0.0"
  ui_print "- Author: Advanced Security Framework Team"
}

##########################################################################################
# Module.prop Content
##########################################################################################

# This will be the content of module.prop
cat > $MODPATH/module.prop << EOF
id=SecurityFramework
name=Advanced Security Framework
version=v1.0.0
versionCode=1
author=Advanced Security Framework Team
description=Comprehensive system-level protection against surveillance and tracking services
EOF

##########################################################################################
# Instructions for installation
##########################################################################################

# To install this Magisk module:
# 1. Ensure your device is rooted with Magisk
# 2. Create a zip file with this structure:
#    - META-INF/com/google/android/update-binary (standard Magisk installer)
#    - META-INF/com/google/android/updater-script (contains "#MAGISK")
#    - install.sh (this file)
#    - module.prop (will be generated)
#    - system/ (empty directory for system files)
#    - common/ (will be created with service scripts)
# 3. Install via Magisk Manager or flash in recovery
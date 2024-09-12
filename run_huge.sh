#!/bin/bash

# Function to check THP settings
check_thp_settings() {
    local enabled=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)
    local defrag=$(cat /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null)
    local errors=0
    local advice=""
    
    # Check if THP is supported
    if [ ! -f "/sys/kernel/mm/transparent_hugepage/enabled" ]; then
        echo "ERROR: Transparent HugePages not supported on this system!"
        echo "       Your kernel might not support THP or it might be disabled in BIOS."
        return 1
    fi  # Changed this line - removed extra }

    # Check enabled status
    if [[ ! "$enabled" =~ "always"|"madvise" ]]; then
        errors=$((errors + 1))
        advice="${advice}- Transparent HugePages is not properly enabled.\n"
        advice="${advice}  Current setting: $enabled\n"
        advice="${advice}  Run as root: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled\n\n"
    fi

    # Check defrag status
    if [[ ! "$defrag" =~ "always"|"madvise" ]]; then
        errors=$((errors + 1))
        advice="${advice}- THP defragmentation is not properly configured.\n"
        advice="${advice}  Current setting: $defrag\n"
        advice="${advice}  Run as root: echo madvise > /sys/kernel/mm/transparent_hugepage/defrag\n\n"
    fi

    # If there are errors, display advice
    if [ $errors -gt 0 ]; then
        echo "WARNING: System is not optimally configured for huge pages!"
        echo -e "$advice"
        echo "To make these changes permanent, create a systemd service:"
        echo "1. Create /etc/systemd/system/hugepage-settings.service with:"
        echo "[Unit]"
        echo "Description=Set Transparent Hugepage Settings"
        echo "After=network.target"
        echo ""
        echo "[Service]"
        echo "Type=oneshot"
        echo "ExecStart=/bin/bash -c 'echo madvise > /sys/kernel/mm/transparent_hugepage/enabled && echo madvise > /sys/kernel/mm/transparent_hugepage/defrag'"
        echo "RemainAfterExit=yes"
        echo ""
        echo "[Install]"
        echo "WantedBy=multi-user.target"
        echo ""
        echo "2. Then run:"
        echo "   sudo systemctl enable hugepage-settings"
        echo "   sudo systemctl start hugepage-settings"
        echo ""
    fi

    return $errors
}

# Usage check
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path_to_executable> [args...]"
    exit 1
fi

# Check THP settings
check_thp_settings

# Get the executable and its arguments
EXECUTABLE=$1
shift
ARGS="$@"

# Set LD_PRELOAD_PATH and LD_LIBRARY_PATH_DIR
CURRENT_DIR=$(pwd)
LD_PRELOAD_PATH="./bin/tcollapse.so"
LD_LIBRARY_PATH_DIR="$CURRENT_DIR/output"

# Check if required files exist
if [ ! -f "$LD_PRELOAD_PATH" ]; then
    echo "ERROR: tcollapse.so not found in current directory!"
    exit 1
fi

if [ ! -d "$LD_LIBRARY_PATH_DIR" ]; then
    echo "WARNING: output directory not found. Creating it..."
    mkdir -p "$LD_LIBRARY_PATH_DIR"
fi

# Run the executable with LD_PRELOAD and LD_LIBRARY_PATH
echo "Running with huge page support..."
echo "Command: LD_PRELOAD=$LD_PRELOAD_PATH LD_LIBRARY_PATH=$LD_LIBRARY_PATH_DIR $EXECUTABLE $ARGS"
LD_PRELOAD=$LD_PRELOAD_PATH LD_LIBRARY_PATH=$LD_LIBRARY_PATH_DIR "$EXECUTABLE" $ARGS

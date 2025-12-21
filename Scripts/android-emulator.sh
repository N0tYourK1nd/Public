#!/bin/bash

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android}"
AVD_HOME="${ANDROID_AVD_HOME:-$HOME/.config/.android/avd}"
LOG_DIR="$HOME/.android-pentest/logs"
SCRIPT_VERSION="1.3.0"

# Android SDK configuration
BASE_SDK_URL="https://dl.google.com/android/repository"
CMDLINE_TOOLS_URL="${BASE_SDK_URL}/commandlinetools-linux-11076708_latest.zip"

# Default specs
DEFAULT_RAM=4096
DEFAULT_STORAGE=8
DEFAULT_ARCH="x86_64"
DEFAULT_DENSITY=420
DEFAULT_RESOLUTION="1080x1920"

# Boot timeout (seconds)
BOOT_TIMEOUT=180

# Proxy defaults
PROXY_HOST="127.0.0.1"
PROXY_PORT="8080"

# Common proxy presets
declare -A PROXY_PRESETS=(
    ["burp"]="127.0.0.1:8080"
    ["mitmproxy"]="127.0.0.1:8888"
    ["charles"]="127.0.0.1:8888"
    ["fiddler"]="127.0.0.1:8888"
)

mkdir -p "$LOG_DIR"
mkdir -p "$ANDROID_HOME/cmdline-tools"
mkdir -p "$AVD_HOME"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_action() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $*" >> "$LOG_DIR/android-emulator.log"
}

check_android_home() {
    if [ ! -d "$ANDROID_HOME" ]; then
        echo "Error: ANDROID_HOME not found at $ANDROID_HOME"
        echo "Run: ./android-emulator.sh install"
        return 1
    fi
    return 0
}

check_sdkmanager() {
    if ! command -v sdkmanager &>/dev/null; then
        # Try to add to PATH temporarily
        if [ -f "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
            export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
            echo "[*] Added sdkmanager to PATH temporarily"
            return 0
        fi
        
        echo "Error: sdkmanager not found. Add to PATH:"
        echo "export PATH=\$PATH:$ANDROID_HOME/cmdline-tools/latest/bin"
        return 1
    fi
    return 0
}

check_emulator() {
    if ! command -v emulator &>/dev/null; then
        # Try to add to PATH temporarily
        if [ -f "$ANDROID_HOME/emulator/emulator" ]; then
            export PATH="$ANDROID_HOME/emulator:$PATH"
            echo "[*] Added emulator to PATH temporarily"
            return 0
        fi
        
        echo "Error: emulator not found. Add to PATH:"
        echo "export PATH=\$PATH:$ANDROID_HOME/emulator"
        return 1
    fi
    return 0
}

check_adb() {
    if ! command -v adb &>/dev/null; then
        # Try to add to PATH temporarily
        if [ -f "$ANDROID_HOME/platform-tools/adb" ]; then
            export PATH="$ANDROID_HOME/platform-tools:$PATH"
            echo "[*] Added adb to PATH temporarily"
            return 0
        fi
        
        echo "Error: adb not found. Add to PATH:"
        echo "export PATH=\$PATH:$ANDROID_HOME/platform-tools"
        return 1
    fi
    return 0
}

check_avd_exists() {
    if [ ! -d "$AVD_HOME/$1.avd" ]; then
        return 1
    fi
    return 0
}

ensure_paths() {
    check_sdkmanager || return 1
    check_emulator || return 1
    check_adb || return 1
    return 0
}

check_kvm() {
    if [ ! -e /dev/kvm ]; then
        echo "[!] Warning: /dev/kvm not found - KVM virtualization not available"
        echo "    The emulator may run VERY slowly"
        return 1
    fi
    return 0
}

# ============================================================================
# INSTALLATION & SETUP
# ============================================================================

install_android_sdk() {
    echo "[*] Installing Android SDK components..."
    
    if [ ! -f "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
        echo "[*] Downloading Command Line Tools..."
        
        local tmpdir=$(mktemp -d)
        cd "$tmpdir" || exit 1
        
        wget -q "$CMDLINE_TOOLS_URL" || {
            echo "Error: Failed to download command line tools"
            rm -rf "$tmpdir"
            return 1
        }
        
        unzip -q commandlinetools-linux-*_latest.zip
        
        mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
        mv cmdline-tools/* "$ANDROID_HOME/cmdline-tools/latest/" 2>/dev/null || true
        
        rm -rf "$tmpdir"
        echo "[+] Command line tools installed"
    fi
    
    # Add to PATH for this session
    export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
    
    # Accept licenses
    echo "[*] Accepting Android licenses..."
    yes | sdkmanager --licenses > /dev/null 2>&1
    
    # Install base components
    echo "[*] Installing base SDK components..."
    sdkmanager "platform-tools" "emulator" "tools"
    
    # Add platform-tools and emulator to PATH
    export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
    
    log_action "Installed Android SDK"
    echo "[+] Android SDK installation complete"
    echo ""
    echo "To make permanent, add to ~/.bashrc:"
    echo "export ANDROID_HOME=\"$ANDROID_HOME\""
    echo "export PATH=\$PATH:\$ANDROID_HOME/cmdline-tools/latest/bin:\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator"
}

install_system_image() {
    local api_level=$1
    local arch=$2
    
    if [ -z "$api_level" ] || [ -z "$arch" ]; then
        echo "Usage: $0 install-image <api_level> <arch>"
        echo "Example: $0 install-image 30 x86_64"
        return 1
    fi
    
    ensure_paths || return 1
    
    local image_name="system-images;android-${api_level};google_apis;${arch}"
    
    echo "[*] Installing Android $api_level system image for $arch..."
    sdkmanager "platforms;android-${api_level}" "$image_name" || {
        echo "Error: Failed to install system image"
        return 1
    }
    
    log_action "Installed system image: $image_name"
    echo "[+] System image installed: $image_name"
}

# ============================================================================
# AVD MANAGEMENT
# ============================================================================

create_avd() {
    local name=$1
    local api_level=$2
    local arch=${3:-$DEFAULT_ARCH}
    
    if [ -z "$name" ] || [ -z "$api_level" ]; then
        echo "Usage: $0 create <name> <api_level> [arch]"
        echo "Example: $0 create MyDevice 30 x86_64"
        return 1
    fi
    
    ensure_paths || return 1
    
    if check_avd_exists "$name"; then
        echo "Error: AVD '$name' already exists"
        return 1
    fi
    
    local image_name="system-images;android-${api_level};google_apis;${arch}"
    
    # Check if system image exists, if not try to install it
    if ! sdkmanager --list_installed 2>/dev/null | grep -q "$image_name"; then
        echo "[!] System image not found: $image_name"
        read -p "Would you like to install it now? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_system_image "$api_level" "$arch" || return 1
        else
            echo "Cannot create AVD without system image. Aborting."
            return 1
        fi
    fi
    
    echo "[*] Creating AVD: $name (API $api_level, $arch)..."
    
    # Create the AVD
    avdmanager create avd \
        -n "$name" \
        -k "$image_name" \
        --device "pixel" \
        --force > /dev/null 2>&1
    
    if [ ! -d "$AVD_HOME/$name.avd" ]; then
        echo "Error: Failed to create AVD"
        return 1
    fi
    
    # Customize AVD config
    local config_file="$AVD_HOME/$name.ini"
    
    cat > "$config_file" <<EOF
avd.ini.encoding=UTF-8
path=$AVD_HOME/$name.avd
path.rel=avd/$name.avd
target=android-$api_level
EOF
    
    # Customize hardware config
    # Customize hardware config - use working Pentest_Device config as base
    local hw_config="$AVD_HOME/$name.avd/config.ini"
    
    cat > "$hw_config" <<EOF
PlayStore.enabled = no
abi.type = $arch
avd.id = <build>
avd.ini.encoding = UTF-8
avd.name = <build>
disk.cachePartition = yes
disk.cachePartition.size = 66MB
disk.dataPartition.path = <temp>
disk.dataPartition.size = 6442450944
disk.systemPartition.size = 0
disk.vendorPartition.size = 0
fastboot.forceChosenSnapshotBoot = no
fastboot.forceColdBoot = no
fastboot.forceFastBoot = yes
firstboot.bootFromDownloadableSnapshot = yes
firstboot.bootFromLocalSnapshot = yes
firstboot.saveToLocalSnapshot = yes
hw.accelerometer = yes
hw.accelerometer_uncalibrated = yes
hw.arc = no
hw.arc.autologin = no
hw.audioInput = yes
hw.audioOutput = yes
hw.battery = yes
hw.camera.back = emulated
hw.camera.front = none
hw.cpu.arch = $arch
hw.cpu.ncore = 4
hw.dPad = no
hw.device.hash2 = MD5:55acbc835978f326788ed66a5cd4c9a7
hw.device.manufacturer = Google
hw.device.name = pixel
hw.display1.density = 0
hw.display1.flag = 0
hw.display1.height = 0
hw.display1.width = 0
hw.display1.xOffset = -1
hw.display1.yOffset = -1
hw.display2.density = 0
hw.display2.flag = 0
hw.display2.height = 0
hw.display2.width = 0
hw.display2.xOffset = -1
hw.display2.yOffset = -1
hw.display3.density = 0
hw.display3.flag = 0
hw.display3.height = 0
hw.display3.width = 0
hw.display3.xOffset = -1
hw.display3.yOffset = -1
hw.displayRegion.0.1.height = 0
hw.displayRegion.0.1.width = 0
hw.displayRegion.0.1.xOffset = -1
hw.displayRegion.0.1.yOffset = -1
hw.displayRegion.0.2.height = 0
hw.displayRegion.0.2.width = 0
hw.displayRegion.0.2.xOffset = -1
hw.displayRegion.0.2.yOffset = -1
hw.displayRegion.0.3.height = 0
hw.displayRegion.0.3.width = 0
hw.displayRegion.0.3.xOffset = -1
hw.displayRegion.0.3.yOffset = -1
hw.gltransport = pipe
hw.gltransport.asg.dataRingSize = 32768
hw.gltransport.asg.writeBufferSize = 1048576
hw.gltransport.asg.writeStepSize = 4096
hw.gltransport.drawFlushInterval = 800
hw.gps = yes
hw.gpu.enabled = no
hw.gpu.mode = auto
hw.gsmModem = yes
hw.gyroscope = yes
hw.hotplug_multi_display = no
hw.initialOrientation = portrait
hw.keyboard = no
hw.keyboard.charmap = qwerty2
hw.keyboard.lid = yes
hw.lcd.backlight = yes
hw.lcd.circular = false
hw.lcd.density = 420
hw.lcd.depth = 16
hw.lcd.height = 1920
hw.lcd.transparent = false
hw.lcd.vsync = 60
hw.lcd.width = 1080
hw.mainKeys = no
hw.multi_display_window = no
hw.ramSize = 1536M
hw.rotaryInput = no
hw.screen = multi-touch
hw.sdCard = yes
hw.sensor.hinge = no
hw.sensor.hinge.count = 0
hw.sensor.hinge.fold_to_displayRegion.0.1_at_posture = 1
hw.sensor.hinge.resizable.config = 1
hw.sensor.hinge.sub_type = 0
hw.sensor.hinge.type = 0
hw.sensor.roll = no
hw.sensor.roll.count = 0
hw.sensor.roll.resize_to_displayRegion.0.1_at_posture = 6
hw.sensor.roll.resize_to_displayRegion.0.2_at_posture = 6
hw.sensor.roll.resize_to_displayRegion.0.3_at_posture = 6
hw.sensors.gyroscope_uncalibrated = yes
hw.sensors.heading = no
hw.sensors.heart_rate = no
hw.sensors.humidity = yes
hw.sensors.light = yes
hw.sensors.magnetic_field = yes
hw.sensors.magnetic_field_uncalibrated = yes
hw.sensors.orientation = yes
hw.sensors.pressure = yes
hw.sensors.proximity = yes
hw.sensors.rgbclight = no
hw.sensors.temperature = yes
hw.sensors.wrist_tilt = no
hw.touchpad0 = no
hw.touchpad0.height = 400
hw.touchpad0.width = 600
hw.trackBall = no
hw.useext4 = yes
image.sysdir.1 = system-images/android-$api_level/google_apis/$arch/
kernel.newDeviceNaming = autodetect
kernel.supportsYaffs2 = autodetect
runtime.network.latency = none
runtime.network.speed = full
sdcard.size = 512 MB
showDeviceFrame = yes
tag.display = Google APIs
tag.id = google_apis
test.delayAdbTillBootComplete = 0
test.monitorAdb = 0
test.quitAfterBootTimeOut = -1
userdata.useQcow2 = no
vm.heapSize = 228M
EOF

    
    log_action "Created AVD: $name (API $api_level, $arch)"
    echo "[+] AVD created successfully: $name"
    echo "    Location: $AVD_HOME/$name.avd"
    echo "    API Level: $api_level"
    echo "    Architecture: $arch"
    echo ""
    echo "Next: $0 start $name"
}

delete_avd() {
    local name=$1
    
    if [ -z "$name" ]; then
        echo "Usage: $0 delete <name>"
        return 1
    fi
    
    if ! check_avd_exists "$name"; then
        echo "Error: AVD '$name' does not exist"
        return 1
    fi
    
    read -p "Delete AVD '$name'? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted"
        return
    fi
    
    echo "[*] Deleting AVD: $name..."
    
    # Kill any running instances
    pkill -f "emulator.*-avd.*$name" 2>/dev/null || true
    
    # Delete via avdmanager
    ensure_paths && avdmanager delete avd -n "$name" 2>/dev/null || true
    
    # Ensure directory is removed
    rm -rf "$AVD_HOME/$name.avd" "$AVD_HOME/$name.ini"
    
    log_action "Deleted AVD: $name"
    echo "[+] AVD deleted: $name"
}

list_avds() {
    echo "[*] Available AVDs:"
    echo ""
    
    if [ ! -d "$AVD_HOME" ] || [ -z "$(ls -A "$AVD_HOME" 2>/dev/null)" ]; then
        echo "    (no AVDs found)"
        echo ""
        echo "Create one: $0 create <name> <api_level>"
        return
    fi
    
    local count=0
    for avd_dir in "$AVD_HOME"/*.avd; do
        if [ -d "$avd_dir" ]; then
            local avd_name=$(basename "$avd_dir" .avd)
            local config_file="$AVD_HOME/$avd_name.ini"
            
            if [ -f "$config_file" ]; then
                local api_level=$(grep "^target=" "$config_file" | cut -d= -f2 | sed 's/android-//')
                echo "    • $avd_name (API $api_level)"
                
                local hw_config="$avd_dir/config.ini"
                if [ -f "$hw_config" ]; then
                    local ram=$(grep "^hw.ramSize=" "$hw_config" | cut -d= -f2)
                    local arch=$(grep "^hw.cpu.arch=" "$hw_config" | cut -d= -f2)
                    [ -n "$ram" ] && echo "      RAM: ${ram}GB"
                    [ -n "$arch" ] && echo "      Arch: $arch"
                fi
                ((count++))
            fi
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo "    (no AVDs found)"
        echo ""
        echo "Create one: $0 create <name> <api_level>"
    else
        echo ""
    fi
}

# ============================================================================
# EMULATOR CONTROL
# ============================================================================

wait_for_boot() {
    local wait_count=0
    local boot_complete=0
    
    echo "[*] Waiting for device to boot (timeout: ${BOOT_TIMEOUT}s)..."
    
    while [ $wait_count -lt $BOOT_TIMEOUT ]; do
        # Print progress indicator every 10 seconds
        if [ $((wait_count % 10)) -eq 0 ] && [ $wait_count -ne 0 ]; then
            echo "[*] Still booting... ($wait_count/${BOOT_TIMEOUT}s)"
        else
            printf "."
        fi
        
        # Check if boot is complete
        if adb shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; then
            boot_complete=1
            break
        fi
        
        sleep 1
        ((wait_count++))
    done
    
    echo ""
    
    if [ $boot_complete -eq 1 ]; then
        return 0
    else
        return 1
    fi
}

start_emulator() {
    local name=$1
    local proxy_preset=$2
    local proxy_host=""
    local proxy_port=""
    
    if [ -z "$name" ]; then
        echo "Usage: $0 start <name> [--burp|--mitmproxy|--charles|<host>] [port]"
        echo "Example: $0 start MyDevice --burp"
        echo "Example: $0 start MyDevice 127.0.0.1 8080"
        return 1
    fi
    
    ensure_paths || return 1
    
    if ! check_avd_exists "$name"; then
        echo "Error: AVD '$name' does not exist"
        echo "Available AVDs:"
        list_avds
        return 1
    fi
    
    # Check KVM availability
    check_kvm || echo "[!] This will be slow without KVM"
    
    # Parse proxy preset or explicit host/port
    if [ -n "$proxy_preset" ]; then
        if [[ "$proxy_preset" == --* ]]; then
            # It's a preset
            local preset_name="${proxy_preset#--}"
            if [ -n "${PROXY_PRESETS[$preset_name]}" ]; then
                proxy_host="${PROXY_PRESETS[$preset_name]%:*}"
                proxy_port="${PROXY_PRESETS[$preset_name]#*:}"
                echo "[*] Using preset: $preset_name ($proxy_host:$proxy_port)"
            else
                echo "Error: Unknown proxy preset: $preset_name"
                echo "Available: ${!PROXY_PRESETS[@]}"
                return 1
            fi
        else
            # It's a host
            proxy_host="$proxy_preset"
            proxy_port="${3:-$PROXY_PORT}"
        fi
    fi
    
    # Check if already running
    if pgrep -f "emulator.*-avd" > /dev/null 2>&1; then
        echo "[!] Warning: An emulator is already running"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    echo "[*] Starting emulator: $name"
    [ -n "$proxy_host" ] && echo "    Proxy: $proxy_host:$proxy_port"
    echo "[*] This may take 1-3 minutes to boot..."
    
    # Build emulator command
    local emu_cmd="emulator -avd \"$name\" \
        -no-snapshot \
        -no-audio \
        -gpu swiftshader_indirect \
        -writable-system"
    
    # Add proxy if specified
    if [ -n "$proxy_host" ]; then
        emu_cmd="$emu_cmd -http-proxy $proxy_host:$proxy_port"
    fi
    
    # Run in background
    eval "$emu_cmd" > /dev/null 2>&1 &
    local emu_pid=$!
    
    echo "[*] Emulator PID: $emu_pid"
    
    # Wait for ADB to detect device
    echo "[*] Waiting for ADB connection..."
    adb wait-for-device || {
        echo "[ERROR] ADB failed to detect device"
        log_action "Failed to start emulator: $name (ADB connection timeout)"
        return 1
    }
    
    # Wait for full boot
    if ! wait_for_boot; then
        echo ""
        echo "[ERROR] Emulator boot timeout after ${BOOT_TIMEOUT}s"
        echo ""
        echo "Troubleshooting:"
        echo "1. Check if emulator process is still running:"
        echo "   ps aux | grep emulator"
        echo ""
        echo "2. View emulator logs:"
        echo "   adb logcat | head -50"
        echo ""
        echo "3. Verify KVM is available:"
        echo "   ls -la /dev/kvm"
        echo ""
        echo "4. Try restarting with longer timeout:"
        echo "   BOOT_TIMEOUT=300 $0 start $name"
        echo ""
        echo "5. Check system requirements:"
        echo "   $0 device-info"
        echo ""
        log_action "Failed to start emulator: $name (boot timeout)"
        stop_emulator "$name"
        return 1
    fi
    
    # Show connected device
    echo "[+] Emulator started successfully!"
    echo ""
    adb devices -l | grep emulator || true
    
    if [ -n "$proxy_host" ]; then
        echo ""
        echo "[*] Configure apps to use proxy: $proxy_host:$proxy_port"
        echo "    Or run: $0 config-proxy $proxy_host $proxy_port"
    fi
    
    log_action "Started emulator: $name (PID: $emu_pid, proxy: ${proxy_host:-none}:${proxy_port:-none})"
}

stop_emulator() {
    local name=${1:-emulator}
    
    echo "[*] Stopping emulator..."
    
    adb emu kill 2>/dev/null || {
        pkill -f "emulator.*-avd" 2>/dev/null || true
    }
    
    sleep 1
    
    if ! pgrep -f "emulator" > /dev/null; then
        echo "[+] Emulator stopped"
        log_action "Stopped emulator: $name"
    else
        echo "Warning: Emulator still running, killing forcefully..."
        pkill -9 -f "emulator" || true
        sleep 1
        echo "[+] Emulator killed"
    fi
}

connect_adb() {
    local cmd=${1:-shell}
    
    echo "[*] Connecting to device (${cmd})..."
    
    # Wait for device if not connected
    adb wait-for-device
    
    if [ "$cmd" = "shell" ]; then
        adb shell
    else
        eval "adb $cmd"
    fi
    
    log_action "ADB connection: $cmd"
}

push_file() {
    local local_path=$1
    local remote_path=$2
    
    if [ -z "$local_path" ] || [ -z "$remote_path" ]; then
        echo "Usage: $0 push <local_path> <remote_path>"
        return 1
    fi
    
    if [ ! -f "$local_path" ]; then
        echo "Error: File not found: $local_path"
        return 1
    fi
    
    echo "[*] Pushing file to device..."
    adb push "$local_path" "$remote_path"
    
    log_action "Pushed file: $local_path -> $remote_path"
}

pull_file() {
    local remote_path=$1
    local local_path=${2:-.}
    
    if [ -z "$remote_path" ]; then
        echo "Usage: $0 pull <remote_path> [local_path]"
        return 1
    fi
    
    echo "[*] Pulling file from device..."
    adb pull "$remote_path" "$local_path"
    
    log_action "Pulled file: $remote_path -> $local_path"
}

install_apk() {
    local apk_path=$1
    
    if [ -z "$apk_path" ]; then
        echo "Usage: $0 install-apk <path_to_apk>"
        return 1
    fi
    
    if [ ! -f "$apk_path" ]; then
        echo "Error: APK not found: $apk_path"
        return 1
    fi
    
    echo "[*] Installing APK: $(basename "$apk_path")"
    adb install "$apk_path"
    
    log_action "Installed APK: $apk_path"
}

# ============================================================================
# PROXY CONFIGURATION
# ============================================================================

configure_proxy() {
    local proxy_preset=$1
    local proxy_host=""
    local proxy_port=""
    local proto=${3:-http}
    
    if [ -z "$proxy_preset" ]; then
        echo "Usage: $0 config-proxy [--burp|--mitmproxy|--charles|<host>] [port] [proto]"
        echo "Example: $0 config-proxy --burp"
        echo "Example: $0 config-proxy 127.0.0.1 8080 http"
        echo ""
        echo "Available presets:"
        for preset in "${!PROXY_PRESETS[@]}"; do
            echo "  --$preset: ${PROXY_PRESETS[$preset]}"
        done
        return 1
    fi
    
    # Parse proxy preset or explicit host/port
    if [[ "$proxy_preset" == --* ]]; then
        # It's a preset
        local preset_name="${proxy_preset#--}"
        if [ -n "${PROXY_PRESETS[$preset_name]}" ]; then
            proxy_host="${PROXY_PRESETS[$preset_name]%:*}"
            proxy_port="${PROXY_PRESETS[$preset_name]#*:}"
        else
            echo "Error: Unknown proxy preset: $preset_name"
            echo "Available: ${!PROXY_PRESETS[@]}"
            return 1
        fi
    else
        # It's a host
        proxy_host="$proxy_preset"
        proxy_port="${2:-$PROXY_PORT}"
    fi
    
    echo "[*] Configuring system proxy..."
    
    # Set proxy via adb
    adb shell settings put global http_proxy "$proxy_host:$proxy_port" 2>/dev/null || {
        # Fallback for older Android versions
        adb shell setprop http.proxyHost "$proxy_host"
        adb shell setprop http.proxyPort "$proxy_port"
    }
    
    echo "[+] Proxy configured: $proto://$proxy_host:$proxy_port"
    log_action "Configured proxy: $proto://$proxy_host:$proxy_port"
}

clear_proxy() {
    echo "[*] Clearing proxy configuration..."
    adb shell settings delete global http_proxy 2>/dev/null || true
    adb shell setprop http.proxyHost ""
    adb shell setprop http.proxyPort ""
    
    echo "[+] Proxy cleared"
    log_action "Cleared proxy configuration"
}

# ============================================================================
# PENTESTING UTILITIES
# ============================================================================

install_frida() {
    local frida_server_path=$1
    
    if [ -z "$frida_server_path" ] || [ ! -f "$frida_server_path" ]; then
        echo "Usage: $0 install-frida <path_to_frida_server>"
        echo ""
        echo "Steps to get frida-server:"
        echo "1. Download from: https://github.com/frida/frida/releases"
        echo "2. Choose frida-server-VERSION-android-ARCH.xz"
        echo "3. Extract: xz -d frida-server-VERSION-android-ARCH.xz"
        return 1
    fi
    
    echo "[*] Installing frida-server..."
    
    adb push "$frida_server_path" /data/local/tmp/frida-server
    adb shell chmod +x /data/local/tmp/frida-server
    
    echo "[+] frida-server installed to /data/local/tmp/frida-server"
    echo ""
    echo "To run frida-server:"
    echo "  adb shell /data/local/tmp/frida-server"
    echo ""
    echo "Then from host:"
    echo "  frida-ps -U"
    
    log_action "Installed frida-server from $frida_server_path"
}

install_burp_ca() {
    local cert_path=$1
    
    if [ -z "$cert_path" ] || [ ! -f "$cert_path" ]; then
        echo "Usage: $0 install-burp-ca <path_to_burp_cert>"
        echo ""
        echo "Steps to get Burp CA:"
        echo "1. Open Burp Suite"
        echo "2. Burp > Preferences > Certificates"
        echo "3. Export certificate in DER format"
        echo "4. Run: openssl x509 -inform DER -in cert.der -out cert.pem"
        return 1
    fi
    
    echo "[*] Installing Burp CA certificate..."
    
    # Create certificate directory
    adb shell mkdir -p /system/etc/security/cacerts
    adb remount 2>/dev/null || true
    
    # Calculate certificate hash
    local cert_hash=$(openssl x509 -inform PEM -subject_hash_old -in "$cert_path" | head -1)
    local cert_name="${cert_hash}.0"
    
    # Push certificate
    adb push "$cert_path" "/system/etc/security/cacerts/$cert_name"
    adb shell chmod 644 "/system/etc/security/cacerts/$cert_name"
    
    echo "[+] Burp CA installed: $cert_name"
    echo "[*] Restarting device network..."
    adb shell stop && adb shell start
    
    log_action "Installed Burp CA certificate: $cert_name"
}

dump_logs() {
    local output_file=${1:-android_logcat.log}
    
    echo "[*] Dumping logcat to $output_file..."
    adb logcat -d > "$output_file"
    
    echo "[+] Logs saved to: $output_file"
    log_action "Dumped logcat to: $output_file"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

show_device_info() {
    echo "[*] Device Information:"
    echo ""
    
    adb shell getprop ro.build.version.release | xargs echo "Android Version:"
    adb shell getprop ro.product.manufacturer | xargs echo "Manufacturer:"
    adb shell getprop ro.product.model | xargs echo "Model:"
    adb shell getprop ro.boot.serialno | xargs echo "Serial:"
    adb shell getprop ro.build.fingerprint | xargs echo "Build:"
    adb shell getprop ro.debuggable | xargs echo "Debuggable:"
    
    echo ""
    echo "[*] Storage:"
    adb shell df | grep -E "^/data|Total"
}

get_logs() {
    local log_file=${1:-$LOG_DIR/android-emulator.log}
    
    if [ -f "$log_file" ]; then
        tail -n 20 "$log_file"
    else
        echo "No logs found"
    fi
}

quick_setup() {
    local name=$1
    local api_level=${2:-30}
    local arch=${3:-x86_64}
    
    if [ -z "$name" ]; then
        echo "Usage: $0 quick-setup <name> [api_level] [arch]"
        echo "Example: $0 quick-setup MyDevice 30 x86_64"
        return 1
    fi
    
    echo "[*] Quick setup: Creating and starting $name..."
    create_avd "$name" "$api_level" "$arch" || return 1
    
    echo ""
    read -p "Start emulator now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_emulator "$name" || return 1
    fi
}

# ============================================================================
# USAGE & VERSION
# ============================================================================

usage() {
    cat << EOF
Usage: $0 {command} [options]

QUICK START:
  quick-setup <name> [api] [arch] - Create and optionally start AVD in one go

INSTALLATION:
  install                         - Install Android SDK and tools
  install-image <api> <arch>      - Install system image (e.g., 30 x86_64)

AVD MANAGEMENT:
  create <name> <api> [arch]      - Create AVD (e.g., create Device1 30 x86_64)
  delete <name>                   - Delete AVD
  list                            - List all AVDs
  
EMULATOR CONTROL:
  start <name> [--burp|host] [port] - Start emulator with optional proxy
  stop                            - Stop running emulator
  connect [shell|devices]         - ADB shell or device list
  
FILE OPERATIONS:
  push <local> <remote>           - Push file to device
  pull <remote> [local]           - Pull file from device
  install-apk <apk_path>          - Install APK

PROXY & NETWORK:
  config-proxy [--burp|host] [port] - Configure system proxy
  clear-proxy                     - Clear proxy settings
  
  Available presets: $(echo "${!PROXY_PRESETS[@]}" | tr ' ' ',')

PENTESTING TOOLS:
  install-frida <frida_path>      - Install frida-server
  install-burp-ca <cert_path>     - Install Burp Suite CA
  device-info                     - Show device information
  dump-logs [output]              - Dump logcat to file
  
UTILITIES:
  logs [file]                     - Show recent logs
  help                            - Show this help message
  version                         - Show script version

EXAMPLES:
  # Quick setup (fastest way to get started)
  $0 quick-setup Pentest_Device 30 x86_64
  
  # Setup new device manually
  $0 install
  $0 install-image 30 x86_64
  $0 create Pentest_Device 30 x86_64
  
  # Start with Burp proxy (simple)
  $0 start Pentest_Device --burp
  
  # Start with custom proxy
  $0 start Pentest_Device 192.168.1.100 8080
  
  # Configure proxy after boot
  $0 config-proxy --burp
  
  # Install Frida for dynamic analysis
  $0 install-frida ~/frida-server-android-x86_64
  
  # Install Burp CA for HTTPS interception
  $0 install-burp-ca ~/burp_cert.pem

ENVIRONMENT:
  Set ANDROID_HOME to override default location (default: ~/Android)
  Set ANDROID_AVD_HOME to override AVD storage location
  Set BOOT_TIMEOUT to override emulator boot timeout in seconds (default: 180)

TIPS:
  - If tools aren't in PATH, they'll be added temporarily during this session
  - Missing system images are auto-detected and offered for installation
  - Emulator boot has a ${BOOT_TIMEOUT}s timeout with progress updates
  - All actions are logged to: $LOG_DIR/android-emulator.log
  - If boot times out, check KVM availability: ls -la /dev/kvm

EOF
    exit 1
}

version() {
    echo "android-emulator.sh v$SCRIPT_VERSION"
}

# ============================================================================
# MAIN ARGUMENT PARSING
# ============================================================================

case "$1" in
    install) install_android_sdk ;;
    install-image) install_system_image "$2" "$3" ;;
    
    create) create_avd "$2" "$3" "$4" ;;
    delete) delete_avd "$2" ;;
    list) list_avds ;;
    quick-setup) quick_setup "$2" "$3" "$4" ;;
    
    start) start_emulator "$2" "$3" "$4" ;;
    stop) stop_emulator "$2" ;;
    connect) connect_adb "${2:-shell}" ;;
    
    push) push_file "$2" "$3" ;;
    pull) pull_file "$2" "$3" ;;
    install-apk) install_apk "$2" ;;
    
    config-proxy) configure_proxy "$2" "$3" "$4" ;;
    clear-proxy) clear_proxy ;;
    
    install-frida) install_frida "$2" ;;
    install-burp-ca) install_burp_ca "$2" ;;
    device-info) show_device_info ;;
    dump-logs) dump_logs "$2" ;;
    
    logs) get_logs "$2" ;;
    help) usage ;;
    version) version ;;
    
    *) usage ;;
esac

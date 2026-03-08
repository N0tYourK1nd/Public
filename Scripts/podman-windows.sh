#!/bin/bash
#
# podman-windows.sh - Windows Container Management Script
# Manages dockur/windows containers for malware development testing
#
BASE_IMAGE="docker.io/dockurr/windows:latest"
GOLDEN_NAME="windows-golden"
LOG_DIR="$HOME/.windows-pentest/logs"
STORAGE_BASE="$HOME/.windows-pentest/storage"
SCRIPT_VERSION="1.6.0"

# Default Windows configuration
DEFAULT_VERSION="11"
DEFAULT_RAM="4G"
DEFAULT_CPU="2"
DEFAULT_DISK="64G"
DEFAULT_USERNAME="Docker"
DEFAULT_PASSWORD="admin"

# Port tracking file for unique port assignments
PORT_TRACK_FILE="$HOME/.windows-pentest/ports"

# Create directories if they don't exist
mkdir -p "$LOG_DIR"
mkdir -p "$STORAGE_BASE"
mkdir -p "$(dirname "$PORT_TRACK_FILE")"
touch "$PORT_TRACK_FILE"

usage() {
  cat << EOF
Usage: $0 {command} [options]

Container Lifecycle:
  create [name] [options]  - Create new Windows container (instant CoW clone)
                             Options: --version=<ver> --ram=<size> --cpu=<cores>
                                      --disk=<size> --user=<name> --pass=<pwd>
                                      --fresh (skip golden, fresh install)
                                      --full-copy (slow full copy instead of CoW)
  start [name]             - Start a stopped container
  connect [name]           - Show connection info (RDP/Web/VNC)
  delete [name]            - Stop and remove a container
  restart [name]           - Restart a container
  stop [name]              - Stop a running container (graceful 2min timeout)
  force-stop [name]        - Force stop a container immediately

Golden Image Management:
  golden [options]         - Create/start golden Windows container
                             Options: --version=<ver> --ram=<size> --cpu=<cores>
  adopt [path]             - Adopt existing Windows storage as golden image
  convert-golden           - Convert golden to QCOW2 for instant cloning
  commit [name]            - Save container's storage as the new golden image
  golden-status            - Show golden image storage info
  snapshot [name]          - Create a snapshot of container's storage
  restore [name] [snap]    - Restore container from snapshot
  update-base              - Pull latest upstream dockur/windows image

Container Inspection:
  list                     - List all containers (running and stopped)
  list-running             - List running containers
  list-stopped             - List stopped containers
  inspect [name]           - Show detailed container info
  logs [name]              - Show container logs
  stats [name]             - Show container resource usage
  ports [name]             - Show port mappings for container
  list-images              - List all local images
  list-snapshots [name]    - List snapshots for a container

Batch Operations:
  clean                    - Stop and remove all stopped containers
  clean-all                - Stop and remove ALL containers (excluding golden)
  stop-all                 - Stop all running containers (excluding golden)

Utilities:
  clone [name] [new_name]  - Clone container (instant CoW)
  rename [old] [new]       - Rename a container
  export-storage [n] [path] - Export container's Windows disk
  import-storage [path] [name] - Import Windows disk to new container
  remove-image [image]     - Remove a local image
  rdp [name]               - Open RDP connection (requires xfreerdp)
  web [name]               - Open web viewer in browser
  vnc [name]               - Open VNC connection (requires vncviewer)

Windows Versions (use with --version):
  11/11l/11e  - Windows 11 Pro/LTSC/Enterprise
  10/10l/10e  - Windows 10 Pro/LTSC/Enterprise
  8e          - Windows 8.1 Enterprise
  7u          - Windows 7 Ultimate
  vu          - Vista Ultimate
  xp          - Windows XP
  2k          - Windows 2000
  2025/2022/2019/2016/2012/2008/2003 - Windows Server

Help:
  help                     - Show this help message
  version                  - Show script version

Examples:
  $0 adopt ./windows              # Use existing installation as golden
  $0 convert-golden               # Convert to QCOW2 for instant clones
  $0 create test1                 # Instant clone from golden
  $0 create test2                 # Another instant clone
  $0 snapshot test1               # Save state before testing
  $0 restore test1                # Revert to clean state

EOF
  exit 1
}

log_action() {
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $*" >> "$LOG_DIR/windows-podman.log"
}

check_container_exists() {
  if ! podman container exists "$1" 2>/dev/null; then
    echo "Error: Container '$1' does not exist"
    return 1
  fi
  return 0
}

check_image_exists() {
  if ! podman image exists "$1" 2>/dev/null; then
    echo "Error: Image '$1' does not exist"
    return 1
  fi
  return 0
}

check_kvm() {
  if [ ! -e /dev/kvm ]; then
    echo "Error: /dev/kvm not found. KVM is required for Windows containers."
    echo "Ensure KVM is enabled and you have proper permissions."
    exit 1
  fi
}

get_storage_path() {
  local name=$1
  echo "$STORAGE_BASE/$name"
}

get_golden_storage() {
  local gs="$STORAGE_BASE/$GOLDEN_NAME"
  if [ -L "$gs" ]; then
    gs=$(readlink -f "$gs")
  fi
  echo "$gs"
}

# Find the Windows disk image in a storage directory
find_disk_image() {
  local storage_dir=$1
  
  # Check common disk image names - qcow2 first (preferred)
  for disk in "data.qcow2" "data.img"; do
    if [ -f "$storage_dir/$disk" ]; then
      echo "$storage_dir/$disk"
      return 0
    fi
  done
  
  return 1
}

# Get container IP address
get_container_ip() {
  local name=$1
  local ip=""
  
  # Try different methods to get IP
  ip=$(podman inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null)
  
  # If empty, try alternative format
  if [ -z "$ip" ]; then
    ip=$(podman inspect --format='{{.NetworkSettings.IPAddress}}' "$name" 2>/dev/null)
  fi
  
  echo "$ip"
}

# Check if container is running
is_container_running() {
  local name=$1
  local state=$(podman inspect --format='{{.State.Status}}' "$name" 2>/dev/null)
  [ "$state" = "running" ]
}

# Get container state
get_container_state() {
  local name=$1
  podman inspect --format='{{.State.Status}}' "$name" 2>/dev/null
}

# Find next available port pair (web + rdp)
get_next_ports() {
  local base_web=8006
  local base_rdp=3389
  local offset=0
  
  while true; do
    local web_port=$((base_web + offset))
    local rdp_port=$((base_rdp + offset))
    
    # Check if ports are in use by another container
    if ! grep -q "^$web_port:" "$PORT_TRACK_FILE" 2>/dev/null; then
      if ! ss -tuln 2>/dev/null | grep -q ":$web_port " && ! ss -tuln 2>/dev/null | grep -q ":$rdp_port "; then
        echo "$web_port:$rdp_port"
        return
      fi
    fi
    
    ((offset++))
    if [ "$offset" -gt 100 ]; then
      echo "Error: No available ports in range"
      exit 1
    fi
  done
}

register_ports() {
  local name=$1
  local web_port=$2
  local rdp_port=$3
  sed -i "/^.*:.*:$name$/d" "$PORT_TRACK_FILE" 2>/dev/null
  echo "$web_port:$rdp_port:$name" >> "$PORT_TRACK_FILE"
}

get_container_ports() {
  local name=$1
  grep ":$name$" "$PORT_TRACK_FILE" 2>/dev/null | head -1
}

parse_options() {
  WIN_VERSION="$DEFAULT_VERSION"
  WIN_RAM="$DEFAULT_RAM"
  WIN_CPU="$DEFAULT_CPU"
  WIN_DISK="$DEFAULT_DISK"
  WIN_USERNAME="$DEFAULT_USERNAME"
  WIN_PASSWORD="$DEFAULT_PASSWORD"
  FRESH_INSTALL="false"
  FULL_COPY="false"
  
  for arg in "$@"; do
    case $arg in
      --version=*) WIN_VERSION="${arg#*=}" ;;
      --ram=*) WIN_RAM="${arg#*=}" ;;
      --cpu=*) WIN_CPU="${arg#*=}" ;;
      --disk=*) WIN_DISK="${arg#*=}" ;;
      --user=*) WIN_USERNAME="${arg#*=}" ;;
      --pass=*) WIN_PASSWORD="${arg#*=}" ;;
      --fresh) FRESH_INSTALL="true" ;;
      --full-copy) FULL_COPY="true" ;;
    esac
  done
}

# Check if a path is accessible (for backing file validation)
check_path_accessible() {
  local path=$1
  [ -f "$path" ] && [ -r "$path" ]
}

# Create a standalone QCOW2 copy (no backing file dependency)
create_standalone_qcow2() {
  local source_disk=$1
  local target_disk=$2
  
  echo "Creating standalone QCOW2 copy..."
  echo "This takes longer but avoids backing file issues."
  
  if command -v qemu-img &>/dev/null; then
    # Convert to standalone qcow2 (no backing file)
    qemu-img convert -p -O qcow2 "$source_disk" "$target_disk"
    return $?
  else
    # Fallback to cp
    cp --sparse=always "$source_disk" "$target_disk"
    return $?
  fi
}

# Fast clone using QCOW2 backing files (only if golden is in STORAGE_BASE)
fast_clone_storage() {
  local source_dir=$1
  local target_dir=$2
  
  mkdir -p "$target_dir"
  
  local source_disk=$(find_disk_image "$source_dir")
  if [ -z "$source_disk" ]; then
    echo "Error: No source disk found in $source_dir"
    return 1
  fi
  
  local disk_name=$(basename "$source_disk")
  
  # Copy metadata files first
  for f in windows.base windows.boot windows.mac windows.rom windows.vars windows.ver; do
    [ -f "$source_dir/$f" ] && cp "$source_dir/$f" "$target_dir/"
  done
  
  # Check if source is within STORAGE_BASE (safe for backing files)
  # Backing files with absolute paths outside the storage can cause issues
  local source_real=$(realpath "$source_dir")
  local storage_real=$(realpath "$STORAGE_BASE")
  
  # If source is a symlink to somewhere else, we can't use backing files reliably
  if [ -L "$STORAGE_BASE/$GOLDEN_NAME" ]; then
    echo "Golden storage is symlinked to external location."
    echo "Using standalone copy for reliability..."
    create_standalone_qcow2 "$source_disk" "$target_dir/data.qcow2"
    return $?
  fi
  
  # QCOW2 backing file (instant, but only works if paths are consistent)
  if [[ "$disk_name" == *.qcow2 ]] && command -v qemu-img &>/dev/null; then
    echo "Creating instant CoW clone (QCOW2 backing file)..."
    if qemu-img create -f qcow2 -b "$source_disk" -F qcow2 "$target_dir/data.qcow2" 2>/dev/null; then
      # Verify the backing file is accessible
      local backing_check=$(qemu-img info "$target_dir/data.qcow2" 2>&1)
      if echo "$backing_check" | grep -q "Could not open backing file"; then
        echo "Warning: Backing file not accessible, creating standalone copy..."
        rm -f "$target_dir/data.qcow2"
        create_standalone_qcow2 "$source_disk" "$target_dir/data.qcow2"
      else
        echo "Done! (instant)"
      fi
      return 0
    fi
  fi
  
  # Raw image - convert to qcow2
  if [[ "$disk_name" == *.img ]] && command -v qemu-img &>/dev/null; then
    echo "Converting raw image to QCOW2..."
    create_standalone_qcow2 "$source_disk" "$target_dir/data.qcow2"
    return $?
  fi
  
  # Fallback: Full copy
  echo "Copying disk..."
  if command -v rsync &>/dev/null; then
    rsync -a --sparse --info=progress2 "$source_disk" "$target_dir/"
  else
    cp -a --sparse=always "$source_disk" "$target_dir/"
  fi
  
  return 0
}

# Convert golden image to QCOW2 for better cloning
convert_golden() {
  local golden_storage=$(get_golden_storage)
  local disk=$(find_disk_image "$golden_storage")
  
  if [ -z "$disk" ]; then
    echo "Error: No golden disk found at $golden_storage"
    exit 1
  fi
  
  local disk_name=$(basename "$disk")
  
  if [[ "$disk_name" == *.qcow2 ]]; then
    echo "Golden image is already QCOW2 format."
    if command -v qemu-img &>/dev/null; then
      qemu-img info "$disk" | head -5
    fi
    return 0
  fi
  
  if ! command -v qemu-img &>/dev/null; then
    echo "Error: qemu-img not found. Install qemu-utils package."
    exit 1
  fi
  
  echo "Converting golden image to QCOW2 format..."
  echo "Source: $disk"
  echo ""
  
  local actual_size=$(du -h "$disk" | cut -f1)
  local apparent_size=$(ls -lh "$disk" | awk '{print $5}')
  echo "Size: $actual_size actual / $apparent_size apparent"
  echo ""
  
  # Check if golden container is running
  if podman container exists "$GOLDEN_NAME" 2>/dev/null; then
    local state=$(get_container_state "$GOLDEN_NAME")
    if [ "$state" = "running" ]; then
      echo "Golden container is running. Stop it first for safe conversion."
      read -p "Stop golden container? (y/N) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        stop_container "$GOLDEN_NAME"
      else
        echo "Aborted."
        return
      fi
    fi
  fi
  
  local qcow2_disk="$golden_storage/data.qcow2"
  
  echo "Converting (this takes several minutes)..."
  
  if qemu-img convert -p -O qcow2 -o preallocation=off "$disk" "$qcow2_disk"; then
    local new_size=$(du -h "$qcow2_disk" | cut -f1)
    echo ""
    echo "Done! New size: $new_size"
    
    # Verify
    if qemu-img check "$qcow2_disk" 2>&1 | grep -q "No errors"; then
      echo "Verification passed!"
      
      read -p "Remove original raw image? (y/N) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm "$disk"
        echo "Original removed."
      else
        mv "$disk" "${disk}.backup"
        echo "Original backed up to ${disk}.backup"
      fi
      
      echo ""
      echo "Golden image converted successfully!"
    else
      echo "Warning: Verification found issues. Keeping original."
      rm -f "$qcow2_disk"
    fi
  else
    echo "Error: Conversion failed"
    rm -f "$qcow2_disk"
    exit 1
  fi
  
  log_action "Converted golden to QCOW2"
}

# Show golden storage status
golden_status() {
  local golden_storage=$(get_golden_storage)
  
  echo "Golden Image Status"
  echo "==================="
  echo ""
  echo "Storage path: $STORAGE_BASE/$GOLDEN_NAME"
  
  if [ -L "$STORAGE_BASE/$GOLDEN_NAME" ]; then
    echo "Type: Symlink -> $golden_storage"
    echo ""
    echo "⚠ Note: Symlinked storage uses standalone copies (slower but reliable)"
  elif [ -d "$golden_storage" ]; then
    echo "Type: Directory (instant CoW cloning available)"
  else
    echo "Status: NOT CONFIGURED"
    echo ""
    echo "Run: $0 adopt <path-to-windows-storage>"
    return 1
  fi
  
  echo ""
  echo "Contents:"
  ls -lh "$golden_storage" 2>/dev/null || echo "  (empty)"
  
  echo ""
  local disk=$(find_disk_image "$golden_storage")
  if [ -n "$disk" ]; then
    local disk_name=$(basename "$disk")
    local actual_size=$(du -h "$disk" 2>/dev/null | cut -f1)
    local apparent_size=$(ls -lh "$disk" 2>/dev/null | awk '{print $5}')
    
    echo "Windows disk: $disk_name"
    echo "Size: $actual_size actual / $apparent_size apparent"
    
    if [[ "$disk_name" == *.qcow2 ]]; then
      echo "Format: QCOW2 ✓"
    else
      echo "Format: Raw image"
      echo ""
      echo "Tip: Run '$0 convert-golden' to convert to QCOW2"
    fi
    
    echo ""
    echo "Metadata files:"
    for f in windows.base windows.boot windows.mac windows.rom windows.vars windows.ver; do
      if [ -f "$golden_storage/$f" ]; then
        echo "  ✓ $f"
      fi
    done
  else
    echo "ERROR: No Windows disk image found!"
    echo "Expected: data.qcow2 or data.img"
  fi
}

# Adopt existing Windows storage as golden image
adopt_golden() {
  local source_path=$1
  if [ -z "$source_path" ]; then
    echo "Error: Source path required"
    echo "Usage: $0 adopt <path-to-windows-storage>"
    exit 1
  fi
  
  # Resolve to absolute path
  source_path=$(realpath "$source_path" 2>/dev/null || echo "$source_path")
  
  if [ ! -d "$source_path" ]; then
    echo "Error: Directory '$source_path' does not exist"
    exit 1
  fi
  
  echo "Checking source directory..."
  echo "Path: $source_path"
  echo ""
  echo "Contents:"
  ls -lh "$source_path"
  echo ""
  
  # Check for Windows disk image
  local disk=$(find_disk_image "$source_path")
  if [ -n "$disk" ]; then
    local actual_size=$(du -h "$disk" | cut -f1)
    local apparent_size=$(ls -lh "$disk" | awk '{print $5}')
    echo "Found Windows disk: $(basename "$disk")"
    echo "Size: $actual_size actual / $apparent_size apparent"
  else
    echo "WARNING: No Windows disk image found!"
    echo "Expected: data.qcow2 or data.img"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  fi
  
  local golden_storage="$STORAGE_BASE/$GOLDEN_NAME"
  
  # Check if golden already exists
  if [ -e "$golden_storage" ]; then
    echo ""
    echo "Warning: Golden storage already exists at $golden_storage"
    if [ -L "$golden_storage" ]; then
      echo "  (currently a symlink to: $(readlink -f "$golden_storage"))"
    fi
    read -p "Replace it? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
    rm -rf "$golden_storage"
  fi
  
  echo ""
  echo "How do you want to adopt '$source_path'?"
  echo ""
  echo "  1) Copy - Recommended, enables instant CoW cloning"
  echo "  2) Move - Fast, original location becomes empty"
  echo "  3) Link - Fastest setup, but clones will be slower"
  echo ""
  read -p "Choose [1/2/3]: " -n 1 -r choice
  echo
  
  mkdir -p "$(dirname "$golden_storage")"
  
  case $choice in
    1)
      echo "Copying (this may take a while for large disks)..."
      mkdir -p "$golden_storage"
      if command -v rsync &>/dev/null; then
        rsync -a --sparse --info=progress2 "$source_path/" "$golden_storage/"
      else
        cp -a --sparse=always "$source_path/." "$golden_storage/"
      fi
      echo "Copied to $golden_storage"
      echo ""
      echo "✓ Instant CoW cloning is now available!"
      ;;
    2)
      mv "$source_path" "$golden_storage"
      echo "Moved to $golden_storage"
      echo ""
      echo "✓ Instant CoW cloning is now available!"
      ;;
    3)
      ln -s "$source_path" "$golden_storage"
      echo "Linked: $golden_storage -> $source_path"
      echo ""
      echo "Note: Clones will use standalone copies (slower but reliable)"
      ;;
    *)
      echo "Invalid choice. Aborted."
      return
      ;;
  esac
  
  log_action "Adopted golden storage from: $source_path"
  echo ""
  
  # Show status
  golden_status
  
  # Check if conversion is recommended
  local new_disk=$(find_disk_image "$(get_golden_storage)")
  if [ -n "$new_disk" ] && [[ "$new_disk" == *.img ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "RECOMMENDED: Convert to QCOW2 format:"
    echo "  $0 convert-golden"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  fi
}

# Commit a container's storage as the new golden image
commit_golden() {
  local name=$1
  
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    echo "Usage: $0 commit <container-name>"
    exit 1
  fi
  
  local storage_path=$(get_storage_path "$name")
  if [ -L "$storage_path" ]; then
    storage_path=$(readlink -f "$storage_path")
  fi
  
  local disk=$(find_disk_image "$storage_path")
  if [ -z "$disk" ]; then
    echo "Error: No Windows disk found for '$name'"
    exit 1
  fi
  
  local golden_storage=$(get_golden_storage)
  
  echo "This will save '$name' as the new golden image."
  echo "Source: $storage_path"
  echo "Target: $STORAGE_BASE/$GOLDEN_NAME"
  echo ""
  
  # Stop container for consistent copy
  if podman container exists "$name" 2>/dev/null; then
    if is_container_running "$name"; then
      echo "Container is running. Stop it for a clean commit."
      read -p "Stop container now? (y/N) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        stop_container "$name"
      else
        echo "Warning: Committing while running may cause inconsistencies."
      fi
    fi
  fi
  
  read -p "Commit '$name' as new golden image? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  
  # Remove symlink if exists, backup if directory
  if [ -L "$STORAGE_BASE/$GOLDEN_NAME" ]; then
    rm "$STORAGE_BASE/$GOLDEN_NAME"
  elif [ -d "$golden_storage" ] && [ "$(ls -A "$golden_storage" 2>/dev/null)" ]; then
    local backup="${golden_storage}.backup-$(date +%Y%m%d-%H%M%S)"
    echo "Backing up existing golden to: $backup"
    mv "$golden_storage" "$backup"
  fi
  
  # Create new golden storage with standalone copy
  mkdir -p "$STORAGE_BASE/$GOLDEN_NAME"
  echo "Copying storage (this ensures standalone golden image)..."
  
  if command -v rsync &>/dev/null; then
    rsync -a --sparse --info=progress2 "$storage_path/" "$STORAGE_BASE/$GOLDEN_NAME/"
  else
    cp -a --sparse=always "$storage_path/." "$STORAGE_BASE/$GOLDEN_NAME/"
  fi
  
  log_action "Committed $name as new golden image"
  echo ""
  echo "Done! '$name' is now the golden image."
  echo "New containers will use instant CoW cloning."
}

create_container() {
  local name=$1
  shift
  
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  if podman container exists "$name" 2>/dev/null; then
    echo "Error: Container '$name' already exists"
    exit 1
  fi
  
  check_kvm
  parse_options "$@"
  
  local storage_path=$(get_storage_path "$name")
  local golden_storage=$(get_golden_storage)
  
  # Clone from golden unless --fresh specified
  if [ "$FRESH_INSTALL" != "true" ]; then
    local golden_disk=$(find_disk_image "$golden_storage")
    
    if [ -n "$golden_disk" ]; then
      if [ "$FULL_COPY" = "true" ]; then
        echo "Creating full copy..."
        mkdir -p "$storage_path"
        if command -v rsync &>/dev/null; then
          rsync -a --sparse --info=progress2 "$golden_storage/" "$storage_path/"
        else
          cp -a --sparse=always "$golden_storage/." "$storage_path/"
        fi
      else
        fast_clone_storage "$golden_storage" "$storage_path" || exit 1
      fi
    else
      echo "No golden image found."
      echo ""
      echo "Options:"
      echo "  1) Create fresh Windows installation (downloads ISO)"
      echo "  2) Abort and setup golden image first"
      echo ""
      read -p "Choose [1/2]: " -n 1 -r
      echo
      
      case $REPLY in
        1) 
          FRESH_INSTALL="true"
          mkdir -p "$storage_path"
          ;;
        *) 
          echo "Aborted. Run: $0 adopt <path-to-windows-storage>"
          exit 1 
          ;;
      esac
    fi
  else
    mkdir -p "$storage_path"
  fi
  
  # Get unique ports
  local ports=$(get_next_ports)
  local web_port=$(echo "$ports" | cut -d: -f1)
  local rdp_port=$(echo "$ports" | cut -d: -f2)
  
  echo ""
  echo "Creating Windows container '$name'..."
  if [ "$FRESH_INSTALL" = "true" ]; then
    echo "  Mode: Fresh installation (Windows $WIN_VERSION)"
  else
    echo "  Mode: Cloned from golden"
  fi
  echo "  RAM: $WIN_RAM"
  echo "  CPU Cores: $WIN_CPU"
  echo "  Web Port: $web_port"
  echo "  RDP Port: $rdp_port"
  echo "  Storage: $storage_path"
  echo ""
  
  local version_env=""
  [ "$FRESH_INSTALL" = "true" ] && version_env="-e VERSION=$WIN_VERSION"
  
  podman run -d --name "$name" \
    $version_env \
    -e RAM_SIZE="$WIN_RAM" \
    -e CPU_CORES="$WIN_CPU" \
    -e DISK_SIZE="$WIN_DISK" \
    -e USERNAME="$WIN_USERNAME" \
    -e PASSWORD="$WIN_PASSWORD" \
    -p "$web_port:8006" \
    -p "$rdp_port:3389/tcp" \
    -p "$rdp_port:3389/udp" \
    --device /dev/kvm \
    --device /dev/net/tun \
    --cap-add NET_ADMIN \
    --stop-timeout 120 \
    -v "$storage_path:/storage:Z" \
    "$BASE_IMAGE"

  register_ports "$name" "$web_port" "$rdp_port"
  
  # Wait and check if container is actually running
  sleep 3
  if ! is_container_running "$name"; then
    echo ""
    echo "Warning: Container may have failed to start!"
    echo "Check logs with: $0 logs $name"
    echo ""
    local exit_code=$(podman inspect --format='{{.State.ExitCode}}' "$name" 2>/dev/null)
    echo "Exit code: $exit_code"
    return 1
  fi
  
  log_action "Created container: $name (Web: $web_port, RDP: $rdp_port)"
  echo ""
  echo "Container '$name' created and running!"
  echo ""
  echo "Access:"
  echo "  Web Viewer: http://localhost:$web_port"
  echo "  RDP:        localhost:$rdp_port (user: $WIN_USERNAME, pass: $WIN_PASSWORD)"
  echo ""
  echo "Commands:"
  echo "  $0 web $name    # Open web viewer"
  echo "  $0 rdp $name    # Connect via RDP"
  echo "  $0 vnc $name    # Connect via VNC"
  echo "  $0 stop $name   # Stop container"
}

start_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  check_kvm
  
  podman start "$name"
  
  # Wait for container to initialize
  sleep 3
  
  if is_container_running "$name"; then
    log_action "Started container: $name"
    local port_info=$(get_container_ports "$name")
    if [ -n "$port_info" ]; then
      local web_port=$(echo "$port_info" | cut -d: -f1)
      local rdp_port=$(echo "$port_info" | cut -d: -f2)
      echo "Container '$name' started"
      echo "  Web: http://localhost:$web_port"
      echo "  RDP: localhost:$rdp_port"
    else
      echo "Container '$name' started"
    fi
  else
    echo "Error: Container failed to start!"
    echo "Check logs: $0 logs $name"
    local exit_code=$(podman inspect --format='{{.State.ExitCode}}' "$name" 2>/dev/null)
    echo "Exit code: $exit_code"
  fi
}

connect_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  
  local port_info=$(get_container_ports "$name")
  local web_port=$(echo "$port_info" | cut -d: -f1)
  local rdp_port=$(echo "$port_info" | cut -d: -f2)
  local state=$(get_container_state "$name")
  
  echo "Connection Info for '$name':"
  echo ""
  echo "Status: $state"
  echo ""
  echo "Web Viewer:"
  echo "  URL: http://localhost:$web_port"
  echo ""
  echo "RDP (recommended for regular use):"
  echo "  Host: localhost:$rdp_port"
  echo "  Username: Docker"
  echo "  Password: admin"
  echo ""
  
  if [ "$state" = "running" ]; then
    local ip=$(get_container_ip "$name")
    if [ -n "$ip" ]; then
      echo "VNC (direct to QEMU):"
      echo "  Address: $ip:5900"
    fi
  fi
  
  echo ""
  echo "Quick commands:"
  echo "  $0 web $name"
  echo "  $0 rdp $name"
  echo "  $0 vnc $name"
}

delete_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  
  if [ "$name" = "$GOLDEN_NAME" ]; then
    echo "Warning: This will delete the golden container."
    echo "Golden storage will remain."
    read -p "Continue? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  fi
  
  echo "Stopping container '$name'..."
  podman stop -t 120 "$name" 2>/dev/null
  podman rm "$name"
  
  sed -i "/:$name$/d" "$PORT_TRACK_FILE" 2>/dev/null
  
  log_action "Deleted container: $name"
  echo "Container '$name' removed"
  
  local storage_path=$(get_storage_path "$name")
  if [ -d "$storage_path" ] && [ ! -L "$storage_path" ] && [ "$name" != "$GOLDEN_NAME" ]; then
    local disk=$(find_disk_image "$storage_path")
    if [ -n "$disk" ]; then
      local size=$(du -h "$disk" 2>/dev/null | cut -f1)
      echo ""
      echo "Storage remains at: $storage_path ($size)"
      read -p "Delete storage too? (y/N) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$storage_path"
        echo "Storage deleted"
      fi
    fi
  fi
}

restart_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  
  echo "Restarting '$name'..."
  podman restart -t 120 "$name"
  
  sleep 3
  if is_container_running "$name"; then
    log_action "Restarted container: $name"
    echo "Container '$name' restarted"
  else
    echo "Error: Container failed to restart!"
    echo "Check logs: $0 logs $name"
  fi
}

stop_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  
  echo "Stopping '$name' gracefully (up to 2 minutes)..."
  podman stop -t 120 "$name"
  log_action "Stopped container: $name"
  echo "Container '$name' stopped"
}

force_stop_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  
  echo "Force stopping '$name'..."
  podman stop -t 0 "$name"
  log_action "Force stopped container: $name"
  echo "Container '$name' force stopped"
}

golden_shell() {
  parse_options "$@"
  check_kvm
  
  local golden_storage=$(get_golden_storage)
  mkdir -p "$golden_storage"
  
  if podman container exists "$GOLDEN_NAME" 2>/dev/null; then
    if ! is_container_running "$GOLDEN_NAME"; then
      echo "Starting golden container..."
      podman start "$GOLDEN_NAME"
      sleep 3
    fi
    
    if is_container_running "$GOLDEN_NAME"; then
      echo "Golden container is running."
    else
      echo "Error: Golden container failed to start!"
      echo "Check logs: $0 logs $GOLDEN_NAME"
      return 1
    fi
  else
    echo "Creating golden container..."
    
    local version_env=""
    local existing_disk=$(find_disk_image "$golden_storage")
    
    if [ -z "$existing_disk" ]; then
      echo "No existing Windows installation found."
      echo "Will create fresh Windows $WIN_VERSION installation."
      version_env="-e VERSION=$WIN_VERSION"
    else
      echo "Using existing Windows installation: $(basename "$existing_disk")"
    fi
    
    podman run -d --name "$GOLDEN_NAME" \
      $version_env \
      -e RAM_SIZE="$WIN_RAM" \
      -e CPU_CORES="$WIN_CPU" \
      -e DISK_SIZE="$WIN_DISK" \
      -p 8006:8006 \
      -p 3389:3389/tcp \
      -p 3389:3389/udp \
      --device /dev/kvm \
      --device /dev/net/tun \
      --cap-add NET_ADMIN \
      --stop-timeout 120 \
      -v "$golden_storage:/storage:Z" \
      "$BASE_IMAGE"
    
    register_ports "$GOLDEN_NAME" "8006" "3389"
    
    sleep 3
    if is_container_running "$GOLDEN_NAME"; then
      log_action "Created golden container: $GOLDEN_NAME"
    else
      echo "Error: Golden container failed to start!"
      echo "Check logs: $0 logs $GOLDEN_NAME"
      return 1
    fi
  fi
  
  echo ""
  echo "Golden Windows container is running!"
  echo ""
  echo "Access:"
  echo "  Web: http://localhost:8006"
  echo "  RDP: localhost:3389 (user: Docker, pass: admin)"
  echo ""
  echo "Customize Windows, then new containers will clone it."
  echo "Storage: $golden_storage"
}

# Snapshot management
create_snapshot() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  local storage_path=$(get_storage_path "$name")
  if [ -L "$storage_path" ]; then
    storage_path=$(readlink -f "$storage_path")
  fi
  
  if [ ! -d "$storage_path" ]; then
    echo "Error: No storage found for '$name'"
    exit 1
  fi
  
  local disk=$(find_disk_image "$storage_path")
  if [ -z "$disk" ]; then
    echo "Error: No disk image found"
    exit 1
  fi
  
  # Stop container for consistent snapshot
  if podman container exists "$name" 2>/dev/null && is_container_running "$name"; then
    echo "Stopping container for consistent snapshot..."
    podman stop -t 120 "$name"
  fi
  
  local snapshot_name="snapshot-$(date +%Y%m%d-%H%M%S)"
  local snapshot_dir="$storage_path/snapshots"
  mkdir -p "$snapshot_dir"
  
  echo "Creating snapshot '$snapshot_name'..."
  
  local disk_name=$(basename "$disk")
  
  if [[ "$disk_name" == *.qcow2 ]] && command -v qemu-img &>/dev/null; then
    qemu-img snapshot -c "$snapshot_name" "$disk"
    echo "Snapshot created: $snapshot_name (internal qcow2)"
  else
    echo "Copying disk..."
    if command -v rsync &>/dev/null; then
      rsync -a --sparse --info=progress2 "$disk" "$snapshot_dir/${snapshot_name}.img"
    else
      cp --sparse=always "$disk" "$snapshot_dir/${snapshot_name}.img"
    fi
    echo "Snapshot created: $snapshot_name (file copy)"
  fi
  
  log_action "Created snapshot for $name: $snapshot_name"
  echo ""
  echo "Restore with: $0 restore $name $snapshot_name"
}

restore_snapshot() {
  local name=$1
  local snapshot=$2
  
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  local storage_path=$(get_storage_path "$name")
  if [ -L "$storage_path" ]; then
    storage_path=$(readlink -f "$storage_path")
  fi
  
  local disk=$(find_disk_image "$storage_path")
  if [ -z "$disk" ]; then
    echo "Error: No disk image found"
    exit 1
  fi
  
  # Stop container
  if podman container exists "$name" 2>/dev/null && is_container_running "$name"; then
    echo "Stopping container..."
    podman stop -t 120 "$name"
  fi
  
  if [ -z "$snapshot" ]; then
    echo "Available snapshots for '$name':"
    echo ""
    if [[ "$(basename "$disk")" == *.qcow2 ]] && command -v qemu-img &>/dev/null; then
      echo "Internal snapshots:"
      qemu-img snapshot -l "$disk" 2>/dev/null || echo "  (none)"
    fi
    if [ -d "$storage_path/snapshots" ]; then
      echo ""
      echo "File snapshots:"
      ls -lh "$storage_path/snapshots"/ 2>/dev/null || echo "  (none)"
    fi
    return
  fi
  
  echo "Restoring snapshot '$snapshot'..."
  
  # Try internal qcow2 snapshot
  if [[ "$(basename "$disk")" == *.qcow2 ]] && command -v qemu-img &>/dev/null; then
    if qemu-img snapshot -a "$snapshot" "$disk" 2>/dev/null; then
      echo "Restored: $snapshot"
      log_action "Restored snapshot for $name: $snapshot"
      echo ""
      echo "Start with: $0 start $name"
      return
    fi
  fi
  
  # Try file snapshot
  for ext in img qcow2; do
    if [ -f "$storage_path/snapshots/${snapshot}.${ext}" ]; then
      echo "Restoring from file..."
      cp --sparse=always "$storage_path/snapshots/${snapshot}.${ext}" "$disk"
      echo "Restored: $snapshot"
      log_action "Restored snapshot for $name: $snapshot"
      echo ""
      echo "Start with: $0 start $name"
      return
    fi
  done
  
  echo "Error: Snapshot '$snapshot' not found"
  exit 1
}

list_snapshots() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  local storage_path=$(get_storage_path "$name")
  if [ -L "$storage_path" ]; then
    storage_path=$(readlink -f "$storage_path")
  fi
  
  local disk=$(find_disk_image "$storage_path")
  
  echo "Snapshots for '$name':"
  echo ""
  
  if [ -n "$disk" ] && [[ "$(basename "$disk")" == *.qcow2 ]] && command -v qemu-img &>/dev/null; then
    echo "Internal QCOW2 snapshots:"
    qemu-img snapshot -l "$disk" 2>/dev/null || echo "  (none)"
  fi
  
  if [ -d "$storage_path/snapshots" ]; then
    echo ""
    echo "File snapshots:"
    ls -lh "$storage_path/snapshots"/ 2>/dev/null || echo "  (none)"
  fi
}

update_base() {
  echo "Pulling latest dockur/windows image..."
  podman pull "$BASE_IMAGE"
  log_action "Updated base image: $BASE_IMAGE"
  echo "Base image updated"
}

list_containers() {
  echo "All Windows containers:"
  podman ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

list_running() {
  echo "Running Windows containers:"
  podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

list_stopped() {
  echo "Stopped Windows containers:"
  podman ps -a --filter "status=exited" --format "table {{.Names}}\t{{.Status}}"
}

list_images() {
  echo "Local images:"
  podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"
}

inspect_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  podman inspect "$name"
}

show_logs() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  podman logs "$name"
}

show_stats() {
  local name=$1
  if [ -z "$name" ]; then
    podman stats
  else
    check_container_exists "$name" || exit 1
    podman stats "$name"
  fi
}

show_ports() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  check_container_exists "$name" || exit 1
  podman port "$name"
}

clean_stopped() {
  local count=$(podman ps -a --filter "status=exited" -q | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "No stopped containers"
    return
  fi
  
  echo "Found $count stopped containers."
  read -p "Remove them? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && return
  
  podman container prune -f
  log_action "Cleaned stopped containers"
}

clean_all_containers() {
  echo "This will stop and remove ALL containers except golden."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && return
  
  for cid in $(podman ps -a -q); do
    [ -z "$cid" ] && continue
    local cname=$(podman inspect --format='{{.Name}}' "$cid" | sed 's|^/||')
    if [ "$cname" != "$GOLDEN_NAME" ]; then
      echo "Removing $cname..."
      podman stop -t 60 "$cid" 2>/dev/null
      podman rm "$cid"
      sed -i "/:$cname$/d" "$PORT_TRACK_FILE" 2>/dev/null
    fi
  done
  
  log_action "Cleaned all containers except golden"
}

stop_all_containers() {
  echo "This will stop all running containers except golden."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && return
  
  for cid in $(podman ps -q); do
    [ -z "$cid" ] && continue
    local cname=$(podman inspect --format='{{.Name}}' "$cid" | sed 's|^/||')
    if [ "$cname" != "$GOLDEN_NAME" ]; then
      echo "Stopping $cname..."
      podman stop -t 120 "$cid"
    fi
  done
  
  log_action "Stopped all containers except golden"
}

clone_container() {
  local source=$1
  local target=$2
  
  if [ -z "$source" ] || [ -z "$target" ]; then
    echo "Usage: $0 clone <source> <target>"
    exit 1
  fi
  
  if podman container exists "$target" 2>/dev/null; then
    echo "Error: Target '$target' already exists"
    exit 1
  fi
  
  local source_storage=$(get_storage_path "$source")
  [ -L "$source_storage" ] && source_storage=$(readlink -f "$source_storage")
  
  local source_disk=$(find_disk_image "$source_storage")
  [ -z "$source_disk" ] && { echo "Error: Source disk not found"; exit 1; }
  
  # Stop source for consistent copy
  if podman container exists "$source" 2>/dev/null && is_container_running "$source"; then
    echo "Stopping source container..."
    podman stop -t 120 "$source"
  fi
  
  echo "Cloning '$source' to '$target'..."
  fast_clone_storage "$source_storage" "$(get_storage_path "$target")"
  
  local ports=$(get_next_ports)
  local web_port=$(echo "$ports" | cut -d: -f1)
  local rdp_port=$(echo "$ports" | cut -d: -f2)
  
  podman run -d --name "$target" \
    -e RAM_SIZE="$DEFAULT_RAM" \
    -e CPU_CORES="$DEFAULT_CPU" \
    -p "$web_port:8006" \
    -p "$rdp_port:3389/tcp" \
    -p "$rdp_port:3389/udp" \
    --device /dev/kvm \
    --device /dev/net/tun \
    --cap-add NET_ADMIN \
    --stop-timeout 120 \
    -v "$(get_storage_path "$target"):/storage:Z" \
    "$BASE_IMAGE"
  
  register_ports "$target" "$web_port" "$rdp_port"
  log_action "Cloned: $source -> $target"
  
  echo ""
  echo "Cloned '$source' to '$target'"
  echo "  Web: http://localhost:$web_port"
  echo "  RDP: localhost:$rdp_port"
}

rename_container() {
  local old=$1
  local new=$2
  
  [ -z "$old" ] || [ -z "$new" ] && { echo "Usage: $0 rename <old> <new>"; exit 1; }
  check_container_exists "$old" || exit 1
  
  podman rename "$old" "$new"
  
  local port_info=$(get_container_ports "$old")
  if [ -n "$port_info" ]; then
    local web_port=$(echo "$port_info" | cut -d: -f1)
    local rdp_port=$(echo "$port_info" | cut -d: -f2)
    sed -i "/:$old$/d" "$PORT_TRACK_FILE" 2>/dev/null
    register_ports "$new" "$web_port" "$rdp_port"
  fi
  
  local old_storage=$(get_storage_path "$old")
  if [ -d "$old_storage" ] && [ ! -L "$old_storage" ]; then
    mv "$old_storage" "$(get_storage_path "$new")"
  fi
  
  log_action "Renamed: $old -> $new"
  echo "Renamed '$old' to '$new'"
}

export_storage() {
  local name=$1
  local path=$2
  
  [ -z "$name" ] || [ -z "$path" ] && { echo "Usage: $0 export-storage <name> <path>"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  [ -L "$storage_path" ] && storage_path=$(readlink -f "$storage_path")
  
  local disk=$(find_disk_image "$storage_path")
  [ -z "$disk" ] && { echo "Error: No disk found"; exit 1; }
  
  echo "Exporting: $disk"
  
  if command -v pigz &>/dev/null; then
    pigz -c "$disk" > "$path"
  else
    gzip -c "$disk" > "$path"
  fi
  
  echo "Exported to: $path ($(du -h "$path" | cut -f1))"
}

import_storage() {
  local path=$1
  local name=$2
  
  [ -z "$path" ] || [ -z "$name" ] && { echo "Usage: $0 import-storage <path> <name>"; exit 1; }
  [ ! -f "$path" ] && { echo "Error: File not found: $path"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  mkdir -p "$storage_path"
  
  echo "Importing..."
  
  if [[ "$path" == *.gz ]]; then
    if command -v pigz &>/dev/null; then
      pigz -dc "$path" > "$storage_path/data.qcow2"
    else
      gunzip -c "$path" > "$storage_path/data.qcow2"
    fi
  else
    cp --sparse=always "$path" "$storage_path/data.qcow2"
  fi
  
  echo "Imported to: $storage_path"
  echo "Create container: $0 create $name"
}

remove_image() {
  local image=$1
  [ -z "$image" ] && { echo "Error: Image name required"; exit 1; }
  check_image_exists "$image" || exit 1
  podman rmi "$image"
  echo "Removed: $image"
}

open_rdp() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  if ! is_container_running "$name"; then
    echo "Error: Container '$name' is not running"
    echo "Start it: $0 start $name"
    exit 1
  fi
  
  local port_info=$(get_container_ports "$name")
  local rdp_port=$(echo "$port_info" | cut -d: -f2)
  [ -z "$rdp_port" ] && rdp_port="3389"
  
  echo "Connecting to localhost:$rdp_port..."
  
  if command -v xfreerdp3 &>/dev/null; then
    xfreerdp3 /v:localhost:$rdp_port /u:Docker /p:admin /dynamic-resolution +clipboard &
  elif command -v xfreerdp &>/dev/null; then
    xfreerdp /v:localhost:$rdp_port /u:Docker /p:admin /dynamic-resolution +clipboard &
  else
    echo "xfreerdp not found."
    echo "Manual: localhost:$rdp_port (Docker/admin)"
  fi
}

open_web() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  if ! is_container_running "$name"; then
    echo "Error: Container '$name' is not running"
    echo "Start it: $0 start $name"
    exit 1
  fi
  
  local port_info=$(get_container_ports "$name")
  local web_port=$(echo "$port_info" | cut -d: -f1)
  [ -z "$web_port" ] && web_port="8006"
  
  local url="http://localhost:$web_port"
  echo "Opening: $url"
  
  if command -v xdg-open &>/dev/null; then
    xdg-open "$url" 2>/dev/null &
  else
    echo "Open manually: $url"
  fi
}

open_vnc() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  if ! is_container_running "$name"; then
    echo "Error: Container '$name' is not running"
    echo "Start it: $0 start $name"
    exit 1
  fi
  
  local ip=$(get_container_ip "$name")
  
  if [ -z "$ip" ]; then
    echo "Error: Could not get container IP"
    echo "Try: podman inspect $name | grep IPAddress"
    exit 1
  fi
  
  echo "Connecting to $ip:5900..."
  
  if command -v vncviewer &>/dev/null; then
    vncviewer "$ip:5900" &
  else
    echo "vncviewer not found."
    echo "Manual: vncviewer $ip:5900"
  fi
}

version() {
  echo "podman-windows.sh v$SCRIPT_VERSION"
}

# Main
case ${1:-} in
  adopt) adopt_golden "$2" ;;
  clean) clean_stopped ;;
  clean-all) clean_all_containers ;;
  clone) clone_container "$2" "$3" ;;
  commit) commit_golden "$2" ;;
  connect) connect_container "$2" ;;
  convert-golden) convert_golden ;;
  create) shift; create_container "$@" ;;
  delete) delete_container "$2" ;;
  export-storage) export_storage "$2" "$3" ;;
  force-stop) force_stop_container "$2" ;;
  golden) shift; golden_shell "$@" ;;
  golden-status) golden_status ;;
  help) usage ;;
  import-storage) import_storage "$2" "$3" ;;
  inspect) inspect_container "$2" ;;
  list) list_containers ;;
  list-images) list_images ;;
  list-running) list_running ;;
  list-snapshots) list_snapshots "$2" ;;
  list-stopped) list_stopped ;;
  logs) show_logs "$2" ;;
  ports) show_ports "$2" ;;
  rdp) open_rdp "$2" ;;
  remove-image) remove_image "$2" ;;
  rename) rename_container "$2" "$3" ;;
  restart) restart_container "$2" ;;
  restore) restore_snapshot "$2" "$3" ;;
  snapshot) create_snapshot "$2" ;;
  start) start_container "$2" ;;
  stats) show_stats "$2" ;;
  stop) stop_container "$2" ;;
  stop-all) stop_all_containers ;;
  update-base) update_base ;;
  version) version ;;
  vnc) open_vnc "$2" ;;
  web) open_web "$2" ;;
  *) usage ;;
esac

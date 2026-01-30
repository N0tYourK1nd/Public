#!/bin/bash
#
# podman-windows.sh - Windows Container Management Script
# Manages dockur/windows containers for malware development testing
#
BASE_IMAGE="docker.io/dockurr/windows:latest"
GOLDEN_NAME="windows-golden"
LOG_DIR="$HOME/.windows-pentest/logs"
STORAGE_BASE="$HOME/.windows-pentest/storage"
SCRIPT_VERSION="1.1.1"

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
  create [name] [options]  - Create new Windows container (clones golden storage)
                             Options: --version=<ver> --ram=<size> --cpu=<cores>
                                      --disk=<size> --user=<name> --pass=<pwd>
                                      --fresh (skip golden, fresh install)
  start [name]             - Start a stopped container
  connect [name]           - Show connection info (RDP/Web)
  delete [name]            - Stop and remove a container
  restart [name]           - Restart a container
  stop [name]              - Stop a running container (graceful 2min timeout)
  force-stop [name]        - Force stop a container immediately

Golden Image Management:
  golden [options]         - Create/start golden Windows container
                             Options: --version=<ver> --ram=<size> --cpu=<cores>
  adopt [path]             - Adopt existing Windows storage as golden image
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
  clone [name] [new_name]  - Clone container (copies Windows disk)
  rename [old] [new]       - Rename a container
  export-storage [n] [path] - Export container's Windows disk
  import-storage [path] [name] - Import Windows disk to new container
  remove-image [image]     - Remove a local image
  rdp [name]               - Open RDP connection (requires xfreerdp)
  web [name]               - Open web viewer in browser

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
  $0 create malware-test          # Clone golden to new test environment
  $0 create fresh-win10 --fresh --version=10l  # Fresh install, no clone
  $0 snapshot malware-test        # Save state before testing
  $0 restore malware-test         # Revert to clean state

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
  echo "$STORAGE_BASE/$GOLDEN_NAME"
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
  
  for arg in "$@"; do
    case $arg in
      --version=*) WIN_VERSION="${arg#*=}" ;;
      --ram=*) WIN_RAM="${arg#*=}" ;;
      --cpu=*) WIN_CPU="${arg#*=}" ;;
      --disk=*) WIN_DISK="${arg#*=}" ;;
      --user=*) WIN_USERNAME="${arg#*=}" ;;
      --pass=*) WIN_PASSWORD="${arg#*=}" ;;
      --fresh) FRESH_INSTALL="true" ;;
    esac
  done
}

# Copy additional files from source to target storage
copy_extra_files() {
  local source_dir=$1
  local target_dir=$2
  
  # Copy ROM files
  for f in "$source_dir"/*.rom; do
    [ -f "$f" ] && cp "$f" "$target_dir/"
  done
  
  # Copy FD files
  for f in "$source_dir"/*.fd; do
    [ -f "$f" ] && cp "$f" "$target_dir/"
  done
  
  # Copy ISO files
  for f in "$source_dir"/*.iso; do
    [ -f "$f" ] && cp "$f" "$target_dir/"
  done
}

# Adopt existing Windows storage as golden image
adopt_golden() {
  local source_path=$1
  [ -z "$source_path" ] && { echo "Error: Source path required"; exit 1; }
  
  # Resolve to absolute path
  source_path=$(realpath "$source_path" 2>/dev/null || echo "$source_path")
  
  if [ ! -d "$source_path" ]; then
    echo "Error: Directory '$source_path' does not exist"
    exit 1
  fi
  
  # Check for Windows disk image
  if [ ! -f "$source_path/data.qcow2" ] && [ ! -f "$source_path/data.img" ]; then
    echo "Warning: No Windows disk image found in '$source_path'"
    echo "Expected: data.qcow2 or data.img"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  fi
  
  local golden_storage=$(get_golden_storage)
  
  # Check if golden already exists
  if [ -d "$golden_storage" ] && [ "$(ls -A "$golden_storage" 2>/dev/null)" ]; then
    echo "Warning: Golden storage already exists at $golden_storage"
    read -p "Replace it? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
    rm -rf "$golden_storage"
  fi
  
  echo "Adopting '$source_path' as golden image..."
  
  echo "Options:"
  echo "  1) Move - Fast, original location becomes empty"
  echo "  2) Copy - Slow but preserves original"
  echo "  3) Link - Fastest, uses original location"
  read -p "Choose [1/2/3]: " -n 1 -r choice
  echo
  
  case $choice in
    1)
      mkdir -p "$(dirname "$golden_storage")"
      mv "$source_path" "$golden_storage"
      echo "Moved to $golden_storage"
      ;;
    2)
      mkdir -p "$golden_storage"
      echo "Copying (this may take a while for large disks)..."
      cp -a "$source_path/." "$golden_storage/"
      echo "Copied to $golden_storage"
      ;;
    3)
      mkdir -p "$(dirname "$golden_storage")"
      ln -s "$source_path" "$golden_storage"
      echo "Linked to $golden_storage -> $source_path"
      ;;
    *)
      echo "Invalid choice. Aborted."
      return
      ;;
  esac
  
  log_action "Adopted golden storage from: $source_path"
  echo ""
  echo "Golden image ready!"
  echo "Storage: $golden_storage"
  echo ""
  echo "You can now:"
  echo "  $0 golden          # Start golden container to customize"
  echo "  $0 create test1    # Create test container from golden"
}

create_container() {
  local name=$1
  shift
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  
  if podman container exists "$name" 2>/dev/null; then
    echo "Error: Container '$name' already exists"
    exit 1
  fi
  
  check_kvm
  parse_options "$@"
  
  local storage_path=$(get_storage_path "$name")
  local golden_storage=$(get_golden_storage)
  
  # Setup storage
  mkdir -p "$storage_path"
  
  # Clone from golden unless --fresh specified
  if [ "$FRESH_INSTALL" != "true" ]; then
    if [ -d "$golden_storage" ] && [ -f "$golden_storage/data.qcow2" ]; then
      echo "Cloning Windows disk from golden image..."
      echo "This may take a few minutes for large disks..."
      
      # Use qemu-img for CoW copy if available (much faster)
      if command -v qemu-img &>/dev/null; then
        # Create a backing file based copy (instant, CoW)
        qemu-img create -f qcow2 -b "$golden_storage/data.qcow2" -F qcow2 "$storage_path/data.qcow2"
        echo "Created CoW clone (instant, space-efficient)"
      else
        # Fallback to regular copy
        cp "$golden_storage/data.qcow2" "$storage_path/data.qcow2"
        echo "Created full copy"
      fi
      
      # Copy other files (rom, fd, iso)
      copy_extra_files "$golden_storage" "$storage_path"
    else
      echo "No golden image found. Creating fresh Windows installation."
      echo "This will download and install Windows (may take 30+ minutes)."
      read -p "Continue? (y/N) " -n 1 -r
      echo
      [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
      FRESH_INSTALL="true"
    fi
  fi
  
  # Get unique ports
  local ports=$(get_next_ports)
  local web_port=$(echo "$ports" | cut -d: -f1)
  local rdp_port=$(echo "$ports" | cut -d: -f2)
  
  echo ""
  echo "Creating Windows container '$name'..."
  [ "$FRESH_INSTALL" = "true" ] && echo "  Mode: Fresh installation"
  [ "$FRESH_INSTALL" != "true" ] && echo "  Mode: Cloned from golden"
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
  
  log_action "Created container: $name (Web: $web_port, RDP: $rdp_port)"
  echo ""
  echo "Container '$name' created!"
  echo ""
  echo "Access:"
  echo "  Web Viewer: http://localhost:$web_port"
  echo "  RDP:        localhost:$rdp_port (user: $WIN_USERNAME, pass: $WIN_PASSWORD)"
  echo ""
  echo "Commands:"
  echo "  $0 web $name    # Open web viewer"
  echo "  $0 rdp $name    # Connect via RDP"
  echo "  $0 stop $name   # Stop container"
}

start_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  check_kvm
  
  podman start "$name"
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
}

connect_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  local port_info=$(get_container_ports "$name")
  if [ -n "$port_info" ]; then
    local web_port=$(echo "$port_info" | cut -d: -f1)
    local rdp_port=$(echo "$port_info" | cut -d: -f2)
    
    echo "Connection Info for '$name':"
    echo ""
    echo "Web Viewer:"
    echo "  URL: http://localhost:$web_port"
    echo ""
    echo "RDP (recommended):"
    echo "  Host: localhost:$rdp_port"
    echo "  Username: Docker"
    echo "  Password: admin"
    echo ""
    echo "Commands:"
    echo "  $0 web $name"
    echo "  $0 rdp $name"
  else
    echo "Port info not found. Checking container..."
    podman port "$name"
  fi
}

delete_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  if [ "$name" = "$GOLDEN_NAME" ]; then
    echo "Warning: This will delete the golden container."
    echo "Golden storage at $(get_golden_storage) will remain."
    read -p "Continue? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  fi
  
  echo "Stopping container '$name' (graceful Windows shutdown, up to 2 minutes)..."
  podman stop -t 120 "$name" 2>/dev/null
  podman rm "$name"
  
  sed -i "/:$name$/d" "$PORT_TRACK_FILE" 2>/dev/null
  
  log_action "Deleted container: $name"
  echo "Container '$name' removed"
  
  local storage_path=$(get_storage_path "$name")
  if [ -d "$storage_path" ]; then
    echo ""
    echo "Storage remains at: $storage_path"
    read -p "Delete storage too? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      rm -rf "$storage_path"
      echo "Storage deleted"
    fi
  fi
}

restart_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  echo "Restarting '$name' (may take up to 2 minutes)..."
  podman restart -t 120 "$name"
  log_action "Restarted container: $name"
  echo "Container '$name' restarted"
}

stop_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  echo "Stopping '$name' gracefully (Windows shutdown, up to 2 minutes)..."
  podman stop -t 120 "$name"
  log_action "Stopped container: $name"
  echo "Container '$name' stopped"
}

force_stop_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
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
    local state=$(podman inspect --format='{{.State.Status}}' "$GOLDEN_NAME")
    if [ "$state" != "running" ]; then
      echo "Starting golden container..."
      podman start "$GOLDEN_NAME"
    fi
  else
    echo "Creating golden container..."
    
    # Check if we have existing storage
    local version_env=""
    if [ ! -f "$golden_storage/data.qcow2" ]; then
      echo "No existing Windows installation found."
      echo "Will create fresh Windows $WIN_VERSION installation."
      version_env="-e VERSION=$WIN_VERSION"
    else
      echo "Using existing Windows installation from $golden_storage"
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
    log_action "Created golden container: $GOLDEN_NAME"
  fi
  
  echo ""
  echo "Golden Windows container is running!"
  echo ""
  echo "Access:"
  echo "  Web: http://localhost:8006"
  echo "  RDP: localhost:3389 (user: Docker, pass: admin)"
  echo ""
  echo "Customize this Windows installation, then new containers will clone it."
  echo "Storage: $golden_storage"
}

# Snapshot management
create_snapshot() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  [ ! -d "$storage_path" ] && { echo "Error: No storage found for '$name'"; exit 1; }
  [ ! -f "$storage_path/data.qcow2" ] && { echo "Error: No disk image found"; exit 1; }
  
  # Stop container for consistent snapshot
  if podman container exists "$name" 2>/dev/null; then
    local state=$(podman inspect --format='{{.State.Status}}' "$name" 2>/dev/null)
    if [ "$state" = "running" ]; then
      echo "Stopping container for consistent snapshot..."
      podman stop -t 120 "$name"
    fi
  fi
  
  local snapshot_name="snapshot-$(date +%Y%m%d-%H%M%S)"
  local snapshot_dir="$storage_path/snapshots"
  mkdir -p "$snapshot_dir"
  
  echo "Creating snapshot '$snapshot_name'..."
  
  if command -v qemu-img &>/dev/null; then
    # Create internal QCOW2 snapshot (fast, space-efficient)
    qemu-img snapshot -c "$snapshot_name" "$storage_path/data.qcow2"
    echo "$snapshot_name" >> "$snapshot_dir/list.txt"
    echo "Snapshot created: $snapshot_name (internal)"
  else
    # Fallback: copy the disk
    cp "$storage_path/data.qcow2" "$snapshot_dir/${snapshot_name}.qcow2"
    echo "Snapshot created: $snapshot_name (full copy)"
  fi
  
  log_action "Created snapshot for $name: $snapshot_name"
  echo "Done! Restore with: $0 restore $name $snapshot_name"
}

restore_snapshot() {
  local name=$1
  local snapshot=$2
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  [ ! -d "$storage_path" ] && { echo "Error: No storage found for '$name'"; exit 1; }
  
  # Stop container
  if podman container exists "$name" 2>/dev/null; then
    local state=$(podman inspect --format='{{.State.Status}}' "$name" 2>/dev/null)
    if [ "$state" = "running" ]; then
      echo "Stopping container..."
      podman stop -t 120 "$name"
    fi
  fi
  
  if [ -z "$snapshot" ]; then
    # List available snapshots
    echo "Available snapshots for '$name':"
    if command -v qemu-img &>/dev/null; then
      qemu-img snapshot -l "$storage_path/data.qcow2" 2>/dev/null || echo "  (none)"
    fi
    if [ -d "$storage_path/snapshots" ]; then
      ls -1 "$storage_path/snapshots"/*.qcow2 2>/dev/null | xargs -I{} basename {} .qcow2 || true
    fi
    return
  fi
  
  echo "Restoring snapshot '$snapshot'..."
  
  if command -v qemu-img &>/dev/null; then
    # Try internal snapshot first
    if qemu-img snapshot -a "$snapshot" "$storage_path/data.qcow2" 2>/dev/null; then
      echo "Restored internal snapshot: $snapshot"
    elif [ -f "$storage_path/snapshots/${snapshot}.qcow2" ]; then
      cp "$storage_path/snapshots/${snapshot}.qcow2" "$storage_path/data.qcow2"
      echo "Restored from file: $snapshot"
    else
      echo "Error: Snapshot '$snapshot' not found"
      exit 1
    fi
  else
    if [ -f "$storage_path/snapshots/${snapshot}.qcow2" ]; then
      cp "$storage_path/snapshots/${snapshot}.qcow2" "$storage_path/data.qcow2"
      echo "Restored from file: $snapshot"
    else
      echo "Error: Snapshot '$snapshot' not found"
      exit 1
    fi
  fi
  
  log_action "Restored snapshot for $name: $snapshot"
  echo "Done! Start container with: $0 start $name"
}

list_snapshots() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  [ ! -d "$storage_path" ] && { echo "Error: No storage found for '$name'"; exit 1; }
  
  echo "Snapshots for '$name':"
  echo ""
  
  if command -v qemu-img &>/dev/null && [ -f "$storage_path/data.qcow2" ]; then
    echo "Internal snapshots:"
    qemu-img snapshot -l "$storage_path/data.qcow2" 2>/dev/null || echo "  (none)"
  fi
  
  if [ -d "$storage_path/snapshots" ]; then
    echo ""
    echo "File snapshots:"
    ls -lh "$storage_path/snapshots"/*.qcow2 2>/dev/null || echo "  (none)"
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
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  podman inspect "$name"
}

show_logs() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  podman logs -f "$name"
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
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  echo "Port mappings for '$name':"
  podman port "$name"
}

clean_stopped() {
  local count=$(podman ps -a --filter "status=exited" -q | wc -l)
  [ "$count" -eq 0 ] && { echo "No stopped containers to clean"; return; }
  
  echo "Found $count stopped containers."
  read -p "Remove them? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  
  podman container prune -f
  log_action "Cleaned stopped containers"
  echo "Cleaned $count stopped containers"
}

clean_all_containers() {
  echo "This will stop and remove ALL containers except golden."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  
  for cid in $(podman ps -a -q); do
    [ -z "$cid" ] && continue
    cname=$(podman inspect --format='{{.Name}}' "$cid" | sed 's|^/||')
    if [ "$cname" != "$GOLDEN_NAME" ]; then
      echo "Removing $cname..."
      podman stop -t 120 "$cid" 2>/dev/null
      podman rm "$cid"
      sed -i "/:$cname$/d" "$PORT_TRACK_FILE" 2>/dev/null
    fi
  done
  
  log_action "Cleaned all containers except golden"
  echo "Done"
}

stop_all_containers() {
  echo "This will stop all running containers except golden."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Aborted."; return; }
  
  for cid in $(podman ps -q); do
    [ -z "$cid" ] && continue
    cname=$(podman inspect --format='{{.Name}}' "$cid" | sed 's|^/||')
    if [ "$cname" != "$GOLDEN_NAME" ]; then
      echo "Stopping $cname..."
      podman stop -t 120 "$cid"
    fi
  done
  
  log_action "Stopped all containers except golden"
  echo "Done"
}

clone_container() {
  local source=$1
  local target=$2
  [ -z "$source" ] || [ -z "$target" ] && { echo "Error: Source and target names required"; exit 1; }
  
  podman container exists "$target" 2>/dev/null && { echo "Error: Target '$target' already exists"; exit 1; }
  
  local source_storage=$(get_storage_path "$source")
  local target_storage=$(get_storage_path "$target")
  
  [ ! -d "$source_storage" ] && { echo "Error: Source storage not found"; exit 1; }
  [ ! -f "$source_storage/data.qcow2" ] && { echo "Error: Source disk not found"; exit 1; }
  
  # Stop source for consistent copy
  if podman container exists "$source" 2>/dev/null; then
    local state=$(podman inspect --format='{{.State.Status}}' "$source")
    if [ "$state" = "running" ]; then
      echo "Stopping source container for consistent clone..."
      podman stop -t 120 "$source"
    fi
  fi
  
  echo "Cloning storage..."
  mkdir -p "$target_storage"
  
  if command -v qemu-img &>/dev/null; then
    qemu-img create -f qcow2 -b "$source_storage/data.qcow2" -F qcow2 "$target_storage/data.qcow2"
    echo "Created CoW clone"
  else
    cp "$source_storage/data.qcow2" "$target_storage/data.qcow2"
    echo "Created full copy"
  fi
  
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
    -v "$target_storage:/storage:Z" \
    "$BASE_IMAGE"
  
  register_ports "$target" "$web_port" "$rdp_port"
  log_action "Cloned: $source -> $target"
  
  echo "Cloned '$source' to '$target'"
  echo "  Web: http://localhost:$web_port"
  echo "  RDP: localhost:$rdp_port"
}

rename_container() {
  local old=$1
  local new=$2
  [ -z "$old" ] || [ -z "$new" ] && { echo "Error: Old and new names required"; exit 1; }
  check_container_exists "$old" || exit 1
  
  podman rename "$old" "$new"
  
  # Update port tracking
  local port_info=$(get_container_ports "$old")
  if [ -n "$port_info" ]; then
    local web_port=$(echo "$port_info" | cut -d: -f1)
    local rdp_port=$(echo "$port_info" | cut -d: -f2)
    sed -i "/:$old$/d" "$PORT_TRACK_FILE" 2>/dev/null
    register_ports "$new" "$web_port" "$rdp_port"
  fi
  
  # Rename storage directory
  local old_storage=$(get_storage_path "$old")
  local new_storage=$(get_storage_path "$new")
  if [ -d "$old_storage" ]; then
    mv "$old_storage" "$new_storage"
  fi
  
  log_action "Renamed: $old -> $new"
  echo "Renamed '$old' to '$new'"
}

export_storage() {
  local name=$1
  local path=$2
  [ -z "$name" ] || [ -z "$path" ] && { echo "Error: Container name and path required"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  [ ! -f "$storage_path/data.qcow2" ] && { echo "Error: No disk image found"; exit 1; }
  
  echo "Exporting Windows disk..."
  
  if command -v pigz &>/dev/null; then
    pigz -c "$storage_path/data.qcow2" > "$path"
  else
    gzip -c "$storage_path/data.qcow2" > "$path"
  fi
  
  log_action "Exported storage: $name to $path"
  echo "Exported to: $path"
}

import_storage() {
  local path=$1
  local name=$2
  [ -z "$path" ] || [ -z "$name" ] && { echo "Error: Path and container name required"; exit 1; }
  [ ! -f "$path" ] && { echo "Error: File not found: $path"; exit 1; }
  
  local storage_path=$(get_storage_path "$name")
  mkdir -p "$storage_path"
  
  echo "Importing Windows disk..."
  
  if [[ "$path" == *.gz ]]; then
    if command -v pigz &>/dev/null; then
      pigz -dc "$path" > "$storage_path/data.qcow2"
    else
      gunzip -c "$path" > "$storage_path/data.qcow2"
    fi
  else
    cp "$path" "$storage_path/data.qcow2"
  fi
  
  log_action "Imported storage: $path to $name"
  echo "Imported to: $storage_path"
  echo "Create container with: $0 create $name"
}

remove_image() {
  local image=$1
  [ -z "$image" ] && { echo "Error: Image name required"; exit 1; }
  check_image_exists "$image" || exit 1
  podman rmi "$image"
  log_action "Removed image: $image"
  echo "Image '$image' removed"
}

open_rdp() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  local port_info=$(get_container_ports "$name")
  local rdp_port="3389"
  [ -n "$port_info" ] && rdp_port=$(echo "$port_info" | cut -d: -f2)
  
  if command -v xfreerdp &>/dev/null; then
    echo "Connecting to localhost:$rdp_port..."
    xfreerdp /v:localhost:$rdp_port /u:Docker /p:admin /dynamic-resolution +clipboard &
  elif command -v xfreerdp3 &>/dev/null; then
    echo "Connecting to localhost:$rdp_port..."
    xfreerdp3 /v:localhost:$rdp_port /u:Docker /p:admin /dynamic-resolution +clipboard &
  else
    echo "xfreerdp not found. Install: apt install freerdp2-x11"
    echo ""
    echo "Manual: localhost:$rdp_port (Docker/admin)"
  fi
}

open_web() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  check_container_exists "$name" || exit 1
  
  local port_info=$(get_container_ports "$name")
  local web_port="8006"
  [ -n "$port_info" ] && web_port=$(echo "$port_info" | cut -d: -f1)
  
  local url="http://localhost:$web_port"
  
  if command -v xdg-open &>/dev/null; then
    xdg-open "$url" &
  elif command -v firefox &>/dev/null; then
    firefox "$url" &
  else
    echo "Open: $url"
  fi
  
  echo "Opening: $url"
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
  connect) connect_container "$2" ;;
  create) shift; create_container "$@" ;;
  delete) delete_container "$2" ;;
  export-storage) export_storage "$2" "$3" ;;
  force-stop) force_stop_container "$2" ;;
  golden) shift; golden_shell "$@" ;;
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
  web) open_web "$2" ;;
  *) usage ;;
esac

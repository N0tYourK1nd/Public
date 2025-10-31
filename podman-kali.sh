#!/bin/bash

BASE_IMAGE="docker.io/kalilinux/kali-rolling:latest"
GOLDEN_NAME="kali-golden"
GOLDEN_IMAGE="kali-golden:latest"
LOG_DIR="$HOME/.kali-pentest/logs"
MOUNT_DIR="/mnt/container"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

usage() {
  cat << EOF
Usage: $0 {command} [options]

Container Lifecycle:
  create [name]           - Create new CoW container from golden image with X11
  start [name]            - Start a stopped container
  connect [name]          - Connect interactively to a named container (bash)
  delete [name]           - Stop and remove a container
  exec [name] [cmd...]    - Execute command in container without interactive shell
  restart [name]          - Restart a stopped container
  stop [name]             - Stop a running container
  pause [name]            - Pause a running container
  unpause [name]          - Unpause a paused container

Golden Image Management:
  golden                  - Run shell in golden container for admin/updates
  commit                  - Snapshot changes in golden container to golden image
  update-base             - Pull latest upstream Kali image
  recreate-golden         - Destroy golden container and recreate from base image
  restore-golden          - Recreate golden container from existing golden image

Container Inspection:
  list                    - List all containers (running and stopped)
  list-running            - List running containers
  list-stopped            - List stopped containers
  inspect [name]          - Show detailed container info
  logs [name]             - Show container logs
  stats [name]            - Show container resource usage
  
Batch Operations:
  clean                   - Stop and remove all stopped containers
  clean-all               - Stop and remove ALL containers (excluding golden)
  stop-all                - Stop all running containers (excluding golden)
  cleanup-golden          - Remove old golden image versions

Utilities:
  clone [name] [new_name]       - Clone an existing container to a new one
  rename [old] [new]            - Rename a container
  export-container [name] [path]  - Export container as tar (supports gzip)
  import-image [tar_path] [name]  - Import container from tar (supports gzip)
  mount [name]                  - Mount container filesystem for inspection
  umount [name]                - Unmount container filesystem
  list-images                   - List all local images
  remove-image [image]          - Remove a local image

Help:
  help                         - Show this help message
  version                      - Show script version

EOF
  exit 1
}

log_action() {
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $*" >> "$LOG_DIR/kali-podman.log"
}

check_container_exists() {
  if ! podman container exists "$1"; then
    echo "Error: Container '$1' does not exist"
    return 1
  fi
  return 0
}

check_image_exists() {
  if ! podman image exists "$1"; then
    echo "Error: Image '$1' does not exist"
    return 1
  fi
  return 0
}

ensure_xauth() {
  if [ ! -f "$HOME/.Xauthority" ] || [ ! -s "$HOME/.Xauthority" ]; then
    xauth add $DISPLAY . $(mcookie)
  fi
}

create_container() {
  local name=$1
  [ -z "$name" ] && { echo "Error: Container name required"; exit 1; }
  podman container exists "$name" && { echo "Error: Container '$name' already exists"; exit 1; }
  check_image_exists "$GOLDEN_IMAGE" || exit 1
  
  sudo mkdir -p "$MOUNT_DIR/$name"
  
  podman run -d --name "$name" \
    --userns=keep-id \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
    -v $HOME/.Xauthority:/root/.Xauthority:ro \
    --device /dev/dri \
    --security-opt label=disable \
    --ipc=host \
    -v "$MOUNT_DIR/$name:/mnt/share" \
    "$GOLDEN_IMAGE" tail -f /dev/null

  log_action "Created container: $name"
  echo "✓ Container '$name' created"
  echo "  Bidirectional sync: $MOUNT_DIR/$name ↔ /mnt/share"
}




start_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  podman start "$name"
  log_action "Started container: $name"
  echo "✓ Container '$name' started"
}

connect_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  log_action "Connected to container: $name"
  podman exec -it --user root "$name" bash
}

exec_command() {
  local name=$1
  shift
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  log_action "Executed command in $name: $*"
  podman exec -it --user root "$name" "$@"
}

delete_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  if [ "$name" = "$GOLDEN_NAME" ]; then
    echo "Warning: Deleting golden container. Golden image will remain."
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Aborted."
      return
    fi
  fi
  
  podman stop "$name" 2>/dev/null
  podman rm "$name"
  
  log_action "Deleted container: $name"
  echo "✓ Container '$name' stopped and removed"
}

restart_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  podman restart "$name"
  log_action "Restarted container: $name"
  echo "✓ Container '$name' restarted"
}

stop_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  podman stop "$name"
  log_action "Stopped container: $name"
  echo "✓ Container '$name' stopped"
}

pause_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  podman pause "$name"
  log_action "Paused container: $name"
  echo "✓ Container '$name' paused"
}

unpause_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi
  
  check_container_exists "$name" || exit 1
  
  podman unpause "$name"
  log_action "Unpaused container: $name"
  echo "✓ Container '$name' unpaused"
}

golden_shell() {
  if ! podman container exists "$GOLDEN_NAME"; then
    echo "Golden container does not exist. Creating from '$BASE_IMAGE'..."
    mkdir -p "$MOUNT_DIR/$GOLDEN_NAME"
    podman run -dit --name "$GOLDEN_NAME" \
      --userns=keep-id \
      -e DISPLAY=$DISPLAY \
      -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
      -v $HOME/.Xauthority:/root/.Xauthority:ro \
      --device /dev/dri \
      --security-opt label=disable \
      --ipc=host \
      -v "$MOUNT_DIR/$GOLDEN_NAME:/mnt/share" \
      "$BASE_IMAGE" bash

    log_action "Created golden container: $GOLDEN_NAME"
    echo "✓ Golden container '$GOLDEN_NAME' created"
  fi
  
  log_action "Entered golden shell"
  podman exec -it --user root "$GOLDEN_NAME" bash
}


restore-golden() {
  if ! check_image_exists "$GOLDEN_IMAGE"; then
    echo "Error: Golden image '$GOLDEN_IMAGE' not found"
    exit 1
  fi
  
  mkdir -p "$MOUNT_DIR/$GOLDEN_NAME"
  
  echo "Restoring golden container from existing image '$GOLDEN_IMAGE'..."
  podman run -dit --replace --name "$GOLDEN_NAME" \
    --userns=keep-id \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
    -v $HOME/.Xauthority:/root/.Xauthority:ro \
    --device /dev/dri \
    --security-opt label=disable \
    --ipc=host \
    -v "$MOUNT_DIR/$GOLDEN_NAME:/mnt/share" \
    "$GOLDEN_IMAGE" bash

  
  log_action "Restored golden container from existing image: $GOLDEN_IMAGE"
  echo "✓ Golden container '$GOLDEN_NAME' restored"
}




commit_golden() {
  if ! check_container_exists "$GOLDEN_NAME"; then
    echo "Error: Golden container '$GOLDEN_NAME' not running/found"
    exit 1
  fi
  
  podman commit "$GOLDEN_NAME" "$GOLDEN_IMAGE"
  log_action "Committed golden container to image: $GOLDEN_IMAGE"
  echo "✓ Golden container committed to '$GOLDEN_IMAGE'"
}

update_base() {
  echo "Pulling latest Kali base image..."
  podman pull "$BASE_IMAGE"
  log_action "Updated base image: $BASE_IMAGE"
  echo "✓ Base image updated"
}

recreate_golden() {
  echo "This will delete the golden container and recreate from base image."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    return
  fi
  
  if podman container exists "$GOLDEN_NAME"; then
    podman stop "$GOLDEN_NAME" 2>/dev/null
    podman rm "$GOLDEN_NAME"
    log_action "Deleted golden container"
  fi
  
  mkdir -p "$MOUNT_DIR/$GOLDEN_NAME"
  podman run -dit --name "$GOLDEN_NAME" \
    --userns=keep-id \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
    --device /dev/dri \
    --security-opt label=disable \
    --ipc=host \
    -v "$MOUNT_DIR/$GOLDEN_NAME:/mnt/share" \
    "$BASE_IMAGE" bash

  
  log_action "Recreated golden container from base image"
  echo "✓ Golden container recreated from '$BASE_IMAGE'"
  echo "  Files sync: $MOUNT_DIR/$GOLDEN_NAME ↔ /mnt/share"
}

list_containers() {
  echo "All containers:"
  podman ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
}

list_running() {
  echo "Running containers:"
  podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
}

list_stopped() {
  echo "Stopped containers:"
  podman ps -a --filter "status=exited" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
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
  
  podman logs -f "$name"
}

show_stats() {
  local name=$1
  if [ -z "$name" ]; then
    echo "All container stats:"
    podman stats
  else
    check_container_exists "$name" || exit 1
    podman stats "$name"
  fi
}

clean_stopped() {
  local count=$(podman ps -a --filter "status=exited" -q | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "No stopped containers to clean"
    return
  fi
  
  echo "Found $count stopped containers. Removing..."
  podman container prune -f
  log_action "Cleaned stopped containers"
  echo "✓ Cleaned $count stopped containers"
}

clean_all_containers() {
  echo "This will stop and remove ALL containers except the golden container."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    return
  fi
  
  podman ps -a -q --filter "label!=golden" | while read cid; do
    cname=$(podman inspect --format='{{.Name}}' "$cid" | sed 's|^/||')
    if [ "$cname" != "$GOLDEN_NAME" ]; then
      podman stop "$cid" 2>/dev/null
      podman rm "$cid"
    fi
  done
  
  log_action "Cleaned all containers except golden"
  echo "✓ All containers removed (except golden)"
}

stop_all_containers() {
  echo "This will stop all running containers except the golden container."
  read -p "Continue? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    return
  fi
  
  podman ps -q --filter "label!=golden" | while read cid; do
    cname=$(podman inspect --format='{{.Name}}' "$cid" | sed 's|^/||')
    if [ "$cname" != "$GOLDEN_NAME" ]; then
      podman stop "$cid"
    fi
  done
  
  log_action "Stopped all containers except golden"
  echo "✓ All containers stopped (except golden)"
}

cleanup_golden_images() {
  echo "Removing dangling golden images..."
  podman image prune -f
  log_action "Cleaned up golden images"
  echo "✓ Cleaned up old golden images"
}

clone_container() {
  local source=$1
  local target=$2
  if [ -z "$source" ] || [ -z "$target" ]; then
    echo "Error: Source and target container names required"
    exit 1
  fi
  
  check_container_exists "$source" || exit 1
  
  if podman container exists "$target"; then
    echo "Error: Target container '$target' already exists"
    exit 1
  fi
  
  local source_image=$(podman inspect --format='{{.Image}}' "$source")
  podman run -d --name "$target" \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
    --device /dev/dri \
    --security-opt label=disable \
    --ipc=host \
    "$source_image" tail -f /dev/null
  
  log_action "Cloned container: $source -> $target"
  echo "✓ Container '$source' cloned to '$target'"
}

rename_container() {
  local old=$1
  local new=$2
  if [ -z "$old" ] || [ -z "$new" ]; then
    echo "Error: Old and new container names required"
    exit 1
  fi
  
  check_container_exists "$old" || exit 1
  
  podman rename "$old" "$new"
  log_action "Renamed container: $old -> $new"
  echo "✓ Container renamed: '$old' -> '$new'"
}

export_container() {
  local name=$1
  local path=$2
  if [ -z "$name" ] || [ -z "$path" ]; then
    echo "Error: Container name and export path required"
    exit 1
  fi

  check_container_exists "$name" || exit 1

  local tmp_image="tmp-export-$name:latest"
  podman commit "$name" "$tmp_image"

  # Add .gz suffix if missing
  if [[ "$path" != *.gz ]]; then
    path="$path.gz"
  fi

  # Save and gzip on the fly
  podman save "$tmp_image" | gzip -c > "$path"

  podman rmi "$tmp_image"

  log_action "Exported container (compressed): $name to $path"
  echo "✓ Container '$name' committed and compressed exported to '$path'"
}


import_image() {
  local tar_path=$1
  local name=$2
  if [ -z "$tar_path" ] || [ -z "$name" ]; then
    echo "Error: Tar path and image name required"
    exit 1
  fi

  if [ ! -f "$tar_path" ]; then
    echo "Error: Tar file '$tar_path' not found"
    exit 1
  fi

  # Detect gzip compressed files by extension
  if [[ "$tar_path" == *.gz ]]; then
    gunzip -c "$tar_path" | podman load
  else
    podman load -i "$tar_path"
  fi

  log_action "Imported (possibly compressed) image from: $tar_path as $name"
  echo "✓ Image imported from '$tar_path'"
}

remove_image() {
  local image=$1
  if [ -z "$image" ]; then
    echo "Error: Image name required"
    exit 1
  fi
  
  check_image_exists "$image" || exit 1
  
  podman rmi "$image"
  log_action "Removed image: $image"
  echo "✓ Image '$image' removed"
}

version() {
  echo "kali-podman.sh v1.0.0"
}


mount_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi

  sudo podman container exists "$name" || { echo "Error: Container '$name' does not exist"; exit 1; }

  local mount_dir="/mnt/container-$name"
  
  sudo mkdir -p "$mount_dir"
  local mountpoint=$(sudo podman mount "$name") || { echo "Failed to mount"; exit 1; }
  sudo mount --bind "$mountpoint" "$mount_dir" || { echo "Bind mount failed"; exit 1; }

  echo "Container '$name' filesystem mounted at:"
  echo "  $mount_dir"
  echo "Unmount with: $0 umount $name"

  log_action "Mounted container filesystem: $name at $mount_dir"
}

umount_container() {
  local name=$1
  if [ -z "$name" ]; then
    echo "Error: Container name required"
    exit 1
  fi

  local mount_dir="/mnt/container-$name"
  sudo umount "$mount_dir" 2>/dev/null
  sudo podman unmount "$name" 2>/dev/null

  log_action "Unmounted container filesystem: $name"
  echo "Container '$name' filesystem unmounted."
}


# Main argument parsing
case $1 in
  create)
    create_container "$2"
    ;;
  start)
    start_container "$2"
    ;;
  connect)
    connect_container "$2"
    ;;
  exec)
    shift
    exec_command "$@"
    ;;
  delete)
    delete_container "$2"
    ;;
  restart)
    restart_container "$2"
    ;;
  stop)
    stop_container "$2"
    ;;
  pause)
    pause_container "$2"
    ;;
  unpause)
    unpause_container "$2"
    ;;
  golden)
    golden_shell
    ;;
  commit)
    commit_golden
    ;;
  update-base)
    update_base
    ;;
  recreate-golden)
    recreate_golden
    ;;
  list)
    list_containers
    ;;
  list-running)
    list_running
    ;;
  list-stopped)
    list_stopped
    ;;
  inspect)
    inspect_container "$2"
    ;;
  logs)
    show_logs "$2"
    ;;
  stats)
    show_stats "$2"
    ;;
  clean)
    clean_stopped
    ;;
  clean-all)
    clean_all_containers
    ;;
  stop-all)
    stop_all_containers
    ;;
  cleanup-golden)
    cleanup_golden_images
    ;;
  clone)
    clone_container "$2" "$3"
    ;;
  rename)
    rename_container "$2" "$3"
    ;;
  export-container)
    export_container "$2" "$3"
    ;;
  import-image)
    import_image "$2" "$3"
    ;;
  list-images)
    list_images
    ;;
  remove-image)
    remove_image "$2"
    ;;
  help)
    usage
    ;;
  mount)
    mount_container "$2"
    ;;
  umount)
    umount_container "$2"
    ;;
  restore-golden)
    restore-golden
    ;;
  version)
    version
    ;;
  *)
    usage
    ;;
esac

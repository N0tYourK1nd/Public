#!/usr/bin/env python3
"""
labctl.py - NYK
Usage: labctl [--dry-run] [--verbose] <command> [args]
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import termios
import tty
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple

VERSION = "1.0.0"

# ── SIGINT ─────────────────────────────────────────────────────────────────────
def _sigint(sig, frame):  # noqa
    print("\nInterrupted.", file=sys.stderr)
    sys.exit(130)

signal.signal(signal.SIGINT, _sigint)

# ── Colors ─────────────────────────────────────────────────────────────────────
class Colors:
    _on = sys.stdout.isatty()
    RED    = "\033[0;31m"  if _on else ""
    GREEN  = "\033[0;32m"  if _on else ""
    YELLOW = "\033[1;33m"  if _on else ""
    BLUE   = "\033[0;34m"  if _on else ""
    CYAN   = "\033[0;36m"  if _on else ""
    BOLD   = "\033[1m"     if _on else ""
    DIM    = "\033[2m"     if _on else ""
    RESET  = "\033[0m"     if _on else ""

def _p(sym, col, msg):
    print(f"{col}{sym}{Colors.RESET} {msg}")

def info(msg):    _p("ℹ", Colors.BLUE,   msg)
def warn(msg):    _p("⚠", Colors.YELLOW, msg)
def success(msg): _p("✔", Colors.GREEN,  msg)
def header(msg):  print(f"\n{Colors.BOLD}{msg}{Colors.RESET}")

def error(msg, code=1):
    _p("✖", Colors.RED, msg)
    if code:
        sys.exit(code)

def confirm(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    print(f"{prompt} [{hint}] ", end="", flush=True)
    try:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except (termios.error, AttributeError, OSError):
        ch = input()
    print()
    if ch in ("", "\r", "\n"):
        return default
    return ch.lower() == "y"

# ── Constants / defaults ───────────────────────────────────────────────────────
LABCTL_DIR  = Path.home() / ".labctl"
SHARED_DIR  = LABCTL_DIR / "shared"
LABS_DIR    = LABCTL_DIR / "labs"

DEFAULTS: dict = {
    "linux": {
        "base_image":  "docker.io/kalilinux/kali-rolling:latest",
        "golden_name": "kali-golden",
        "log_dir":     str(Path.home() / ".kali-pentest/logs"),
        "mount_dir":   "/mnt/container",
    },
    "windows": {
        "base_image":       "docker.io/dockurr/windows:latest",
        "golden_name":      "windows-golden",
        "log_dir":          str(Path.home() / ".windows-pentest/logs"),
        "storage_base":     str(Path.home() / ".windows-pentest/storage"),
        "default_version":  "11",
        "default_ram":      "4G",
        "default_cpu":      "2",
        "default_disk":     "64G",
        "default_user":     "Docker",
        "default_pass":     "admin",
    },
    "network": {
        "name":    "lab-net",
        "subnet":  "10.88.0.0/24",
        "gateway": "10.88.0.1",
    },
    "shared_dir": str(SHARED_DIR),
}

# ── Config ─────────────────────────────────────────────────────────────────────
class Config:
    def __init__(self):
        LABCTL_DIR.mkdir(parents=True, exist_ok=True)
        SHARED_DIR.mkdir(parents=True, exist_ok=True)
        LABS_DIR.mkdir(parents=True, exist_ok=True)
        self._cfg_f  = LABCTL_DIR / "config.json"
        self._reg_f  = LABCTL_DIR / "containers.json"
        self._port_f = LABCTL_DIR / "ports.json"
        self._fwd_f  = LABCTL_DIR / "forwards.json"
        self._cfg  = self._load(self._cfg_f,  {})
        self._reg  = self._load(self._reg_f,  {})
        self._port = self._load(self._port_f, {})
        self._fwd  = self._load(self._fwd_f,  {})

    # ── internal ──
    @staticmethod
    def _load(p: Path, default: dict) -> dict:
        if p.exists():
            try:
                return json.loads(p.read_text())
            except Exception:
                return dict(default)
        return dict(default)

    @staticmethod
    def _save(p: Path, d: dict):
        p.write_text(json.dumps(d, indent=2, default=str))

    # ── config get/set/show/reset ──
    def get(self, key: str, default=None):
        """Get value by dotted key, falling back to DEFAULTS."""
        parts = key.split(".")
        val, dval = self._cfg, DEFAULTS
        for p in parts:
            val  = val.get(p)  if isinstance(val,  dict) else None
            dval = dval.get(p) if isinstance(dval, dict) else None
        return val if val is not None else (dval if dval is not None else default)

    def set_key(self, key: str, value: str):
        parts = key.split(".")
        d = self._cfg
        for p in parts[:-1]:
            d = d.setdefault(p, {})
        d[parts[-1]] = value
        self._save(self._cfg_f, self._cfg)

    def show(self):
        import copy
        merged = copy.deepcopy(DEFAULTS)
        def _merge(base, over):
            for k, v in over.items():
                if isinstance(v, dict) and isinstance(base.get(k), dict):
                    _merge(base[k], v)
                else:
                    base[k] = v
        _merge(merged, self._cfg)
        print(json.dumps(merged, indent=2))

    def reset(self):
        self._cfg = {}
        self._save(self._cfg_f, {})

    # ── container registry ──
    def register(self, name: str, ctype: str, meta: dict = None):
        self._reg[name] = {
            "type": ctype,
            "created": datetime.now().isoformat(),
            **(meta or {}),
        }
        self._save(self._reg_f, self._reg)

    def unregister(self, name: str):
        self._reg.pop(name, None)
        self._save(self._reg_f, self._reg)

    def rename_reg(self, old: str, new: str):
        if old in self._reg:
            self._reg[new] = self._reg.pop(old)
            self._reg[new]["name"] = new
            self._save(self._reg_f, self._reg)

    def get_type(self, name: str) -> Optional[str]:
        e = self._reg.get(name)
        return e.get("type") if e else None

    def get_registry(self) -> dict:
        return dict(self._reg)

    def get_names_by_type(self, ctype: str) -> List[str]:
        """Return all registered container names matching a type."""
        return [n for n, e in self._reg.items() if e.get("type") == ctype]

    # ── port tracking ──
    def _legacy_port_file(self) -> Path:
        return Path.home() / ".windows-pentest" / "ports"

    def get_ports(self, name: str) -> Optional[Tuple[int, int]]:
        e = self._port.get(name)
        if e:
            return e["web"], e["rdp"]
        lf = self._legacy_port_file()
        if lf.exists():
            for line in lf.read_text().splitlines():
                parts = line.strip().split(":")
                if len(parts) == 3 and parts[2] == name:
                    try:
                        return int(parts[0]), int(parts[1])
                    except ValueError:
                        pass
        return None

    def register_ports(self, name: str, web: int, rdp: int):
        self._port[name] = {"web": web, "rdp": rdp}
        self._save(self._port_f, self._port)
        lf = self._legacy_port_file()
        lf.parent.mkdir(parents=True, exist_ok=True)
        if not lf.exists():
            lf.touch()
        lines = [l for l in lf.read_text().splitlines()
                 if not (l.strip().endswith(f":{name}") and len(l.split(":")) == 3)]
        lines.append(f"{web}:{rdp}:{name}")
        lf.write_text("\n".join(lines) + "\n")

    def unregister_ports(self, name: str):
        self._port.pop(name, None)
        self._save(self._port_f, self._port)
        lf = self._legacy_port_file()
        if lf.exists():
            lines = [l for l in lf.read_text().splitlines()
                     if not (l.strip().endswith(f":{name}") and len(l.split(":")) == 3)]
            lf.write_text("\n".join(lines) + ("\n" if lines else ""))

    def rename_ports(self, old: str, new: str):
        e = self._port.pop(old, None)
        if e:
            self._port[new] = e
            self._save(self._port_f, self._port)
        lf = self._legacy_port_file()
        if lf.exists():
            lines = []
            for l in lf.read_text().splitlines():
                parts = l.strip().split(":")
                if len(parts) == 3 and parts[2] == old:
                    lines.append(f"{parts[0]}:{parts[1]}:{new}")
                else:
                    lines.append(l)
            lf.write_text("\n".join(lines) + "\n")

    def get_next_ports(self) -> Tuple[int, int]:
        used_web: set = {v["web"] for v in self._port.values()}
        lf = self._legacy_port_file()
        if lf.exists():
            for line in lf.read_text().splitlines():
                p = line.strip().split(":")
                if len(p) == 3:
                    try:
                        used_web.add(int(p[0]))
                    except ValueError:
                        pass
        listening = self._listening_ports()
        for offset in range(101):
            w, r = 8006 + offset, 3389 + offset
            if w not in used_web and w not in listening and r not in listening:
                return w, r
        raise RuntimeError("No available ports in range 8006-8106")

    # ── port forward tracking ──
    def get_forwards(self) -> dict:
        return dict(self._fwd)

    def add_forward(self, rule_id: str, container: str, host_port: int,
                    container_port: int, proto: str, ip: str):
        self._fwd[rule_id] = {
            "container":      container,
            "host_port":      host_port,
            "container_port": container_port,
            "proto":          proto,
            "ip":             ip,
            "created":        datetime.now().isoformat(),
        }
        self._save(self._fwd_f, self._fwd)

    def remove_forward(self, rule_id: str):
        self._fwd.pop(rule_id, None)
        self._save(self._fwd_f, self._fwd)

    @staticmethod
    def _listening_ports() -> set:
        try:
            out = subprocess.run(["ss", "-tuln"], capture_output=True, text=True).stdout
            ports: set = set()
            for line in out.splitlines():
                for tok in line.split():
                    if ":" in tok:
                        try:
                            ports.add(int(tok.rsplit(":", 1)[1]))
                        except (ValueError, IndexError):
                            pass
            return ports
        except Exception:
            return set()


# ── Podman ─────────────────────────────────────────────────────────────────────
class Podman:
    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose

    def _run(self, args: list, check=True, capture=False,
             sudo=False, input_text=None) -> subprocess.CompletedProcess:
        cmd = (["sudo", "podman"] if sudo else ["podman"]) + args
        if self.verbose or self.dry_run:
            print(f"{Colors.DIM}$ {' '.join(str(x) for x in cmd)}{Colors.RESET}")
        if self.dry_run:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.run(cmd, check=check,
                              capture_output=capture, text=True,
                              input=input_text)

    def run(self, args: list, check=True, capture=False) -> subprocess.CompletedProcess:
        return self._run(args, check=check, capture=capture)

    def sudo_run(self, args: list, check=True, capture=False) -> subprocess.CompletedProcess:
        return self._run(args, check=check, capture=capture, sudo=True)

    def container_exists(self, name: str) -> bool:
        return self._run(["container", "exists", name],
                         check=False, capture=True).returncode == 0

    def image_exists(self, name: str) -> bool:
        return self._run(["image", "exists", name],
                         check=False, capture=True).returncode == 0

    def is_running(self, name: str) -> bool:
        return self.get_state(name) == "running"

    def get_state(self, name: str) -> str:
        r = self._run(["inspect", "--format={{.State.Status}}", name],
                      check=False, capture=True)
        return r.stdout.strip() if r.returncode == 0 else ""

    def get_ip(self, name: str, network: str = "") -> str:
        if network:
            fmt = ('{{range $k,$v := .NetworkSettings.Networks}}'
                   '{{if eq $k "' + network + '"}}{{$v.IPAddress}}{{end}}{{end}}')
        else:
            fmt = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
        r = self._run(["inspect", f"--format={fmt}", name],
                      check=False, capture=True)
        return r.stdout.strip() if r.returncode == 0 else ""

    def get_container_name(self, cid: str) -> str:
        """Get container name from a container ID."""
        r = self._run(["inspect", "--format={{.Name}}", cid],
                      capture=True, check=False)
        return r.stdout.strip().lstrip("/") if r.returncode == 0 else ""

    def get_all_container_names(self, running_only=False,
                                stopped_only=False) -> List[str]:
        """Return all podman container names matching the given filter."""
        args = ["ps", "-a", "--format={{.Names}}"]
        if running_only:
            args = ["ps", "--format={{.Names}}"]
        elif stopped_only:
            args = ["ps", "-a", "--filter", "status=exited",
                    "--format={{.Names}}"]
        r = self._run(args, capture=True, check=False)
        if r.returncode != 0 or not r.stdout.strip():
            return []
        return [n.strip() for n in r.stdout.strip().splitlines() if n.strip()]

    def get_used_ips(self, prefix: str = "") -> List[str]:
        r = self._run(["ps", "-aq"], check=False, capture=True)
        if r.returncode != 0 or not r.stdout.strip():
            return []
        ips: List[str] = []
        for cid in r.stdout.strip().splitlines():
            ir = self._run(
                ["inspect",
                 "--format={{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                 cid], check=False, capture=True)
            for ip in ir.stdout.strip().split():
                if ip and (not prefix or ip.startswith(prefix)):
                    ips.append(ip)
        return ips

    def network_exists(self, name: str) -> bool:
        return self._run(["network", "exists", name],
                         check=False, capture=True).returncode == 0

    def execvp(self, name: str, cmd: list,
               user: str = "root", workdir: str = "",
               sudo: bool = False):
        """Replace this process with an interactive podman exec."""
        prefix = ["sudo", "podman"] if sudo else ["podman"]
        full = prefix + ["exec", "-it", "--user", user]
        if workdir:
            full += ["--workdir", workdir]
        full += [name] + cmd
        if self.dry_run:
            print(f"{Colors.DIM}$ {' '.join(full)}{Colors.RESET}")
            return
        if self.verbose:
            print(f"{Colors.DIM}$ {' '.join(full)}{Colors.RESET}")
        os.execvp(full[0], full)

    def get_image_ref(self, ref: str) -> str:
        r = self.run(["inspect", "--format", "{{.ImageName}}", ref],
                     check=False, capture=True)
        img = (r.stdout or "").strip()
        if img:
            return img
        r = self.run(["inspect", "--format", "{{.Image}}", ref],
                     check=False, capture=True)
        return (r.stdout or "").strip()

    def resolve_ref(self, ref: str) -> list[str]:
        ref = (ref or "").strip()
        if not ref:
            return []

        # 1) Exact name
        if self.container_exists(ref):
            return [ref]

        # 2) Treat as ID (or unique ID prefix) -> name via inspect
        n = self.get_container_name(ref)
        if n:
            return [n.lstrip("/")]

        # 3) Prefix search over all containers (names + IDs)
        r = self.run(["ps", "-aq"], check=False, capture=True)
        ids = [x.strip() for x in (r.stdout or "").splitlines() if x.strip()]
        matches = []
        for cid in ids:
            name = self.get_container_name(cid).lstrip("/")
            if not name:
                continue
            if name == ref or name.startswith(ref) or cid.startswith(ref):
                matches.append(name)

        # De-dupe, stable order
        seen = set()
        out = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out



# ── NetworkManager ─────────────────────────────────────────────────────────────
class NetworkManager:
    def __init__(self, cfg: Config, podman: Podman):
        self.cfg    = cfg
        self.podman = podman

    @property
    def name(self) -> str:
        return self.cfg.get("network.name", "lab-net")

    @property
    def subnet(self) -> str:
        return self.cfg.get("network.subnet", "10.88.0.0/24")

    @property
    def gateway(self) -> str:
        return self.cfg.get("network.gateway", "10.88.0.1")

    def ensure(self):
        if not self.podman.network_exists(self.name):
            info(f"Creating network '{self.name}' ({self.subnet})…")
            self.podman.run([
                "network", "create",
                "--subnet", self.subnet,
                "--gateway", self.gateway,
                self.name,
            ])
            success(f"Network '{self.name}' created")

    def allocate_ip(self) -> str:
        prefix = self.subnet.rsplit(".", 1)[0]   # e.g. "10.88.0"
        # Collect IPs from live containers
        used = set(self.podman.get_used_ips(prefix + "."))
        # Also include IPs of stopped containers stored in the registry
        # so we never recycle an IP that belongs to a registered container
        for entry in self.cfg.get_registry().values():
            ip = entry.get("ip", "")
            if ip.startswith(prefix + "."):
                used.add(ip)
        # .1 is the host/gateway; guests start at .2 and increment
        for oct in range(2, 255):
            candidate = f"{prefix}.{oct}"
            if candidate not in used:
                return candidate
        raise RuntimeError(f"No available IPs in {self.subnet}")


# ── ForwardManager ─────────────────────────────────────────────────────────────
class ForwardManager:
    """Manage temporary host→container port forwards via iptables DNAT."""

    def __init__(self, cfg: Config, pod: Podman, dry_run=False, verbose=False):
        self.cfg      = cfg
        self.pod      = pod
        self.dry_run  = dry_run
        self.verbose  = verbose

    def _sys(self, args: list, check=True, capture=False):
        return _run_sys(args, check=check, capture=capture,
                        dry_run=self.dry_run, verbose=self.verbose)

    def _container_ip(self, name: str) -> str:
        """Return the container IP, preferring the registry over live inspect."""
        entry = self.cfg.get_registry().get(name, {})
        ip = entry.get("ip", "")
        if not ip:
            ip = self.pod.get_ip(name)
        return ip

    def _iptables_nat(self, action: str, proto: str,
                      host_port: int, ip: str, ctr_port: int):
        self._sys(["sudo", "iptables", "-t", "nat", action, "PREROUTING",
                   "-p", proto, "--dport", str(host_port),
                   "-j", "DNAT", "--to-destination", f"{ip}:{ctr_port}"],
                  check=(action == "-A"))

    def _iptables_fwd(self, action: str, proto: str, ip: str, ctr_port: int):
        self._sys(["sudo", "iptables", action, "FORWARD",
                   "-p", proto, "-d", ip, "--dport", str(ctr_port),
                   "-j", "ACCEPT"],
                  check=(action == "-A"))

    def add(self, container: str, spec: str):
        """Add a forward.  spec = host_port:container_port[/tcp|udp]"""
        proto = "tcp"
        if "/" in spec:
            spec, proto = spec.rsplit("/", 1)
            proto = proto.lower()
        if proto not in ("tcp", "udp"):
            error("Protocol must be tcp or udp")
        parts = spec.split(":")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            error("Format: host_port:container_port[/tcp|udp]")
        host_port, ctr_port = int(parts[0]), int(parts[1])

        ip = self._container_ip(container)
        if not ip:
            error(f"Cannot resolve IP for '{container}'. "
                  "Is it running (or registered with an IP)?")

        rule_id = f"{container}:{host_port}:{ctr_port}/{proto}"
        if rule_id in self.cfg.get_forwards():
            warn(f"Forward already exists: {rule_id}")
            return

        self._iptables_nat("-A", proto, host_port, ip, ctr_port)
        self._iptables_fwd("-A", proto, ip, ctr_port)
        self.cfg.add_forward(rule_id, container, host_port, ctr_port, proto, ip)
        success(f"Forward added: host:{host_port} → {container} ({ip}):{ctr_port}/{proto}")

    def list(self):
        forwards = self.cfg.get_forwards()
        if not forwards:
            print("No active port forwards.")
            return
        header("Active port forwards:")
        fmt = "  {:<22} {:>6}  →  {:<15} {:>6}  {}"
        print(fmt.format("Container", "Host", "Container IP", "Port", "Proto"))
        print("  " + "-" * 60)
        for r in forwards.values():
            print(fmt.format(
                r["container"], r["host_port"],
                r["ip"], r["container_port"], r["proto"],
            ))

    def remove(self, container: str, host_port: int):
        """Remove all forwards for container:host_port."""
        forwards = self.cfg.get_forwards()
        targets = {rid: r for rid, r in forwards.items()
                   if r["container"] == container and r["host_port"] == host_port}
        if not targets:
            error(f"No forward found for {container} host_port={host_port}")
        for rule_id, r in targets.items():
            self._iptables_nat("-D", r["proto"], r["host_port"], r["ip"], r["container_port"])
            self._iptables_fwd("-D", r["proto"], r["ip"], r["container_port"])
            self.cfg.remove_forward(rule_id)
            success(f"Removed: host:{r['host_port']} → {container}:{r['container_port']}/{r['proto']}")

    def flush(self, container: str = ""):
        """Remove all forwards, or all forwards for one container."""
        forwards = self.cfg.get_forwards()
        targets = ({rid: r for rid, r in forwards.items() if r["container"] == container}
                   if container else dict(forwards))
        if not targets:
            print("Nothing to flush.")
            return
        for rule_id, r in targets.items():
            self._iptables_nat("-D", r["proto"], r["host_port"], r["ip"], r["container_port"])
            self._iptables_fwd("-D", r["proto"], r["ip"], r["container_port"])
            self.cfg.remove_forward(rule_id)
            success(f"Removed: host:{r['host_port']} → {r['container']}:{r['container_port']}/{r['proto']}")


# ── helpers ────────────────────────────────────────────────────────────────────
def _run_sys(args: list, check=True, capture=False,
             dry_run=False, verbose=False) -> subprocess.CompletedProcess:
    """Run a non-podman system command."""
    if verbose or dry_run:
        print(f"{Colors.DIM}$ {' '.join(str(x) for x in args)}{Colors.RESET}")
    if dry_run:
        return subprocess.CompletedProcess(args, 0, "", "")
    return subprocess.run(args, check=check,
                          capture_output=capture, text=True)

def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None

def _log(log_dir: Path, log_file: str, msg: str):
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_dir / log_file, "a") as fh:
        fh.write(f"[{ts}] {msg}\n")


# ══════════════════════════════════════════════════════════════════════════════
# LinuxManager – mirrors podman-kali.sh v1.9.0
# ══════════════════════════════════════════════════════════════════════════════
class LinuxManager:
    LOG_FILE = "kali-podman.log"

    def __init__(self, cfg: Config, podman: Podman, net: NetworkManager,
                 dry_run=False, verbose=False):
        self.cfg     = cfg
        self.podman  = podman
        self.net     = net
        self.dry_run = dry_run
        self.verbose = verbose

    # ── properties ──
    @property
    def base_image(self) -> str:
        return self.cfg.get("linux.base_image",
                            "docker.io/kalilinux/kali-rolling:latest")
    @property
    def golden_name(self) -> str:
        return self.cfg.get("linux.golden_name", "kali-golden")
    @property
    def golden_image(self) -> str:
        return f"{self.golden_name}:latest"
    @property
    def log_dir(self) -> Path:
        return Path(self.cfg.get("linux.log_dir",
                                 str(Path.home() / ".kali-pentest/logs")))
    @property
    def mount_dir(self) -> Path:
        return Path(self.cfg.get("linux.mount_dir", "/mnt/container"))
    @property
    def x11_fix_file(self) -> Path:
        return Path("/tmp/x11fix")
    @property
    def shared_dir(self) -> Path:
        return Path(self.cfg.get("shared_dir", str(SHARED_DIR)))

    def _log(self, msg: str):
        _log(self.log_dir, self.LOG_FILE, msg)

    def _sys(self, args: list, check=True, capture=False):
        return _run_sys(args, check=check, capture=capture,
                        dry_run=self.dry_run, verbose=self.verbose)

    # ── Container lifecycle ────────────────────────────────────────────────────
    def create(self, name: str):
        if not name:
            error("Container name required")
        if self.podman.container_exists(name):
            error(f"Container '{name}' already exists")
        if not self.podman.image_exists(self.golden_image):
            error(f"Golden image '{self.golden_image}' not found. "
                  "Run: labctl golden --type linux")

        # Ensure lab-net exists
        self.net.ensure()
        ip = self.net.allocate_ip()

        # Shared / per-container storage
        host_share = self.mount_dir / name
        if not self.dry_run:
            self._sys(["sudo", "mkdir", "-p", str(host_share)], check=False)

        lab_shared = self.shared_dir
        if not self.dry_run:
            lab_shared.mkdir(parents=True, exist_ok=True)

        # Per-container hosts file
        hosts_file = host_share / "hosts"
        if not self.dry_run and not hosts_file.exists():
            self._sys(["sudo", "bash", "-c",
                       f'echo "127.0.0.1   localhost" > {hosts_file} && '
                       f'echo "::1         localhost" >> {hosts_file} && '
                       f'echo "{ip}    {name}" >> {hosts_file} && '
                       f'echo "# Custom hosts file for {name}" >> {hosts_file}'],
                      check=False)

        info(f"Assigning IP: {ip}")
        display = os.environ.get("DISPLAY", ":0")

        self.podman.run([
            "run", "-d", "--name", name,
            "--network", self.net.name,
            "--ip", ip,
            "--hostname", name,
            "--no-hosts",
            "-v", f"{host_share}/hosts:/etc/hosts",
            "-e", f"DISPLAY={display}",
            "-v", "/tmp/.X11-unix:/tmp/.X11-unix:rw",
            "--device", "/dev/dri",
            "--device", "/dev/net/tun",
            "--security-opt", "label=disable",
            "--ipc=host",
            "--cap-add=NET_ADMIN",
            "--cap-add=SYS_MODULE",
            "--cap-add=NET_RAW",
            "--sysctl=net.ipv4.conf.all.src_valid_mark=1",
            "--sysctl=net.ipv4.conf.all.forwarding=1",
            "--sysctl=net.ipv4.ip_forward=1",
            "--restart", "unless-stopped",
            "--privileged",
            "--pids-limit", "-1",
            "-v", f"{host_share}:/mnt/share",
            "-v", f"{lab_shared}:/mnt/lab-shared",
            self.golden_image, "tail", "-f", "/dev/null",
        ])

        self.cfg.register(name, "linux", {"ip": ip})
        self._log(f"Created container: {name} with IP {ip}")
        success(f"Container '{name}' created (IP {ip})")
        info(f"Share: {host_share} ↔ /mnt/share")
        info(f"Lab shared: {lab_shared} ↔ /mnt/lab-shared")

    def start(self, name: str):
        self._require(name)
        host_share = self.mount_dir / name
        if not self.dry_run:
            self._sys(["sudo", "mkdir", "-p", str(host_share)], check=False)
        self.podman.run(["start", name])
        self._log(f"Started container: {name}")
        success(f"Container '{name}' started")

    def connect(self, name: str):
        self._require(name)
        if not self.x11_fix_file.exists():
            info("X11 fix not applied, auto-patching…")
            self.fix_x11()
        self._log(f"Connected to container: {name}")
        self.podman.execvp(name, ["tmux"], user="root", workdir="/root/")

    def exec_cmd(self, name: str, cmd: list):
        self._require(name)
        if not cmd:
            error("Command required")
        self._log(f"Executed in {name}: {' '.join(cmd)}")
        self.podman.execvp(name, cmd, user="root")

    def delete(self, name: str):
        self._require(name)
        if name == self.golden_name:
            warn("Deleting golden container. Golden image will remain.")
            if not confirm("Continue?"):
                print("Aborted.")
                return
        self.podman.run(["stop", name], check=False)
        self.podman.run(["rm", name])
        self.cfg.unregister(name)
        self._log(f"Deleted container: {name}")
        host_share = self.mount_dir / name
        if not self.dry_run:
            self._sys(["sudo", "rm", "-rf", str(host_share)], check=False)
        success(f"Container '{name}' removed")

    def restart(self, name: str):
        self._require(name)
        self.podman.run(["restart", name])
        self._log(f"Restarted container: {name}")
        success(f"Container '{name}' restarted")

    def stop(self, name: str):
        self._require(name)
        self.podman.run(["stop", name])
        self._log(f"Stopped container: {name}")
        success(f"Container '{name}' stopped")

    def pause(self, name: str):
        self._require(name)
        self.podman.run(["pause", name])
        self._log(f"Paused container: {name}")
        success(f"Container '{name}' paused")

    def unpause(self, name: str):
        self._require(name)
        self.podman.run(["unpause", name])
        self._log(f"Unpaused container: {name}")
        success(f"Container '{name}' unpaused")

    # ── Golden image management ────────────────────────────────────────────────
    def golden(self):
        if not self.podman.container_exists(self.golden_name):
            info(f"Golden container not found. Creating from '{self.base_image}'…")
            host_share = self.mount_dir / self.golden_name
            if not self.dry_run:
                host_share.mkdir(parents=True, exist_ok=True)
            display = os.environ.get("DISPLAY", ":0")
            self.podman.run([
                "run", "-dit", "--name", self.golden_name,
                "-e", f"DISPLAY={display}",
                "-v", "/tmp/.X11-unix:/tmp/.X11-unix:rw",
                "--device", "/dev/dri",
                "--device", "/dev/net/tun",
                "--security-opt", "label=disable",
                "--ipc=host",
                "--cap-add=NET_ADMIN",
                "--cap-add=NET_RAW",
                "-v", f"{host_share}:/mnt/share",
                self.base_image, "bash",
            ])
            self.cfg.register(self.golden_name, "linux")
            self._log(f"Created golden container: {self.golden_name}")
            success(f"Golden container '{self.golden_name}' created")
        self._log("Entered golden shell")
        self.podman.execvp(self.golden_name, ["bash"], user="root")

    def commit(self):
        if not self.podman.container_exists(self.golden_name):
            error(f"Golden container '{self.golden_name}' not found")
        self.podman.run(["commit", self.golden_name, self.golden_image])
        self._log(f"Committed golden container to: {self.golden_image}")
        success(f"Golden container committed to '{self.golden_image}'")

    def update_base(self):
        info(f"Pulling latest base image: {self.base_image}")
        self.podman.run(["pull", self.base_image])
        self._log(f"Updated base image: {self.base_image}")
        success("Base image updated")

    def recreate_golden(self):
        warn("This will destroy the golden container and recreate from base image.")
        if not confirm("Continue?"):
            print("Aborted.")
            return
        if self.podman.container_exists(self.golden_name):
            self.podman.run(["stop", self.golden_name], check=False)
            self.podman.run(["rm",   self.golden_name])
            self._log(f"Deleted golden container")
        host_share = self.mount_dir / self.golden_name
        if not self.dry_run:
            host_share.mkdir(parents=True, exist_ok=True)
        display = os.environ.get("DISPLAY", ":0")
        self.podman.run([
            "run", "-dit", "--name", self.golden_name,
            "-e", f"DISPLAY={display}",
            "-v", "/tmp/.X11-unix:/tmp/.X11-unix:rw",
            "--device", "/dev/dri",
            "--device", "/dev/net/tun",
            "--security-opt", "label=disable",
            "--ipc=host",
            "--cap-add=NET_ADMIN",
            "--cap-add=NET_RAW",
            "-v", f"{host_share}:/mnt/share",
            self.base_image, "bash",
        ])
        self.cfg.register(self.golden_name, "linux")
        self._log("Recreated golden container from base image")
        success(f"Golden container recreated from '{self.base_image}'")

    def restore_golden(self):
        if not self.podman.image_exists(self.golden_image):
            error(f"Golden image '{self.golden_image}' not found")
        host_share = self.mount_dir / self.golden_name
        if not self.dry_run:
            host_share.mkdir(parents=True, exist_ok=True)
        display = os.environ.get("DISPLAY", ":0")
        self.podman.run([
            "run", "-dit", "--replace", "--name", self.golden_name,
            "-e", f"DISPLAY={display}",
            "-v", "/tmp/.X11-unix:/tmp/.X11-unix:rw",
            "--device", "/dev/dri",
            "--device", "/dev/net/tun",
            "--security-opt", "label=disable",
            "--ipc=host",
            "--cap-add=NET_ADMIN",
            "-v", f"{host_share}:/mnt/share",
            self.golden_image, "bash",
        ])
        self.cfg.register(self.golden_name, "linux")
        self._log(f"Restored golden container from image: {self.golden_image}")
        success(f"Golden container '{self.golden_name}' restored")

    # ── Inspection ────────────────────────────────────────────────────────────
    def list_containers(self, running_only=False, stopped_only=False):
        """List only containers registered/detected as linux."""
        header("Linux containers:")
        all_names = self.podman.get_all_container_names(
            running_only=running_only, stopped_only=stopped_only)
        linux_names = self._filter_names_by_type(all_names)
        if not linux_names:
            info("  (none)")
            return
        filter_args = []
        for n in linux_names:
            filter_args += ["--filter", f"name=^{n}$"]
        args = ["ps", "-a"] + filter_args
        if running_only:
            args = ["ps"] + filter_args
        elif stopped_only:
            args = ["ps", "-a", "--filter", "status=exited"] + filter_args
        args += ["--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}"]
        self.podman.run(args)

    def inspect(self, name: str):
        self._require(name)
        self.podman.run(["inspect", name])

    def logs(self, name: str):
        self._require(name)
        self.podman.run(["logs", "-f", name])

    def stats(self, name: str = ""):
        if name:
            self._require(name)
            self.podman.run(["stats", name])
        else:
            self.podman.run(["stats"])

    def list_images(self):
        header("Local images:")
        self.podman.run(["images", "--format",
                         "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"])

    # ── Batch operations ──────────────────────────────────────────────────────
    def clean(self):
        """Remove stopped containers that are registered/detected as linux."""
        all_stopped = self.podman.get_all_container_names(stopped_only=True)
        linux_stopped = self._filter_names_by_type(all_stopped)
        if not linux_stopped:
            info("No stopped Linux containers to clean")
            return
        info(f"Found {len(linux_stopped)} stopped Linux container(s). Removing…")
        for cname in linux_stopped:
            self.podman.run(["rm", cname], check=False)
            self.cfg.unregister(cname)
        self._log(f"Cleaned {len(linux_stopped)} stopped Linux containers")
        success(f"Cleaned {len(linux_stopped)} stopped Linux container(s)")

    def clean_all(self):
        """Stop and remove all Linux containers except golden."""
        all_names = self.podman.get_all_container_names()
        linux_names = self._filter_names_by_type(all_names)
        targets = [n for n in linux_names if n != self.golden_name]
        if not targets:
            info("No Linux containers to clean (except golden)")
            return
        warn(f"This will stop and remove {len(targets)} Linux container(s) (except golden).")
        if not confirm("Continue?"):
            print("Aborted.")
            return
        for cname in targets:
            self.podman.run(["stop", cname], check=False)
            self.podman.run(["rm", cname], check=False)
            self.cfg.unregister(cname)
        self._log("Cleaned all Linux containers except golden")
        success("All Linux containers removed (except golden)")

    def stop_all(self):
        """Stop all running Linux containers except golden."""
        running = self.podman.get_all_container_names(running_only=True)
        linux_running = self._filter_names_by_type(running)
        targets = [n for n in linux_running if n != self.golden_name]
        if not targets:
            info("No running Linux containers to stop (except golden)")
            return
        warn(f"This will stop {len(targets)} running Linux container(s) (except golden).")
        if not confirm("Continue?"):
            print("Aborted.")
            return
        for cname in targets:
            self.podman.run(["stop", cname], check=False)
        self._log("Stopped all Linux containers except golden")
        success("All Linux containers stopped (except golden)")

    def cleanup_golden(self):
        info("Removing dangling images…")
        self.podman.run(["image", "prune", "-f"])
        self._log("Cleaned up golden images")
        success("Cleaned up old golden images")

    # ── Utilities ─────────────────────────────────────────────────────────────
    def clone(self, source: str, target: str):
        self._require(source)
        if self.podman.container_exists(target):
            error(f"Target container '{target}' already exists")
        src_img = self.podman._run(
            ["inspect", "--format={{.Image}}", source],
            capture=True, check=False).stdout.strip()
        host_share = self.mount_dir / target
        if not self.dry_run:
            self._sys(["sudo", "mkdir", "-p", str(host_share)], check=False)
        display = os.environ.get("DISPLAY", ":0")
        self.podman.run([
            "run", "-d", "--name", target,
            "-e", f"DISPLAY={display}",
            "-v", "/tmp/.X11-unix:/tmp/.X11-unix:rw",
            "--device", "/dev/dri",
            "--security-opt", "label=disable",
            "--ipc=host",
            "-v", f"{host_share}:/mnt/share",
            src_img, "tail", "-f", "/dev/null",
        ])
        self.cfg.register(target, "linux")
        self._log(f"Cloned container: {source} -> {target}")
        success(f"Container '{source}' cloned to '{target}'")

    def rename(self, old: str, new: str):
        self._require(old)
        self.podman.run(["rename", old, new])
        self.cfg.rename_reg(old, new)
        self._log(f"Renamed container: {old} -> {new}")
        success(f"Container renamed: '{old}' -> '{new}'")

    def export_container(self, name: str, path: str):
        self._require(name)
        tmp_image = f"tmp-export-{name}:latest"
        info("Committing container to temporary image…")
        self.podman.run(["commit", name, tmp_image])
        if not path.endswith(".gz"):
            path = path + ".gz"
        info(f"Exporting image to {path} (this may take a while)…")
        if not self.dry_run:
            if _which("pigz"):
                info("Using pigz for parallel compression…")
                with open(path, "wb") as fh:
                    save = subprocess.Popen(
                        ["podman", "save", tmp_image], stdout=subprocess.PIPE)
                    pigz = subprocess.Popen(
                        ["pigz", "-c"], stdin=save.stdout, stdout=fh)
                    save.stdout.close()
                    pigz.communicate()
                    if save.wait() != 0 or pigz.returncode != 0:
                        error("Export failed")
            else:
                info("Using gzip (pigz not found)…")
                with open(path, "wb") as fh:
                    save = subprocess.Popen(
                        ["podman", "save", tmp_image], stdout=subprocess.PIPE)
                    gz = subprocess.Popen(
                        ["gzip", "-c"], stdin=save.stdout, stdout=fh)
                    save.stdout.close()
                    gz.communicate()
                    if save.wait() != 0 or gz.returncode != 0:
                        error("Export failed")
            self.podman.run(["rmi", tmp_image], check=False)
            size = subprocess.run(["du", "-h", path],
                                  capture_output=True, text=True).stdout.split()[0]
        else:
            size = "n/a"
        self._log(f"Exported container: {name} to {path}")
        success(f"Container '{name}' exported to '{path}' (size: {size})")

    def import_image(self, tar_path: str, name: str):
        if not Path(tar_path).exists():
            error(f"File not found: {tar_path}")
        info(f"Importing image from {tar_path}…")
        if not self.dry_run:
            if tar_path.endswith(".gz"):
                if _which("pigz"):
                    tool, flag = "pigz", "-dc"
                else:
                    tool, flag = "gzip", "-dc"
                with open(tar_path, "rb") as fh:
                    decomp = subprocess.Popen(
                        [tool, flag], stdin=fh, stdout=subprocess.PIPE)
                    load = subprocess.Popen(
                        ["podman", "load"], stdin=decomp.stdout)
                    decomp.stdout.close()
                    load.communicate()
                    if decomp.wait() != 0 or load.returncode != 0:
                        error("Import failed")
            else:
                subprocess.run(["podman", "load", "-i", tar_path], check=True)
        self._log(f"Imported image from: {tar_path}")
        success(f"Image imported from '{tar_path}'")
    def mount(self, name: str):
        mount_dir = Path(f"/mnt/container-{name}")
        if not self.dry_run:
            self._sys(["sudo", "mkdir", "-p", str(mount_dir)])
        r = self.podman.sudo_run(["mount", name], capture=True)
        mountpoint = r.stdout.strip()
        if not self.dry_run:
            self._sys(["sudo", "mount", "--bind", mountpoint, str(mount_dir)])
        self._log(f"Mounted container filesystem: {name} at {mount_dir}")
        success(f"Container '{name}' filesystem mounted at:")
        print(f"  {mount_dir}")
        info(f"Unmount with: labctl umount {name}")

    def umount(self, name: str):
        mount_dir = Path(f"/mnt/container-{name}")
        self._sys(["sudo", "umount", str(mount_dir)], check=False)
        self.podman.sudo_run(["unmount", name], check=False)
        self._log(f"Unmounted container filesystem: {name}")
        success(f"Container '{name}' filesystem unmounted")

    def remove_image(self, image: str):
        if not self.podman.image_exists(image):
            error(f"Image '{image}' not found")
        self.podman.run(["rmi", image])
        self._log(f"Removed image: {image}")
        success(f"Image '{image}' removed")

    def fix_x11(self):
        self._sys(["xauth", "generate", ":0", ".", "trusted"], check=False)
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user:
            self._sys(["xhost", f"+si:localuser:{sudo_user}"], check=False)
        self._sys(["xhost", "+si:localuser:root"], check=False)
        if not self.dry_run:
            self.x11_fix_file.touch()
        success("X11 forwarding fix applied")

    def _filter_names_by_type(self, all_names: List[str]) -> List[str]:
        """Filter container names to only those belonging to linux.

        Uses the registry first. For unregistered containers, uses heuristics:
        containers whose image contains 'kali' or match the linux golden name
        are treated as linux. Containers with 'dockurr' or 'windows' in image
        are excluded.
        """
        result: List[str] = []
        linux_golden = self.golden_name
        windows_golden = self.cfg.get("windows.golden_name", "windows-golden")
        for name in all_names:
            reg_type = self.cfg.get_type(name)
            if reg_type == "linux":
                result.append(name)
            elif reg_type is not None:
                continue  # registered as something else, skip
            else:
                # Unregistered — heuristic based on name and image
                if name == linux_golden:
                    result.append(name)
                elif name == windows_golden:
                    continue
                else:
                    img = self.podman._run(
                        ["inspect", "--format={{.ImageName}}", name],
                        capture=True, check=False).stdout.strip().lower()
                    if not img:
                        img = self.podman._run(
                            ["inspect", "--format={{.Image}}", name],
                            capture=True, check=False).stdout.strip().lower()
                    if "kali" in img or "kali-golden" in img:
                        result.append(name)
                    elif "dockurr" in img or "windows" in img:
                        continue
                    else:
                        # Unknown image — include under linux as default
                        result.append(name)
        return result

    # ── internal ──────────────────────────────────────────────────────────────
    def _require(self, name: str):
        if not self.podman.container_exists(name):
            error(f"Container '{name}' does not exist")


# ══════════════════════════════════════════════════════════════════════════════
# WindowsManager – mirrors podman-windows.sh v1.6.0
# ══════════════════════════════════════════════════════════════════════════════
class WindowsManager:
    LOG_FILE = "windows-podman.log"

    def __init__(self, cfg: Config, podman: Podman, net: NetworkManager,
                 dry_run=False, verbose=False):
        self.cfg     = cfg
        self.podman  = podman
        self.net     = net
        self.dry_run = dry_run
        self.verbose = verbose

    # ── properties ──
    @property
    def base_image(self) -> str:
        return self.cfg.get("windows.base_image",
                            "docker.io/dockurr/windows:latest")
    @property
    def golden_name(self) -> str:
        return self.cfg.get("windows.golden_name", "windows-golden")
    @property
    def log_dir(self) -> Path:
        return Path(self.cfg.get("windows.log_dir",
                                 str(Path.home() / ".windows-pentest/logs")))
    @property
    def storage_base(self) -> Path:
        return Path(self.cfg.get("windows.storage_base",
                                 str(Path.home() / ".windows-pentest/storage")))
    @property
    def shared_dir(self) -> Path:
        return Path(self.cfg.get("shared_dir", str(SHARED_DIR)))

    def _def(self, key: str) -> str:
        defaults = {
            "version": "11", "ram": "4G", "cpu": "2",
            "disk": "64G", "user": "Docker", "pass": "admin",
        }
        return self.cfg.get(f"windows.default_{key}", defaults[key])

    def _log(self, msg: str):
        _log(self.log_dir, self.LOG_FILE, msg)

    def _sys(self, args: list, check=True, capture=False):
        return _run_sys(args, check=check, capture=capture,
                        dry_run=self.dry_run, verbose=self.verbose)

    def _storage(self, name: str) -> Path:
        return self.storage_base / name

    def _golden_storage(self) -> Path:
        p = self.storage_base / self.golden_name
        if p.is_symlink() and not self.dry_run:
            return p.resolve()
        return p

    def _find_disk(self, storage_dir: Path) -> Optional[Path]:
        for name in ("data.qcow2", "data.img"):
            p = storage_dir / name
            if p.exists():
                return p
        return None

    def _check_kvm(self):
        if not Path("/dev/kvm").exists():
            error("/dev/kvm not found. KVM is required for Windows containers.")

    # ── QCOW2 cloning ────────────────────────────────────────────────────────
    def _create_standalone_qcow2(self, src: Path, dst: Path) -> bool:
        info("Creating standalone QCOW2 copy…")
        if _which("qemu-img"):
            r = self._sys(["qemu-img", "convert", "-p", "-O", "qcow2",
                           str(src), str(dst)], check=False)
            return r.returncode == 0
        else:
            r = self._sys(["cp", "--sparse=always", str(src), str(dst)],
                          check=False)
            return r.returncode == 0

    def _fast_clone(self, src_dir: Path, dst_dir: Path) -> bool:
        if not self.dry_run:
            dst_dir.mkdir(parents=True, exist_ok=True)
        src_disk = self._find_disk(src_dir)
        if not src_disk:
            error(f"No source disk found in {src_dir}", 0)
            return False

        # Copy metadata files
        for fname in ("windows.base", "windows.boot", "windows.mac",
                      "windows.rom", "windows.vars", "windows.ver"):
            fp = src_dir / fname
            if fp.exists() and not self.dry_run:
                self._sys(["cp", str(fp), str(dst_dir / fname)], check=False)

        sym_link = self.storage_base / self.golden_name
        if sym_link.is_symlink():
            info("Golden storage is symlinked – using standalone copy…")
            return self._create_standalone_qcow2(src_disk, dst_dir / "data.qcow2")

        if src_disk.suffix == ".qcow2" and _which("qemu-img"):
            info("Creating instant CoW clone (QCOW2 backing file)…")
            r = self._sys(["qemu-img", "create", "-f", "qcow2",
                           "-b", str(src_disk), "-F", "qcow2",
                           str(dst_dir / "data.qcow2")],
                          check=False, capture=True)
            if r.returncode == 0:
                chk = self._sys(["qemu-img", "info", str(dst_dir / "data.qcow2")],
                                check=False, capture=True)
                if "Could not open backing file" in chk.stdout:
                    warn("Backing file not accessible, creating standalone copy…")
                    if not self.dry_run:
                        (dst_dir / "data.qcow2").unlink(missing_ok=True)
                    return self._create_standalone_qcow2(src_disk,
                                                          dst_dir / "data.qcow2")
                success("Done! (instant)")
                return True

        if src_disk.suffix == ".img" and _which("qemu-img"):
            info("Converting raw image to QCOW2…")
            return self._create_standalone_qcow2(src_disk, dst_dir / "data.qcow2")

        # Fallback: full copy
        info("Copying disk (fallback)…")
        if _which("rsync"):
            r = self._sys(["rsync", "-a", "--sparse", "--info=progress2",
                           str(src_disk), str(dst_dir) + "/"], check=False)
        else:
            r = self._sys(["cp", "-a", "--sparse=always",
                           str(src_disk), str(dst_dir) + "/"], check=False)
        return r.returncode == 0

    # ── Container lifecycle ───────────────────────────────────────────────────
    def create(self, name: str, version: str = "", ram: str = "",
               cpu: str = "", disk: str = "", user: str = "",
               password: str = "", fresh: bool = False,
               full_copy: bool = False):
        if not name:
            error("Container name required")
        if self.podman.container_exists(name):
            error(f"Container '{name}' already exists")
        self._check_kvm()

        version  = version  or self._def("version")
        ram      = ram      or self._def("ram")
        cpu      = cpu      or self._def("cpu")
        disk     = disk     or self._def("disk")
        user     = user     or self._def("user")
        password = password or self._def("pass")

        storage_path = self._storage(name)
        golden_store = self._golden_storage()

        if not self.dry_run:
            self.storage_base.mkdir(parents=True, exist_ok=True)

        if not fresh:
            golden_disk = self._find_disk(golden_store)
            if golden_disk:
                if full_copy:
                    info("Creating full copy…")
                    storage_path.mkdir(parents=True, exist_ok=True)
                    if _which("rsync"):
                        self._sys(["rsync", "-a", "--sparse", "--info=progress2",
                                   str(golden_store) + "/",
                                   str(storage_path) + "/"])
                    else:
                        self._sys(["cp", "-a", "--sparse=always",
                                   str(golden_store) + "/.",
                                   str(storage_path) + "/"])
                else:
                    if not self._fast_clone(golden_store, storage_path):
                        error("Clone failed")
            else:
                info("No golden image found.")
                print("\n  1) Fresh installation (downloads ISO)")
                print("  2) Abort (set up golden image first)\n")
                if not confirm("Create fresh installation?", default=False):
                    error("Aborted. Run: labctl golden --type windows", 0)
                    return
                fresh = True
                if not self.dry_run:
                    storage_path.mkdir(parents=True, exist_ok=True)
        else:
            if not self.dry_run:
                storage_path.mkdir(parents=True, exist_ok=True)

        web_port, rdp_port = self.cfg.get_next_ports()

        self.net.ensure()
        lab_shared = self.shared_dir
        if not self.dry_run:
            lab_shared.mkdir(parents=True, exist_ok=True)

        info(f"Creating Windows container '{name}'…")
        info(f"  Mode: {'Fresh install' if fresh else 'Cloned from golden'}")
        info(f"  RAM: {ram}  CPU: {cpu}  Web: {web_port}  RDP: {rdp_port}")

        run_args = ["run", "-d", "--name", name]
        if fresh:
            run_args += ["-e", f"VERSION={version}"]
        run_args += [
            "-e", f"RAM_SIZE={ram}",
            "-e", f"CPU_CORES={cpu}",
            "-e", f"DISK_SIZE={disk}",
            "-e", f"USERNAME={user}",
            "-e", f"PASSWORD={password}",
            "-p", f"{web_port}:8006",
            "-p", f"{rdp_port}:3389/tcp",
            "-p", f"{rdp_port}:3389/udp",
            "--device", "/dev/kvm",
            "--device", "/dev/net/tun",
            "--cap-add", "NET_ADMIN",
            "--stop-timeout", "120",
            "--network", self.net.name,
            "-v", f"{storage_path}:/storage:Z",
            "-v", f"{lab_shared}:/shared",
            self.base_image,
        ]
        self.podman.run(run_args)
        self.cfg.register_ports(name, web_port, rdp_port)
        self.cfg.register(name, "windows",
                          {"web_port": web_port, "rdp_port": rdp_port})
        import time; time.sleep(3) if not self.dry_run else None
        if not self.dry_run and not self.podman.is_running(name):
            warn("Container may have failed to start! Check: labctl logs " + name)
            return
        self._log(f"Created container: {name} (Web: {web_port}, RDP: {rdp_port})")
        success(f"Container '{name}' created and running!")
        print(f"\n  Web Viewer : http://localhost:{web_port}")
        print(f"  RDP        : localhost:{rdp_port}  ({user}/{password})\n")

    def start(self, name: str):
        self._require(name)
        self._check_kvm()
        self.podman.run(["start", name])
        import time; time.sleep(3) if not self.dry_run else None
        if not self.dry_run and self.podman.is_running(name):
            self._log(f"Started container: {name}")
            ports = self.cfg.get_ports(name)
            if ports:
                w, r = ports
                success(f"Container '{name}' started")
                print(f"  Web: http://localhost:{w}")
                print(f"  RDP: localhost:{r}")
            else:
                success(f"Container '{name}' started")
        elif not self.dry_run:
            warn("Container failed to start. Check: labctl logs " + name)

    def connect(self, name: str):
        self._require(name)
        ports = self.cfg.get_ports(name)
        state = self.podman.get_state(name)
        header(f"Connection Info for '{name}':")
        print(f"\n  Status: {state}")
        if ports:
            w, r = ports
            print(f"\n  Web Viewer : http://localhost:{w}")
            print(f"  RDP        : localhost:{r}  (user: Docker / pass: admin)")
        ip = self.podman.get_ip(name)
        if ip:
            print(f"\n  VNC        : {ip}:5900")
        print(f"\n  Quick commands:")
        print(f"    labctl web {name}")
        print(f"    labctl rdp {name}")
        print(f"    labctl vnc {name}\n")

    def delete(self, name: str):
        self._require(name)
        if name == self.golden_name:
            warn("This will delete the golden container. Storage will remain.")
            if not confirm("Continue?"):
                print("Aborted.")
                return
        info(f"Stopping '{name}'…")
        self.podman.run(["stop", "-t", "120", name], check=False)
        self.podman.run(["rm", name])
        self.cfg.unregister_ports(name)
        self.cfg.unregister(name)
        self._log(f"Deleted container: {name}")
        success(f"Container '{name}' removed")

        storage_path = self._storage(name)
        if (not self.dry_run and storage_path.is_dir()
                and not storage_path.is_symlink()
                and name != self.golden_name):
            disk = self._find_disk(storage_path)
            if disk:
                r = self._sys(["du", "-h", str(disk)], capture=True, check=False)
                sz = r.stdout.split()[0] if r.returncode == 0 else "?"
                print(f"\n  Storage remains at: {storage_path} ({sz})")
                if confirm("Delete storage too?"):
                    import shutil
                    shutil.rmtree(str(storage_path))
                    success("Storage deleted")

    def restart(self, name: str):
        self._require(name)
        info(f"Restarting '{name}'…")
        self.podman.run(["restart", "-t", "120", name])
        import time; time.sleep(3) if not self.dry_run else None
        if not self.dry_run and self.podman.is_running(name):
            self._log(f"Restarted container: {name}")
            success(f"Container '{name}' restarted")
        elif not self.dry_run:
            warn("Container failed to restart. Check: labctl logs " + name)

    def stop(self, name: str):
        self._require(name)
        info(f"Stopping '{name}' gracefully (up to 2 minutes)…")
        self.podman.run(["stop", "-t", "120", name])
        self._log(f"Stopped container: {name}")
        success(f"Container '{name}' stopped")

    def force_stop(self, name: str):
        self._require(name)
        info(f"Force stopping '{name}'…")
        self.podman.run(["stop", "-t", "0", name])
        self._log(f"Force stopped container: {name}")
        success(f"Container '{name}' force stopped")

    # ── Golden image management ───────────────────────────────────────────────
    def golden(self, version: str = "", ram: str = "", cpu: str = ""):
        self._check_kvm()
        version = version or self._def("version")
        ram     = ram     or self._def("ram")
        cpu     = cpu     or self._def("cpu")
        golden_store = self._golden_storage()
        if not self.dry_run:
            golden_store.mkdir(parents=True, exist_ok=True)

        if self.podman.container_exists(self.golden_name):
            if not self.podman.is_running(self.golden_name):
                info("Starting golden container…")
                self.podman.run(["start", self.golden_name])
                import time; time.sleep(3) if not self.dry_run else None
            if not self.dry_run and self.podman.is_running(self.golden_name):
                success("Golden container is running")
            elif not self.dry_run:
                error("Golden container failed to start. Check: labctl logs " +
                      self.golden_name, 0)
                return
        else:
            info("Creating golden container…")
            existing_disk = self._find_disk(golden_store)
            run_args = ["run", "-d", "--name", self.golden_name,
                        "-e", f"RAM_SIZE={ram}",
                        "-e", f"CPU_CORES={cpu}",
                        "-p", "8006:8006",
                        "-p", "3389:3389/tcp",
                        "-p", "3389:3389/udp",
                        "--device", "/dev/kvm",
                        "--device", "/dev/net/tun",
                        "--cap-add", "NET_ADMIN",
                        "--stop-timeout", "120"]
            if not existing_disk:
                run_args += ["-e", f"VERSION={version}"]
            run_args += ["-v", f"{golden_store}:/storage:Z", self.base_image]
            self.podman.run(run_args)
            self.cfg.register_ports(self.golden_name, 8006, 3389)
            self.cfg.register(self.golden_name, "windows")
            import time; time.sleep(3) if not self.dry_run else None
            if not self.dry_run and not self.podman.is_running(self.golden_name):
                error("Golden container failed to start!", 0)
                return
            self._log(f"Created golden container: {self.golden_name}")

        success("Golden Windows container is running!")
        print("\n  Web: http://localhost:8006")
        print("  RDP: localhost:3389  (Docker/admin)")
        print(f"  Storage: {golden_store}\n")

    def adopt(self, source_path: str, mode: str = ""):
        src = Path(source_path).resolve() if not self.dry_run else Path(source_path)
        if not self.dry_run and not src.is_dir():
            error(f"Directory '{source_path}' does not exist")

        if not self.dry_run:
            print(f"\nChecking: {src}")
            disk = self._find_disk(src)
            if disk:
                r = self._sys(["du", "-h", str(disk)], capture=True, check=False)
                sz = r.stdout.split()[0] if r.returncode == 0 else "?"
                info(f"Found disk: {disk.name} ({sz})")
            else:
                warn("No Windows disk image found (expected data.qcow2 or data.img)")
                if not confirm("Continue anyway?"):
                    print("Aborted.")
                    return

        golden_store = self.storage_base / self.golden_name
        if not self.dry_run and golden_store.exists():
            sym = f" (symlink → {golden_store.resolve()})" if golden_store.is_symlink() else ""
            warn(f"Golden storage already exists at {golden_store}{sym}")
            if not confirm("Replace it?"):
                print("Aborted.")
                return
            import shutil
            if golden_store.is_symlink():
                golden_store.unlink()
            else:
                shutil.rmtree(str(golden_store))

        if not mode:
            print("\nHow to adopt?")
            print("  1) Copy  – recommended, enables instant CoW cloning")
            print("  2) Move  – fast, original becomes empty")
            print("  3) Link  – fastest setup, clones will be slower")
            ch = input("\nChoose [1/2/3]: ").strip()
            mode = {"1": "copy", "2": "move", "3": "link"}.get(ch, "")
            if not mode:
                error("Invalid choice")

        golden_store.parent.mkdir(parents=True, exist_ok=True)

        if mode == "copy":
            info("Copying (this may take a while)…")
            golden_store.mkdir(parents=True, exist_ok=True)
            if _which("rsync"):
                self._sys(["rsync", "-a", "--sparse", "--info=progress2",
                           str(src) + "/", str(golden_store) + "/"])
            else:
                self._sys(["cp", "-a", "--sparse=always",
                           str(src) + "/.", str(golden_store) + "/"])
            success(f"Copied to {golden_store}")
            success("Instant CoW cloning is now available!")
        elif mode == "move":
            import shutil
            shutil.move(str(src), str(golden_store))
            success(f"Moved to {golden_store}")
            success("Instant CoW cloning is now available!")
        elif mode == "link":
            golden_store.symlink_to(src)
            success(f"Linked: {golden_store} → {src}")
            info("Clones will use standalone copies (slower but reliable)")

        self._log(f"Adopted golden storage from: {source_path}")
        self.golden_status()

    def convert_golden(self):
        golden_store = self._golden_storage()
        disk = self._find_disk(golden_store)
        if not disk:
            error(f"No golden disk found at {golden_store}")
        if not _which("qemu-img"):
            error("qemu-img not found. Install qemu-utils.")
        if disk.suffix == ".qcow2":
            info("Golden image is already QCOW2 format.")
            self._sys(["qemu-img", "info", str(disk)], check=False)
            return
        # Check if golden container is running
        if (self.podman.container_exists(self.golden_name)
                and self.podman.is_running(self.golden_name)):
            warn("Golden container is running. Stop it first for safe conversion.")
            if confirm("Stop golden container?"):
                self.stop(self.golden_name)
            else:
                print("Aborted.")
                return
        info("Converting golden image to QCOW2…")
        qcow2 = golden_store / "data.qcow2"
        r = self._sys(["qemu-img", "convert", "-p", "-O", "qcow2",
                       "-o", "preallocation=off", str(disk), str(qcow2)],
                      check=False)
        if r.returncode != 0:
            error("Conversion failed")
        chk = self._sys(["qemu-img", "check", str(qcow2)],
                        capture=True, check=False)
        if "No errors" in chk.stdout:
            sz_r = self._sys(["du", "-h", str(qcow2)], capture=True, check=False)
            sz = sz_r.stdout.split()[0] if sz_r.returncode == 0 else "?"
            success(f"Done! New size: {sz}")
            if confirm("Remove original raw image?"):
                disk.unlink()
                success("Original removed")
            else:
                disk.rename(str(disk) + ".backup")
                info("Original backed up")
            success("Golden image converted to QCOW2!")
        else:
            warn("Verification found issues. Keeping original.")
            qcow2.unlink(missing_ok=True)
        self._log("Converted golden to QCOW2")

    def commit(self, name: str):
        if not name:
            error("Container name required")
        storage_path = self._storage(name)
        if storage_path.is_symlink() and not self.dry_run:
            storage_path = storage_path.resolve()
        disk = self._find_disk(storage_path)
        if not disk:
            error(f"No Windows disk found for '{name}'")
        golden_store = self._golden_storage()
        info(f"Saving '{name}' as new golden image…")
        info(f"  Source: {storage_path}")
        info(f"  Target: {self.storage_base / self.golden_name}")
        if self.podman.container_exists(name) and self.podman.is_running(name):
            warn("Container is running. Stop it for a clean commit.")
            if confirm("Stop container now?"):
                self.stop(name)
        if not confirm(f"Commit '{name}' as new golden image?"):
            print("Aborted.")
            return
        sym = self.storage_base / self.golden_name
        if sym.is_symlink():
            sym.unlink()
        elif golden_store.is_dir() and any(golden_store.iterdir()):
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            bak = Path(str(golden_store) + f".backup-{ts}")
            info(f"Backing up existing golden to: {bak}")
            golden_store.rename(bak)
        (self.storage_base / self.golden_name).mkdir(parents=True, exist_ok=True)
        info("Copying storage…")
        if _which("rsync"):
            self._sys(["rsync", "-a", "--sparse", "--info=progress2",
                       str(storage_path) + "/",
                       str(self.storage_base / self.golden_name) + "/"])
        else:
            self._sys(["cp", "-a", "--sparse=always",
                       str(storage_path) + "/.",
                       str(self.storage_base / self.golden_name) + "/"])
        self._log(f"Committed {name} as new golden image")
        success(f"'{name}' is now the golden image.")

    def golden_status(self):
        sym = self.storage_base / self.golden_name
        golden_store = self._golden_storage()
        header("Golden Image Status")
        print(f"\n  Storage path: {sym}")
        if sym.is_symlink() and not self.dry_run:
            print(f"  Type: Symlink → {golden_store}")
            warn("Symlinked storage uses standalone copies (slower but reliable)")
        elif golden_store.is_dir():
            print("  Type: Directory (instant CoW cloning available)")
        else:
            print("  Status: NOT CONFIGURED")
            info("Run: labctl adopt <path> --type windows")
            return
        disk = self._find_disk(golden_store)
        if disk:
            r = self._sys(["du", "-h", str(disk)], capture=True, check=False)
            sz = r.stdout.split()[0] if r.returncode == 0 else "?"
            print(f"\n  Disk    : {disk.name}")
            print(f"  Size    : {sz}")
            print(f"  Format  : {'QCOW2 ✓' if disk.suffix == '.qcow2' else 'Raw image'}")
            if disk.suffix == ".img":
                info("Run: labctl convert-golden --type windows")
        else:
            warn("No Windows disk image found! Expected: data.qcow2 or data.img")

    def update_base(self):
        info(f"Pulling latest base image: {self.base_image}")
        self.podman.run(["pull", self.base_image])
        self._log(f"Updated base image: {self.base_image}")
        success("Base image updated")

    # ── Snapshot management ──────────────────────────────────────────────────
    def snapshot(self, name: str):
        self._require(name)
        storage_path = self._storage(name)
        if not self.dry_run and storage_path.is_symlink():
            storage_path = storage_path.resolve()
        disk = self._find_disk(storage_path)
        if not disk:
            error(f"No disk image found for '{name}'")
        if self.podman.is_running(name):
            info("Stopping container for consistent snapshot…")
            self.podman.run(["stop", "-t", "120", name])
        snap_name = f"snapshot-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        snap_dir  = storage_path / "snapshots"
        if not self.dry_run:
            snap_dir.mkdir(exist_ok=True)
        info(f"Creating snapshot '{snap_name}'…")
        if disk.suffix == ".qcow2" and _which("qemu-img"):
            self._sys(["qemu-img", "snapshot", "-c", snap_name, str(disk)])
            success(f"Snapshot created: {snap_name} (internal qcow2)")
        else:
            if _which("rsync"):
                self._sys(["rsync", "-a", "--sparse", "--info=progress2",
                           str(disk), str(snap_dir / f"{snap_name}.img")])
            else:
                self._sys(["cp", "--sparse=always",
                           str(disk), str(snap_dir / f"{snap_name}.img")])
            success(f"Snapshot created: {snap_name} (file copy)")
        self._log(f"Created snapshot for {name}: {snap_name}")
        info(f"Restore with: labctl restore {name} {snap_name}")

    def restore(self, name: str, snapshot: str = ""):
        self._require(name)
        storage_path = self._storage(name)
        if not self.dry_run and storage_path.is_symlink():
            storage_path = storage_path.resolve()
        disk = self._find_disk(storage_path)
        if not disk:
            error(f"No disk image found for '{name}'")
        if self.podman.is_running(name):
            info("Stopping container…")
            self.podman.run(["stop", "-t", "120", name])
        if not snapshot:
            self.list_snapshots(name)
            return
        info(f"Restoring snapshot '{snapshot}'…")
        if disk.suffix == ".qcow2" and _which("qemu-img"):
            r = self._sys(["qemu-img", "snapshot", "-a", snapshot, str(disk)],
                          check=False)
            if r.returncode == 0:
                success(f"Restored: {snapshot}")
                self._log(f"Restored snapshot for {name}: {snapshot}")
                info(f"Start with: labctl start {name}")
                return
        for ext in ("img", "qcow2"):
            snap_f = storage_path / "snapshots" / f"{snapshot}.{ext}"
            if snap_f.exists():
                self._sys(["cp", "--sparse=always", str(snap_f), str(disk)])
                success(f"Restored: {snapshot}")
                self._log(f"Restored snapshot for {name}: {snapshot}")
                info(f"Start with: labctl start {name}")
                return
        error(f"Snapshot '{snapshot}' not found")

    def list_snapshots(self, name: str):
        self._require(name)
        storage_path = self._storage(name)
        if not self.dry_run and storage_path.is_symlink():
            storage_path = storage_path.resolve()
        disk = self._find_disk(storage_path)
        header(f"Snapshots for '{name}':")
        if disk and disk.suffix == ".qcow2" and _which("qemu-img"):
            print("\nInternal QCOW2 snapshots:")
            self._sys(["qemu-img", "snapshot", "-l", str(disk)], check=False)
        snap_dir = storage_path / "snapshots"
        if not self.dry_run and snap_dir.is_dir():
            print("\nFile snapshots:")
            r = self._sys(["ls", "-lh", str(snap_dir)], check=False)
            if r.returncode != 0:
                print("  (none)")
        elif not self.dry_run:
            print("  (none)")

    # ── Inspection ───────────────────────────────────────────────────────────
    def list_containers(self, running_only=False, stopped_only=False):
        """List only containers registered/detected as windows."""
        header("Windows containers:")
        all_names = self.podman.get_all_container_names(
            running_only=running_only, stopped_only=stopped_only)
        win_names = self._filter_names_by_type(all_names)
        if not win_names:
            info("  (none)")
            return
        filter_args = []
        for n in win_names:
            filter_args += ["--filter", f"name=^{n}$"]
        args = ["ps", "-a"] + filter_args
        if running_only:
            args = ["ps"] + filter_args
        elif stopped_only:
            args = ["ps", "-a", "--filter", "status=exited"] + filter_args
        args += ["--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"]
        self.podman.run(args)

    def inspect(self, name: str):
        self._require(name)
        self.podman.run(["inspect", name])

    def logs(self, name: str):
        self._require(name)
        self.podman.run(["logs", name])

    def stats(self, name: str = ""):
        if name:
            self._require(name)
            self.podman.run(["stats", name])
        else:
            self.podman.run(["stats"])

    def ports(self, name: str):
        self._require(name)
        p = self.cfg.get_ports(name)
        if p:
            w, r = p
            print(f"  Web: {w}  RDP: {r}")
        self.podman.run(["port", name])

    def list_images(self):
        header("Local images:")
        self.podman.run(["images", "--format",
                         "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"])

    # ── Batch operations ──────────────────────────────────────────────────────
    def clean(self):
        """Remove stopped containers that are registered/detected as windows."""
        all_stopped = self.podman.get_all_container_names(stopped_only=True)
        win_stopped = self._filter_names_by_type(all_stopped)
        if not win_stopped:
            info("No stopped Windows containers")
            return
        info(f"Found {len(win_stopped)} stopped Windows container(s).")
        if not confirm("Remove them?"):
            return
        for cname in win_stopped:
            self.podman.run(["rm", cname], check=False)
            self.cfg.unregister_ports(cname)
            self.cfg.unregister(cname)
        self._log(f"Cleaned {len(win_stopped)} stopped Windows containers")
        success(f"Cleaned {len(win_stopped)} stopped Windows container(s)")

    def clean_all(self):
        """Stop and remove all Windows containers except golden."""
        all_names = self.podman.get_all_container_names()
        win_names = self._filter_names_by_type(all_names)
        targets = [n for n in win_names if n != self.golden_name]
        if not targets:
            info("No Windows containers to clean (except golden)")
            return
        warn(f"This will stop and remove {len(targets)} Windows container(s) (except golden).")
        if not confirm("Continue?"):
            return
        for cname in targets:
            self.podman.run(["stop", "-t", "60", cname], check=False)
            self.podman.run(["rm", cname], check=False)
            self.cfg.unregister_ports(cname)
            self.cfg.unregister(cname)
        self._log("Cleaned all Windows containers except golden")
        success("All Windows containers removed (except golden)")

    def stop_all(self):
        """Stop all running Windows containers except golden."""
        running = self.podman.get_all_container_names(running_only=True)
        win_running = self._filter_names_by_type(running)
        targets = [n for n in win_running if n != self.golden_name]
        if not targets:
            info("No running Windows containers to stop (except golden)")
            return
        warn(f"This will stop {len(targets)} running Windows container(s) (except golden).")
        if not confirm("Continue?"):
            return
        for cname in targets:
            self.podman.run(["stop", "-t", "120", cname], check=False)
        self._log("Stopped all Windows containers except golden")
        success("All Windows containers stopped (except golden)")
    # ── Utilities ─────────────────────────────────────────────────────────────
    def clone(self, source: str, target: str):
        self._require(source)
        if self.podman.container_exists(target):
            error(f"Target '{target}' already exists")
        src_storage = self._storage(source)
        if not self.dry_run and src_storage.is_symlink():
            src_storage = src_storage.resolve()
        src_disk = self._find_disk(src_storage)
        if not src_disk:
            error("Source disk not found")
        if self.podman.is_running(source):
            info("Stopping source container…")
            self.podman.run(["stop", "-t", "120", source])
        info(f"Cloning '{source}' to '{target}'…")
        self._fast_clone(src_storage, self._storage(target))
        web_port, rdp_port = self.cfg.get_next_ports()
        self.podman.run([
            "run", "-d", "--name", target,
            "-e", f"RAM_SIZE={self._def('ram')}",
            "-e", f"CPU_CORES={self._def('cpu')}",
            "-p", f"{web_port}:8006",
            "-p", f"{rdp_port}:3389/tcp",
            "-p", f"{rdp_port}:3389/udp",
            "--device", "/dev/kvm",
            "--device", "/dev/net/tun",
            "--cap-add", "NET_ADMIN",
            "--stop-timeout", "120",
            "-v", f"{self._storage(target)}:/storage:Z",
            self.base_image,
        ])
        self.cfg.register_ports(target, web_port, rdp_port)
        self.cfg.register(target, "windows",
                          {"web_port": web_port, "rdp_port": rdp_port})
        self._log(f"Cloned: {source} -> {target}")
        success(f"Cloned '{source}' to '{target}'")
        print(f"  Web: http://localhost:{web_port}")
        print(f"  RDP: localhost:{rdp_port}")

    def rename(self, old: str, new: str):
        self._require(old)
        self.podman.run(["rename", old, new])
        self.cfg.rename_ports(old, new)
        self.cfg.rename_reg(old, new)
        old_st = self._storage(old)
        if old_st.is_dir() and not old_st.is_symlink() and not self.dry_run:
            old_st.rename(self._storage(new))
        self._log(f"Renamed: {old} -> {new}")
        success(f"Renamed '{old}' to '{new}'")

    def export_storage(self, name: str, path: str):
        self._require(name)
        storage_path = self._storage(name)
        if not self.dry_run and storage_path.is_symlink():
            storage_path = storage_path.resolve()
        disk = self._find_disk(storage_path)
        if not disk:
            error("No disk found")
        info(f"Exporting: {disk}")
        if not self.dry_run:
            with open(path, "wb") as fh:
                tool = "pigz" if _which("pigz") else "gzip"
                with open(str(disk), "rb") as src:
                    gz = subprocess.Popen([tool, "-c"], stdin=src, stdout=fh)
                    gz.communicate()
            r = self._sys(["du", "-h", path], capture=True, check=False)
            sz = r.stdout.split()[0] if r.returncode == 0 else "?"
            success(f"Exported to: {path} ({sz})")

    def import_storage(self, path: str, name: str):
        if not Path(path).exists() and not self.dry_run:
            error(f"File not found: {path}")
        storage_path = self._storage(name)
        if not self.dry_run:
            storage_path.mkdir(parents=True, exist_ok=True)
        info("Importing…")
        if not self.dry_run:
            if path.endswith(".gz"):
                tool = "pigz" if _which("pigz") else "gunzip"
                flag = "-dc"
                with open(path, "rb") as src:
                    with open(str(storage_path / "data.qcow2"), "wb") as dst:
                        decomp = subprocess.Popen([tool, flag],
                                                  stdin=src, stdout=dst)
                        decomp.communicate()
            else:
                self._sys(["cp", "--sparse=always", path,
                           str(storage_path / "data.qcow2")])
        success(f"Imported to: {storage_path}")
        info(f"Create container: labctl create {name} --type windows")

    def remove_image(self, image: str):
        if not self.podman.image_exists(image):
            error(f"Image '{image}' not found")
        self.podman.run(["rmi", image])
        success(f"Removed: {image}")

    def rdp(self, name: str):
        self._require(name)
        if not self.podman.is_running(name) and not self.dry_run:
            error(f"Container '{name}' is not running. Start it first.")
        ports = self.cfg.get_ports(name)
        rdp_port = ports[1] if ports else 3389
        info(f"Connecting to localhost:{rdp_port}…")
        for cli in ("xfreerdp3", "xfreerdp"):
            if _which(cli):
                self._sys([cli, f"/v:localhost:{rdp_port}",
                           "/u:Docker", "/p:admin",
                           "/dynamic-resolution", "+clipboard"],
                          check=False)
                return
        warn("xfreerdp not found.")
        print(f"  Manual: localhost:{rdp_port}  (Docker/admin)")

    def web(self, name: str):
        self._require(name)
        if not self.podman.is_running(name) and not self.dry_run:
            error(f"Container '{name}' is not running. Start it first.")
        ports = self.cfg.get_ports(name)
        web_port = ports[0] if ports else 8006
        url = f"http://localhost:{web_port}"
        info(f"Opening: {url}")
        if _which("xdg-open"):
            self._sys(["xdg-open", url], check=False)
        else:
            print(f"  Open manually: {url}")

    def vnc(self, name: str):
        self._require(name)
        if not self.podman.is_running(name) and not self.dry_run:
            error(f"Container '{name}' is not running. Start it first.")
        ip = self.podman.get_ip(name)
        if not ip and not self.dry_run:
            error(f"Could not get IP for '{name}'")
        addr = f"{ip}:5900" if ip else "CONTAINER_IP:5900"
        info(f"Connecting to {addr}…")
        if _which("vncviewer"):
            self._sys(["vncviewer", addr], check=False)
        else:
            warn("vncviewer not found.")
            print(f"  Manual: vncviewer {addr}")

    def _filter_names_by_type(self, all_names: List[str]) -> List[str]:
        """Filter container names to only those belonging to windows.

        Uses the registry first. For unregistered containers, uses heuristics:
        containers whose image contains 'dockurr' or 'windows' or match the
        windows golden name are treated as windows.
        """
        result: List[str] = []
        linux_golden = self.cfg.get("linux.golden_name", "kali-golden")
        windows_golden = self.golden_name
        for name in all_names:
            reg_type = self.cfg.get_type(name)
            if reg_type == "windows":
                result.append(name)
            elif reg_type is not None:
                continue  # registered as something else, skip
            else:
                # Unregistered — heuristic
                if name == windows_golden:
                    result.append(name)
                elif name == linux_golden:
                    continue
                else:
                    img = self.podman._run(
                        ["inspect", "--format={{.ImageName}}", name],
                        capture=True, check=False).stdout.strip().lower()
                    if not img:
                        img = self.podman._run(
                            ["inspect", "--format={{.Image}}", name],
                            capture=True, check=False).stdout.strip().lower()
                    if "dockurr" in img or "windows" in img:
                        result.append(name)
                    elif "kali" in img:
                        continue
                    # Unknown image — do NOT include under windows
        return result

    # ── internal ──────────────────────────────────────────────────────────────
    def _require(self, name: str):
        if not self.podman.container_exists(name) and not self.dry_run:
            error(f"Container '{name}' does not exist")


# ══════════════════════════════════════════════════════════════════════════════
# LabManager
# ══════════════════════════════════════════════════════════════════════════════
class LabManager:
    def __init__(self, cfg: Config, podman: Podman, net: NetworkManager,
                 linux: "LinuxManager", windows: "WindowsManager",
                 dry_run=False, verbose=False):
        self.cfg     = cfg
        self.podman  = podman
        self.net     = net
        self.linux   = linux
        self.windows = windows
        self.dry_run = dry_run
        self.verbose = verbose

    def _lab_file(self, name: str) -> Path:
        return LABS_DIR / f"{name}.json"

    def create(self, lab_name: str, config_file: str = ""):
        if config_file:
            cfg_path = Path(config_file)
            if not cfg_path.exists() and not self.dry_run:
                error(f"Config file not found: {config_file}")
            lab_cfg = json.loads(cfg_path.read_text())
        else:
            lab_cfg = {"name": lab_name, "containers": []}

        lab_cfg["name"] = lab_name
        lf = self._lab_file(lab_name)
        if lf.exists():
            error(f"Lab '{lab_name}' already exists")

        header(f"Creating lab '{lab_name}'…")
        for ct in lab_cfg.get("containers", []):
            cname  = ct.get("name", "")
            ctype  = ct.get("type", "linux")
            if not cname:
                warn("Skipping container with no name")
                continue
            info(f"  Creating {ctype} container '{cname}'…")
            if ctype == "linux":
                self.linux.create(cname)
            elif ctype == "windows":
                self.windows.create(
                    cname,
                    version =ct.get("version", ""),
                    ram     =ct.get("ram", ""),
                    cpu     =ct.get("cpu", ""),
                )
            else:
                warn(f"  Unknown type '{ctype}' for '{cname}', skipping")

        if not self.dry_run:
            lf.write_text(json.dumps(lab_cfg, indent=2))
        success(f"Lab '{lab_name}' created")

    def start(self, lab_name: str):
        lab_cfg = self._load_lab(lab_name)
        header(f"Starting lab '{lab_name}'…")
        for ct in lab_cfg.get("containers", []):
            cname, ctype = ct.get("name", ""), ct.get("type", "linux")
            if not cname: continue
            info(f"  Starting '{cname}'…")
            if ctype == "linux":
                self.linux.start(cname)
            else:
                self.windows.start(cname)

    def stop(self, lab_name: str):
        lab_cfg = self._load_lab(lab_name)
        header(f"Stopping lab '{lab_name}'…")
        for ct in reversed(lab_cfg.get("containers", [])):
            cname, ctype = ct.get("name", ""), ct.get("type", "linux")
            if not cname: continue
            info(f"  Stopping '{cname}'…")
            if ctype == "linux":
                self.linux.stop(cname)
            else:
                self.windows.stop(cname)

    def delete(self, lab_name: str):
        lab_cfg = self._load_lab(lab_name)
        warn(f"This will delete all containers in lab '{lab_name}'.")
        if not confirm("Continue?"):
            print("Aborted.")
            return
        for ct in lab_cfg.get("containers", []):
            cname, ctype = ct.get("name", ""), ct.get("type", "linux")
            if not cname: continue
            if self.podman.container_exists(cname):
                info(f"  Deleting '{cname}'…")
                if ctype == "linux":
                    self.linux.delete(cname)
                else:
                    self.windows.delete(cname)
        lf = self._lab_file(lab_name)
        if lf.exists() and not self.dry_run:
            lf.unlink()
        success(f"Lab '{lab_name}' deleted")

    def status(self, lab_name: str):
        lab_cfg = self._load_lab(lab_name)
        header(f"Lab '{lab_name}' status:")
        for ct in lab_cfg.get("containers", []):
            cname = ct.get("name", "")
            ctype = ct.get("type", "linux")
            if not cname: continue
            state = self.podman.get_state(cname) or "not found"
            col = Colors.GREEN if state == "running" else (
                  Colors.YELLOW if state == "exited" else Colors.RED)
            print(f"  {col}{cname}{Colors.RESET}  [{ctype}]  {state}")

    def list_labs(self):
        header("Labs:")
        labs = list(LABS_DIR.glob("*.json"))
        if not labs:
            info("No labs found. Create one with: labctl lab create <name>")
            return
        for lf in labs:
            try:
                d = json.loads(lf.read_text())
                containers = d.get("containers", [])
                print(f"  {Colors.BOLD}{d.get('name', lf.stem)}{Colors.RESET}"
                      f"  ({len(containers)} container(s))")
            except Exception:
                print(f"  {lf.stem}  (parse error)")

    def _load_lab(self, name: str) -> dict:
        lf = self._lab_file(name)
        if not lf.exists() and not self.dry_run:
            error(f"Lab '{name}' not found")
        if lf.exists():
            return json.loads(lf.read_text())
        return {"name": name, "containers": []}


# ══════════════════════════════════════════════════════════════════════════════
# CLI – argument parser
# ══════════════════════════════════════════════════════════════════════════════
class _GroupedHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Hides the flat subcommand listing so the grouped epilog takes its place."""
    def _format_action(self, action):
        if isinstance(action, argparse._SubParsersAction):
            return ""
        return super()._format_action(action)


def _build_parser() -> argparse.ArgumentParser:
    _S = argparse.SUPPRESS   # suppress from auto-list; grouped epilog replaces it

    _EPILOG = """\
Commands:

  Lifecycle
    create              Create a new container  (--type linux|windows required)
    start               Start a stopped container
    stop                Stop a running container
    restart             Restart a container
    delete              Stop and remove a container

  Interaction
    connect             Interactive shell (Linux: tmux) or RDP launch (Windows)
    exec                Run a command inside a Linux container
    logs                Show container logs
    inspect             Show full container details
    stats               Show resource usage  [name]

  Container Management
    list                List containers  [--running|--stopped]  [--type]
    clone               Clone a container  source target
    rename              Rename a container  old new
    clean               Remove all stopped containers
    clean-all           Remove all containers except golden
    stop-all            Stop all running containers except golden
    list-images         List locally cached images
    remove-image        Remove a local image  image

  Networking & Port Forwards
    forward add         Add a host→container forward  name host:ctr[/tcp|udp]
    forward list        Show all active port forwards
    forward remove      Remove a forward by host port  name host_port
    forward flush       Remove all forwards  [name]

  Linux (Kali)
    pause               Pause a container
    unpause             Unpause a paused container
    mount               Mount container filesystem to host
    umount              Unmount container filesystem
    fix-x11             Fix X11/XAUTH display forwarding
    export-container    Export container as tar.gz  name path
    import-image        Import a container image from tar  tar name
    cleanup-golden      Remove dangling golden images
    recreate-golden     Recreate golden container from base image
    restore-golden      Restore golden container from saved image

  Windows
    force-stop          Force-stop a hung container
    ports               Show web/RDP port mappings
    rdp                 Open an RDP client session
    web                 Open the web viewer  (port 8006+)
    vnc                 Open a VNC client session
    snapshot            Create a storage snapshot
    list-snapshots      List available snapshots
    restore             Restore from a snapshot  name [snapshot]
    export-storage      Export Windows storage directory  name path
    import-storage      Import a Windows storage directory  path name
    adopt               Adopt an existing storage dir as the golden  path
    convert-golden      Convert golden disk image to QCOW2
    golden-status       Show golden storage status

  Golden Images
    golden              Shell into (Linux) or start (Windows) golden container
    commit              Save golden container/storage as the new golden image
    update-base         Pull the latest base image

  Labs
    lab create          Create a lab from a JSON config file  name [--config]
    lab start           Start all containers in a lab  name
    lab stop            Stop all containers in a lab  name
    lab delete          Delete all containers in a lab  name
    lab status          Show container statuses for a lab  name
    lab list            List all saved labs

  Configuration
    config show         Show merged configuration
    config set          Set a config value  key value  (e.g. windows.default_ram 8G)
    config reset        Reset all configuration to defaults

  System
    version             Show labctl version
    help                Show this help

Use 'labctl <command> --help' for per-command options and arguments."""

    p = argparse.ArgumentParser(
        prog="labctl",
        description="Unified lab container management (Linux + Windows via Podman)",
        formatter_class=_GroupedHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Print commands without executing")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print commands before executing")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    # ── helpers ──
    def _name(sp): sp.add_argument("name", help="Container name")
    def _type(sp, required=False):
        sp.add_argument("--type", choices=["linux", "windows"],
                        required=required,
                        default=None,
                        help="Container type (auto-detected from registry if omitted)")

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    c = sub.add_parser("create", help=_S,
                       description="Create a new container from the golden image.")
    _name(c); _type(c, required=True)
    c.add_argument("--version",   default="", help="(Windows) OS version")
    c.add_argument("--ram",       default="", help="(Windows) RAM size, e.g. 4G")
    c.add_argument("--cpu",       default="", help="(Windows) CPU core count")
    c.add_argument("--disk",      default="", help="(Windows) disk size, e.g. 64G")
    c.add_argument("--user",      default="", help="(Windows) username")
    c.add_argument("--pass",      dest="password", default="",
                   help="(Windows) password")
    c.add_argument("--fresh",     action="store_true",
                   help="(Windows) skip golden image, do a fresh OS install")
    c.add_argument("--full-copy", dest="full_copy", action="store_true",
                   help="(Windows) full disk copy instead of CoW clone")

    for cmd in ("start", "stop", "restart", "delete"):
        sp = sub.add_parser(cmd, help=_S); _name(sp); _type(sp)

    # ── Interaction ────────────────────────────────────────────────────────────
    for cmd in ("connect", "inspect", "logs"):
        sp = sub.add_parser(cmd, help=_S); _name(sp); _type(sp)

    sp = sub.add_parser("exec", help=_S,
                        description="Execute a command inside a Linux container.")
    _name(sp); _type(sp)
    sp.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute")

    sp = sub.add_parser("stats", help=_S,
                        description="Show resource usage. Omit name to show all containers.")
    sp.add_argument("name", nargs="?", default="", help="Container name (optional)")
    _type(sp)

    # ── Container Management ───────────────────────────────────────────────────
    sp = sub.add_parser("list", help=_S,
                        description="List containers. Filter by state or type.")
    _type(sp)
    sp.add_argument("--running", action="store_true", help="Show only running containers")
    sp.add_argument("--stopped", action="store_true", help="Show only stopped containers")

    for cmd in ("list-running", "list-stopped"):   # legacy compat
        sp = sub.add_parser(cmd, help=_S); _type(sp)

    sub.add_parser("list-images", help=_S)

    sp = sub.add_parser("remove-image", help=_S)
    sp.add_argument("image"); _type(sp)

    sp = sub.add_parser("clone", help=_S,
                        description="Clone a container (Linux or Windows).")
    sp.add_argument("source"); sp.add_argument("target"); _type(sp)

    sp = sub.add_parser("rename", help=_S)
    sp.add_argument("old"); sp.add_argument("new"); _type(sp)

    for cmd in ("clean", "clean-all", "stop-all"):
        sp = sub.add_parser(cmd, help=_S); _type(sp)

    # ── Linux (Kali) ───────────────────────────────────────────────────────────
    for cmd in ("pause", "unpause", "mount", "umount"):
        sp = sub.add_parser(cmd, help=_S); _name(sp); _type(sp)

    sub.add_parser("fix-x11", help=_S)

    sp = sub.add_parser("export-container", help=_S,
                        description="Export a Linux container as a tar.gz archive.")
    _name(sp); sp.add_argument("path"); _type(sp)

    sp = sub.add_parser("import-image", help=_S,
                        description="Import a container image from a tar archive.")
    sp.add_argument("tar"); sp.add_argument("name"); _type(sp)

    for cmd in ("cleanup-golden", "recreate-golden", "restore-golden"):
        sp = sub.add_parser(cmd, help=_S); _type(sp)

    # ── Windows ────────────────────────────────────────────────────────────────
    for cmd in ("force-stop", "ports", "snapshot", "list-snapshots",
                "rdp", "web", "vnc"):
        sp = sub.add_parser(cmd, help=_S); _name(sp); _type(sp)

    sp = sub.add_parser("restore", help=_S,
                        description="Restore a Windows container from a snapshot.")
    _name(sp)
    sp.add_argument("snapshot", nargs="?", default="", help="Snapshot name (omit for latest)")
    _type(sp)

    sp = sub.add_parser("export-storage", help=_S,
                        description="Export a Windows container storage directory.")
    _name(sp); sp.add_argument("path"); _type(sp)

    sp = sub.add_parser("import-storage", help=_S,
                        description="Import a Windows storage directory as a container.")
    sp.add_argument("path"); sp.add_argument("name"); _type(sp)

    sp = sub.add_parser("adopt", help=_S,
                        description="Adopt an existing storage directory as the Windows golden image.")
    sp.add_argument("path"); _type(sp)

    for cmd in ("convert-golden", "golden-status"):
        sp = sub.add_parser(cmd, help=_S); _type(sp)

    # ── Golden Images ──────────────────────────────────────────────────────────
    sp = sub.add_parser("golden", help=_S,
                        description="Shell into the Linux golden container, "
                                    "or start the Windows golden container.")
    _type(sp, required=True)
    sp.add_argument("--version", default="", help="(Windows) OS version")
    sp.add_argument("--ram",     default="", help="(Windows) RAM size")
    sp.add_argument("--cpu",     default="", help="(Windows) CPU cores")

    sp = sub.add_parser("commit", help=_S,
                        description="Linux: commit golden container to a saved image. "
                                    "Windows: save container storage as the new golden.")
    sp.add_argument("name", nargs="?", default="",
                    help="Container name (required for Windows)")
    _type(sp, required=True)

    sp = sub.add_parser("update-base", help=_S,
                        description="Pull the latest base image for the given type.")
    _type(sp, required=True)

    # ── Labs ───────────────────────────────────────────────────────────────────
    lp = sub.add_parser("lab", help=_S,
                        description="Manage lab environments (named groups of containers).")
    lsub = lp.add_subparsers(dest="lab_cmd", metavar="<subcommand>")
    sp = lsub.add_parser("create", help="Create a lab from a JSON config file")
    sp.add_argument("name")
    sp.add_argument("--config", dest="config_file", default="",
                    help="Path to lab JSON config file")
    for lcmd, lhelp in [("start",  "Start all containers in the lab"),
                         ("stop",   "Stop all containers in the lab"),
                         ("delete", "Delete all containers in the lab"),
                         ("status", "Show container statuses for the lab")]:
        sp = lsub.add_parser(lcmd, help=lhelp)
        sp.add_argument("name")
    lsub.add_parser("list", help="List all saved labs")

    # ── Networking & Port Forwards ─────────────────────────────────────────────
    fp = sub.add_parser("forward", help=_S,
                        description="Manage host→container port forwards via iptables DNAT.\n"
                                    "Rules require sudo and are not persistent across reboots.\n"
                                    "Run 'forward flush' before rebooting for a clean teardown.")
    fsub = fp.add_subparsers(dest="fwd_cmd", metavar="<subcommand>")

    sp = fsub.add_parser("add",
                         help="Add a forward  name host:ctr[/tcp|udp]")
    sp.add_argument("name", help="Container name")
    sp.add_argument("spec", help="host_port:container_port[/tcp|udp]  e.g. 8080:80/tcp")

    sp = fsub.add_parser("remove",
                         help="Remove a forward by container and host port")
    sp.add_argument("name", help="Container name")
    sp.add_argument("host_port", type=int, help="Host port to remove")

    fsub.add_parser("list", help="List all active port forwards")

    sp = fsub.add_parser("flush",
                         help="Remove all forwards, or all for one container")
    sp.add_argument("name", nargs="?", default="",
                    help="Container name (omit to flush all)")

    # ── Configuration ──────────────────────────────────────────────────────────
    cp = sub.add_parser("config", help=_S,
                        description="Manage labctl configuration (stored in ~/.labctl/config.json).")
    csub = cp.add_subparsers(dest="config_cmd", metavar="<subcommand>")
    csub.add_parser("show",  help="Show merged configuration (defaults + overrides)")
    sp = csub.add_parser("set",
                         help="Set a config key  (e.g. windows.default_ram 8G)")
    sp.add_argument("key"); sp.add_argument("value")
    csub.add_parser("reset", help="Reset all configuration to built-in defaults")

    # ── System ─────────────────────────────────────────────────────────────────
    sub.add_parser("version", help=_S)
    sub.add_parser("help",    help=_S)

    return p


# ══════════════════════════════════════════════════════════════════════════════
# Main dispatch
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None or args.command == "help":
        parser.print_help()
        return

    if args.command == "version":
        print(f"labctl v{VERSION}")
        return

    dry   = args.dry_run
    verb  = args.verbose
    cfg   = Config()
    pod   = Podman(dry_run=dry, verbose=verb)
    net   = NetworkManager(cfg, pod)
    linux = LinuxManager(cfg, pod, net, dry_run=dry, verbose=verb)
    win   = WindowsManager(cfg, pod, net, dry_run=dry, verbose=verb)
    lab   = LabManager(cfg, pod, net, linux, win, dry_run=dry, verbose=verb)
    fwd   = ForwardManager(cfg, pod, dry_run=dry, verbose=verb)

    cmd = args.command

    # ── config ──────────────────────────────────────────────────────────────
    if cmd == "config":
        cc = getattr(args, "config_cmd", None)
        if cc == "show":
            cfg.show()
        elif cc == "set":
            cfg.set_key(args.key, args.value)
            success(f"Set {args.key} = {args.value}")
        elif cc == "reset":
            if confirm("Reset all config to defaults?"):
                cfg.reset()
                success("Config reset to defaults")
        else:
            parser.parse_args(["config", "--help"])
        return

    # ── lab ──────────────────────────────────────────────────────────────────
    if cmd == "lab":
        lc = getattr(args, "lab_cmd", None)
        if lc == "create":
            lab.create(args.name, getattr(args, "config_file", ""))
        elif lc == "start":
            lab.start(args.name)
        elif lc == "stop":
            lab.stop(args.name)
        elif lc == "delete":
            lab.delete(args.name)
        elif lc == "status":
            lab.status(args.name)
        elif lc == "list":
            lab.list_labs()
        else:
            parser.parse_args(["lab", "--help"])
        return

    # ── resolve type (auto-detect from registry for existing containers) ────
    ctype = getattr(args, "type", None)
    if not ctype:
        # Try to auto-detect from the container name in the registry
        name_candidate = (getattr(args, "name",   None) or
                          getattr(args, "source", None) or
                          getattr(args, "old",    None))
        if name_candidate:
            ctype = cfg.get_type(name_candidate)

    def _linux():
        if ctype and ctype != "linux":
            error(f"Command '{cmd}' is Linux-only but container is type '{ctype}'")
        return linux

    def _windows():
        if ctype and ctype != "windows":
            error(f"Command '{cmd}' is Windows-only but container is type '{ctype}'")
        return win

    def _guess_type_from_podman(name: str) -> Optional[str]:
        img = pod.get_image_ref(name).strip().lower()
        if not img:
            return None
        if "dockurr" in img or "windows" in img:
            return "windows"
        if "kali" in img:
            return "linux"
        return None

    def _pick_container(ref: str) -> str:
        matches = pod.resolve_ref(ref)
        if not matches:
            error(f"Container '{ref}' not found (name/ID/prefix).")
        if len(matches) == 1:
            return matches[0]

        # Ambiguous: ask user
        print(f"Multiple containers match '{ref}':")
        for i, n in enumerate(matches, 1):
            t = cfg.get_type(n) or _guess_type_from_podman(n) or "unknown"
            print(f"  {i}) {n} ({t})")
        while True:
            sel = input(f"Select 1-{len(matches)} (or blank to abort): ").strip()
            if not sel:
                error("Aborted.")
            if sel.isdigit():
                k = int(sel)
                if 1 <= k <= len(matches):
                    return matches[k - 1]

    def _auto(container_ref: str = ""):
        """Return (mgr, resolved_type) auto-detecting from registry/podman."""
        name = _pick_container(container_ref) if container_ref else ""
        ct = ctype or (cfg.get_type(name) if name else None)
        if not ct and name:
            ct = _guess_type_from_podman(name)

        if ct == "linux":
            return linux, "linux"
        if ct == "windows":
            return win, "windows"

        error(f"Cannot determine container type for '{container_ref}'. "
              "Pass --type linux|windows")

    # ── command dispatch ─────────────────────────────────────────────────────
    if cmd == "create":
        if ctype == "linux":
            linux.create(args.name)
        else:
            win.create(args.name,
                       version=args.version, ram=args.ram, cpu=args.cpu,
                       disk=args.disk, user=args.user,fresh=args.fresh, full_copy=args.full_copy)

    elif cmd == "start":
        mgr, _ = _auto(args.name)
        mgr.start(args.name)

    elif cmd == "stop":
        mgr, _ = _auto(args.name)
        mgr.stop(args.name)

    elif cmd == "restart":
        mgr, _ = _auto(args.name)
        mgr.restart(args.name)

    elif cmd == "delete":
        mgr, _ = _auto(args.name)
        mgr.delete(args.name)

    elif cmd == "connect":
        mgr, _ = _auto(args.name)
        mgr.connect(args.name)

    elif cmd == "exec":
        _linux().exec_cmd(args.name, list(args.cmd))

    elif cmd == "inspect":
        mgr, _ = _auto(args.name)
        mgr.inspect(args.name)

    elif cmd == "logs":
        mgr, _ = _auto(args.name)
        mgr.logs(args.name)

    elif cmd == "stats":
        if ctype == "windows":
            win.stats(args.name)
        elif ctype == "linux":
            linux.stats(args.name)
        elif args.name:
            mgr, _ = _auto(args.name)
            mgr.stats(args.name)
        else:
            # Show all stats
            pod.run(["stats"])

    elif cmd == "clone":
        mgr, _ = _auto(args.source)
        mgr.clone(args.source, args.target)

    elif cmd == "rename":
        mgr, _ = _auto(args.old)
        mgr.rename(args.old, args.new)

    elif cmd == "list":
        if ctype == "windows":
            win.list_containers(running_only=args.running,
                                stopped_only=args.stopped)
        elif ctype == "linux":
            linux.list_containers(running_only=args.running,
                                  stopped_only=args.stopped)
        else:
            linux.list_containers(running_only=args.running,
                                  stopped_only=args.stopped)
            win.list_containers(running_only=args.running,
                                stopped_only=args.stopped)

    elif cmd == "list-running":
        if ctype == "windows":
            win.list_containers(running_only=True)
        elif ctype == "linux":
            linux.list_containers(running_only=True)
        else:
            linux.list_containers(running_only=True)
            win.list_containers(running_only=True)

    elif cmd == "list-stopped":
        if ctype == "windows":
            win.list_containers(stopped_only=True)
        elif ctype == "linux":
            linux.list_containers(stopped_only=True)
        else:
            linux.list_containers(stopped_only=True)
            win.list_containers(stopped_only=True)

    elif cmd == "list-images":
        linux.list_images()   # podman images is shared

    elif cmd == "remove-image":
        if ctype == "windows":
            win.remove_image(args.image)
        else:
            linux.remove_image(args.image)

    # ── Linux-only ──────────────────────────────────────────────────────────
    elif cmd == "pause":
        _linux().pause(args.name)

    elif cmd == "unpause":
        _linux().unpause(args.name)

    elif cmd == "mount":
        _linux().mount(args.name)

    elif cmd == "umount":
        _linux().umount(args.name)

    elif cmd == "fix-x11":
        _linux().fix_x11()

    elif cmd == "export-container":
        _linux().export_container(args.name, args.path)

    elif cmd == "import-image":
        _linux().import_image(args.tar, args.name)

    elif cmd == "cleanup-golden":
        if ctype == "windows":
            error("cleanup-golden is Linux-only. "
                  "Use 'labctl golden-status --type windows' for Windows golden info.")
        _linux().cleanup_golden()

    # ── Windows-only ─────────────────────────────────────────────────────────
    elif cmd == "force-stop":
        _windows().force_stop(args.name)

    elif cmd == "ports":
        _windows().ports(args.name)

    elif cmd == "snapshot":
        _windows().snapshot(args.name)

    elif cmd == "restore":
        _windows().restore(args.name, getattr(args, "snapshot", ""))

    elif cmd == "list-snapshots":
        _windows().list_snapshots(args.name)

    elif cmd == "export-storage":
        _windows().export_storage(args.name, args.path)

    elif cmd == "import-storage":
        _windows().import_storage(args.path, args.name)

    elif cmd == "rdp":
        _windows().rdp(args.name)

    elif cmd == "web":
        _windows().web(args.name)

    elif cmd == "vnc":
        _windows().vnc(args.name)

    elif cmd == "adopt":
        _windows().adopt(args.path)

    elif cmd == "convert-golden":
        _windows().convert_golden()

    elif cmd == "golden-status":
        _windows().golden_status()

    # ── Golden image management ───────────────────────────────────────────────
    elif cmd == "golden":
        if ctype == "linux":
            linux.golden()
        else:
            win.golden(version=args.version, ram=args.ram, cpu=args.cpu)

    elif cmd == "commit":
        if ctype == "linux":
            linux.commit()
        else:
            if not args.name:
                error("Container name required for Windows commit")
            win.commit(args.name)

    elif cmd == "update-base":
        if ctype == "linux":
            linux.update_base()
        else:
            win.update_base()

    elif cmd == "recreate-golden":
        _linux().recreate_golden()

    elif cmd == "restore-golden":
        _linux().restore_golden()

    # ── Batch operations ──────────────────────────────────────────────────────
    elif cmd == "clean":
        if ctype == "windows":
            win.clean()
        elif ctype == "linux":
            linux.clean()
        else:
            linux.clean(); win.clean()

    elif cmd == "clean-all":
        if ctype == "windows":
            win.clean_all()
        elif ctype == "linux":
            linux.clean_all()
        else:
            linux.clean_all(); win.clean_all()

    elif cmd == "stop-all":
        if ctype == "windows":
            win.stop_all()
        elif ctype == "linux":
            linux.stop_all()
        else:
            linux.stop_all(); win.stop_all()

    # ── Port forward management ───────────────────────────────────────────────
    elif cmd == "forward":
        fc = getattr(args, "fwd_cmd", None)
        if fc == "add":
            fwd.add(args.name, args.spec)
        elif fc == "remove":
            fwd.remove(args.name, args.host_port)
        elif fc == "list":
            fwd.list()
        elif fc == "flush":
            fwd.flush(getattr(args, "name", ""))
        else:
            parser.parse_args(["forward", "--help"])

    else:
        parser.print_help()


def auto_resolve_type(cfg, linux_mgr, win_mgr, pod, name):
    """
    Auto-resolve container type from name.
    
    Strategy:
    1. Check registry first (cfg.gettype) - most reliable
    2. If not registered, check if container exists and use heuristics
       via filternamesbytype() on both managers
    3. If found in exactly one manager, use that type
    4. If ambiguous or not found, return None
    
    Args:
        cfg: Config instance
        linux_mgr: LinuxManager instance
        win_mgr: WindowsManager instance
        pod: Podman instance
        name: Container name to resolve
    
    Returns:
        tuple (manager, type_str) or (None, None) if cannot resolve
    
    Example:
        mgr, ctype = auto_resolve_type(cfg, linux, win, pod, 'Development')
        if mgr is None:
            error(f"Cannot determine type for '{name}'. Pass --type")
        mgr.start(name)
    """
    # First try: check registry (registered containers)
    reg_type = cfg.gettype(name)
    if reg_type == 'linux':
        return (linux_mgr, 'linux')
    elif reg_type == 'windows':
        return (win_mgr, 'windows')
    
    # Second try: check if container exists and use heuristics
    if pod.container_exists(name):
        all_names = [name]
        
        # Check both managers using their heuristics
        # (image name patterns, golden container names, etc.)
        linux_matches = linux_mgr.filternamesbytype(all_names)
        windows_matches = win_mgr.filternamesbytype(all_names)
        
        # If only one manager claims it, use that
        if linux_matches and not windows_matches:
            return (linux_mgr, 'linux')
        elif windows_matches and not linux_matches:
            return (win_mgr, 'windows')
        elif linux_matches and windows_matches:
            # Both claim it - ambiguous (shouldn't happen in practice)
            # Return None to force user to specify
            pass
    
    # Cannot resolve (ambiguous, doesn't exist, or unrecognized)
    return (None, None)


if __name__ == "__main__":
    main()


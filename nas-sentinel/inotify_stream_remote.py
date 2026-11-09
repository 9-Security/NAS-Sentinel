#!/usr/bin/env python3
"""
Real-time Linux kernel inotify stream for Synology NAS (zero external packages).
Uses ctypes + libc.so.6 inotify_init / inotify_add_watch to monitor web server
and security directories with millisecond latency.

Outputs newline-delimited JSON (NDJSON) to stdout.
When the SSH connection closes, the kernel automatically closes the inotify fd
and releases all watches cleanly.
"""
import ctypes
import grp
import hashlib
import json
import os
import pwd
import re
import select
import stat
import struct
import sys
import time

# inotify event mask constants (from <sys/inotify.h>)
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

WATCH_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

FLAG_NAMES = [
    (IN_CREATE, "IN_CREATE (新建)"),
    (IN_MODIFY, "IN_MODIFY (修改)"),
    (IN_CLOSE_WRITE, "IN_CLOSE_WRITE (寫入完成)"),
    (IN_ATTRIB, "IN_ATTRIB (權限/屬性變更)"),
    (IN_MOVED_FROM, "IN_MOVED_FROM (移出/更名)"),
    (IN_MOVED_TO, "IN_MOVED_TO (移入/更名)"),
    (IN_DELETE, "IN_DELETE (刪除)"),
    (IN_DELETE_SELF, "IN_DELETE_SELF (目標刪除)"),
    (IN_MOVE_SELF, "IN_MOVE_SELF (目標移動)"),
]

# Full directory trees to watch
WATCH_TARGETS = [
    ("/etc/nginx", 4, "web_config", "nginx_etc"),
    ("/usr/syno/share/nginx", 4, "web_config", "nginx_share"),
    ("/var/tmp/nginx/html", 3, "web_root", "nginx_tmp_html"),
    ("/usr/syno/synoman", 4, "web_root", "dsm_synoman"),
    ("/var/lib/letsencrypt", 3, "web_root", "letsencrypt_root"),
    ("/volume1/web", 4, "user_web", "web_station"),
    ("/etc/sysctl.d", 2, "security_config", "security_configs"),
    ("/usr/syno/etc/firewall.d", 2, "security_config", "security_configs"),
    ("/volume1/public", 1, "shared_watch", "shared_watched"),
    ("/volume1/tmp", 1, "shared_watch", "shared_watched"),
]

# Parent directories watched with specific filename filter (survives atomic rename/vim/sed -i)
FILTERED_DIR_TARGETS = [
    ("/etc/ssh", {"sshd_config"}, "security_config", "security_configs"),
    ("/etc", {"crontab", "chrony.conf.user", "ld.so.preload", "ld.so.conf"}, "security_config", "security_configs"),
    ("/var/services/homes/shar/.ssh", {"authorized_keys"}, "security_config", "security_configs"),
    ("/bin", {"sh", "bash", "ps", "ls", "netstat", "login", "kmod"}, "system_binary", "system_binaries"),
    ("/usr/bin", {"sshd", "sudo", "nginx", "find", "top", "kill", "sha256sum"}, "system_binary", "system_binaries"),
    ("/usr/sbin", {"ip", "lsmod", "tcpdump", "aa-status"}, "system_binary", "system_binaries"),
    ("/usr/syno/bin", {"synowebapi"}, "system_binary", "system_binaries"),
    ("/usr/syno/sbin", {"synotifyd"}, "system_binary", "system_binaries"),
]

KNOWN_DSM_SPECIAL_FILES = {
    "/usr/syno/synoman/webapi/otp.cgi",
    "/usr/syno/synoman/scripts/uistrings.php",
    "/usr/syno/synoman/webman/modules/Indexer/indexer.php",
}

SUSPICIOUS_EXTS = {".php", ".phtml", ".php5", ".sh", ".pl", ".py", ".elf", ".jsp", ".asp", ".aspx"}
SCRIPT_SCAN_EXTS = SUSPICIOUS_EXTS | {".cgi", ".js", ".html", ".htm"}

WEBSHELL_PATTERNS = re.compile(
    rb"(eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_POST|\$_GET|\$_REQUEST)"
    rb"|shell_exec\s*\(|passthru\s*\(|system\s*\(\s*\$_(POST|GET|REQUEST)"
    rb"|/dev/tcp/[0-9]+\.[0-9]+|nc\s+-e\s+/bin/(sh|bash)|bash\s+-i\s+>&)",
    re.IGNORECASE,
)


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def get_owner_name(uid, gid):
    try:
        u = pwd.getpwuid(uid).pw_name
    except KeyError:
        u = str(uid)
    try:
        g = grp.getgrgid(gid).gr_name
    except KeyError:
        g = str(gid)
    return f"{u}:{g}"


def inspect_file_now(fpath, category, target_id):
    try:
        st = os.lstat(fpath)
    except OSError:
        return None

    is_link = stat.S_ISLNK(st.st_mode)
    is_reg = stat.S_ISREG(st.st_mode)
    if not (is_reg or is_link):
        return None

    mode_oct = oct(stat.S_IMODE(st.st_mode))[2:].zfill(4)
    owner = get_owner_name(st.st_uid, st.st_gid)
    ext = os.path.splitext(fpath)[1].lower()

    sha256_hex = None
    hash_type = "sha256"
    suspicious_reasons = []

    if is_link:
        try:
            target = os.readlink(fpath)
            link_str = f"SYMLINK->{target}"
            if category == "system_binary" and os.path.isfile(fpath):
                h_tgt = hashlib.sha256()
                with open(fpath, "rb") as tf:
                    while True:
                        chunk = tf.read(65536)
                        if not chunk:
                            break
                        h_tgt.update(chunk)
                link_str += f"|TARGET_SHA256->{h_tgt.hexdigest()}"
            sha256_hex = hashlib.sha256(link_str.encode("utf-8", "replace")).hexdigest()
            hash_type = "symlink"
        except OSError:
            sha256_hex = f"META:{st.st_size}:{st.st_mtime_ns}:{mode_oct}:{owner}"
            hash_type = "metadata"
    elif is_reg:
        if (st.st_mode & stat.S_IWOTH) and category in ("web_root", "web_config", "user_web", "security_config", "system_binary"):
            suspicious_reasons.append("檔案權限含全員可寫入 (World-Writable)")
        if (st.st_mode & stat.S_ISUID) and category in ("web_root", "user_web", "shared_watch"):
            if fpath not in KNOWN_DSM_SPECIAL_FILES:
                suspicious_reasons.append("發現非預期 SUID 權限檔案")
        if category in ("web_root", "web_config") and ext in {".php", ".phtml", ".php5", ".jsp", ".asp", ".aspx"}:
            if fpath not in KNOWN_DSM_SPECIAL_FILES:
                suspicious_reasons.append(f"DSM 系統網頁目錄出現非預期腳本檔 ({ext})")

        if st.st_size <= 15 * 1024 * 1024:
            try:
                h = hashlib.sha256()
                check_sig = ext in SCRIPT_SCAN_EXTS
                matched_sig = False
                tail = b""
                with open(fpath, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
                        if check_sig and not matched_sig:
                            window = tail + chunk
                            if WEBSHELL_PATTERNS.search(window):
                                matched_sig = True
                            tail = chunk[-256:]
                sha256_hex = h.hexdigest()
                if matched_sig:
                    suspicious_reasons.append("檔案內容命中高風險 Webshell/遠端執行特徵")
            except (PermissionError, OSError):
                meta_str = f"META:size={st.st_size}:mtime={st.st_mtime_ns}:ctime={st.st_ctime_ns}:ino={st.st_ino}:mode={mode_oct}:owner={owner}"
                sha256_hex = hashlib.sha256(meta_str.encode()).hexdigest()
                hash_type = "meta_protected"
        else:
            meta_str = f"LARGE:size={st.st_size}:mtime={st.st_mtime_ns}:ctime={st.st_ctime_ns}:ino={st.st_ino}:mode={mode_oct}:owner={owner}"
            sha256_hex = hashlib.sha256(meta_str.encode()).hexdigest()
            hash_type = "meta_large"

    return {
        "path": fpath,
        "target_id": target_id,
        "category": category,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "ctime": int(st.st_ctime),
        "mode": mode_oct,
        "owner": owner,
        "hash": sha256_hex,
        "hash_type": hash_type,
        "suspicious": suspicious_reasons,
    }


def decode_mask(mask):
    names = []
    for bit, label in FLAG_NAMES:
        if mask & bit:
            names.append(label)
    if mask & IN_ISDIR:
        names.append("DIR")
    return names or [f"MASK_0x{mask:x}"]


def main():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.inotify_init.argtypes = []
    libc.inotify_init.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int

    fd = libc.inotify_init()
    if fd < 0:
        emit({"type": "error", "error": f"inotify_init failed: errno={ctypes.get_errno()}"})
        sys.exit(1)

    wd_to_info = {}

    def add_watch_path(path_str, category, target_id, only_names=None, depth=1, max_depth=3):
        bpath = path_str.encode("utf-8", "surrogateescape")
        wd = libc.inotify_add_watch(fd, bpath, ctypes.c_uint32(WATCH_MASK))
        if wd >= 0:
            wd_to_info[wd] = {
                "path": path_str,
                "category": category,
                "target_id": target_id,
                "only_names": only_names,
                "depth": depth,
                "max_depth": max_depth,
            }
            return True
        return False

    for base_dir, max_d, cat, tid in WATCH_TARGETS:
        if not os.path.isdir(base_dir):
            continue
        base_clean = base_dir.rstrip("/")
        base_slashes = base_clean.count("/")
        for root, subdirs, _ in os.walk(base_clean):
            curr_d = root.rstrip("/").count("/") - base_slashes + 1
            if curr_d >= max_d:
                subdirs[:] = []
            else:
                subdirs[:] = [d for d in subdirs if d not in ("@eaDir", "#recycle", "@tmp")]
            add_watch_path(root, cat, tid, only_names=None, depth=curr_d, max_depth=max_d)

    for parent_dir, allowed_set, cat, tid in FILTERED_DIR_TARGETS:
        if os.path.isdir(parent_dir):
            add_watch_path(parent_dir.rstrip("/"), cat, tid, only_names=allowed_set, depth=1, max_depth=1)

    emit({
        "type": "ready",
        "timestamp": time.time(),
        "watches_count": len(wd_to_info),
    })

    last_heartbeat = time.time()
    recent_modify_ts = {}

    try:
        while True:
            rlist, _, _ = select.select([fd], [], [], 10.0)
            now = time.time()
            if not rlist:
                if now - last_heartbeat >= 20.0:
                    emit({"type": "heartbeat", "timestamp": now, "watches_count": len(wd_to_info)})
                    last_heartbeat = now
                continue

            raw = os.read(fd, 65536)
            offset = 0
            raw_len = len(raw)

            while offset + 16 <= raw_len:
                wd, mask, cookie, name_len = struct.unpack_from("<iIII", raw, offset)
                offset += 16
                name_bytes = raw[offset:offset + name_len]
                offset += name_len

                if mask & IN_IGNORED:
                    wd_to_info.pop(wd, None)
                    continue

                name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")
                if name in ("@eaDir", "#recycle", "@tmp") or name.endswith(".tmp"):
                    continue

                info = wd_to_info.get(wd)
                if not info:
                    continue

                if info["only_names"] is not None:
                    if name not in info["only_names"]:
                        continue

                full_path = os.path.join(info["path"], name) if name else info["path"]

                if (mask & IN_ISDIR) and not (mask & (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM)):
                    continue

                # Dynamically attach watch to newly created subdirectories & scan any pre-existing files inside
                if (mask & IN_ISDIR) and (mask & (IN_CREATE | IN_MOVED_TO)) and info["only_names"] is None:
                    if info["depth"] < info["max_depth"] and os.path.isdir(full_path):
                        add_watch_path(
                            full_path,
                            info["category"],
                            info["target_id"],
                            only_names=None,
                            depth=info["depth"] + 1,
                            max_depth=info["max_depth"],
                        )
                        try:
                            with os.scandir(full_path) as it:
                                for de in it:
                                    if de.is_file(follow_symlinks=False) or de.is_symlink():
                                        sub_entry = inspect_file_now(de.path, info["category"], info["target_id"])
                                        if sub_entry:
                                            emit({
                                                "type": "fs_event",
                                                "timestamp": now,
                                                "iso_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}",
                                                "path": de.path,
                                                "category": info["category"],
                                                "target_id": info["target_id"],
                                                "is_dir": False,
                                                "is_delete": False,
                                                "ephemeral": False,
                                                "mask": IN_CREATE,
                                                "flags": ["IN_CREATE (新建子目錄內檔案)"],
                                                "file": sub_entry,
                                            })
                        except OSError:
                            pass

                is_delete = bool(mask & (IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM))

                # Only coalesce intermediate IN_MODIFY stream chunks; never drop IN_CLOSE_WRITE, IN_ATTRIB, IN_CREATE, or IN_DELETE
                if mask == IN_MODIFY:
                    if now - recent_modify_ts.get(full_path, 0) < 0.2:
                        continue
                    recent_modify_ts[full_path] = now
                    if len(recent_modify_ts) > 500:
                        recent_modify_ts.clear()

                file_entry = None
                ephemeral = False
                if not is_delete and not (mask & IN_ISDIR):
                    file_entry = inspect_file_now(full_path, info["category"], info["target_id"])
                    if file_entry is None:
                        ephemeral = True

                emit({
                    "type": "fs_event",
                    "timestamp": now,
                    "iso_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}",
                    "path": full_path,
                    "category": info["category"],
                    "target_id": info["target_id"],
                    "is_dir": bool(mask & IN_ISDIR),
                    "is_delete": is_delete,
                    "ephemeral": ephemeral,
                    "mask": mask,
                    "flags": decode_mask(mask),
                    "file": file_entry,
                })
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


if __name__ == "__main__":
    main()

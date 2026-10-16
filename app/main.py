"""CloudBox: drive picker + media server dashboard."""
import hmac
import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from starlette.concurrency import run_in_threadpool

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

MOUNT_ROOT = Path(os.environ.get("MOUNT_ROOT", "/mnt/cloudbox"))
# Bootstrap values from .env; on first start they are migrated into /data/auth.json (hashed) and the file wins afterwards
BOOT_PASSWORD = os.environ.get("CLOUDBOX_PASSWORD", "")
BOOT_SECRET = os.environ.get("CLOUDBOX_SECRET", "")
ROOT_DISK = os.environ.get("ROOT_DISK", "").strip()
SESSION_SECONDS = 7 * 24 * 3600
STATIC = Path(__file__).parent / "static"

MEDIA_EXT = {
    "video": {".mp4", ".mkv", ".webm", ".mov", ".m4v", ".avi"},
    "audio": {".mp3", ".flac", ".wav", ".m4a", ".ogg", ".opus", ".aac"},
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".avif"},
}

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
HOST_MEDIA = Path(os.environ.get("HOST_MEDIA", "/host-media"))  # host's /media, mounted rslave
SETTINGS_FILE = DATA_DIR / "settings.json"
_mount_lock = threading.Lock()
_declined: set[str] = set()  # devices the user explicitly stopped sharing; cleared when unplugged


DEFAULT_SETTINGS = {
    "auto_share": False,     # auto-mount newly plugged removable drives (read-only)
    "client_enabled": True,  # the public client page; off = it shows "unavailable"
    "admin_remote": False,   # allow the admin dashboard through the public ngrok link
}


def load_settings() -> dict:
    try:
        return {**DEFAULT_SETTINGS, **json.loads(SETTINGS_FILE.read_text())}
    except Exception:
        return dict(DEFAULT_SETTINGS)


def save_settings(s: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(s))


@asynccontextmanager
async def lifespan(_app):
    if load_auth() is None:  # also migrates the .env bootstrap password into auth.json
        raise RuntimeError("No password is set. Run on the host: sudo cloudbox reset-password")
    threading.Thread(target=watcher, daemon=True).start()
    yield


app = FastAPI(title="CloudBox", lifespan=lifespan)

# ---------- auth ----------
AUTH_FILE = DATA_DIR / "auth.json"
MIN_PASSWORD_LEN = 8
_fails: dict[str, list[float]] = {}


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()


def _write_auth(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = AUTH_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, AUTH_FILE)


def set_password(password: str) -> None:
    """Store a new password (hashed) and rotate the session secret, which signs out every device."""
    salt = os.urandom(16)
    _write_auth({"salt": salt.hex(), "hash": _hash(password, salt), "secret": secrets.token_hex(32)})


def load_auth() -> dict | None:
    try:
        return json.loads(AUTH_FILE.read_text())
    except Exception:
        pass
    if BOOT_PASSWORD:  # first start: migrate the installer's password
        salt = os.urandom(16)
        data = {"salt": salt.hex(), "hash": _hash(BOOT_PASSWORD, salt),
                "secret": BOOT_SECRET or secrets.token_hex(32)}
        _write_auth(data)
        return data
    return None


def check_password(password: str) -> bool:
    a = load_auth()
    if not a:
        return False
    return hmac.compare_digest(_hash(password, bytes.fromhex(a["salt"])), a["hash"])


def _sign(ts: str) -> str:
    a = load_auth()
    if not a:
        return ""
    return hmac.new(a["secret"].encode(), ts.encode(), hashlib.sha256).hexdigest()


def make_token() -> str:
    ts = str(int(time.time()))
    return f"{ts}.{_sign(ts)}"


def valid_token(tok: str | None) -> bool:
    if not tok or "." not in tok:
        return False
    ts, sig = tok.split(".", 1)
    expected = _sign(ts) if ts.isdigit() else ""
    if not expected or not hmac.compare_digest(sig, expected):
        return False
    return time.time() - int(ts) < SESSION_SECONDS


def require_auth(request: Request):
    if not valid_token(request.cookies.get("cb_session")):
        raise HTTPException(401, "Not logged in")


def _client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0].strip()


def _check_attempts(ip: str) -> list[float]:
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 600]
    if len(recent) >= 8:
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
    return recent


def _set_session_cookie(request: Request, response: Response) -> None:
    response.set_cookie("cb_session", make_token(), httponly=True, samesite="lax",
                        secure=request.headers.get("x-forwarded-proto") == "https",
                        max_age=SESSION_SECONDS)


@app.post("/api/login")
async def login(request: Request, response: Response):
    ip = _client_ip(request)
    recent = _check_attempts(ip)
    body = await request.json()
    if not check_password(str(body.get("password", ""))):
        recent.append(time.time())
        _fails[ip] = recent
        raise HTTPException(401, "Wrong password")
    _set_session_cookie(request, response)
    return {"ok": True}


@app.post("/api/change-password")
async def change_password(request: Request, response: Response, _: None = Depends(require_auth)):
    ip = _client_ip(request)
    recent = _check_attempts(ip)
    body = await request.json()
    current, new = str(body.get("current", "")), str(body.get("new", ""))
    if not check_password(current):
        recent.append(time.time())
        _fails[ip] = recent
        raise HTTPException(401, "Current password is wrong.")
    if len(new) < MIN_PASSWORD_LEN:
        raise HTTPException(400, f"New password must be at least {MIN_PASSWORD_LEN} characters.")
    if new == current:
        raise HTTPException(400, "New password must be different from the current one.")
    set_password(new)              # rotates the secret: every other signed-in device is logged out
    _set_session_cookie(request, response)  # keep this device signed in
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("cb_session")
    return {"ok": True}


@app.get("/api/me")
def me(_: None = Depends(require_auth)):
    return {"ok": True}


# ---------- drives ----------
def sh(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def safe_name(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._")
    return s[:40] or "drive"


def list_partitions(show_internal: bool = False) -> list[dict]:
    out = sh(["lsblk", "-J", "-b", "-o",
              "NAME,PATH,SIZE,FSTYPE,LABEL,UUID,TYPE,RM,HOTPLUG,TRAN,MODEL,PKNAME"])
    if out.returncode != 0:
        raise HTTPException(500, f"lsblk failed: {out.stderr.strip()}")
    devices = json.loads(out.stdout)["blockdevices"]
    parts = []

    def walk(node, parent=None):
        node["_parent"] = parent
        if node.get("type") in ("part", "disk") and node.get("fstype") and node["fstype"] not in (
                "swap", "crypto_LUKS", "LVM2_member", "linux_raid_member", "squashfs"):
            parts.append(node)
        for ch in node.get("children") or []:
            walk(ch, node)

    for d in devices:
        if d.get("type") == "loop" or d["name"].startswith(("loop", "ram", "zram")):
            continue
        walk(d)

    result = []
    for p in parts:
        disk = p["_parent"] or p
        disk_name = disk["name"]
        if ROOT_DISK and disk_name == ROOT_DISK:
            continue  # never offer the host's system disk
        removable = bool(p.get("rm") or disk.get("rm") or p.get("hotplug") or disk.get("hotplug")
                         or (disk.get("tran") in ("usb", "mmc")) or disk_name.startswith("mmcblk"))
        if not removable and not show_internal:
            continue
        name = safe_name(p.get("label") or p.get("uuid") or p["name"])
        mp = MOUNT_ROOT / name
        result.append({
            "device": p["path"],
            "name": name,
            "label": p.get("label"),
            "fstype": p["fstype"],
            "size": int(p["size"]),
            "model": (disk.get("model") or "").strip(),
            "transport": disk.get("tran"),
            "removable": removable,
            "mounted": mp.is_mount(),
        })
    return result


@app.get("/api/drives")
def drives(show_internal: bool = False, _: None = Depends(require_auth)):
    return {"drives": list_partitions(show_internal), "mounted": mounted_list()}


def mounted_list() -> list[dict]:
    items = []
    if MOUNT_ROOT.exists():
        for d in sorted(MOUNT_ROOT.iterdir()):
            if d.is_dir() and d.is_mount():
                u = os.statvfs(d)
                items.append({"name": d.name, "total": u.f_blocks * u.f_frsize,
                              "free": u.f_bavail * u.f_frsize,
                              "writable": _is_rw(d)})
    return items


def _is_rw(path: Path) -> bool:
    with open("/proc/self/mountinfo") as f:
        for line in f:
            parts = line.split()
            if parts[4] == str(path):
                return "rw" in parts[5].split(",")
    return False


def find_host_mount(device: str) -> Path | None:
    """If the desktop already mounted this device under the host's /media, return that path as seen in the container."""
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        left, _, right = line.partition(" - ")
        lp, rp = left.split(), right.split()
        if len(rp) < 2 or rp[1] != device:
            continue
        mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), lp[4])
        p = Path(mp)
        if p == HOST_MEDIA or HOST_MEDIA in p.parents:
            return p
    return None


def do_mount(match: dict, readonly: bool = True) -> None:
    """Share a partition. Reuses the desktop's existing mount if there is one, otherwise mounts it directly."""
    with _mount_lock:
        target = MOUNT_ROOT / match["name"]
        if target.is_mount():
            raise HTTPException(409, "Already mounted.")
        target.mkdir(parents=True, exist_ok=True)
        existing = find_host_mount(match["device"])
        if existing:
            # Bind the desktop's mount instead of mounting the device a second time (safe for NTFS/FAT)
            r = sh(["mount", "--bind", str(existing), str(target)])
            if r.returncode == 0 and readonly:
                r = sh(["mount", "-o", "remount,bind,ro,nosuid,nodev,noexec", str(target)])
        else:
            opts = ["nosuid", "nodev", "noexec", "ro" if readonly else "rw"]
            r = sh(["mount", "-o", ",".join(opts), match["device"], str(target)])
        if r.returncode != 0:
            if target.is_mount():
                sh(["umount", str(target)])
            try:
                target.rmdir()
            except OSError:
                pass
            raise HTTPException(500, f"mount failed: {(r.stderr or r.stdout).strip()}")


@app.post("/api/mount")
async def mount(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    device = str(body.get("device", ""))
    readonly = bool(body.get("readonly", True))
    match = next((d for d in list_partitions(show_internal=bool(body.get("show_internal"))) if d["device"] == device), None)
    if not match:
        raise HTTPException(400, "That device is not available for sharing.")
    _declined.discard(device)
    do_mount(match, readonly)
    return {"ok": True, "name": match["name"]}


@app.post("/api/unmount")
async def unmount(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    name = safe_name(str(body.get("name", "")))
    target = MOUNT_ROOT / name
    if not target.is_mount():
        raise HTTPException(404, "Not mounted.")
    r = sh(["umount", str(target)])
    if r.returncode != 0:
        raise HTTPException(409, f"umount failed (busy?): {(r.stderr or r.stdout).strip()}")
    try:
        target.rmdir()
    except OSError:
        pass
    # don't auto-share this drive again until it is unplugged and re-inserted
    for d in list_partitions():
        if d["name"] == name:
            _declined.add(d["device"])
    return {"ok": True}


# ---------- settings + auto-share ----------
@app.get("/api/settings")
def get_settings(_: None = Depends(require_auth)):
    return load_settings()


@app.post("/api/settings")
async def set_settings(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    s = load_settings()
    for key in DEFAULT_SETTINGS:
        if key in body:
            s[key] = bool(body[key])
    save_settings(s)
    if s["auto_share"]:
        _declined.clear()
    return s


def watcher() -> None:
    """Every few seconds, share newly inserted removable drives (read-only) if auto-share is on."""
    while True:
        try:
            present = {d["device"]: d for d in list_partitions(show_internal=False)}
            _declined.intersection_update(present)  # forget unplugged devices
            if load_settings().get("auto_share"):
                for dev, d in present.items():
                    if not d["mounted"] and dev not in _declined:
                        try:
                            do_mount(d, readonly=True)
                        except Exception:
                            _declined.add(dev)  # don't retry a failing drive in a loop
        except Exception:
            pass
        time.sleep(5)


# ---------- files ----------
def resolve(drive: str, rel: str) -> Path:
    base = (MOUNT_ROOT / safe_name(drive))
    if not base.is_mount():
        raise HTTPException(404, "Drive not mounted.")
    base = base.resolve()
    p = (base / rel.lstrip("/")).resolve()
    if p != base and base not in p.parents:
        raise HTTPException(403, "Forbidden path.")
    return p


def kind_of(p: Path) -> str:
    ext = p.suffix.lower()
    for k, exts in MEDIA_EXT.items():
        if ext in exts:
            return k
    return "file"


@app.get("/api/files/{drive}")
@app.get("/api/files/{drive}/{path:path}")
def files(drive: str, path: str = "", _: None = Depends(require_auth)):
    p = resolve(drive, path)
    if not p.is_dir():
        raise HTTPException(404, "Not a folder.")
    entries = []
    for e in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        if e.name.startswith("."):
            continue
        try:
            st = e.stat()
        except OSError:
            continue
        entries.append({"name": e.name, "dir": e.is_dir(), "size": st.st_size,
                        "kind": "folder" if e.is_dir() else kind_of(e)})
    return {"drive": drive, "path": path.strip("/"), "entries": entries}


@app.get("/media/{drive}/{path:path}")
def media(drive: str, path: str, _: None = Depends(require_auth)):
    p = resolve(drive, path)
    if not p.is_file():
        raise HTTPException(404, "File not found.")
    # FileResponse supports HTTP Range, so seeking in video/audio works
    return FileResponse(p)

# ---------- upload / new folder (admin only) ----------
def writable_dir(drive: str, rel: str) -> Path:
    base = MOUNT_ROOT / safe_name(drive)
    if not base.is_mount():
        raise HTTPException(404, "Drive not mounted.")
    if not _is_rw(base):
        raise HTTPException(403, "This drive is shared read-only. Stop sharing it, then share it again with 'allow writes' ticked.")
    p = resolve(drive, rel)
    if not p.is_dir():
        raise HTTPException(404, "Target folder not found.")
    return p


def clean_name(n: str) -> str:
    n = n.strip()
    if not n or n in (".", "..") or any(c in n for c in '/\\\0') or len(n.encode()) > 200:
        raise HTTPException(400, f"Invalid name: {n[:40]!r}")
    return n


def unique(path: Path) -> Path:
    """If 'movie.mp4' exists, return 'movie (2).mp4', and so on. Never overwrites."""
    c, i = path, 2
    while c.exists():
        c = path.with_name(f"{path.stem} ({i}){path.suffix}")
        i += 1
    return c


def inside(root: Path, p: Path) -> bool:
    p = p.resolve()
    return p == root or root in p.parents


@app.post("/api/mkdir")
async def mkdir(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    parent = writable_dir(str(body.get("drive", "")), str(body.get("path", "")))
    target = parent / clean_name(str(body.get("name", "")))
    if target.exists():
        raise HTTPException(409, "A file or folder with that name already exists.")
    target.mkdir()
    return {"ok": True}


@app.put("/api/upload")
async def upload(request: Request, drive: str, path: str = "", name: str = "", _: None = Depends(require_auth)):
    """Upload ONE file as the raw request body. `name` may be 'Trip/Day1/a.jpg' (folder upload);
    missing sub-folders are created inside `path`."""
    parent = writable_dir(drive, path)
    root = (MOUNT_ROOT / safe_name(drive)).resolve()
    parts = [clean_name(p) for p in name.replace("\\", "/").split("/") if p]
    if not parts:
        raise HTTPException(400, "Missing file name.")
    d = parent
    for part in parts[:-1]:
        d = d / part
        d.mkdir(exist_ok=True)
        if not inside(root, d):
            raise HTTPException(403, "Forbidden path.")
    final = unique(d / parts[-1])
    tmp = final.with_name(final.name + ".part")
    try:
        with open(tmp, "wb") as f:
            async for chunk in request.stream():
                await run_in_threadpool(f.write, chunk)
        os.replace(tmp, final)
    except BaseException:  # cancelled, disk full, network drop: leave no half file behind
        tmp.unlink(missing_ok=True)
        raise
    return {"ok": True, "name": final.name}


# ---------- tunnel ----------
@app.get("/api/tunnel")
def tunnel(_: None = Depends(require_auth)):
    try:
        with urllib.request.urlopen("http://ngrok:4040/api/tunnels", timeout=2) as r:
            data = json.load(r)
        return {"url": next((t["public_url"] for t in data["tunnels"] if t["public_url"].startswith("https")), None)}
    except Exception:
        return {"url": None}


# ---------- client sharing (public, read-only, no login) ----------
SHARES_FILE = DATA_DIR / "shares.json"
_shares_lock = threading.Lock()


def load_shares() -> list[dict]:
    try:
        return json.loads(SHARES_FILE.read_text())
    except Exception:
        return []


def save_shares(shares: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SHARES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(shares))
    os.replace(tmp, SHARES_FILE)


def clean_rel(rel: str) -> str:
    """Normalise a relative path; refuse '..', absolute tricks, and hidden (dot) components."""
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." or p.startswith(".") for p in parts):
        raise HTTPException(400, "Invalid or hidden path.")
    return "/".join(parts)


def share_base(share: dict) -> Path | None:
    """Real folder behind a share, or None if its drive is not mounted / the folder is gone."""
    drive = MOUNT_ROOT / safe_name(share["drive"])
    if not drive.is_mount():
        return None
    root = drive.resolve()
    base = (root / share["path"]).resolve()
    if base != root and root not in base.parents:
        return None
    return base if base.is_dir() else None


def get_share(sid: str) -> tuple[dict, Path]:
    if not load_settings().get("client_enabled"):
        raise HTTPException(503, "This page is currently unavailable.")
    share = next((s for s in load_shares() if s["id"] == sid), None)
    base = share_base(share) if share else None
    if not share or base is None:
        raise HTTPException(404, "Not found.")
    return share, base


def public_resolve(sid: str, rel: str) -> tuple[Path, Path]:
    _, base = get_share(sid)
    rel = clean_rel(rel)
    p = (base / rel).resolve()
    if p != base and base not in p.parents:
        raise HTTPException(403, "Forbidden.")
    return base, p


@app.get("/api/c/shares")
def client_shares():
    if not load_settings().get("client_enabled"):
        raise HTTPException(503, "This page is currently unavailable.")
    return {"shares": [{"id": s["id"], "name": s["name"]} for s in load_shares() if share_base(s) is not None]}


@app.get("/api/c/files/{sid}")
@app.get("/api/c/files/{sid}/{path:path}")
def client_files(sid: str, path: str = ""):
    base, p = public_resolve(sid, path)
    if not p.is_dir():
        raise HTTPException(404, "Not a folder.")
    entries = []
    for e in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        if e.name.startswith("."):
            continue
        try:
            real = e.resolve()
            if real != base and base not in real.parents:
                continue  # symlink pointing outside the shared folder
            st = e.stat()
        except OSError:
            continue
        entries.append({"name": e.name, "dir": e.is_dir(), "size": st.st_size,
                        "kind": "folder" if e.is_dir() else kind_of(e)})
    name = next(s["name"] for s in load_shares() if s["id"] == sid)
    return {"share": name, "path": clean_rel(path), "entries": entries}


@app.get("/c/file/{sid}/{path:path}")
def client_file(sid: str, path: str, dl: int = 0):
    _, p = public_resolve(sid, path)
    if not p.is_file():
        raise HTTPException(404, "File not found.")
    if dl:
        return FileResponse(p, filename=p.name, content_disposition_type="attachment")
    return FileResponse(p)  # inline + HTTP Range for streaming


# ---------- client sharing (admin) ----------
@app.get("/api/shares")
def admin_shares(_: None = Depends(require_auth)):
    return {"shares": [{**s, "available": share_base(s) is not None} for s in load_shares()]}


@app.post("/api/shares")
async def add_share(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    drive = safe_name(str(body.get("drive", "")))
    rel = clean_rel(str(body.get("path", "")))
    candidate = {"drive": drive, "path": rel}
    if share_base(candidate) is None:
        raise HTTPException(400, "That folder does not exist or its drive is not mounted.")
    with _shares_lock:
        shares = load_shares()
        if any(s["drive"] == drive and s["path"] == rel for s in shares):
            raise HTTPException(409, "That folder is already shared.")
        base_name = (str(body.get("name", "")).strip() or (rel.split("/")[-1] if rel else drive))[:60]
        name, n = base_name, 2
        while any(s["name"] == name for s in shares):
            name, n = f"{base_name} ({n})", n + 1
        shares.append({"id": secrets.token_hex(4), "drive": drive, "path": rel, "name": name})
        save_shares(shares)
    return {"ok": True}


@app.post("/api/shares/rename")
async def rename_share(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    name = str(body.get("name", "")).strip()[:60]
    if not name:
        raise HTTPException(400, "Name cannot be empty.")
    with _shares_lock:
        shares = load_shares()
        if any(s["name"] == name and s["id"] != body.get("id") for s in shares):
            raise HTTPException(409, "Another shared folder already uses that name.")
        target = next((s for s in shares if s["id"] == body.get("id")), None)
        if not target:
            raise HTTPException(404, "Share not found.")
        target["name"] = name
        save_shares(shares)
    return {"ok": True}


@app.post("/api/shares/delete")
async def delete_share(request: Request, _: None = Depends(require_auth)):
    body = await request.json()
    with _shares_lock:
        shares = load_shares()
        kept = [s for s in shares if s["id"] != body.get("id")]
        if len(kept) == len(shares):
            raise HTTPException(404, "Share not found.")
        save_shares(kept)
    return {"ok": True}


# ---------- pages + admin-origin guard ----------
@app.middleware("http")
async def admin_origin_guard(request: Request, call_next):
    """Requests arriving through ngrok always carry X-Forwarded-For; direct local ones don't.
    Unless the owner allows it, the admin side is therefore reachable only from this computer."""
    path = request.url.path
    admin_path = (path == "/admin" or path.startswith("/media/")
                  or (path.startswith("/api/") and not path.startswith("/api/c/")))
    if admin_path and "x-forwarded-for" in request.headers and not load_settings().get("admin_remote"):
        if path == "/admin":
            return HTMLResponse("<h3>Admin is only available on the computer running CloudBox.</h3>"
                                "<p>Open <code>http://localhost:8000/admin</code> there.</p>", status_code=403)
        return JSONResponse({"detail": "Admin is only available on the computer running CloudBox."}, status_code=403)
    return await call_next(request)


@app.get("/")
def client_page():
    return FileResponse(STATIC / "client.html")


@app.get("/admin")
def admin_page():
    return FileResponse(STATIC / "admin.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")

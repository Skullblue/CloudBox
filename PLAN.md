# CloudBox: turn any machine into a personal media cloud

## Goal
Install once, pick a drive (HDD, SSD, pendrive, SD card) from a web dashboard, and stream or browse its media from anywhere through a public ngrok URL.

## Architecture (v0.1, Ubuntu + Docker)

```
 Phone / browser ──► ngrok edge ──► [ngrok container] ──► [app container] ──► /mnt/cloudbox/<drive>
                                                            │  FastAPI: dashboard + media API
                                                            └─ mounts the chosen partition (rshared, so it shows on the host too)
```

| Piece | Responsibility |
|---|---|
| `install.sh` | Installs Docker, prepares the shared mount dir, asks for a password and ngrok token, starts the stack |
| `app` container | Lists drives, mounts/unmounts them, browses files, streams media (HTTP Range), password login |
| `ngrok` container | Public HTTPS URL, no router port forwarding; app reads the URL from ngrok's local API |
| `.env` | Password, secret, ngrok token, root disk to hide |

## Key design decisions
1. **Mount inside the container, propagate to the host.** `/srv/cloudbox/mnt` is made `rshared` on the host and bind-mounted into the app container, which holds `SYS_ADMIN` and a device-cgroup rule for block devices. This avoids a separate privileged host daemon. Tradeoff: the app container is powerful. Mitigation: it only mounts devices that appear in its own filtered list, never the root disk, with `nosuid,nodev,noexec`.
2. **Read-only by default.** Drives mount `ro`. Remounting read-write is an explicit per-drive choice, so a bug or an attacker can't alter your files by default.
3. **Auth is mandatory.** The ngrok URL is public, so every route needs the password cookie. Login attempts are rate-limited. Passwords are stored as scrypt hashes; a forgotten password can only be reset from the host (`sudo cloudbox reset-password`), never over the internet, so a stranger can't take over the cloud through a reset link.
4. **Path safety.** Every file path is resolved and must stay inside the mounted drive; mount names are sanitised.
5. **Custom server, no Jellyfin.** Range-request streaming covers video/audio/images in the browser. Transcoding is out of scope for v0.1.

## Client sharing model
- A **share** = one folder on a mounted drive (or a whole drive) with a client-visible name. Everything inside it, including subfolders, is visible; nothing outside it is reachable.
- Clients need **no login** (owner's choice), so the only protection is that the link is secret and the shared list is narrow. The owner can turn the client page off instantly with one switch, or remove any share.
- Enforced on the server for every request: path must stay inside the share (`..`, symlinks that leave the share and dotfiles/hidden folders are refused), drive must be mounted, client page must be on. Unmounting a drive hides its shares until it returns.
- The **admin dashboard is local-only by default**. Requests arriving via ngrok always carry `X-Forwarded-For`, and `/admin`, `/api/*` (admin) and `/media/*` reject those unless the owner enables "allow admin over the internet".
- Clients can view/stream/download only. No upload, rename or delete exists on the public side.

## Platforms
| Platform | Status | How |
|---|---|---|
| Ubuntu PC/laptop | v0.1 | `install.sh` |
| Raspberry Pi (Ubuntu/RPi OS 64-bit) | works with same stack | Multi-arch Python/ngrok images; use a powered USB hub for HDDs |
| Android | Phase 3 | No Docker. Use Termux + proot Ubuntu, or Android's Linux Terminal app (newer Android), running the app without Docker. Non-root Android cannot mount raw drives, so it serves paths already visible to storage (SD/OTG via SAF/Termux storage). |

## Roadmap
- **v0.1**: drive list, mount/unmount, browse, stream, password, ngrok URL display.
- **v0.1.1** (this repo): auto-share toggle for newly plugged removable drives (read-only, 5s poll); reuses the desktop's existing `/media` mount via bind instead of mounting twice.
- **v0.1.2**: `cloudbox start|stop|status|url|logs|autostart` command (stop also unmounts shared drives).
- **v0.1.3**: change password in the dashboard; `cloudbox reset-password` for a forgotten one. Password stored as a scrypt hash in the data volume; changing/resetting signs out all devices.
- **v0.2.0**: two dashboards. `/admin` (password, controls drives, picks which folders clients can see) and `/` (public client page, no login, read-only browse/stream/download of the shared folders only).
- **v0.3**: thumbnails (ffmpeg), search, upload, udev-event based detection instead of polling.
- **v0.3**: multi-user accounts and share links with expiry, HTTPS-only cookies, audit log.
- **v0.4**: optional transcoding (ffmpeg HLS), subtitles, resume playback.
- **v1.0**: Raspberry Pi image, Android build, Tailscale/Cloudflare alternatives to ngrok.

## Risks
- ngrok free plan: random URL changes on restart and has bandwidth limits; a reserved domain is a paid feature.
- Streaming through ngrok is limited by your home upload speed.
- exFAT/NTFS support depends on host kernel; the image ships `ntfs-3g` and `exfatprogs`.
- Hot-unplugging a mounted drive can corrupt it; always use Unmount first.

# Vigil

**Logs in to your Linux servers over SSH, reads, and tells you what is wrong,
what is exposed, what is unpatched — and what changed since yesterday that
nobody meant to change.**

Nothing is installed on the machines it watches. There is no agent, no daemon
and no cron entry: it connects, runs one script that only reads, and
disconnects.

It is read-only out of the box. The single exception is Docker cleanup, which is
**off by default** and, when you switch it on, can run a fixed list of
`docker ... prune -f` commands and nothing else — see
[Docker](#docker-and-the-one-write-path).

```
   you add a server            ← name, IP, login user, private key
        ↓
   one SSH session             ← read-only, unprivileged, no sudo needed
        ↓
   one script, one round trip  ← /proc, df, ss, systemctl, apt-get -s
        ↓
   parse                       ← unknown stays unknown, never becomes zero
        ↓
   ┌──────────────┬──────────────────┐
   │  rules       │  anomalies       │
   │  vs fixed    │  vs this host's  │
   │  thresholds  │  own history     │
   └──────────────┴──────────────────┘
        ↓
   critical · warning · info   ← with the measurement behind each one
        ↓
   YOU run the fix             ← it hands you the command (Docker cleanup can
                                 run its own, if you switch that on)
```

Multi-user, Postgres-backed, private keys encrypted at rest, **no sample data** —
the dashboard stays empty until it has your servers.

---

## Table of contents

1. [Run it](#run-it)
2. [Add a server](#add-a-server)
3. [Prepare the login (least privilege)](#prepare-the-login-least-privilege)
4. [What it checks](#what-it-checks)
5. [Anomalies: normal for *this* machine](#anomalies-normal-for-this-machine)
6. [Docker, and the one write path](#docker-and-the-one-write-path)
7. [Acknowledgements](#acknowledgements)
8. [Configuration](#configuration)
9. [Security notes](#security-notes)
10. [Architecture](#architecture)
11. [API](#api)
12. [Tests](#tests)

---

## Run it

Docker only — nothing is built or installed on your machine.

```bash
docker compose up -d --build
# dashboard: http://localhost:8080
```

Port 8080 already taken?

```bash
VG_PORT=8090 docker compose up -d --build
```

Sign up, and you own your own estate: the servers you add are visible to you and
to nobody else. There is **no demo data** — a new account sees an empty dashboard
and a prompt to add a server. That is deliberate, because a dashboard full of
invented numbers is worse than an empty one: sooner or later somebody quotes it.

```bash
docker compose logs -f app     # follow
docker compose down            # stop, keep data
docker compose down -v         # stop and wipe database + encryption key
```

Two containers: `app` (Node, two dependencies) and `postgres` (17-alpine).
Postgres is not published to the host by default.

---

## Add a server

Four things:

| Field | Example | Notes |
| --- | --- | --- |
| **Server name** | `web-01` | Whatever you call it. Only you see it. |
| **IP or hostname** | `10.0.4.11` | Must be reachable **from the container**, not from your laptop. |
| **Login user** | `monitor` | An ordinary account. No sudo required. |
| **Private key** | `-----BEGIN OPENSSH PRIVATE KEY-----…` | The **private** half — the file *without* `.pub`. |

> **It is the private key, not the public one.** Vigil is the SSH *client* here:
> it needs the half that proves identity. The public half is the one that goes
> in `authorized_keys` **on your server**, and it is already there if the key
> works from your terminal. Paste the wrong half and the form says so rather
> than failing at the first scan.

The key is sealed with AES-256-GCM before it reaches Postgres, decrypted into
memory only for the length of one connection, and **never written to disk** —
not to a temp file, not to an agent socket. No page and no API endpoint in this
product can read it back.

Vigil scans the server the moment you add it, so you find out immediately
whether the credentials actually work.

### Host keys are pinned

The first successful connection records the server's host key fingerprint. Every
later connection is **refused** if it changes, and the change is written to the
append-only audit log. That is what makes the encryption mean something —
without it, anything that can answer on port 22 could read the session.

If you legitimately rebuilt or re-imaged a host, reset the pin on its settings
page. The scanner will never silently re-pin.

---

## Prepare the login (least privilege)

On the server you want watched:

```bash
sudo useradd -m -s /bin/bash monitor
sudo -u monitor mkdir -p -m 700 /home/monitor/.ssh
sudo -u monitor tee /home/monitor/.ssh/authorized_keys >/dev/null <<'EOF'
ssh-ed25519 AAAA...your public key... vigil
EOF
sudo -u monitor chmod 600 /home/monitor/.ssh/authorized_keys
```

That is the whole setup. **No sudo, no group memberships, no packages.**

You can lock the account down further — Vigil only ever runs one non-interactive
command, so it works fine with a forced command and no PTY:

```
# /home/monitor/.ssh/authorized_keys
no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA... vigil
```

### What running unprivileged costs, exactly

Three checks see less without root. Vigil **says so on the page** rather than
quietly showing you less than it claims, and tells you the single command that
would lift each one:

| Check | Without sudo | Sudoers line that fixes it |
| --- | --- | --- |
| Listening sockets | Ports and addresses, but **process names only for the login's own processes** | `monitor ALL=(root) NOPASSWD: /usr/bin/ss -H -tuln -p` |
| sshd settings | Read from `sshd_config`, so directives left at their compiled-in default are invisible | `monitor ALL=(root) NOPASSWD: /usr/sbin/sshd -T` |
| Failed SSH logins | **Not visible at all** if neither the journal nor `auth.log` is readable | `monitor ALL=(root) NOPASSWD: /usr/bin/journalctl -q --since -24?hours -t sshd` |

Everything else — disks, inodes, memory, load, updates, security updates,
reboots, kernels, failed units, clock — is fully visible to an ordinary user.

**The recommended setup is no sudo at all.** The degraded checks are honest about
their gaps, which is worth more than the extra fidelity.

---

## What it checks

Twenty-odd rules, each answering one question, each carrying the measurement it
is based on and the command to act on it.

| Area | What it looks for |
| --- | --- |
| **Disk** | Filesystems over 80% / 90%. **Inode exhaustion** separately — the failure where `df` shows space free and writes still fail |
| **Memory** | `MemAvailable` under 10% / 5%, and swap over 80%. Uses MemAvailable, not MemFree, so a healthy page cache is never reported as an emergency |
| **CPU** | 15-minute load above 1× / 2× the core count. Zombie process build-up |
| **Updates** | Pending updates, and **security updates identified by their archive** (`-security`), not guessed from the package name |
| **Stale lists** | Package lists not refreshed in a week — because "0 security updates" from a six-month-old list is a lie the dashboard would otherwise tell with a green tick |
| **Reboots** | `reboot-required`, `needs-restarting`, and a **kernel newer than the running one** — the case where the flag was cleaned up but the reboot never happened |
| **Services** | Failed systemd units. Critical when the unit is one that matters (ssh, docker, kubelet, nginx, the databases, the firewall); a warning otherwise |
| **Network** | ~26 risky services (databases, admin APIs, cleartext protocols) **bound to a routable address**. Postgres on `127.0.0.1` is silent; Postgres on `0.0.0.0` is critical |
| **Security** | `PermitRootLogin yes`, `PermitEmptyPasswords yes`, `PasswordAuthentication yes`, failed-login volume |
| **Platform** | Releases past end of life, where no security patch is coming at all |
| **Time** | Clock skew against the dashboard, and whether anything is keeping it in sync |
| **Docker** | Containers stuck in a restart loop, containers that are up but failing their own health check, exited containers piling up, dangling images, and reclaimable space judged against the disk Docker actually sits on |

Severity means something specific:

- **critical** — acting today is cheaper than acting tomorrow. Something is
  broken, exposed, or will break within days on the current trajectory.
- **warning** — real, wants scheduling, will not bite this week.
- **info** — context worth having, not worth waking anyone for.

> **Unknown never becomes zero.** If the package manager could not be read, the
> update count is *unknown*, not `0`. If the auth log is unreadable, failed
> logins are *unknown*, not `0`. A monitoring product that confuses those two
> reports a healthy fleet right up until the incident.

---

## Anomalies: normal for *this* machine

Fixed thresholds and per-host baselines disagree constantly, and **both
disagreements matter**:

> A build server that sits at load 14 all day is not an incident. A threshold
> alerts on it every minute until someone silences the rule — and the day it hits
> 40, nobody is listening.
>
> A database that has run at 30% disk for two years and is now at 47% is nowhere
> near any threshold, and is the most interesting thing on the estate — because
> at that slope it is full in nine days.

So Vigil runs both engines and puts their output on the same page.

| Signal | What it catches |
| --- | --- |
| **New listening socket** | The highest-signal check here. Nothing opens a port by accident: it is a deploy, a package that enabled itself — or it is someone else's shell |
| **Socket disappeared** | A service that was up in every previous scan and is not now |
| **Disk fill forecast** | Theil–Sen median slope over every pair of samples, so one log-rotation blip cannot swing the forecast by weeks |
| **Level excursions** | Load, memory, failed logins and process count more than 3.5 *robust* sigmas outside the host's own median |
| **State transitions** | Reboots (uptime going backwards), kernel changes, units that newly failed, security backlog jumps |

The statistics are deliberately robust — median and MAD rather than mean and
standard deviation, because **on a server the outlier is the event**. A mean gets
dragged up by yesterday's incident, which makes a machine that misbehaved once
progressively harder to alert on. Exactly backwards.

With fewer than 8 scans behind a host, the anomaly engine returns **no opinion**
rather than a confident one from three data points.

---

## Docker, and the one write path

Where Docker is installed, Vigil reports what is running, what is broken and
what is dead weight:

| | |
| --- | --- |
| **Restart loops** | A container Docker keeps restarting is not untidiness, it is an outage that keeps announcing itself. Critical. |
| **Unhealthy containers** | Up, so nothing restarted it, but its own health check says it is not working. This is the state that silently serves errors. Critical. |
| **Exited containers** | Each keeps its writable layer and its logs until removed. Individually small; collectively what fills a build host. |
| **Dangling images** | Untagged layers left behind when an image was rebuilt under the same tag. |
| **Reclaimable space** | Taken from `docker system df`, which accounts for layers shared between images — summing image sizes double-counts them, often by gigabytes. |

Reclaimable space is judged **against the filesystem Docker's root directory is
on**. 30 GB of dead layers is a footnote on a 4 TB volume and an emergency on a
40 GB root, and a fixed byte threshold cannot tell those apart.

### Cleanup

Every other finding in Vigil hands you a command to run yourself. Docker cleanup
can also run it for you — but that is a real change to what this product is, so
it is built to be hard to misuse:

- **Off by default.** `VG_ALLOW_DOCKER_PRUNE=on` is required. A default
  deployment cannot change anything on any host.
- **Fixed commands.** The six commands live in a table in `server/ssh/prune.mjs`
  as constant strings. The API takes an action *key*, looks it up, and runs what
  it finds. Nothing from a request, a database row or a scan is ever
  interpolated into a command — the injection surface is not sanitised, it is
  absent.
- **Prune only, never targeted.** There is deliberately no "remove this
  container" verb. `prune` removes only what Docker itself considers unused, so
  a running service cannot be taken down by a mistake here or by someone
  guessing an id.
- **Volumes are separate.** `docker volume prune` deletes *data*, not waste — a
  database volume whose container is merely stopped looks exactly like an
  abandoned one. It needs its own second flag (`VG_ALLOW_VOLUME_PRUNE=on`), it
  is never part of the headline reclaimable figure, and it is never included in
  the combined action.
- **Everything is audited**, with the actor, the host and the exact command; and
  the server is re-scanned immediately afterwards so the page shows what actually
  changed rather than what you hoped would.

| Action | Command | Deletes data |
| --- | --- | --- |
| Remove exited containers | `docker container prune -f` | no |
| Remove dangling images | `docker image prune -f` | no |
| Remove all unused images | `docker image prune -a -f` | no |
| Remove build cache | `docker builder prune -f` | no |
| All of the above | `docker system prune -f` | no |
| Remove unused volumes | `docker volume prune -f` | **yes** |

Leave `VG_ALLOW_DOCKER_PRUNE` unset and the cleanup panel still lists every
action, its size and its exact command — with a Copy button instead of a Run
button. That is the recommended way to run this.

> **Reaching the Docker socket needs the `docker` group, which is
> root-equivalent** — anyone in it can start a privileged container and own the
> host. Vigil does not ask for it. On a host where the login is not in that
> group, the Docker page says so plainly instead of showing an empty card.

---

## Acknowledgements

Acknowledging an issue hides it. It is **not a mute**: the acknowledgement
records the measurement you accepted, and the issue comes back on its own if it
gets materially worse — more than 10% worse, or 8 points.

Acknowledge a disk at 82% and it stays quiet. At 91% it returns, flagged
**Reopened**, with the value you originally accepted attached. Without that, the
first acknowledgement of a slowly-worsening condition would be the last anyone
ever heard of it.

---

## Configuration

Everything is an environment variable on the `app` service.

| Variable | Default | What it does |
| --- | --- | --- |
| `VG_ENCRYPTION_KEY` | generated | 32 bytes base64 (`openssl rand -base64 32`). Unset, one is generated into the data volume with a loud warning — fine locally, not for production |
| `VG_PORT` | `8080` | Host port to publish on |
| `VG_ALLOW_SIGNUP` | `on` | Set `off` to close sign-up once your accounts exist |
| `VG_SCAN_MINUTES` | `15` | Minutes between automatic sweeps. `0` disables them and scanning becomes manual |
| `VG_SCAN_CONCURRENCY` | `8` | How many servers to hold SSH connections to at once |
| `VG_SCAN_RETENTION` | `2000` | Scans kept per server — about three weeks at the default interval, which is what the anomaly baselines are drawn from |
| `VG_SSH_CONNECT_TIMEOUT_MS` | `12000` | Handshake timeout |
| `VG_SSH_COMMAND_TIMEOUT_MS` | `45000` | Whole-operation deadline, so a host that connects and then goes silent cannot hold a slot open |
| `VG_SESSION_DAYS` | `14` | Session lifetime |
| `VG_SECURE_COOKIES` | `false` | Set `true` behind HTTPS |
| `VG_ALLOW_DOCKER_PRUNE` | `off` | The only write path. `on` lets the Docker page run the fixed prune list above |
| `VG_ALLOW_VOLUME_PRUNE` | `off` | Additionally allows `docker volume prune`, which **deletes data** |

---

## Security notes

- **One write path, and it is off by default.** `server/ssh/probe.mjs` is the
  complete list of commands the scanner can run, it is fixed at build time, and
  every one of them reads. The only module that can change anything is
  `server/ssh/prune.mjs`: six constant `docker ... prune -f` strings, gated
  behind `VG_ALLOW_DOCKER_PRUNE`, unable to target a specific object, and
  audited. With that variable unset the product cannot alter a monitored host at
  all.
- **`apt-get -s` is the simulate flag.** It downloads nothing, installs nothing
  and takes no lock. `dnf -C` reads the local cache and will not touch the
  network.
- **Private keys are sealed** with AES-256-GCM under a key that is not in the
  database, with the server's row id as additional authenticated data — so a
  sealed key cannot be lifted from one row and replayed into another. They are
  never written to disk on this host.
- **Host keys are pinned** trust-on-first-use, and a change fails the scan loudly
  instead of connecting anyway.
- **Passwords** are scrypt (N=16384, r=8, p=1). **Session tokens** are 32 random
  bytes, stored only as their SHA-256, so a database dump cannot be replayed as a
  live session.
- **Every query is scoped by `user_id`** in its `WHERE` clause. There is
  deliberately no `getServer(id)` without one: ownership is not a layer above the
  queries that somebody could forget to call, it is the queries.
- **CSRF**: `SameSite=Lax` cookies plus a same-origin check on every mutating
  request.
- The suggested commands shown against each finding are for **you** to run.
  Nothing in this product executes them.

---

## Architecture

```
server/
  index.mjs            HTTP, sessions, the user-scoped JSON API, SSE
  db/pool.mjs          Postgres pool, schema bootstrap
  db/schema.sql        idempotent, runs on every boot
  crypto/secrets.mjs   AES-256-GCM seal/open
  auth/users.mjs       scrypt passwords, hashed session tokens
  repo/servers.mjs     server CRUD; every query scoped by user_id
  ssh/client.mjs       ssh2 transport, host-key pinning, error translation
  ssh/probe.mjs        THE SCRIPT — every command the scanner can run
  ssh/parse.mjs        pure parsers: text in, structure out
  ssh/prune.mjs        the only write path: a fixed docker-prune allowlist
  engine/checks.mjs    facts -> findings (fixed thresholds)
  engine/anomalies.mjs facts + history -> anomalies (per-host baselines)
  engine/stats.mjs     median, MAD, robust z, Theil-Sen
  store.mjs            scan orchestration, aggregation, scheduler
web/                   vanilla ES modules, no build step, no framework
```

Two runtime dependencies: `pg` and `ssh2`.

`ssh2` rather than shelling out to the OpenSSH client for one specific reason:
the OpenSSH client can only take a private key from a **file** or an **agent**,
and this product must never write a customer's private key to disk. `ssh2`
accepts it as a string, in memory.

**Findings are derived, not stored as truth.** They are recomputed from the
stored facts on every read, so improving a rule improves every historical scan
rather than leaving the estate showing whatever the rules said last Tuesday.
What *is* stored as fact: the scan itself, and someone's acknowledgement.

**A failed scan never overwrites a good picture.** An unreachable host keeps
showing its last successful state, clearly labelled stale — because "we could not
reach it" and "it has no listening ports any more" must never look the same.

---

## API

All endpoints are cookie-authenticated and scoped to the calling user.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/signup` · `/login` · `/logout` · `/password` | Account and session |
| `GET` | `/api/auth/me` | Current user |
| `GET` `POST` | `/api/servers` | List / add a server |
| `GET` `PATCH` `DELETE` | `/api/servers/:id` | Detail (facts, findings, anomalies, history, series) / edit / remove |
| `POST` | `/api/servers/:id/scan` | Scan one server now |
| `POST` | `/api/servers/:id/reset-host-key` | Clear the pinned host key (audited) |
| `POST` `DELETE` | `/api/servers/:id/ack` | Acknowledge / un-acknowledge a finding |
| `GET` | `/api/fleet` | Servers plus estate totals |
| `GET` | `/api/issues` | Findings **and** anomalies, with facets; `?severity=&category=&server=&q=&acked=` |
| `GET` | `/api/anomalies` | Anomalies only |
| `GET` | `/api/ports` · `/api/updates` · `/api/disks` · `/api/docker` | Fleet-wide inventories |
| `POST` | `/api/servers/:id/docker-prune` | Run one allowlisted cleanup action (`403` unless enabled) |
| `POST` | `/api/scan` | Sweep every server (returns `202`; follow it on the event stream) |
| `GET` | `/api/events` | Server-sent events: scan progress and completion |
| `GET` | `/api/health` | Unauthenticated liveness |

---

## Tests

```bash
npm test
```

86 tests, no network and no database required. They cover the three places bugs
actually hide:

- **Parsers**, against verbatim output from Ubuntu, Debian, RHEL and busybox
  hosts — ragged column widths and all. `ss` and `netstat`, mount points with
  spaces, btrfs reporting `-` for inodes, apt and dnf.
- **Judgement calls**: which conditions are critical rather than warnings, and -
  roughly half the suite - **what must stay silent**. A healthy server produces
  zero findings; a database on loopback is not "exposed"; a permanently busy
  build server raises no anomaly while still tripping the fixed rule; a brand new
  server with no history produces no anomalies at all.
- **The write path**: that every cleanup command is a constant matching a strict
  shape, that none of them can target a container or an image, that only volume
  pruning is marked as destroying data, and that all of it is refused outright
  until it is explicitly enabled.

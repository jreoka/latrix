# latrix

**Run your apps on all your servers as if they were one machine.**

latrix is a single binary. On your computer it's the CLI; on your servers it's
the agent. Point it at any Linux boxes you can SSH into (Hetzner, DigitalOcean,
a NUC under your desk...) and it:

- **installs everything itself**: Docker, WireGuard, firewall rules and a systemd service
- **joins them into one encrypted mesh** (WireGuard), so every machine can reach every app
- **builds your app on the cluster**, with build caches that follow your app between machines
- **places and balances instances**: spreads them across machines, rebalances as load changes, and autoscales between min/max
- **heals itself**: dead machines are detected, their instances replaced and their volumes failed over
- **deploys with zero downtime**: rolling updates, with automatic rollback if the new version isn't healthy
- **replicates volumes** across machines, and moves them with a final sync (no data loss) when a machine is drained
- **does HTTPS for you**: Let's Encrypt certificates, renewed automatically and served by every machine
- **updates the OS for you**: one machine at a time, in a time window. It moves work off first, reboots if needed, then moves work back
- **buys and sizes servers for you (autopilot)**: give it a cloud token and a budget. It picks the cheapest server that fits, adds servers when apps need room, removes or downsizes ones you don't need, and replaces dead ones
- **runs the control plane on your servers**, so nothing has to keep running on your PC
- **also deploys to Kubernetes**: the same `latrix.toml` and commands work on any Kubernetes cluster you already have

```
$ latrix provider set hetzner <token>
$ latrix up --budget 30          # cheapest server + autopilot
$ cd my-app && latrix launch && latrix deploy
==> Deploying my-app
==> Uploading build context (14 files, 0.1 MB) to hel1
[+] Building 21.4s (9/9) FINISHED        ← Docker's own live, colored build view
 => [internal] load build definition from Dockerfile               0.0s
 ...
==> Built 10.77.0.1:7471/my-app:1795738097-onbk in 21s
==> Release v1 created
    2/2 healthy  [running@hel1, running@fsn2]

✓ my-app v1 is live
  http://my-app.203-0-113-10.sslip.io
```

## Quick start

### 1. Get the binary

```bash
cargo install --git https://github.com/jreoka/latrix
```

Or download a release binary. For servers, latrix uploads itself when you run
it from Linux; from macOS/Windows it downloads the static Linux build from the
GitHub release onto the server.

### 2. Try it locally (optional, needs Docker)

```bash
latrix dev                     # terminal 1: a one-machine cluster on your computer
cd my-app && latrix launch     # terminal 2
latrix deploy                  # → http://my-app.localhost:7480
latrix dashboard               # → http://127.0.0.1:7470
```

### 3. Let latrix run the servers (recommended)

Give it a cloud API token and a budget. latrix buys the cheapest server
that fits, then manages servers from there:

```bash
latrix provider set hetzner <api-token>    # and/or: latrix provider set digitalocean <token>
latrix up --budget 30                      # cheapest server + autopilot, ≤ 30/month
```

That's the whole setup. You don't pick sizes, regions or OS versions, and
you don't need an SSH key (latrix makes one if you have none).

### Or add servers yourself

You need root SSH access, or a user with passwordless sudo.

```bash
latrix machine add root@203.0.113.10          # first machine creates the cluster
latrix machine add root@203.0.113.11          # more machines join it
latrix machine add ubuntu@my-box.example.com --name office -i ~/.ssh/id_ed25519
```

Or let latrix buy one: `latrix machine create` picks the cheapest server
(across every provider you have a token for) with at least 2 GB of RAM, and
installs the newest Ubuntu LTS. You can still choose with `--provider`,
`--type`, `--region`, `--min-memory 8GB` or `--image`. To see prices, run
`latrix provider sizes hetzner`.

Supported server OSes: Ubuntu, Debian, Fedora, RHEL/Rocky/Alma, openSUSE and
Arch (anything with systemd plus apt/dnf/yum/zypper/pacman).
Open ports: TCP 80 and 443 for web traffic, and UDP 51870 for the mesh. latrix
configures ufw/firewalld if they're active.

### 4. Deploy

```bash
cd my-app
latrix launch          # writes latrix.toml (detects your Dockerfile / port)
latrix deploy          # uploads the source, builds on the cluster, rolls out
```

## latrix.toml

The smallest useful config:

```toml
app = "hello"

[http]
port = 8080
```

Everything else is optional:

```toml
app = "shop"

[build]
# Default: build ./Dockerfile on the cluster. Alternatives:
# image = "ghcr.io/me/shop:1.2"                      # prebuilt image
# git = "https://github.com/me/shop"  branch = "main" # build from git on the cluster
dockerfile = "Dockerfile"
args = { NODE_ENV = "production" }

command = "node server.js"          # override the image's command

[env]
LOG_LEVEL = "info"                  # use `latrix secrets set` for secrets

[http]
port = 3000                         # the port your app listens on
domains = ["shop.example.com"]      # point an A record at any machine → automatic HTTPS
health = "/healthz"                 # optional; otherwise a TCP check

[[ports]]                           # extra TCP ports
port = 9000                         # reachable as shop.internal:9000 from other apps
public = true                       # ...and on every machine's public IP

[scale]
min = 2                             # autoscale between min and max on CPU/memory
max = 6                             # (or `count = 3` for a fixed number)
cpu = 0.5                           # cores per instance (limit + scheduling)
memory = "512MB"

[[volumes]]                         # replicated; apps with volumes run 1 instance
name = "data"
path = "/data"
copies = 2                          # primary + 1 replica on another machine
sync = "30s"                        # replication interval
# pre_sync = "sqlite3 /data/db '.backup /data/db.bak'"   # consistent snapshot hook

[deploy]
strategy = "rolling"                # or "immediate"
health_timeout = "90s"              # roll back automatically after this
```

### Talking between apps

Every app gets a private DNS name and a virtual IP that work from any
container on any machine:

- `http://shop.internal:3000`
- for compose stacks, the short service name works too: `db:5432` → `db.<stack>.internal`

Ports your image `EXPOSE`s are reachable automatically, so `postgres` is on
`<app>.internal:5432` without extra config.

### Docker Compose

```bash
latrix deploy --compose docker-compose.yml        # each service becomes an app
latrix compose convert docker-compose.yml --write # or convert to latrix.toml files
```

`build`, `image`, `command`, `environment`, `env_file`, `ports`, `expose`, named
`volumes`, `deploy.replicas` and resource limits are converted. Services keep
reaching each other by their compose names, even across machines. Bind mounts
(`./dir:/path`) are skipped, because they can't follow an app between
machines. Bake those files into the image instead.

## Autopilot

With `latrix up`, or `latrix autopilot on --budget 30`, the leader manages
servers by itself once a minute. It compares what your apps ask for
(instances × cpu/memory) with what the machines have.

- **Grows:** when apps need more than ~80% of capacity or a machine is full,
  it buys the cheapest server that covers the shortfall. It uses live prices
  from every provider you gave a token for, prefers the location the
  cluster already uses at equal price, and never exceeds the monthly budget.
  If an app runs 2+ instances or has volume replicas, it makes sure there
  are at least 2 machines.
- **Shrinks:** after ~30 minutes under ~45% use, it drains the most expensive
  server the cluster can do without (apps move first, nothing goes down),
  then deletes it.
- **Right-sizes:** after an hour, a server much bigger than its load is
  replaced with one at least 30% cheaper. The new server starts first, then
  the old one is drained and deleted.
- **Heals:** a server it bought that stops responding for 15 minutes is
  rebooted through the provider API. If it's still dead 30 minutes later,
  it's replaced.
- **Never touches** servers you added with `latrix machine add`, and never
  removes the current leader.

New servers are set up by the cluster itself, over SSH with its own key and
your key (so this computer can still reach them). Your computer doesn't need
to be on.

```bash
latrix autopilot status    # capacity, cost, cheapest server right now, last decision
latrix autopilot on --budget 50 --max-machines 6
latrix autopilot off       # servers stay as they are
```

Your provider token is stored in the cluster's state, which is root-only
(0600) on your servers and never shown in status output. Use a token
scoped to a dedicated project.

## Backups

```bash
latrix backup myapp           # one app
latrix backup --all --stop    # everything; --stop briefly stops apps with volumes for a consistent copy
latrix restore ~/latrix-backups/myapp-2026-11-27-0207.latrix-backup.tar [--as myapp-copy]
```

A backup is a single file in `~/latrix-backups` (or `-o dir`) holding the
app's config, secrets, image and a snapshot of every volume. Restoring
recreates the app with its data on this or any other latrix cluster, without
needing the source code. Backup files contain your secrets, so they're
written readable only by you; keep them somewhere safe.

## Moving from Fly.io

```bash
latrix import fly my-fly-app            # run where your `fly` CLI is logged in
latrix import fly my-fly-app --from-source   # build from this directory instead of copying Fly's image
```

latrix reads the app through your `fly` CLI:

- **Config:** `fly.toml` becomes `latrix.toml`. That covers the HTTP
  service and health check, extra services, env, VM size, mounts and process
  command.
- **Secrets:** Fly never shows secret values, so they're read from a running
  machine's environment.
- **Image:** the deployed image is copied over (needs Docker locally).
- **Volume data:** each volume is archived on the machine and copied.
- **Domains:** your custom domains carry over, and latrix gets new
  certificates once DNS points here.

The import is also saved as a normal backup file. latrix then prints the
DNS change for the cut-over. Fly process groups other than `app`, and
`release_command`, are reported rather than migrated.

## Kubernetes

Already have a Kubernetes cluster (k3s, DOKS, GKE, EKS, AKS...)? Register it
and the same `latrix.toml` and commands work there. latrix drives the
`kubectl` on your computer, so anything kubectl can reach works.

```bash
latrix k8s add prod --context my-cluster --namespace apps --registry ghcr.io/you
latrix --cluster prod k8s setup-tls --email you@example.com   # optional: cert-manager + Let's Encrypt
latrix --cluster prod deploy        # or `latrix cluster use prod`, then plain `latrix deploy`
latrix --cluster prod status
```

| latrix.toml | becomes |
|---|---|
| app | Deployment (rolling updates, spread across nodes) |
| app with `[[volumes]]` | StatefulSet with a PersistentVolumeClaim per volume (`size = "20GB"`) |
| `[http]` / `[[ports]]` | Service `<app>`, plus `<service>` for compose short names |
| `[[ports]] public = true` | Service of type LoadBalancer |
| `[http] domains` | Ingress, with TLS via cert-manager after `k8s setup-tls` |
| `[scale] min/max` | HorizontalPodAutoscaler |
| secrets | Secret `<app>-secrets` |

- **Builds** run on your computer with Docker (`buildx`, for `--platform`,
  default `linux/amd64`). They're pushed to the registry you set with
  `--registry`, and `:latest` doubles as the build cache. You need to be
  logged in to it (`docker login`). Prebuilt images (`[build] image`) need
  nothing extra.
- **Rollouts** are watched. If a release doesn't become ready, latrix
  re-applies the previous one and marks the new one failed. Release history
  lives in a ConfigMap `<app>-latrix`, so `releases`, `rollback`, `scale`,
  `restart`, `secrets`, `logs`, `console`, `ps` and `destroy` all work.
- `latrix k8s export` prints the YAML instead, if you'd rather apply it yourself.
- **Declare ports on Kubernetes.** latrix's own machines discover EXPOSEd
  ports automatically, but Kubernetes can't, so an app with no `[http]` or
  `[[ports]]` gets no Service.
- **Nodes** are managed by Kubernetes, not latrix. `latrix machine list` shows
  them; draining, OS updates and volume replication are the cluster's job
  there.

## Commands

| | |
|---|---|
| `latrix status` | machines, apps, health, recent events |
| `latrix dashboard` | web dashboard (through an SSH tunnel) |
| `latrix ps <app>` | instances, URLs, volumes, releases |
| `latrix logs <app> [-f]` | logs from every instance, merged |
| `latrix deploy [--image ...] [--git url#branch] [--compose file]` | build and roll out |
| `latrix scale <app> 3` / `--min 2 --max 8` / `--memory 1GB` | change scale or resources |
| `latrix restart <app>` | rolling restart |
| `latrix rollback <app> [version]` | back to the previous (or a given) release |
| `latrix secrets set <app> KEY=value` | secrets as env vars (triggers a rolling restart) |
| `latrix console <app> [-- cmd]` | shell into an instance |
| `latrix up [--budget 30]` | buy the cheapest server and turn on the autopilot |
| `latrix backup [app] [--all] [--stop]` / `latrix restore <file>` | full app backups to your computer |
| `latrix import fly <app>` | move a Fly.io app (config, secrets, image, data, domains) |
| `latrix autopilot on\|off\|status` | automatic buying, resizing and deleting of servers |
| `latrix machine list\|add\|create\|remove\|drain\|cordon\|uncordon\|update\|ssh` | machines |
| `latrix volumes`, `latrix certs`, `latrix events` | the rest of the state |
| `latrix settings [key=value ...]` | cluster settings (see below) |
| `latrix upgrade` | roll a new latrix version out to every machine (apps keep running) |
| `latrix cluster list\|use\|forget` | switch between clusters |
| `latrix k8s add\|export\|setup-tls` | use a Kubernetes cluster as a target |

Every command has `--help`.

### Settings

```bash
latrix settings update_window=01:00-04:00   # UTC window for automatic OS updates ("" = any time)
latrix settings auto_updates=false
latrix settings acme_email=me@example.com
latrix settings base_domain=apps.example.com  # every app gets <app>.apps.example.com (wildcard DNS)
latrix settings monthly_budget=40           # shown next to the cost estimate; warns when over
latrix settings rebalance=false autoscale=false
```

## How it works

```
 your computer                         your servers
 ─────────────                         ─────────────────────────────────────────────
 latrix CLI ──ssh tunnel──▶ any machine ──▶ leader (lowest-id live machine)
                                           │  scheduler · state · ACME · maintenance
                                           ▼  replicates state to everyone
                 ┌──────── WireGuard mesh (10.77.0.0/16) ────────┐
                 ▼                       ▼                       ▼
              agent                    agent                   agent
              proxy :80/:443           proxy :80/:443          proxy :80/:443
              registry · DNS           registry · DNS          registry · DNS
              containers               containers              containers
```

- **One agent per machine**, all identical. The live machine with the lowest id
  is the leader: it runs the scheduler and owns writes to the cluster state,
  which it replicates to every machine. If the leader dies, the next machine
  takes over within seconds with a full copy of the state.
- **The CLI talks to the cluster through an SSH tunnel** to any machine. Your
  SSH key is the only credential; the API never listens on a public interface.
- **Every machine runs the same proxy.** You can point DNS at one machine or
  all of them. Requests go to the less busy of two random healthy instances,
  anywhere in the mesh. A failed backend is skipped immediately, and instances
  on unreachable machines leave the routing table within seconds.
- **Builds** run on a machine chosen by cache affinity: the machine that built
  your app last time has warm layers. Images go into a registry on that
  machine. Other machines pull from whichever machine has the image, then keep
  a copy. BuildKit inline cache lets a build on a *new* machine reuse layers
  from the previous release. Old images, registry tags and build cache are
  pruned automatically: the last 3 releases are kept for rollbacks, and the
  build cache stays within a disk-based budget.
- **Volumes** are directories on the primary machine, rsynced over the mesh to
  replicas every `sync` interval. On a *planned* move (drain or OS update), the
  app stops, a final sync runs, and the app starts on the replica: nothing is
  lost. On an *unplanned* failure (machine dead for 60s), the freshest replica
  is promoted, and you lose at most one sync interval of writes.
- **OS updates**: every machine checks for package updates. Inside the update
  window, the leader picks one machine at a time and drains it (instances
  start elsewhere *before* the old ones stop). The machine then installs
  updates, reboots if the OS asks for it, and rejoins. The rebalancer moves
  work back.

## Limits and non-goals

latrix is meant for small clusters (1 to roughly 20 machines) run by one
person or a small team. To keep it simple:

- **Leader election is not Raft.** The lowest-id reachable machine leads, and
  state merges by version. A network partition can briefly produce two
  leaders. They reconcile when the partition heals, but a few changes made on
  the losing side can be lost.
- **Volume replication is asynchronous** (rsync). It's great for app data,
  SQLite and uploads. For a busy database, also use the database's own
  replication or backups, or set `pre_sync` to take consistent snapshots.
- **One writer per volume:** apps with volumes run a single instance (with
  fast failover).
- **Kubernetes is a deploy target, not part of the mesh.** latrix doesn't
  move apps between your own machines and a Kubernetes cluster.
- **The autopilot sizes by what apps reserve** (`cpu`/`memory` in
  latrix.toml), not by live traffic. Autoscaling changes instance counts,
  and the autopilot follows. Prices are refreshed hourly; a small
  provider-side extra such as a public IPv4 fee isn't counted.
- The CLI needs `ssh`/`scp` (OpenSSH) on your computer.

## Building

```bash
cargo build --release                                     # CLI for your machine
cargo build --release --target x86_64-unknown-linux-musl  # static binary for servers
cargo test
```

`e2e/up.sh` starts a few simulated servers (Docker containers with sshd, their
own Docker daemon and userspace WireGuard) so you can try multi-machine
features locally: add them with `latrix machine add`, deploy, then
`docker kill vps1` and watch the failover.

When you run `latrix machine add` from Linux, the running binary is uploaded,
so use a static (musl) build if your desktop's glibc is newer than the
server's. You can also pass `--agent-binary path/to/latrix`.

## License

MIT

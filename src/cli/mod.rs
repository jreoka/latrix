//! Command line interface.

pub mod backup;
pub mod client;
pub mod commands;
pub mod compose;
pub mod deploy;
pub mod doctor;
pub mod fly;
pub mod k8s;
pub mod machine;
pub mod profile;
pub mod providers;
pub mod rexctl;
pub mod ssh;
pub mod update;

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

const ABOUT: &str = "latrix — run your apps on all your servers as if they were one machine.";

const LONG_ABOUT: &str = "\
latrix — run your apps on all your servers as if they were one machine.

Add any Linux servers (Hetzner, DigitalOcean, a box under your desk...) and
latrix joins them into an encrypted mesh, then keeps your apps running on it:
it builds on the cluster, spreads and rebalances instances, replaces anything
that dies, replicates volumes, gets HTTPS certificates and installs OS updates
one machine at a time without downtime.

The control plane runs on your servers. Your computer only needs SSH access.";

const EXAMPLES: &str = "\
Getting started:
  latrix machine add root@203.0.113.10     add a server (creates the cluster)
  latrix machine add root@203.0.113.11     add more; they form one mesh
  cd my-app && latrix launch               write latrix.toml
  latrix deploy                            build on the cluster and roll out
  latrix status                            everything at a glance
  latrix dashboard                         web dashboard

Try it locally first (needs Docker):
  latrix dev                               run a one-machine cluster here
  latrix deploy                            (in another terminal)";

#[derive(Parser)]
#[command(name = "latrix", version, about = ABOUT, long_about = LONG_ABOUT, after_help = EXAMPLES)]
pub struct Cli {
    /// Cluster to use (see `latrix cluster list`)
    #[arg(long, global = true, env = "LATRIX_CLUSTER")]
    pub cluster: Option<String>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Create a latrix.toml for the app in the current directory
    Launch {
        /// App name (defaults to the directory name)
        #[arg(long)]
        name: Option<String>,
        /// Deploy a prebuilt image instead of building a Dockerfile
        #[arg(long)]
        image: Option<String>,
        /// Port your app listens on
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        /// Overwrite an existing latrix.toml
        #[arg(long)]
        force: bool,
    },
    /// Build (on the cluster) and deploy the app, with zero-downtime rollout
    Deploy(DeployArgs),
    /// Cluster overview: machines, apps, recent events
    Status,
    /// List apps (also: apps list, apps show <app>, apps destroy <app>)
    #[command(visible_alias = "app")]
    Apps {
        /// Show individual services of managed stacks (e.g. Fluxer)
        #[arg(short, long)]
        all: bool,
        #[command(subcommand)]
        action: Option<AppsCmd>,
    },
    /// Show an app's instances, URLs, volumes and releases
    #[command(visible_alias = "show", alias = "info")]
    Ps { app: String },
    /// Show / follow an app's logs from all instances
    #[command(alias = "log")]
    Logs {
        app: String,
        /// Keep streaming new lines
        #[arg(short, long)]
        follow: bool,
        /// Lines of history per instance
        #[arg(short = 'n', long, default_value_t = 100)]
        tail: u32,
        /// Only this instance
        #[arg(long)]
        instance: Option<String>,
    },
    /// Change instance count, autoscaling bounds or resources
    Scale {
        app: String,
        /// Fixed number of instances
        count: Option<u32>,
        /// Autoscale: minimum instances
        #[arg(long)]
        min: Option<u32>,
        /// Autoscale: maximum instances
        #[arg(long)]
        max: Option<u32>,
        /// CPU cores per instance
        #[arg(long)]
        cpu: Option<f64>,
        /// Memory per instance, e.g. 512MB
        #[arg(long)]
        memory: Option<String>,
    },
    /// Rolling restart of all instances
    Restart { app: String },
    /// Roll back to the previous (or a specific) release
    Rollback { app: String, version: Option<u64> },
    /// List an app's releases
    Releases { app: String },
    /// Delete an app: its instances, images and volume data
    #[command(visible_alias = "rm", alias = "delete")]
    Destroy(DestroyArgs),
    /// Manage secrets (environment variables kept out of latrix.toml)
    #[command(subcommand, alias = "secret")]
    Secrets(SecretsCmd),
    /// Open a shell (or run a command) inside an instance
    Console {
        app: String,
        /// Command to run (default: sh)
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Add, create, drain and update machines
    #[command(subcommand, visible_alias = "machines")]
    Machine(MachineCmd),
    /// Cloud provider API tokens and sizes/prices
    #[command(subcommand)]
    Provider(ProviderCmd),
    /// Back up apps to this computer: config, secrets, image and volume data
    Backup {
        /// Apps to back up (default: the only app, or use --all)
        apps: Vec<String>,
        /// Back up every app
        #[arg(long)]
        all: bool,
        /// Directory for the backup files (default: ~/latrix-backups)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Skip the image (restoring then needs the image or source again)
        #[arg(long)]
        no_image: bool,
        /// Briefly stop apps with volumes for a fully consistent copy (databases)
        #[arg(long)]
        stop: bool,
    },
    /// Restore an app from a backup file (onto this or any other cluster)
    Restore {
        file: PathBuf,
        /// Restore under a different app name
        #[arg(long = "as")]
        as_name: Option<String>,
    },
    /// Bring apps over from other platforms
    #[command(subcommand)]
    Import(ImportCmd),
    /// Deploy, restore, upgrade and auto-manage a Fluxer stack from a rexctl backup
    #[command(visible_alias = "fluxer")]
    Rexctl {
        #[command(subcommand)]
        action: Option<RexctlCmd>,
    },
    /// Check every machine (over SSH) and explain anything that's wrong
    Doctor {
        /// Only this machine
        machine: Option<String>,
    },
    /// List volumes, including data left on disk by removed apps (also: volumes prune)
    #[command(visible_alias = "volume", alias = "vol")]
    Volumes {
        #[command(subcommand)]
        action: Option<VolumesCmd>,
    },
    /// List TLS certificates
    #[command(alias = "cert")]
    Certs {
        #[command(subcommand)]
        action: Option<ListCmd>,
    },
    /// Automatic Cloudflare DNS management and per-app DNS records
    Dns {
        #[command(subcommand)]
        action: Option<DnsCmd>,
    },
    /// Recent cluster events (deploys, failovers, moves, updates)
    #[command(alias = "event")]
    Events {
        #[command(subcommand)]
        action: Option<ListCmd>,
    },
    /// Show or change cluster settings (updates window, ACME email, ...)
    Settings {
        /// key=value pairs to set, e.g. update_window=01:00-04:00 acme_email=me@example.com
        pairs: Vec<String>,
    },
    /// Open the web dashboard
    Dashboard {
        /// Local port for the dashboard
        #[arg(long, default_value_t = 7475, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// Don't open a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Run a local single-machine cluster on this computer (needs Docker)
    Dev {
        /// Data directory
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Docker Compose helpers
    #[command(subcommand)]
    Compose(ComposeCmd),
    /// Switch between clusters, or reconnect to one (`cluster connect root@<ip>`)
    #[command(subcommand)]
    Cluster(ClusterCmd),
    /// SSH keys that can manage the cluster (add a backup key!)
    #[command(alias = "key")]
    Keys {
        #[command(subcommand)]
        action: Option<KeysCmd>,
    },
    /// Use a Kubernetes cluster as a deploy target
    #[command(subcommand)]
    K8s(K8sCmd),
    /// Start (or grow) a cluster with zero decisions: buys the cheapest
    /// server, then lets the autopilot manage servers from there
    Up {
        /// Monthly spending limit for servers (0 = no limit)
        #[arg(long)]
        budget: Option<f64>,
        /// hetzner or digitalocean (default: any you have a token for)
        #[arg(long)]
        provider: Option<String>,
        /// Most machines the autopilot may run
        #[arg(long)]
        max_machines: Option<u32>,
    },
    /// Automatic server management: buy, resize and delete servers as needed
    #[command(subcommand)]
    Autopilot(AutopilotCmd),
    /// Update this latrix to the newest release (your machines follow)
    SelfUpdate,
    /// Upgrade the latrix agent on every machine to this version
    Upgrade {
        /// Only this machine
        #[arg(long)]
        machine: Option<String>,
        /// Linux binary to upload (defaults to this binary on Linux, or a release download)
        #[arg(long)]
        agent_binary: Option<PathBuf>,
    },
    /// Internal: the agent that runs on each machine
    #[command(subcommand, hide = true)]
    Agent(AgentCmd),
}

#[derive(Args, Clone)]
pub struct DestroyArgs {
    pub app: String,
    /// Don't ask for confirmation
    #[arg(short, long)]
    pub yes: bool,
    /// Keep the app's volume data on the machines (deleted by default)
    #[arg(long, conflicts_with = "purge_volumes")]
    pub keep_volumes: bool,
    /// (old flag; volume data is now deleted by default)
    #[arg(long, hide = true)]
    pub purge_volumes: bool,
}

#[derive(Subcommand)]
pub enum AppsCmd {
    /// List apps
    #[command(alias = "ls")]
    List {
        /// Show individual services of managed stacks (e.g. Fluxer)
        #[arg(short, long)]
        all: bool,
    },
    /// Show an app's instances, URLs, volumes and releases
    #[command(alias = "ps", alias = "info")]
    Show { app: String },
    /// Delete an app: its instances, images and volume data
    #[command(alias = "rm", alias = "delete")]
    Destroy(DestroyArgs),
}

#[derive(Subcommand)]
pub enum VolumesCmd {
    /// List volumes (and unattached data left on disk)
    #[command(alias = "ls")]
    List,
    /// Delete volume data that no app uses any more
    #[command(alias = "clean")]
    Prune {
        /// Don't ask for confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// List an app's daily volume snapshots
    Snapshots { app: String },
    /// Take a snapshot of an app's volumes now
    Snapshot { app: String },
    /// Put an app's volume back to a snapshot (stops the app briefly)
    Rollback {
        app: String,
        /// Snapshot name from `latrix volumes snapshots <app>`
        snapshot: String,
        /// Only this volume (default: every volume of the app)
        #[arg(long)]
        volume: Option<String>,
        /// Don't ask for confirmation
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum ListCmd {
    /// List them (same as without a subcommand)
    #[command(alias = "ls")]
    List,
}

#[derive(Subcommand)]
pub enum DnsCmd {
    /// Show Cloudflare DNS status and managed records (default)
    #[command(alias = "ls", alias = "list")]
    Status {
        /// Only show records for this app
        app: Option<String>,
    },
    /// Configure automatic Cloudflare DNS with an API token (needs Zone:Read + Zone:DNS:Edit)
    #[command(visible_alias = "cf", alias = "setup", alias = "token")]
    Cloudflare {
        /// Cloudflare API token (or set CLOUDFLARE_API_TOKEN / `latrix provider set cloudflare <token>`)
        token: Option<String>,
        /// Proxy records through Cloudflare (orange cloud) by default
        #[arg(long, conflicts_with = "no_proxied")]
        proxied: bool,
        /// Do not proxy records through Cloudflare by default (DNS only)
        #[arg(long)]
        no_proxied: bool,
        /// Default TTL in seconds (1 = Auto, or 60-86400)
        #[arg(long)]
        ttl: Option<u32>,
    },
    /// Disable automatic Cloudflare DNS (existing records in Cloudflare are left untouched)
    #[command(alias = "disable")]
    Off,
    /// Add or update a DNS record for an app (omit --type/--content to auto-point at cluster/app IPs)
    #[command(alias = "set")]
    Add {
        /// App name
        app: String,
        /// Fully-qualified DNS name (e.g. play.example.com or www.shop.example.com)
        name: String,
        /// Record type: A, AAAA, CNAME, TXT, MX, SRV, CAA (omit for auto A/AAAA)
        #[arg(short = 't', long = "type")]
        record_type: Option<String>,
        /// Record value/target (omit for auto-managed cluster/app IPs)
        #[arg(short = 'c', long)]
        content: Option<String>,
        /// Proxy through Cloudflare (orange cloud)
        #[arg(long, conflicts_with = "no_proxied")]
        proxied: bool,
        /// Do not proxy through Cloudflare (DNS only)
        #[arg(long)]
        no_proxied: bool,
        /// TTL in seconds (1 = Auto, or 60-86400)
        #[arg(long)]
        ttl: Option<u32>,
        /// Priority (for MX / SRV records)
        #[arg(long)]
        priority: Option<u16>,
    },
    /// Remove a CLI-managed DNS record from an app
    #[command(alias = "rm", alias = "delete")]
    Remove {
        /// App name
        app: String,
        /// DNS record name to remove
        name: String,
        /// Only remove this record type (e.g. TXT, CNAME, A)
        #[arg(short = 't', long = "type")]
        record_type: Option<String>,
        /// Only remove a record with this exact content
        #[arg(short = 'c', long)]
        content: Option<String>,
    },
    /// Sync all app DNS records with Cloudflare now
    Sync,
}

#[derive(Args)]
pub struct DeployArgs {
    /// Path to latrix.toml
    #[arg(short, long, default_value = "latrix.toml")]
    pub config: PathBuf,
    /// Deploy this image instead of building
    #[arg(long, conflicts_with_all = ["git", "compose"])]
    pub image: Option<String>,
    /// Build from this git repository on the cluster (url[#branch])
    #[arg(long, conflicts_with_all = ["image", "compose"])]
    pub git: Option<String>,
    /// Deploy every service of a docker-compose file
    #[arg(long, conflicts_with_all = ["image", "git"])]
    pub compose: Option<PathBuf>,
    /// Don't wait for the rollout to finish
    #[arg(short, long)]
    pub detach: bool,
    /// Release description
    #[arg(short, long)]
    pub message: Option<String>,
}

#[derive(Subcommand)]
pub enum SecretsCmd {
    /// Set secrets: latrix secrets set myapp KEY=value OTHER=value
    Set {
        app: String,
        #[arg(required = true)]
        pairs: Vec<String>,
    },
    /// Remove secrets
    #[command(alias = "rm", alias = "delete")]
    Unset {
        app: String,
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// List secret names
    #[command(alias = "ls")]
    List { app: String },
}

#[derive(Subcommand)]
pub enum MachineCmd {
    /// Add an existing server over SSH (installs everything it needs)
    Add {
        /// user@host (root, or a user with passwordless sudo)
        target: String,
        /// Machine name (defaults to the hostname)
        #[arg(long)]
        name: Option<String>,
        /// SSH port
        #[arg(short, long, default_value_t = 22, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// SSH private key
        #[arg(short = 'i', long)]
        key: Option<String>,
        /// Region label used to spread instances
        #[arg(long)]
        region: Option<String>,
        /// Public IP other machines use to reach this one (default: resolved from host)
        #[arg(long)]
        public_ip: Option<String>,
        /// Linux latrix binary to install
        #[arg(long)]
        agent_binary: Option<PathBuf>,
    },
    /// Buy a new server and add it (cheapest that fits, unless you choose)
    Create {
        /// hetzner or digitalocean (default: any you have a token for)
        #[arg(long)]
        provider: Option<String>,
        /// Server size/type (default: cheapest with at least --min-memory)
        #[arg(long = "type", alias = "size")]
        size: Option<String>,
        /// Region / location (default: wherever that is cheapest)
        #[arg(long)]
        region: Option<String>,
        /// Minimum memory when picking automatically, e.g. 4GB
        #[arg(long, default_value = "2GB")]
        min_memory: String,
        /// OS image
        #[arg(long)]
        image: Option<String>,
        /// Machine name
        #[arg(long)]
        name: Option<String>,
        /// SSH private key (its .pub is uploaded)
        #[arg(short = 'i', long)]
        key: Option<String>,
        #[arg(long)]
        agent_binary: Option<PathBuf>,
    },
    /// List machines with load, updates and cost
    #[command(alias = "ls")]
    List,
    /// Drain a machine (moves everything off), then remove it
    #[command(alias = "rm", alias = "delete")]
    Remove {
        name: String,
        /// Remove without draining
        #[arg(long)]
        force: bool,
        /// Also delete the server at its cloud provider
        #[arg(long)]
        destroy: bool,
    },
    /// Move all instances off a machine and cordon it
    Drain { name: String },
    /// Stop placing new instances on a machine
    Cordon { name: String },
    /// Put a machine back into service
    Uncordon { name: String },
    /// Drain, install OS updates (+reboot if needed), and rejoin — now
    Update { name: String },
    /// SSH into a machine
    Ssh { name: String },
}

#[derive(Subcommand)]
pub enum ProviderCmd {
    /// Save an API token: latrix provider set hetzner <token>
    Set { provider: String, token: String },
    /// Remove an API token (locally and on the cluster): latrix provider unset digitalocean
    #[command(aliases = ["rm", "remove", "delete"])]
    Unset { provider: String },
    /// List server sizes with monthly prices
    Sizes { provider: String },
}

#[derive(Subcommand)]
pub enum ComposeCmd {
    /// Print (or write) latrix.toml files for each compose service
    Convert {
        #[arg(default_value = "docker-compose.yml")]
        file: PathBuf,
        /// Write latrix.<service>.toml files next to the compose file
        #[arg(long)]
        write: bool,
    },
}

#[derive(Subcommand)]
pub enum ImportCmd {
    /// Move a Fly.io app here: config, secrets, image, volume data, domains
    Fly {
        /// The Fly app name
        app: String,
        /// Name on latrix (default: same as on Fly)
        #[arg(long = "as")]
        as_name: Option<String>,
        /// Don't copy volume data
        #[arg(long)]
        no_data: bool,
        /// Don't copy secrets
        #[arg(long)]
        no_secrets: bool,
        /// Build from the current directory instead of copying Fly's image
        #[arg(long)]
        from_source: bool,
    },
}

#[derive(Subcommand)]
pub enum RexctlCmd {
    /// Show the managed Fluxer stack, release version, voice endpoints and service health (default)
    #[command(alias = "ps")]
    Status,
    /// Load and deploy a Fluxer rexctl backup (.tar.zst) onto the cluster and auto-manage it
    #[command(visible_alias = "restore", alias = "import")]
    Deploy {
        /// Path to the rexctl backup archive (.tar.zst)
        file: PathBuf,
        /// Stack/group name on latrix (default: from backup manifest, usually "fluxer")
        #[arg(long)]
        project: Option<String>,
        /// Override the Fluxer domain (default: from backup)
        #[arg(long)]
        domain: Option<String>,
        /// Override the Fluxer release version (e.g. 2026.1124.80040)
        #[arg(long)]
        release: Option<String>,
        /// Disable automatic background Fluxer upgrades on the cluster leader
        #[arg(long)]
        no_auto_upgrade: bool,
        /// Volume replica count across machines (default: 2)
        #[arg(long, default_value_t = 2)]
        copies: u32,
        /// Optional region pin for Fluxer services (e.g. ash)
        #[arg(long)]
        region: Option<String>,
        /// Skip SHA256SUMS verification when reading the backup
        #[arg(long)]
        skip_verify: bool,
        /// Replace an existing managed Fluxer stack on this cluster
        #[arg(long)]
        replace: bool,
        /// Inspect the backup and print the deployment plan without modifying the cluster
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect and verify a rexctl backup file locally (no cluster required)
    Inspect {
        /// Path to the rexctl backup archive (.tar.zst)
        file: PathBuf,
        /// Skip SHA256SUMS verification
        #[arg(long)]
        skip_verify: bool,
    },
    /// Upgrade the managed Fluxer stack (snapshots volumes + automatic rollback on failure)
    Upgrade {
        /// Target Fluxer release version (default: latest from fluxer.dev)
        version: Option<String>,
        /// Force re-applying even if already on the target release
        #[arg(long)]
        force: bool,
    },
    /// Configure automatic background Fluxer upgrades on the cluster leader
    AutoUpgrade {
        /// `on` or `off` (omit to view current setting)
        mode: Option<String>,
        /// Hours between automatic release checks (1-168, default 6)
        #[arg(long)]
        interval: Option<u64>,
        /// Trigger a release check immediately
        #[arg(long)]
        check_now: bool,
    },
    /// Create a rexctl-compatible .tar.zst backup from the running Fluxer stack
    Backup {
        /// Directory for the backup file (default: ~/latrix-backups)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Skip bundled SeaweedFS uploads volume
        #[arg(long)]
        no_uploads: bool,
    },
    /// View or follow logs for one Fluxer service (e.g. api, edge, livekit) or core services
    #[command(alias = "log")]
    Logs {
        /// Service name (e.g. api, gateway, edge, livekit, postgres); omit for core services
        service: Option<String>,
        /// Keep streaming new lines
        #[arg(short, long)]
        follow: bool,
        /// Lines of history per instance
        #[arg(short = 'n', long, default_value_t = 100)]
        tail: u32,
    },
    /// Rolling restart of one Fluxer service or the whole stack
    Restart {
        /// Service name (omit to restart every Fluxer service)
        service: Option<String>,
    },
    /// View or change Fluxer settings (re-applies to affected services automatically)
    Config {
        #[command(subcommand)]
        action: Option<RexctlConfigCmd>,
    },
    /// Destroy the managed Fluxer stack and all its services
    #[command(alias = "rm", alias = "delete")]
    Destroy {
        /// Don't ask for confirmation
        #[arg(short, long)]
        yes: bool,
        /// Keep volume data on the machines (deleted by default)
        #[arg(long)]
        keep_volumes: bool,
    },
}

#[derive(Subcommand)]
pub enum RexctlConfigCmd {
    /// List current Fluxer settings (secrets masked)
    #[command(alias = "ls")]
    List,
    /// Set one or more settings: latrix rexctl config set domain=chat.example.com storage.region=auto
    Set { pairs: Vec<String> },
    /// Remove one or more settings
    #[command(alias = "rm", alias = "delete")]
    Unset { keys: Vec<String> },
}

#[derive(Subcommand)]
pub enum AutopilotCmd {
    /// Turn it on (sends your provider tokens and SSH key to the cluster)
    On {
        /// Monthly spending limit for servers (0 = no limit)
        #[arg(long)]
        budget: Option<f64>,
        /// Keep at least this many machines
        #[arg(long)]
        min_machines: Option<u32>,
        /// Never run more than this many machines
        #[arg(long)]
        max_machines: Option<u32>,
        /// Only use these providers (default: every provider you have a token for)
        #[arg(long)]
        provider: Vec<String>,
    },
    /// Turn it off (servers stay as they are)
    Off,
    /// What it sees and what it decided last
    Status,
}

#[derive(Subcommand)]
pub enum K8sCmd {
    /// Register a Kubernetes cluster (via kubectl) under a name
    Add {
        /// Name to use with --cluster / `latrix cluster use`
        name: String,
        /// kubeconfig context (default: kubectl's current context)
        #[arg(long)]
        context: Option<String>,
        /// Path to a kubeconfig file
        #[arg(long)]
        kubeconfig: Option<String>,
        /// Namespace for your apps
        #[arg(long, default_value = "default")]
        namespace: String,
        /// Registry to push built images to, e.g. ghcr.io/you
        #[arg(long)]
        registry: Option<String>,
        /// Ingress class (e.g. nginx, traefik); default: the cluster's default
        #[arg(long)]
        ingress_class: Option<String>,
        /// StorageClass for volumes; default: the cluster's default
        #[arg(long)]
        storage_class: Option<String>,
        /// Platform to build images for
        #[arg(long, default_value = "linux/amd64")]
        platform: String,
        /// Give every HTTP app <app>.<base_domain> (needs wildcard DNS to your ingress)
        #[arg(long)]
        base_domain: Option<String>,
    },
    /// Print the Kubernetes YAML for latrix.toml (or a compose file)
    Export {
        #[arg(short, long, default_value = "latrix.toml")]
        config: PathBuf,
        #[arg(long)]
        compose: Option<PathBuf>,
        /// Image to use instead of [build] image / the registry
        #[arg(long)]
        image: Option<String>,
    },
    /// Install cert-manager + a Let's Encrypt issuer so domains get HTTPS
    SetupTls {
        /// Email for Let's Encrypt
        #[arg(long)]
        email: String,
        /// ClusterIssuer name
        #[arg(long, default_value = "letsencrypt")]
        issuer: String,
    },
}

#[derive(Subcommand)]
pub enum ClusterCmd {
    /// List configured clusters
    #[command(alias = "ls")]
    List,
    /// Make a cluster the default
    Use { name: String },
    /// Forget a cluster locally (does not touch the machines)
    Forget { name: String },
    /// Reconnect to an existing cluster through any of its machines (new
    /// computer, lost config): latrix cluster connect root@<ip>
    Connect {
        /// user@host of any machine in the cluster
        target: String,
        /// SSH port
        #[arg(short, long, default_value_t = 22, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// SSH private key
        #[arg(short = 'i', long)]
        key: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum KeysCmd {
    /// SSH keys every machine accepts
    #[command(alias = "ls")]
    List,
    /// Let a key log in to every machine (default: this computer's key)
    Add {
        /// Public key, or a .pub file
        key: Option<String>,
    },
    /// Remove a key from every machine
    #[command(alias = "rm")]
    Remove {
        /// Public key, a .pub file, or the key's comment (e.g. me@laptop)
        key: String,
    },
}

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Run the agent
    Run {
        #[arg(long)]
        dev: bool,
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Print this machine's WireGuard public key (generating it if needed)
    Keygen {
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Print machine facts as JSON
    Facts,
    /// Initialize the first machine of a cluster (JSON on stdin)
    InitFirst {
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Write identity + state received when joining (JSON on stdin)
    WriteJoin {
        #[arg(long)]
        data: Option<PathBuf>,
    },
}

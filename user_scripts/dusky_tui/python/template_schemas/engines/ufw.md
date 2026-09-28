# Engine: `ufw`

`UfwEngine` provides high-performance, comprehensive management of Linux netfilter firewalls through UFW (Uncomplicated Firewall).

## Capabilities

- **Status & Control**: Real-time status inspection (`active`/`inactive`), live logging levels (`off`, `low`, `medium`, `high`, `full`), default incoming/outgoing/routed traffic policies (`allow`, `deny`, `reject`), reload, enable, disable, and clean reset.
- **Port Inspector & Prober**: Correlates live listening TCP/UDP sockets (`ss -tlunp`) with UFW firewall rules to categorize every port into `EXPOSED`, `ALLOWED`, `BLOCKED`, `PROTECTED` (localhost-only), or `FILTERED` (default drop). Includes active socket connection probing.
- **Fast Port Opening & Closing**: Instant 1-click port opening (`allow`), closing (`deny`), or rejecting (`reject`) for TCP, UDP, or both, scoped to anywhere, LAN RFC1918 subnets, or specific CIDRs.
- **Common Service Switches**: Instant switches for SSH (22), HTTP (80), HTTPS (443), FTP (21), DNS (53), WireGuard (51820), Tailscale (41641), Moonlight (47984-48010), Plex (32400), Minecraft (25565), Samba (445), VNC (5901), and Syncthing (22000).
- **Active Connections & IP Ban**: Live connection tracking (`ss -tunp state established`), instant 1-click top-priority IP banning, unbanning, and a Panic Killswitch.
- **Stealth ICMP Ping Mode**: Toggles ICMP echo-request rules between `ACCEPT` and `DROP` in `/etc/ufw/before.rules` to make the host completely invisible to network ping sweeps.
- **Port Forwarding / NAT Redirection**: Configure PREROUTING DNAT rules in `/etc/ufw/before.rules` to route external WAN ports to internal container IPs (Docker, Waydroid, KVM).
- **Rule Lifecycle**: Parse numbered active rules, delete rules by number or signature, prepend urgent rules, insert rules at arbitrary indices, and build rules with simple or extended OpenBSD PF-style syntax (ports, port ranges, protocols, source/dest subnets, interfaces).
- **Domain & Website Filter**: Dynamic DNS resolution (A and AAAA IPv4/IPv6 records) for domain names, allowing users to block specific websites or activate **Exclusive Lockdown / Whitelist Mode** where all general outbound web traffic is blocked and only specified domains/ports plus core DNS/DHCP/loopback are permitted.
- **Framework & Kernel Integration**: Toggle kernel IP forwarding (`net/ipv4/ip_forward` and `net/ipv6/conf/all/forwarding` in `/etc/ufw/sysctl.conf`), Waydroid NAT masquerading in `/etc/ufw/before.rules`, and Docker bypass mitigation via the `DOCKER-USER` chain in `/etc/ufw/after.rules`.
- **Application Profiles**: Discover and manage application profiles from `/etc/ufw/applications.d/`, view port definitions, and allow/deny application suites.
- **Hardened Presets**: Pre-configured battle-tested profiles including Dusky Full Provisioning, Strict Workstation, Exclusive Whitelist Lockdown, Developer LAN Trust, Stealth Mode, and Moonlight/Streaming.
- **Live Netfilter Reports**: Stream live kernel netfilter diagnostics (`listening`, `added`, `user-rules`, `before-rules`, `after-rules`, `logging-rules`, `raw`).

## Scopes and Keys

| Scope | Key | Type | Description |
|---|---|---|---|
| `status` | `firewall_enabled` | `bool` | Master firewall enable/disable state |
| `status` | `logging_level` | `cycle` | Logging level (`off`, `low`, `medium`, `high`, `full`) |
| `status` | `default_incoming` | `cycle` | Default incoming policy (`deny`, `allow`, `reject`) |
| `status` | `default_outgoing` | `cycle` | Default outgoing policy (`allow`, `deny`, `reject`) |
| `status` | `default_routed` | `cycle` | Default forward/routed policy (`deny`, `allow`, `reject`) |
| `ports` | `quick_port` | `string` | Target port or range for quick open/close |
| `ports` | `quick_proto` | `cycle` | Protocol (`tcp`, `udp`, `both`) |
| `ports` | `quick_scope` | `string` | Ingress scope (`any`, `lan`, or custom IP/CIDR) |
| `ports` | `probe_port` | `int` | Port number to actively test and probe |
| `services` | `<service_name>` | `bool` | Toggle individual common services (e.g. `ssh`, `https`, `wireguard`) |
| `connections` | `ban_ip_target` | `string` | Target remote IP to ban or unban |
| `framework` | `icmp_stealth` | `bool` | Drop ICMP ping requests (stealth mode) |
| `nat` | `forward_ext_port` | `string` | External WAN port to forward |
| `nat` | `forward_dest_ip` | `string` | Internal destination IP (e.g. Waydroid/Docker) |
| `nat` | `forward_dest_port` | `string` | Internal destination port |
| `builder` | `action` | `cycle` | Rule action (`allow`, `deny`, `reject`, `limit`) |
| `builder` | `direction` | `cycle` | Rule direction (`in`, `out`, `route`) |
| `builder` | `proto` | `cycle` | Protocol (`any`, `tcp`, `udp`, `ah`, `esp`, `gre`, `vrrp`, `ipv6`, `igmp`) |
| `builder` | `port` | `string` | Target port(s) or range (e.g. `80`, `443`, `80,443`, `8080:8090`) |
| `builder` | `source` | `string` | Source IP or subnet (default `"any"`) |
| `builder` | `dest` | `string` | Destination IP or subnet (default `"any"`) |
| `builder` | `interface` | `string` | Ingress interface (e.g. `wlan0`, `eth0`, `any`) |
| `builder` | `out_interface` | `string` | Egress interface for routed rules |
| `builder` | `log` | `cycle` | Per-rule packet logging (`none`, `log`, `log-all`) |
| `builder` | `comment` | `string` | Rule comment annotation |
| `builder` | `placement` | `cycle` | Placement mode (`append`, `prepend`, `insert`) |
| `builder` | `insert_num` | `int` | Insertion rule index |
| `domains` | `whitelist_mode` | `bool` | Toggle strict Exclusive Whitelist / Lockdown mode |
| `framework` | `ip_forward` | `bool` | Kernel IP forwarding sysctl toggle |
| `framework` | `waydroid_nat` | `bool` | Waydroid container NAT postrouting toggle |
| `framework` | `docker_mitigation` | `bool` | Docker daemon bypass prevention toggle |
| `actions` | `action_*` | `bool` (`trigger`) | Momentary action triggers |

# Optional service firewall

RustIPS always drops traffic from addresses it has blocked. The **service
firewall** adds a second, optional layer: a default-deny input policy with
allow rules generated from the services the host is actually running.

It is **disabled by default**. An administrator enables it on the **Firewall**
page (`/firewall`), using the same single-button state control as the detector
catalog. The toggle is stored in SQLite (`settings.firewall.settings`) and
takes effect within about a second; no restart is required.

The service firewall is only written to nftables when the daemon is in
`enforce` mode. In `observe` mode the page shows what would be applied, but no
kernel rules change.

## What the chain looks like when enabled

The RustIPS-owned `inet rustips` input chain is rewritten atomically in this
order:

1. Drop IPv4/IPv6 traffic from the blocked-source sets. Blocks always win.
2. Accept `iif "lo"`, so loopback services and the loopback web UI keep working
   even if an admin rule targets local traffic.
3. Apply **Admin Drops** and per-service drop toggles.
4. Accept `ct state established,related`, so replies to connections the host
   initiated keep working.
5. Accept essential non-service traffic: IPv6 neighbour discovery/router
   advertisements and DHCPv4/DHCPv6 server replies.
6. Accept TCP/UDP traffic to the generated service ports.
7. Rate-limit and log remaining packets with the prefix `rustips-fw-drop`.
8. `drop` (default) or `reject` everything else.

## Firewall page tabs

* **Active Drops** — temporary active blocks: sources RustIPS is currently
  dropping with an expiry, plus manual block and unblock. `/blocks` redirects
  here.
* **Permanent Drops** — active blocks with no expiry. They remain until an
  administrator unblocks them.
* **Admin Drops** — explicit drop rules with optional source, destination,
  protocol and port. Rules can be added, edited, enabled/disabled and deleted.
  They are evaluated before established connections and service allows.
* **External System Services** — discovered services reachable beyond loopback.
  Services default to allow; the toggle writes an explicit drop rule ahead of
  the allow rules.
* **Internal System Services** — loopback-only services. They default to allow
  and are protected by the loopback rule, so no drop toggle is offered.
* **Honeypot** — DET-26 enable/threshold settings plus add/edit/delete for
  honeypot ports. The firewall allow set follows port changes immediately; the
  detector still needs a restart to watch new ports.

Service rows no longer carry separate status/mode columns. The toggle itself is
the mode, and newly discovered services are highlighted in yellow until
acknowledged or toggled.

Discovery refresh, pinned ports, honeypot inclusion, DET-27 logging and
drop-vs-reject remain in the separate **Firewall settings** card below the tabs.

The nftables log is limited to 10 packets/second with a burst of 20 so a scan
cannot flood the journal. Journal ingestion recognises the prefix, records the
source address and emits the alert-only **DET-27 Firewall default-drop**
detector. DET-27 is cooldown-limited per source; the shipped disposition rule
alerts and does not auto-block because the packet is already denied.

## Where allow rules come from

The allow set is the union of:

* **Listening services** discovered from `/proc/net/{tcp,tcp6,udp,udp6}`.
  TCP listeners are state `0A`; UDP sockets are included when their remote
  address is unspecified. Discovery is repeated every `refresh_secs` (default
  30 seconds), so services that start later are picked up automatically.
* **Pinned ports** (`allow_tcp_ports`, `allow_udp_ports`) for services that are
  not listening yet or listen only intermittently.
* **Honeypot ports** when DET-26 is enabled and `include_honeypot` is true.
  Honeypot ports must be reachable for the detector to see contact; there is no
  real listener behind them.

Services bound only to a loopback address do not open an external port; the
`iif lo` rule covers them. A service bound to `0.0.0.0` or `::` is allowed on
all local addresses. A service bound to one specific non-loopback address gets
a destination-address-qualified rule, so its port is not opened on other
interfaces.

## Configuration file

The defaults live in the `[firewall]` section of `/etc/rustips/config.toml`:

```toml
[firewall]
enabled = false
discover_services = true
refresh_secs = 30
allow_tcp_ports = []
allow_udp_ports = []
include_honeypot = true
log_drops = true
reject = false
```

The UI saves its live copy in SQLite and overrides this section on the next
read. Honeypot ports are still detector parameters
(`detection.honeypot_ports`) stored in the same override store. The firewall
reads them live, so the allow set follows a port add/edit/delete immediately;
DET-26 itself still requires a RustIPS restart to watch the new ports.

Admin drop rules and discovered-service state use schema v12 tables
(`firewall_admin_rules` and `firewall_services`).

## Safety and recovery

* RustIPS owns only its `inet rustips` table. This mode does not read or merge
  ufw/firewalld/nftables rulesets from other tools. If the host already runs a
  strict firewall, decide which layer should own the input policy before
  enabling this one.
* Existing SSH/RDP/web sessions survive because established connections are
  accepted.
* Loopback traffic is never blocked, so loopback-only services are listed under
  Internal System Services as “loopback protected” without a drop toggle.
* If service discovery fails, the daemon keeps the last-good allow set rather
  than applying an empty one. At startup, if discovery has never succeeded, it
  does not enable the firewall.
* An administrator can always disable the layer from the Firewall page over an
  existing session, or by removing the RustIPS table from a local console:
  `sudo nft delete table inet rustips`.
* `sudo rustips check` reports the effective firewall state, discovery health
  and an observe-mode warning.

## Known limits

* The firewall only covers the `input` hook; RustIPS does not route or forward
  traffic.
* Service discovery is socket-based, not process-based. It does not know which
  package owns a port.
* A service that opens and closes a port between refresh intervals may be
  dropped until the next discovery.
* ICMP echo requests are not part of the generated service set and are
  therefore dropped; IPv6 neighbour discovery and related ICMP errors remain
  allowed. Disable the layer if you need unrestricted ping.
* DET-27 depends on kernel messages reaching the journal
  (`ReadKMsg=yes`, the systemd default) and on host-log ingestion being
  enabled. The firewall still drops traffic when logging is unavailable; only
  the detector evidence is missing.

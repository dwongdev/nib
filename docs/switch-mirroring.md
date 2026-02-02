# Switch Port Mirroring Setup

When running NIB as a dedicated sensor, you'll need to configure your switch to mirror traffic to the NIB host. This guide covers setup for popular managed switches.

## How Port Mirroring Works

```
┌─────────────────────────────────────────┐
│           Managed Switch                │
├─────────────────────────────────────────┤
│                                         │
│  Port 1 (Router uplink) ──┐             │
│  Port 2 (Server)         ─┼── Mirror    │
│  Port 3 (Workstations)   ─┤   Sources   │
│       ...                 │             │
│                           ▼             │
│  Port 24 (NIB host) ◄─── Mirror Target  │
│                                         │
└─────────────────────────────────────────┘
```

The switch copies packets from source ports to the target port. NIB's Suricata sees all mirrored traffic.

## UniFi (Ubiquiti)

### Requirements
- UniFi managed switch (USW, US-*-* series)
- UniFi Network Controller

### Setup

1. **Open UniFi Network Controller** → **Devices** → Select your switch

2. **Go to Ports tab** (switch port diagram)

3. **Click the port where NIB is connected** (this will be the mirror destination)

4. **In port settings**, find **Port Mirroring**:
   - Enable port mirroring
   - Select source port(s) to mirror (e.g., your router's uplink port)
   - Direction: **Both** (Ingress + Egress)

5. **Apply** the changes

### Tips
- Mirror your **router uplink port** to see all internet-bound traffic
- For full visibility, mirror multiple ports (but watch bandwidth)
- SFP+ ports work great as mirror destinations for high-speed capture

---

## TP-Link Omada

### Requirements
- Omada managed switch (TL-SG*MP, SG3*, JetStream series)
- Omada SDN Controller (hardware, software, or cloud)

### Setup via Omada Controller

1. **Log into Omada Controller** → **Devices** → Select your switch

2. **Go to Ports** tab

3. **Click the destination port** (where NIB is connected)

4. **Enable Port Mirroring**:
   - Select source port(s)
   - Direction: **Both**

5. **Apply** changes

### Setup via Switch Web UI (standalone mode)

If not using Omada Controller:

1. Log into switch directly: `http://<switch-ip>`
2. Go to **Switching** → **Port Mirror**
3. Configure source and destination ports
4. Save

### Blocking with Omada

NIB includes an Omada sync script that pushes CrowdSec decisions to Omada-managed gateways:

**Requirements:**
- Omada SDN Controller 5.0+
- Omada-managed gateway (ER605, ER7206, etc.)
- API access enabled on controller

**Step 1: Configure NIB**

```bash
# In .env
BOUNCER_MODE=sensor
ROUTER_TYPE=omada
OMADA_URL=https://192.168.1.10:8043
OMADA_USER=admin
OMADA_PASS=your-password
OMADA_SITE=Default
OMADA_GROUP_NAME=nib-blocklist
```

**Step 2: Generate bouncer API key**

```bash
make add-router-bouncer
# Copy the key to CROWDSEC_LAPI_KEY in .env
```

**Step 3: Test the sync**

```bash
# Dry run - shows what would be synced
python3 scripts/omada-sync.py --dry-run

# One-shot sync
python3 scripts/omada-sync.py

# Continuous sync (daemon)
python3 scripts/omada-sync.py --daemon
```

**Step 4: Create ACL rule in Omada**

The sync creates an IP Group but doesn't create firewall rules (to avoid accidentally blocking everything). You need to create an ACL rule:

1. Log into Omada Controller
2. Go to **Settings** → **Network Security** → **ACL** → **Gateway ACL**
3. Click **+ Create New Rule**:
   - **Name**: `NIB Blocklist`
   - **Status**: Enable
   - **Policy**: Deny
   - **Protocols**: All
   - **Source**: IP Group → `nib-blocklist`
   - **Destination**: Any
4. Save and apply

**Step 5: Run as service (optional)**

Create a systemd service for continuous sync:

```bash
# /etc/systemd/system/nib-omada-sync.service
[Unit]
Description=NIB Omada CrowdSec Sync
After=network.target

[Service]
Type=simple
EnvironmentFile=/path/to/nib/.env
ExecStart=/usr/bin/python3 /path/to/nib/scripts/omada-sync.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now nib-omada-sync
```

---

## MikroTik

### Requirements
- MikroTik switch or router with switching chip
- RouterOS v6 or v7

### Setup via WinBox/WebFig

1. Go to **Switch** → **Port** (or **Bridge** → **Ports** for bridged setup)

2. Configure port mirroring:
   - **Mirror Source**: Select port(s) to mirror
   - **Mirror Target**: Port where NIB is connected
   - **Mirror**: `both` (ingress + egress)

### Setup via CLI

```bash
# RouterOS 7 (CRS3xx, CRS5xx switches)
/interface/ethernet/switch/port
set [find name=ether1] mirror-source=both mirror-target=ether24

# Or for bridged ports
/interface/bridge/port
set [find interface=ether1] hw=yes
```

### Blocking with MikroTik

MikroTik has excellent CrowdSec integration:

```bash
# In NIB .env
BOUNCER_MODE=sensor
ROUTER_TYPE=mikrotik
ROUTER_URL=https://192.168.1.1
ROUTER_USER=admin
ROUTER_PASS=your-password

# Start sync
make router-sync-daemon
```

NIB will push blocked IPs to a MikroTik address list, which you can reference in firewall rules.

---

## Cisco (Small Business / Catalyst)

### Small Business (SG/SF series)

1. Log into switch web UI
2. Go to **Status and Statistics** → **Port Mirroring**
3. Configure:
   - Source Port
   - Destination Port
   - Direction: Both

### Catalyst (IOS)

```
configure terminal
monitor session 1 source interface Gi0/1 both
monitor session 1 destination interface Gi0/24
```

---

## Netgear

### Smart Managed Plus / Pro series

1. Log into switch web UI
2. Go to **Monitoring** → **Mirroring**
3. Configure:
   - Destination Port (NIB host)
   - Source Port(s)
   - Direction: Both
4. Enable mirroring

---

## Generic Recommendations

### What to Mirror

| Scenario | What to Mirror | Notes |
|----------|----------------|-------|
| **Internet threats** | Router uplink port | See all external traffic |
| **Full visibility** | All ports | High bandwidth, need capable NIC |
| **Server protection** | Specific server ports | Targeted monitoring |
| **Segmented network** | Inter-VLAN trunk | See traffic between VLANs |

### Bandwidth Considerations

- Mirror destination port receives **copies** of all traffic
- If you mirror a 1 Gbps link that's 80% utilized, the mirror port needs 800 Mbps capacity
- Mirroring multiple ports multiplies bandwidth
- Use a dedicated NIC on the NIB host if possible

### NIB Configuration

After setting up mirroring, configure NIB:

```bash
# In .env
SURICATA_INTERFACE=eth1    # Interface connected to mirror port
BOUNCER_MODE=sensor        # Mirrored traffic can't be blocked inline

# Then restart
make restart
```

### Verify Traffic is Flowing

```bash
# Check Suricata sees packets
make shell-suricata
suricatasc -c "iface-stat default"

# Should show packet counts increasing
# "drop" should stay near 0 (otherwise your hardware can't keep up)
```

---

## Troubleshooting

### No traffic in Grafana

1. **Check interface name**: Run `ip link` on NIB host, verify `SURICATA_INTERFACE` matches
2. **Check mirror config**: Verify switch shows mirroring enabled
3. **Check promiscuous mode**: Run `ip link show <interface>` — should show `PROMISC`
4. **Generate test traffic**: `make test-alert` sends a test pattern

### High packet drops

1. **CPU bottleneck**: Check `htop` during traffic — if Suricata workers are maxed, you need more cores
2. **NIC issues**: Intel NICs handle high packet rates better than Realtek
3. **Ring buffer**: Increase with `ethtool -G <interface> rx 4096`

### Only seeing one direction

- Ensure mirror is set to **Both** (ingress + egress)
- Some switches default to ingress-only

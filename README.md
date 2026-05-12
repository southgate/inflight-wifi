# inflightd

A terminal-based diagnostic tool for inflight WiFi. Auto-detects the onboard system, surfaces hidden flight telemetry, measures the satellite link, and tells you whether the connection is actually broken or just blocking ICMP.

## Why

Inflight WiFi is frequently flaky in ways that are hard to diagnose. Is the satellite handing off? Is the local AP overloaded? Is the gateway blocking ICMP and making the path look broken when TCP works fine? Is my device on a paid tier or stuck in the free messaging walled garden? The carriers don't surface any of this. The avionics vendors do — they just don't tell you the URL.

## What it does

- **Auto-detects** the inflight WiFi system (currently Panasonic Avionics; FlyNet stubs in place but unverified)
- **Pulls live flight data** straight from the IFEC system: flight number, aircraft type and tail number, route, speed, altitude, heading, OAT, time/distance to destination, position (lat/lon)
- **Plots your position** on an ASCII world map with the great-circle route (proper spherical interpolation, not a straight line)
- **Measures the network** at every layer: gateway ICMP/HTTPS, onboard API, Squid proxy, external HTTPS, DNS resolution, throughput
- **Tracks satellite coverage events** — detects state transitions, logs how long each connected/disconnected period lasts
- **Surfaces issues** with a clear severity model that distinguishes "ICMP blocked" (cosmetic) from "actually unreachable" (real problem)
- **Records history** in a ring buffer so you can see latency/throughput trends and spot satellite handoffs in the sparkline charts

## Status

| System                | Airlines                              | Status                              |
| ---                   | ---                                   | ---                                 |
| Panasonic Avionics    | TAP, SWISS, KLM, Air France           | Verified on TAP and SWISS; full API mapped |
| Lufthansa FlyNet      | LH, OS, EW, WK                        | Detection + parser stubs, **not yet verified** on a live aircraft |

Everything else lands as `Unknown` — `--probe-deep` is built to help map new systems quickly.

Currently **macOS only**. Linux support would mostly be replacing `networksetup` / `scutil` calls with `ip` / `nmcli`. PRs welcome.

## Install

No dependencies. Standard library only. Tested on Python 3.10+.

```sh
git clone https://github.com/<you>/inflight-wifi.git
cd inflight-wifi
python3 inflightd.py --help
```

## Usage

### TUI (default)

```sh
python3 inflightd.py
```

Launches the curses TUI. Six views:

| Key | View      | Shows                                                                        |
| --- | ---       | ---                                                                          |
| `o` | overview  | Flight progress, connectivity, key latency numbers, mini sparklines, issues  |
| `n` | network   | Full latency table, DNS, throughput, system info                             |
| `f` | flight    | Detailed flight data + ASCII world map with great-circle route               |
| `t` | trends    | Sparkline charts for every metric, satellite coverage gap log                |
| `p` | plans     | WISP product catalog (free messaging, Light, Premium, Full Flight, etc.)     |
| `i` | issues    | Current issues with detail, historical issue frequency                       |

Other keys: `r` force refresh · `+`/`-` adjust interval · `d` dump history JSON · `?` help overlay · `q` quit (auto-saves session).

### One-shot report

```sh
python3 inflightd.py --report          # human-readable
python3 inflightd.py --json            # machine-readable
```

### When you board an unfamiliar airline

```sh
python3 inflightd.py --probe           # quick path sweep (~30 known endpoints)
python3 inflightd.py --probe-deep      # JS mining + HTML scrape + TLS SAN + port scan + well-knowns
```

`--probe-deep` is the one that found `api.airpana.com` in the cert SAN of a SWISS gateway and let me confirm the system was Panasonic underneath the SWISS branding.

## How it identifies the system

In rough order of confidence:

1. **Gateway MAC OUI** — `00:0d:2e` is registered to Matsushita Avionics (Panasonic).
2. **DNS search domain** — `onboardwifi` (TAP), `swissconnectforguests` (SWISS), `flynet`/`telekom`/`lufthansa` (FlyNet).
3. **Server header on the gateway** — `PAC Web Server` is a dead giveaway.
4. **TLS certificate SAN on the gateway** — Panasonic gateways present a cert for `api.airpana.com`.
5. **ARP-table hostnames** — `flytap`, `klm`, `airfrance`, etc.

If any of these match, the rest of the Panasonic codepath kicks in and you get full flight + connectivity + WISP data.

## Architecture

Single file, single process, no external dependencies.

- **`NetworkSignals.gather()`** — one-shot capture of WiFi info, ARP table, DNS search domain, gateway MAC, captive-portal redirect. Providers read these; they don't re-fetch.
- **`Provider`** — base class. Each inflight system is a subclass implementing `detect()` (returns a `Match` with a confidence score), `discover_api_base()`, and `fetch_flight()` / `fetch_connectivity()` / `fetch_device_state()` / `fetch_wisp_products()`. Defaults return `None`/`[]`, so providers only override what they expose.
- **`PROVIDERS`** — registry list. `detect_system()` runs each provider against the gathered signals, picks the highest-confidence `Match` above `DETECT_FLOOR` (30), and stamps the result onto `SystemInfo`.
- **`PanasonicProvider`** — TAP, KLM, Air France, SWISS. Constants (`oui_prefixes`, `api_base`) live as class attributes. API: `api.airpana.com/inflight/services/...`.
- **`FlynetProvider`** — Lufthansa Group stubs. Schema-tolerant parser that handles multiple JSON shapes; probes several candidate API bases since FlyNet's portal hostname varies.
- **`DataCollector`** — ring buffer of `Snapshot`s, satellite coverage event tracker. Dispatches through `self.provider.fetch_*()` — no per-provider branching.
- **`render_map()`** — ASCII world map with simplified coastline polylines and `great_circle_point()` interpolation.
- **`TUI`** — curses front-end, threaded background collection, six views.
- **`run_deep_probe()`** — endpoint discovery: HTML scrape (CSP, preconnect, embedded JSON, data attrs), JS bundle mining (URL constants, builder functions, WebSockets), TLS cert SAN via `openssl`, well-known files, port scan. Discovery candidates are walked from `provider.discovery_domains` so adding a provider also extends probe coverage.

## A few hard-earned lessons

- **ICMP loss is not reachability.** Most aircraft routers block ICMP wholesale to save uplink and reduce attack surface. TCP/HTTPS goes through fine. The tool now distinguishes the two — if ICMP fails but HTTPS works to the same host, it surfaces "ICMP blocked" as info instead of "Gateway unreachable" as critical.
- **`arp -a` is slow.** Without `-n`, arp does a reverse-DNS lookup on every cached entry. On a satellite link with a populated ARP table, this can take 15+ seconds and time out. Always use `arp -an`.
- **ARP cache only contains hosts you've contacted.** If you want to count visible devices on the local subnet, you have to prod the cache first with parallel TCP connects to a sample of subnet IPs.
- **CSP and preconnect headers are gold.** They often enumerate every API host an app uses. So do TLS cert SANs.
- **`Server: PAC Web Server`** — sometimes the simplest header is the most diagnostic.

## Adding support for a new system

The tool is built around a `Provider` base class and a `PROVIDERS` registry. Adding a new airline/system means writing one subclass and appending it to the list — no edits to `detect_system()` or `DataCollector`.

### 1. Reconnaissance

Connect to the airline WiFi and run:

```sh
python3 inflightd.py --probe-deep
```

Look in the output for:

- A unique **DNS search domain** (e.g. `onboardwifi`, `swissconnectforguests`)
- A distinctive **`Server` header** on the gateway (Panasonic's is `PAC Web Server`)
- **TLS cert SANs** on the gateway or portal — often a dead giveaway (e.g. `api.airpana.com`)
- **CSP / preconnect** headers and **JS bundle URL builders** like `makeServiceURL`, `apiBase`, `BASE_URL`
- The **gateway MAC OUI** — vendor-assigned, harder to spoof than anything else
- The **captive-portal redirect** — what host does Apple's captive probe get redirected to?

### 2. Implement a Provider subclass

In `inflightd.py`, subclass `Provider`. Only override what you need; defaults return `None` / `[]`.

```python
class MyAirlineProvider(Provider):
    name = "MyAirline Inflight"
    hardware = "Vendor Hardware Name"
    discovery_domains = ["portal.myairline.com"]   # for --probe / --probe-deep

    def detect(self, sig: NetworkSignals) -> Optional[Match]:
        confidence = 0
        if sig.gateway_mac_oui == "aa:bb:cc":
            confidence += 60                       # MAC OUI is a strong signal
        if "myairline" in sig.dns_domain.lower():
            confidence += 30                       # DNS search domain
        if any("myairline" in c.get("hostname", "") for c in sig.arp_clients):
            confidence += 15                       # weak: ARP hostname hint
        if confidence == 0:
            return None
        return Match(confidence=min(confidence, 100))

    def discover_api_base(self, sig: NetworkSignals) -> Optional[str]:
        # Return a constant if well-known, or probe candidates and return the first that responds
        return "https://api.myairline.com"

    def fetch_flight(self, api_base: str) -> Optional[FlightData]:
        data, _ = http_get_json(f"{api_base}/flight")
        if not data:
            return None
        fd = FlightData()
        fd.flight_number = data.get("flightNumber", "")
        # …map the rest of the fields
        return fd

    def fetch_connectivity(self, api_base: str) -> Optional[ConnectivityStatus]:
        ...
```

**Confidence scoring.** `detect()` returns a `Match` with a 0–100 score. The convention:

| Signal | Range |
| --- | --- |
| Vendor MAC OUI / TLS cert SAN / vendor `Server` header | 50–60 (strong) |
| DNS search domain / captive-portal redirect to known host | 25–40 (medium) |
| ARP hostname hint / SSID heuristic | 5–20 (weak) |

Multiple signals stack (sum, capped at 100). `DETECT_FLOOR` (30) is the threshold below which the system stays `Unknown` — so a single weak signal won't false-positive.

### 3. Register it

```python
PROVIDERS: list[Provider] = [
    PanasonicProvider(),
    FlynetProvider(),
    MyAirlineProvider(),     # add yours here
]
```

That's it. `detect_system()` will run your `detect()` alongside the others; `DataCollector` will dispatch fetches through your provider; `--probe` and `--probe-deep` will pick up your `discovery_domains` automatically.

### 4. Optional hooks

- **`post_detect(self, info, sig)`** — enrich `SystemInfo` after detection (e.g. discover a portal URL via DNS-domain wildcards, fetch a WISP URL once).
- **`fetch_device_state(self, api_base)`** — return a `DeviceState` if the system exposes one (Panasonic does; FlyNet doesn't).
- **`fetch_wisp_products(self, api_base)`** — return a list of paid-tier products for the **plans** view.
- **`airline_from_flight_number(self, fn)`** — map a flight-number prefix (`"LX"` → `"SWISS"`) when the airline isn't known from network signals alone.

### 5. Send a PR

Include:

- The new `Provider` subclass with brief comments on which signals you're matching.
- Redacted output from `--probe-deep` showing the evidence your `detect()` relies on.
- A live `--report` from an actual flight to confirm the fetchers work end-to-end.

## Disclaimer

This tool talks to documented and undocumented endpoints exposed by inflight entertainment systems for the purpose of diagnosis. It does not attempt to authenticate, evade billing, alter aircraft systems, or bypass paid tiers. The flight-data endpoints used are publicly accessible from any connected device on the aircraft network — they're the same ones that power the moving-map web app passengers already use.

These endpoints are undocumented and can change at any time. Don't expect this to keep working without updates.

## License

MIT. See `LICENSE`.

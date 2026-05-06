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

- **`detect_system()`** — five-signal classifier (above)
- **`fetch_flight_data()` / `fetch_connectivity()` / `fetch_device_state()` / `fetch_wisp_products()`** — Panasonic API fetchers (`api.airpana.com/inflight/services/...`)
- **`flynet_*` family** — Lufthansa FlyNet stubs, schema-tolerant parser that handles multiple JSON shapes
- **`run_diagnostics()`** — ICMP + HTTPS + DNS + throughput probes
- **`DataCollector`** — ring buffer of `Snapshot`s, satellite coverage event tracker
- **`render_map()`** — ASCII world map with simplified coastline polylines and `great_circle_point()` interpolation
- **`TUI`** — curses front-end, threaded background collection, six views
- **`run_deep_probe()`** — endpoint discovery: HTML scrape (CSP, preconnect, embedded JSON, data attrs), JS bundle mining (URL constants, builder functions, WebSockets), TLS cert SAN via `openssl`, well-known files, port scan

## A few hard-earned lessons

- **ICMP loss is not reachability.** Most aircraft routers block ICMP wholesale to save uplink and reduce attack surface. TCP/HTTPS goes through fine. The tool now distinguishes the two — if ICMP fails but HTTPS works to the same host, it surfaces "ICMP blocked" as info instead of "Gateway unreachable" as critical.
- **`arp -a` is slow.** Without `-n`, arp does a reverse-DNS lookup on every cached entry. On a satellite link with a populated ARP table, this can take 15+ seconds and time out. Always use `arp -an`.
- **ARP cache only contains hosts you've contacted.** If you want to count visible devices on the local subnet, you have to prod the cache first with parallel TCP connects to a sample of subnet IPs.
- **CSP and preconnect headers are gold.** They often enumerate every API host an app uses. So do TLS cert SANs.
- **`Server: PAC Web Server`** — sometimes the simplest header is the most diagnostic.

## Adding support for a new system

1. Connect to the airline WiFi and run `python3 inflightd.py --probe-deep`. Save the output.
2. Look for: a unique DNS search domain, distinctive `Server` header, JS bundles with URL builders (e.g., `makeServiceURL`), CSP-allowed hosts, embedded JSON state.
3. Add a detection branch in `detect_system()` (it's a flat if/elif chain).
4. Add a `<system>_fetch_flight_data()` / `_fetch_connectivity()` pair. If the schema is very different, follow the `flynet_*` pattern — try multiple endpoint paths, then a flexible parser that handles several JSON shapes.
5. Send a PR with a redacted probe output and the live `--report` to confirm.

## Disclaimer

This tool talks to documented and undocumented endpoints exposed by inflight entertainment systems for the purpose of diagnosis. It does not attempt to authenticate, evade billing, alter aircraft systems, or bypass paid tiers. The flight-data endpoints used are publicly accessible from any connected device on the aircraft network — they're the same ones that power the moving-map web app passengers already use.

These endpoints are undocumented and can change at any time. Don't expect this to keep working without updates.

## License

MIT. See `LICENSE`.

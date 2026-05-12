#!/usr/bin/env python3
"""
inflightd - Inflight WiFi Diagnostics TUI

Detects and diagnoses inflight WiFi systems, currently supporting
Panasonic Avionics (PAC/WISP) as used by TAP, KLM, Air France, etc.

Usage:
    python3 inflightd.py              # Launch TUI
    python3 inflightd.py --report     # One-shot diagnostic report (no TUI)
    python3 inflightd.py --json       # JSON output
"""

import argparse
import collections
import curses
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import math
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Provider-specific constants (OUIs, SSIDs, portal domains, etc.) live as
# class attributes on each Provider subclass below. To add a new provider,
# subclass Provider and append to PROVIDERS — no changes here.

LATENCY_GOOD = 100    # ms
LATENCY_WARN = 500    # ms
LATENCY_BAD = 2000    # ms
LOSS_WARN = 5         # %
LOSS_BAD = 20         # %
DNS_WARN = 1000       # ms

HISTORY_MAX = 120     # ring buffer size (~1hr at 30s intervals)

# ANSI codes for --report mode
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"


# ---------------------------------------------------------------------------
# HTTP helper (stdlib, skip TLS verify for onboard certs)
# ---------------------------------------------------------------------------

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def http_get(url: str, timeout: float = 5.0) -> tuple[int, str, float]:
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "inflightd/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, (time.monotonic() - start) * 1000
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, (time.monotonic() - start) * 1000
    except Exception as e:
        return 0, str(e), (time.monotonic() - start) * 1000


def http_get_json(url: str, timeout: float = 5.0) -> tuple[Optional[dict], float]:
    code, body, elapsed = http_get(url, timeout)
    if code == 200 and body:
        try:
            return json.loads(body), elapsed
        except json.JSONDecodeError:
            pass
    return None, elapsed


# ---------------------------------------------------------------------------
# macOS network utilities
# ---------------------------------------------------------------------------

def run_cmd(cmd: str, timeout: float = 10) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, executable="/bin/bash")
        return r.stdout.strip()
    except Exception:
        return ""


_active_iface_cache: Optional[str] = None


def get_active_interface() -> str:
    """Find the interface used by the default route (cached)."""
    global _active_iface_cache
    if _active_iface_cache:
        return _active_iface_cache
    raw = run_cmd("route -n get default")
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            _active_iface_cache = line.split(":", 1)[1].strip()
            return _active_iface_cache
    _active_iface_cache = "en0"
    return _active_iface_cache


def get_wifi_info() -> dict:
    info = {}
    raw = run_cmd("networksetup -getinfo Wi-Fi")
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip().lower().replace(" ", "_")] = v.strip()
    iface = get_active_interface()
    ssid_raw = run_cmd(f"networksetup -getairportnetwork {iface}")
    if ":" in ssid_raw:
        info["ssid"] = ssid_raw.split(":", 1)[1].strip()
    info["interface"] = iface
    return info


def populate_arp_cache(subnet_base: str, port: int = 80, timeout: float = 0.25,
                       sample_size: int = 60) -> int:
    """Trigger ARP resolution for hosts in a /24 subnet via brief TCP connect probes.
    macOS only caches ARP entries for hosts we've directly contacted; this prods the cache.
    Returns number of probes fired."""
    if not subnet_base or subnet_base.count(".") < 2:
        return 0
    parts = subnet_base.split(".")
    if len(parts) < 3:
        return 0
    prefix = ".".join(parts[:3])
    # Sample a spread of host octets, including likely device ranges
    octets = list(range(1, 256))
    if sample_size < len(octets):
        # Even spread
        step = max(1, len(octets) // sample_size)
        octets = octets[::step][:sample_size]

    def probe(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect_ex((ip, port))
            s.close()
        except Exception:
            pass

    threads = []
    for o in octets:
        t = threading.Thread(target=probe, args=(f"{prefix}.{o}",), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=timeout + 0.1)
    return len(octets)


def get_gateway_mac() -> Optional[str]:
    arp_out = run_cmd("arp -an", timeout=15)
    wifi = get_wifi_info()
    gw = wifi.get("router", "")
    if not gw:
        return None
    for line in arp_out.splitlines():
        if gw in line:
            m = re.search(r"([\da-f]{1,2}:[\da-f]{1,2}:[\da-f]{1,2}:[\da-f]{1,2}:[\da-f]{1,2}:[\da-f]{1,2})", line, re.I)
            if m:
                return m.group(1)
    return None


def get_dns_domain() -> Optional[str]:
    raw = run_cmd("scutil --dns")
    for line in raw.splitlines():
        if "search domain" in line.lower():
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[1].strip()
    return None


def get_arp_clients() -> list[dict]:
    """Return ARP entries on the active default-route interface."""
    iface = get_active_interface()
    raw = run_cmd("arp -an", timeout=15)
    clients = []
    iface_re = re.compile(rf"\bon\s+{re.escape(iface)}\b")
    for line in raw.splitlines():
        # Match interface as a whole word ("on en0"), not a substring
        if not iface_re.search(line):
            continue
        m = re.match(r"(\S+)\s+\(([\d.]+)\)\s+at\s+(\S+)", line)
        if not m:
            continue
        mac = m.group(3)
        if mac == "(incomplete)":
            continue
        clients.append({"hostname": m.group(1), "ip": m.group(2), "mac": mac})
    return clients


def check_gateway_https(gateway_ip: str, timeout: float = 4.0) -> bool:
    """Return True if the gateway responds to HTTPS (regardless of status code)."""
    if not gateway_ip:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((gateway_ip, 443))
        sock.close()
        return result == 0
    except Exception:
        return False


def ping_host(host: str, count: int = 3, timeout: int = 2) -> dict:
    raw = run_cmd(f"ping -c {count} -W {timeout * 1000} {host}", timeout=count * timeout + 5)
    result = {"host": host, "sent": count, "received": 0, "loss_pct": 100.0,
              "min_ms": 0, "avg_ms": 0, "max_ms": 0}
    loss_m = re.search(r"(\d+(?:\.\d+)?)% packet loss", raw)
    if loss_m:
        result["loss_pct"] = float(loss_m.group(1))
    recv_m = re.search(r"(\d+) packets received", raw)
    if recv_m:
        result["received"] = int(recv_m.group(1))
    rtt_m = re.search(r"min/avg/max/\S+ = ([\d.]+)/([\d.]+)/([\d.]+)", raw)
    if rtt_m:
        result["min_ms"] = float(rtt_m.group(1))
        result["avg_ms"] = float(rtt_m.group(2))
        result["max_ms"] = float(rtt_m.group(3))
    return result


def measure_dns(domain: str) -> float:
    start = time.monotonic()
    try:
        socket.getaddrinfo(domain, 80, socket.AF_INET)
    except socket.gaierror:
        pass
    return (time.monotonic() - start) * 1000


def measure_throughput(url: str = "https://www.google.com") -> dict:
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "inflightd/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as resp:
            data = resp.read()
            elapsed = time.monotonic() - start
            size = len(data)
            return {"bytes": size, "elapsed_s": round(elapsed, 3),
                    "kbps": round((size * 8) / (elapsed * 1000), 1) if elapsed > 0 else 0, "ok": True}
    except Exception as e:
        return {"bytes": 0, "elapsed_s": 0, "kbps": 0, "ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SystemInfo:
    provider: str = "Unknown"
    hardware: str = "Unknown"
    airline: str = ""
    ssid: str = ""
    portal_url: str = ""
    api_base: str = ""
    proxy: str = ""
    dns_domain: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    local_ip: str = ""
    subnet: str = ""
    pac_wisp_url: str = ""


@dataclass
class FlightData:
    flight_number: str = ""
    departure_iata: str = ""
    departure_icao: str = ""
    destination_iata: str = ""
    destination_icao: str = ""
    aircraft_type: str = ""
    tail_number: str = ""
    ground_speed_kts: int = 0
    altitude_ft: int = 0
    heading_deg: int = 0
    outside_temp_c: int = 0
    latitude: float = 0.0
    longitude: float = 0.0
    departure_lat: float = 0.0
    departure_lon: float = 0.0
    destination_lat: float = 0.0
    destination_lon: float = 0.0
    time_to_dest_min: int = 0
    distance_to_dest_nm: int = 0
    distance_from_origin_nm: float = 0.0
    distance_covered_pct: int = 0
    flight_phase: str = ""
    takeoff_time_utc: str = ""
    estimated_arrival_utc: str = ""
    current_utc_date: str = ""
    flight_state: str = ""
    weight_on_wheels: bool = False
    all_doors_closed: bool = False


@dataclass
class ConnectivityStatus:
    global_conn_enabled: bool = False
    internet_connectivity: bool = False
    time_until_coverage_change: int = 0
    total_coverage_remaining: int = 0


@dataclass
class DeviceState:
    status: str = "UNKNOWN"
    enabled: bool = False


@dataclass
class WISPProduct:
    id: int = 0
    name: str = ""
    description: str = ""
    price_eur: float = 0.0


@dataclass
class CoverageEvent:
    timestamp: float = 0.0
    was_connected: bool = False
    is_connected: bool = False
    duration_s: float = 0.0  # duration of the previous state


@dataclass
class Snapshot:
    """A single point-in-time measurement."""
    timestamp: float = 0.0
    flight: Optional[FlightData] = None
    connectivity: Optional[ConnectivityStatus] = None
    device: Optional[DeviceState] = None
    # Network measurements
    gateway_ping: dict = field(default_factory=dict)
    gateway_https_reachable: bool = False
    icmp_blocked: bool = False  # heuristic: ICMP fails but HTTPS works
    external_ping: dict = field(default_factory=dict)
    dns_resolve_ms: float = 0.0
    dns_external_ms: float = 0.0
    api_latency_ms: float = 0.0
    portal_latency_ms: float = 0.0
    proxy_latency_ms: float = 0.0
    external_latency_ms: float = 0.0
    throughput: dict = field(default_factory=dict)
    client_count: int = 0
    issues: list = field(default_factory=list)
    collect_duration_s: float = 0.0


# ---------------------------------------------------------------------------
# Provider framework
#
# Each inflight WiFi system (Panasonic, FlyNet, …) is a Provider subclass.
# Adding a new system is two steps:
#   1) Subclass Provider, implement detect() + discover_api_base() + fetch_*().
#   2) Append an instance to PROVIDERS below.
# Detection runs each provider against a one-shot NetworkSignals snapshot;
# the highest-confidence Match wins.
# ---------------------------------------------------------------------------

def _detect_captive_portal() -> tuple[str, str, str]:
    """Follow captive portal redirect to discover portal URL and proxy.
    Returns (portal_url, proxy_info, final_url)."""
    portal_url = ""
    proxy_info = ""
    final_url = ""
    for test_url in ["http://captive.apple.com", "http://connectivitycheck.gstatic.com/generate_204"]:
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "inflightd/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                final_url = resp.url
                via = resp.headers.get("Via", "")
                if "squid" in via.lower():
                    proxy_info = f"Squid ({via.split(',')[-1].strip()})"
                location = resp.headers.get("Location", "")
                if location and location != test_url:
                    portal_url = location
        except urllib.error.HTTPError as e:
            # 302/303 redirects to portal
            location = e.headers.get("Location", "") if e.headers else ""
            if location:
                portal_url = location
        except Exception:
            pass
        if portal_url:
            break
    return portal_url, proxy_info, final_url


@dataclass
class NetworkSignals:
    """Network observations gathered once before provider detection.
    Providers read these — they don't re-issue network calls during detect()."""
    ssid: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    gateway_mac_oui: str = ""
    dns_domain: str = ""
    arp_clients: list = field(default_factory=list)
    portal_url: str = ""
    proxy: str = ""
    local_ip: str = ""
    subnet: str = ""

    @classmethod
    def gather(cls) -> "NetworkSignals":
        wifi = get_wifi_info()
        sig = cls(
            ssid=wifi.get("ssid", ""),
            gateway_ip=wifi.get("router", ""),
            local_ip=wifi.get("ip_address", ""),
            subnet=wifi.get("subnet_mask", ""),
            dns_domain=get_dns_domain() or "",
            gateway_mac=get_gateway_mac() or "",
            arp_clients=get_arp_clients(),
        )
        sig.gateway_mac_oui = sig.gateway_mac[:8].lower() if sig.gateway_mac else ""
        sig.portal_url, sig.proxy, _ = _detect_captive_portal()
        return sig


@dataclass
class Match:
    """A provider's claim that this network is theirs."""
    confidence: int = 0
    airline: str = ""
    portal_url: str = ""
    proxy: str = ""
    hardware: str = ""


class Provider:
    """Base class for inflight WiFi providers.

    Subclass this, implement detect() / discover_api_base() / fetch_*(),
    and append an instance to PROVIDERS.

    Confidence convention for detect():
      50–60  strong   (vendor MAC OUI, TLS cert SAN, vendor Server header)
      25–40  medium   (DNS search domain, captive-portal redirect)
       5–20  weak     (ARP hostname, SSID heuristic)
    Multiple signals stack (sum, capped at 100). Floor for a non-Unknown
    match is DETECT_FLOOR; below that the system stays "Unknown"."""

    name: str = "Unknown"
    hardware: str = ""
    discovery_domains: list[str] = []  # used as candidate hosts by --probe / --probe-deep

    def detect(self, sig: NetworkSignals) -> Optional[Match]:
        """Return a Match if this network is yours, else None."""
        return None

    def discover_api_base(self, sig: NetworkSignals) -> Optional[str]:
        """Return the provider's API base URL on this network, or None."""
        return None

    def post_detect(self, info: SystemInfo, sig: NetworkSignals) -> None:
        """Optional: enrich SystemInfo after detection (e.g. provider-specific URLs)."""
        return None

    def fetch_flight(self, api_base: str) -> Optional[FlightData]:
        return None

    def fetch_connectivity(self, api_base: str) -> Optional[ConnectivityStatus]:
        return None

    def fetch_device_state(self, api_base: str) -> Optional[DeviceState]:
        return None

    def fetch_wisp_products(self, api_base: str) -> list[WISPProduct]:
        return []

    def airline_from_flight_number(self, flight_number: str) -> str:
        """Optional: map a flight-number prefix to an airline name."""
        return ""


# ---------------------------------------------------------------------------
# Panasonic Avionics — TAP, KLM, Air France, SWISS (777), …
# ---------------------------------------------------------------------------

class PanasonicProvider(Provider):
    name = "Panasonic Avionics"
    hardware = "Matsushita/Panasonic Avionics"
    api_base = "https://api.airpana.com/inflight/services"
    oui_prefixes = ["00:0d:2e"]  # Matsushita / Panasonic Avionics

    def detect(self, sig: NetworkSignals) -> Optional[Match]:
        confidence = 0
        airline = ""
        portal_url = ""

        if sig.gateway_mac_oui in self.oui_prefixes:
            confidence += 60
        dns = sig.dns_domain.lower()
        if "onboardwifi" in dns:
            confidence += 30
        if "swissconnect" in dns:
            confidence += 30
            airline = "SWISS"
        for c in sig.arp_clients:
            host = c.get("hostname", "").lower()
            if "airpana" in host or "panasonic" in host:
                confidence += 50
            if "flytap" in host:
                confidence += 20
                airline = airline or "TAP Air Portugal"
            elif "klm" in host:
                airline = airline or "KLM"
            elif "airfrance" in host:
                airline = airline or "Air France"
            elif "swiss" in host:
                airline = airline or "SWISS"
            if "onboardwifi" in host:
                portal_url = f"https://{c['hostname']}"

        # Last-resort: hit the gateway and look for "PAC Web Server" header.
        # Only fired if cheap signals didn't already match (saves an HTTP call).
        if confidence == 0 and sig.gateway_ip:
            try:
                _, hdrs, _, _ = _fetch_with_headers(f"https://{sig.gateway_ip}/", timeout=4)
                if "PAC" in hdrs.get("Server", ""):
                    confidence += 50
            except Exception:
                pass

        if confidence == 0:
            return None
        return Match(confidence=min(confidence, 100), airline=airline, portal_url=portal_url)

    def discover_api_base(self, sig: NetworkSignals) -> Optional[str]:
        return self.api_base

    def post_detect(self, info: SystemInfo, sig: NetworkSignals) -> None:
        # Try DNS-search-domain wildcards for a portal URL if not already found
        if not info.portal_url and info.dns_domain:
            for sub in ("portal", "www", "wifi", "captive", "onboard"):
                code, _, _ = http_get(f"https://{sub}.{info.dns_domain}/", timeout=3)
                if code and code not in (0, 404):
                    info.portal_url = f"https://{sub}.{info.dns_domain}"
                    break
        wisp, _ = http_get_json(f"{self.api_base}/exconnect/v1/wisp?lang=en")
        if wisp and "url" in wisp:
            info.pac_wisp_url = wisp["url"]

    def fetch_flight(self, api_base: str) -> Optional[FlightData]:
        data, _ = http_get_json(f"{api_base}/flightdata/v2/flightdata")
        if not data:
            return None
        fd = FlightData()
        fd.flight_number = data.get("flight_number", "")
        fd.departure_iata = data.get("departure_iata", "")
        fd.departure_icao = data.get("departure_icao", "")
        fd.destination_iata = data.get("destination_iata", "")
        fd.destination_icao = data.get("destination_icao", "")
        fd.aircraft_type = data.get("aircraft_type", "")
        fd.tail_number = data.get("tail_number", "")
        fd.ground_speed_kts = data.get("ground_speed_knots", 0) or 0
        fd.altitude_ft = data.get("altitude_feet", 0) or 0
        fd.heading_deg = data.get("true_heading_degree", 0) or 0
        fd.outside_temp_c = data.get("outside_air_temp_celsius", 0) or 0
        coords = data.get("current_coordinates", {})
        fd.latitude = coords.get("latitude", 0.0) or 0.0
        fd.longitude = coords.get("longitude", 0.0) or 0.0
        dep_coords = data.get("departure_coordinates", {})
        fd.departure_lat = dep_coords.get("latitude", 0.0) or 0.0
        fd.departure_lon = dep_coords.get("longitude", 0.0) or 0.0
        dst_coords = data.get("destination_coordinates", {})
        fd.destination_lat = dst_coords.get("latitude", 0.0) or 0.0
        fd.destination_lon = dst_coords.get("longitude", 0.0) or 0.0
        fd.time_to_dest_min = data.get("time_to_destination_minutes", 0) or 0
        fd.distance_to_dest_nm = data.get("distance_to_destination_nautical_miles", 0) or 0
        fd.distance_from_origin_nm = data.get("distance_from_departure_nautical_miles", 0) or 0
        fd.distance_covered_pct = data.get("distance_covered_percentage", 0) or 0
        fd.flight_phase = data.get("flight_phase", "")
        fd.takeoff_time_utc = data.get("takeoff_time_utc", "")
        fd.estimated_arrival_utc = data.get("estimated_arrival_time_utc", "")
        fd.current_utc_date = data.get("current_utc_date", "")
        fd.flight_state = data.get("flight_state", "")
        fd.weight_on_wheels = data.get("weight_on_wheels", False)
        fd.all_doors_closed = data.get("all_doors_closed", False)
        return fd

    def fetch_connectivity(self, api_base: str) -> Optional[ConnectivityStatus]:
        data, _ = http_get_json(f"{api_base}/exconnect/v1/status")
        if not data:
            return None
        cs = ConnectivityStatus()
        cs.global_conn_enabled = data.get("global_conn_enabled", False)
        cs.internet_connectivity = data.get("internet_connectivity_status", False)
        cs.time_until_coverage_change = data.get("time_until_coverage_change", 0) or 0
        cs.total_coverage_remaining = data.get("total_coverage_remaining", 0) or 0
        return cs

    def fetch_device_state(self, api_base: str) -> Optional[DeviceState]:
        data, _ = http_get_json(f"{api_base}/exconnect/v1/device_state")
        if not data:
            return None
        return DeviceState(status=data.get("status", "UNKNOWN"), enabled=data.get("enabled", False))

    def fetch_wisp_products(self, api_base: str) -> list[WISPProduct]:
        data, _ = http_get_json(f"{api_base}/exconnect/v1/wisp_product_info?lang=en")
        if not data or "data" not in data:
            return []
        products = []
        for item in data["data"]:
            p = WISPProduct()
            p.id = item.get("id", 0)
            name = item.get("name", {})
            p.name = name.get("eng", "") if isinstance(name, dict) else str(name)
            desc = item.get("description", {})
            p.description = desc.get("eng", "") if isinstance(desc, dict) else str(desc)
            price = item.get("price", {})
            eur = price.get("eur", {}) if isinstance(price, dict) else {}
            p.price_eur = eur.get("amount", 0) if isinstance(eur, dict) else 0
            products.append(p)
        return products


# ---------------------------------------------------------------------------
# Lufthansa Group FlyNet — SWISS, Lufthansa, Austrian, Eurowings
# (Detection + parser stubs; not yet verified on a live aircraft.)
# ---------------------------------------------------------------------------

class FlynetProvider(Provider):
    name = "Lufthansa Group FlyNet"
    hardware = "Deutsche Telekom / EAN or Inmarsat Ka"
    ssids = ["telekom_flynet", "flynet", "lufthansa flynet", "swiss connect", "swissconnect"]
    discovery_domains = ["lufthansa-flynet.com", "flynet.lufthansa.com",
                         "wlan.onboard.lufthansa.com",
                         "swissconnect.com", "www.swissconnect.com",
                         "portal.swissconnect.com", "api.swissconnect.com"]
    api_base_candidates = [
        "https://www.lufthansa-flynet.com",
        "https://wlan.onboard.lufthansa.com",
        "https://flynet.lufthansa.com",
    ]
    flight_paths = [
        "/api/flightData", "/api/v1/flightData",
        "/api/v1/flight-info", "/api/flight", "/flightInfo",
    ]
    connectivity_paths = ["/api/connectivity", "/api/v1/connectivity",
                          "/api/status", "/api/v1/status", "/api/network"]
    airlines_by_prefix = {
        "LX": "SWISS", "LH": "Lufthansa", "OS": "Austrian Airlines",
        "EW": "Eurowings", "WK": "Edelweiss Air",
    }

    def detect(self, sig: NetworkSignals) -> Optional[Match]:
        confidence = 0
        portal_url = ""
        if sig.ssid.lower().strip() in self.ssids:
            confidence += 50
        dns = sig.dns_domain.lower()
        if any(d in dns for d in ["flynet", "telekom", "lufthansa"]):
            confidence += 40
        if sig.portal_url:
            for d in self.discovery_domains:
                if d in sig.portal_url:
                    confidence += 40
                    portal_url = sig.portal_url
                    break

        if confidence == 0:
            return None
        return Match(confidence=min(confidence, 100), portal_url=portal_url)

    def discover_api_base(self, sig: NetworkSignals) -> Optional[str]:
        for base in self.api_base_candidates:
            for path in ("/api/flightData", "/api/v1/flightData"):
                code, _, _ = http_get(f"{base}{path}", timeout=3)
                if code == 200:
                    return base
        return None

    def post_detect(self, info: SystemInfo, sig: NetworkSignals) -> None:
        # Fall back to any reachable known portal if we still don't have one
        if not info.portal_url:
            for domain in self.discovery_domains:
                code, _, _ = http_get(f"https://{domain}/", timeout=5)
                if code and code != 0:
                    info.portal_url = f"https://{domain}"
                    break

    def fetch_flight(self, api_base: str) -> Optional[FlightData]:
        for path in self.flight_paths:
            data, _ = http_get_json(f"{api_base}{path}")
            if data:
                return self._parse_flight(data)

        # Some FlyNet portals embed flight data in the main page as JSON
        code, body, _ = http_get(api_base, timeout=5)
        if code == 200 and body:
            for m in re.finditer(r'(?:flightData|flightInfo|flight_data)\s*[=:]\s*(\{[^;]{20,2000}\})', body):
                try:
                    data = json.loads(m.group(1))
                    fd = self._parse_flight(data)
                    if fd and fd.flight_number:
                        return fd
                except (json.JSONDecodeError, ValueError):
                    continue
        return None

    def fetch_connectivity(self, api_base: str) -> Optional[ConnectivityStatus]:
        for path in self.connectivity_paths:
            data, _ = http_get_json(f"{api_base}{path}")
            if data:
                cs = ConnectivityStatus()
                cs.internet_connectivity = bool(data.get("connected") or data.get("online")
                                                or data.get("internetAvailable") or True)
                cs.global_conn_enabled = bool(data.get("enabled") or data.get("serviceAvailable")
                                              or True)
                return cs
        # If portal is reachable at all, connectivity is likely up
        code, _, _ = http_get(api_base, timeout=3)
        if code and code < 500:
            cs = ConnectivityStatus()
            cs.internet_connectivity = True
            cs.global_conn_enabled = True
            return cs
        return None

    def airline_from_flight_number(self, flight_number: str) -> str:
        return self.airlines_by_prefix.get(flight_number[:2], "")

    @staticmethod
    def _num(d: dict, *keys) -> float:
        for k in keys:
            v = d.get(k)
            if v is not None:
                try:
                    return float(v)
                except (ValueError, TypeError):
                    continue
        return 0

    def _parse_flight(self, data: dict) -> Optional[FlightData]:
        """Parse FlyNet flight data — handles multiple known JSON shapes."""
        if not data:
            return None
        fd = FlightData()
        fd.flight_number = (data.get("flightNumber") or data.get("flight_number")
                            or data.get("fn") or "")
        fd.departure_iata = (data.get("departureAirportCode") or data.get("departure")
                             or data.get("dep") or data.get("origin", {}).get("code", "") or "")
        fd.destination_iata = (data.get("arrivalAirportCode") or data.get("destination")
                               or data.get("dst") or data.get("destination", {}).get("code", "") or "")
        fd.aircraft_type = data.get("aircraftType") or data.get("aircraft_type") or ""
        fd.tail_number = data.get("tailNumber") or data.get("registration") or ""

        fd.ground_speed_kts = int(self._num(data, "groundSpeed", "ground_speed", "speed") or 0)
        fd.altitude_ft = int(self._num(data, "altitude", "altitudeFeet") or 0)
        fd.heading_deg = int(self._num(data, "heading", "trueHeading") or 0)
        fd.outside_temp_c = int(self._num(data, "outsideTemperature", "oat", "temperature") or 0)

        fd.latitude = self._num(data, "latitude", "lat") or 0.0
        fd.longitude = self._num(data, "longitude", "lng", "lon") or 0.0
        pos = data.get("position") or data.get("currentPosition") or {}
        if isinstance(pos, dict):
            fd.latitude = fd.latitude or self._num(pos, "latitude", "lat") or 0.0
            fd.longitude = fd.longitude or self._num(pos, "longitude", "lng", "lon") or 0.0

        fd.time_to_dest_min = int(self._num(data, "timeToDestination", "remainingTime",
                                           "estimatedTimeRemaining") or 0)
        fd.distance_to_dest_nm = int(self._num(data, "distanceToDestination", "remainingDistance") or 0)
        fd.distance_covered_pct = int(self._num(data, "progress", "percentComplete") or 0)
        fd.estimated_arrival_utc = (data.get("estimatedArrival") or data.get("eta")
                                    or data.get("arrivalTime") or "")

        dep = data.get("departureAirport") or data.get("origin") or {}
        if isinstance(dep, dict):
            fd.departure_lat = self._num(dep, "latitude", "lat") or 0.0
            fd.departure_lon = self._num(dep, "longitude", "lng", "lon") or 0.0
        dst = data.get("arrivalAirport") or data.get("destination") or {}
        if isinstance(dst, dict) and dst.get("latitude") is not None:
            fd.destination_lat = self._num(dst, "latitude", "lat") or 0.0
            fd.destination_lon = self._num(dst, "longitude", "lng", "lon") or 0.0
        return fd


# ---------------------------------------------------------------------------
# Provider registry — append to add a system; order does not matter.
# ---------------------------------------------------------------------------

PROVIDERS: list[Provider] = [
    PanasonicProvider(),
    FlynetProvider(),
]

DETECT_FLOOR = 30   # minimum confidence for a non-Unknown match


def _provider_for(name: str) -> Optional[Provider]:
    return next((p for p in PROVIDERS if p.name == name), None)


def detect_system() -> SystemInfo:
    """Detect which inflight WiFi system this network belongs to."""
    sig = NetworkSignals.gather()
    info = SystemInfo(
        ssid=sig.ssid,
        gateway_ip=sig.gateway_ip,
        gateway_mac=sig.gateway_mac,
        local_ip=sig.local_ip,
        subnet=sig.subnet,
        dns_domain=sig.dns_domain,
        portal_url=sig.portal_url,
        proxy=sig.proxy,
    )

    best_provider: Optional[Provider] = None
    best_match: Optional[Match] = None
    for p in PROVIDERS:
        m = p.detect(sig)
        if m and (best_match is None or m.confidence > best_match.confidence):
            best_provider, best_match = p, m

    if best_provider is None or best_match is None or best_match.confidence < DETECT_FLOOR:
        return info

    info.provider = best_provider.name
    info.hardware = best_match.hardware or best_provider.hardware
    if best_match.airline:
        info.airline = best_match.airline
    if best_match.portal_url:
        info.portal_url = best_match.portal_url
    if best_match.proxy:
        info.proxy = best_match.proxy
    info.api_base = best_provider.discover_api_base(sig) or ""
    best_provider.post_detect(info, sig)
    return info


# ---------------------------------------------------------------------------
# Endpoint probe / discovery (for mapping unknown systems)
# ---------------------------------------------------------------------------

def probe_system(sys_info: SystemInfo) -> list[dict]:
    """Systematically probe for API endpoints on the current network.
    Returns list of {url, status, content_type, body_preview, elapsed_ms}."""
    results = []

    # Determine base URLs to probe
    bases = []
    if sys_info.portal_url:
        bases.append(sys_info.portal_url)
    if sys_info.api_base and sys_info.api_base not in bases:
        bases.append(sys_info.api_base)
    if sys_info.gateway_ip:
        bases.append(f"http://{sys_info.gateway_ip}")
        bases.append(f"https://{sys_info.gateway_ip}")

    # Add provider-declared discovery domains as candidate bases
    for prov in PROVIDERS:
        for domain in prov.discovery_domains:
            bases.append(f"https://{domain}")

    # Common API paths found across inflight wifi systems
    api_paths = [
        "/", "/api", "/api/v1", "/api/v2",
        "/api/flightData", "/api/v1/flightData", "/api/flight",
        "/api/connectivity", "/api/v1/connectivity", "/api/status",
        "/api/v1/status", "/api/network", "/api/v1/network",
        "/api/session", "/api/v1/session", "/api/user",
        "/api/v1/products", "/api/v1/plans",
        "/flightInfo", "/flight", "/status", "/connectivity",
        "/services", "/system", "/portal",
        # Panasonic-specific
        "/inflight/services/flightdata/v2/flightdata",
        "/inflight/services/exconnect/v1/status",
        "/inflight/services/network/v1/ping",
        "/inflight/services/service_discovery/v1/services",
    ]

    seen = set()
    for base in bases:
        base = base.rstrip("/")
        for path in api_paths:
            url = f"{base}{path}"
            if url in seen:
                continue
            seen.add(url)
            code, body, elapsed = http_get(url, timeout=3)
            if code and code not in (0, 404, 403):
                content_type = ""
                is_json = False
                if body:
                    stripped = body.strip()
                    is_json = stripped.startswith("{") or stripped.startswith("[")
                    if is_json:
                        content_type = "json"
                    elif stripped.startswith("<!") or stripped.startswith("<html"):
                        content_type = "html"
                    else:
                        content_type = "text"
                results.append({
                    "url": url,
                    "status": code,
                    "content_type": content_type,
                    "body_preview": body[:500] if body else "",
                    "elapsed_ms": round(elapsed, 1),
                    "is_json": is_json,
                })

    # Also probe for JS files that might contain API endpoint definitions
    for base in bases[:2]:  # Only first two to limit time
        for js_path in ["/app.js", "/main.js", "/bundle.js",
                        "/static/js/main.js", "/assets/index.js",
                        "/engine/portal-engine.min.js"]:
            url = f"{base}{js_path}"
            if url in seen:
                continue
            seen.add(url)
            code, body, elapsed = http_get(url, timeout=5)
            if code == 200 and body and len(body) > 100:
                # Extract API-like URLs from JS
                urls_found = re.findall(
                    r'["\'](/api[^"\'\\s]{3,80})["\']', body)
                urls_found += re.findall(
                    r'["\']((https?://)[^"\'\\s]{10,120})["\']', body)
                if urls_found:
                    results.append({
                        "url": url,
                        "status": code,
                        "content_type": "javascript",
                        "body_preview": f"Found {len(urls_found)} API URLs: " +
                                        ", ".join(sorted(set(
                                            u if isinstance(u, str) else u[0]
                                            for u in urls_found))[:20]),
                        "elapsed_ms": round(elapsed, 1),
                        "is_json": False,
                    })

    return results


# ---------------------------------------------------------------------------
# Deep probe — JS bundle mining, HTML scraping, TLS SAN, port scan, well-knowns
# ---------------------------------------------------------------------------

# API URL pattern: matches strings like "/api/...", "/v1/...", "/services/...",
# "https://...", "wss://..."
_API_URL_RE = re.compile(
    r"""['"`]((?:https?://|wss?://|/(?:api|v\d|services|inflight|graphql|portal|"""
    r"""rest|backend|connect|swissconnect|flynet|onboard|wlan)/)[^'"`\s<>{}]{2,200})['"`]""",
    re.IGNORECASE,
)
# Function-style URL builders e.g. makeServiceURL("/path"), apiBase + "/foo"
_BUILDER_RE = re.compile(
    r"""(makeServiceURL|apiBase|API_BASE|baseUrl|BASE_URL|endpoint)\s*[=:(]"""
    r"""\s*['"`]([^'"`]{2,200})['"`]""",
    re.IGNORECASE,
)
# WebSocket constructors
_WS_RE = re.compile(r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""")
# Generic "Bearer ", "X-Api-Key", "Authorization" hints
_AUTH_RE = re.compile(r"""(Bearer\s|X-Api-Key|Authorization|api[_-]?key)""", re.IGNORECASE)


def _fetch_with_headers(url: str, timeout: float = 5.0):
    """Like http_get but also returns response headers as a dict."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "inflightd/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body, (time.monotonic() - start) * 1000
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers) if e.headers else {}, body, (time.monotonic() - start) * 1000
    except Exception as e:
        return 0, {}, str(e), (time.monotonic() - start) * 1000


def deep_probe_html(base: str) -> dict:
    """Mine an HTML page for everything API-related."""
    out = {
        "base": base,
        "ok": False,
        "headers_of_interest": {},
        "preconnect_hosts": [],
        "preload_assets": [],
        "script_srcs": [],
        "link_srcs": [],
        "iframe_srcs": [],
        "data_attrs": [],
        "meta_hints": [],
        "csp_hosts": [],
        "embedded_json": [],
        "found_urls": set(),
    }
    code, hdrs, body, _ = _fetch_with_headers(base, timeout=8)
    if code == 0 or not body:
        out["error"] = body if isinstance(body, str) else "no response"
        return out
    out["ok"] = True
    out["status"] = code

    # Headers of interest
    for h in ("Server", "X-Powered-By", "Via", "X-Cache", "X-Backend", "X-Aws-Region",
              "Set-Cookie", "Strict-Transport-Security",
              "Content-Security-Policy", "Content-Security-Policy-Report-Only",
              "Access-Control-Allow-Origin", "Access-Control-Allow-Headers",
              "X-Request-Id", "X-Trace-Id"):
        v = hdrs.get(h)
        if v:
            out["headers_of_interest"][h] = v[:300]

    # CSP — often enumerates every allowed API/WS/connect-src host
    csp = hdrs.get("Content-Security-Policy", "") or hdrs.get("Content-Security-Policy-Report-Only", "")
    if csp:
        for tok in re.findall(r"(?:connect-src|script-src|frame-src|default-src|img-src)[^;]*;", csp + ";"):
            for host in re.findall(r"(?:https?://|wss?://)[a-z0-9.\-:_*]+", tok, re.IGNORECASE):
                out["csp_hosts"].append(host)
        out["csp_hosts"] = sorted(set(out["csp_hosts"]))

    # <link rel="preconnect|dns-prefetch|preload"> hints
    for m in re.finditer(
            r"""<link[^>]+rel=['"](preconnect|dns-prefetch|preload)['"][^>]+href=['"]([^'"]+)['"]""",
            body, re.IGNORECASE):
        rel, href = m.group(1).lower(), m.group(2)
        if rel == "preload":
            out["preload_assets"].append(href)
        else:
            out["preconnect_hosts"].append(href)

    # <script src=...>
    for m in re.finditer(r"""<script[^>]+src=['"]([^'"]+)['"]""", body, re.IGNORECASE):
        out["script_srcs"].append(m.group(1))

    # <link href=...>
    for m in re.finditer(r"""<link[^>]+href=['"]([^'"]+\.(?:js|json|css))['"]""", body, re.IGNORECASE):
        out["link_srcs"].append(m.group(1))

    # iframes
    for m in re.finditer(r"""<iframe[^>]+src=['"]([^'"]+)['"]""", body, re.IGNORECASE):
        out["iframe_srcs"].append(m.group(1))

    # data-api-* attributes
    for m in re.finditer(r"""data-(api[a-z\-]*|endpoint|url|graphql)=['"]([^'"]+)['"]""", body, re.IGNORECASE):
        out["data_attrs"].append(f"{m.group(1)}={m.group(2)}")

    # <meta name="..." content="..."> with hints
    for m in re.finditer(r"""<meta[^>]+name=['"]([^'"]+)['"][^>]+content=['"]([^'"]+)['"]""", body, re.IGNORECASE):
        name, content = m.group(1).lower(), m.group(2)
        if any(k in name for k in ("api", "url", "endpoint", "version", "build", "csrf")):
            out["meta_hints"].append(f"{name}={content[:120]}")

    # <script type="application/json"> blobs (Next/Nuxt initial state)
    for m in re.finditer(
            r"""<script[^>]*type=['"]application/(?:json|ld\+json)['"][^>]*>(.*?)</script>""",
            body, re.DOTALL | re.IGNORECASE):
        try:
            blob = json.loads(m.group(1).strip())
            preview = json.dumps(blob)[:500]
            out["embedded_json"].append(preview)
        except (json.JSONDecodeError, ValueError):
            continue

    # Inline JS URL extraction
    for m in _API_URL_RE.finditer(body):
        out["found_urls"].add(m.group(1))
    for m in _BUILDER_RE.finditer(body):
        out["found_urls"].add(m.group(2))
    for m in _WS_RE.finditer(body):
        out["found_urls"].add(m.group(1))

    out["found_urls"] = sorted(out["found_urls"])
    return out


def deep_probe_js(url: str) -> dict:
    """Mine a JS bundle for API URLs, builder functions, and auth hints."""
    out = {"url": url, "ok": False, "size": 0, "found_urls": set(),
           "builders": [], "ws_urls": [], "auth_hints": []}
    code, body, elapsed = http_get(url, timeout=10)
    if code != 200 or not body:
        out["error"] = f"status {code}"
        return out
    out["ok"] = True
    out["size"] = len(body)
    out["elapsed_ms"] = round(elapsed, 1)

    for m in _API_URL_RE.finditer(body):
        out["found_urls"].add(m.group(1))
    for m in _BUILDER_RE.finditer(body):
        out["builders"].append(f"{m.group(1)} -> {m.group(2)}")
    for m in _WS_RE.finditer(body):
        out["ws_urls"].append(m.group(1))
    for m in _AUTH_RE.finditer(body):
        out["auth_hints"].append(m.group(1))

    out["found_urls"] = sorted(out["found_urls"])
    out["auth_hints"] = sorted(set(out["auth_hints"]))
    return out


def deep_probe_tls_san(host: str, port: int = 443) -> dict:
    """Use openssl CLI to extract subjectAltName/CN/issuer from the cert.
    More reliable than ssl.getpeercert() which returns {} when verify is off."""
    out = {"host": host, "port": port, "ok": False, "san": [], "cn": "", "issuer": ""}
    try:
        cmd = (f"echo | openssl s_client -connect {host}:{port} "
               f"-servername {host} -showcerts 2>/dev/null | "
               f"openssl x509 -noout -ext subjectAltName -subject -issuer 2>/dev/null")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                timeout=10, executable="/bin/bash")
        text = result.stdout
        if not text.strip():
            out["error"] = "no cert returned"
            return out
        out["ok"] = True
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("subject="):
                m = re.search(r"CN\s*=\s*([^,/]+)", line)
                if m:
                    out["cn"] = m.group(1).strip()
            elif line.startswith("issuer="):
                m = re.search(r"CN\s*=\s*([^,/]+)", line)
                if m:
                    out["issuer"] = m.group(1).strip()
            elif "DNS:" in line:
                # SAN line looks like:  DNS:foo.com, DNS:bar.com, IP:1.2.3.4
                for tok in line.split(","):
                    tok = tok.strip()
                    if tok.startswith("DNS:"):
                        out["san"].append(tok[4:].strip())
        out["san"] = sorted(set(out["san"]))
    except Exception as e:
        out["error"] = str(e)
    return out


def deep_probe_well_known(base: str) -> list[dict]:
    """Try common well-known paths that often leak useful info."""
    paths = [
        "/robots.txt", "/sitemap.xml", "/humans.txt",
        "/manifest.json", "/asset-manifest.json",
        "/.well-known/openid-configuration",
        "/.well-known/security.txt",
        "/.well-known/host-meta",
        "/.well-known/apple-app-site-association",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
        "/api-docs", "/api-docs.json", "/v3/api-docs",
        "/graphql",  # POST {"query":"{__schema{types{name}}}"} — but a GET often returns useful errors
        "/socket.io/",
        "/sw.js", "/service-worker.js",
        "/version", "/version.json", "/build-info", "/buildInfo",
        "/health", "/healthz", "/_health", "/ping",
        "/portal/api", "/portal/config", "/config.json", "/env.json",
    ]
    hits = []
    for p in paths:
        url = f"{base.rstrip('/')}{p}"
        code, body, elapsed = http_get(url, timeout=3)
        if code and code not in (0, 404, 403):
            preview = (body or "").strip()[:300]
            hits.append({"url": url, "status": code, "size": len(body or ""),
                         "elapsed_ms": round(elapsed, 1), "preview": preview})
    return hits


def deep_probe_ports(host: str) -> list[dict]:
    """Quick TCP scan of common HTTP/API ports on a host."""
    ports = [80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 3001, 5000, 5001, 9000, 9090, 7000]
    hits = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=1.5):
                hits.append({"host": host, "port": p, "open": True})
        except Exception:
            continue
    return hits


def run_deep_probe(sys_info: SystemInfo):
    """Run the deep probe and print findings."""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║  inflightd — Deep Probe                                  ║")
    print(f"╚══════════════════════════════════════════════════════════╝{RESET}")

    print(f"\n{BOLD}System:{RESET}")
    print(f"  Provider:  {sys_info.provider}")
    print(f"  SSID:      {sys_info.ssid}")
    print(f"  Gateway:   {sys_info.gateway_ip} ({sys_info.gateway_mac})")
    print(f"  DNS:       {sys_info.dns_domain}")
    print(f"  Portal:    {sys_info.portal_url}")

    # Build target list — include known FlyNet/SWISS portals + detected portal + gateway
    targets = []
    if sys_info.portal_url:
        targets.append(sys_info.portal_url)
    if sys_info.gateway_ip:
        targets.append(f"http://{sys_info.gateway_ip}")
        targets.append(f"https://{sys_info.gateway_ip}")
    # The DNS search domain is the airline's onboard zone — try common subdomains
    if sys_info.dns_domain:
        for sub in ("portal", "www", "api", "wifi", "captive", "onboard", "connect"):
            targets.append(f"https://{sub}.{sys_info.dns_domain}")
        targets.append(f"https://{sys_info.dns_domain}")
    for prov in PROVIDERS:
        for d in prov.discovery_domains:
            targets.append(f"https://{d}")
    # Dedup preserving order
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]

    # ---- Stage 1: HTML scrape each target ----
    print(f"\n{BOLD}── 1. HTML scrape ─────────────────────────────────────────{RESET}")
    all_js_urls: set[str] = set()
    all_hosts: set[str] = set()
    all_found_urls: set[str] = set()
    for base in targets:
        print(f"\n  {CYAN}Target: {base}{RESET}")
        result = deep_probe_html(base)
        if not result["ok"]:
            print(f"    {DIM}error: {result.get('error', '?')}{RESET}")
            continue
        print(f"    {GREEN}HTTP {result.get('status', '?')}{RESET}")

        if result["headers_of_interest"]:
            print(f"    {BOLD}Headers:{RESET}")
            for k, v in result["headers_of_interest"].items():
                print(f"      {DIM}{k}:{RESET} {v[:200]}")
        if result["csp_hosts"]:
            print(f"    {BOLD}{GREEN}CSP-allowed hosts:{RESET}")
            for h in result["csp_hosts"][:30]:
                print(f"      {h}")
                all_hosts.add(h)
        if result["preconnect_hosts"]:
            print(f"    {BOLD}{GREEN}preconnect/dns-prefetch:{RESET}")
            for h in result["preconnect_hosts"]:
                print(f"      {h}")
                all_hosts.add(h)
        if result["meta_hints"]:
            print(f"    {BOLD}Meta hints:{RESET}")
            for m in result["meta_hints"]:
                print(f"      {m}")
        if result["data_attrs"]:
            print(f"    {BOLD}data-* attrs:{RESET}")
            for d in result["data_attrs"][:20]:
                print(f"      {d}")
        if result["embedded_json"]:
            print(f"    {BOLD}{GREEN}Embedded JSON ({len(result['embedded_json'])}):{RESET}")
            for j in result["embedded_json"][:3]:
                print(f"      {j[:280]}")
        if result["iframe_srcs"]:
            print(f"    {BOLD}iframes:{RESET}")
            for s in result["iframe_srcs"]:
                print(f"      {s}")
        if result["found_urls"]:
            print(f"    {BOLD}Inline URLs ({len(result['found_urls'])}):{RESET}")
            for u in result["found_urls"][:25]:
                print(f"      {u}")
                all_found_urls.add(u)

        # Collect JS sources for stage 2
        for src in result["script_srcs"]:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(base)
                src = f"{parsed.scheme}://{parsed.netloc}{src}"
            if src.startswith(("http://", "https://")):
                all_js_urls.add(src)

    # ---- Stage 2: Mine JS bundles ----
    print(f"\n{BOLD}── 2. JS bundle mining ────────────────────────────────────{RESET}")
    if not all_js_urls:
        print(f"  {DIM}No JS bundles discovered in stage 1.{RESET}")
    for url in sorted(all_js_urls)[:15]:
        print(f"\n  {CYAN}JS: {url}{RESET}")
        result = deep_probe_js(url)
        if not result["ok"]:
            print(f"    {DIM}error: {result.get('error', '?')}{RESET}")
            continue
        print(f"    {DIM}{result['size']:,} bytes in {result['elapsed_ms']}ms{RESET}")
        if result["builders"]:
            print(f"    {BOLD}{GREEN}URL builders:{RESET}")
            for b in result["builders"][:15]:
                print(f"      {b}")
        if result["ws_urls"]:
            print(f"    {BOLD}{GREEN}WebSocket URLs:{RESET}")
            for w in result["ws_urls"]:
                print(f"      {w}")
        if result["auth_hints"]:
            print(f"    {BOLD}Auth hints:{RESET} {', '.join(result['auth_hints'])}")
        if result["found_urls"]:
            print(f"    {BOLD}{GREEN}Found URLs ({len(result['found_urls'])}):{RESET}")
            for u in result["found_urls"][:25]:
                print(f"      {u}")
                all_found_urls.add(u)

    # ---- Stage 3: TLS cert SAN ----
    print(f"\n{BOLD}── 3. TLS cert SAN scan ───────────────────────────────────{RESET}")
    san_targets = set()
    if sys_info.gateway_ip:
        san_targets.add(sys_info.gateway_ip)
    for base in targets:
        if base.startswith("https://"):
            from urllib.parse import urlparse
            host = urlparse(base).hostname
            if host:
                san_targets.add(host)
    for host in sorted(san_targets):
        result = deep_probe_tls_san(host)
        if not result["ok"]:
            print(f"  {DIM}{host}: {result.get('error', 'no cert')}{RESET}")
            continue
        print(f"  {CYAN}{host}{RESET} — CN={result['cn']}  Issuer={result['issuer']}")
        if result["san"]:
            print(f"    {BOLD}{GREEN}SAN ({len(result['san'])}):{RESET}")
            for s in result["san"][:30]:
                print(f"      {s}")
                # SAN entries can be hostnames or IPs
                if "." in s and not s.startswith(("http://", "https://")):
                    all_hosts.add(f"https://{s}")

    # ---- Stage 4: Well-known paths ----
    print(f"\n{BOLD}── 4. Well-known files ────────────────────────────────────{RESET}")
    for base in targets[:5]:
        hits = deep_probe_well_known(base)
        if not hits:
            continue
        print(f"\n  {CYAN}{base}{RESET}")
        for h in hits:
            print(f"    {GREEN}[{h['status']}]{RESET} {h['url']}  ({h['size']}B, {h['elapsed_ms']}ms)")
            if h["preview"]:
                first = h["preview"].split("\n")[0][:200]
                print(f"      {DIM}{first}{RESET}")

    # ---- Stage 5: Port scan gateway ----
    print(f"\n{BOLD}── 5. Port scan ───────────────────────────────────────────{RESET}")
    scan_hosts = set()
    if sys_info.gateway_ip:
        scan_hosts.add(sys_info.gateway_ip)
    for base in targets:
        if base.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            host = urlparse(base).hostname
            if host and not host.startswith(("flynet", "lufthansa", "swiss", "wlan")):
                # Only scan IPs / on-network hosts, not the public domains
                pass
            if host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                scan_hosts.add(host)
    for host in sorted(scan_hosts):
        hits = deep_probe_ports(host)
        if hits:
            print(f"  {CYAN}{host}{RESET}: {', '.join(str(h['port']) for h in hits)}")
        else:
            print(f"  {DIM}{host}: no common ports open{RESET}")

    # ---- Summary ----
    print(f"\n{BOLD}{CYAN}── SUMMARY ────────────────────────────────────────────────{RESET}")
    print(f"  {BOLD}Distinct API/host candidates discovered:{RESET}")
    all_candidates = sorted(all_hosts | {u for u in all_found_urls if u.startswith(("http", "ws"))})
    if all_candidates:
        for c in all_candidates[:50]:
            print(f"    {c}")
    else:
        print(f"    {DIM}(none){RESET}")

    # Path candidates (relative URLs)
    rel_paths = sorted(u for u in all_found_urls if u.startswith("/"))
    if rel_paths:
        print(f"\n  {BOLD}Relative API paths discovered:{RESET}")
        for p in rel_paths[:50]:
            print(f"    {p}")

    print(f"\n  {DIM}Tip: rerun with --probe to test these paths against the live network.{RESET}")
    print(f"  {DIM}Or paste interesting URLs back so we can hand-craft a fetcher.{RESET}\n")


def run_probe(sys_info: SystemInfo):
    """Run endpoint discovery and print results."""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║  inflightd — Endpoint Discovery                          ║")
    print(f"╚══════════════════════════════════════════════════════════╝{RESET}")

    print(f"\n{BOLD}System:{RESET}")
    print(f"  Provider:  {sys_info.provider}")
    print(f"  SSID:      {sys_info.ssid}")
    print(f"  Gateway:   {sys_info.gateway_ip} ({sys_info.gateway_mac})")
    print(f"  DNS:       {sys_info.dns_domain}")
    print(f"  Portal:    {sys_info.portal_url}")
    print(f"  API Base:  {sys_info.api_base}")
    print(f"  Proxy:     {sys_info.proxy}")

    print(f"\n{BOLD}Probing endpoints...{RESET}\n")
    results = probe_system(sys_info)

    json_hits = [r for r in results if r["is_json"]]
    html_hits = [r for r in results if r["content_type"] == "html"]
    js_hits = [r for r in results if r["content_type"] == "javascript"]
    other_hits = [r for r in results if r not in json_hits + html_hits + js_hits]

    if json_hits:
        print(f"{GREEN}{BOLD}JSON API Endpoints ({len(json_hits)}):{RESET}")
        for r in json_hits:
            print(f"  {GREEN}[{r['status']}]{RESET} {r['url']}  ({r['elapsed_ms']}ms)")
            preview = r["body_preview"][:200]
            # Pretty-print JSON preview
            try:
                parsed = json.loads(r["body_preview"])
                preview = json.dumps(parsed, indent=2)[:200]
            except (json.JSONDecodeError, ValueError):
                pass
            for line in preview.split("\n")[:8]:
                print(f"    {DIM}{line}{RESET}")
            print()

    if js_hits:
        print(f"{YELLOW}{BOLD}JavaScript with API URLs ({len(js_hits)}):{RESET}")
        for r in js_hits:
            print(f"  {YELLOW}[{r['status']}]{RESET} {r['url']}")
            print(f"    {DIM}{r['body_preview'][:200]}{RESET}")
            print()

    if html_hits:
        print(f"{CYAN}HTML Endpoints ({len(html_hits)}):{RESET}")
        for r in html_hits:
            title = ""
            m = re.search(r'<title>([^<]{1,80})</title>', r["body_preview"], re.I)
            if m:
                title = f' — "{m.group(1)}"'
            print(f"  [{r['status']}] {r['url']}{title}  ({r['elapsed_ms']}ms)")

    if other_hits:
        print(f"\n{DIM}Other Responses ({len(other_hits)}):{RESET}")
        for r in other_hits:
            print(f"  [{r['status']}] {r['url']}  ({r['elapsed_ms']}ms)")
            if r["body_preview"]:
                print(f"    {DIM}{r['body_preview'][:100]}{RESET}")

    total = len(results)
    if total == 0:
        print(f"{RED}No endpoints responded. Network may not be active.{RESET}")
    else:
        print(f"\n{BOLD}Summary:{RESET} {len(json_hits)} JSON APIs, {len(html_hits)} HTML, "
              f"{len(js_hits)} JS sources, {len(other_hits)} other ({total} total)")

    # Save results
    fname = f"probe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    fpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
    with open(fpath, "w") as f:
        json.dump({"system": asdict(sys_info), "results": results}, f, indent=2)
    print(f"\n{GREEN}Results saved to {fname}{RESET}\n")


# ---------------------------------------------------------------------------
# Issue detection
# ---------------------------------------------------------------------------

def detect_issues(snap: Snapshot, sys_info: SystemInfo) -> list[dict]:
    issues = []
    gw = snap.gateway_ping
    # Don't flag the gateway as unreachable based on ICMP alone — many onboard
    # APs block ICMP but pass TCP fine. Trust the HTTPS reachability check.
    if gw and gw.get("loss_pct", 100) > LOSS_BAD and not snap.gateway_https_reachable:
        issues.append({"severity": "critical", "component": "gateway",
                       "message": f"Gateway unreachable (ICMP {gw['loss_pct']:.0f}% loss, HTTPS down)",
                       "detail": "Onboard AP not responding on either ICMP or HTTPS. Hardware issue or system restart."})
    elif gw and gw.get("loss_pct", 0) > LOSS_WARN and not snap.icmp_blocked:
        issues.append({"severity": "warning", "component": "gateway",
                       "message": f"High gateway packet loss ({gw['loss_pct']:.0f}%)",
                       "detail": "Local WiFi congestion or interference."})
    if gw and gw.get("avg_ms", 0) > LATENCY_WARN:
        issues.append({"severity": "warning", "component": "gateway",
                       "message": f"High gateway latency ({gw['avg_ms']:.0f}ms)",
                       "detail": "Onboard router overloaded."})
    # Surface the ICMP-blocked state as informational so the user understands the loss numbers
    if snap.icmp_blocked:
        issues.append({"severity": "info", "component": "network",
                       "message": "ICMP blocked by onboard network",
                       "detail": "Gateway/external 'packet loss' figures reflect blocked pings, "
                                 "not actual reachability. TCP/HTTPS paths are working."})
    if snap.dns_resolve_ms > DNS_WARN:
        issues.append({"severity": "warning", "component": "dns",
                       "message": f"Slow DNS ({snap.dns_resolve_ms:.0f}ms)",
                       "detail": "Onboard DNS server may be overloaded."})
    if snap.external_latency_ms > LATENCY_BAD:
        issues.append({"severity": "warning", "component": "satellite",
                       "message": f"High external latency ({snap.external_latency_ms:.0f}ms)",
                       "detail": "Satellite uplink slow. Possible handoff or congestion."})
    tp = snap.throughput
    if tp.get("ok") and tp.get("kbps", 0) < 100:
        issues.append({"severity": "warning", "component": "throughput",
                       "message": f"Very low throughput ({tp['kbps']:.0f} kbps)",
                       "detail": "Satellite link congested or in handoff."})
    if snap.connectivity and not snap.connectivity.internet_connectivity:
        issues.append({"severity": "critical", "component": "satellite",
                       "message": "Internet connectivity DOWN",
                       "detail": "Satellite link reports no internet. Coverage gap or system issue."})
    if snap.connectivity and not snap.connectivity.global_conn_enabled:
        issues.append({"severity": "critical", "component": "system",
                       "message": "Global connectivity DISABLED",
                       "detail": "The aircraft WiFi system has disabled internet globally."})
    if snap.client_count > 50:
        issues.append({"severity": "info", "component": "network",
                       "message": f"{snap.client_count} devices on network",
                       "detail": "High device count may cause congestion."})
    return issues


# ---------------------------------------------------------------------------
# DataCollector — ring buffer + satellite coverage tracker
# ---------------------------------------------------------------------------

class DataCollector:
    def __init__(self, sys_info: SystemInfo):
        self.sys_info = sys_info
        self.provider: Optional[Provider] = _provider_for(sys_info.provider)
        self.history: collections.deque[Snapshot] = collections.deque(maxlen=HISTORY_MAX)
        self.products: list[WISPProduct] = []
        self.coverage_events: list[CoverageEvent] = []
        self._last_conn_state: Optional[bool] = None
        self._last_conn_time: float = 0.0
        self._products_fetched = False
        self._arp_populated = False
        self.collecting = False
        self.last_error: str = ""

    @property
    def latest(self) -> Optional[Snapshot]:
        return self.history[-1] if self.history else None

    def collect(self) -> Snapshot:
        """Run one full collection cycle."""
        self.collecting = True
        self.last_error = ""
        t0 = time.monotonic()
        snap = Snapshot(timestamp=time.time())
        api = self.sys_info.api_base

        try:
            # Fast API calls — dispatch through the matched provider
            if self.provider and api:
                snap.flight = self.provider.fetch_flight(api)
                snap.connectivity = self.provider.fetch_connectivity(api)
                snap.device = self.provider.fetch_device_state(api)

            # Detect airline from flight number if not already set
            if (snap.flight and snap.flight.flight_number
                    and not self.sys_info.airline and self.provider):
                al = self.provider.airline_from_flight_number(snap.flight.flight_number)
                if al:
                    self.sys_info.airline = al

            # Track satellite coverage state transitions
            if snap.connectivity:
                self._track_coverage(snap.connectivity, snap.timestamp)

            # Fetch products once (providers return [] if they don't expose this)
            if not self._products_fetched and self.provider and api:
                self.products = self.provider.fetch_wisp_products(api)
                self._products_fetched = True

            # Network measurements
            # Populate ARP cache once via TCP probes — ARP only caches hosts we've
            # contacted, so on captive networks `arp -a` is empty without this.
            if self.sys_info.gateway_ip and not self._arp_populated:
                populate_arp_cache(self.sys_info.gateway_ip)
                self._arp_populated = True

            clients = get_arp_clients()
            snap.client_count = len(clients)

            if self.sys_info.gateway_ip:
                snap.gateway_ping = ping_host(self.sys_info.gateway_ip, count=3, timeout=2)
                snap.gateway_https_reachable = check_gateway_https(self.sys_info.gateway_ip)

            snap.dns_resolve_ms = measure_dns("google.com")
            snap.dns_external_ms = measure_dns("cloudflare.com")

            _, _, snap.api_latency_ms = http_get(
                f"{api}/network/v1/ping?t={int(time.time())}", timeout=5)

            if self.sys_info.portal_url:
                _, _, snap.portal_latency_ms = http_get(self.sys_info.portal_url, timeout=5)

            _, _, snap.proxy_latency_ms = http_get("http://captive.apple.com", timeout=10)
            _, _, snap.external_latency_ms = http_get("https://www.google.com/generate_204", timeout=10)

            snap.throughput = measure_throughput("https://www.google.com")

            snap.external_ping = ping_host("8.8.8.8", count=3, timeout=2)

            # Heuristic: ICMP is blocked if both gateway and 8.8.8.8 ICMP fail
            # but at least one HTTPS path works.
            gw_icmp_lost = snap.gateway_ping.get("loss_pct", 100) >= 99
            ext_icmp_lost = snap.external_ping.get("loss_pct", 100) >= 99
            https_works = (snap.gateway_https_reachable
                           or snap.api_latency_ms > 0
                           or snap.external_latency_ms > 0
                           or (snap.throughput.get("ok") and snap.throughput.get("kbps", 0) > 0))
            snap.icmp_blocked = (gw_icmp_lost and ext_icmp_lost and https_works)

        except Exception as e:
            self.last_error = str(e)

        snap.issues = detect_issues(snap, self.sys_info)
        snap.collect_duration_s = time.monotonic() - t0
        self.history.append(snap)
        self.collecting = False
        return snap

    def _track_coverage(self, cs: ConnectivityStatus, ts: float):
        """Detect satellite coverage state transitions."""
        current = cs.internet_connectivity
        if self._last_conn_state is not None and current != self._last_conn_state:
            duration = ts - self._last_conn_time if self._last_conn_time else 0
            self.coverage_events.append(CoverageEvent(
                timestamp=ts,
                was_connected=self._last_conn_state,
                is_connected=current,
                duration_s=duration,
            ))
        if self._last_conn_state is None or current != self._last_conn_state:
            self._last_conn_time = ts
        self._last_conn_state = current

    def trend_values(self, attr: str, count: int = 60) -> list[float]:
        """Get last N values of a numeric attribute from history."""
        items = list(self.history)[-count:]
        vals = []
        for snap in items:
            v = getattr(snap, attr, None)
            if v is not None:
                vals.append(float(v))
            elif attr in ("gateway_avg_ms",):
                gw = snap.gateway_ping
                vals.append(gw.get("avg_ms", 0) if gw else 0)
            elif attr == "throughput_kbps":
                tp = snap.throughput
                vals.append(tp.get("kbps", 0) if tp else 0)
            elif attr == "loss_pct":
                gw = snap.gateway_ping
                vals.append(gw.get("loss_pct", 0) if gw else 0)
            else:
                vals.append(0)
        return vals

    def save_history(self, path: str):
        """Dump history to JSON."""
        data = []
        for snap in self.history:
            entry = {
                "timestamp": snap.timestamp,
                "flight": asdict(snap.flight) if snap.flight else None,
                "connectivity": asdict(snap.connectivity) if snap.connectivity else None,
                "device": asdict(snap.device) if snap.device else None,
                "gateway_ping": snap.gateway_ping,
                "external_ping": snap.external_ping,
                "dns_resolve_ms": snap.dns_resolve_ms,
                "api_latency_ms": snap.api_latency_ms,
                "external_latency_ms": snap.external_latency_ms,
                "proxy_latency_ms": snap.proxy_latency_ms,
                "throughput": snap.throughput,
                "client_count": snap.client_count,
                "issues": snap.issues,
            }
            data.append(entry)
        with open(path, "w") as f:
            json.dump({"snapshots": data, "coverage_events": [asdict(e) for e in self.coverage_events],
                        "system": asdict(self.sys_info)}, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Curses TUI
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ASCII map rendering
# ---------------------------------------------------------------------------

# Simplified coastline polylines: list of (lat, lon) segments.
# Just enough to be recognizable at terminal resolution.
COASTLINES = [
    # North America - west coast
    [(60,-140),(55,-133),(50,-128),(48,-124),(44,-124),(40,-124),
     (37,-122),(34,-120),(32,-117),(28,-114),(23,-110)],
    # North America - gulf + east coast
    [(23,-110),(20,-105),(18,-96),(18,-88),(20,-87),(22,-90),
     (25,-90),(29,-89),(30,-86),(30,-84),(27,-82),(25,-80),
     (27,-80),(30,-81),(35,-76),(39,-74),(41,-72),(43,-70),
     (45,-67),(47,-60),(50,-56),(53,-60),(55,-60),(60,-64)],
    # Canada north (rough)
    [(60,-140),(60,-130),(58,-110),(55,-95),(52,-82),(50,-80),
     (52,-79),(55,-77),(58,-70),(60,-64)],
    # Hudson Bay
    [(60,-95),(58,-89),(55,-83),(53,-80),(52,-82)],
    # Greenland
    [(84,-28),(82,-20),(78,-18),(75,-20),(72,-24),(68,-30),
     (64,-44),(67,-52),(70,-55),(75,-58),(78,-68),(82,-55),(84,-28)],
    # Iceland
    [(66,-24),(66,-14),(64,-13),(63,-19),(64,-23),(66,-24)],
    # British Isles
    [(59,-5),(58,-3),(55,-1),(53,0),(51,1),(50,-5),
     (51,-3),(52,-5),(54,-5),(56,-6),(58,-5),(59,-5)],
    # Ireland
    [(55,-6),(54,-10),(52,-10),(51,-9),(52,-7),(53,-6),(55,-6)],
    # Iberian Peninsula
    [(44,-9),(44,-1),(42,3),(40,0),(37,-1),(36,-6),
     (37,-9),(40,-9),(42,-9),(44,-9)],
    # France
    [(51,2),(49,0),(48,-5),(47,-2),(44,-1),(43,3),
     (43,7),(46,6),(48,8),(51,4),(51,2)],
    # Italy
    [(46,7),(46,13),(44,12),(42,12),(40,16),(38,16),
     (37,15),(38,13),(41,9),(44,8),(46,7)],
    # Scandinavia
    [(58,6),(60,5),(63,5),(66,14),(69,16),(71,26),
     (70,30),(66,14),(62,12),(60,11),(57,12),(56,8),(58,6)],
    # NW Africa coast
    [(36,-6),(36,-1),(34,0),(33,-2),(31,-5),(28,-13),
     (24,-16),(20,-17),(15,-17),(12,-16),(8,-13),
     (5,-5),(5,1),(5,10)],
    # Africa east + south
    [(5,10),(10,42),(12,44),(5,42),(0,42),(-5,40),
     (-12,44),(-16,40),(-26,33),(-34,26),(-35,19)],
    # Africa west coast (south)
    [(5,10),(3,10),(0,10),(-5,12),(-10,14),(-17,12),
     (-22,14),(-30,17),(-35,19)],
    # South America
    [(12,-70),(10,-76),(5,-77),(0,-80),(-5,-81),(-15,-75),
     (-24,-70),(-33,-72),(-42,-65),(-46,-68),(-55,-68),
     (-56,-66),(-52,-70),(-48,-66),(-42,-63),(-35,-57),
     (-32,-52),(-25,-48),(-23,-43),(-13,-39),(-8,-35),
     (-3,-42),(0,-50),(5,-53),(8,-60),(10,-62),(12,-70)],
    # Central America
    [(23,-110),(20,-105),(15,-92),(12,-84),(9,-78),(12,-70)],
    # Arabia
    [(30,34),(28,35),(22,36),(13,43),(12,44),(15,52),
     (25,56),(28,49),(30,34)],
    # India
    [(28,68),(24,69),(20,73),(15,74),(8,77),(12,80),
     (18,82),(22,89),(28,89),(28,68)],
    # SE Asia (rough)
    [(22,100),(18,98),(10,99),(1,104),(6,108),(10,106),
     (18,107),(22,107),(25,100),(22,100)],
    # China / East Asia coast
    [(55,135),(50,132),(45,132),(42,132),(40,122),(35,120),
     (30,121),(25,112),(22,107),(22,100),(25,100),(28,98),
     (32,105),(35,115),(38,118),(40,120),(42,132)],
    # Japan
    [(45,142),(43,145),(40,140),(35,136),(33,131),
     (34,133),(38,137),(40,140),(45,142)],
    # Australia
    [(-12,131),(-17,128),(-22,114),(-32,115),(-35,117),
     (-37,140),(-38,146),(-34,151),(-28,153),(-20,149),
     (-15,145),(-12,136),(-12,131)],
    # New Zealand
    [(-36,174),(-39,176),(-47,167),(-45,167),(-42,172),(-36,174)],
]


def great_circle_point(lat1: float, lon1: float,
                       lat2: float, lon2: float, f: float) -> tuple[float, float]:
    """Interpolate along a great circle. f=0 -> point1, f=1 -> point2."""
    lat1, lon1, lat2, lon2 = (math.radians(v) for v in (lat1, lon1, lat2, lon2))
    d = math.acos(max(-1.0, min(1.0,
        math.sin(lat1) * math.sin(lat2) +
        math.cos(lat1) * math.cos(lat2) * math.cos(lon2 - lon1))))
    if d < 1e-6:
        return math.degrees(lat1), math.degrees(lon1)
    a = math.sin((1 - f) * d) / math.sin(d)
    b = math.sin(f * d) / math.sin(d)
    x = a * math.cos(lat1) * math.cos(lon1) + b * math.cos(lat2) * math.cos(lon2)
    y = a * math.cos(lat1) * math.sin(lon1) + b * math.cos(lat2) * math.sin(lon2)
    z = a * math.sin(lat1) + b * math.sin(lat2)
    return math.degrees(math.atan2(z, math.sqrt(x * x + y * y))), \
           math.degrees(math.atan2(y, x))


def render_map(map_h: int, map_w: int,
               cur_lat: float, cur_lon: float,
               dep_lat: float, dep_lon: float,
               dst_lat: float, dst_lon: float) -> list[list[tuple[str, str]]]:
    """Render ASCII map. Returns grid[row][col] = (char, kind).
    kind is one of: 'water', 'land', 'path', 'plane', 'dep', 'dst'."""

    # Compute viewport to fit departure, destination, and current position
    all_lats = [cur_lat, dep_lat, dst_lat]
    all_lons = [cur_lon, dep_lon, dst_lon]
    pad_lat = max(8, (max(all_lats) - min(all_lats)) * 0.25)
    pad_lon = max(12, (max(all_lons) - min(all_lons)) * 0.15)
    lat_min = min(all_lats) - pad_lat
    lat_max = max(all_lats) + pad_lat
    lon_min = min(all_lons) - pad_lon
    lon_max = max(all_lons) + pad_lon

    # Adjust aspect ratio: terminal chars are ~2x tall as wide,
    # so lon span should be ~2x lat span * (map_w/map_h)
    lat_span = lat_max - lat_min
    lon_span = lon_max - lon_min
    target_lon = lat_span * (map_w / map_h) * 0.5
    if lon_span < target_lon:
        mid = (lon_min + lon_max) / 2
        lon_min, lon_max = mid - target_lon / 2, mid + target_lon / 2
    else:
        target_lat = lon_span / ((map_w / map_h) * 0.5)
        if lat_span < target_lat:
            mid = (lat_min + lat_max) / 2
            lat_min, lat_max = mid - target_lat / 2, mid + target_lat / 2

    lat_min, lat_max = max(-80, lat_min), min(85, lat_max)
    lon_min, lon_max = max(-180, lon_min), min(180, lon_max)
    lat_span = lat_max - lat_min or 1
    lon_span = lon_max - lon_min or 1

    grid = [[(' ', 'water')] * map_w for _ in range(map_h)]

    def to_rc(lat, lon):
        r = int((lat_max - lat) / lat_span * (map_h - 1))
        c = int((lon - lon_min) / lon_span * (map_w - 1))
        return max(0, min(map_h - 1, r)), max(0, min(map_w - 1, c))

    # Draw coastlines
    for seg in COASTLINES:
        for i in range(len(seg) - 1):
            r1, c1 = to_rc(seg[i][0], seg[i][1])
            r2, c2 = to_rc(seg[i + 1][0], seg[i + 1][1])
            steps = max(abs(r2 - r1), abs(c2 - c1)) or 1
            for s in range(steps + 1):
                r = round(r1 + (r2 - r1) * s / steps)
                c = round(c1 + (c2 - c1) * s / steps)
                if 0 <= r < map_h and 0 <= c < map_w:
                    grid[r][c] = ('.', 'land')

    # Draw great-circle flight path
    path_steps = map_w * 3
    for s in range(path_steps + 1):
        lat, lon = great_circle_point(dep_lat, dep_lon, dst_lat, dst_lon, s / path_steps)
        r, c = to_rc(lat, lon)
        if grid[r][c][1] == 'water':
            grid[r][c] = ('-', 'path')

    # Markers (drawn last so they overwrite)
    dr, dc = to_rc(dep_lat, dep_lon)
    grid[dr][dc] = ('o', 'dep')
    ar, ac = to_rc(dst_lat, dst_lon)
    grid[ar][ac] = ('o', 'dst')
    pr, pc = to_rc(cur_lat, cur_lon)
    grid[pr][pc] = ('*', 'plane')

    return grid


def sparkline(vals: list[float], width: int = 0) -> str:
    if not vals:
        return ""
    w = width or len(vals)
    # Resample to width if needed
    if len(vals) > w:
        step = len(vals) / w
        vals = [vals[int(i * step)] for i in range(w)]
    blocks = " ▁▂▃▄▅▆▇█"
    if not vals or all(v == 0 for v in vals):
        return "─" * len(vals)
    mn, mx = min(vals), max(vals)
    rng = mx - mn if mx > mn else 1
    return "".join(blocks[min(8, int((v - mn) / rng * 8))] for v in vals)


def bar_chart(pct: int, width: int = 30) -> str:
    filled = int(width * max(0, min(100, pct)) / 100)
    return "█" * filled + "░" * (width - filled)


class TUI:
    VIEWS = ["overview", "network", "flight", "trends", "plans", "issues"]
    VIEW_KEYS = {"o": "overview", "n": "network", "f": "flight", "t": "trends",
                 "p": "plans", "i": "issues"}

    def __init__(self, stdscr, collector: DataCollector, interval: int = 30):
        self.scr = stdscr
        self.collector = collector
        self.interval = interval
        self.view = "overview"
        self.show_help = False
        self.running = True
        self.status_msg = ""
        self.status_time = 0.0
        self._collect_thread: Optional[threading.Thread] = None
        self._scroll_offset = 0

        curses.curs_set(0)
        curses.use_default_colors()
        self._init_colors()
        self.scr.nodelay(True)
        self.scr.timeout(500)  # 500ms getch timeout

    def _init_colors(self):
        curses.init_pair(1, curses.COLOR_CYAN, -1)     # headers
        curses.init_pair(2, curses.COLOR_GREEN, -1)     # good
        curses.init_pair(3, curses.COLOR_YELLOW, -1)    # warning
        curses.init_pair(4, curses.COLOR_RED, -1)       # bad/critical
        curses.init_pair(5, -1, -1)                      # bar (used with A_REVERSE)
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_GREEN)  # good badge
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_YELLOW) # warn badge
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_RED)    # crit badge
        curses.init_pair(9, curses.COLOR_MAGENTA, -1)   # dim/accent
        curses.init_pair(10, curses.COLOR_WHITE, -1)     # normal bright
        curses.init_pair(11, curses.COLOR_CYAN, -1)      # active tab (used with A_REVERSE)

    def _color(self, pair: int, bold: bool = False) -> int:
        attr = curses.color_pair(pair)
        if bold:
            attr |= curses.A_BOLD
        return attr

    def _latency_attr(self, ms: float) -> int:
        if ms <= 0:
            return curses.A_DIM
        if ms < LATENCY_GOOD:
            return self._color(2)
        if ms < LATENCY_WARN:
            return self._color(3)
        return self._color(4, bold=True)

    def _loss_attr(self, pct: float) -> int:
        if pct == 0:
            return self._color(2)
        if pct < LOSS_WARN:
            return self._color(3)
        return self._color(4, bold=True)

    def set_status(self, msg: str):
        self.status_msg = msg
        self.status_time = time.time()

    def _bg_collect(self):
        self.collector.collect()

    def trigger_collect(self):
        if self._collect_thread and self._collect_thread.is_alive():
            return
        self._collect_thread = threading.Thread(target=self._bg_collect, daemon=True)
        self._collect_thread.start()

    # -- Safe drawing helpers --

    def _addstr(self, y: int, x: int, text: str, attr: int = 0, max_w: int = 0):
        """Safe addstr that won't crash on out-of-bounds."""
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        max_len = (max_w or w) - x
        if max_len <= 0:
            return
        text = text[:max_len]
        try:
            self.scr.addnstr(y, x, text, max_len, attr)
        except curses.error:
            pass

    def _hline(self, y: int, x: int, ch: str, length: int, attr: int = 0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h:
            return
        length = min(length, w - x)
        if length <= 0:
            return
        try:
            self.scr.addnstr(y, x, ch * length, length, attr)
        except curses.error:
            pass

    def _draw_kv(self, y: int, key: str, value: str, val_attr: int = 0,
                 key_w: int = 22, indent: int = 2) -> int:
        self._addstr(y, indent, key, curses.A_DIM)
        self._addstr(y, indent + key_w, value, val_attr)
        return y + 1

    # -- Status bar (top) --

    def _draw_top_bar(self):
        h, w = self.scr.getmaxyx()
        snap = self.collector.latest
        bar_attr = curses.A_REVERSE | curses.A_BOLD

        # Fill bar
        self._addstr(0, 0, " " * w, bar_attr)

        # Left: flight info
        left = " inflightd"
        if snap and snap.flight:
            fd = snap.flight
            left = f" {fd.flight_number}  {fd.departure_iata}>{fd.destination_iata}"
            left += f"  {fd.aircraft_type} ({fd.tail_number})"
        self._addstr(0, 0, left, bar_attr)

        # Right: time + collection status
        now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        right_parts = [now]
        if self.collector.collecting:
            right_parts.insert(0, "collecting...")
        elif snap:
            age = time.time() - snap.timestamp
            right_parts.insert(0, f"{age:.0f}s ago")
        right = "  ".join(right_parts) + " "
        self._addstr(0, max(0, w - len(right)), right, bar_attr)

    # -- Command bar (bottom) --

    def _draw_bottom_bar(self):
        h, w = self.scr.getmaxyx()
        bar_attr = curses.A_REVERSE
        active_attr = self._color(11) | curses.A_REVERSE | curses.A_BOLD
        self._addstr(h - 1, 0, " " * w, bar_attr)

        # View tabs
        x = 1
        for v in self.VIEWS:
            label = f" {v[0].upper()}:{v} "
            if v == self.view:
                self._addstr(h - 1, x, label, active_attr)
            else:
                self._addstr(h - 1, x, label, bar_attr)
            x += len(label)

        # Right side: interval + help hint
        right = f"interval:{self.interval}s  ?:help  q:quit "
        self._addstr(h - 1, max(0, w - len(right)), right, bar_attr)

        # Status message (line above bottom bar)
        if self.status_msg and time.time() - self.status_time < 5:
            self._addstr(h - 2, 2, self.status_msg, self._color(9))

    # -- Section header helper --

    def _draw_section(self, y: int, title: str) -> int:
        h, w = self.scr.getmaxyx()
        self._addstr(y, 1, f"── {title} ", self._color(1, bold=True))
        self._hline(y, len(title) + 5, "─", w - len(title) - 6, self._color(1))
        return y + 1

    # -- Views --

    def _draw_overview(self, y: int) -> int:
        snap = self.collector.latest
        if not snap:
            self._addstr(y + 1, 2, "Waiting for first data collection...", curses.A_DIM)
            return y + 3

        h, w = self.scr.getmaxyx()

        # Flight progress
        if snap.flight:
            fd = snap.flight
            y = self._draw_section(y, "FLIGHT")
            hrs, mins = divmod(fd.time_to_dest_min, 60)
            eta = f"{hrs}h{mins:02d}m" if hrs else f"{mins}m"
            y = self._draw_kv(y, "Route", f"{fd.departure_iata} > {fd.destination_iata}   ETA {eta}   arr {fd.estimated_arrival_utc} UTC",
                              self._color(10, bold=True))
            # Progress bar
            pct = fd.distance_covered_pct
            bar_w = min(40, w - 20)
            bar_str = bar_chart(pct, bar_w)
            self._addstr(y, 2, "Progress")
            self._addstr(y, 22, bar_str, self._color(2) if pct > 50 else self._color(3))
            self._addstr(y, 23 + bar_w, f" {pct}%", curses.A_BOLD)
            y += 1

            lat_d = "N" if fd.latitude >= 0 else "S"
            lon_d = "E" if fd.longitude >= 0 else "W"
            y = self._draw_kv(y, "Position",
                              f"{abs(fd.latitude):.2f}{lat_d}  {abs(fd.longitude):.2f}{lon_d}   "
                              f"FL{fd.altitude_ft // 100}   {fd.ground_speed_kts}kts   hdg {fd.heading_deg}")
            y += 1

        # Connectivity
        y = self._draw_section(y, "CONNECTIVITY")
        if snap.connectivity:
            cs = snap.connectivity
            inet_str = "CONNECTED" if cs.internet_connectivity else "DOWN"
            inet_attr = self._color(2, bold=True) if cs.internet_connectivity else self._color(4, bold=True)
            y = self._draw_kv(y, "Internet", inet_str, inet_attr)

            glob_str = "Enabled" if cs.global_conn_enabled else "DISABLED"
            glob_attr = self._color(2) if cs.global_conn_enabled else self._color(4, bold=True)
            y = self._draw_kv(y, "Global Conn", glob_str, glob_attr)

            if snap.device:
                dev_str = f"{snap.device.status}" + (" (active)" if snap.device.enabled else "")
                dev_attr = self._color(2) if snap.device.enabled else self._color(3)
                y = self._draw_kv(y, "Device", dev_str, dev_attr)

            # Satellite coverage
            if cs.time_until_coverage_change > 0:
                mins = cs.time_until_coverage_change // 60
                secs = cs.time_until_coverage_change % 60
                label = "Coverage loss in" if cs.internet_connectivity else "Coverage back in"
                attr = self._color(3, bold=True) if cs.internet_connectivity else self._color(4, bold=True)
                y = self._draw_kv(y, label, f"{mins}m{secs:02d}s", attr)
            if cs.total_coverage_remaining > 0:
                rem_min = cs.total_coverage_remaining // 60
                y = self._draw_kv(y, "Total coverage left", f"{rem_min}m", self._color(3))
        else:
            y = self._draw_kv(y, "Status", "No data", curses.A_DIM)

        # Coverage gap log
        if self.collector.coverage_events:
            y += 1
            y = self._draw_section(y, "COVERAGE EVENTS")
            for ev in self.collector.coverage_events[-5:]:
                ts_str = datetime.fromtimestamp(ev.timestamp, tz=timezone.utc).strftime("%H:%M:%S")
                if ev.is_connected:
                    msg = f"{ts_str}  Reconnected (gap lasted {ev.duration_s:.0f}s)"
                    attr = self._color(2)
                else:
                    msg = f"{ts_str}  Connection LOST (was up {ev.duration_s:.0f}s)"
                    attr = self._color(4)
                self._addstr(y, 2, msg, attr)
                y += 1

        y += 1

        # Key network stats (compact)
        y = self._draw_section(y, "NETWORK")
        dev_label = f"{snap.client_count}" + (" (visible via ARP)" if snap.client_count else " (none in ARP)")
        y = self._draw_kv(y, "Devices", dev_label)

        # Gateway: prefer HTTPS reachability over ICMP, since ICMP is often blocked
        gw_ms = snap.gateway_ping.get("avg_ms", 0) if snap.gateway_ping else 0
        gw_loss = snap.gateway_ping.get("loss_pct", 100) if snap.gateway_ping else 100
        if snap.gateway_https_reachable:
            if gw_loss >= 99:
                gw_str = "HTTPS reachable (ICMP blocked)"
                gw_attr = self._color(2)
            elif gw_ms > 0:
                gw_str = f"{gw_ms:.0f}ms (HTTPS up)"
                gw_attr = self._latency_attr(gw_ms)
            else:
                gw_str = "HTTPS reachable"
                gw_attr = self._color(2)
        elif gw_ms > 0:
            gw_str = f"{gw_ms:.0f}ms (ICMP, HTTPS down)"
            gw_attr = self._color(3)
        else:
            gw_str = "unreachable"
            gw_attr = self._color(4, bold=True)
        y = self._draw_kv(y, "Gateway", gw_str, gw_attr)
        y = self._draw_kv(y, "PAC API", f"{snap.api_latency_ms:.0f}ms", self._latency_attr(snap.api_latency_ms))
        y = self._draw_kv(y, "Squid Proxy", f"{snap.proxy_latency_ms:.0f}ms", self._latency_attr(snap.proxy_latency_ms))
        y = self._draw_kv(y, "External (Google)", f"{snap.external_latency_ms:.0f}ms",
                          self._latency_attr(snap.external_latency_ms))
        y = self._draw_kv(y, "DNS", f"{snap.dns_resolve_ms:.0f}ms", self._latency_attr(snap.dns_resolve_ms))
        tp = snap.throughput
        if tp.get("ok"):
            y = self._draw_kv(y, "Throughput", f"{tp['kbps']:.0f} kbps",
                              self._color(2) if tp['kbps'] > 500 else
                              self._color(3) if tp['kbps'] > 100 else self._color(4))

        # Mini sparklines if we have history
        if len(self.collector.history) > 2:
            y += 1
            ext_vals = self.collector.trend_values("external_latency_ms", 30)
            tp_vals = [s.throughput.get("kbps", 0) for s in list(self.collector.history)[-30:]]
            spark_w = min(30, w - 30)
            self._addstr(y, 2, "Ext latency", curses.A_DIM)
            self._addstr(y, 22, sparkline(ext_vals, spark_w), self._color(3))
            if ext_vals:
                self._addstr(y, 23 + spark_w, f" {ext_vals[-1]:.0f}ms", curses.A_DIM)
            y += 1
            self._addstr(y, 2, "Throughput", curses.A_DIM)
            self._addstr(y, 22, sparkline(tp_vals, spark_w), self._color(2))
            if tp_vals:
                self._addstr(y, 23 + spark_w, f" {tp_vals[-1]:.0f}kbps", curses.A_DIM)
            y += 1

        # Issues summary
        y += 1
        issues = snap.issues
        if issues:
            y = self._draw_section(y, f"ISSUES ({len(issues)})")
            for iss in issues[:4]:
                sev = iss["severity"]
                if sev == "critical":
                    badge_attr = self._color(8, bold=True)
                elif sev == "warning":
                    badge_attr = self._color(7, bold=True)
                else:
                    badge_attr = self._color(6, bold=True)
                badge = f" {sev[:4].upper()} "
                self._addstr(y, 2, badge, badge_attr)
                self._addstr(y, 2 + len(badge) + 1, iss["message"], curses.A_BOLD)
                y += 1
        else:
            y = self._draw_section(y, "ISSUES")
            self._addstr(y, 2, "No issues detected", self._color(2))
            y += 1

        return y

    def _draw_network(self, y: int) -> int:
        snap = self.collector.latest
        if not snap:
            self._addstr(y + 1, 2, "No data yet...", curses.A_DIM)
            return y + 3

        h, w = self.scr.getmaxyx()
        y = self._draw_section(y, "NETWORK DIAGNOSTICS")
        dev_label = f"{snap.client_count}" + (" (visible via ARP)" if snap.client_count else " (none in ARP)")
        y = self._draw_kv(y, "Visible Devices", dev_label)
        y = self._draw_kv(y, "Active Interface", get_active_interface(), curses.A_DIM)
        y = self._draw_kv(y, "Collection Time", f"{snap.collect_duration_s:.1f}s", curses.A_DIM)
        if snap.icmp_blocked:
            y = self._draw_kv(y, "ICMP Status",
                              "BLOCKED — loss numbers below reflect blocked pings, not real reachability",
                              self._color(3))
        y += 1

        # Latency table
        col_w = 14
        self._addstr(y, 2, f"{'Target':<22} {'Latency':>{col_w}} {'Loss':>{col_w}} {'Min/Max':>{col_w}}", curses.A_BOLD)
        y += 1
        self._hline(y, 2, "─", min(66, w - 4), curses.A_DIM)
        y += 1

        def row(label, avg_ms, loss_pct=None, min_ms=None, max_ms=None, suffix=""):
            nonlocal y
            self._addstr(y, 2, f"{label:<22}")
            self._addstr(y, 24, f"{avg_ms:.0f}ms" if avg_ms > 0 else "---",
                         self._latency_attr(avg_ms))
            if loss_pct is not None:
                self._addstr(y, 24 + col_w, f"{loss_pct:.1f}%", self._loss_attr(loss_pct))
            if min_ms is not None and max_ms is not None:
                self._addstr(y, 24 + col_w * 2, f"{min_ms:.0f}/{max_ms:.0f}ms", curses.A_DIM)
            if suffix:
                self._addstr(y, 24 + col_w * 3 + 12, suffix, curses.A_DIM)
            y += 1

        gw = snap.gateway_ping
        if gw:
            gw_suffix = "HTTPS up" if snap.gateway_https_reachable else "HTTPS down"
            row("Gateway (ICMP)", gw.get("avg_ms", 0), gw.get("loss_pct", 0),
                gw.get("min_ms", 0), gw.get("max_ms", 0), suffix=gw_suffix)
        row("PAC API (HTTPS)", snap.api_latency_ms)
        if snap.portal_latency_ms > 0:
            row("Portal (HTTPS)", snap.portal_latency_ms)
        row("Squid Proxy (HTTP)", snap.proxy_latency_ms)
        row("External (HTTPS)", snap.external_latency_ms)
        ext = snap.external_ping
        if ext:
            row("ICMP 8.8.8.8", ext.get("avg_ms", 0), ext.get("loss_pct", 100),
                ext.get("min_ms", 0), ext.get("max_ms", 0))

        y += 1
        y = self._draw_section(y, "DNS RESOLUTION")
        y = self._draw_kv(y, "google.com", f"{snap.dns_resolve_ms:.0f}ms",
                          self._latency_attr(snap.dns_resolve_ms))
        y = self._draw_kv(y, "cloudflare.com", f"{snap.dns_external_ms:.0f}ms",
                          self._latency_attr(snap.dns_external_ms))

        y += 1
        y = self._draw_section(y, "THROUGHPUT")
        tp = snap.throughput
        if tp.get("ok"):
            y = self._draw_kv(y, "Download", f"{tp['kbps']:.1f} kbps",
                              self._color(2) if tp['kbps'] > 500 else
                              self._color(3) if tp['kbps'] > 100 else self._color(4))
            y = self._draw_kv(y, "Transfer", f"{tp['bytes']} bytes in {tp['elapsed_s']}s", curses.A_DIM)
        elif tp.get("error"):
            y = self._draw_kv(y, "Error", tp["error"][:50], self._color(4))
        else:
            y = self._draw_kv(y, "Download", "---", curses.A_DIM)

        # System info
        y += 1
        y = self._draw_section(y, "SYSTEM")
        si = self.collector.sys_info
        provider_str = si.provider
        if si.airline:
            provider_str += f" ({si.airline})"
        y = self._draw_kv(y, "Provider", provider_str, curses.A_BOLD)
        if si.ssid:
            y = self._draw_kv(y, "SSID", si.ssid)
        y = self._draw_kv(y, "Gateway", f"{si.gateway_ip} ({si.gateway_mac})")
        y = self._draw_kv(y, "Local IP", f"{si.local_ip} / {si.subnet}")
        y = self._draw_kv(y, "DNS Domain", si.dns_domain)
        if si.proxy:
            y = self._draw_kv(y, "Proxy", si.proxy[:50])
        if si.portal_url:
            y = self._draw_kv(y, "Portal", si.portal_url)
        if si.pac_wisp_url:
            y = self._draw_kv(y, "WISP", si.pac_wisp_url)

        return y

    def _draw_map(self, y: int, fd: FlightData) -> int:
        """Draw the ASCII flight map. Returns next y position."""
        h, w = self.scr.getmaxyx()
        map_w = min(72, w - 6)
        map_h = min(18, h - y - 10)
        if map_h < 6 or map_w < 30:
            return y

        # Skip map if we don't have valid route coordinates
        if (fd.departure_lat == 0 and fd.departure_lon == 0) or \
           (fd.destination_lat == 0 and fd.destination_lon == 0):
            self._addstr(y, 2, "Map unavailable: route coordinates missing",
                         curses.A_DIM)
            return y + 2

        grid = render_map(map_h, map_w,
                          fd.latitude, fd.longitude,
                          fd.departure_lat, fd.departure_lon,
                          fd.destination_lat, fd.destination_lon)

        # Top border
        self._addstr(y, 2, "+" + "-" * map_w + "+", curses.A_DIM)
        y += 1

        kind_attr = {
            'water': curses.A_DIM,
            'land':  self._color(1),           # cyan
            'path':  curses.A_DIM,
            'dep':   self._color(2, bold=True), # green bold
            'dst':   self._color(4, bold=True), # red bold
            'plane': self._color(3, bold=True), # yellow bold
        }

        for row in range(map_h):
            self._addstr(y, 2, "|", curses.A_DIM)
            # Batch consecutive chars with the same attr for performance
            col = 0
            while col < map_w:
                ch, kind = grid[row][col]
                attr = kind_attr.get(kind, 0)
                # Collect run of same attr
                run = ch
                end = col + 1
                while end < map_w:
                    nch, nkind = grid[row][end]
                    if kind_attr.get(nkind, 0) != attr:
                        break
                    run += nch
                    end += 1
                self._addstr(y, 3 + col, run, attr)
                col = end
            self._addstr(y, 3 + map_w, "|", curses.A_DIM)
            y += 1

        # Bottom border
        self._addstr(y, 2, "+" + "-" * map_w + "+", curses.A_DIM)
        y += 1

        # Legend
        lx = 3
        self._addstr(y, lx, "o", self._color(2, bold=True))
        lx += 1
        dep_label = f" {fd.departure_iata}  "
        self._addstr(y, lx, dep_label, curses.A_DIM)
        lx += len(dep_label)
        self._addstr(y, lx, "*", self._color(3, bold=True))
        lx += 1
        plane_label = f" {fd.flight_number}  "
        self._addstr(y, lx, plane_label, curses.A_DIM)
        lx += len(plane_label)
        self._addstr(y, lx, "o", self._color(4, bold=True))
        lx += 1
        self._addstr(y, lx, f" {fd.destination_iata}  ", curses.A_DIM)
        lx += len(fd.destination_iata) + 3
        self._addstr(y, lx, "- path  . land", curses.A_DIM)
        y += 1

        return y

    def _draw_flight(self, y: int) -> int:
        snap = self.collector.latest
        if not snap or not snap.flight:
            self._addstr(y + 1, 2, "No flight data available.", curses.A_DIM)
            return y + 3

        fd = snap.flight
        h, w = self.scr.getmaxyx()

        # Header line
        hrs, mins = divmod(fd.time_to_dest_min, 60)
        eta = f"{hrs}h{mins:02d}m" if hrs else f"{mins}m"
        header = (f"{fd.flight_number}  {fd.departure_iata}>{fd.destination_iata}  "
                  f"{fd.aircraft_type} ({fd.tail_number})  "
                  f"ETA {eta}  {fd.distance_covered_pct}%")
        y = self._draw_section(y, header)

        # Map
        y = self._draw_map(y, fd)
        y += 1

        # Key stats in compact two-column layout
        lat_d = "N" if fd.latitude >= 0 else "S"
        lon_d = "E" if fd.longitude >= 0 else "W"
        pos_str = f"{abs(fd.latitude):.2f}{lat_d} {abs(fd.longitude):.2f}{lon_d}"

        col2_x = max(42, w // 2)

        y = self._draw_kv(y, "Position", pos_str)
        self._addstr(y - 1, col2_x, "Heading", curses.A_DIM)
        self._addstr(y - 1, col2_x + 12, f"{fd.heading_deg}", 0)

        y = self._draw_kv(y, "Altitude", f"{fd.altitude_ft:,} ft (FL{fd.altitude_ft // 100})")
        self._addstr(y - 1, col2_x, "Temp", curses.A_DIM)
        self._addstr(y - 1, col2_x + 12, f"{fd.outside_temp_c} C", 0)

        y = self._draw_kv(y, "Ground Speed", f"{fd.ground_speed_kts} kts ({fd.ground_speed_kts * 1.852:.0f} km/h)")
        self._addstr(y - 1, col2_x, "Phase", curses.A_DIM)
        self._addstr(y - 1, col2_x + 12, fd.flight_phase, 0)

        y = self._draw_kv(y, "Dist Remaining", f"{fd.distance_to_dest_nm} nm")
        self._addstr(y - 1, col2_x, "Arrival", curses.A_DIM)
        self._addstr(y - 1, col2_x + 12, f"{fd.estimated_arrival_utc} UTC", curses.A_BOLD)

        # Progress bar
        y += 1
        bar_w = min(50, w - 10)
        self._addstr(y, 2, fd.departure_iata, self._color(2, bold=True))
        self._addstr(y, 6, " " + bar_chart(fd.distance_covered_pct, bar_w) + " ", 0)
        self._addstr(y, 7 + bar_w + 1, fd.destination_iata, self._color(4, bold=True))
        y += 1

        return y

    def _draw_trends(self, y: int) -> int:
        hist = self.collector.history
        if len(hist) < 2:
            self._addstr(y + 1, 2, f"Need at least 2 readings (have {len(hist)}). Waiting...", curses.A_DIM)
            return y + 3

        h, w = self.scr.getmaxyx()
        spark_w = min(50, w - 32)
        n = len(hist)

        y = self._draw_section(y, f"TRENDS ({n} readings)")
        y += 1

        def trend_row(label: str, vals: list[float], unit: str, color_pair: int):
            nonlocal y
            if not vals:
                return
            cur = vals[-1]
            avg = sum(vals) / len(vals)
            mn = min(vals)
            mx = max(vals)
            self._addstr(y, 2, f"{label:<18}", curses.A_BOLD)
            self._addstr(y, 20, sparkline(vals, spark_w), self._color(color_pair))
            self._addstr(y, 21 + spark_w, f" {cur:.0f}{unit}", curses.A_BOLD)
            y += 1
            self._addstr(y, 20, f"avg:{avg:.0f}  min:{mn:.0f}  max:{mx:.0f}{unit}", curses.A_DIM)
            y += 2

        ext_vals = self.collector.trend_values("external_latency_ms")
        api_vals = self.collector.trend_values("api_latency_ms")
        proxy_vals = self.collector.trend_values("proxy_latency_ms")
        dns_vals = self.collector.trend_values("dns_resolve_ms")
        gw_vals = [s.gateway_ping.get("avg_ms", 0) if s.gateway_ping else 0 for s in hist]
        tp_vals = [s.throughput.get("kbps", 0) if s.throughput else 0 for s in hist]
        gw_loss = [s.gateway_ping.get("loss_pct", 0) if s.gateway_ping else 0 for s in hist]
        ext_loss = [s.external_ping.get("loss_pct", 0) if s.external_ping else 0 for s in hist]
        client_vals = [float(s.client_count) for s in hist]

        trend_row("Ext Latency", ext_vals, "ms", 4)
        trend_row("API Latency", api_vals, "ms", 3)
        trend_row("Proxy Latency", proxy_vals, "ms", 3)
        trend_row("DNS Resolve", dns_vals, "ms", 3)
        trend_row("Gateway", gw_vals, "ms", 2)
        trend_row("Throughput", tp_vals, "kbps", 2)
        trend_row("Loss (ext)", ext_loss, "%", 4)
        trend_row("Loss (gw)", gw_loss, "%", 4)
        trend_row("Devices", client_vals, "", 9)

        # Satellite coverage timeline
        events = self.collector.coverage_events
        if events:
            y += 1
            y = self._draw_section(y, "SATELLITE COVERAGE LOG")
            for ev in events[-10:]:
                ts_str = datetime.fromtimestamp(ev.timestamp, tz=timezone.utc).strftime("%H:%M:%S")
                if ev.is_connected:
                    self._addstr(y, 2, f"{ts_str}", curses.A_DIM)
                    self._addstr(y, 13, "UP", self._color(2, bold=True))
                    self._addstr(y, 18, f"gap lasted {ev.duration_s:.0f}s", curses.A_DIM)
                else:
                    self._addstr(y, 2, f"{ts_str}", curses.A_DIM)
                    self._addstr(y, 13, "DOWN", self._color(4, bold=True))
                    self._addstr(y, 18, f"was up {ev.duration_s:.0f}s", curses.A_DIM)
                y += 1

        return y

    def _draw_plans(self, y: int) -> int:
        products = self.collector.products
        if not products:
            self._addstr(y + 1, 2, "No plan data available.", curses.A_DIM)
            return y + 3

        y = self._draw_section(y, "WIFI PLANS")
        y += 1
        for p in products:
            price = f"EUR {p.price_eur:.2f}" if p.price_eur > 0 else "FREE"
            price_attr = self._color(2, bold=True) if p.price_eur == 0 else curses.A_BOLD
            self._addstr(y, 2, f"{p.name:<20}", curses.A_BOLD)
            self._addstr(y, 24, price, price_attr)
            y += 1
            if p.description:
                h_scr, w_scr = self.scr.getmaxyx()
                for line in textwrap.wrap(p.description, width=min(60, w_scr - 6)):
                    self._addstr(y, 4, line, curses.A_DIM)
                    y += 1
            y += 1

        # WISP portal
        si = self.collector.sys_info
        if si.pac_wisp_url:
            y += 1
            y = self._draw_section(y, "WISP PORTAL")
            y = self._draw_kv(y, "URL", si.pac_wisp_url)

        return y

    def _draw_issues(self, y: int) -> int:
        snap = self.collector.latest
        issues = snap.issues if snap else []

        y = self._draw_section(y, f"CURRENT ISSUES ({len(issues)})")
        y += 1
        if not issues:
            self._addstr(y, 2, "No issues detected", self._color(2))
            return y + 2

        for iss in issues:
            sev = iss["severity"]
            if sev == "critical":
                badge_attr = self._color(8, bold=True)
            elif sev == "warning":
                badge_attr = self._color(7, bold=True)
            else:
                badge_attr = self._color(6, bold=True)

            badge = f" {sev[:4].upper()} "
            self._addstr(y, 2, badge, badge_attr)
            self._addstr(y, 2 + len(badge) + 1, iss["message"], curses.A_BOLD)
            y += 1
            self._addstr(y, 4, iss.get("detail", ""), curses.A_DIM)
            y += 1
            self._addstr(y, 4, f"Component: {iss.get('component', '?')}", curses.A_DIM)
            y += 2

        # Historical issue frequency
        if len(self.collector.history) > 2:
            y += 1
            y = self._draw_section(y, "ISSUE FREQUENCY (last 10 readings)")
            comp_counts: dict[str, int] = {}
            for s in list(self.collector.history)[-10:]:
                for i in s.issues:
                    c = i.get("component", "?")
                    comp_counts[c] = comp_counts.get(c, 0) + 1
            for comp, cnt in sorted(comp_counts.items(), key=lambda x: -x[1]):
                pct = cnt * 100 // 10
                self._addstr(y, 2, f"{comp:<16}", curses.A_DIM)
                bar_w = min(20, cnt * 2)
                self._addstr(y, 20, "█" * bar_w, self._color(4) if cnt > 7 else self._color(3))
                self._addstr(y, 22 + bar_w, f" {cnt}/10 ({pct}%)", curses.A_DIM)
                y += 1

        return y

    def _draw_help(self):
        h, w = self.scr.getmaxyx()
        box_h, box_w = 18, 46
        top = max(0, (h - box_h) // 2)
        left = max(0, (w - box_w) // 2)

        box_attr = curses.A_REVERSE
        title_attr = curses.A_REVERSE | curses.A_BOLD
        key_attr = curses.A_REVERSE | curses.A_BOLD

        for row in range(box_h):
            self._addstr(top + row, left, " " * box_w, box_attr)

        title = " KEYBOARD SHORTCUTS "
        self._addstr(top, left + (box_w - len(title)) // 2, title, title_attr)

        lines = [
            ("o", "Overview (default)"),
            ("n", "Network diagnostics"),
            ("f", "Flight details"),
            ("t", "Trend charts"),
            ("p", "WiFi plans"),
            ("i", "Issues detail"),
            ("", ""),
            ("r", "Force refresh now"),
            ("+/-", "Adjust refresh interval"),
            ("d", "Dump history to JSON file"),
            ("", ""),
            ("?/h", "Toggle this help"),
            ("q", "Quit"),
        ]
        for idx, (key, desc) in enumerate(lines):
            if key:
                self._addstr(top + 2 + idx, left + 3, f"{key:>5}", key_attr)
                self._addstr(top + 2 + idx, left + 10, desc, box_attr)

    # -- Main draw --

    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()

        self._draw_top_bar()
        self._draw_bottom_bar()

        # Content area: rows 1 to h-2
        y = 2
        view_draw = {
            "overview": self._draw_overview,
            "network": self._draw_network,
            "flight": self._draw_flight,
            "trends": self._draw_trends,
            "plans": self._draw_plans,
            "issues": self._draw_issues,
        }
        draw_fn = view_draw.get(self.view, self._draw_overview)
        draw_fn(y)

        if self.show_help:
            self._draw_help()

        self.scr.refresh()

    # -- Input handling --

    def handle_key(self, ch: int):
        if ch < 0:
            return

        c = chr(ch) if 0 < ch < 256 else ""

        if c == "q":
            self.running = False
        elif c in self.VIEW_KEYS:
            self.view = self.VIEW_KEYS[c]
            self._scroll_offset = 0
        elif c in ("?", "h"):
            self.show_help = not self.show_help
        elif c == "r":
            self.trigger_collect()
            self.set_status("Refreshing...")
        elif c == "+":
            self.interval = min(300, self.interval + 10)
            self.set_status(f"Interval: {self.interval}s")
        elif c == "-":
            self.interval = max(10, self.interval - 10)
            self.set_status(f"Interval: {self.interval}s")
        elif c == "d":
            fname = f"inflightd_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            fpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
            self.collector.save_history(fpath)
            self.set_status(f"Saved {len(self.collector.history)} readings to {fname}")

    # -- Main loop --

    def run(self):
        last_collect = 0

        while self.running:
            now = time.time()

            # Trigger collection at interval
            if now - last_collect >= self.interval:
                self.trigger_collect()
                last_collect = now

            self.draw()

            ch = self.scr.getch()
            self.handle_key(ch)


# ---------------------------------------------------------------------------
# CLI report mode (non-TUI, same as before)
# ---------------------------------------------------------------------------

def run_report(json_mode: bool = False):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not json_mode:
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗")
        print(f"║  inflightd — Inflight WiFi Diagnostics                   ║")
        print(f"╚══════════════════════════════════════════════════════════╝{RESET}")
        print(f"  {DIM}Report generated at {ts}{RESET}")
        print(f"  {DIM}Detecting inflight WiFi system...{RESET}")

    sys_info = detect_system()
    collector = DataCollector(sys_info)

    if not json_mode and sys_info.provider != "Unknown":
        print(f"\n{BOLD}{CYAN}── SYSTEM ──────────────────────────────────────────────{RESET}")
        print(f"  {DIM}{'Provider':<22}{RESET} {BOLD}{sys_info.provider}{RESET}")
        if sys_info.portal_url:
            print(f"  {DIM}{'Portal':<22}{RESET} {sys_info.portal_url}")
        if sys_info.pac_wisp_url:
            print(f"  {DIM}{'WISP Portal':<22}{RESET} {sys_info.pac_wisp_url}")
        print(f"  {DIM}{'Gateway':<22}{RESET} {sys_info.gateway_ip} ({sys_info.gateway_mac})")
        print(f"  {DIM}{'Local IP':<22}{RESET} {sys_info.local_ip} / {sys_info.subnet}")

    if not json_mode:
        print(f"\n  {DIM}Collecting data (this takes ~20s)...{RESET}")

    snap = collector.collect()

    if json_mode:
        result = {
            "timestamp": ts,
            "system": asdict(sys_info),
            "flight": asdict(snap.flight) if snap.flight else None,
            "connectivity": asdict(snap.connectivity) if snap.connectivity else None,
            "device": asdict(snap.device) if snap.device else None,
            "products": [asdict(p) for p in collector.products],
            "diagnostics": {
                "gateway_ping": snap.gateway_ping,
                "external_ping": snap.external_ping,
                "dns_resolve_ms": snap.dns_resolve_ms,
                "api_latency_ms": snap.api_latency_ms,
                "external_latency_ms": snap.external_latency_ms,
                "proxy_latency_ms": snap.proxy_latency_ms,
                "throughput": snap.throughput,
                "client_count": snap.client_count,
            },
            "issues": snap.issues,
        }
        print(json.dumps(result, indent=2, default=str))
        return

    # Flight
    if snap.flight:
        fd = snap.flight
        print(f"\n{BOLD}{CYAN}── FLIGHT ──────────────────────────────────────────────{RESET}")
        print(f"  {DIM}{'Flight':<22}{RESET} {BOLD}{fd.flight_number}{RESET}  {fd.departure_iata} > {fd.destination_iata}")
        print(f"  {DIM}{'Aircraft':<22}{RESET} {fd.aircraft_type}  ({fd.tail_number})")
        h, m = divmod(fd.time_to_dest_min, 60)
        eta = f"{h}h{m:02d}m" if h else f"{m}m"
        pct = fd.distance_covered_pct
        bar = "█" * (pct * 30 // 100) + "░" * (30 - pct * 30 // 100)
        print(f"  {DIM}{'Progress':<22}{RESET} [{bar}] {pct}%")
        print(f"  {DIM}{'ETA':<22}{RESET} {eta} remaining  (arr {fd.estimated_arrival_utc} UTC)")
        lat_d = "N" if fd.latitude >= 0 else "S"
        lon_d = "E" if fd.longitude >= 0 else "W"
        print(f"  {DIM}{'Position':<22}{RESET} {abs(fd.latitude):.2f}{lat_d} {abs(fd.longitude):.2f}{lon_d} hdg {fd.heading_deg}")
        print(f"  {DIM}{'Altitude':<22}{RESET} {fd.altitude_ft:,} ft")
        print(f"  {DIM}{'Ground Speed':<22}{RESET} {fd.ground_speed_kts} kts ({fd.ground_speed_kts * 1.852:.0f} km/h)")
        print(f"  {DIM}{'Outside Temp':<22}{RESET} {fd.outside_temp_c} C")

    # Connectivity
    if snap.connectivity:
        cs = snap.connectivity
        print(f"\n{BOLD}{CYAN}── CONNECTIVITY ────────────────────────────────────────{RESET}")
        ic = f"{GREEN}CONNECTED{RESET}" if cs.internet_connectivity else f"{RED}DOWN{RESET}"
        print(f"  {DIM}{'Internet':<22}{RESET} {ic}")
        gc = f"{GREEN}Enabled{RESET}" if cs.global_conn_enabled else f"{RED}DISABLED{RESET}"
        print(f"  {DIM}{'Global Conn':<22}{RESET} {gc}")
        if cs.time_until_coverage_change > 0:
            print(f"  {DIM}{'Coverage Change In':<22}{RESET} {YELLOW}{cs.time_until_coverage_change}s{RESET}")
        if cs.total_coverage_remaining > 0:
            print(f"  {DIM}{'Coverage Remaining':<22}{RESET} {YELLOW}{cs.total_coverage_remaining}s{RESET}")

    # Network
    print(f"\n{BOLD}{CYAN}── NETWORK ─────────────────────────────────────────────{RESET}")
    dev_extra = " (visible via ARP)" if snap.client_count else " (none in ARP)"
    print(f"  {DIM}{'Devices':<22}{RESET} {snap.client_count}{DIM}{dev_extra}{RESET}")
    print(f"  {DIM}{'Active Interface':<22}{RESET} {DIM}{get_active_interface()}{RESET}")
    if snap.icmp_blocked:
        print(f"  {DIM}{'ICMP Status':<22}{RESET} {YELLOW}BLOCKED — loss numbers below are ping-only, not real reachability{RESET}")

    def _fmt_lat(ms):
        if ms <= 0: return f"{DIM}---{RESET}"
        c = GREEN if ms < 100 else YELLOW if ms < 500 else RED
        return f"{c}{ms:.0f}ms{RESET}"

    gw = snap.gateway_ping
    if gw:
        gw_https = f"{GREEN}HTTPS up{RESET}" if snap.gateway_https_reachable else f"{RED}HTTPS down{RESET}"
        print(f"  {DIM}{'Gateway (ICMP)':<22}{RESET} {_fmt_lat(gw.get('avg_ms',0))}  loss {gw.get('loss_pct',0):.1f}%  {gw_https}")
    print(f"  {DIM}{'PAC API (HTTPS)':<22}{RESET} {_fmt_lat(snap.api_latency_ms)}")
    print(f"  {DIM}{'Squid Proxy (HTTP)':<22}{RESET} {_fmt_lat(snap.proxy_latency_ms)}")
    print(f"  {DIM}{'External (HTTPS)':<22}{RESET} {_fmt_lat(snap.external_latency_ms)}")
    print(f"  {DIM}{'DNS (google.com)':<22}{RESET} {_fmt_lat(snap.dns_resolve_ms)}")
    tp = snap.throughput
    if tp.get("ok"):
        print(f"  {DIM}{'Throughput':<22}{RESET} {tp['kbps']:.1f} kbps")

    # Issues
    if snap.issues:
        print(f"\n{BOLD}{CYAN}── ISSUES ({len(snap.issues)}) ──────────────────────────────────────{RESET}")
        for iss in snap.issues:
            sev = iss["severity"]
            badge = f"{BG_RED}{BOLD} CRIT {RESET}" if sev == "critical" else \
                    f"{BG_YELLOW}{BOLD} WARN {RESET}" if sev == "warning" else \
                    f"{BG_GREEN}{BOLD} INFO {RESET}"
            print(f"  {badge} {BOLD}{iss['message']}{RESET}")
            print(f"    {DIM}{iss['detail']}{RESET}")
    else:
        print(f"\n  {GREEN}No issues detected{RESET}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="inflightd - Inflight WiFi Diagnostics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Supported systems:
              Panasonic Avionics  TAP, KLM, Air France, and others
              Lufthansa FlyNet   SWISS, Lufthansa, Austrian, Eurowings

            Workflow on a new airline:
              1. Connect to WiFi
              2. python3 inflightd.py --probe    (discover API endpoints)
              3. python3 inflightd.py            (launch TUI)

            Keys (TUI mode):
              o/n/f/t/p/i   Switch views (overview/network/flight/trends/plans/issues)
              r             Force refresh      +/-  Adjust interval
              d             Dump history JSON   ?   Help overlay
              q             Quit
        """))
    parser.add_argument("--report", action="store_true", help="One-shot report (no TUI)")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output (implies --report)")
    parser.add_argument("--interval", "-i", type=int, default=30, help="Refresh interval in seconds (default: 30)")
    parser.add_argument("--probe", action="store_true",
                        help="Discover API endpoints on the current network (run on first connect)")
    parser.add_argument("--probe-deep", action="store_true",
                        help="Deep probe: JS bundle mining, HTML scraping, TLS SAN, port scan, well-knowns")

    args = parser.parse_args()

    if args.probe:
        print("inflightd: detecting system for endpoint discovery...")
        sys_info = detect_system()
        run_probe(sys_info)
        return

    if args.probe_deep:
        print("inflightd: running deep probe (JS mining + HTML + TLS SAN + ports)...")
        sys_info = detect_system()
        run_deep_probe(sys_info)
        return

    if args.json:
        run_report(json_mode=True)
        return

    if args.report:
        run_report(json_mode=False)
        return

    # TUI mode: detect system first (before entering curses)
    print("inflightd: detecting inflight WiFi system...")
    sys_info = detect_system()
    if sys_info.provider == "Unknown":
        print("Warning: could not detect an inflight WiFi system.")
        print(f"  Gateway: {sys_info.gateway_ip}  MAC: {sys_info.gateway_mac}  DNS: {sys_info.dns_domain}")
        print("  Continuing anyway — network diagnostics will still run.\n")

    collector = DataCollector(sys_info)

    def curses_main(stdscr):
        tui = TUI(stdscr, collector, interval=args.interval)
        tui.trigger_collect()  # start first collection immediately
        tui.run()

        # Save on exit
        if collector.history:
            fname = f"inflightd_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            fpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
            collector.save_history(fpath)
            return fpath
        return None

    save_path = curses.wrapper(curses_main)
    if save_path:
        print(f"Session saved to {save_path} ({len(collector.history)} readings)")


if __name__ == "__main__":
    main()

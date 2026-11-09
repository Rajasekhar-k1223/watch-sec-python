"""
Monitorix Enterprise Threat Intelligence Platform — Feed Engine
==============================================================
Provides high-throughput, secure ingestion of external and internal CTI feeds.
Supported formats:
- STIX 2.1 (JSON bundles)
- TAXII 2.1 (Collections & polling)
- JSON (Custom & structured feeds)
- CSV (Auto-detected columns)
- Plaintext newline-delimited lists
- Manual bulk IOC imports

Includes enterprise SSRF protection, strict rate-limit handling, exponential
backoff with jitter, and audit provenance tracking.
"""

import asyncio
import csv
import io
import json
import logging
import random
import re
import socket
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set

import httpx

from .core import (
    IndicatorType,
    ThreatSeverity,
    ThreatClassification,
    IocRecord,
    normalize_indicator,
    detect_indicator_type
)

logger = logging.getLogger("ThreatIntelFeedEngine")

# Blocked IP networks for SSRF Defense
_BLOCKED_SSRF_NETWORKS = [
    # IPv4 Private / Loopback / Metadata
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",       # Cloud metadata (AWS 169.254.169.254, Azure, GCP)
    "0.0.0.0/8",
    "100.64.0.0/10",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",          # Multicast
    "240.0.0.0/4",          # Reserved
    # IPv6 Loopback / Link-Local / Unique Local
    "::1/128",
    "fc00::/7",
    "fe80::/10"
]

import ipaddress
_PARSED_BLOCKED_NETWORKS = [ipaddress.ip_network(net) for net in _BLOCKED_SSRF_NETWORKS]


def is_safe_feed_url(url: str) -> Tuple[bool, str]:
    """
    Validates a feed URL against SSRF vulnerabilities.
    Blocks private IP ranges, loopback, link-local, cloud metadata services,
    and non-standard URI schemes.
    Returns: (is_safe: bool, reason: str)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    url_clean = url.strip()
    try:
        parsed = urllib.parse.urlparse(url_clean)
    except Exception as e:
        return False, f"Malformed URL syntax: {e}"

    # Enforce safe protocols
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname"

    # Reject localhost aliases
    if hostname.lower() in ("localhost", "localhost.localdomain", "127.0.0.1", "::1", "metadata.google.internal"):
        return False, f"Access to localhost/internal hostname '{hostname}' is strictly prohibited."

    # DNS Resolution Check & IP Range Verification
    try:
        # Resolve all addresses associated with hostname
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            # Check loopback, private, link-local, multicast directly
            if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                return False, f"SSRF blocked: Hostname '{hostname}' resolves to restricted IP {ip_str}."

            for net in _PARSED_BLOCKED_NETWORKS:
                if ip_obj in net:
                    return False, f"SSRF blocked: Hostname '{hostname}' resolves to prohibited network range {net}."
    except socket.gaierror as dns_err:
        # If hostname cannot be resolved in production, block or flag
        return False, f"DNS resolution failed for '{hostname}': {dns_err}"
    except Exception as ex:
        return False, f"SSRF security validation error: {ex}"

    return True, "URL is safe"


class FeedIngestionEngine:
    """
    Enterprise-grade CTI Feed Ingestion Engine.
    """

    def __init__(self, timeout_seconds: float = 10.0, max_feed_size_bytes: int = 15 * 1024 * 1024):
        self.timeout = timeout_seconds
        self.max_size = max_feed_size_bytes

    async def fetch_feed_data(
        self,
        url: str,
        auth_header: Optional[Dict[str, str]] = None,
        max_retries: int = 3
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Securely fetches raw feed content with SSRF defenses, rate-limit backoff, and size caps.
        Returns: (content_string, error_message)
        """
        safe, reason = is_safe_feed_url(url)
        if not safe:
            logger.warning(f"[FeedEngine] SSRF validation rejected feed URL {url!r}: {reason}")
            return None, f"SSRF Check Failed: {reason}"

        headers = {
            "User-Agent": "Monitorix-CTI-Engine/3.0 (Enterprise Threat Feed Ingestion)",
            "Accept": "application/json, text/csv, text/plain, application/taxii+json;version=2.1, */*"
        }
        if auth_header:
            headers.update(auth_header)

        delay = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                    resp = await client.get(url, headers=headers)

                    # Handle HTTP Redirects securely (re-validating target URL against SSRF)
                    if resp.is_redirect:
                        redirect_url = resp.headers.get("location")
                        if not redirect_url:
                            return None, "Received HTTP redirect without Location header"
                        full_redirect = urllib.parse.urljoin(url, redirect_url)
                        safe_redir, redir_reason = is_safe_feed_url(full_redirect)
                        if not safe_redir:
                            return None, f"Redirect to prohibited host blocked: {redir_reason}"
                        resp = await client.get(full_redirect, headers=headers)

                    # Rate-limiting / Backoff
                    if resp.status_code in (429, 503):
                        if attempt < max_retries:
                            retry_after = resp.headers.get("Retry-After")
                            wait_time = float(retry_after) if retry_after and retry_after.isdigit() else delay + random.uniform(0.1, 0.5)
                            logger.info(f"[FeedEngine] Rate limited ({resp.status_code}) on {url!r}. Retrying in {wait_time:.2f}s...")
                            await asyncio.sleep(wait_time)
                            delay *= 2
                            continue

                    resp.raise_for_status()

                    # Enforce body size limit to prevent memory exhaustion
                    content_bytes = resp.content
                    if len(content_bytes) > self.max_size:
                        return None, f"Feed size ({len(content_bytes)} bytes) exceeded max allowable limit ({self.max_size} bytes)"

                    return resp.text, None

            except httpx.HTTPStatusError as http_err:
                if attempt == max_retries:
                    return None, f"HTTP Error {http_err.response.status_code}: {http_err}"
                await asyncio.sleep(delay)
                delay *= 2
            except httpx.RequestError as req_err:
                if attempt == max_retries:
                    return None, f"Network transport error: {req_err}"
                await asyncio.sleep(delay)
                delay *= 2
            except Exception as e:
                return None, f"Unexpected ingestion error: {e}"

        return None, "Exceeded maximum retry attempts."

    # -------------------------------------------------------------------------
    # Format Parsers
    # -------------------------------------------------------------------------

    def parse_plain_text(
        self,
        content: str,
        source_name: str = "Feed",
        max_items: int = 10000
    ) -> List[IocRecord]:
        """
        Parses newline-delimited lists of IPs, domains, URLs, hashes with inline # comment filtering.
        """
        records: List[IocRecord] = []
        seen: Set[str] = set()

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip inline comments
            if " #" in line:
                line = line.split(" #")[0].strip()
            if "\t#" in line:
                line = line.split("\t#")[0].strip()

            # Handle CSV-like rows in plain lists (e.g. "1.2.3.4,8080" or "hash,malware")
            val = line
            if "," in line and not line.startswith("http"):
                parts = [p.strip().strip('"').strip("'") for p in line.split(",") if p.strip()]
                if parts:
                    val = parts[0]

            try:
                detected_type = detect_indicator_type(val)
                rec = IocRecord(
                    value=val,
                    indicator_type=detected_type,
                    source=source_name,
                    confidence=85,
                    severity=ThreatSeverity.HIGH.value
                )
                if rec.value not in seen:
                    records.append(rec)
                    seen.add(rec.value)
            except Exception:
                continue

            if len(records) >= max_items:
                break

        return records

    def parse_csv(
        self,
        content: str,
        ioc_column: str = "indicator",
        type_column: str = "type",
        source_name: str = "CSV Feed",
        max_items: int = 10000
    ) -> List[IocRecord]:
        """
        Parses CSV feeds with auto-detection of column headers and metadata.
        """
        records: List[IocRecord] = []
        seen: Set[str] = set()

        # Filter out pre-header comments, preserving commented header if followed by data
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        header_idx = None
        for i, l in enumerate(lines):
            if "," in l:
                if l.startswith("#"):
                    # If this commented line has commas and next line is data, treat as header
                    if i + 1 < len(lines) and not lines[i + 1].startswith("#") and "," in lines[i + 1]:
                        lines[i] = l.lstrip("#").strip()
                        header_idx = i
                        break
                else:
                    header_idx = i
                    break

        if header_idx is None:
            return records

        clean_lines = [l for l in lines[header_idx:] if not l.startswith("#")]
        if not clean_lines:
            return records

        try:
            reader = csv.DictReader(io.StringIO("\n".join(clean_lines)))
            if not reader.fieldnames:
                return records
            
            # Map column names case-insensitively
            col_map = {col.lower().strip(): col for col in reader.fieldnames}
            
            val_col = col_map.get(ioc_column.lower()) or col_map.get("ioc") or col_map.get("ioc_value") or col_map.get("indicator_value") or col_map.get("url") or col_map.get("ip_address")
            type_col = col_map.get(type_column.lower()) or col_map.get("ioc_type") or col_map.get("type") or col_map.get("threat_type")
            sev_col = col_map.get("severity") or col_map.get("threat_level")
            conf_col = col_map.get("confidence") or col_map.get("confidence_level")
            threat_col = col_map.get("malware") or col_map.get("threat") or col_map.get("classification")

            for row in reader:
                val = (row.get(val_col) if val_col else "").strip()
                if not val:
                    continue

                raw_t = (row.get(type_col) if type_col else "").strip()
                detected_t = raw_t if raw_t else detect_indicator_type(val)
                sev = (row.get(sev_col) if sev_col else ThreatSeverity.HIGH.value).capitalize()
                
                conf = 80
                if conf_col and row.get(conf_col):
                    try:
                        conf = int(row.get(conf_col))
                    except ValueError:
                        pass

                threat_class = (row.get(threat_col) if threat_col else ThreatClassification.UNKNOWN.value)

                try:
                    rec = IocRecord(
                        value=val,
                        indicator_type=detected_t,
                        threat_classification=threat_class,
                        confidence=conf,
                        severity=sev if sev in [s.value for s in ThreatSeverity] else ThreatSeverity.HIGH.value,
                        source=source_name
                    )
                    if rec.value not in seen:
                        records.append(rec)
                        seen.add(rec.value)
                except Exception:
                    continue

                if len(records) >= max_items:
                    break

        except Exception as e:
            logger.error(f"[FeedEngine] CSV parse failure: {e}")

        return records

    def parse_stix21(
        self,
        content: str,
        source_name: str = "STIX 2.1 Feed",
        max_items: int = 10000
    ) -> List[IocRecord]:
        """
        Parses STIX 2.1 JSON bundle containing indicator, observed-data, or malware SDOs.
        Extracts indicator patterns:
        - [ipv4-addr:value = '...']
        - [domain-name:value = '...']
        - [url:value = '...']
        - [file:hashes.'SHA-256' = '...']
        - [file:hashes.'MD5' = '...']
        """
        records: List[IocRecord] = []
        seen: Set[str] = set()

        try:
            data = json.loads(content)
            objects = data.get("objects", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

            # Regex for STIX 2.1 pattern extraction
            pattern_regex = re.compile(
                r"\[\s*([\w\-]+):(\w+(?:\.[\w\-'\"]+)?)\s*(=|LIKE|MATCHES)\s*'([^']+)'\s*\]",
                re.IGNORECASE
            )

            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                obj_type = obj.get("type")
                if obj_type != "indicator":
                    continue

                pattern = obj.get("pattern", "")
                confidence = obj.get("confidence", 75)
                labels = obj.get("labels", []) or obj.get("indicator_types", [])
                threat_class = labels[0] if labels else ThreatClassification.UNKNOWN.value

                # Extract MITRE technique if present in kill_chain_phases
                mitre_tech = None
                mitre_tact = None
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        mitre_tact = phase.get("phase_name")
                for ext_ref in obj.get("external_references", []):
                    if ext_ref.get("source_name") == "mitre-attack":
                        mitre_tech = ext_ref.get("external_id")

                matches = pattern_regex.findall(pattern)
                for sdo_type, field, op, val in matches:
                    val = val.strip()
                    if not val:
                        continue

                    # Map STIX object to Monitorix indicator type
                    sdo_lower = sdo_type.lower()
                    field_lower = field.lower()
                    ind_type = IndicatorType.DOMAIN.value

                    if "ipv4" in sdo_lower:
                        ind_type = IndicatorType.IPV4.value
                    elif "ipv6" in sdo_lower:
                        ind_type = IndicatorType.IPV6.value
                    elif "domain" in sdo_lower:
                        ind_type = IndicatorType.DOMAIN.value
                    elif "url" in sdo_lower:
                        ind_type = IndicatorType.URL.value
                    elif "file" in sdo_lower or "hashes" in field_lower:
                        if "sha-256" in field_lower or "sha256" in field_lower:
                            ind_type = IndicatorType.SHA256.value
                        elif "md5" in field_lower:
                            ind_type = IndicatorType.MD5.value
                        elif "sha-1" in field_lower or "sha1" in field_lower:
                            ind_type = IndicatorType.SHA1.value
                        else:
                            ind_type = detect_indicator_type(val)
                    elif "email" in sdo_lower:
                        ind_type = IndicatorType.EMAIL.value

                    try:
                        rec = IocRecord(
                            value=val,
                            indicator_type=ind_type,
                            threat_classification=threat_class,
                            confidence=int(confidence),
                            severity=ThreatSeverity.HIGH.value if confidence >= 70 else ThreatSeverity.MEDIUM.value,
                            source=source_name,
                            tags=labels,
                            mitre_technique=mitre_tech,
                            mitre_tactic=mitre_tact
                        )
                        if rec.value not in seen:
                            records.append(rec)
                            seen.add(rec.value)
                    except Exception:
                        continue

                if len(records) >= max_items:
                    break

        except Exception as e:
            logger.error(f"[FeedEngine] STIX 2.1 parse error: {e}")

        return records

    def parse_taxii21_envelope(
        self,
        content: str,
        source_name: str = "TAXII 2.1 Collection",
        max_items: int = 10000
    ) -> List[IocRecord]:
        """
        Parses a TAXII 2.1 envelope containing STIX objects.
        """
        try:
            data = json.loads(content)
            # TAXII envelopes store STIX bundles or objects directly in 'objects'
            return self.parse_stix21(content, source_name=source_name, max_items=max_items)
        except Exception as e:
            logger.error(f"[FeedEngine] TAXII 2.1 parse failure: {e}")
            return []

    def parse_generic_json(
        self,
        content: str,
        source_name: str = "JSON Feed",
        max_items: int = 10000
    ) -> List[IocRecord]:
        """
        Parses arbitrary structured JSON feeds by scanning for indicator fields.
        """
        records: List[IocRecord] = []
        seen: Set[str] = set()

        try:
            data = json.loads(content)
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                # Search common container keys
                for key in ("indicators", "iocs", "data", "results", "threats", "items"):
                    if isinstance(data.get(key), list):
                        items = data[key]
                        break
                if not items:
                    items = [data]

            for item in items:
                if not isinstance(item, dict):
                    continue

                # Locate indicator value
                val = None
                for k in ("indicator", "value", "ioc", "ip", "domain", "url", "hash", "sha256"):
                    if item.get(k) and isinstance(item[k], str):
                        val = item[k].strip()
                        break

                if not val:
                    continue

                raw_t = item.get("type") or item.get("indicator_type")
                detected_t = raw_t if raw_t else detect_indicator_type(val)
                conf = item.get("confidence", 75)
                sev = item.get("severity", ThreatSeverity.HIGH.value)
                threat = item.get("threat_classification", ThreatClassification.UNKNOWN.value)

                try:
                    rec = IocRecord(
                        value=val,
                        indicator_type=detected_t,
                        threat_classification=threat,
                        confidence=int(conf) if isinstance(conf, (int, float)) else 75,
                        severity=sev if sev in [s.value for s in ThreatSeverity] else ThreatSeverity.HIGH.value,
                        source=source_name
                    )
                    if rec.value not in seen:
                        records.append(rec)
                        seen.add(rec.value)
                except Exception:
                    continue

                if len(records) >= max_items:
                    break

        except Exception as e:
            logger.error(f"[FeedEngine] JSON parse error: {e}")

        return records


# Singleton instance
feed_ingestion_engine = FeedIngestionEngine()


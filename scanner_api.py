import os
import hashlib
import logging
import json
import re
import csv
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse, FileResponse
import pandas as pd
import requests
from requests.adapters import HTTPAdapter
import zipfile
import nvdlib
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import traceback
import sys
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle

# Config
OUTPUT_DIR = "output"
UPLOAD_DIR = "uploaded"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- API key loading from api_keys.txt ---
def load_api_keys_from_file(filepath: str = "api_keys.txt") -> Dict[str, str]:
    keys = {}
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    keys[k.strip()] = v.strip()
    return keys

api_keys = load_api_keys_from_file()

# Support multiple API keys for better rate limiting
VT_API_KEYS = [key.strip() for key in api_keys.get("VT_API_KEY", "").split(',') if key.strip()]
NVD_API_KEYS = [key.strip() for key in api_keys.get("NVD_API_KEY", "").split(',') if key.strip()]
ABUSEIPDB_API_KEYS = [key.strip() for key in api_keys.get("ABUSEIPDB_API_KEY", "").split(',') if key.strip()]
IPAPI_KEYS = [key.strip() for key in api_keys.get("IPAPI_KEY", "").split(',') if key.strip()]
THREATFOX_API_KEY = api_keys.get("THREATFOX_API_KEY", "").strip()

# Rate limiting configuration
RATE_LIMITS = {
    'virustotal': {'requests_per_minute': 4, 'requests_per_hour': 500},
    'nvd': {'requests_per_minute': 5, 'requests_per_hour': 1000},
    'abuseipdb': {'requests_per_minute': 2, 'requests_per_hour': 1000},
    'ipapi': {'requests_per_minute': 10, 'requests_per_hour': 1000},
    'threatfox': {'requests_per_minute': 5, 'requests_per_hour': 1000}
}

class ThreadSafeRateLimiter:
    """Thread-safe rate limiter with exponential backoff"""

    def __init__(self, api_name: str):
        self.api_name = api_name
        self.limits = RATE_LIMITS.get(api_name, {'requests_per_minute': 1, 'requests_per_hour': 100})
        self.lock = threading.Lock()
        self.request_times = []
        self.last_request_time = 0
        self.backoff_multiplier = 1

    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        with self.lock:
            current_time = time.time()

            # Clean old requests (older than 1 hour)
            self.request_times = [t for t in self.request_times if current_time - t < 3600]

            # Check minute limit
            recent_requests = [t for t in self.request_times if current_time - t < 60]
            if len(recent_requests) >= self.limits['requests_per_minute']:
                wait_time = 60 - (current_time - recent_requests[0])
                if wait_time > 0:
                    logger.info(f"⏳ Rate limit hit for {self.api_name}, waiting {wait_time:.1f}s")
                    time.sleep(wait_time)

            # Check hour limit
            if len(self.request_times) >= self.limits['requests_per_hour']:
                wait_time = 3600 - (current_time - self.request_times[0])
                if wait_time > 0:
                    logger.warning(f"⚠️ Hourly rate limit hit for {self.api_name}, waiting {wait_time:.1f}s")
                    time.sleep(wait_time)

            # Add jitter to prevent thundering herd
            jitter = random.uniform(0.1, 0.5)
            time.sleep(jitter)

            # Record this request
            self.request_times.append(current_time)
            self.last_request_time = current_time

    def handle_error(self, status_code: int):
        """Handle API errors with exponential backoff"""
        with self.lock:
            if status_code in [429, 503]:  # Rate limit or service unavailable
                self.backoff_multiplier = min(self.backoff_multiplier * 2, 32)
                wait_time = self.backoff_multiplier * random.uniform(1, 3)
                logger.warning(f"⚠️ {self.api_name} rate limited ({status_code}), backing off for {wait_time:.1f}s")
                time.sleep(wait_time)
            elif status_code == 200:
                self.backoff_multiplier = max(1, self.backoff_multiplier // 2)

# Setup verbose logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(OUTPUT_DIR, "bulk_scan_api.log"), encoding="utf-8"), 
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add a custom exception handler for clean error reporting
def log_error_with_context(logger, error, context=""):
    """Log errors with essential context"""
    logger.error(f"❌ {context}: {str(error)}")
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Stack trace: {traceback.format_exc()}")

class VirusTotalScanner:
    def __init__(self, api_keys: List[str]):
        if not api_keys:
            logger.warning("⚠️ No VirusTotal API keys provided. Scanner will be disabled.")
            self.api_keys = []
            return

        self.api_keys = api_keys
        self.base_url = "https://www.virustotal.com/api/v3/files/"

        self.key_cycler = cycle(self.api_keys)
        self.key_lock = threading.Lock()

        self.rate_limiters = {
            key: ThreadSafeRateLimiter(f'virustotal-{key[:4]}') for key in self.api_keys
        }

    def get_next_key_and_limiter(self) -> Optional[tuple[str, ThreadSafeRateLimiter]]:
        if not self.api_keys:
            return None
        with self.key_lock:
            key = next(self.key_cycler)
        return key, self.rate_limiters[key]

    def extract_comprehensive_data(self, data: Dict) -> Dict:
        """Extract ALL relevant data from VirusTotal API response"""
        stats = data.get("last_analysis_stats", {})
        
        # Basic detection stats
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        undetected_count = stats.get('undetected', 0)
        harmless_count = stats.get('harmless', 0)
        total_detections = malicious_count + suspicious_count
        total_engines = sum(stats.values())
        
        # File information
        file_info = {
            "file_name": data.get("meaningful_name", ""),
            "file_size": data.get("size", 0),
            "file_type": data.get("type_description", ""),
            "magic": data.get("magic", ""),
            "first_submission_date": data.get("first_submission_date", 0),
            "last_analysis_date": data.get("last_analysis_date", 0),
            "reputation": data.get("reputation", 0),
            "tags": ";".join(data.get("tags", [])),
        }
        
        # Threat classification
        threat_class = data.get("popular_threat_classification", {})
        threat_info = {
            "suggested_threat_label": threat_class.get("suggested_threat_label", ""),
            "suggested_threat_names": ";".join(threat_class.get("suggested_threat_names", [])),
            "popular_threat_names": ";".join(threat_class.get("popular_threat_names", [])),
            "popular_threat_category": threat_class.get("popular_threat_category", ""),
        }
        
        # Extract CVEs from multiple sources
        cves = set()
        
        # From YARA rules
        yara_results = data.get("crowdsourced_yara_results", [])
        for yara in yara_results:
            desc = yara.get("description", "")
            if "cve" in desc.lower():
                cves.add(desc)
        
        # From threat labels
        for ref in threat_info["suggested_threat_label"].split():
            if "CVE-" in ref:
                cves.add(ref)
        
        # From behavior reports
        behavior_reports = data.get("crowdsourced_ids_results", [])
        for report in behavior_reports:
            desc = report.get("description", "")
            if "cve" in desc.lower():
                cves.add(desc)
        
        # Network behavior analysis
        network_data = data.get("network", {})
        network_info = {
            "hosts": ";".join(network_data.get("hosts", [])),
            "domains": ";".join(network_data.get("domains", [])),
            "urls": ";".join([url.get("url", "") for url in network_data.get("urls", [])]),
            "dns_requests": ";".join([dns.get("hostname", "") for dns in network_data.get("dns_requests", [])]),
            "http_requests": ";".join([req.get("url", "") for req in network_data.get("http_requests", [])]),
        }
        
        # Extract IPs from network behavior
        ips = set()
        for host in network_data.get("hosts", []):
            if re.match(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", host):
                ips.add(host)
        
        for dns in network_data.get("dns_requests", []):
            if dns.get("ip"):
                ips.add(dns["ip"])
        
        for http_req in network_data.get("http_requests", []):
            if http_req.get("ip"):
                ips.add(http_req["ip"])
        
        # TA Origin Country tracking - use the first IP found as potential TA origin
        ta_origin_country = ""
        ta_origin_region = ""
        ta_origin_city = ""
        if ips:
            # For now, we'll use the first IP as potential TA origin
            # In a more sophisticated implementation, you might want to analyze
            # which IPs are most likely to be the origin based on timing, frequency, etc.
            first_ip = list(ips)[0]
            # This will be populated later in the processing pipeline
            ta_origin_country = f"TA_ORIGIN_{first_ip}"
            ta_origin_region = f"TA_ORIGIN_{first_ip}"
            ta_origin_city = f"TA_ORIGIN_{first_ip}"
        
        # PE file analysis (if applicable)
        pe_info = {}
        if data.get("pe_info"):
            pe_data = data["pe_info"]
            pe_info = {
                "pe_architecture": pe_data.get("architecture", ""),
                "pe_compilation_date": pe_data.get("compilation_date", ""),
                "pe_entry_point": pe_data.get("entry_point", ""),
                "pe_image_base": pe_data.get("image_base", ""),
                "pe_subsystem": pe_data.get("subsystem", ""),
                "pe_sections": len(pe_data.get("sections", [])),
                "pe_imports": ";".join([imp.get("dll_name", "") for imp in pe_data.get("imports", [])]),
                "pe_exports": ";".join([exp.get("name", "") for exp in pe_data.get("exports", [])]),
            }
        
        # Behavior analysis
        behavior_info = {}
        if data.get("crowdsourced_ids_results"):
            behaviors = []
            for behavior in data["crowdsourced_ids_results"]:
                behaviors.append(behavior.get("description", ""))
            behavior_info = {
                "behavior_tags": ";".join(behaviors),
                "behavior_count": len(behaviors),
            }
        
        # Sandbox analysis
        sandbox_info = {}
        if data.get("sandbox_verdicts"):
            sandbox_data = data["sandbox_verdicts"]
            sandbox_info = {
                "sandbox_verdicts": ";".join([f"{k}:{v}" for k, v in sandbox_data.items()]),
                "sandbox_count": len(sandbox_data),
            }
        
        # Capabilities analysis
        capabilities = data.get("capabilities_tags", [])
        capabilities_info = {
            "capabilities": ";".join(capabilities),
            "capabilities_count": len(capabilities),
        }
        
        # Sigma rules
        sigma_rules = data.get("sigma_analysis_results", [])
        sigma_info = {
            "sigma_rules": ";".join([rule.get("title", "") for rule in sigma_rules]),
            "sigma_count": len(sigma_rules),
        }
        
        # YARA rules
        yara_info = {
            "yara_rules": ";".join([yara.get("rule_name", "") for yara in yara_results]),
            "yara_count": len(yara_results),
        }
        
        # Packer analysis
        packer_info = {}
        if data.get("packers"):
            packer_info = {
                "packers": ";".join(data["packers"]),
                "packer_count": len(data["packers"]),
            }
        
        # Compilation analysis
        compilation_info = {}
        if data.get("compilation_date"):
            compilation_info = {
                "compilation_date": data["compilation_date"],
                "compilation_timestamp": data.get("compilation_timestamp", ""),
            }
        
        # Assembly analysis
        assembly_info = {}
        if data.get("assembly"):
            assembly_data = data["assembly"]
            assembly_info = {
                "assembly_instructions": assembly_data.get("instructions", ""),
                "assembly_functions": ";".join([func.get("name", "") for func in assembly_data.get("functions", [])]),
            }
        
        # Comprehensive result
        result = {
            # Basic info
            "hash": data.get("sha256", ""),
            "md5": data.get("md5", ""),
            "sha1": data.get("sha1", ""),
            "sha256": data.get("sha256", ""),  # Explicit SHA-256 field
            
            # Detection stats
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "undetected_count": undetected_count,
            "harmless_count": harmless_count,
            "total_detections": total_detections,
            "total_engines": total_engines,
            "detection_ratio": f"{total_detections}/{total_engines}" if total_engines > 0 else "0/0",
            
            # File info
            **file_info,
            
            # Threat classification
            **threat_info,
            
            # TA Origin Country tracking
            "ta_origin_country": ta_origin_country,
            "ta_origin_region": ta_origin_region,
            "ta_origin_city": ta_origin_city,
            
            # Network analysis
            **network_info,
            "ips": list(ips),
            "cves": list(cves),
            
            # PE analysis
            **pe_info,
            
            # Behavior analysis
            **behavior_info,
            
            # Sandbox analysis
            **sandbox_info,
            
            # Capabilities
            **capabilities_info,
            
            # Sigma rules
            **sigma_info,
            
            # YARA rules
            **yara_info,
            
            # Packer analysis
            **packer_info,
            
            # Compilation info
            **compilation_info,
            
            # Assembly info
            **assembly_info,
            
            # Metadata
            "source_api": "virustotal",
            "analysis_date": datetime.now().isoformat(),
        }
        
        return result

    def check_hash(self, h: str) -> Dict:
        key_info = self.get_next_key_and_limiter()
        if not key_info:
            return {"hash": h, "error": "No API key configured", "source_api": "virustotal"}
        api_key, rate_limiter = key_info

        rate_limiter.wait_if_needed()

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        url = self.base_url + h

        try:
            logger.info(f"🔍 Scanning hash: {h[:8]}... with key {api_key[:4]}...")

            response = requests.get(url, headers=headers, timeout=30)
            rate_limiter.handle_error(response.status_code)

            if response.status_code == 200:
                obj = response.json()
                data = obj.get("data", {}).get("attributes", {})
                
                # Extract comprehensive data
                result = self.extract_comprehensive_data(data)
                result["hash"] = h  # Ensure hash is set correctly
                
                # Log summary
                total_detections = result.get("total_detections", 0)
                total_engines = result.get("total_engines", 0)
                cves_count = len(result.get("cves", []))
                ips_count = len(result.get("ips", []))
                behaviors_count = result.get("behavior_count", 0)
                capabilities_count = result.get("capabilities_count", 0)
                
                logger.info(f"✅ {h[:8]}... - {total_detections}/{total_engines} detections, {cves_count} CVEs, {ips_count} IPs, {behaviors_count} behaviors, {capabilities_count} capabilities")
                
                return result
            elif response.status_code == 404:
                logger.warning(f"⚠️  Hash not found: {h[:8]}...")
                return {"hash": h, "error": "Not found", "source_api": "virustotal"}
            else:
                logger.error(f"❌ VT API error {response.status_code}: {h[:8]}...")
                return {"hash": h, "error": f"{response.status_code} {response.text}", "source_api": "virustotal"}
        except Exception as e:
            log_error_with_context(logger, e, f"VT scan {h[:8]}...")
            return {"hash": h, "error": str(e), "source_api": "virustotal"}


class CVELookup:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def get_cve(self, cve_id: str) -> Dict:
        try:
            results = nvdlib.searchCVE(cveId=cve_id, key=self.api_key)
            if not results:
                return {"cve_id": cve_id, "error": "CVE not found", "source_api": "cve"}
            r = results[0]
            published = getattr(r, 'published', None)
            if published is None:
                published = getattr(r, 'publishedDate', None)
            
            # Enhanced CVE data
            result = {
                "cve_id": cve_id,
                "score": r.score[1] if r.score else None,
                "severity": r.score[2] if r.score else None,
                "vector": getattr(r, 'v31vector', None) or getattr(r, 'v30vector', None) or getattr(r, 'v2vector', None),
                "published": str(published) if published else None,
                "description": (r.descriptions[0].value if getattr(r, 'descriptions', []) else ""),
                "references": ";".join([ref.url for ref in getattr(r, 'references', [])]) if getattr(r, 'references', []) else "",
                "cwe": ";".join([cwe.name for cwe in getattr(r, 'cwe', [])]) if getattr(r, 'cwe', []) else "",
                "source_api": "cve"
            }
            return result
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return {"cve_id": cve_id, "error": str(e), "source_api": "cve"}


class AbuseIPDB:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip: str):
        try:
            response = requests.get(
                self.base_url,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}
            )
            if response.ok:
                data = response.json().get('data', {})
                hostnames = data.get("hostnames", [])
                return {
                    "ip": ip,
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "countryCode": data.get("countryCode"),
                    "domain": data.get("domain"),
                    "hostnames": ";".join(hostnames) if hostnames else "",
                    "totalReports": data.get("totalReports"),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "isp": data.get("isp"),
                    "usageType": data.get("usageType"),
                    "source_api": "abuseipdb"
                }
            else:
                return {"ip": ip, "error": response.text, "source_api": "abuseipdb"}
        except Exception as e:
            return {"ip": ip, "error": str(e), "source_api": "abuseipdb"}


class IPGeolocation:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = "http://api.ipapi.com" if not api_key else "https://api.ipapi.com"

    def get_location(self, ip: str):
        try:
            url = f"{self.base_url}/{ip}"
            params = {"access_key": self.api_key} if self.api_key else {}
            response = requests.get(url, params=params, timeout=10)
            
            if response.ok:
                data = response.json()
                connection_data = data.get("connection", {})
                return {
                    "ip": ip,
                    "country": data.get("country_name"),
                    "region": data.get("region_name"),
                    "city": data.get("city"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "isp": connection_data.get("isp"),
                    "organization": connection_data.get("organization"),
                    "asn": connection_data.get("asn"),
                    "asn_label": f"AS{connection_data.get('asn', '')} - {connection_data.get('organization', '')}",
                    "timezone": data.get("timezone", {}).get("id"),
                    "source_api": "ipapi"
                }
            else:
                return {"ip": ip, "error": response.text, "source_api": "ipapi"}
        except Exception as e:
            return {"ip": ip, "error": str(e), "source_api": "ipapi"}


class ThreatFoxScanner:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"

    def search_hash(self, file_hash: str):
        try:
            payload = {
                "query": "search_hash",
                "hash": file_hash
            }
            response = requests.post(self.base_url, json=payload, timeout=10)
            
            if response.ok:
                data = response.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    threat_data = data["data"][0]
                    return {
                        "hash": file_hash,
                        "malware_family": threat_data.get("malware_family"),
                        "malware_type": threat_data.get("malware_type"),
                        "platform": threat_data.get("platform"),
                        "first_seen": threat_data.get("first_seen"),
                        "last_seen": threat_data.get("last_seen"),
                        "status": threat_data.get("status"),
                        "source_api": "threatfox"
                    }
                else:
                    return {"hash": file_hash, "error": "Not found in ThreatFox", "source_api": "threatfox"}
            else:
                return {"hash": file_hash, "error": response.text, "source_api": "threatfox"}
        except Exception as e:
            return {"hash": file_hash, "error": str(e), "source_api": "threatfox"}


def scanner_process(folder: str, hashes_list: List[str]) -> List[Dict]:
    vt = VirusTotalScanner(VT_API_KEYS)
    cve = CVELookup(NVD_API_KEYS[0] if NVD_API_KEYS else None)
    ip_geo = IPGeolocation(IPAPI_KEYS[0] if IPAPI_KEYS else "")
    
    vt_results, geo_results, cve_results = [], [], []
    hash_set = set()
    if hashes_list:
        hash_set = set(hashes_list)
    else:
        for root, _, files in os.walk(folder):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    h = hashlib.sha256(open(path, 'rb').read()).hexdigest()
                    hash_set.add(h)
                except Exception as e:
                    logger.error(f"Error hashing {path}: {e}")
    
    for h in hash_set:
        # VirusTotal scan
        vt_result = vt.check_hash(h)
        vt_results.append(vt_result)
        
        # Get geolocation for IPs found in VT
        for ip in vt_result.get('ips', []):
            geo_result = ip_geo.get_location(ip)
            geo_results.append(geo_result)
        
        # CVE lookups from VT results
        for cve_id in vt_result.get('cves', []):
            cve_data = cve.get_cve(cve_id)
            cve_results.append(cve_data)
    
    merged = vt_results + geo_results + cve_results
    return merged


from fastapi import BackgroundTasks

app = FastAPI(
    title="Malwize - The Smart Way to Outsmart Malware",
    description="Comprehensive malware intelligence platform with multi-source threat analysis, bulk scanning, and detailed reporting.",
    version="4.1"
)

# Ensure CORS middleware is set up correctly (move to top if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev, allow all. Restrict in prod!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def merge_results(all_results, geo_results=None, cve_results=None):
    # If all_results is a list of lists, flatten it
    if all_results and isinstance(all_results[0], list):
        merged = []
        for result_list in all_results:
            merged.extend(result_list)
    else:
        merged = all_results
    
    # Add any additional results if provided
    if geo_results:
        merged.extend(geo_results)
    if cve_results:
        merged.extend(cve_results)
    
    merged_json_path = os.path.join(OUTPUT_DIR, "merged_results.json")
    with open(merged_json_path, "w", encoding="utf-8") as mf:
        for entry in merged:
            mf.write(json.dumps(entry, ensure_ascii=False, indent=2) + "\n")
    
    # Updated CSV columns to match user requirements
    pretty_columns = [
        # Source identification
        "source_api", "hash", "error",
        
        # File Hash Indicators (MD5, SHA-1, SHA-256)
        "md5", "sha1", "sha256",
        
        # Threat Information (Attack group name, Malware name, etc.)
        "suggested_threat_label", "suggested_threat_names", "popular_threat_names", 
        "popular_threat_category", "malware_family", "malware_type",
        
        # TA Origin Country (from IP Geolocation)
        "ta_origin_country", "ta_origin_region", "ta_origin_city",
        
        # Autonomous System Label/Domain
        "asn", "asn_label", "domain", "hostnames",
        
        # IP/Domain/URL Country
        "country", "region", "city", "latitude", "longitude",
        
        # VirusTotal Data
        "malicious_count", "suspicious_count", "total_detections", "total_engines",
        "detection_ratio", "reputation",
        
        # AbuseIPDB Data
        "abuseConfidenceScore", "totalReports", "lastReportedAt", "usageType",
        
        # Network Indicators
        "ips", "domains", "urls", "cves",
        
        # Additional Threat Intelligence
        "behavior_tags", "capabilities", "yara_rules", "sigma_rules",
        
        # File Information
        "file_name", "file_size", "file_type", "magic",
        
        # CVE Data
        "cve_id", "score", "severity", "vector", "published", "description"
    ]
    
    def prettify_row(d):
        row = {col: "" for col in pretty_columns}
        for k, v in d.items():
            if k == "cves" and isinstance(v, list):
                row["cves"] = ";".join(v)
            elif k == "ips" and isinstance(v, list):
                row["ips"] = ";".join(v)
            elif k == "domains" and isinstance(v, list):
                row["domains"] = ";".join(v)
            elif k == "urls" and isinstance(v, list):
                row["urls"] = ";".join(v)
            elif k == "behavior_tags" and isinstance(v, list):
                row["behavior_tags"] = ";".join(v)
            elif k == "capabilities" and isinstance(v, list):
                row["capabilities"] = ";".join(v)
            elif k == "yara_rules" and isinstance(v, list):
                row["yara_rules"] = ";".join(v)
            elif k == "sigma_rules" and isinstance(v, list):
                row["sigma_rules"] = ";".join(v)
            elif k in pretty_columns:
                row[k] = v
        return row
    
    pretty_merged = [prettify_row(entry) for entry in merged]
    merged_csv_path = os.path.join(OUTPUT_DIR, "merged_results.csv")
    with open(merged_csv_path, "w", newline='', encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=pretty_columns)
        writer.writeheader()
        for row in pretty_merged:
            writer.writerow(row)
    return merged

def scan_hashes_optimized(hash_list: List[str], search_folder=None) -> List[Dict]:
    """Optimized hash scanning with parallel processing and caching"""
    
    # Load already scanned hashes
    scanned_hashes = load_scanned_hashes(os.path.join(OUTPUT_DIR, "merged_results.csv"))
    
    # Filter out already scanned hashes
    new_hashes = filter_new_hashes(hash_list, scanned_hashes)
    
    if not new_hashes:
        logger.info("✅ All hashes have already been scanned!")
        return []
    
    # Initialize scanners with multiple API keys
    vt_scanner = VirusTotalScanner(VT_API_KEYS)
    cve_lookup = CVELookup(NVD_API_KEYS[0] if NVD_API_KEYS else None)
    ip_geo = IPGeolocation(IPAPI_KEYS[0] if IPAPI_KEYS else "")
    abuse_ipdb = AbuseIPDB(ABUSEIPDB_API_KEYS[0] if ABUSEIPDB_API_KEYS else "")
    threatfox = ThreatFoxScanner(THREATFOX_API_KEY)
    
    # Create connection pool for better performance
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=30,
        pool_maxsize=100,
        max_retries=3,
        pool_block=False
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    # Cache for avoiding duplicate API calls
    cache = {
        'ips': {},
        'cves': {},
        'hashes': {}
    }
    
    results = []
    
    def process_hash_with_cache(h: str) -> List[Dict]:
        """Process hash with intelligent caching"""
        hash_results = []
        
        # Check cache first
        if h in cache['hashes']:
            logger.info(f"💾 Using cached result for {h[:8]}...")
            return cache['hashes'][h]
        
        try:
        # VirusTotal scan
            vt_result = vt_scanner.check_hash(h)
            hash_results.append(vt_result)
            
            # Extract unique IPs and CVEs
            ips = list(set(vt_result.get('ips', [])))
            cves = list(set(vt_result.get('cves', [])))
            
            # Process IPs with caching and TA Origin Country tracking
            ta_origin_data = {}
            for ip in ips:
                if ip not in cache['ips']:
                    # Parallel IP processing
                    ip_results = []
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        geo_future = executor.submit(ip_geo.get_location, ip)
                        abuse_future = executor.submit(abuse_ipdb.check_ip, ip)
                        
                        try:
                            geo_result = geo_future.result(timeout=30)
                            if not geo_result.get('error'):
                                ip_results.append(geo_result)
                                # Store TA Origin Country data for the first IP (potential origin)
                                if not ta_origin_data:
                                    ta_origin_data = {
                                        "ta_origin_country": geo_result.get("country", ""),
                                        "ta_origin_region": geo_result.get("region", ""),
                                        "ta_origin_city": geo_result.get("city", ""),
                                        "asn_label": geo_result.get("asn_label", "")
                                    }
                        except:
                            pass
                        
                        try:
                            abuse_result = abuse_future.result(timeout=30)
                            if not abuse_result.get('error'):
                                ip_results.append(abuse_result)
                        except:
                            pass
                    
                    cache['ips'][ip] = ip_results
                
                hash_results.extend(cache['ips'][ip])
            
            # Update VirusTotal result with TA Origin Country data
            if ta_origin_data and vt_result.get('source_api') == 'virustotal':
                vt_result.update(ta_origin_data)
            
            # Process CVEs with caching
            for cve in cves:
                if cve not in cache['cves']:
                    try:
                        cve_result = cve_lookup.get_cve(cve)
                        cache['cves'][cve] = cve_result
                    except:
                        cache['cves'][cve] = {"cve_id": cve, "error": "Processing failed", "source_api": "cve"}
                
                if not cache['cves'][cve].get('error'):
                    hash_results.append(cache['cves'][cve])
            
            # ThreatFox lookup
            try:
                threatfox_result = threatfox.search_hash(h)
                if not threatfox_result.get('error'):
                    hash_results.append(threatfox_result)
            except:
                pass
            
            # Cache the complete result
            cache['hashes'][h] = hash_results
            return hash_results
            
        except Exception as e:
            logger.error(f"❌ Failed to process hash {h[:8]}...: {str(e)}")
            return [{"hash": h, "error": str(e), "source_api": "batch_processor"}]
    
    # Process in optimized batches
    batch_size = 20  # Smaller batch size for API to avoid timeouts
    total_batches = (len(new_hashes) + batch_size - 1) // batch_size
    
    logger.info(f"🚀 Starting optimized batch processing: {len(new_hashes)} hashes in {total_batches} batches")
    
    start_time = time.time()
    
    for batch_num in range(total_batches):
        start_idx = batch_num * batch_size
        end_idx = min(start_idx + batch_size, len(new_hashes))
        current_batch = new_hashes[start_idx:end_idx]
        
        logger.info(f"📦 Processing batch {batch_num + 1}/{total_batches} ({len(current_batch)} hashes)")
        
        # Process current batch in parallel
        with ThreadPoolExecutor(max_workers=min(5, len(current_batch))) as executor:
            batch_futures = {
                executor.submit(process_hash_with_cache, h): h 
                for h in current_batch
            }
            
            for future in as_completed(batch_futures):
                hash_value = batch_futures[future]
                try:
                    batch_results = future.result(timeout=120)  # 2 minute timeout
                    results.extend(batch_results)
                except Exception as e:
                    logger.error(f"❌ Batch processing failed for {hash_value[:8]}...: {str(e)}")
                    results.append({
                        "hash": hash_value, 
                        "error": f"Batch processing failed: {str(e)}", 
                        "source_api": "batch_processor"
                    })
        
        # Progress update
        processed = len([r for r in results if r.get('hash')])
        elapsed = time.time() - start_time
        rate = processed / elapsed if elapsed > 0 else 0
        remaining = len(new_hashes) - processed
        eta = remaining / rate if rate > 0 else 0
        
        logger.info(f"📊 Overall progress: {processed}/{len(new_hashes)} hashes "
                   f"({rate:.2f} hashes/sec, ETA: {eta:.1f}s)")
    
    session.close()
    
    total_time = time.time() - start_time
    logger.info(f"✅ Optimized batch processing completed in {total_time:.2f}s")
    logger.info(f" Performance: {len(new_hashes)} hashes, {len(results)} results, "
               f"{len(cache['ips'])} unique IPs, {len(cache['cves'])} unique CVEs")
    
    return results

def scan_hashes(hash_list: List[str], search_folder=None) -> List[Dict]:
    """Legacy scan function - now uses optimized version"""
    return scan_hashes_optimized(hash_list, search_folder)

@app.post("/upload/folder_zip/")
async def upload_folder_zip(file: UploadFile = File(...)):
    tempdir = tempfile.mkdtemp(dir=UPLOAD_DIR)
    filename = file.filename or "uploaded_file.zip"
    zip_path = os.path.join(tempdir, filename)
    with open(zip_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(tempdir)
    # Gather hashes
    hash_list = []
    for root, _, files in os.walk(tempdir):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                h = hashlib.sha256(open(path, 'rb').read()).hexdigest()
                hash_list.append(h)
            except Exception as e:
                logger.error(f"Error hashing {path}: {e}")
    results = scan_hashes(hash_list, search_folder=tempdir)
    
    # Save results to files for frontend access
    if results:
        # Separate results by source for merge_results function
        vt_results = [r for r in results if r.get('source_api') == 'virustotal']
        geo_results = [r for r in results if r.get('source_api') == 'ipapi']
        cve_results = [r for r in results if r.get('source_api') == 'cve']
        abuse_results = [r for r in results if r.get('source_api') == 'abuseipdb']
        threatfox_results = [r for r in results if r.get('source_api') == 'threatfox']
        
        # Combine all results for merging
        all_results = vt_results + geo_results + cve_results + abuse_results + threatfox_results
        merge_results(all_results, [], [])  # Use existing results, no need to separate again
    
    shutil.rmtree(tempdir)
    return {
        "results": results,
        "csv_file": "/download/csv",
        "json_file": "/download/json"
    }

@app.post("/upload/hashes_txt/")
async def upload_hashes_txt(file: UploadFile = File(...)):
    hashes = []
    for line in (await file.read()).decode('utf-8').splitlines():
        h = line.strip()
        if h:
            hashes.append(h)
    results = scan_hashes(hashes)
    
    # Save results to files for frontend access
    if results:
        # Separate results by source for merge_results function
        vt_results = [r for r in results if r.get('source_api') == 'virustotal']
        geo_results = [r for r in results if r.get('source_api') == 'ipapi']
        cve_results = [r for r in results if r.get('source_api') == 'cve']
        abuse_results = [r for r in results if r.get('source_api') == 'abuseipdb']
        threatfox_results = [r for r in results if r.get('source_api') == 'threatfox']
        
        # Combine all results for merging
        all_results = vt_results + geo_results + cve_results + abuse_results + threatfox_results
        merge_results(all_results, [], [])  # Use existing results, no need to separate again
    
    return {
        "results": results,
        "csv_file": "/download/csv",
        "json_file": "/download/json"
    }

@app.post("/upload/hashes_csv/")
async def upload_hashes_csv(file: UploadFile = File(...), hash_column: str = Form("hash")):
    df = pd.read_csv(file.file)
    if hash_column not in df.columns:
        return JSONResponse(status_code=400, content={"error": f"No column '{hash_column}' found."})
    hashes = list(df[hash_column].dropna().astype(str))
    results = scan_hashes(hashes)
    
    # Save results to files for frontend access
    if results:
        # Separate results by source for merge_results function
        vt_results = [r for r in results if r.get('source_api') == 'virustotal']
        geo_results = [r for r in results if r.get('source_api') == 'ipapi']
        cve_results = [r for r in results if r.get('source_api') == 'cve']
        abuse_results = [r for r in results if r.get('source_api') == 'abuseipdb']
        threatfox_results = [r for r in results if r.get('source_api') == 'threatfox']
        
        # Combine all results for merging
        all_results = vt_results + geo_results + cve_results + abuse_results + threatfox_results
        merge_results(all_results, [], [])  # Use existing results, no need to separate again
    
    return {
        "results": results,
        "csv_file": "/download/csv",
        "json_file": "/download/json"
    }

@app.post("/scan/from_spreadsheet/")
async def scan_from_spreadsheet(spreadsheet_url: str = Form(...), column: str = Form("hash")):
    if "docs.google.com/spreadsheets" in spreadsheet_url:
        if "export?format=csv" in spreadsheet_url:
            csv_url = spreadsheet_url
        elif "/edit" in spreadsheet_url:
            csv_url = spreadsheet_url.split("/edit")[0] + "/export?format=csv"
        else:
            return JSONResponse(status_code=400, content={"error": "Invalid Google Sheets URL"})
        df = pd.read_csv(csv_url)
    elif spreadsheet_url.endswith(".csv"):
        df = pd.read_csv(spreadsheet_url)
    elif spreadsheet_url.endswith(".xlsx"):
        df = pd.read_excel(spreadsheet_url)
    else:
        return JSONResponse(status_code=400, content={"error": "Unsupported spreadsheet format"})
    if column not in df.columns:
        return JSONResponse(status_code=400, content={"error": f"Column '{column}' not found in spreadsheet"})
    hashes = list(df[column].dropna().astype(str))
    results = scan_hashes(hashes)
    
    # Save results to files for frontend access
    if results:
        # Separate results by source for merge_results function
        vt_results = [r for r in results if r.get('source_api') == 'virustotal']
        geo_results = [r for r in results if r.get('source_api') == 'ipapi']
        cve_results = [r for r in results if r.get('source_api') == 'cve']
        abuse_results = [r for r in results if r.get('source_api') == 'abuseipdb']
        threatfox_results = [r for r in results if r.get('source_api') == 'threatfox']
        
        # Combine all results for merging
        all_results = vt_results + geo_results + cve_results + abuse_results + threatfox_results
        merge_results(all_results, [], [])  # Use existing results, no need to separate again
    
    return {
        "results": results,
        "csv_file": "/download/csv",
        "json_file": "/download/json"
    }

@app.get("/download/csv")
def download_csv():
    merged_csv_path = os.path.join(OUTPUT_DIR, "merged_results.csv")
    if not os.path.exists(merged_csv_path):
        return JSONResponse(status_code=404, content={"error": "CSV file not found"})
    return FileResponse(merged_csv_path, filename="merged_results.csv", media_type="text/csv")

@app.get("/download/json")
def download_json():
    merged_json_path = os.path.join(OUTPUT_DIR, "merged_results.json")
    if not os.path.exists(merged_json_path):
        return JSONResponse(status_code=404, content={"error": "JSON file not found"})
    return FileResponse(merged_json_path, filename="merged_results.json", media_type="application/json")

def load_scanned_hashes(csv_path: str) -> set:
    """Load already scanned hashes from CSV file to avoid re-scanning"""
    if Path(csv_path).exists():
        try:
            df = pd.read_csv(csv_path)
            # Check for hash column in various possible names
            hash_columns = ['hash', 'sha256', 'file_hash', 'hash_value']
            for col in hash_columns:
                if col in df.columns:
                    scanned_hashes = set(df[col].dropna().astype(str))
                    logger.info(f"📋 Loaded {len(scanned_hashes)} already scanned hashes from {csv_path}")
                    return scanned_hashes
            logger.warning(f"⚠️ No hash column found in {csv_path}")
        except Exception as e:
            logger.warning(f"⚠️ Could not load scanned hashes: {e}")
    return set()

def filter_new_hashes(hash_list: List[str], scanned_hashes: set) -> List[str]:
    """Filter out already scanned hashes"""
    new_hashes = [h for h in hash_list if h not in scanned_hashes]
    skipped_count = len(hash_list) - len(new_hashes)
    
    if skipped_count > 0:
        logger.info(f"⏭️ Skipping {skipped_count} already scanned hashes")
        logger.info(f"🔍 Processing {len(new_hashes)} new hashes")
    else:
        logger.info(f"🔍 Processing all {len(new_hashes)} hashes (no duplicates found)")
    
    return new_hashes

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)

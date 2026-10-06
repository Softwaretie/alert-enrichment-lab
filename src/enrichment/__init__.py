"""Aggregates IOC enrichment across VirusTotal, AbuseIPDB, and urlscan.io."""
import logging
from concurrent.futures import ThreadPoolExecutor

from src.enrichment.abuseipdb import AbuseIPDBClient
from src.enrichment.urlscan import UrlscanClient
from src.enrichment.virustotal import VirusTotalClient
from src.ioc_extractor import ExtractedIOCs

logger = logging.getLogger(__name__)

# Caps keep a single noisy email from burning the whole VirusTotal free-tier
# rate budget (4 req/min) on one alert.
_MAX_PER_CATEGORY = 5

# urlscan.io scans take ~5-45s each (submit + poll), far slower than a
# VirusTotal lookup, so sandbox fewer URLs per email to bound latency.
_MAX_URLSCAN_PER_EMAIL = 2


def enrich(iocs: ExtractedIOCs, vt: VirusTotalClient, abuseipdb: AbuseIPDBClient,
           urlscan: UrlscanClient = None) -> dict:
    results = {"urls": {}, "domains": {}, "ips": {}, "hashes": {}}
    urls_to_scan = iocs.urls[:_MAX_PER_CATEGORY]

    # urlscan.io scans are independent of VirusTotal and each other, so kick
    # them all off up front and let them run in the background while the
    # (rate-limited, sequential) VirusTotal lookups below proceed, instead of
    # waiting on each scan one at a time. This overlaps two unrelated waits
    # instead of stacking them, which is where most of the per-email latency
    # comes from.
    urlscan_futures = {}
    if urlscan is not None:
        executor = ThreadPoolExecutor(max_workers=_MAX_URLSCAN_PER_EMAIL)
        for url in urls_to_scan[:_MAX_URLSCAN_PER_EMAIL]:
            logger.info("Sandboxing URL with urlscan.io: %s", url)
            urlscan_futures[url] = executor.submit(urlscan.scan_url, url)

    for url in urls_to_scan:
        logger.info("Checking URL with VirusTotal: %s", url)
        results["urls"][url] = {"virustotal": vt.check_url(url)}

    if urlscan_futures:
        for url, future in urlscan_futures.items():
            results["urls"][url]["urlscan"] = future.result()
        executor.shutdown()

    for domain in iocs.domains[:_MAX_PER_CATEGORY]:
        logger.info("Checking domain with VirusTotal: %s", domain)
        results["domains"][domain] = {"virustotal": vt.check_domain(domain)}

    for ip in iocs.ips[:_MAX_PER_CATEGORY]:
        logger.info("Checking IP with VirusTotal + AbuseIPDB: %s", ip)
        results["ips"][ip] = {
            "virustotal": vt.check_ip(ip),
            "abuseipdb": abuseipdb.check_ip(ip),
        }

    for file_hash in iocs.hashes[:_MAX_PER_CATEGORY]:
        logger.info("Checking hash with VirusTotal: %s", file_hash)
        results["hashes"][file_hash] = {"virustotal": vt.check_hash(file_hash)}

    return results

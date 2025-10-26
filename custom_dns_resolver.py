#!/usr/bin/env python3
import dns.query
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver # Added for Part E
import time
import logging
import json

# Setup the JSON logger
log_file_handler = logging.FileHandler('dns_resolver.log')
log_file_handler.setFormatter(logging.Formatter('%(message)s'))
logger = logging.getLogger('CustomDNSResolver')
logger.setLevel(logging.INFO)
logger.addHandler(log_file_handler)
logger.propagate = False

# A root server to start our queries
ROOT_SERVER = '198.41.0.4' # a.root-servers.net

# --- PART F: CACHING ---
# Simple dictionary cache with TTL
CACHE = {}
DEFAULT_TTL = 300 # Default cache time: 5 minutes

def resolve_iterative(domain_name, enable_cache=False):
    """
    Performs an iterative DNS lookup (PART D)
    with optional caching (PART F).
    """
    total_start_time = time.time()
    
    # --- PART F: Cache Check ---
    if enable_cache:
        if domain_name in CACHE:
            entry = CACHE[domain_name]
            # Check if cache entry is still valid
            if (time.time() - entry['timestamp']) < entry['ttl']:
                log_entry = {
                    "timestamp": time.time(),
                    "domain_name_queried": domain_name,
                    "resolution_mode": "Iterative",
                    "dns_server_ip_contacted": "CACHE",
                    "step_of_resolution": "Cache",
                    "response_or_referral_received": f"ANSWER: {entry['ip']}",
                    "round_trip_time_to_that_server": 0,
                    "total_time_to_resolution": (time.time() - total_start_time) * 1000,
                    "cache_status": "HIT"
                }
                logger.info(json.dumps(log_entry))
                return entry['ip'], log_entry["total_time_to_resolution"]

    # --- PART D: Iterative Lookup (Cache MISS) ---
    nameserver_ip = ROOT_SERVER
    qname = dns.name.from_text(domain_name)
    step = 'Root'
    
    cache_status = "MISS" if enable_cache else "N/A"

    while True:
        query = dns.message.make_query(qname, dns.rdatatype.A)
        log_entry = {
            "timestamp": time.time(),
            "domain_name_queried": domain_name,
            "resolution_mode": "Iterative",
            "dns_server_ip_contacted": nameserver_ip,
            "step_of_resolution": step,
            "cache_status": cache_status
        }

        try:
            start_rtt = time.time()
            response = dns.query.udp(query, nameserver_ip, timeout=2)
            rtt = (time.time() - start_rtt) * 1000 # RTT in ms
            log_entry["round_trip_time_to_that_server"] = rtt

            if response.answer:
                ip_address = response.answer[0][0].to_text()
                log_entry["step_of_resolution"] = "Authoritative"
                log_entry["response_or_referral_received"] = f"ANSWER: {ip_address}"
                total_time = (time.time() - total_start_time) * 1000
                log_entry["total_time_to_resolution"] = total_time
                logger.info(json.dumps(log_entry))
                
                # --- PART F: Add to cache ---
                if enable_cache:
                    CACHE[domain_name] = {'ip': ip_address, 'ttl': DEFAULT_TTL, 'timestamp': time.time()}
                
                return ip_address, total_time

            elif response.additional:
                next_ns_ip = response.additional[0][0].to_text()
                log_entry["response_or_referral_received"] = f"REFERRAL to {next_ns_ip}"
                nameserver_ip = next_ns_ip
                step = "TLD" if step == "Root" else "Authoritative"

            elif response.authority:
                ns_name = response.authority[0][0].to_text()
                log_entry["response_or_referral_received"] = f"REFERRAL to {ns_name} (needs glue lookup)"
                try:
                    glue_ip = dns.resolver.resolve(ns_name, 'A')[0].to_text()
                    nameserver_ip = glue_ip
                    step = "TLD" if step == "Root" else "Authoritative"
                except Exception as e:
                    log_entry["response_or_referral_received"] = f"Glue lookup failed: {e}"
                    raise
            else:
                raise Exception("No answer or referral received")

            logger.info(json.dumps(log_entry))

        except Exception as e:
            log_entry["response_or_referral_received"] = f"ERROR: {str(e)}"
            total_time = (time.time() - total_start_time) * 1000
            log_entry["total_time_to_resolution"] = total_time
            logger.error(json.dumps(log_entry))
            return None, total_time

# --- PART E: RECURSIVE RESOLUTION ---
def resolve_recursively(domain_name, enable_cache=False):
    """
    Performs a recursive DNS lookup (PART E)
    with optional caching (PART F).
    """
    total_start_time = time.time()
    log_entry = {
        "timestamp": time.time(),
        "domain_name_queried": domain_name,
        "resolution_mode": "Recursive",
        "step_of_resolution": "N/A (Recursive)"
    }

    try:
        resolver = dns.resolver.Resolver()
        
        # --- PART F: Enable Caching ---
        if enable_cache:
            resolver.cache = dns.resolver.Cache()
        
        start_rtt = time.time()
        answer = resolver.resolve(domain_name, 'A')
        rtt = (time.time() - start_rtt) * 1000

        ip_address = str(answer[0])
        total_time = (time.time() - total_start_time) * 1000
        cache_status = "N/A"
        
        if enable_cache:
            cache_status = "HIT" if answer.from_cache else "MISS"

        log_entry.update({
            "dns_server_ip_contacted": resolver.nameservers[0],
            "response_or_referral_received": f"ANSWER: {ip_address}",
            "round_trip_time_to_that_server": rtt,
            "total_time_to_resolution": total_time,
            "cache_status": cache_status
        })
        logger.info(json.dumps(log_entry))
        return ip_address, total_time

    except Exception as e:
        total_time = (time.time() - total_start_time) * 1000
        log_entry.update({
            "response_or_referral_received": f"ERROR: {str(e)}",
            "total_time_to_resolution": total_time,
            "cache_status": "MISS" if enable_cache else "N/A"
        })
        logger.error(json.dumps(log_entry))
        return None, total_time

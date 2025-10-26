#!/usr/bin/env python3
from scapy.all import PcapReader, DNS, DNSQR
import time
import logging
import concurrent.futures

# --- Number of parallel DNS lookups to run at once ---
MAX_WORKERS = 30

def process_pcap_queries(pcap_file, resolver_function, log_file):
    """
    Reads a pcap packet-by-packet, finds ALL unique queries,
    and runs them through a resolver in PARALLEL.
    
    :param pcap_file: Path to the PCAP file.
    :param resolver_function: The function to call to resolve a domain.
    :param log_file: The specific log file to use for this PCAP run.
    """
    
    # Set the log file for our custom resolver
    resolver_name = resolver_function.__name__
    if 'resolver' in resolver_name: # Check if it's one of our custom ones
        logger = logging.getLogger('CustomDNSResolver')
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        if log_file:
            # IMPORTANT: Add lock for thread-safe logging
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter('%(message)s'))
            logger.addHandler(file_handler)

    print(f"Processing {pcap_file} using {resolver_name}...")
    
    queries = set()
    print(f"Reading {pcap_file} (Full File)...")

    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    try:
                        domain = pkt[DNSQR].qname.decode().rstrip('.')
                        if domain and domain != "localhost":
                            queries.add(domain)
                    except Exception:
                        pass # Ignore malformed packets

    except (FileNotFoundError, Scapy_Exception) as e:
        print(f"Error reading PCAP: {e}")
        return None

    if not queries:
        print("No DNS queries found in PCAP.")
        return None
    
    print(f"Found {len(queries)} unique domains. Now resolving with {MAX_WORKERS} parallel workers...")

    latencies = []
    success_count = 0
    failed_count = 0
    total_start_time = time.time()

    # --- This is the new parallel processing part ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Create a "future" for each domain resolution
        future_to_domain = {executor.submit(resolver_function, domain): domain for domain in queries}
        
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                ip, latency = future.result()
                if ip:
                    success_count += 1
                    latencies.append(latency)
                else:
                    failed_count += 1
            except Exception as exc:
                print(f'{domain} generated an exception: {exc}')
                failed_count += 1
    # -------------------------------------------------
    
    total_run_time = time.time() - total_start_time

    # Calculate metrics
    metrics = {
        "pcap_file": pcap_file,
        "resolver": resolver_name,
        "total_queries": len(queries),
        "successfully_resolved": success_count,
        "failed_resolutions": failed_count,
        "avg_lookup_latency_ms": (sum(latencies) / len(latencies)) if latencies else 0,
        "avg_throughput_qps": len(queries) / total_run_time if total_run_time > 0 else 0
    }
    
    print(f"Processing complete for {pcap_file} in {total_run_time:.2f} seconds.")
    return metrics

#!/usr/bin/env python3
import time
import dns.resolver
import logging
import json
from pcap_processor import process_pcap_queries
from custom_dns_resolver import resolve_iterative, resolve_recursively

# --- Define wrapper functions for our resolvers ---
# This makes it easy to pass them to the pcap_processor

def default_resolver(domain_name):
    """PART B: Wrapper for the system's default (recursive) resolver."""
    try:
        start_time = time.time()
        answer = dns.resolver.resolve(domain_name, 'A')
        latency = (time.time() - start_time) * 1000
        return str(answer[0]), latency
    except Exception:
        return None, (time.time() - start_time) * 1000

def part_d_resolver(domain_name):
    """PART D: Iterative, No Cache"""
    return resolve_iterative(domain_name, enable_cache=False)

def part_e_resolver(domain_name):
    """PART E: Recursive, No Cache"""
    return resolve_recursively(domain_name, enable_cache=False)

def part_f_iterative_resolver(domain_name):
    """PART F (Iterative): Iterative + Cache"""
    return resolve_iterative(domain_name, enable_cache=True)

def part_f_recursive_resolver(domain_name):
    """PART F (Recursive): Recursive + Cache"""
    return resolve_recursively(domain_name, enable_cache=True)


# --- Main execution ---
if __name__ == "__main__":
    PCAP_FILES = [
        'PCAP_1_H1.pcap',
        'PCAP_2_H2.pcap',
        'PCAP_3_H3.pcap',
        'PCAP_4_H4.pcap'
    ]
    
    all_results = {}

    # --- Run Part B (Default Resolver) ---
    print("--- Running Part B (Default System Resolver) ---")
    results_b = []
    for pcap in PCAP_FILES:
        metrics = process_pcap_queries(pcap, default_resolver, log_file=None)
        if metrics: results_b.append(metrics)
    all_results["Part_B_Default"] = results_b
    
    # --- Run Part D (Custom Iterative) ---
    print("\n--- Running Part D (Custom Iterative Resolver, No Cache) ---")
    results_d = []
    for pcap in PCAP_FILES:
        log_filename = f"part_d_{pcap}.log"
        metrics = process_pcap_queries(pcap, part_d_resolver, log_file=log_filename)
        if metrics: results_d.append(metrics)
    all_results["Part_D_Iterative_NoCache"] = results_d

    # --- Run Part E (Custom Recursive) ---
    print("\n--- Running Part E (Custom Recursive Resolver, No Cache) ---")
    results_e = []
    for pcap in PCAP_FILES:
        log_filename = f"part_e_{pcap}.log"
        metrics = process_pcap_queries(pcap, part_e_resolver, log_file=log_filename)
        if metrics: results_e.append(metrics)
    all_results["Part_E_Recursive_NoCache"] = results_e

    # --- Run Part F (Iterative + Cache) ---
    print("\n--- Running Part F (Custom Iterative Resolver, WITH Cache) ---")
    results_f_iter = []
    for pcap in PCAP_FILES:
        log_filename = f"part_f_iterative_{pcap}.log"
        metrics = process_pcap_queries(pcap, part_f_iterative_resolver, log_file=log_filename)
        if metrics: results_f_iter.append(metrics)
    all_results["Part_F_Iterative_Cache"] = results_f_iter

    # --- Run Part F (Recursive + Cache) ---
    print("\n--- Running Part F (Custom Recursive Resolver, WITH Cache) ---")
    results_f_rec = []
    for pcap in PCAP_FILES:
        log_filename = f"part_f_recursive_{pcap}.log"
        metrics = process_pcap_queries(pcap, part_f_recursive_resolver, log_file=log_filename)
        if metrics: results_f_rec.append(metrics)
    all_results["Part_F_Recursive_Cache"] = results_f_rec

    # --- Save comparison results to a file ---
    with open("comparison_results.txt", "w") as f:
        f.write(json.dumps(all_results, indent=2))

    print("\nAnalysis complete.")
    print("All comparison metrics saved to 'comparison_results.txt'")
    print("Detailed logs saved to 'part_d_*.log', 'part_e_*.log', and 'part_f_*.log' files.")

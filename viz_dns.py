#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import json

LOG_FILE = 'part_d_PCAP_1_H1.pcap.log'

def create_plots():
    print(f"Loading log file: {LOG_FILE}")
    # Load the JSON log data
    data = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                data.append(json.loads(line))
    except FileNotFoundError:
        print(f"Error: Log file not found at {LOG_FILE}")
        print("Please run 'main_assignment.py' first.")
        return

    if not data:
        print("Log file is empty.")
        return

    df = pd.DataFrame(data)

    # Get the first 10 URLs that were queried
    urls_to_plot = df['domain_name_queried'].unique()[:10]
    plot_df = df[df['domain_name_queried'].isin(urls_to_plot)]

    # 1. Plot: Total number of DNS servers visited
    # We count the unique IPs contacted for each query
    servers_visited = plot_df.groupby('domain_name_queried')['dns_server_ip_contacted'].nunique()
    
    plt.figure(figsize=(12, 6))
    servers_visited.plot(kind='bar', rot=45)
    plt.title('Total DNS Servers Visited per Query (First 10 URLs)')
    plt.xlabel('Domain Name')
    plt.ylabel('Number of Servers')
    plt.tight_layout()
    plt.savefig('plot_servers_visited.png')
    print("Saved plot_servers_visited.png")

    # 2. Plot: Latency per query
    # We only want the *final* latency, which is on the log entry
    # that has the 'total_time_to_resolution' key
    latency_df = plot_df.dropna(subset=['total_time_to_resolution'])
    latency_per_query = latency_df.groupby('domain_name_queried')['total_time_to_resolution'].mean()

    plt.figure(figsize=(12, 6))
    latency_per_query.plot(kind='bar', rot=45)
    plt.title('Total Resolution Latency per Query (First 10 URLs)')
    plt.xlabel('Domain Name')
    plt.ylabel('Latency (ms)')
    plt.tight_layout()
    plt.savefig('plot_latency.png')
    print("Saved plot_latency.png")

if __name__ == "__main__":
    create_plots()

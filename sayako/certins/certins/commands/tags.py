def run_tags(config):
    if not config:
        print("No configurations found.")
        return

    print(f"{'Tag':<20} {'Connection (user@ip)':<40}")
    print("-" * 60)
    for tag, data in config.items():
        host = data.get('host', 'N/A')
        print(f"{tag:<20} {host:<40}")

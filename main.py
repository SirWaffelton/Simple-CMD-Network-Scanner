import scanner
from utils import log_event

def main():
    print("=== Network Scanner Tool ===")
    print("1. Scan Network")
    print("2. Exit")
    
    choice = input("Enter Choice: ").strip()
    
    if choice == "1":
        base_ip = input("Enter base IP (e.g., 192.168.1): ").strip()
        start = int(input("Enter start of IP range (e.g., 1): ").strip())
        end = int(input("Enter end of IP range (e.g., 10): ").strip())
        
        # For simplicity, scan these common ports
        common_ports = [22, 80, 443, 8080]
        
        print(f"Scanning IPs from {base_ip}.{start} to {base_ip}.{end} on ports {common_ports} ...")
        
        results = scanner.scan_network(base_ip, start, end, common_ports)
        
        if results:
            print("\nScan Results:")
            for ip, ports in results.items():
                if ports:
                    ports_str = ", ".join(str(p) for p in ports)
                    print(f"- {ip}: Open ports -> {ports_str}")
                else:
                    print(f"- {ip}: No open ports found")
        else:
            print("No active hosts found in the specified range.")
        
        log_event(f"Network scan performed on {base_ip}.{start}-{end}")
    
    elif choice == "2":
        print("Exiting...")
    else:
        print("Invalid Choice")
        
ip_input = input("Enter IP (single, range, or CIDR): ").strip()
ports = [22, 80, 443]  # example ports to scan
run_scan(ip_input, ports)

if __name__ == "__main__":
    main()

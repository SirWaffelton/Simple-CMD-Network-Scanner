import scanner
from utils import log_event

def main():
    print("=== Network Scanner Tool ===")
    print("1. Scan Network")
    print("2. Exit")
    
    choice = input("Enter Choice: ").strip()
    
    if choice == "1":
        ip_input = input("Enter IP (single, range, or CIDR): ").strip()
        # You can customize ports as you want
        common_ports = [22, 80, 443, 8080]
        
        print(f"Scanning IPs: {ip_input} on ports {common_ports} ...")
        
        scanner.run_scan(ip_input, common_ports)
        
        log_event(f"Network scan performed on {ip_input}")
    
    elif choice == "2":
        print("Exiting...")
    
    else:
        print("Invalid Choice")

if __name__ == "__main__":
    main()

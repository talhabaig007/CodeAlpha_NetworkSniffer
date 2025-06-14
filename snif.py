from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
from datetime import datetime
import os

# 🖼️ Banner Function
def print_banner():
    os.system("cls" if os.name == "nt" else "clear")  # Clear screen for Windows/Linux
    print(r"""
          
  /$$$$$$            /$$                                  /$$$$$$            /$$  /$$$$$$  /$$$$$$ 
 /$$__  $$          | $$                                 /$$__  $$          |__/ /$$__  $$/$$__  $$
| $$  \__/ /$$   /$$| $$$$$$$   /$$$$$$   /$$$$$$       | $$  \__/ /$$$$$$$  /$$| $$  \__/ $$  \__/
| $$      | $$  | $$| $$__  $$ /$$__  $$ /$$__  $$      |  $$$$$$ | $$__  $$| $$| $$$$   | $$$$    
| $$      | $$  | $$| $$  \ $$| $$$$$$$$| $$  \__/       \____  $$| $$  \ $$| $$| $$_/   | $$_/    
| $$    $$| $$  | $$| $$  | $$| $$_____/| $$             /$$  \ $$| $$  | $$| $$| $$     | $$      
|  $$$$$$/|  $$$$$$$| $$$$$$$/|  $$$$$$$| $$            |  $$$$$$/| $$  | $$| $$| $$     | $$      
 \______/  \____  $$|_______/  \_______/|__/             \______/ |__/  |__/|__/|__/     |__/      
           /$$  | $$                                                                               
          |  $$$$$$/                                                                               
           \______/                                                                                                                  

                v1.0 | NETWORK ANALYSIS TOOLKIT
        🚀 Next-Gen Packet Analysis | 🔍 Deep Traffic Inspection
    """)

# 📦 Packet Processing
def process_packet(packet):
    time = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocol Name
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = f"Other ({proto})"

        print(f"[{time}] {protocol} | {src} ➜ {dst}")

        # Raw Data Check
        if Raw in packet:
            try:
                data = packet[Raw].load.decode(errors="ignore")
                print(f"Payload:\n{data}\n{'-'*60}")
            except:
                print("Non-text Payload\n" + "-"*60)

# 🚀 Main Function
def main():
    print_banner()

    print("🔧 Available Network Interfaces:")
    interfaces = get_if_list()
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")

    choice = input("\nSelect interface number to sniff on: ")
    try:
        iface = interfaces[int(choice)]
        print(f"\n📡 Sniffing on interface: {iface} (Press CTRL+C to stop)\n")
        sniff(iface=iface, prn=process_packet, store=False)
    except:
        print("❌ Invalid interface number!")

# 🧠 Start
if __name__ == "__main__":
    main()

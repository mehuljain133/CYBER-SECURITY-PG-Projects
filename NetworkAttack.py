# Unit-II Network Attacks: Network Threat Vectors, MITM, OWAPS, ARP Spoofing, IP & MAC Spoofing, DNS Attacks, SYN Flooding attacks, UDP ping-pong and fraggle attacks, TCP port scanning and reflection attacks, DoS, DDOS. Network Penetration Testing Threat assessment, Penetration testing tools, Penetration testing, Vulnerability Analysis, Threat matrices, Firewall and IDS/IPS, Wireless networks, Wireless Fidelity (Wi-Fi), Wireless network security protocols, Nmap, Network fingerprinting, BackTrack, Metasploit.

# Cyber Security - Unit II: Network Attacks and Penetration Testing Simulator

import time
import random

class NetworkSecuritySimulator:
    def __init__(self):
        self.topics = {
            1: ("Network Threat Vectors", self.threat_vectors),
            2: ("MITM (Man-in-the-Middle)", self.mitm_attack),
            3: ("OWASP Top Vulnerabilities", self.owasp),
            4: ("ARP Spoofing", self.arp_spoofing),
            5: ("IP & MAC Spoofing", self.ip_mac_spoofing),
            6: ("DNS Attacks", self.dns_attacks),
            7: ("SYN Flooding", self.syn_flood),
            8: ("UDP Ping-Pong & Fraggle", self.udp_fraggle),
            9: ("TCP Port Scanning", self.tcp_scan),
            10: ("DoS/DDoS", self.dos_ddos),
            11: ("Penetration Testing Tools", self.pen_test_tools),
            12: ("Threat Assessment & Vulnerability Analysis", self.vulnerability_analysis),
            13: ("Firewall and IDS/IPS", self.firewall_ids),
            14: ("Wireless Networks & Security", self.wireless_security),
            15: ("Nmap & Network Fingerprinting", self.nmap_fingerprint),
            16: ("BackTrack & Metasploit", self.backtrack_metasploit)
        }

    def run(self):
        print("=== UNIT-II: Network Security Simulator ===")
        while True:
            for k, (title, _) in self.topics.items():
                print(f"{k}. {title}")
            print("0. Exit")

            try:
                choice = int(input("\nSelect a topic (0 to Exit): "))
                if choice == 0:
                    print("Exiting simulation. Stay secure!")
                    break
                elif choice in self.topics:
                    print(f"\n--- Simulating: {self.topics[choice][0]} ---")
                    self.topics[choice][1]()
                    print("\n--- End of Simulation ---\n")
                else:
                    print("Invalid input.")
            except ValueError:
                print("Enter a valid number.")

    # === Simulations ===

    def threat_vectors(self):
        vectors = ["Email Phishing", "Malicious Attachments", "Open Ports", "Weak Passwords"]
        for v in vectors:
            print(f"⚠️ Threat Vector Detected: {v}")
            time.sleep(0.5)

    def mitm_attack(self):
        print("Intercepting traffic between Client ↔ Server...")
        print("Injecting malicious payload...")
        print("Credentials captured: user: admin | pass: ****")

    def owasp(self):
        top_3 = ["1. Injection (SQL, NoSQL)", "2. Broken Authentication", "3. XSS"]
        for item in top_3:
            print(f"OWASP Top: {item}")
            time.sleep(1)

    def arp_spoofing(self):
        print("Sending forged ARP replies to router...")
        print("Router now sends all packets through attacker.")

    def ip_mac_spoofing(self):
        print("Spoofing IP: 192.168.1.1 → Attacker")
        print("Spoofing MAC: 00:0A:E6:3E:FD:E1")
        print("Network identity hijacked.")

    def dns_attacks(self):
        print("Simulating DNS poisoning...")
        print("Legit domain resolves to: 45.55.66.77 (attacker site)")

    def syn_flood(self):
        print("Sending massive SYN requests to server...")
        print("Server overwhelmed and crashing...")

    def udp_fraggle(self):
        print("Sending broadcast UDP packets with spoofed source...")
        print("Victim gets flooded (Ping-Pong Amplification)")

    def tcp_scan(self):
        ports = [21, 22, 80, 443, 3306]
        print("Scanning TCP ports...")
        for port in ports:
            state = random.choice(["open", "closed", "filtered"])
            print(f"Port {port}: {state}")

    def dos_ddos(self):
        print("Launching DoS from single IP...")
        print("Launching DDoS from botnet of 10,000 IPs...")
        print("Service Unavailable (HTTP 503)")

    def pen_test_tools(self):
        tools = ["Nmap", "Wireshark", "Burp Suite", "Metasploit"]
        for tool in tools:
            print(f"🛠 Tool: {tool}")
        print("Each tool specializes in scanning, sniffing, exploiting, or testing.")

    def vulnerability_analysis(self):
        vulns = ["Unpatched Software", "Default Credentials", "Open SMB Shares"]
        matrix = {v: random.choice(["Critical", "High", "Medium"]) for v in vulns}
        for k, v in matrix.items():
            print(f"{k}: {v} risk")

    def firewall_ids(self):
        print("Deploying Firewall → Blocks unauthorized ports")
        print("Enabling IDS → Intrusion Detected: SQL Injection attempt")
        print("Response: Alert triggered, IP blacklisted")

    def wireless_security(self):
        protocols = ["WEP", "WPA", "WPA2", "WPA3"]
        for p in protocols:
            print(f"{p} - {'Secure' if '3' in p or '2' in p else 'Weak'}")
        print("Using WPA3 and rotating keys is best practice.")

    def nmap_fingerprint(self):
        print("Using Nmap for OS detection...")
        print("Target OS: Linux Kernel 5.x detected")
        print("Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)")

    def backtrack_metasploit(self):
        print("BackTrack (Kali Linux predecessor) booted...")
        print("Launching Metasploit Framework...")
        print("Exploit: Windows SMB Vulnerability")
        print("Reverse shell gained on victim.")

# Run the simulation
if __name__ == "__main__":
    sim = NetworkSecuritySimulator()
    sim.run()

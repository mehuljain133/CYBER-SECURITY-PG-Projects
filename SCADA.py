# Unit-III Introduction to SCADA (supervisory control and data acquisition) Understanding SCADA security policies, SCADA Physical and Logical Security, Understanding differences between physical and logical security, Define perimeter controls and terms, Define various security zones, Understand communication cyber threats, Understand firewall, architectures.

# Cyber Security - Unit III: SCADA Security Simulator
# Educational Simulation for SCADA Concepts

import time

class SCADASimulator:
    def __init__(self):
        self.topics = {
            1: ("Introduction to SCADA", self.intro_scada),
            2: ("SCADA Security Policies", self.scada_policies),
            3: ("Physical vs Logical Security", self.physical_logical_security),
            4: ("Perimeter Controls & Terms", self.perimeter_controls),
            5: ("Security Zones", self.security_zones),
            6: ("Communication Cyber Threats", self.comm_threats),
            7: ("Firewall Architectures", self.firewall_architecture)
        }

    def run(self):
        print("=== UNIT-III: SCADA Security Simulator ===")
        while True:
            for k, (title, _) in self.topics.items():
                print(f"{k}. {title}")
            print("0. Exit")

            try:
                choice = int(input("\nSelect a topic (0 to Exit): "))
                if choice == 0:
                    print("Exiting SCADA simulation.")
                    break
                elif choice in self.topics:
                    print(f"\n--- {self.topics[choice][0]} ---")
                    self.topics[choice][1]()
                    print("\n--- End ---\n")
                else:
                    print("Invalid input.")
            except ValueError:
                print("Enter a valid number.")

    # === Simulations ===

    def intro_scada(self):
        print("SCADA = Supervisory Control and Data Acquisition")
        print("Used to monitor & control industrial systems: power, water, transport.")
        print("Components: RTUs, PLCs, HMI, and SCADA server.")
        time.sleep(1)
        print("🛠 Example: SCADA controlling city-wide electricity grid.")

    def scada_policies(self):
        print("Implementing SCADA security policies...")
        policies = ["Access Control", "Patch Management", "Audit Logging", "Incident Response"]
        for p in policies:
            print(f"Policy enforced: {p}")
            time.sleep(0.5)

    def physical_logical_security(self):
        print("Physical Security: Guards, locked cabinets, access badges.")
        print("Logical Security: Firewalls, passwords, role-based access.")
        print("🔐 Difference: Physical = tangible protection; Logical = digital protection.")

    def perimeter_controls(self):
        print("Defining perimeter security controls...")
        controls = ["Fencing", "CCTV", "Mantraps", "IDS", "DMZ"]
        for c in controls:
            print(f"Control: {c}")
            time.sleep(0.5)

    def security_zones(self):
        print("Segmenting system into security zones...")
        zones = {
            "Enterprise Zone": "Corporate IT systems.",
            "DMZ": "Public-facing systems (web, email).",
            "Control Zone": "PLC, RTU, HMI.",
            "Safety Zone": "Failsafe emergency systems."
        }
        for zone, desc in zones.items():
            print(f"{zone}: {desc}")
            time.sleep(0.5)

    def comm_threats(self):
        print("Communication-based cyber threats in SCADA:")
        threats = [
            "Man-in-the-Middle (MITM)",
            "Replay Attacks",
            "Protocol Spoofing",
            "Insider Attacks"
        ]
        for t in threats:
            print(f"⚠️ Threat: {t}")
            time.sleep(1)
        print("Use encrypted protocols (e.g., TLS over MODBUS) to protect communication.")

    def firewall_architecture(self):
        print("Designing secure firewall architecture...")
        layers = [
            "Outer Firewall → between Internet and DMZ",
            "Inner Firewall → between DMZ and Control Zone",
            "Application Firewall → for HMI & SCADA apps"
        ]
        for l in layers:
            print(f"🔒 {l}")
            time.sleep(1)
        print("Architecture must support zoning, monitoring, and failover.")

# Run the simulation
if __name__ == "__main__":
    sim = SCADASimulator()
    sim.run()

# Unit-I Introduction: Cyberspace, Internet, Internet of things, Cyber Crimes, cyber criminals, Cyber security, Cyber Security Threats, Cyber laws and legislation, Law Enforcement Roles and Responses. 

# Cyber Security Unit-I: All-in-One Simulation Code
# Author: [Your Name or Research Lab]
# Purpose: Academic simulation for advanced understanding of foundational Cyber Security topics.

import random
import time

class CyberSecuritySimulator:
    def __init__(self):
        self.topics = {
            1: ("Cyberspace", self.simulate_cyberspace),
            2: ("Internet", self.simulate_internet),
            3: ("Internet of Things (IoT)", self.simulate_iot),
            4: ("Cyber Crimes", self.simulate_cyber_crimes),
            5: ("Cyber Criminals", self.simulate_cyber_criminals),
            6: ("Cyber Security", self.simulate_cyber_security),
            7: ("Cyber Security Threats", self.simulate_cyber_threats),
            8: ("Cyber Laws and Legislation", self.simulate_cyber_laws),
            9: ("Law Enforcement Roles and Responses", self.simulate_law_enforcement)
        }

    def run(self):
        print("=== CYBER SECURITY UNIT-I SIMULATION ENGINE ===")
        while True:
            for k, (title, _) in self.topics.items():
                print(f"{k}. {title}")
            print("0. Exit")

            try:
                choice = int(input("\nSelect a topic to simulate (0 to exit): "))
                if choice == 0:
                    print("Exiting simulator. Stay secure!")
                    break
                elif choice in self.topics:
                    print(f"\n--- Simulating: {self.topics[choice][0]} ---")
                    self.topics[choice][1]()
                    print("\n--- End of Simulation ---\n")
                else:
                    print("Invalid option. Try again.")
            except ValueError:
                print("Enter a valid number.")

    # === Simulations ===

    def simulate_cyberspace(self):
        print("Cyberspace is the virtual domain of digital networks where communication and data flow happen.")
        print("Simulating a network topology of 3 countries connected via a secure backbone...")
        time.sleep(1)
        print("Data packets flowing securely between New York ↔ London ↔ Tokyo...")

    def simulate_internet(self):
        print("The Internet connects billions of devices globally.")
        print("Simulating DNS resolution and HTTP request...")
        time.sleep(1)
        print("Resolving www.university.edu → 192.168.45.11")
        print("Request sent → HTML page received → Rendered in browser")

    def simulate_iot(self):
        print("IoT connects physical objects to the internet.")
        devices = ["Smart Fridge", "Health Tracker", "Security Drone"]
        for d in devices:
            print(f"{d} → Data sent to cloud → Response: OK")
            time.sleep(1)
        print("Vulnerability check running...")
        print("⚠️ One device uses default credentials. Risk of breach!")

    def simulate_cyber_crimes(self):
        print("Cyber crimes simulate real-world illegal digital activity.")
        crimes = ["Phishing Email", "Malware Injection", "Data Breach"]
        for c in crimes:
            print(f"Detecting: {c}")
            time.sleep(1)
        print("Recommended: Report to CERT, isolate infected systems.")

    def simulate_cyber_criminals(self):
        criminals = {
            "Hacktivist": "Politically motivated digital attacker.",
            "Black Hat": "Unethical hacker exploiting vulnerabilities.",
            "Insider Threat": "Employee stealing internal data."
        }
        for role, desc in criminals.items():
            print(f"{role} → {desc}")
            time.sleep(1)

    def simulate_cyber_security(self):
        print("Cyber security is the defense layer of cyberspace.")
        steps = [
            "Install endpoint protection...",
            "Enable network firewall...",
            "Perform penetration testing...",
            "Update software patches..."
        ]
        for step in steps:
            print(step)
            time.sleep(1)
        print("✅ System hardened and secure.")

    def simulate_cyber_threats(self):
        threats = ["Ransomware", "SQL Injection", "Zero-Day Exploit"]
        for threat in threats:
            print(f"Threat detected: {threat}")
            time.sleep(1)
        print("Countermeasures: Backup, IDS, Patch Management.")

    def simulate_cyber_laws(self):
        laws = {
            "IT Act (India)": "Covers cybercrime, digital signatures, and data protection.",
            "GDPR (EU)": "Ensures data privacy and consent in the EU.",
            "CFAA (USA)": "Criminalizes unauthorized access to systems."
        }
        for law, desc in laws.items():
            print(f"{law} → {desc}")
            time.sleep(1)

    def simulate_law_enforcement(self):
        print("Law enforcement uses cyber forensics to investigate crimes.")
        print("Scenario: Fake bank site detected collecting user data.")
        time.sleep(1)
        print("Steps taken:")
        steps = [
            "1. IP tracing and server location.",
            "2. Digital evidence collection.",
            "3. Arrest warrant via cyber law.",
            "4. International cooperation with INTERPOL."
        ]
        for s in steps:
            print(s)
            time.sleep(1)
        print("👮‍♂️ Case closed. Criminal caught.")

# Run the simulator
if __name__ == "__main__":
    simulator = CyberSecuritySimulator()
    simulator.run()

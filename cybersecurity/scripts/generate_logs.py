import os
import random
import csv
from datetime import datetime, timedelta

def generate_sample_logs(output_path="dataset/sample_logs.csv", num_records=5000):
    """
    Generates a realistic set of cybersecurity logs containing normal and malicious activity.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Configuration lists
    countries = ["United States", "India", "Germany", "China", "Russia", "Brazil", "United Kingdom", "Canada", "Australia", "Ukraine"]
    devices = ["Windows", "Linux", "MacOS", "Android", "iOS"]
    usernames = ["jdoe", "asmith", "bjones", "clark", "admin", "root", "guest", "db_admin", "user1", "user2"]
    event_types = ["Login", "File Access", "Port Scan", "Data Export", "Privilege Escalation"]
    
    # Map country to specific IP ranges (simulated)
    country_ips = {
        "United States": ["192.168.1.", "10.0.0.", "45.79.", "104.244."],
        "India": ["103.21.", "115.112.", "223.224."],
        "Germany": ["46.112.", "80.128.", "193.176."],
        "China": ["112.98.", "220.181.", "58.20."],
        "Russia": ["95.108.", "185.220.", "82.142."],
        "Brazil": ["200.140.", "177.85."],
        "United Kingdom": ["188.120.", "82.165."],
        "Canada": ["198.50.", "204.101."],
        "Australia": ["101.160.", "120.150."],
        "Ukraine": ["195.138.", "91.196."]
    }
    
    def get_random_ip(country):
        prefixes = country_ips.get(country, ["192.168.1."])
        prefix = random.choice(prefixes)
        if prefix.count(".") == 3:
            return prefix + str(random.randint(1, 254))
        else:
            return prefix + ".".join(str(random.randint(1, 254)) for _ in range(4 - prefix.count(".")))

    # Start date 7 days ago
    start_date = datetime.now() - timedelta(days=7)
    
    # We will generate logs and sort them by timestamp at the end
    logs = []
    
    # Setup some consistent attackers
    malicious_ips = {
        "brute_force_1": (get_random_ip("Russia"), "admin", "Russia"),
        "brute_force_2": (get_random_ip("China"), "root", "China"),
        "port_scanner": (get_random_ip("Ukraine"), "system", "Ukraine"),
        "exfiltrator": (get_random_ip("Brazil"), "db_admin", "Brazil"),
    }
    
    # 1. Generate normal activity (80% of data)
    num_normal = int(num_records * 0.80)
    for _ in range(num_normal):
        # Normal records are spread across 7 days, mostly during business hours (8 AM to 6 PM)
        day_offset = random.randint(0, 7)
        hour = random.choices(
            population=list(range(24)),
            weights=[1, 1, 1, 1, 1, 2, 4, 8, 12, 14, 15, 12, 14, 15, 14, 12, 8, 6, 4, 3, 2, 1, 1, 1],
            k=1
        )[0]
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        log_time = start_date + timedelta(days=day_offset, hours=hour - start_date.hour, minutes=minute - start_date.minute, seconds=second - start_date.second)
        
        country = random.choices(
            population=countries,
            weights=[35, 20, 15, 5, 3, 5, 7, 5, 3, 2],
            k=1
        )[0]
        
        ip = get_random_ip(country)
        username = random.choice(usernames)
        if username in ["admin", "root", "db_admin"]:
            # Admin accounts have slightly higher failed login chances from random users but mostly success
            login_status = random.choices(["Success", "Failed"], weights=[90, 10], k=1)[0]
        else:
            login_status = random.choices(["Success", "Failed"], weights=[97, 3], k=1)[0]
            
        event_type = random.choices(
            population=event_types,
            weights=[50, 40, 2, 6, 2],
            k=1
        )[0]
        
        # Override some properties for logical consistency
        if event_type == "Login":
            pass
        else:
            login_status = "Success" # Non-login events are successful actions
            
        device = random.choice(devices)
        
        # Raw severity estimate (before rule engine)
        if login_status == "Failed":
            severity = "Low"
        elif event_type in ["Data Export", "Privilege Escalation"] and username in ["admin", "db_admin"]:
            severity = "Medium"
        else:
            severity = "Low"
            
        logs.append([
            log_time.strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            username,
            login_status,
            country,
            event_type,
            device,
            severity
        ])
        
    # 2. Inject Brute Force Attacks
    # Attack 1: Russia IP targeting admin
    bf_ip_1, bf_user_1, bf_country_1 = malicious_ips["brute_force_1"]
    for day in range(3, 6): # Attacks happen on day 3, 4, 5
        attack_time = start_date + timedelta(days=day, hours=random.randint(22, 23), minutes=random.randint(10, 40))
        # 10 quick failed logins, then 1 success (compromise!)
        for i in range(12):
            log_time = attack_time + timedelta(seconds=i * random.randint(2, 8))
            status = "Failed" if i < 11 else "Success"
            logs.append([
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                bf_ip_1,
                bf_user_1,
                status,
                bf_country_1,
                "Login",
                "Linux",
                "Medium" if status == "Failed" else "High"
            ])
            
    # Attack 2: China IP targeting root (pure failure brute force)
    bf_ip_2, bf_user_2, bf_country_2 = malicious_ips["brute_force_2"]
    for day in range(1, 3):
        attack_time = start_date + timedelta(days=day, hours=random.randint(1, 4), minutes=random.randint(15, 45))
        # 25 consecutive failures
        for i in range(25):
            log_time = attack_time + timedelta(seconds=i * random.randint(1, 5))
            logs.append([
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                bf_ip_2,
                bf_user_2,
                "Failed",
                bf_country_2,
                "Login",
                "Linux",
                "Medium"
            ])

    # 3. Inject Port Scan Scenario
    # Port scanner IP firing 80 scan events in 5 minutes
    scan_ip, _, scan_country = malicious_ips["port_scanner"]
    for day in [2, 5]:
        scan_time = start_date + timedelta(days=day, hours=random.randint(12, 16), minutes=random.randint(0, 50))
        for i in range(70):
            log_time = scan_time + timedelta(seconds=i * random.randint(1, 3))
            logs.append([
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                scan_ip,
                "system",
                "Success",
                scan_country,
                "Port Scan",
                "Linux",
                "Medium"
            ])

    # 4. Inject Data Exfiltration Scenario
    # Brazilian IP logging in as db_admin at 3 AM and performing large data exports
    ex_ip, ex_user, ex_country = malicious_ips["exfiltrator"]
    for day in [4, 6]:
        ex_time = start_date + timedelta(days=day, hours=3, minutes=random.randint(10, 20))
        # 1 login, 3 file accesses, 4 data exports
        events = [
            ("Login", "Success"),
            ("File Access", "Success"),
            ("File Access", "Success"),
            ("Data Export", "Success"),
            ("Data Export", "Success"),
            ("Data Export", "Success")
        ]
        for i, (evt, stat) in enumerate(events):
            log_time = ex_time + timedelta(minutes=i * random.randint(1, 3))
            logs.append([
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                ex_ip,
                ex_user,
                stat,
                ex_country,
                evt,
                "MacOS",
                "High" if evt == "Data Export" else "Medium"
            ])

    # 5. Inject Privilege Escalation Scenario
    # Internal user 'bjones' doing suspicious privilege escalation
    user_ip = "192.168.1.105"
    for day in [5]:
        pe_time = start_date + timedelta(days=day, hours=17, minutes=45)
        # Login -> File Access -> Failed Privilege Escalation -> Successful Privilege Escalation -> File Access
        events = [
            ("Login", "Success", "Low"),
            ("File Access", "Success", "Low"),
            ("Privilege Escalation", "Failed", "Medium"),
            ("Privilege Escalation", "Failed", "Medium"),
            ("Privilege Escalation", "Success", "High"),
            ("File Access", "Success", "High")
        ]
        for i, (evt, stat, sev) in enumerate(events):
            log_time = pe_time + timedelta(minutes=i * 2)
            logs.append([
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                user_ip,
                "bjones",
                stat,
                "United States",
                evt,
                "Windows",
                sev
            ])

    # Sort logs by timestamp
    logs.sort(key=lambda x: x[0])
    
    # Save to CSV
    headers = ["Timestamp", "IP Address", "Username", "Login Status", "Country", "Event Type", "Device", "Severity"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(logs)
        
    print(f"Generated {len(logs)} security logs in {output_path}")

if __name__ == "__main__":
    generate_sample_logs()

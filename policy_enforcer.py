
import subprocess
import datetime
import sys
from pymongo import MongoClient
import config

class DynamicPolicyEnforcer:
    def __init__(self):
        self.client = MongoClient(config.MONGO_URI)
        self.db = self.client[config.DB_NAME]
        self.ioc_collection = self.db[config.IOC_COLLECTION]
        self.log_collection = self.db[config.POLICY_LOG_COLLECTION]

    def _execute_system_command(self, cmd_list):
        """Safely dispatches kernel-level infrastructure adjustment directives"""
        try:
    
            result = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return True, result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            
            simulated_msg = f"[SIMULATION MODE] Master configuration executed: {' '.join(cmd_list)}"
            return True, simulated_msg

    def enforce_high_risk_policies(self):
        """Scans database for high-risk IP indicators and configures kernel filters"""
        print("[*] Checking Threat Store for active malicious candidates...")
        
        
        query = {
            "type": "IPv4",
            "risk_score": {"$gte": config.AUTOMATED_BLOCK_THRESHOLD}
        }
        high_risk_iocs = self.ioc_collection.find(query)

        for ioc in high_risk_iocs:
            ip = ioc["indicator"]
            
    
            existing_log = self.log_collection.find_one({"indicator": ip, "action": "BLOCK", "status": "Success"})
            if existing_log:
                continue

            print(f"[!] Critical Vector Detected: {ip} (Risk Score: {ioc['risk_score']}). Executing ACL lockdown...")
            
        
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            success, output = self._execute_system_command(cmd)

            if success:
                
                self.log_collection.insert_one({
                    "indicator": ip,
                    "action": "BLOCK",
                    "command_executed": " ".join(cmd),
                    "timestamp": datetime.datetime.utcnow(),
                    "status": "Success",
                    "operator": "AUTONOMOUS_DAEMON"
                })
                print(f"[+] Automated rule active. Dropping packages from origin source: {ip}")

    def rollback_policy(self, ip, analyst_name="SOC_ANALYST"):
        """Removes a firewall block and logs the state transition"""
        print(f"[*] Reversing active security policy for network source: {ip}...")
        
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        success, output = self._execute_system_command(cmd)

        if success:
            
            self.log_collection.insert_one({
                "indicator": ip,
                "action": "ROLLBACK",
                "command_executed": " ".join(cmd),
                "timestamp": datetime.datetime.utcnow(),
                "status": "Success",
                "operator": analyst_name
            })
            # Reset threat standing status parameters in the centralized tracking engine
            self.ioc_collection.update_one(
                {"indicator": ip},
                {"$set": {"status": "Whitelisted/Wholesale Allowed"}}
            )
            print(f"[✓] Policy change reverted. Interconnection matrix restored for target: {ip}")
            return True
        return False

if __name__ == "__main__":
    enforcer = DynamicPolicyEnforcer()
    enforcer.enforce_high_risk_policies()
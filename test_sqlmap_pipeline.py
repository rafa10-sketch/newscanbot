import sys
from pathlib import Path

# Mock raw vulnerable SQLMap output for testing
vulnerable_output = """
___
__H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V          |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-05-18/

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] testing if the target URL is stable
[12:00:03] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (it's a classic SQL injection)
[12:00:04] [INFO] testing for SQL injection on GET parameter 'id'
[12:00:05] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others? [y/N] 
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8382=8382
---
[12:00:06] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx, PHP 8.1
back-end DBMS: MySQL >= 5.6
[*] shutting down @ 12:00:07 /2026-05-18/
"""

# Mock clean SQLMap output
clean_output = """
___
__H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V          |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-05-18/

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] testing if the target URL is stable
[12:00:03] [INFO] GET parameter 'id' does not seem to be injectable
[*] shutting down @ 12:00:04 /2026-05-18/
"""

def parse_sqlmap_output(raw: str) -> list:
    findings = []
    # Only trigger if sqlmap explicitly identified an injection point or confirmed a parameter is vulnerable
    is_vulnerable = "sqlmap identified the following injection point(s)" in raw.lower() or "is vulnerable" in raw.lower()
    
    if is_vulnerable:
        for line in raw.splitlines():
            # Match lines indicating a parameter is vulnerable, avoiding false positives like "does not seem to be injectable"
            if "parameter" in line.lower() and "is vulnerable" in line.lower() and "not" not in line.lower():
                findings.append({
                    "description": line.strip(),
                    "severity": "high",
                    "source": "sqlmap"
                })
        if not findings:
            findings.append({
                "description": "SQLMap identified a potential SQL Injection vulnerability (see raw output for details).",
                "severity": "high",
                "source": "sqlmap"
            })
    return findings

def main():
    print("=== TESTING SQLMAP PARSER LOGIC ===")
    
    print("\n--- Test 1: Vulnerable Output ---")
    findings_vuln = parse_sqlmap_output(vulnerable_output)
    print(f"Findings Found: {len(findings_vuln)}")
    for f in findings_vuln:
        print(f"  [{f['severity'].upper()}] Source: {f['source']}")
        print(f"  Description: {f['description']}")
        
    print("\n--- Test 2: Clean Output ---")
    findings_clean = parse_sqlmap_output(clean_output)
    print(f"Findings Found: {len(findings_clean)}")
    for f in findings_clean:
        print(f"  [{f['severity'].upper()}] Source: {f['source']}")
        print(f"  Description: {f['description']}")

if __name__ == "__main__":
    main()

# BadRep

Checks the reputation of a domain or IP address using multiple services, including VirusTotal, AbuseIPDB, SecurityTrails, and DNS-based blacklists (DNSBLs).

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/doomygloom/BadRep.git
   cd BadRep
   ```

2. **Install Requirements:**

   ```bash
   pip install requests dnspython argparse
   ```

---

## API Keys

`BadRep` uses the following APIs:

* VirusTotal
* AbuseIPDB
* SecurityTrails (Optional for historical DNS)

Replace the placeholders in the script with your actual API keys:

```python
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_api_key"
```

---

## Usage

```bash
python BadRep.py <target> [options]
```

### Arguments:

* `<target>`: The domain or IP address to analyze.

### Options:

* `-n`, `--no-api`: Disable all API-based checks.

### Examples:

1. Check a domain/IP with full analysis (APIs required):

   ```bash
   python BadRep.py example.com
   ```

2. Check without API (DNSBL only):

   ```bash
   python BadRep.py 192.168.1.1 --no-api
   ```


The script will provide the following information:

* Resolved IP address (if applicable)
* Reputation results from VirusTotal and AbuseIPDB (if APIs are enabled)
* DNS-based blacklist status
* Historical DNS records (if APIs are enabled)

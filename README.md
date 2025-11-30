# orwell_recon.py

`orwell_recon.py` is a small automated recon helper for CTFs and beginner pentests.

Given a single target (IP, domain, or URL), it will:

1. Normalize the target (strip scheme, extract host)
2. Run a DNS lookup
3. Run a WHOIS lookup
4. Run an Nmap scan (all TCP ports, service/version, vuln scripts)
5. Parse Nmap output for HTTP/HTTPS services
6. If HTTP/HTTPS is found:

   * Run Gobuster **subdomain** fuzzing against the host
   * Build a base URL and run Gobuster **directory** fuzzing
7. Save all results into a structured `results/<target>/` directory

It’s designed to be simple, predictable, and easy to read when you’re deep in a lab or CTF.

---

## Features

* **Flexible input**

  * Accepts:

    * IPs (e.g. `10.10.10.10`)
    * Domains (e.g. `example.com`)
    * URLs (e.g. `https://example.com/login`)

* **Automated scan chain**

  * DNS lookup (Python `socket`)
  * WHOIS lookup (system `whois`)
  * Nmap:

    * SYN scan (`-sS`)
    * All TCP ports (`-p-`)
    * Service/version detection (`-sV`)
    * Default scripts (`-sC`)
    * Basic vulnerability scripts (`--script vuln`)
    * Very verbose (`-vv`)
    * Aggressive timing (`-T5`)
  * Gobuster (if any HTTP/HTTPS service is found):

    * `gobuster dns` → subdomain fuzzing against the host
    * `gobuster dir` → directory fuzzing against a constructed base URL

* **Organized output structure**

  ```text
  results/
    <normalized-target>/
      dns/
        dns.txt
      whois/
        whois.txt
      nmap/
        nmap.txt
      subdomains/
        gobuster_subdomains.txt
      directories/
        gobuster_directories.txt
  ```

---

## Requirements

### Python

* Python 3.x
* Uses only the standard library (no `pip install` required)

### External tools

These must be installed and available in your `PATH`:

* `whois`
* `nmap`
* `gobuster`

On Debian/Kali-like systems:

```bash
sudo apt update
sudo apt install whois nmap gobuster
```

---

## Project Layout

Your repo should look like this:

```text
.
├── orwell_recon.py
└── wordlists/
    ├── common_subdomains.txt
    └── common_dirs.txt
```

You create `wordlists/` and add:

* `common_subdomains.txt` – for `gobuster dns`
* `common_dirs.txt` – for `gobuster dir`

Each is a simple newline-separated wordlist.

**Example `wordlists/common_subdomains.txt`:**

```text
www
mail
ftp
dev
test
admin
portal
api
stage
```

**Example `wordlists/common_dirs.txt`:**

```text
admin
login
dashboard
uploads
images
js
css
api
backup
.old
```

You can drop in trimmed SecLists files or your own lists.

---

## Usage

Basic usage:

```bash
python3 orwell_recon.py -t <target>
```

Examples:

```bash
# Domain
python3 orwell_recon.py -t example.com

# Full URL
python3 orwell_recon.py -t https://example.com/login

# IP address
python3 orwell_recon.py -t 10.10.10.10
```

The script will:

* Normalize the target (`https://example.com/login` → `example.com`)
* Run DNS, WHOIS, and Nmap
* Parse Nmap output for HTTP/HTTPS ports
* If any HTTP/HTTPS services are found:

  * Run Gobuster subdomain fuzzing against the host
  * Build a base URL like `http://example.com` or `https://example.com:8443`
  * Run Gobuster directory fuzzing against that URL

---

## Command-Line Arguments

```bash
python3 orwell_recon.py -t <target> [options]
```

### Required

#### `-t`, `--target`

Target IP, domain, or URL.

Examples:

```bash
-t example.com
-t https://example.com
-t 10.10.10.10
```

### Optional

#### `-o`, `--outdir`

Base output directory.
Default: `results`

```bash
python3 orwell_recon.py -t example.com -o output
```

#### `--subdomain-wordlist`

Wordlist for Gobuster subdomain fuzzing.
Default: `wordlists/common_subdomains.txt`

```bash
python3 orwell_recon.py -t example.com \
    --subdomain-wordlist /path/to/custom_subdomains.txt
```

#### `--dir-wordlist`

Wordlist for Gobuster directory fuzzing.
Default: `wordlists/common_dirs.txt`

```bash
python3 orwell_recon.py -t example.com \
    --dir-wordlist /path/to/custom_dirs.txt
```

---

## Scan Flow (Step-by-Step)

### 1. Target normalization

If input looks like a URL (`scheme://`), `urlparse` extracts the hostname.

Examples:

* `https://example.com/login` → `example.com`
* `http://10.10.10.10` → `10.10.10.10`
* `example.com` → `example.com`

### 2. DNS lookup

Uses `socket.gethostbyname_ex()` to gather:

* Canonical name
* Aliases
* IP addresses

Output:

```text
results/<target>/dns/dns.txt
```

### 3. WHOIS lookup

* Runs `whois <target>` via `subprocess`
* Captures stdout/stderr and handles missing tool/timeout gracefully

Output:

```text
results/<target>/whois/whois.txt
```

### 4. Nmap scan

Command used:

```bash
nmap -sS -sV -sC --script vuln -p- -vv -T5 <target>
```

Flags:

* `-sS`: SYN scan
* `-p-`: all TCP ports
* `-sV`: service/version detection
* `-sC`: default scripts
* `--script vuln`: basic vulnerability-related NSE scripts
* `-vv`: very verbose
* `-T5`: aggressive timing (fast, CTF-style; tune down for stealthy work)

Output:

```text
results/<target>/nmap/nmap.txt
```

The script then parses Nmap’s output, looking for lines where:

* It’s a TCP port (`/tcp`)
* The state is `open`
* The service string contains `"http"` (matches `http`, `https`, `http-alt`, etc.)

Those ports are treated as HTTP/HTTPS.

### 5. Gobuster subdomain fuzzing

If any HTTP/HTTPS ports are found, the script runs:

```bash
gobuster dns -d <normalized-target> -w <subdomain_wordlist> -t 50
```

* Runs regardless of whether the host is an IP or domain (on IPs, it may not find much, but it will still execute).

Output:

```text
results/<target>/subdomains/gobuster_subdomains.txt
```

### 6. Gobuster directory fuzzing

The script builds a base URL from the host and HTTP ports:

* If port 443 is open → `https://<host>` (or `https://<host>:port` if non-standard)
* Else use the first HTTP port:

  * If 80 → `http://<host>`
  * Else → `http://<host>:<port>`

Then runs:

```bash
gobuster dir -u <base_url> -w <dir_wordlist> -t 50
```

Output:

```text
results/<target>/directories/gobuster_directories.txt
```

---

## Example Run

```bash
python3 orwell_recon.py -t example.com
```

Sample console flow:

```text
[*] Raw target: example.com
[*] Normalized target: example.com

[+] Running DNS lookup for: example.com
    Canonical name: example.com
    Aliases: (none)
    IP addresses: 93.184.216.34

[+] Running WHOIS for: example.com
...

[+] Running Nmap scan for: example.com
    [*] Nmap command: nmap -sS -sV -sC --script vuln -p- -vv -T5 example.com
...

[*] Detected HTTP/HTTPS services on ports: 80

[*] Running Gobuster subdomain fuzzing...
    [*] Gobuster dns command: gobuster dns -d example.com -w wordlists/common_subdomains.txt -t 50
...

[*] Running Gobuster directory fuzzing against: http://example.com
    [*] Gobuster dir command: gobuster dir -u http://example.com -w wordlists/common_dirs.txt -t 50
...

[*] All results saved under: results/example.com
```

---

## Legal & Ethical Use

This script is intended for:

* CTFs
* Training labs
* Systems you own
* Systems you have **explicit authorization** to test

Do **not** scan random targets on the internet. Unauthorized scanning can be illegal and/or violate terms of service.


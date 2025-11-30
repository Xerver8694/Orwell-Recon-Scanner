# orwell_recon.py

`orwell_recon.py` is a small automated recon helper for CTFs and beginner pentests.

Given a single target (IP, domain, or URL), it will:

1. Normalize the target (strip scheme, extract host)
2. Run a DNS lookup
3. Run a WHOIS lookup
4. Run an Nmap scan (all TCP ports, service/version, vuln scripts)
5. Parse Nmap output for HTTP/HTTPS services
6. If HTTP/HTTPS is found:
   - Run Gobuster **subdomain** fuzzing against the host
   - Build a base URL and run Gobuster **directory** fuzzing
7. Save all results into a structured `results/<target>/` directory

It’s designed to be simple, predictable, and easy to read when you’re deep in a lab or CTF.

---

## Features

- **Flexible input**
  - Accepts:
    - IPs (e.g. `10.10.10.10`)
    - Domains (e.g. `example.com`)
    - URLs (e.g. `https://example.com/login`)

- **Automated scan chain**
  - DNS lookup (Python `socket`)
  - WHOIS lookup (system `whois`)
  - Nmap:
    - SYN scan (`-sS`)
    - All TCP ports (`-p-`)
    - Service/version detection (`-sV`)
    - Default scripts (`-sC`)
    - Basic vulnerability scripts (`--script vuln`)
    - Very verbose (`-vv`)
    - Aggressive timing (`-T5`)
  - Gobuster (if any HTTP/HTTPS service is found):
    - `gobuster dns` → subdomain fuzzing against the host
    - `gobuster dir` → directory fuzzing against a constructed base URL

- **Organized output structure**

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


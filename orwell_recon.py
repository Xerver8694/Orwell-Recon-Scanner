#!/usr/bin/env python3

import argparse
import socket
import subprocess
import os
from urllib.parse import urlparse

# ---------------------------------------------------------
# Local wordlist paths (bundled with the script)
# ---------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_WORDLIST_DIR = os.path.join(SCRIPT_DIR, "wordlists")
DEFAULT_SUBDOMAIN_WORDLIST = os.path.join(
    LOCAL_WORDLIST_DIR,
    "common_subdomains.txt"
)
DEFAULT_DIR_WORDLIST = os.path.join(
    LOCAL_WORDLIST_DIR,
    "common_dirs.txt"
)


def normalize_target(raw_target: str) -> str:
    """
    Take whatever the user gives us (URL, IP, domain)
    and extract the hostname or IP we should actually work with.
    """
    if "://" in raw_target:
        parsed = urlparse(raw_target)
        if parsed.hostname:
            return parsed.hostname

    return raw_target


def ensure_dir(path: str) -> None:
    """
    Create a directory if it doesn't exist.
    """
    os.makedirs(path, exist_ok=True)


def dns_lookup(hostname: str, output_file: str) -> None:
    """
    Perform a simple DNS lookup using the standard library
    and save the results to output_file.
    """
    lines = []
    header = f"\n[+] Running DNS lookup for: {hostname}"
    print(header)
    lines.append(header)

    try:
        cname, aliases, ips = socket.gethostbyname_ex(hostname)
        line = f"    Canonical name: {cname}"
        print(line)
        lines.append(line)

        if aliases:
            line = f"    Aliases: {', '.join(aliases)}"
            print(line)
            lines.append(line)
        else:
            line = "    Aliases: (none)"
            print(line)
            lines.append(line)

        line = f"    IP addresses: {', '.join(ips)}"
        print(line)
        lines.append(line)
    except socket.gaierror as e:
        line = f"    [!] DNS lookup failed: {e}"
        print(line)
        lines.append(line)

    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_whois(target: str, output_file: str) -> None:
    """
    Run the `whois` command on the target using subprocess
    and save the results to output_file.
    """
    header = f"\n[+] Running WHOIS for: {target}"
    print(header)
    output_chunks = [header]

    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            line = f"    [!] whois returned non-zero exit code: {result.returncode}"
            print(line)
            output_chunks.append(line)
            if result.stderr:
                err_line = f"    STDERR: {result.stderr.strip()}"
                print(err_line)
                output_chunks.append(err_line)
        else:
            print(result.stdout)
            output_chunks.append(result.stdout.rstrip("\n"))
    except FileNotFoundError:
        line = "    [!] 'whois' command not found. Install it (e.g. apt install whois)."
        print(line)
        output_chunks.append(line)
    except subprocess.TimeoutExpired:
        line = "    [!] whois command timed out."
        print(line)
        output_chunks.append(line)

    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_chunks) + "\n")


def parse_http_ports_from_nmap_output(nmap_output: str):
    """
    Parse Nmap output and return a list of TCP ports that look like HTTP/HTTPS services.
    We look for lines with:
      - '/tcp'
      - 'open'
      - 'http' somewhere in the service/description
    """
    http_ports = []

    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line.lower():
            lower = line.lower()
            if "http" in lower:  # catches http, https, http-alt, etc.
                try:
                    # Nmap port line format usually starts with "PORT STATE SERVICE ..."
                    # e.g. "80/tcp open  http  Apache httpd 2.4.41 ((Ubuntu))"
                    port_str = line.split("/")[0].strip()
                    port = int(port_str)
                    http_ports.append(port)
                except ValueError:
                    # If parsing fails, just skip this line
                    continue

    return http_ports


def run_nmap_scan(target: str, output_file: str):
    """
    Run an Nmap scan against the target with:
      - Stealth SYN scan (-sS)
      - All TCP ports (-p-)
      - Service/version detection (-sV)
      - Default scripts (-sC)
      - Basic vulnerability scripts (--script vuln)
      - Verbose output (-vv)
      - Faster timing template (-T5)

    Save the results to output_file and return a list of HTTP/HTTPS ports found.
    """
    header = f"\n[+] Running Nmap scan for: {target}"
    print(header)
    output_chunks = [header]

    cmd = [
        "nmap",
        "-sS",                  # Stealth SYN scan
        "-sV",                  # Service/version detection
        "-sC",                  # Default NSE scripts
        "--script", "vuln",     # Basic vuln scripts
        "-p-",                  # All TCP ports
        "-vv",                  # Very verbose output
        "-T5",                  # Faster timing
        target
    ]

    cmd_line = f"    [*] Nmap command: {' '.join(cmd)}"
    print(cmd_line)
    output_chunks.append(cmd_line)

    nmap_output = ""
    http_ports = []

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800  # up to 30 minutes for all-ports scan
        )
        if result.returncode != 0:
            line = f"    [!] Nmap returned non-zero exit code: {result.returncode}"
            print(line)
            output_chunks.append(line)
            if result.stderr:
                err_line = f"    STDERR: {result.stderr.strip()}"
                print(err_line)
                output_chunks.append(err_line)
        else:
            nmap_output = result.stdout
            print(nmap_output)
            output_chunks.append(nmap_output.rstrip("\n"))
            http_ports = parse_http_ports_from_nmap_output(nmap_output)
    except FileNotFoundError:
        line = "    [!] 'nmap' command not found. Install it (e.g. apt install nmap)."
        print(line)
        output_chunks.append(line)
    except subprocess.TimeoutExpired:
        line = "    [!] Nmap scan timed out (consider scanning fewer ports or using faster settings)."
        print(line)
        output_chunks.append(line)

    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_chunks) + "\n")

    return http_ports


def run_gobuster_subdomains(domain: str, wordlist: str, output_file: str) -> None:
    """
    Run gobuster in DNS mode to fuzz subdomains for the given domain or IP.

    Command:
      gobuster dns -d <domain> -w <wordlist> -t 50

    Save the results to output_file.
    """
    header = f"\n[+] Running Gobuster subdomain fuzzing for: {domain}"
    print(header)
    output_chunks = [header]

    # Check that the wordlist exists before running
    if not os.path.isfile(wordlist):
        line = f"    [!] Wordlist not found at: {wordlist}. Skipping gobuster dns."
        print(line)
        output_chunks.append(line)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(output_chunks) + "\n")
        return

    cmd = [
        "gobuster",
        "dns",
        "-d", domain,
        "-w", wordlist,
        "-t", "50"
    ]

    cmd_line = f"    [*] Gobuster dns command: {' '.join(cmd)}"
    print(cmd_line)
    output_chunks.append(cmd_line)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # up to 1 hour, adjust as needed
        )
        if result.returncode != 0:
            line = f"    [!] Gobuster dns returned non-zero exit code: {result.returncode}"
            print(line)
            output_chunks.append(line)
            if result.stderr:
                err_line = f"    STDERR: {result.stderr.strip()}"
                print(err_line)
                output_chunks.append(err_line)
        else:
            print(result.stdout)
            output_chunks.append(result.stdout.rstrip("\n"))
    except FileNotFoundError:
        line = "    [!] 'gobuster' command not found. Install it (e.g. apt install gobuster)."
        print(line)
        output_chunks.append(line)
    except subprocess.TimeoutExpired:
        line = "    [!] Gobuster dns scan timed out."
        print(line)
        output_chunks.append(line)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_chunks) + "\n")


def run_gobuster_directories(url: str, wordlist: str, output_file: str) -> None:
    """
    Run gobuster in directory mode to fuzz paths on the given URL.

    Command:
      gobuster dir -u <url> -w <wordlist> -t 50

    Save the results to output_file.
    """
    header = f"\n[+] Running Gobuster directory fuzzing for: {url}"
    print(header)
    output_chunks = [header]

    # Check that the wordlist exists before running
    if not os.path.isfile(wordlist):
        line = f"    [!] Directory wordlist not found at: {wordlist}. Skipping gobuster dir."
        print(line)
        output_chunks.append(line)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(output_chunks) + "\n")
        return

    cmd = [
        "gobuster",
        "dir",
        "-u", url,
        "-w", wordlist,
        "-t", "50"
    ]

    cmd_line = f"    [*] Gobuster dir command: {' '.join(cmd)}"
    print(cmd_line)
    output_chunks.append(cmd_line)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # up to 1 hour, adjust as needed
        )
        if result.returncode != 0:
            line = f"    [!] Gobuster dir returned non-zero exit code: {result.returncode}"
            print(line)
            output_chunks.append(line)
            if result.stderr:
                err_line = f"    STDERR: {result.stderr.strip()}"
                print(err_line)
                output_chunks.append(err_line)
        else:
            print(result.stdout)
            output_chunks.append(result.stdout.rstrip("\n"))
    except FileNotFoundError:
        line = "    [!] 'gobuster' command not found. Install it (e.g. apt install gobuster)."
        print(line)
        output_chunks.append(line)
    except subprocess.TimeoutExpired:
        line = "    [!] Gobuster dir scan timed out."
        print(line)
        output_chunks.append(line)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_chunks) + "\n")


def build_base_url(host: str, http_ports):
    """
    Build a base URL from the host (domain or IP) and list of HTTP ports.

    Heuristic:
      - If 443 is open, prefer https:// on 443
      - Otherwise, take the first HTTP port and use http://
      - Include :port when non-standard (not 80/443)
    """
    if not http_ports:
        return None

    if 443 in http_ports:
        port = 443
        scheme = "https"
    else:
        port = http_ports[0]
        scheme = "http"

    if port in (80, 443):
        return f"{scheme}://{host}"
    else:
        return f"{scheme}://{host}:{port}"


def parse_args():
    """
    Use argparse to get the target from the command line.

    Example usage:
      python recon_basic.py -t https://example.com
      python recon_basic.py --target 10.10.10.10
    """
    parser = argparse.ArgumentParser(
        description="Basic recon script: DNS lookup + WHOIS + Nmap + Gobuster (subdomains & directories)."
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP, domain, or URL (e.g. https://example.com or 10.10.10.10)"
    )
    parser.add_argument(
        "-o", "--outdir",
        default="results",
        help="Base output directory (default: results)"
    )
    parser.add_argument(
        "--subdomain-wordlist",
        default=DEFAULT_SUBDOMAIN_WORDLIST,
        help="Wordlist for subdomain fuzzing (default: local bundled wordlist)"
    )
    parser.add_argument(
        "--dir-wordlist",
        default=DEFAULT_DIR_WORDLIST,
        help="Wordlist for directory fuzzing (default: local bundled wordlist)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    raw_target = args.target

    print(f"[*] Raw target: {raw_target}")
    normalized = normalize_target(raw_target)
    print(f"[*] Normalized target: {normalized}")

    # Build directory structure:
    # results/<target>/{dns,whois,nmap,subdomains,directories}/
    base_dir = os.path.join(args.outdir, normalized)
    dns_dir = os.path.join(base_dir, "dns")
    whois_dir = os.path.join(base_dir, "whois")
    nmap_dir = os.path.join(base_dir, "nmap")
    subdomains_dir = os.path.join(base_dir, "subdomains")
    directories_dir = os.path.join(base_dir, "directories")

    # Ensure directories exist BEFORE scans
    ensure_dir(dns_dir)
    ensure_dir(whois_dir)
    ensure_dir(nmap_dir)
    ensure_dir(subdomains_dir)
    ensure_dir(directories_dir)

    dns_output_file = os.path.join(dns_dir, "dns.txt")
    whois_output_file = os.path.join(whois_dir, "whois.txt")
    nmap_output_file = os.path.join(nmap_dir, "nmap.txt")
    gobuster_subdomains_file = os.path.join(subdomains_dir, "gobuster_subdomains.txt")
    gobuster_dirs_file = os.path.join(directories_dir, "gobuster_directories.txt")

    # Run core scans
    dns_lookup(normalized, dns_output_file)
    run_whois(normalized, whois_output_file)
    http_ports = run_nmap_scan(normalized, nmap_output_file)

    # Gobuster scans (regardless of IP vs domain, but still only if HTTP/HTTPS found)
    if http_ports:
        print(f"\n[*] Detected HTTP/HTTPS services on ports: {', '.join(map(str, http_ports))}")

        print("[*] Running Gobuster subdomain fuzzing...")
        run_gobuster_subdomains(
            domain=normalized,
            wordlist=args.subdomain_wordlist,
            output_file=gobuster_subdomains_file
        )

        base_url = build_base_url(normalized, http_ports)
        if base_url:
            print(f"[*] Running Gobuster directory fuzzing against: {base_url}")
            run_gobuster_directories(
                url=base_url,
                wordlist=args.dir_wordlist,
                output_file=gobuster_dirs_file
            )
        else:
            print("[*] Could not determine a base URL for directory fuzzing.")
    else:
        print("\n[*] No HTTP/HTTPS services detected by Nmap; skipping Gobuster fuzzing.")

    print(f"\n[*] All results saved under: {base_dir}")


if __name__ == "__main__":
    main()

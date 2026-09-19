#!/usr/bin/env python3
"""
Kali Linux MCP Server — Exposes Kali pentesting tools as MCP tools.
Runs on the Kali machine, communicates via stdio over SSH.

Install: pip install mcp[cli]<2
Run directly:                          python3 kali_mcp_server.py
Or run using the installed command:    start-mcp-server (installed in PATH by setup.sh)

"""
# Shebang tells Linux which interpreter should execute the file when you run the file directly.
# "Find python3 using the system's PATH and use it to run this file."

import asyncio
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
from datetime import datetime
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────
# Server Setup
# ──────────────────────────────────────────────

mcp = FastMCP(
    "kali",
    instructions=(
        "Kali Linux Pentesting MCP Server — Provides access to "
        "Nmap, Nikto, SQLMap, Gobuster, Dirb, Hydra, John, Metasploit, "
        "WPScan, Enum4Linux, cURL, Wget, WhatWeb, SSLScan, WAFW00F, "
        "Feroxbuster, FFUF, Nuclei, Subfinder, Arjun, XSStrike, Commix, "
        "Dalfox, testssl.sh, and raw command execution."
    )
)

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

MAX_OUTPUT_BYTES = 100_000  # 100 KB output cap per tool call
COMMAND_TIMEOUT = 600       # 10 min default timeout


async def _run(cmd: str, timeout: int = COMMAND_TIMEOUT, cwd: str = "/tmp") -> dict:
    """Run a shell command async, capture stdout+stderr, enforce timeout and output cap."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            preexec_fn=os.setsid,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            # Kill the entire process group
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            return {
                "status": "timeout",
                "exit_code": -1,
                "command": cmd,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds. Partial output may be lost.",
                "timeout_seconds": timeout,
            }

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        # Cap output
        if len(stdout_text) > MAX_OUTPUT_BYTES:
            stdout_text = stdout_text[:MAX_OUTPUT_BYTES] + f"\n\n[OUTPUT TRUNCATED — exceeded {MAX_OUTPUT_BYTES} bytes]"
        if len(stderr_text) > MAX_OUTPUT_BYTES:
            stderr_text = stderr_text[:MAX_OUTPUT_BYTES] + f"\n\n[STDERR TRUNCATED — exceeded {MAX_OUTPUT_BYTES} bytes]"

        return {
            "status": "success" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "command": cmd,
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception as e:
        return {
            "status": "error",
            "exit_code": -1,
            "command": cmd,
            "stdout": "",
            "stderr": str(e),
        }


def _sanitize_target(target: str) -> str:
    """Basic validation to prevent command injection in target parameters."""
    # Allow only reasonable target characters: alphanumeric, dots, colons, slashes, hyphens, underscores
    import re
    if not re.match(r'^[a-zA-Z0-9\.\:\-\_\/\@\?\&\=\%\+\#\~]+$', target):
        raise ValueError(f"Invalid target format: {target}")
    return target


def _sanitize_arg(arg: str) -> str:
    """Shell-escape an argument to prevent injection."""
    return shlex.quote(arg)


# ──────────────────────────────────────────────
# Health Check
# ──────────────────────────────────────────────

@mcp.tool()
async def server_health() -> str:
    """Check the Kali MCP server health and list available tools with their install status."""
    tools = {
        "nmap": "nmap --version",
        "nikto": "nikto -Version",
        "sqlmap": "sqlmap --version",
        "gobuster": "gobuster version",
        "dirb": "which dirb",
        "hydra": "hydra -h 2>&1 | head -1",
        "john": "john --help 2>&1 | head -1",
        "msfconsole": "msfconsole --version",
        "wpscan": "wpscan --version",
        "enum4linux": "which enum4linux",
        "curl": "curl --version | head -1",
        "wget": "which wget",
        "whatweb": "which whatweb",
        "sslscan": "which sslscan",
        "testssl": "which testssl.sh || which testssl",
        "ffuf": "which ffuf",
        "nuclei": "which nuclei",
        "amass": "which amass",
        "subfinder": "which subfinder",
        "httpx": "which httpx",
        "feroxbuster": "which feroxbuster",
    }

    results = {}
    for tool, check_cmd in tools.items():
        r = await _run(check_cmd, timeout=10)
        results[tool] = {
            "installed": r["exit_code"] == 0,
            "info": r["stdout"].strip()[:200] if r["exit_code"] == 0 else "NOT INSTALLED",
        }

    hostname = (await _run("hostname", timeout=5))["stdout"].strip()
    ip = (await _run("hostname -I | awk '{print $1}'", timeout=5))["stdout"].strip()
    uptime = (await _run("uptime -p", timeout=5))["stdout"].strip()

    return json.dumps({
        "server": "Kali MCP Server v2.0.0",
        "hostname": hostname,
        "ip": ip,
        "uptime": uptime,
        "timestamp": datetime.now().isoformat(),
        "tools": results,
    }, indent=2)


# ──────────────────────────────────────────────
# Nmap — Network Scanner
# ──────────────────────────────────────────────

@mcp.tool()
async def nmap_scan(
    target: str,
    scan_type: str = "-sV",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run an Nmap scan against a target.

    Args:
        target: Target IP, hostname, or CIDR range (e.g. "192.168.1.1", "example.com", "10.0.0.0/24")
        scan_type: Nmap scan type flags (default "-sV" for version detection). Examples:
            "-sS" = SYN scan, "-sT" = TCP connect, "-sU" = UDP scan,
            "-sV" = version detection, "-sC" = default scripts,
            "-A" = aggressive (OS, version, scripts, traceroute),
            "-sn" = ping scan (host discovery only)
        ports: Port specification (e.g. "80,443", "1-1000", "top100", "-" for all). Default: Nmap top 1000.
        scripts: NSE scripts to run (e.g. "ssl-enum-ciphers", "http-enum,http-headers", "vuln")
        extra_args: Additional Nmap arguments (e.g. "--min-rate 1000", "-O", "--script-args=unsafe=1")
        timeout: Command timeout in seconds (default 300)
    """
    target = _sanitize_target(target)
    cmd = f"nmap {scan_type}"

    if ports:
        cmd += f" -p {_sanitize_arg(ports)}"
    if scripts:
        cmd += f" --script={_sanitize_arg(scripts)}"
    if extra_args:
        cmd += f" {extra_args}"

    cmd += f" {_sanitize_arg(target)}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Nikto — Web Server Scanner
# ──────────────────────────────────────────────

@mcp.tool()
async def nikto_scan(
    target: str,
    port: Optional[int] = None,
    ssl: bool = False,
    tuning: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run a Nikto web server vulnerability scan.

    Args:
        target: Target URL or hostname (e.g. "http://example.com", "192.168.1.1")
        port: Target port (default: auto-detect from URL)
        ssl: Force SSL/TLS connection
        tuning: Nikto scan tuning options. Values:
            "1" = Interesting File, "2" = Misconfiguration, "3" = Information Disclosure,
            "4" = Injection (XSS/Script), "5" = Remote File Retrieval (in webroot),
            "6" = DoS (SKIPPED by default), "7" = Remote File Retrieval (server-wide),
            "8" = Command Execution, "9" = SQL Injection, "0" = File Upload,
            "a" = Authentication Bypass, "b" = Software Identification, "c" = Remote Source Inclusion
            Combine: "1234589abc" for everything except DoS
        extra_args: Additional Nikto arguments
        timeout: Command timeout in seconds (default 600)
    """
    target = _sanitize_target(target)
    cmd = f"nikto -h {_sanitize_arg(target)} -nointeractive"

    if port:
        cmd += f" -p {port}"
    if ssl:
        cmd += " -ssl"
    if tuning:
        cmd += f" -Tuning {_sanitize_arg(tuning)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# SQLMap — SQL Injection Scanner
# ──────────────────────────────────────────────

@mcp.tool()
async def sqlmap_scan(
    url: Optional[str] = None,
    request_file: Optional[str] = None,
    data: Optional[str] = None,
    param: Optional[str] = None,
    cookie: Optional[str] = None,
    headers: Optional[str] = None,
    method: Optional[str] = None,
    level: int = 3,
    risk: int = 2,
    technique: Optional[str] = None,
    dbms: Optional[str] = None,
    tamper: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run SQLMap for SQL injection detection and exploitation.

    Args:
        url: Target URL with injection point marked by * or with parameters (e.g. "http://site.com/page?id=1")
        request_file: Path to file containing raw HTTP request (alternative to url)
        data: POST data string (e.g. "username=admin&password=test")
        param: Specific parameter to test (e.g. "id", "username")
        cookie: Cookie header value (e.g. "PHPSESSID=abc123")
        headers: Extra headers as newline-separated string (e.g. "X-Auth: token123\\nReferer: http://site.com")
        method: HTTP method (GET, POST, PUT, etc.)
        level: Testing level 1-5 (default 3). Higher = more payloads + tests headers/cookies
        risk: Risk level 1-3 (default 2). Higher = more aggressive payloads (OR-based, heavy queries)
        technique: SQLi techniques to test. B=Boolean, E=Error, U=UNION, S=Stacked, T=Time, Q=Inline
            Default: "BEUSTQ" (all). Example: "BEU" for Boolean+Error+UNION only
        dbms: Force specific DBMS (e.g. "MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite")
        tamper: Tamper scripts for WAF bypass (e.g. "space2comment,between", "charencode")
        extra_args: Additional SQLMap arguments (e.g. "--dump", "--tables", "--dbs", "--os-shell")
        timeout: Command timeout in seconds (default 600)
    """
    cmd = "sqlmap --batch --random-agent"

    if url:
        cmd += f" -u {_sanitize_arg(url)}"
    if request_file:
        cmd += f" -r {_sanitize_arg(request_file)}"
    if data:
        cmd += f" --data={_sanitize_arg(data)}"
    if param:
        cmd += f" -p {_sanitize_arg(param)}"
    if cookie:
        cmd += f" --cookie={_sanitize_arg(cookie)}"
    if headers:
        for h in headers.split("\\n"):
            h = h.strip()
            if h:
                cmd += f" -H {_sanitize_arg(h)}"
    if method:
        cmd += f" --method={_sanitize_arg(method)}"
    if technique:
        cmd += f" --technique={_sanitize_arg(technique)}"
    if dbms:
        cmd += f" --dbms={_sanitize_arg(dbms)}"
    if tamper:
        cmd += f" --tamper={_sanitize_arg(tamper)}"

    cmd += f" --level={level} --risk={risk}"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Gobuster — Directory / DNS / VHost Brute-forcer
# ──────────────────────────────────────────────

@mcp.tool()
async def gobuster_scan(
    target: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: Optional[str] = None,
    status_codes: Optional[str] = None,
    threads: int = 20,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run Gobuster for directory, DNS, or vhost brute-forcing.

    Args:
        target: Target URL (dir mode: "http://example.com") or domain (dns mode: "example.com")
        mode: Scan mode - "dir" (directory), "dns" (subdomain), "vhost" (virtual host), "fuzz"
        wordlist: Path to wordlist. Common ones:
            "/usr/share/wordlists/dirb/common.txt" (4.6K words),
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" (220K words),
            "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        extensions: File extensions to search for in dir mode (e.g. "php,html,txt,bak,old,js,asp,aspx,jsp")
        status_codes: Status codes to include (e.g. "200,204,301,302,307,401,403"). Default: positive codes
        threads: Number of concurrent threads (default 20)
        extra_args: Additional Gobuster arguments (e.g. "--no-tls-validation", "-c 'cookie=val'", "-H 'Authorization: Bearer xxx'")
        timeout: Command timeout in seconds (default 300)
    """
    target = _sanitize_target(target)

    if mode == "dir":
        cmd = f"gobuster dir -u {_sanitize_arg(target)} -w {_sanitize_arg(wordlist)} -t {threads}"
        if extensions:
            cmd += f" -x {_sanitize_arg(extensions)}"
        if status_codes:
            cmd += f" -s {_sanitize_arg(status_codes)}"
    elif mode == "dns":
        cmd = f"gobuster dns -d {_sanitize_arg(target)} -w {_sanitize_arg(wordlist)} -t {threads}"
    elif mode == "vhost":
        cmd = f"gobuster vhost -u {_sanitize_arg(target)} -w {_sanitize_arg(wordlist)} -t {threads}"
    elif mode == "fuzz":
        cmd = f"gobuster fuzz -u {_sanitize_arg(target)} -w {_sanitize_arg(wordlist)} -t {threads}"
    else:
        return json.dumps({"status": "error", "stderr": f"Unknown mode: {mode}. Use dir/dns/vhost/fuzz."})

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Dirb — Web Content Scanner
# ──────────────────────────────────────────────

@mcp.tool()
async def dirb_scan(
    target: str,
    wordlist: str = "/usr/share/dirb/wordlists/common.txt",
    extensions: Optional[str] = None,
    cookie: Optional[str] = None,
    auth: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run DIRB for web content discovery (recursive by default).

    Args:
        target: Target URL (e.g. "http://example.com")
        wordlist: Path to wordlist (default: /usr/share/dirb/wordlists/common.txt)
        extensions: File extensions to search (e.g. ".php,.html,.txt,.bak")
        cookie: Cookie string (e.g. "session=abc123")
        auth: HTTP auth as "user:password"
        extra_args: Additional DIRB arguments (e.g. "-N 404" to ignore 404, "-r" to not recurse)
        timeout: Command timeout in seconds (default 300)
    """
    target = _sanitize_target(target)
    cmd = f"dirb {_sanitize_arg(target)} {_sanitize_arg(wordlist)}"

    if extensions:
        cmd += f" -X {_sanitize_arg(extensions)}"
    if cookie:
        cmd += f" -c {_sanitize_arg(cookie)}"
    if auth:
        cmd += f" -u {_sanitize_arg(auth)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Hydra — Network Login Brute-forcer
# ──────────────────────────────────────────────

@mcp.tool()
async def hydra_attack(
    target: str,
    service: str,
    username: Optional[str] = None,
    username_file: Optional[str] = None,
    password: Optional[str] = None,
    password_file: Optional[str] = None,
    port: Optional[int] = None,
    threads: int = 8,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run Hydra for network login brute-forcing.

    Args:
        target: Target IP or hostname
        service: Service to attack. Common values:
            "http-post-form", "http-get-form", "https-post-form",
            "ssh", "ftp", "mysql", "mssql", "rdp", "smb", "vnc",
            "telnet", "smtp", "pop3", "imap", "ldap"
            For http forms: "http-post-form" with extra_args containing the form spec
        username: Single username to test
        username_file: Path to file with usernames (one per line)
        password: Single password to test
        password_file: Path to password list. Common:
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
            "/usr/share/seclists/Passwords/darkweb2017-top100.txt"
        port: Target port (overrides service default)
        threads: Parallel tasks (default 8, max 64)
        extra_args: Additional Hydra arguments. For HTTP forms, include the form specification:
            '/login:username=^USER^&password=^PASS^:F=Invalid' (path:params:fail_string)
        timeout: Command timeout in seconds (default 600)
    """
    target = _sanitize_target(target)
    cmd = f"hydra -t {threads} -V"

    if username:
        cmd += f" -l {_sanitize_arg(username)}"
    elif username_file:
        cmd += f" -L {_sanitize_arg(username_file)}"

    if password:
        cmd += f" -p {_sanitize_arg(password)}"
    elif password_file:
        cmd += f" -P {_sanitize_arg(password_file)}"

    if port:
        cmd += f" -s {port}"

    cmd += f" {_sanitize_arg(target)} {_sanitize_arg(service)}"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# John the Ripper — Password Cracker
# ──────────────────────────────────────────────

@mcp.tool()
async def john_crack(
    hash_file: str,
    wordlist: Optional[str] = None,
    format: Optional[str] = None,
    rules: Optional[str] = None,
    show: bool = False,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run John the Ripper for password/hash cracking.

    Args:
        hash_file: Path to file containing hashes to crack
        wordlist: Path to wordlist (e.g. "/usr/share/wordlists/rockyou.txt"). If omitted, uses John's default modes.
        format: Hash format (e.g. "raw-md5", "raw-sha256", "bcrypt", "ntlm", "md5crypt", "sha512crypt",
                "zip", "rar", "pdf", "ssh", "keepass"). Use "john --list=formats" to see all.
        rules: Mangling rules (e.g. "best64", "wordlist", "jumbo", "koreLogic")
        show: If True, show already-cracked passwords instead of cracking
        extra_args: Additional John arguments (e.g. "--incremental", "--mask=?a?a?a?a?a")
        timeout: Command timeout in seconds (default 600)
    """
    if show:
        cmd = f"john --show {_sanitize_arg(hash_file)}"
        if format:
            cmd += f" --format={_sanitize_arg(format)}"
    else:
        cmd = f"john {_sanitize_arg(hash_file)}"
        if wordlist:
            cmd += f" --wordlist={_sanitize_arg(wordlist)}"
        if format:
            cmd += f" --format={_sanitize_arg(format)}"
        if rules:
            cmd += f" --rules={_sanitize_arg(rules)}"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)

    # Also show cracked results
    if not show:
        show_result = await _run(f"john --show {_sanitize_arg(hash_file)}", timeout=30)
        result["cracked_passwords"] = show_result["stdout"]

    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Metasploit — Exploitation Framework
# ──────────────────────────────────────────────

@mcp.tool()
async def metasploit_run(
    module: str,
    options: dict,
    payload: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run a Metasploit module (exploit, auxiliary, scanner, post) non-interactively via msfconsole -x.

    Args:
        module: Full module path (e.g. "auxiliary/scanner/http/http_version",
                "exploit/multi/http/struts2_content_type_ognl",
                "auxiliary/scanner/ssl/openssl_heartbleed",
                "auxiliary/scanner/http/dir_scanner")
        options: Dictionary of module options (e.g. {"RHOSTS": "192.168.1.1", "RPORT": 443, "SSL": true})
        payload: Payload module for exploits (e.g. "cmd/unix/reverse_bash", "windows/meterpreter/reverse_tcp").
                 Not needed for auxiliary/scanner modules.
        timeout: Command timeout in seconds (default 300)
    """
    # Build msfconsole resource commands
    commands = [f"use {module}"]

    for key, val in options.items():
        commands.append(f"set {key} {val}")

    if payload:
        commands.append(f"set PAYLOAD {payload}")

    commands.append("run")
    commands.append("exit")

    # Join with semicolons for -x flag
    cmd_string = "; ".join(commands)
    cmd = f"msfconsole -q -x {_sanitize_arg(cmd_string)}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# WPScan — WordPress Vulnerability Scanner
# ──────────────────────────────────────────────

@mcp.tool()
async def wpscan_analyze(
    target: str,
    enumerate: Optional[str] = None,
    api_token: Optional[str] = None,
    passwords: Optional[str] = None,
    usernames: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run WPScan for WordPress vulnerability analysis.

    Args:
        target: WordPress site URL (e.g. "http://example.com")
        enumerate: Enumeration options (comma-separated):
            "vp" = vulnerable plugins, "ap" = all plugins,
            "vt" = vulnerable themes, "at" = all themes,
            "u" = users, "m" = media IDs, "cb" = config backups,
            "dbe" = DB exports, "tt" = timthumbs
            Example: "vp,vt,u,cb,dbe"
        api_token: WPVulnDB API token for vulnerability data
        passwords: Path to password list for brute-force
        usernames: Comma-separated usernames or path to usernames file
        extra_args: Additional WPScan arguments
        timeout: Command timeout in seconds (default 600)
    """
    target = _sanitize_target(target)
    cmd = f"wpscan --url {_sanitize_arg(target)} --no-banner --random-user-agent"

    if enumerate:
        cmd += f" -e {_sanitize_arg(enumerate)}"
    if api_token:
        cmd += f" --api-token {_sanitize_arg(api_token)}"
    if passwords:
        cmd += f" --passwords {_sanitize_arg(passwords)}"
    if usernames:
        cmd += f" --usernames {_sanitize_arg(usernames)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Enum4Linux — SMB/NetBIOS Enumeration
# ──────────────────────────────────────────────

@mcp.tool()
async def enum4linux_scan(
    target: str,
    full: bool = True,
    username: Optional[str] = None,
    password: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run enum4linux for Windows/Samba enumeration (users, shares, groups, policies).

    Args:
        target: Target IP or hostname
        full: Run all enumeration (-a flag). Default True.
        username: Username for authenticated enumeration
        password: Password for authenticated enumeration
        extra_args: Additional arguments (e.g. "-G" for group enum, "-S" for share enum, "-P" for policy)
        timeout: Command timeout in seconds (default 300)
    """
    target = _sanitize_target(target)

    # Try enum4linux-ng first (newer), fall back to classic
    check = await _run("which enum4linux-ng", timeout=5)
    if check["exit_code"] == 0:
        cmd = f"enum4linux-ng {_sanitize_arg(target)}"
        if full:
            cmd += " -A"
    else:
        cmd = f"enum4linux {_sanitize_arg(target)}"
        if full:
            cmd += " -a"

    if username:
        cmd += f" -u {_sanitize_arg(username)}"
    if password:
        cmd += f" -p {_sanitize_arg(password)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# cURL — Raw HTTP Requests
# ──────────────────────────────────────────────

@mcp.tool()
async def curl_request(
    url: str,
    method: str = "GET",
    headers: Optional[list[str]] = None,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    follow_redirects: bool = True,
    insecure: bool = True,
    include_headers: bool = True,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 60,
) -> str:
    """
    Execute a raw HTTP request using curl. Useful for manual testing, custom payloads, and protocol-level attacks.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE)
        headers: List of headers (e.g. ["Content-Type: application/json", "Authorization: Bearer xxx"])
        data: Request body (raw string, JSON, form data)
        cookie: Cookie header value
        follow_redirects: Follow 3xx redirects (default True)
        insecure: Skip TLS verification (default True)
        include_headers: Include response headers in output (default True)
        user_agent: Custom User-Agent string
        proxy: Proxy URL (e.g. "http://127.0.0.1:8080" to route through Burp)
        extra_args: Additional curl arguments (e.g. "--http2", "--compressed", "--max-time 10")
        timeout: Command timeout in seconds (default 60)
    """
    cmd = f"curl -s -X {_sanitize_arg(method)}"

    if include_headers:
        cmd += " -i"
    if follow_redirects:
        cmd += " -L"
    if insecure:
        cmd += " -k"
    if user_agent:
        cmd += f" -A {_sanitize_arg(user_agent)}"
    if cookie:
        cmd += f" -b {_sanitize_arg(cookie)}"
    if proxy:
        cmd += f" -x {_sanitize_arg(proxy)}"
    if data:
        cmd += f" -d {_sanitize_arg(data)}"
    if headers:
        for h in headers:
            cmd += f" -H {_sanitize_arg(h)}"
    if extra_args:
        cmd += f" {extra_args}"

    cmd += f" {_sanitize_arg(url)}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# SSLScan — TLS/SSL Analysis
# ──────────────────────────────────────────────

@mcp.tool()
async def sslscan(
    target: str,
    port: int = 443,
    extra_args: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """
    Run sslscan or testssl.sh for TLS/SSL configuration analysis.

    Args:
        target: Target hostname or IP
        port: Target port (default 443)
        extra_args: Additional arguments
        timeout: Command timeout in seconds (default 120)
    """
    target = _sanitize_target(target)

    # Prefer testssl.sh for more detailed output, fall back to sslscan
    check_testssl = await _run("which testssl.sh || which testssl", timeout=5)
    if check_testssl["exit_code"] == 0:
        testssl_bin = check_testssl["stdout"].strip()
        cmd = f"{testssl_bin} --color 0 {_sanitize_arg(target)}:{port}"
    else:
        cmd = f"sslscan {_sanitize_arg(target)}:{port}"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# WhatWeb — Web Technology Fingerprinting
# ──────────────────────────────────────────────

@mcp.tool()
async def whatweb_scan(
    target: str,
    aggression: int = 3,
    extra_args: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """
    Run WhatWeb for web technology identification and fingerprinting.

    Args:
        target: Target URL (e.g. "http://example.com")
        aggression: Aggression level 1-4 (1=stealthy, 3=aggressive, 4=heavy). Default 3.
        extra_args: Additional arguments (e.g. "--color=never", "-v")
        timeout: Command timeout in seconds (default 120)
    """
    target = _sanitize_target(target)
    cmd = f"whatweb -a {aggression} {_sanitize_arg(target)}"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# ffuf — Fast Fuzzer
# ──────────────────────────────────────────────

@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    method: str = "GET",
    headers: Optional[list[str]] = None,
    data: Optional[str] = None,
    filter_code: Optional[str] = None,
    filter_size: Optional[str] = None,
    match_code: Optional[str] = None,
    threads: int = 40,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run ffuf for web fuzzing (directories, parameters, subdomains, values).
    Mark the fuzz point in URL or data with FUZZ keyword.

    Args:
        url: Target URL with FUZZ keyword marking injection point
            Directory: "http://example.com/FUZZ"
            Parameter name: "http://example.com/page?FUZZ=value"
            Parameter value: "http://example.com/page?id=FUZZ"
            Subdomain: "http://FUZZ.example.com"
        wordlist: Path to wordlist (can use FUZZ keyword for multiple wordlists with -w flag)
        method: HTTP method (default GET)
        headers: List of headers (e.g. ["Cookie: session=abc", "Authorization: Bearer xxx"])
        data: POST body with FUZZ keyword (e.g. "username=admin&password=FUZZ")
        filter_code: HTTP status codes to filter OUT (e.g. "404,403,500")
        filter_size: Response sizes to filter OUT (e.g. "1234", "0")
        match_code: HTTP status codes to match/show (e.g. "200,301,302")
        threads: Concurrent threads (default 40)
        extra_args: Additional ffuf arguments (e.g. "-mc all", "-recursion", "-recursion-depth 3", "-rate 100")
        timeout: Command timeout in seconds (default 300)
    """
    cmd = f"ffuf -u {_sanitize_arg(url)} -w {_sanitize_arg(wordlist)} -t {threads} -X {method}"

    if headers:
        for h in headers:
            cmd += f" -H {_sanitize_arg(h)}"
    if data:
        cmd += f" -d {_sanitize_arg(data)}"
    if filter_code:
        cmd += f" -fc {_sanitize_arg(filter_code)}"
    if filter_size:
        cmd += f" -fs {_sanitize_arg(filter_size)}"
    if match_code:
        cmd += f" -mc {_sanitize_arg(match_code)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Nuclei — Template-based Vulnerability Scanner
# ──────────────────────────────────────────────

@mcp.tool()
async def nuclei_scan(
    target: str,
    templates: Optional[str] = None,
    tags: Optional[str] = None,
    severity: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run Nuclei template-based vulnerability scanner.

    Args:
        target: Target URL or file with list of URLs
        templates: Specific template paths or directories (e.g. "cves/", "vulnerabilities/", "misconfiguration/")
        tags: Template tags to include (e.g. "cve,rce,xss,sqli,lfi,ssrf,redirect")
        severity: Filter by severity (e.g. "critical,high,medium")
        extra_args: Additional Nuclei arguments (e.g. "-H 'Cookie: sess=xxx'", "-rl 50" for rate limit)
        timeout: Command timeout in seconds (default 600)
    """
    target = _sanitize_target(target)
    cmd = f"nuclei -u {_sanitize_arg(target)} -silent"

    if templates:
        cmd += f" -t {_sanitize_arg(templates)}"
    if tags:
        cmd += f" -tags {_sanitize_arg(tags)}"
    if severity:
        cmd += f" -severity {_sanitize_arg(severity)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Subfinder — Subdomain Discovery
# ──────────────────────────────────────────────

@mcp.tool()
async def subfinder_enum(
    domain: str,
    extra_args: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """
    Run Subfinder for passive subdomain enumeration.

    Args:
        domain: Target domain (e.g. "example.com")
        extra_args: Additional arguments (e.g. "-recursive", "-all")
        timeout: Command timeout in seconds (default 120)
    """
    target = _sanitize_target(domain)
    cmd = f"subfinder -d {_sanitize_arg(target)} -silent"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Hashcat — GPU Password Cracker
# ──────────────────────────────────────────────

@mcp.tool()
async def hashcat_crack(
    hash_file: str,
    hash_mode: int,
    wordlist: Optional[str] = None,
    rules: Optional[str] = None,
    attack_mode: int = 0,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run Hashcat for GPU-accelerated password cracking.

    Args:
        hash_file: Path to file containing hashes
        hash_mode: Hash type number. Common:
            0=MD5, 100=SHA1, 1400=SHA256, 1700=SHA512,
            3200=bcrypt, 1000=NTLM, 5600=NetNTLMv2,
            1800=sha512crypt, 500=md5crypt,
            13100=Kerberoast, 18200=AS-REP roast
        wordlist: Path to wordlist (for dictionary attack, mode 0)
        rules: Rules file (e.g. "/usr/share/hashcat/rules/best64.rule")
        attack_mode: 0=dictionary, 1=combinator, 3=brute-force, 6=hybrid(dict+mask), 7=hybrid(mask+dict)
        extra_args: Additional arguments (e.g. "-1 ?l?d" for custom charset, "--increment")
        timeout: Command timeout in seconds (default 600)
    """
    cmd = f"hashcat -m {hash_mode} -a {attack_mode} {_sanitize_arg(hash_file)}"

    if wordlist:
        cmd += f" {_sanitize_arg(wordlist)}"
    if rules:
        cmd += f" -r {_sanitize_arg(rules)}"
    if extra_args:
        cmd += f" {extra_args}"

    cmd += " --force --potfile-disable"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Execute Command — Raw Shell Access
# ──────────────────────────────────────────────

@mcp.tool()
async def execute_command(
    command: str,
    working_directory: str = "/tmp",
    timeout: int = 120,
) -> str:
    """
    Execute an arbitrary shell command on the Kali machine.
    Use this for tools not covered by dedicated functions, chaining commands,
    file operations, installing tools, or any custom workflow.

    Common uses:
    - "searchsploit apache 2.4" — search for exploits
    - "responder -I eth0 -rdw" — LLMNR/NBT-NS poisoning
    - "crackmapexec smb 192.168.1.0/24" — SMB network spray
    - "impacket-secretsdump user:pass@target" — credential dumping
    - "wafw00f http://target.com" — WAF detection
    - "arjun -u http://target.com/endpoint" — hidden parameter discovery
    - "cat /path/to/file" — read file contents
    - "pip install toolname" — install Python tools
    - "apt install -y package" — install system packages

    Args:
        command: Shell command to execute (piping and chaining supported)
        working_directory: Working directory for command execution (default /tmp)
        timeout: Command timeout in seconds (default 120)
    """
    result = await _run(command, timeout=timeout, cwd=working_directory)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Feroxbuster — Recursive Content Discovery
# ──────────────────────────────────────────────

@mcp.tool()
async def feroxbuster_scan(
    target: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    extensions: Optional[str] = None,
    threads: int = 50,
    depth: int = 3,
    filter_status: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Run Feroxbuster for recursive content discovery (faster alternative to Gobuster/Dirb).

    Args:
        target: Target URL (e.g. "http://example.com")
        wordlist: Path to wordlist
        extensions: Extensions to check (e.g. "php,html,js,txt,bak")
        threads: Concurrent threads (default 50)
        depth: Recursion depth (default 3)
        filter_status: Status codes to filter out (e.g. "404,403")
        extra_args: Additional arguments (e.g. "--insecure", "-H 'Cookie: x=y'", "--rate-limit 100")
        timeout: Command timeout in seconds (default 600)
    """
    target = _sanitize_target(target)
    cmd = f"feroxbuster -u {_sanitize_arg(target)} -w {_sanitize_arg(wordlist)} -t {threads} -d {depth} --no-state"

    if extensions:
        cmd += f" -x {_sanitize_arg(extensions)}"
    if filter_status:
        cmd += f" -C {_sanitize_arg(filter_status)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Commix — Command Injection Exploiter
# ──────────────────────────────────────────────

@mcp.tool()
async def commix_scan(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    param: Optional[str] = None,
    level: int = 3,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run Commix for automated command injection detection and exploitation.

    Args:
        url: Target URL (e.g. "http://example.com/page?cmd=test")
        data: POST body data (e.g. "host=127.0.0.1&submit=ping")
        cookie: Cookie string
        param: Specific parameter to test
        level: Testing level 1-3 (default 3)
        extra_args: Additional Commix arguments (e.g. "--technique=classic", "--os=unix")
        timeout: Command timeout in seconds (default 300)
    """
    cmd = f"commix --url={_sanitize_arg(url)} --batch --level={level}"

    if data:
        cmd += f" --data={_sanitize_arg(data)}"
    if cookie:
        cmd += f" --cookie={_sanitize_arg(cookie)}"
    if param:
        cmd += f" -p {_sanitize_arg(param)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# XSStrike — Advanced XSS Detection
# ──────────────────────────────────────────────

@mcp.tool()
async def xsstrike_scan(
    url: str,
    data: Optional[str] = None,
    headers: Optional[list[str]] = None,
    crawl: bool = False,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run XSStrike for advanced XSS detection with intelligent payload generation and WAF bypass.

    Args:
        url: Target URL with parameter (e.g. "http://example.com/search?q=test")
        data: POST data (e.g. "username=test&comment=hello")
        headers: Custom headers list
        crawl: Enable crawling mode to find all injection points
        extra_args: Additional arguments (e.g. "--fuzzer", "--blind", "--skip")
        timeout: Command timeout in seconds (default 300)
    """
    cmd = f"xsstrike -u {_sanitize_arg(url)} --skip"

    if data:
        cmd += f" -d {_sanitize_arg(data)}"
    if crawl:
        cmd += " --crawl"
    if headers:
        for h in headers:
            cmd += f" --headers {_sanitize_arg(h)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Dalfox — Fast XSS Finder
# ──────────────────────────────────────────────

@mcp.tool()
async def dalfox_scan(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run Dalfox for fast parameter-based XSS scanning with WAF evasion.

    Args:
        url: Target URL with parameter (e.g. "http://example.com/page?search=test")
        data: POST data
        cookie: Cookie header value
        extra_args: Additional arguments (e.g. "--blind http://your-callback.com", "--waf-evasion")
        timeout: Command timeout in seconds (default 300)
    """
    cmd = f"dalfox url {_sanitize_arg(url)}"

    if data:
        cmd += f" -d {_sanitize_arg(data)}"
    if cookie:
        cmd += f" --cookie {_sanitize_arg(cookie)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Arjun — Hidden Parameter Discovery
# ──────────────────────────────────────────────

@mcp.tool()
async def arjun_discover(
    url: str,
    method: str = "GET",
    headers: Optional[list[str]] = None,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run Arjun to discover hidden HTTP parameters on endpoints.

    Args:
        url: Target URL (e.g. "http://example.com/api/endpoint")
        method: HTTP method to use (GET, POST, JSON)
        headers: Custom headers list
        extra_args: Additional arguments (e.g. "-w /path/to/wordlist", "--stable")
        timeout: Command timeout in seconds (default 300)
    """
    cmd = f"arjun -u {_sanitize_arg(url)} -m {method}"

    if headers:
        for h in headers:
            cmd += f" --headers {_sanitize_arg(h)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# WAF Detection
# ──────────────────────────────────────────────

@mcp.tool()
async def wafw00f_detect(
    target: str,
    extra_args: Optional[str] = None,
    timeout: int = 60,
) -> str:
    """
    Run wafw00f to detect and identify Web Application Firewalls (WAF).

    Args:
        target: Target URL (e.g. "http://example.com")
        extra_args: Additional arguments (e.g. "-a" for all WAF checks)
        timeout: Command timeout in seconds (default 60)
    """
    target = _sanitize_target(target)
    cmd = f"wafw00f {_sanitize_arg(target)}"

    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# CrackMapExec — Network Pentesting Swiss Army Knife
# ──────────────────────────────────────────────

@mcp.tool()
async def crackmapexec_scan(
    target: str,
    protocol: str = "smb",
    username: Optional[str] = None,
    password: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run CrackMapExec (or NetExec) for network service enumeration and credential testing.

    Args:
        target: Target IP, range, or CIDR (e.g. "192.168.1.0/24")
        protocol: Protocol to test - "smb", "ssh", "ldap", "mssql", "winrm", "rdp", "ftp"
        username: Username (single or file path)
        password: Password (single or file path)
        extra_args: Additional arguments (e.g. "--shares", "--users", "--pass-pol", "--spider_plus", "--sam")
        timeout: Command timeout in seconds (default 300)
    """
    target = _sanitize_target(target)

    # Try netexec first (successor), fall back to crackmapexec
    check = await _run("which netexec", timeout=5)
    tool = "netexec" if check["exit_code"] == 0 else "crackmapexec"

    cmd = f"{tool} {protocol} {_sanitize_arg(target)}"

    if username:
        cmd += f" -u {_sanitize_arg(username)}"
    if password:
        cmd += f" -p {_sanitize_arg(password)}"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Searchsploit — Exploit Database Search
# ──────────────────────────────────────────────

@mcp.tool()
async def searchsploit(
    query: str,
    exact: bool = False,
    json_output: bool = True,
    extra_args: Optional[str] = None,
    timeout: int = 30,
) -> str:
    """
    Search ExploitDB for known exploits matching a software/version.

    Args:
        query: Search query (e.g. "Apache 2.4.49", "WordPress 5.8", "OpenSSH 7.2")
        exact: Match exact term (default False for broader search)
        json_output: Return results as JSON (default True)
        extra_args: Additional arguments (e.g. "--cve", "-w" for web URL)
        timeout: Command timeout in seconds (default 30)
    """
    cmd = f"searchsploit {_sanitize_arg(query)}"

    if exact:
        cmd += " --exact"
    if json_output:
        cmd += " --json"
    if extra_args:
        cmd += f" {extra_args}"

    result = await _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ──────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────

def _print_banner():
    """Print startup banner to stderr (stdout is reserved for JSON-RPC protocol)."""
    import shutil
    tools_to_check = {
        "nmap": "nmap",
        "nikto": "nikto",
        "sqlmap": "sqlmap",
        "gobuster": "gobuster",
        "dirb": "dirb",
        "hydra": "hydra",
        "john": "john",
        "msfconsole": "msfconsole",
        "wpscan": "wpscan",
        "enum4linux": "enum4linux",
        "curl": "curl",
        "whatweb": "whatweb",
        "sslscan": "sslscan",
        "ffuf": "ffuf",
        "nuclei": "nuclei",
        "subfinder": "subfinder",
        "feroxbuster": "feroxbuster",
        "commix": "commix",
        "wafw00f": "wafw00f",
        "hashcat": "hashcat",
        "netexec": "netexec",
        "searchsploit": "searchsploit",
    }

    GREEN = "\033[1;32m"
    RED = "\033[1;31m"
    CYAN = "\033[1;36m"
    YELLOW = "\033[1;33m"
    BOLD = "\033[1m"
    NC = "\033[0m"

    print(f"""
{CYAN}╔══════════════════════════════════════════════════╗
║        Kali MCP Server v2.0.0 — ONLINE           ║
╠══════════════════════════════════════════════════╣{NC}""", file=sys.stderr)

    # Get hostname and IP
    import socket
    hostname = socket.gethostname()
    try:
        ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True, text=True).strip()
    except Exception:
        ip = "unknown"

    print(f"║  {BOLD}Host:{NC} {hostname:<20} {BOLD}IP:{NC} {ip:<17} ║", file=sys.stderr)
    print(f"║  {BOLD}Transport:{NC} stdio          {BOLD}Protocol:{NC} JSON-RPC 2.0  ║", file=sys.stderr)
    print(f"{CYAN}╠══════════════════════════════════════════════════╣{NC}", file=sys.stderr)
    print(f"║  {BOLD}Available Tools:{NC}                                  ║", file=sys.stderr)

    installed = 0
    missing = 0
    for name, binary in tools_to_check.items():
        found = shutil.which(binary) is not None
        if found:
            status = f"{GREEN}✔{NC}"
            installed += 1
        else:
            status = f"{RED}✗{NC}"
            missing += 1
        print(f"║    {status} {name:<20}                         ║", file=sys.stderr)

    print(f"{CYAN}╠══════════════════════════════════════════════════╣{NC}", file=sys.stderr)
    print(f"║  {GREEN}✔ {installed} tools ready{NC}    {RED}✗ {missing} not installed{NC}            ║", file=sys.stderr)
    print(f"{CYAN}╠══════════════════════════════════════════════════╣{NC}", file=sys.stderr)

    # Count registered MCP tools
    print(f"║  {BOLD}MCP Tools Registered:{NC} 27                         ║", file=sys.stderr)
    print(f"║  {YELLOW}Waiting for client connection on stdio...{NC}       ║", file=sys.stderr)
    print(f"{CYAN}╚══════════════════════════════════════════════════╝{NC}", file=sys.stderr)
    print("", file=sys.stderr)


if __name__ == "__main__":
    _print_banner()
    mcp.run(transport="stdio")

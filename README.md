# Nmap NSE Security Scripts

This repository contains two custom **Nmap NSE (Nmap Scripting Engine)** scripts developed for network service discovery and information gathering.

The scripts are written in **Lua** and use Nmap's NSE libraries.

## Scripts

### 1. `tcp-service-info.nse`

A TCP service information script that runs against open TCP ports.

**Features:**
- Displays service information detected by Nmap
- Displays product and version information when available
- Measures TCP connection establishment time
- Attempts to retrieve an initial service banner

**Example:**

```bash
sudo nmap -sV -p 8000 --script tcp-service-info 127.0.0.1
```

A local Python HTTP server can be used for testing:

```bash
python3 -m http.server 8000
```

---

### 2. `https-tls-service-info.nse`

An HTTPS/TLS service information script designed for TCP port 443.

**Features:**
- Establishes an SSL/TLS connection
- Measures TLS connection establishment time
- Retrieves TLS certificate information
- Displays certificate Common Name and issuer
- Displays public-key type and size when available
- Displays certificate validity dates when available

**Example:**

```bash
sudo nmap -sV -p 443 --script https-tls-service-info example.com
```

## Installation

Copy the NSE scripts to the Nmap scripts directory:

```bash
sudo cp tcp-service-info.nse /usr/share/nmap/scripts/
sudo cp https-tls-service-info.nse /usr/share/nmap/scripts/
```

Update the Nmap NSE script database:

```bash
sudo nmap --script-updatedb
```

## Usage

### TCP Service Information

```bash
sudo nmap -sV -p 8000 --script tcp-service-info 127.0.0.1
```

### HTTPS/TLS Service Information

```bash
sudo nmap -sV -p 443 --script https-tls-service-info example.com
```

## Script Structure

Both scripts follow the standard NSE structure:

- `description` – Describes the script
- `author` – Script author
- `categories` – NSE script categories
- `portrule` – Determines when the script runs
- `action` – Contains the main script functionality

## Purpose

The scripts are intended for **network service discovery and information gathering**.

They do not perform:
- Vulnerability auditing
- Security scoring
- Risk scoring
- Security grading

## Requirements

- Linux environment
- Nmap
- Nmap Scripting Engine (NSE)
- Appropriate network permissions for the target

## Author

**Abhinav Mishra**

## Reference

Nmap Documentation:  
https://nmap.org/book/nse.html

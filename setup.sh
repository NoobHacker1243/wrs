#!/bin/bash

echo "[*] Updating package list..."
sudo apt update

echo "[*] Installing required APT packages..."
sudo apt install -y python3 nmap nikto whatweb sqlmap gobuster ffuf wget sslscan gowitness golang

echo "[*] Setting up Go environment..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

echo "[*] Installing Go-based security tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/s0md3v/Arjun@master
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/EnableSecurity/wafw00f@master

echo "[+] Installation complete! You can now run the tool using Python 3."

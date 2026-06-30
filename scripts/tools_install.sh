#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$ROOT_DIR"

OS=""
PACKAGE_MANAGER=""
APT_PACKAGES=(
    nmap
    nikto
    sqlmap
    dirbuster
    aircrack-ng
    wireshark
    git
    curl
    wget
    unzip
    python3
    python3-venv
    python3-pip
    build-essential
)
DNF_PACKAGES=(
    nmap
    nikto
    sqlmap
    dirbuster
    aircrack-ng
    wireshark
    git
    curl
    wget
    unzip
    python3
    python3-venv
    python3-pip
    make
    gcc
)
PACMAN_PACKAGES=(
    nmap
    nikto
    sqlmap
    dirbuster
    aircrack-ng
    wireshark-common
    git
    curl
    wget
    unzip
    python3
    python-pip
    base-devel
)

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="$ID"
        case "$OS" in
            ubuntu|debian|parrot)
                PACKAGE_MANAGER="apt"
                ;;
            fedora|rhel|centos)
                PACKAGE_MANAGER="dnf"
                ;;
            arch|manjaro)
                PACKAGE_MANAGER="pacman"
                ;;
            *)
                PACKAGE_MANAGER="unknown"
                ;;
        esac
    else
        OS="unknown"
    fi
}

echo "[*] Detecting OS..."
detect_os
echo "[+] OS: ${OS} (${PACKAGE_MANAGER})"

install_apt() {
    echo "[*] Updating APT..."
    sudo apt update -y
    echo "[*] Installing packages via apt..."
    sudo apt install -y "${APT_PACKAGES[@]}"
}

verify_tools() {
    local all_ok=true
    local tools=(
        nmap
        nikto
        sqlmap
        dirbuster
        aircrack-ng
        wireshark
        git
        curl
        wget
        unzip
        go
        nuclei
        ffuf
        httpx
        katana
        amass
        subfinder
    )
    echo ""
    echo "[*] Verifying tools..."
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            version=$("$tool" --version 2>&1 | head -n1 || true)
            echo "  [OK] $tool: $version"
        else
            echo "  [MISSING] $tool"
            all_ok=false
        fi
    done
    echo ""
    if [ "$all_ok" = true ]; then
        echo "[+] AllVerification passed."
    else
        echo "[-] Verification failed: some tools are missing or not on PATH."
    fi
}

case "$PACKAGE_MANAGER" in
    apt)
        install_apt
        ;;
    dnf)
        echo "[*] Using dnf..."
        sudo dnf install -y "${DNF_PACKAGES[@]}"
        ;;
    pacman)
        echo "[*] Using pacman..."
        sudo pacman -S --noconfirm "${PACMAN_PACKAGES[@]}"
        ;;
    *)
        echo "[!] Unsupported package manager. Please install tools manually."
        ;;
esac

verify_tools

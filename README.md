# nmap_helper

                                  _   _                       _   _      _
                                 | \ | |_ __ ___   __ _ _ __ | | | | ___| |_ __   ___ _ __
                                 |  \| | '_ ` _ \ / _` | '_ \| |_| |/ _ \ | '_ \ / _ \ '__|
                                 | |\  | | | | | | (_| | |_) |  _  |  __/ | |_) |  __/ |
                                 |_| \_|_| |_| |_|\__,_| .__/|_| |_|\___|_| .__/ \___|_|
                                                       |_|                |_|



# Nmap Cheat Sheet CLI Tool

This Python-based CLI tool provides an easy-to-use interface for learning and executing common Nmap commands, aimed at new cybersecurity professionals and enthusiasts. It simplifies complex Nmap commands by offering pre-built command templates, explanations, and a step-by-step interface for running them. The tool also includes color-coded output and real-time command execution, making it interactive and informative.

## Features

- **Basic Nmap Commands**: Access a list of commonly used Nmap commands, such as fast scans, aggressive scans, and vulnerability scans.
- **Target Specification**: Learn how to scan single or multiple IPs, domains, CIDR ranges, or even random hosts.
- **Host Discovery**: Execute host discovery commands using various methods like TCP SYN, TCP ACK, UDP, and ARP pings.
- **Port Scanning**: Run port scans with specific ports or ranges, or scan all TCP/UDP ports.
- **OS and Service Detection**: Detect the operating system and service versions of hosts.
- **Nmap Scripting Engine (NSE)**: Run NSE scripts to automate vulnerability scanning and service probing.
- **Command History**: View and re-run previously executed commands.
- **Real-time Output**: See the output of your Nmap commands in real-time, with color-coded output for better readability.

## Requirements

- **Python 3.6+**
- **Nmap**: Make sure Nmap is installed and accessible from the terminal.
- **colorama**: For cross-platform colored terminal output.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/nmap-cli-tool.git
    cd nmap-cli-tool
    ```

2. Install the required Python packages:

    ```bash
    pip install colorama
    ```

3. Ensure Nmap is installed on your system. You can check by running:

    ```bash
    nmap -v
    ```

    If Nmap is not installed, follow the instructions on the [Nmap download page](https://nmap.org/download.html).

## Usage

To run the Nmap Cheat Sheet CLI tool, execute the following command:

```bash
python nmap_cli.py

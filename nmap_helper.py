import os
import subprocess
import shlex
from colorama import Fore, init
from shutil import which, get_terminal_size
import textwrap
import sys

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Global variables
command_history = []

# Function to check if Nmap is installed
def check_nmap_installed():
    if which('nmap') is None:
        print(f"{Fore.RED}Error: Nmap is not installed on your system. Please install Nmap and try again.")
        sys.exit(1)

check_nmap_installed()

# Function to clear the screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to get terminal size
def get_terminal_width():
    try:
        width = get_terminal_size().columns
    except:
        width = 80  # Default width
    return width

# Function to sanitize user inputs
def sanitize_input(user_input):
    # Remove any characters that could be used for command injection
    return shlex.quote(user_input.strip())

# Function to execute Nmap commands and display output in real-time
def run_nmap_command(command):
    try:
        clear_screen()
        print(f"{Fore.YELLOW}Running Command: {Fore.CYAN}{command}\n")
        args = shlex.split(command)
        # Check if the command is an Nmap command (allow 'sudo' before 'nmap')
        if args[0].lower() == 'sudo' and len(args) > 1:
            nmap_index = 1
        else:
            nmap_index = 0
        if args[nmap_index].lower() != 'nmap':
            print(f"{Fore.RED}Error: Only 'nmap' commands are allowed.")
            input(f"\n{Fore.LIGHTWHITE_EX}Press Enter to continue...")
            return
        # Start the subprocess
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(f"{Fore.GREEN}{output}", end='')
        except KeyboardInterrupt:
            # If the user presses Ctrl+C, terminate the subprocess
            print(f"\n{Fore.RED}Scan canceled by user.")
            process.terminate()
            process.wait()
            input(f"\n{Fore.LIGHTWHITE_EX}Press Enter to continue...")
            return
        process.wait()
        if process.returncode == 0:
            command_history.append(command)
        else:
            print(f"{Fore.RED}Command exited with error code {process.returncode}. Not added to history.")
        input(f"\n{Fore.LIGHTWHITE_EX}Press Enter to continue...")
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Nmap command not found. Please ensure Nmap is installed and accessible.")
        input(f"\n{Fore.LIGHTWHITE_EX}Press Enter to continue...")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}")
        input(f"\n{Fore.LIGHTWHITE_EX}Press Enter to continue...")

# Function to print command lists with numbering
def print_command_list(commands, title=""):
    clear_screen()
    term_width = get_terminal_width()
    if title:
        print(f"{Fore.YELLOW}{title.center(term_width)}\n")
    # Adjust column widths based on terminal size
    col_no = 4
    col_cmd = int(term_width * 0.4)
    col_desc = term_width - col_no - col_cmd - 6  # Adjust for spacing
    header = f"{'No.':<{col_no}} {'Command':<{col_cmd}} {'Explanation':<{col_desc}}"
    print(f"{Fore.YELLOW}{header}")
    print(f"{Fore.YELLOW}{'-' * term_width}")
    for idx, (command, description) in enumerate(commands, 1):
        cmd_wrapped = textwrap.fill(command, width=col_cmd)
        desc_wrapped = textwrap.fill(description, width=col_desc)
        cmd_lines = cmd_wrapped.split('\n')
        desc_lines = desc_wrapped.split('\n')
        max_lines = max(len(cmd_lines), len(desc_lines))
        for i in range(max_lines):
            cmd_line = cmd_lines[i] if i < len(cmd_lines) else ''
            desc_line = desc_lines[i] if i < len(desc_lines) else ''
            line = f"{Fore.CYAN}{idx if i == 0 else '':<{col_no}} {cmd_line:<{col_cmd}} {Fore.WHITE}{desc_line:<{col_desc}}"
            print(line)
        print()
    footer = f"\n{Fore.LIGHTWHITE_EX}Type the number of the command to execute, type your own command, or press Enter to go back."
    print(footer)

# Function to handle command selection and execution
def select_and_run_command(commands):
    while True:
        print_command_list(commands)
        choice = input(f"{Fore.LIGHTWHITE_EX}\nEnter your choice: ").strip()
        if not choice or choice.lower() == 'exit':
            return
        # Check if the input is a number corresponding to a command
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(commands):
                idx -= 1
                command_template, description = commands[idx]
                # Find placeholders in the command template
                placeholders = [word.strip('{}') for word in command_template.split() if '{' in word and '}' in word]
                command = command_template
                # Prompt user for each placeholder
                for placeholder in placeholders:
                    while True:
                        value = input(f"Enter value for {placeholder}: ").strip()
                        if value:
                            sanitized_value = sanitize_input(value)
                            command = command.replace('{' + placeholder + '}', sanitized_value)
                            break
                        else:
                            print(f"{Fore.RED}Input cannot be empty. Please enter a valid value.")
                run_nmap_command(command)
                # Return to the previous menu after running the command
                return
            else:
                print(f"{Fore.RED}Invalid choice, please enter a number between 1 and {len(commands)}.")
        else:
            # Assume the input is a command and try to run it
            sanitized_command = choice.strip()
            if sanitized_command.lower() == 'exit':
                return
            elif sanitized_command:
                run_nmap_command(sanitized_command)
                # Return to the previous menu after running the command
                return
            else:
                print(f"{Fore.RED}Invalid input. Please enter a command or a valid option.")

# Nmap command categories (unchanged)
def basic_nmap_commands():
    commands = [
        ("nmap -F {target}", "Fast scan (Top 100 ports)"),
        ("nmap -p- {target}", "Full TCP scan (all 65535 ports)"),
        ("nmap -A {target}", "Aggressive scan (OS, version, script, traceroute)"),
        ("nmap --script vuln {target}", "Vulnerability scan using NSE"),
        ("nmap -sS {target}", "Stealth SYN scan"),
        ("nmap -sV {target}", "Service and version detection"),
        ("nmap -O {target}", "OS detection"),
        ("nmap -f {target}", "Scan through firewall (fragment packets)"),
        ("nmap -D RND:10 {target}", "Evade firewall with decoys"),
        ("nmap -T4 {target}", "Timing and performance tuning (fast scan)"),
        ("nmap -sU {target}", "UDP scan"),
        ("nmap {target}", "Default scan")
    ]
    select_and_run_command(commands)

def target_specification():
    commands = [
        ("nmap {ip_address}", "Scan a single IP"),
        ("nmap {ip_address1} {ip_address2}", "Scan multiple specific IPs"),
        ("nmap {ip_range}", "Scan a range of IPs"),
        ("nmap {domain_name}", "Scan a domain"),
        ("nmap {ip_address}/{CIDR}", "Scan using CIDR notation"),
        ("nmap -iL {targets_file}", "Scan targets from a file"),
        ("nmap --exclude {ip_address}", "Exclude specific IPs from scan"),
        ("nmap -iR {number}", "Scan random hosts (specify number)")
    ]
    select_and_run_command(commands)

def host_discovery():
    commands = [
        ("nmap {ip_range} -sL", "List targets only (no scanning)"),
        ("nmap {ip_range} -sn", "Disable port scanning (host discovery only)"),
        ("nmap {ip_address} -Pn", "Disable host discovery (port scan only)"),
        ("nmap {ip_range} -PS{ports}", "TCP SYN discovery on specific ports"),
        ("nmap {ip_range} -PA{ports}", "TCP ACK discovery"),
        ("nmap {ip_range} -PU{ports}", "UDP discovery"),
        ("nmap {ip_range} -PR", "ARP discovery on local network"),
        ("nmap {ip_address} -n", "No DNS resolution")
    ]
    select_and_run_command(commands)

def port_scanning():
    commands = [
        ("nmap {ip_address} -p {port}", "Scan a specific port"),
        ("nmap {ip_address} -p {port_range}", "Scan a range of ports"),
        ("nmap {ip_address} -p U:{udp_port},T:{tcp_ports}", "Scan TCP and UDP ports"),
        ("nmap {ip_address} -p-", "Scan all TCP ports"),
        ("nmap {ip_address} -F", "Fast scan (Top 100 ports)"),
        ("nmap {ip_address} --top-ports {number}", "Scan the top X ports"),
        ("nmap {ip_address} -p {service_names}", "Scan by service name"),
        ("nmap -sn {ip_address}", "Ping scan"),
        ("nmap -sI {zombie_ip} {target}", "Idle scan (zombie host)")
    ]
    select_and_run_command(commands)

def os_detection():
    commands = [
        ("nmap {ip_address} -O", "Remote OS detection"),
        ("nmap {ip_address} -O --osscan-limit", "Limit OS detection attempts"),
        ("nmap {ip_address} -O --osscan-guess", "Aggressive OS detection guessing"),
        ("nmap {ip_address} -O --max-os-tries {number}", "Limit OS detection retries"),
        ("nmap {ip_address} -A", "Enable OS detection, version detection, script scanning, and traceroute")
    ]
    select_and_run_command(commands)

def service_version_detection():
    commands = [
        ("nmap {ip_address} -sV", "Service version detection"),
        ("nmap {ip_address} -sV --version-intensity {number}", "Set intensity of version detection (0-9)"),
        ("nmap {ip_address} -sV --version-light", "Light service detection (faster)"),
        ("nmap {ip_address} -sV --version-all", "Aggressive service detection"),
        ("nmap {ip_address} --version-intensity {number}", "Service fingerprinting")
    ]
    select_and_run_command(commands)

def nse_scripts():
    commands = [
        ("nmap {ip_address} -sC", "Scan with default NSE scripts"),
        ("nmap {ip_address} --script={script_name}", "Run specific script"),
        ("nmap {ip_address} --script={script1},{script2}", "Run multiple scripts"),
        ("nmap {ip_address} --script vuln", "Vulnerability scan using NSE"),
        ("nmap {ip_address} --script {script_name} --script-args={args}", "Scan with specific script and arguments")
    ]
    select_and_run_command(commands)

def view_all_commands():
    clear_screen()
    term_width = get_terminal_width()
    all_commands = []
    categories = [
        ("Basic Nmap Commands", [
            ("nmap -F {target}", "Fast scan (Top 100 ports)"),
            ("nmap -p- {target}", "Full TCP scan (all 65535 ports)"),
            ("nmap -A {target}", "Aggressive scan (OS, version, script, traceroute)"),
            ("nmap --script vuln {target}", "Vulnerability scan using NSE"),
            ("nmap -sS {target}", "Stealth SYN scan"),
            ("nmap -sV {target}", "Service and version detection"),
            ("nmap -O {target}", "OS detection"),
            ("nmap -f {target}", "Scan through firewall (fragment packets)"),
            ("nmap -D RND:10 {target}", "Evade firewall with decoys"),
            ("nmap -T4 {target}", "Timing and performance tuning (fast scan)"),
            ("nmap -sU {target}", "UDP scan"),
            ("nmap {target}", "Default scan")
        ]),
        ("Target Specification", [
            ("nmap {ip_address}", "Scan a single IP"),
            ("nmap {ip_address1} {ip_address2}", "Scan multiple specific IPs"),
            ("nmap {ip_range}", "Scan a range of IPs"),
            ("nmap {domain_name}", "Scan a domain"),
            ("nmap {ip_address}/{CIDR}", "Scan using CIDR notation"),
            ("nmap -iL {targets_file}", "Scan targets from a file"),
            ("nmap --exclude {ip_address}", "Exclude specific IPs from scan"),
            ("nmap -iR {number}", "Scan random hosts (specify number)")
        ]),
        ("Host Discovery", [
            ("nmap {ip_range} -sL", "List targets only (no scanning)"),
            ("nmap {ip_range} -sn", "Disable port scanning (host discovery only)"),
            ("nmap {ip_address} -Pn", "Disable host discovery (port scan only)"),
            ("nmap {ip_range} -PS{ports}", "TCP SYN discovery on specific ports"),
            ("nmap {ip_range} -PA{ports}", "TCP ACK discovery"),
            ("nmap {ip_range} -PU{ports}", "UDP discovery"),
            ("nmap {ip_range} -PR", "ARP discovery on local network"),
            ("nmap {ip_address} -n", "No DNS resolution")
        ]),
        ("Port Scanning", [
            ("nmap {ip_address} -p {port}", "Scan a specific port"),
            ("nmap {ip_address} -p {port_range}", "Scan a range of ports"),
            ("nmap {ip_address} -p U:{udp_port},T:{tcp_ports}", "Scan TCP and UDP ports"),
            ("nmap {ip_address} -p-", "Scan all TCP ports"),
            ("nmap {ip_address} -F", "Fast scan (Top 100 ports)"),
            ("nmap {ip_address} --top-ports {number}", "Scan the top X ports"),
            ("nmap {ip_address} -p {service_names}", "Scan by service name"),
            ("nmap -sn {ip_address}", "Ping scan"),
            ("nmap -sI {zombie_ip} {target}", "Idle scan (zombie host)")
        ]),
        ("OS Detection", [
            ("nmap {ip_address} -O", "Remote OS detection"),
            ("nmap {ip_address} -O --osscan-limit", "Limit OS detection attempts"),
            ("nmap {ip_address} -O --osscan-guess", "Aggressive OS detection guessing"),
            ("nmap {ip_address} -O --max-os-tries {number}", "Limit OS detection retries"),
            ("nmap {ip_address} -A", "Enable OS detection, version detection, script scanning, and traceroute")
        ]),
        ("Service and Version Detection", [
            ("nmap {ip_address} -sV", "Service version detection"),
            ("nmap {ip_address} -sV --version-intensity {number}", "Set intensity of version detection (0-9)"),
            ("nmap {ip_address} -sV --version-light", "Light service detection (faster)"),
            ("nmap {ip_address} -sV --version-all", "Aggressive service detection"),
            ("nmap {ip_address} --version-intensity {number}", "Service fingerprinting")
        ]),
        ("NSE Scripts", [
            ("nmap {ip_address} -sC", "Scan with default NSE scripts"),
            ("nmap {ip_address} --script={script_name}", "Run specific script"),
            ("nmap {ip_address} --script={script1},{script2}", "Run multiple scripts"),
            ("nmap {ip_address} --script vuln", "Vulnerability scan using NSE"),
            ("nmap {ip_address} --script {script_name} --script-args={args}", "Scan with specific script and arguments")
        ])
    ]

    idx = 1
    command_index = []
    col_no = 4
    col_cmd = int(term_width * 0.4)
    col_desc = term_width - col_no - col_cmd - 6  # Adjust for spacing
    print(f"{Fore.YELLOW}{'No.':<{col_no}} {'Command':<{col_cmd}} {'Explanation':<{col_desc}}")
    print(f"{Fore.YELLOW}{'-' * term_width}")
    for category_name, commands in categories:
        print(f"\n{Fore.YELLOW}{category_name.center(term_width)}\n")
        for command, description in commands:
            cmd_wrapped = textwrap.fill(command, width=col_cmd)
            desc_wrapped = textwrap.fill(description, width=col_desc)
            cmd_lines = cmd_wrapped.split('\n')
            desc_lines = desc_wrapped.split('\n')
            max_lines = max(len(cmd_lines), len(desc_lines))
            for i in range(max_lines):
                cmd_line = cmd_lines[i] if i < len(cmd_lines) else ''
                desc_line = desc_lines[i] if i < len(desc_lines) else ''
                line = f"{Fore.CYAN}{idx if i == 0 else '':<{col_no}} {cmd_line:<{col_cmd}} {Fore.WHITE}{desc_line:<{col_desc}}"
                print(line)
            command_index.append((command, description))
            idx += 1
            print()
    footer = f"\n{Fore.LIGHTWHITE_EX}Type the number of the command to execute, type your own command, or press Enter to return to the main menu."
    print(footer)

    # User selects a command to run
    while True:
        choice = input(f"{Fore.LIGHTWHITE_EX}\nEnter your choice: ").strip()
        if not choice or choice.lower() == 'exit':
            return
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(command_index):
                idx -= 1
                command_template, description = command_index[idx]
                # Find placeholders in the command template
                placeholders = [word.strip('{}') for word in command_template.split() if '{' in word and '}' in word]
                command = command_template
                # Prompt user for each placeholder
                for placeholder in placeholders:
                    while True:
                        value = input(f"Enter value for {placeholder}: ").strip()
                        if value:
                            sanitized_value = sanitize_input(value)
                            command = command.replace('{' + placeholder + '}', sanitized_value)
                            break
                        else:
                            print(f"{Fore.RED}Input cannot be empty. Please enter a valid value.")
                run_nmap_command(command)
                # Return to the main menu after running the command
                return
            else:
                print(f"{Fore.RED}Invalid choice, please enter a number between 1 and {len(command_index)}.")
        else:
            # Assume the input is a command and try to run it
            sanitized_command = choice.strip()
            if sanitized_command.lower() == 'exit':
                return
            elif sanitized_command:
                run_nmap_command(sanitized_command)
                # Return to the main menu after running the command
                return
            else:
                print(f"{Fore.RED}Invalid input. Please enter a command or a valid option.")

# Function to display command history
def view_command_history():
    clear_screen()
    term_width = get_terminal_width()
    print(f"{Fore.YELLOW}{'Command History'.center(term_width)}")
    print(f"{Fore.YELLOW}{'-' * term_width}")
    if command_history:
        for idx, cmd in enumerate(command_history, 1):
            cmd_wrapped = textwrap.fill(cmd, width=term_width - 6)
            cmd_lines = cmd_wrapped.split('\n')
            for i, line_content in enumerate(cmd_lines):
                line = f"{Fore.CYAN}{idx if i == 0 else '':<4} {line_content}"
                print(line)
            print()
        print(f"\n{Fore.LIGHTWHITE_EX}Type the number of the command to re-run it, type your own command, or press Enter to return to the main menu.")
        while True:
            choice = input(f"{Fore.LIGHTWHITE_EX}\nEnter your choice: ").strip()
            if not choice or choice.lower() == 'exit':
                return
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(command_history):
                    idx -= 1
                    command = command_history[idx]
                    run_nmap_command(command)
                    # Return to the command history menu after running the command
                    return
                else:
                    print(f"{Fore.RED}Invalid choice, please enter a number between 1 and {len(command_history)}.")
            else:
                # Assume the input is a command and try to run it
                sanitized_command = choice.strip()
                if sanitized_command.lower() == 'exit':
                    return
                elif sanitized_command:
                    run_nmap_command(sanitized_command)
                    # Return to the command history menu after running the command
                    return
                else:
                    print(f"{Fore.RED}Invalid input. Please enter a command or a valid option.")
    else:
        print(f"{Fore.WHITE}No commands have been run successfully yet.")
        input(f"\n{Fore.LIGHTWHITE_EX}Press Enter to return to the main menu.")

# Main menu function
def main_menu():
    clear_screen()
    term_width = get_terminal_width()
    # ASCII art title
    ascii_title = '''
     _   _                       _   _      _                 
    | \\ | |_ __ ___   __ _ _ __ | | | | ___| |_ __   ___ _ __ 
    |  \\| | '_ ` _ \\ / _` | '_ \\| |_| |/ _ \\ | '_ \\ / _ \\ '__|
    | |\\  | | | | | | (_| | |_) |  _  |  __/ | |_) |  __/ |   
    |_| \\_|_| |_| |_|\\__,_| .__/|_| |_|\\___|_| .__/ \\___|_|   
                          |_|                |_|              


    '''
    # Print the ASCII art title
    for line in ascii_title.strip('\n').split('\n'):
        print(line.center(term_width))

    print(f"\n{Fore.YELLOW}{'Please select an option or type your own command:'.center(term_width)}\n")
    menu_options = [
        "1. Basic Nmap Commands",
        "2. Target Specification",
        "3. Host Discovery",
        "4. Port Scanning",
        "5. OS Detection",
        "6. Service and Version Detection",
        "7. NSE Scripts",
        "8. View All Commands",
        "9. View Command History"
    ]
    # Calculate the menu block width
    menu_block_width = max(len(option) for option in menu_options)
    # Calculate left padding to center the block
    left_padding = (term_width - menu_block_width) // 2
    # Print the menu options with left-aligned text within the centered block
    for option in menu_options:
        print(' ' * left_padding + Fore.CYAN + option)
    print(f"\n{Fore.LIGHTWHITE_EX}Type the number of your choice, type your own command, or type 'exit' to leave.")

# Main loop
def menu_loop():
    while True:
        main_menu()
        choice = input(f"{Fore.LIGHTWHITE_EX}\nEnter your choice: ").strip()
        if not choice:
            continue
        if choice.lower() == 'exit':
            print(f"{Fore.LIGHTWHITE_EX}Exiting the Nmap Cheat Sheet CLI. Goodbye!")
            break
        elif choice.isdigit():
            if choice == '1':
                basic_nmap_commands()
            elif choice == '2':
                target_specification()
            elif choice == '3':
                host_discovery()
            elif choice == '4':
                port_scanning()
            elif choice == '5':
                os_detection()
            elif choice == '6':
                service_version_detection()
            elif choice == '7':
                nse_scripts()
            elif choice == '8':
                view_all_commands()
            elif choice == '9':
                view_command_history()
            else:
                print(f"{Fore.RED}Invalid choice, please enter a number between 1 and 9.")
                input(f"{Fore.LIGHTWHITE_EX}\nPress Enter to return to the main menu.")
        else:
            # Assume the input is a command and try to run it
            sanitized_command = choice.strip()
            if sanitized_command.lower() == 'exit':
                print(f"{Fore.LIGHTWHITE_EX}Exiting the Nmap Cheat Sheet CLI. Goodbye!")
                break
            elif sanitized_command:
                run_nmap_command(sanitized_command)
            else:
                print(f"{Fore.RED}Invalid input. Please enter a command or a valid option.")

if __name__ == "__main__":
    menu_loop()

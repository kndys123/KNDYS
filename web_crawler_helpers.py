# WEB_CRAWLER HELPER FUNCTIONS - Insert after run_web_crawler()

    def _check_robots_txt(self, url):
        """Check and parse robots.txt"""
        disallowed = []
        try:
            robots_url = urljoin(url, '/robots.txt')
            response = requests.get(robots_url, timeout=5, verify=False)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.strip().lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed.append(path)
        except:
            pass
        return disallowed
    
    def _detect_technologies(self, response, soup):
        """Detect web technologies"""
        technologies = []
        
        # Check headers
        if 'Server' in response.headers:
            technologies.append(f"Server: {response.headers['Server']}")
        if 'X-Powered-By' in response.headers:
            technologies.append(f"Powered-By: {response.headers['X-Powered-By']}")
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name', '').lower() == 'generator':
                technologies.append(f"Generator: {meta.get('content', '')}")
        
        # Check for common frameworks/CMS
        content = response.text.lower()
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'sites/default'],
            'Joomla': ['joomla', 'com_content'],
            'Django': ['csrfmiddlewaretoken', '__admin__'],
            'Flask': ['werkzeug'],
            'Laravel': ['laravel', 'csrf-token'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue.js', 'vue.min.js', '__vue__'],
            'Angular': ['ng-app', 'angular.js'],
            'jQuery': ['jquery', 'jquery.min.js'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css']
        }
        
        for tech, signatures in tech_signatures.items():
            if any(sig in content for sig in signatures):
                if tech not in [t.split(':')[0] for t in technologies]:
                    technologies.append(tech)
        
        return technologies
    
    def _analyze_security_headers(self, headers):
        """Analyze security headers"""
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Missing')
        }
        return security_headers
    
    def _analyze_cookies(self, cookies):
        """Analyze cookies"""
        cookie_list = []
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                'domain': cookie.domain,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly')
            }
            cookie_list.append(cookie_info)
        return cookie_list
    
    def _extract_forms(self, soup, url, scan_vulns):
        """Extract and analyze forms"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'vulnerabilities': []
            }
            
            # Extract inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_info)
            
            # Vulnerability checks
            if scan_vulns:
                # Check for CSRF protection
                has_csrf = False
                for inp in form_data['inputs']:
                    if any(token in inp['name'].lower() for token in ['csrf', 'token', '_token', 'authenticity']):
                        has_csrf = True
                        break
                
                if form_data['method'] == 'POST' and not has_csrf:
                    form_data['vulnerabilities'].append({
                        'type': 'Missing CSRF Protection',
                        'severity': 'Medium',
                        'description': 'Form does not appear to have CSRF protection'
                    })
                
                # Check for password autocomplete
                for inp in form_data['inputs']:
                    if inp['type'] == 'password' and not any(attr in str(input_tag) for attr in ['autocomplete=\"off\"', 'autocomplete=\"new-password\"']):
                        form_data['vulnerabilities'].append({
                            'type': 'Password Autocomplete Enabled',
                            'severity': 'Low',
                            'description': f\"Password field '{inp['name']}' allows autocomplete\"
                        })
            
            forms.append(form_data)
        
        return forms
    
    def _extract_files(self, soup, base_url, files):
        """Extract files by category"""
        # Documents
        doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv']
        for link in soup.find_all('a', href=True):
            href = link['href']
            if any(ext in href.lower() for ext in doc_extensions):
                full_url = urljoin(base_url, href)
                if full_url not in files['documents']:
                    files['documents'].append(full_url)
        
        # Images
        for img in soup.find_all('img', src=True):
            src = urljoin(base_url, img['src'])
            if src not in files['images']:
                files['images'].append(src)
        
        # Scripts
        for script in soup.find_all('script', src=True):
            src = urljoin(base_url, script['src'])
            if src not in files['scripts']:
                files['scripts'].append(src)
        
        # Stylesheets
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = urljoin(base_url, link['href'])
            if href not in files['stylesheets']:
                files['stylesheets'].append(href)
        
        # Media
        for media in soup.find_all(['video', 'audio'], src=True):
            src = urljoin(base_url, media['src'])
            if src not in files['media']:
                files['media'].append(src)
    
    def _extract_emails(self, text):
        """Extract email addresses"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(pattern, text)
    
    def _extract_phones(self, text):
        """Extract phone numbers"""
        patterns = [
            r'\\+?\\d{1,3}[-.\\s]?\\(?\\d{1,4}\\)?[-.\\s]?\\d{1,4}[-.\\s]?\\d{1,9}',
            r'\\(\\d{3}\\)\\s*\\d{3}[-.]\\d{4}',
            r'\\d{3}[-.]\\d{3}[-.]\\d{4}'
        ]
        phones = []
        for pattern in patterns:
            phones.extend(re.findall(pattern, text))
        return phones
    
    def _extract_parameters(self, url):
        """Extract URL parameters"""
        params = set()
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    params.add(key)
        return params
    
    def _extract_comments(self, soup, url):
        """Extract HTML comments"""
        comments = []
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
            comment_text = str(comment).strip()
            if len(comment_text) > 10:  # Filter out short comments
                comments.append({
                    'url': url,
                    'comment': comment_text[:200]
                })
        return comments
    
    def _extract_js_endpoints(self, text, soup):
        """Extract endpoints from JavaScript"""
        endpoints = []
        
        # Pattern for API endpoints
        patterns = [
            r'[\"\\']/(api|v1|v2|v3)/[a-zA-Z0-9/_-]+[\"\\']',
            r'fetch\\([\"\\']([^\"\\']*/api/[^\"\\']*)[\"\\']]',
            r'axios\\.(get|post|put|delete)\\([\"\\']([^\"\\']*)[\"\\']]',
            r'\\$.ajax\\(.*url:\\s*[\"\\']([^\"\\']*)[\"\\']]'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                endpoint = match if isinstance(match, str) else match[-1]
                endpoint = endpoint.strip('\\'\"')
                if endpoint.startswith('/'):
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _check_sensitive_files(self, base_url):
        """Check for sensitive files"""
        sensitive_files = [
            '.git/config', '.git/HEAD', '.svn/entries',
            '.env', '.env.local', '.env.production',
            'config.php', 'configuration.php', 'wp-config.php',
            'web.config', 'app.config', 'database.yml',
            '.htaccess', '.htpasswd',
            'composer.json', 'package.json', 'package-lock.json',
            'backup.zip', 'backup.sql', 'database.sql', 'db.sql',
            'phpinfo.php', 'info.php', 'test.php',
            'admin.php', 'login.php', 'admin/', 'phpmyadmin/',
            'README.md', 'CHANGELOG.md', 'LICENSE',
            '.DS_Store', 'desktop.ini', 'Thumbs.db'
        ]
        
        found = []
        print(f\"{Fore.YELLOW}  Checking {len(sensitive_files)} sensitive files...{Style.RESET_ALL}\", end='\\r')
        
        for file in sensitive_files:
            try:
                test_url = urljoin(base_url, file)
                response = requests.head(test_url, timeout=3, verify=False, allow_redirects=True)
                if response.status_code == 200:
                    found.append(test_url)
                    print(f\"{Fore.RED}  [!] Found: {file}{' '*30}{Style.RESET_ALL}\")\n            except:
                pass
        
        return found
    
    def _export_crawler_results(self, url, results, elapsed):
        """Export crawler results to JSON and TXT"""
        timestamp = int(time.time())
        domain = urlparse(url).netloc.replace(':', '_')
        
        # JSON Export
        json_data = {
            'url': url,
            'timestamp': timestamp,
            'duration': f'{elapsed:.2f}s',
            'statistics': {
                'pages_crawled': len(results['pages']),
                'links_found': len(results['links']),
                'forms_found': len(results['forms']),
                'emails': len(results['emails']),
                'phones': len(results['phone_numbers']),
                'js_endpoints': len(results['js_endpoints']),
                'sensitive_files': len(results['sensitive_files']),
                'vulnerabilities': len(results['vulnerabilities'])
            },
            'pages': results['pages'],
            'links': results['links'],
            'forms': results['forms'],
            'files': results['files'],
            'emails': results['emails'],
            'phone_numbers': results['phone_numbers'],
            'js_endpoints': results['js_endpoints'],
            'api_endpoints': results['api_endpoints'],
            'parameters': results['parameters'],
            'sensitive_files': results['sensitive_files'],
            'technologies': results['technologies'],
            'security_headers': results['security_headers'],
            'cookies': results['cookies'],
            'vulnerabilities': results['vulnerabilities'],
            'comments': results['comments']
        }
        
        json_file = f'crawler_{domain}_{timestamp}.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
        
        # TXT Export
        txt_file = f'crawler_{domain}_{timestamp}_report.txt'
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(\"=\" * 70 + \"\\n\")
            f.write(\"WEB CRAWLER REPORT - KNDYS FRAMEWORK v3.0\\n\")
            f.write(\"=\" * 70 + \"\\n\\n\")
            f.write(f\"URL: {url}\\n\")
            f.write(f\"Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\\n\")
            f.write(f\"Duration: {elapsed:.2f} seconds\\n\\n\")
            
            f.write(\"STATISTICS:\\n\")
            f.write(\"-\" * 70 + \"\\n\")
            f.write(f\"  Pages Crawled: {len(results['pages'])}\\n\")
            f.write(f\"  Links Found: {len(results['links'])}\\n\")
            f.write(f\"  Forms Found: {len(results['forms'])}\\n\")
            f.write(f\"  Emails: {len(results['emails'])}\\n\")
            f.write(f\"  Phone Numbers: {len(results['phone_numbers'])}\\n\")
            f.write(f\"  JS Endpoints: {len(results['js_endpoints'])}\\n\")
            f.write(f\"  Parameters: {len(results['parameters'])}\\n\")
            f.write(f\"  Sensitive Files: {len(results['sensitive_files'])}\\n\")
            f.write(f\"  Vulnerabilities: {len(results['vulnerabilities'])}\\n\\n\")
            
            if results['technologies']:
                f.write(\"TECHNOLOGIES DETECTED:\\n\")
                f.write(\"-\" * 70 + \"\\n\")
                for tech in results['technologies']:
                    f.write(f\"  - {tech}\\n\")
                f.write(\"\\n\")
            
            if results['sensitive_files']:
                f.write(\"SENSITIVE FILES:\\n\")
                f.write(\"-\" * 70 + \"\\n\")
                for file in results['sensitive_files']:
                    f.write(f\"  - {file}\\n\")
                f.write(\"\\n\")
            
            if results['vulnerabilities']:
                f.write(\"VULNERABILITIES:\\n\")
                f.write(\"-\" * 70 + \"\\n\")
                for vuln in results['vulnerabilities']:
                    f.write(f\"  [{vuln['severity']}] {vuln['type']}\\n\")
                    f.write(f\"    URL: {vuln.get('url', 'N/A')}\\n\")
                    f.write(f\"    Description: {vuln['description']}\\n\\n\")
            
            if results['emails']:
                f.write(\"EMAILS:\\n\")
                f.write(\"-\" * 70 + \"\\n\")
                for email in results['emails'][:20]:
                    f.write(f\"  - {email}\\n\")
                if len(results['emails']) > 20:
                    f.write(f\"  ... and {len(results['emails']) - 20} more\\n\")
                f.write(\"\\n\")
            
            if results['api_endpoints']:
                f.write(\"API ENDPOINTS:\\n\")
                f.write(\"-\" * 70 + \"\\n\")
                for endpoint in results['api_endpoints'][:30]:
                    f.write(f\"  - {endpoint}\\n\")
                f.write(\"\\n\")
            
            if results['security_headers']:
                f.write(\"SECURITY HEADERS:\\n\")
                f.write(\"-\" * 70 + \"\\n\")
                for header, value in results['security_headers'].items():
                    status = \"✓\" if value != 'Missing' else \"✗\"
                    f.write(f\"  {status} {header}: {value}\\n\")
                f.write(\"\\n\")
        
        print(f\"{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}\")
        print(f\"  • {json_file}\")
        print(f\"  • {txt_file}\")

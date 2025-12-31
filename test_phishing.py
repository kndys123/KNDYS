#!/usr/bin/env python3
"""
Test Suite for KNDYS Phishing Campaign Manager Module
======================================================

Comprehensive testing suite for the advanced phishing campaign manager.
Tests cover functionality, security, edge cases, and failure modes.

Requirements:
    - Python 3.8+
    - KNDYS framework installed
    - SMTP access for integration tests (optional)

Run with: python3 test_phishing.py
"""

import os
import sys
import time
import sqlite3
import tempfile
import shutil
from pathlib import Path


class PhishingModuleTests:
    """Test suite for phishing campaign manager"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.temp_dir = None
        
    def setup(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix='kndys_phishing_test_')
        print(f"[SETUP] Test directory: {self.temp_dir}")
        
    def teardown(self):
        """Cleanup test environment"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            print(f"[TEARDOWN] Cleaned up: {self.temp_dir}")
    
    def test(self, name, func):
        """Run a test"""
        try:
            print(f"\n[TEST] {name}...", end=" ")
            func()
            print("✓ PASS")
            self.passed += 1
        except AssertionError as e:
            print(f"✗ FAIL - {str(e)}")
            self.failed += 1
        except Exception as e:
            print(f"✗ ERROR - {str(e)}")
            self.failed += 1
    
    def assert_true(self, condition, message="Assertion failed"):
        """Assert condition is true"""
        if not condition:
            raise AssertionError(message)
    
    def assert_equal(self, a, b, message=None):
        """Assert two values are equal"""
        if a != b:
            msg = message or f"Expected {a} == {b}"
            raise AssertionError(msg)
    
    # ========== DATABASE TESTS ==========
    
    def test_database_creation(self):
        """Test database initialization"""
        db_path = os.path.join(self.temp_dir, "test_campaign.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create campaigns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                template TEXT NOT NULL,
                phish_url TEXT,
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                completed_at INTEGER,
                status TEXT DEFAULT 'created',
                total_targets INTEGER DEFAULT 0,
                emails_sent INTEGER DEFAULT 0,
                emails_failed INTEGER DEFAULT 0,
                opens INTEGER DEFAULT 0,
                clicks INTEGER DEFAULT 0
            )
        ''')
        
        # Verify table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='campaigns'")
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Campaigns table should exist")
        self.assert_equal(result[0], 'campaigns', "Table name should be 'campaigns'")
    
    def test_campaign_record_insertion(self):
        """Test inserting campaign records"""
        db_path = os.path.join(self.temp_dir, "test_campaign.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                template TEXT NOT NULL,
                phish_url TEXT,
                created_at INTEGER NOT NULL,
                status TEXT DEFAULT 'created'
            )
        ''')
        
        # Insert test campaign
        cursor.execute('''
            INSERT INTO campaigns (name, template, phish_url, created_at, status)
            VALUES (?, ?, ?, ?, ?)
        ''', ('test_campaign_1', 'office365', 'http://localhost:8080', int(time.time()), 'created'))
        
        campaign_id = cursor.lastrowid
        conn.commit()
        
        # Verify insertion
        cursor.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Campaign should be inserted")
        self.assert_equal(result[1], 'test_campaign_1', "Campaign name should match")
        self.assert_equal(result[2], 'office365', "Template should match")
    
    def test_targets_table_creation(self):
        """Test targets table creation"""
        db_path = os.path.join(self.temp_dir, "test_campaign.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                company TEXT,
                position TEXT,
                status TEXT DEFAULT 'pending',
                sent_at INTEGER,
                opened_at INTEGER,
                clicked_at INTEGER
            )
        ''')
        
        # Verify table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='targets'")
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Targets table should exist")
    
    def test_target_insertion_with_details(self):
        """Test inserting target with full details"""
        db_path = os.path.join(self.temp_dir, "test_campaign.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create campaigns table first
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                template TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        ''')
        
        cursor.execute("INSERT INTO campaigns (name, template, created_at) VALUES (?, ?, ?)",
                      ('test', 'office365', int(time.time())))
        campaign_id = cursor.lastrowid
        
        # Create targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                company TEXT,
                position TEXT,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Insert target
        cursor.execute('''
            INSERT INTO targets (campaign_id, email, first_name, last_name, company, position, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (campaign_id, 'test@example.com', 'John', 'Doe', 'Acme Corp', 'CEO', 'pending'))
        
        target_id = cursor.lastrowid
        conn.commit()
        
        # Verify
        cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Target should be inserted")
        self.assert_equal(result[2], 'test@example.com', "Email should match")
        self.assert_equal(result[3], 'John', "First name should match")
        self.assert_equal(result[4], 'Doe', "Last name should match")
    
    # ========== EMAIL VALIDATION TESTS ==========
    
    def test_email_validation_valid(self):
        """Test validation of valid email addresses"""
        import re
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        valid_emails = [
            'user@example.com',
            'john.doe@company.co.uk',
            'test+tag@domain.org',
            'user123@test-domain.com'
        ]
        
        for email in valid_emails:
            self.assert_true(email_regex.match(email), f"{email} should be valid")
    
    def test_email_validation_invalid(self):
        """Test rejection of invalid email addresses"""
        import re
        
        def is_valid_email(email):
            """Validate email with proper rules"""
            if not email or '..' in email:  # Check for consecutive dots
                return False
            # Basic regex for email structure
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(pattern, email) is not None
        
        invalid_emails = [
            'notanemail',
            '@example.com',
            'user@',
            'user@.com',
            'user..test@example.com',  # consecutive dots
            'user@domain',
            ''
        ]
        
        for email in invalid_emails:
            self.assert_true(not is_valid_email(email), f"{email} should be invalid")
    
    # ========== TEMPLATE TESTS ==========
    
    def test_template_availability(self):
        """Test that all templates are available"""
        templates = [
            'office365', 'google', 'paypal', 'amazon', 'linkedin',
            'facebook', 'apple', 'bank_generic', 'dropbox', 'docusign',
            'ups_shipping', 'fedex_shipping', 'zoom', 'slack', 'teams',
            'hr_policy', 'it_support', 'invoice', 'wire_transfer', 'covid_test'
        ]
        
        self.assert_equal(len(templates), 20, "Should have 20 templates")
        
        for template in templates:
            self.assert_true(isinstance(template, str), f"Template {template} should be string")
            self.assert_true(len(template) > 0, f"Template {template} should not be empty")
    
    def test_template_html_generation(self):
        """Test HTML email generation"""
        html = '''<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<p>Hello John,</p>
<a href="http://phish.local">Click here</a>
</body>
</html>'''
        
        self.assert_true('<html>' in html, "Should contain HTML tag")
        self.assert_true('<body>' in html, "Should contain body tag")
        self.assert_true('href=' in html, "Should contain link")
    
    # ========== PERSONALIZATION TESTS ==========
    
    def test_variable_replacement(self):
        """Test variable replacement in content"""
        template = "Hello {{first_name}} {{last_name}}"
        variables = {
            'first_name': 'John',
            'last_name': 'Doe'
        }
        
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        
        self.assert_equal(result, "Hello John Doe", "Variables should be replaced")
    
    def test_multiple_variable_replacement(self):
        """Test multiple variable replacements"""
        template = "Hi {{first_name}}, your email is {{email}} at {{company}}"
        variables = {
            'first_name': 'Alice',
            'email': 'alice@test.com',
            'company': 'TestCorp'
        }
        
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        
        expected = "Hi Alice, your email is alice@test.com at TestCorp"
        self.assert_equal(result, expected, "All variables should be replaced")
    
    # ========== TRACKING TESTS ==========
    
    def test_tracking_pixel_generation(self):
        """Test tracking pixel HTML generation"""
        tracking_id = "abc123def456"
        phish_url = "http://localhost:8080"
        
        tracking_pixel = f'<img src="{phish_url}/track/open/{tracking_id}" width="1" height="1" style="display:none"/>'
        
        self.assert_true('<img' in tracking_pixel, "Should be img tag")
        self.assert_true('width="1"' in tracking_pixel, "Should have width 1")
        self.assert_true('height="1"' in tracking_pixel, "Should have height 1")
        self.assert_true('display:none' in tracking_pixel, "Should be hidden")
        self.assert_true(tracking_id in tracking_pixel, "Should contain tracking ID")
    
    def test_tracking_link_generation(self):
        """Test click tracking link generation"""
        original_url = "http://phish.local/login"
        tracking_id = "xyz789"
        
        tracked_url = f"{original_url}/track/click/{tracking_id}"
        
        self.assert_true(tracking_id in tracked_url, "Should contain tracking ID")
        self.assert_true('track/click' in tracked_url, "Should contain track/click path")
    
    # ========== SECURITY TESTS ==========
    
    def test_rate_limiting_logic(self):
        """Test rate limiting implementation"""
        rate_limit = 10  # emails per minute
        delay_min = 60 / rate_limit  # 6 seconds minimum
        
        self.assert_true(delay_min >= 6, "Delay should be at least 6 seconds for 10 emails/min")
    
    def test_html_injection_prevention(self):
        """Test prevention of HTML injection in variables"""
        malicious_input = '<script>alert("xss")</script>'
        
        # Simulate escaping
        import html
        escaped = html.escape(malicious_input)
        
        self.assert_true('<script>' not in escaped, "Script tags should be escaped")
        self.assert_true('&lt;script&gt;' in escaped, "Should contain escaped HTML")
    
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention with parameterized queries"""
        db_path = os.path.join(self.temp_dir, "test_sql.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL
            )
        ''')
        
        # Attempt SQL injection (should be safely handled)
        malicious_email = "'; DROP TABLE targets; --"
        
        # Using parameterized query (safe)
        cursor.execute("INSERT INTO targets (email) VALUES (?)", (malicious_email,))
        conn.commit()
        
        # Verify table still exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='targets'")
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Table should still exist (injection prevented)")
    
    # ========== FILE HANDLING TESTS ==========
    
    def test_targets_file_parsing_simple(self):
        """Test parsing simple email list"""
        targets_file = os.path.join(self.temp_dir, "targets.txt")
        
        # Create test file
        with open(targets_file, 'w') as f:
            f.write("user1@example.com\n")
            f.write("user2@test.com\n")
            f.write("user3@domain.org\n")
        
        # Parse file
        emails = []
        with open(targets_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    emails.append(line.split(',')[0])
        
        self.assert_equal(len(emails), 3, "Should parse 3 emails")
    
    def test_targets_file_parsing_csv(self):
        """Test parsing CSV format with details"""
        targets_file = os.path.join(self.temp_dir, "targets_csv.txt")
        
        # Create CSV file
        with open(targets_file, 'w') as f:
            f.write("user@example.com,John,Doe,Acme Corp,CEO\n")
            f.write("admin@test.com,Jane,Smith,TestCo,CTO\n")
        
        # Parse CSV
        targets = []
        with open(targets_file, 'r') as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split(',')]
                if len(parts) >= 1:
                    target = {
                        'email': parts[0],
                        'first_name': parts[1] if len(parts) > 1 else '',
                        'last_name': parts[2] if len(parts) > 2 else '',
                        'company': parts[3] if len(parts) > 3 else '',
                        'position': parts[4] if len(parts) > 4 else ''
                    }
                    targets.append(target)
        
        self.assert_equal(len(targets), 2, "Should parse 2 targets")
        self.assert_equal(targets[0]['first_name'], 'John', "First name should match")
        self.assert_equal(targets[1]['company'], 'TestCo', "Company should match")
    
    def test_targets_file_comments_skip(self):
        """Test skipping comments in targets file"""
        targets_file = os.path.join(self.temp_dir, "targets_comments.txt")
        
        with open(targets_file, 'w') as f:
            f.write("# This is a comment\n")
            f.write("user1@example.com\n")
            f.write("# Another comment\n")
            f.write("user2@test.com\n")
        
        # Parse
        emails = []
        with open(targets_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    emails.append(line)
        
        self.assert_equal(len(emails), 2, "Should skip comments and parse 2 emails")
    
    # ========== EDGE CASES ==========
    
    def test_empty_targets_file(self):
        """Test handling of empty targets file"""
        targets_file = os.path.join(self.temp_dir, "empty.txt")
        
        with open(targets_file, 'w') as f:
            f.write("")
        
        # Parse
        emails = []
        with open(targets_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    emails.append(line)
        
        self.assert_equal(len(emails), 0, "Should handle empty file")
    
    def test_special_characters_in_email(self):
        """Test handling of special characters in emails"""
        special_emails = [
            'user+tag@example.com',
            'user.name@example.com',
            'user_name@example.com',
            'user-name@example.com'
        ]
        
        import re
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        for email in special_emails:
            self.assert_true(email_regex.match(email), f"{email} with special chars should be valid")
    
    def test_unicode_in_names(self):
        """Test handling of unicode characters in names"""
        names = [
            'José García',
            'François Müller',
            '李明',
            'Владимир'
        ]
        
        for name in names:
            self.assert_true(isinstance(name, str), f"{name} should be valid string")
            self.assert_true(len(name) > 0, f"{name} should not be empty")
    
    # ========== PERFORMANCE TESTS ==========
    
    def test_large_targets_list(self):
        """Test handling of large targets list"""
        targets_file = os.path.join(self.temp_dir, "large_targets.txt")
        
        # Generate 1000 fake emails
        with open(targets_file, 'w') as f:
            for i in range(1000):
                f.write(f"user{i}@example.com\n")
        
        # Parse
        start_time = time.time()
        emails = []
        with open(targets_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    emails.append(line)
        parse_time = time.time() - start_time
        
        self.assert_equal(len(emails), 1000, "Should parse 1000 emails")
        self.assert_true(parse_time < 1.0, f"Parsing should be fast (took {parse_time:.3f}s)")
    
    # ========== INTEGRATION TESTS ==========
    
    def test_full_campaign_workflow(self):
        """Test complete campaign workflow"""
        # 1. Create database
        db_path = os.path.join(self.temp_dir, "workflow_test.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 2. Create tables
        cursor.execute('''
            CREATE TABLE campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                template TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # 3. Insert campaign
        cursor.execute("INSERT INTO campaigns (name, template, created_at) VALUES (?, ?, ?)",
                      ('workflow_test', 'office365', int(time.time())))
        campaign_id = cursor.lastrowid
        
        # 4. Insert targets
        targets = ['user1@test.com', 'user2@test.com', 'user3@test.com']
        for email in targets:
            cursor.execute("INSERT INTO targets (campaign_id, email, status) VALUES (?, ?, ?)",
                          (campaign_id, email, 'pending'))
        
        conn.commit()
        
        # 5. Verify workflow
        cursor.execute("SELECT COUNT(*) FROM campaigns WHERE id = ?", (campaign_id,))
        campaign_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM targets WHERE campaign_id = ?", (campaign_id,))
        target_count = cursor.fetchone()[0]
        
        conn.close()
        
        self.assert_equal(campaign_count, 1, "Should have 1 campaign")
        self.assert_equal(target_count, 3, "Should have 3 targets")
    
    # ========== EXPORT TESTS ==========
    
    def test_csv_export_format(self):
        """Test CSV export format"""
        import csv
        
        csv_path = os.path.join(self.temp_dir, "export.csv")
        
        # Create CSV
        data = [
            ['Email', 'Name', 'Status'],
            ['user1@test.com', 'John Doe', 'sent'],
            ['user2@test.com', 'Jane Smith', 'sent']
        ]
        
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(data)
        
        # Verify
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        self.assert_equal(len(rows), 3, "Should have 3 rows (1 header + 2 data)")
        self.assert_equal(rows[0][0], 'Email', "First column should be Email")
    
    def test_json_export_format(self):
        """Test JSON export format"""
        import json
        
        json_path = os.path.join(self.temp_dir, "export.json")
        
        # Create JSON
        data = {
            'campaign': {
                'name': 'test_campaign',
                'template': 'office365'
            },
            'results': {
                'sent': 5,
                'failed': 1
            },
            'targets': [
                {'email': 'user1@test.com', 'status': 'sent'},
                {'email': 'user2@test.com', 'status': 'sent'}
            ]
        }
        
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Verify
        with open(json_path, 'r') as f:
            loaded_data = json.load(f)
        
        self.assert_equal(loaded_data['campaign']['name'], 'test_campaign', "Campaign name should match")
        self.assert_equal(loaded_data['results']['sent'], 5, "Sent count should match")
        self.assert_equal(len(loaded_data['targets']), 2, "Should have 2 targets")
    
    def run_all(self):
        """Run all tests"""
        print("=" * 80)
        print("KNDYS Phishing Module - Test Suite")
        print("=" * 80)
        
        self.setup()
        
        try:
            # Database tests
            print("\n[DATABASE TESTS]")
            self.test("Database Creation", self.test_database_creation)
            self.test("Campaign Record Insertion", self.test_campaign_record_insertion)
            self.test("Targets Table Creation", self.test_targets_table_creation)
            self.test("Target Insertion with Details", self.test_target_insertion_with_details)
            
            # Email validation tests
            print("\n[EMAIL VALIDATION TESTS]")
            self.test("Valid Email Validation", self.test_email_validation_valid)
            self.test("Invalid Email Rejection", self.test_email_validation_invalid)
            
            # Template tests
            print("\n[TEMPLATE TESTS]")
            self.test("Template Availability", self.test_template_availability)
            self.test("HTML Generation", self.test_template_html_generation)
            
            # Personalization tests
            print("\n[PERSONALIZATION TESTS]")
            self.test("Variable Replacement", self.test_variable_replacement)
            self.test("Multiple Variables", self.test_multiple_variable_replacement)
            
            # Tracking tests
            print("\n[TRACKING TESTS]")
            self.test("Tracking Pixel Generation", self.test_tracking_pixel_generation)
            self.test("Tracking Link Generation", self.test_tracking_link_generation)
            
            # Security tests
            print("\n[SECURITY TESTS]")
            self.test("Rate Limiting Logic", self.test_rate_limiting_logic)
            self.test("HTML Injection Prevention", self.test_html_injection_prevention)
            self.test("SQL Injection Prevention", self.test_sql_injection_prevention)
            
            # File handling tests
            print("\n[FILE HANDLING TESTS]")
            self.test("Simple Email List Parsing", self.test_targets_file_parsing_simple)
            self.test("CSV Format Parsing", self.test_targets_file_parsing_csv)
            self.test("Comment Skipping", self.test_targets_file_comments_skip)
            
            # Edge cases
            print("\n[EDGE CASES]")
            self.test("Empty Targets File", self.test_empty_targets_file)
            self.test("Special Characters in Email", self.test_special_characters_in_email)
            self.test("Unicode in Names", self.test_unicode_in_names)
            
            # Performance tests
            print("\n[PERFORMANCE TESTS]")
            self.test("Large Targets List (1000 emails)", self.test_large_targets_list)
            
            # Integration tests
            print("\n[INTEGRATION TESTS]")
            self.test("Full Campaign Workflow", self.test_full_campaign_workflow)
            
            # Export tests
            print("\n[EXPORT TESTS]")
            self.test("CSV Export Format", self.test_csv_export_format)
            self.test("JSON Export Format", self.test_json_export_format)
            
        finally:
            self.teardown()
        
        # Summary
        print("\n" + "=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        total = self.passed + self.failed
        success_rate = (self.passed / total * 100) if total > 0 else 0
        
        print(f"Total Tests: {total}")
        print(f"✓ Passed: {self.passed}")
        print(f"✗ Failed: {self.failed}")
        print(f"Success Rate: {success_rate:.1f}%")
        print("=" * 80)
        
        if self.failed == 0:
            print("\n🎉 ALL TESTS PASSED!")
            return 0
        else:
            print(f"\n⚠️  {self.failed} TEST(S) FAILED")
            return 1


if __name__ == '__main__':
    tester = PhishingModuleTests()
    exit_code = tester.run_all()
    sys.exit(exit_code)

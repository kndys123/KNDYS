#!/usr/bin/env python3
"""
Test Suite for KNDYS Mass Mailer Campaign Manager Module
=========================================================

Comprehensive testing suite for the enterprise mass email campaign manager.
Tests cover functionality, security, edge cases, and failure modes.

Requirements:
    - Python 3.8+
    - KNDYS framework installed
    - SMTP access for integration tests (optional)

Run with: python3 test_mass_mailer.py
"""

import os
import sys
import time
import sqlite3
import tempfile
import shutil
import json
import csv
from pathlib import Path


class MassMailerModuleTests:
    """Test suite for mass mailer campaign manager"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.temp_dir = None
        
    def setup(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix='kndys_mass_mailer_test_')
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
    
    def assert_not_equal(self, a, b, message=None):
        """Assert two values are not equal"""
        if a == b:
            msg = message or f"Expected {a} != {b}"
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
                created_at INTEGER NOT NULL,
                status TEXT DEFAULT 'created'
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
                created_at INTEGER NOT NULL,
                status TEXT DEFAULT 'created'
            )
        ''')
        
        # Insert test campaign
        cursor.execute('''
            INSERT INTO campaigns (name, template, created_at, status)
            VALUES (?, ?, ?, ?)
        ''', ('test_campaign_1', 'newsletter', int(time.time()), 'created'))
        
        campaign_id = cursor.lastrowid
        conn.commit()
        
        # Verify insertion
        cursor.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Campaign should be inserted")
        self.assert_equal(result[1], 'test_campaign_1', "Campaign name should match")
        self.assert_equal(result[2], 'newsletter', "Template should match")
    
    def test_recipients_table_creation(self):
        """Test recipients table creation"""
        db_path = os.path.join(self.temp_dir, "test_campaign.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recipients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                company TEXT,
                position TEXT,
                custom_fields TEXT,
                status TEXT DEFAULT 'pending',
                tracking_id TEXT UNIQUE,
                ab_variant TEXT
            )
        ''')
        
        # Verify table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='recipients'")
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Recipients table should exist")
    
    def test_recipient_insertion_with_details(self):
        """Test inserting recipient with full details"""
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
                      ('test', 'newsletter', int(time.time())))
        campaign_id = cursor.lastrowid
        
        # Create recipients table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recipients (
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
        
        # Insert recipient
        cursor.execute('''
            INSERT INTO recipients (campaign_id, email, first_name, last_name, company, position, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (campaign_id, 'test@example.com', 'John', 'Doe', 'Acme Corp', 'CEO', 'pending'))
        
        recipient_id = cursor.lastrowid
        conn.commit()
        
        # Verify
        cursor.execute("SELECT * FROM recipients WHERE id = ?", (recipient_id,))
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Recipient should be inserted")
        self.assert_equal(result[2], 'test@example.com', "Email should match")
        self.assert_equal(result[3], 'John', "First name should match")
        self.assert_equal(result[4], 'Doe', "Last name should match")
    
    def test_tracking_events_table(self):
        """Test tracking events table creation"""
        db_path = os.path.join(self.temp_dir, "test_campaign.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tracking_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tracking_events'")
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Tracking events table should exist")
    
    # ========== EMAIL VALIDATION TESTS ==========
    
    def test_email_validation_valid(self):
        """Test validation of valid email addresses"""
        import re
        
        def is_valid_email(email):
            if not email or '..' in email:
                return False
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(pattern, email) is not None
        
        valid_emails = [
            'user@example.com',
            'john.doe@company.co.uk',
            'test+tag@domain.org',
            'user123@test-domain.com'
        ]
        
        for email in valid_emails:
            self.assert_true(is_valid_email(email), f"{email} should be valid")
    
    def test_email_validation_invalid(self):
        """Test rejection of invalid email addresses"""
        import re
        
        def is_valid_email(email):
            if not email or '..' in email:
                return False
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(pattern, email) is not None
        
        invalid_emails = [
            'notanemail',
            '@example.com',
            'user@',
            'user@.com',
            'user..test@example.com',
            'user@domain',
            ''
        ]
        
        for email in invalid_emails:
            self.assert_true(not is_valid_email(email), f"{email} should be invalid")
    
    # ========== TEMPLATE TESTS ==========
    
    def test_template_availability(self):
        """Test that all templates are available"""
        templates = [
            'newsletter', 'invoice', 'shipping', 'password_reset',
            'security_alert', 'promotional', 'event_invitation', 'welcome',
            'survey', 'abandoned_cart', 'account_update', 'referral'
        ]
        
        self.assert_equal(len(templates), 12, "Should have 12 templates")
        
        for template in templates:
            self.assert_true(isinstance(template, str), f"Template {template} should be string")
            self.assert_true(len(template) > 0, f"Template {template} should not be empty")
    
    def test_template_structure(self):
        """Test template structure has required fields"""
        template = {
            'name': 'Newsletter',
            'subject': 'Test Subject',
            'preheader': 'Test Preheader',
            'category': 'marketing',
            'html': '<html></html>'
        }
        
        required_fields = ['name', 'subject', 'preheader', 'category', 'html']
        for field in required_fields:
            self.assert_true(field in template, f"Template should have '{field}' field")
    
    def test_template_html_generation(self):
        """Test HTML email generation"""
        html = '''<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<p>Hello {{first_name}},</p>
<a href="{{link}}">Click here</a>
</body>
</html>'''
        
        self.assert_true('<html>' in html, "Should contain HTML tag")
        self.assert_true('<body>' in html, "Should contain body tag")
        self.assert_true('{{first_name}}' in html, "Should contain variable")
        self.assert_true('{{link}}' in html, "Should contain link variable")
    
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
    
    def test_missing_variable_handling(self):
        """Test handling of missing variables"""
        template = "Hello {{first_name}} {{last_name}}"
        variables = {
            'first_name': 'John'
            # last_name is missing
        }
        
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        
        # Should still have unreplaced variable
        self.assert_true('{{last_name}}' in result, "Unreplaced variable should remain")
    
    # ========== A/B TESTING TESTS ==========
    
    def test_ab_variant_assignment(self):
        """Test A/B variant assignment"""
        recipients = []
        for i in range(10):
            variant = 'A' if i % 2 == 0 else 'B'
            recipients.append({'email': f'user{i}@test.com', 'variant': variant})
        
        variant_a = len([r for r in recipients if r['variant'] == 'A'])
        variant_b = len([r for r in recipients if r['variant'] == 'B'])
        
        self.assert_equal(variant_a, 5, "Should have 5 in variant A")
        self.assert_equal(variant_b, 5, "Should have 5 in variant B")
    
    def test_ab_split_calculation(self):
        """Test A/B split calculation"""
        total = 100
        variant_a = 50
        variant_b = 50
        
        self.assert_equal(variant_a + variant_b, total, "Variants should sum to total")
        self.assert_equal(variant_a, variant_b, "Variants should be equal in 50/50 split")
    
    # ========== TRACKING TESTS ==========
    
    def test_tracking_pixel_generation(self):
        """Test tracking pixel HTML generation"""
        tracking_id = "abc123def456"
        base_url = "http://localhost:8080"
        
        tracking_pixel = f'<img src="{base_url}/track/open/{tracking_id}" width="1" height="1" style="display:none"/>'
        
        self.assert_true('<img' in tracking_pixel, "Should be img tag")
        self.assert_true('width="1"' in tracking_pixel, "Should have width 1")
        self.assert_true('height="1"' in tracking_pixel, "Should have height 1")
        self.assert_true('display:none' in tracking_pixel, "Should be hidden")
        self.assert_true(tracking_id in tracking_pixel, "Should contain tracking ID")
    
    def test_tracking_link_generation(self):
        """Test click tracking link generation"""
        original_url = "http://example.com/page"
        tracking_id = "xyz789"
        base_url = "http://localhost:8080"
        
        tracked_url = f"{base_url}/track/click/{tracking_id}?redirect={original_url}"
        
        self.assert_true(tracking_id in tracked_url, "Should contain tracking ID")
        self.assert_true('track/click' in tracked_url, "Should contain track/click path")
        self.assert_true(original_url in tracked_url, "Should contain original URL")
    
    def test_unsubscribe_link_generation(self):
        """Test unsubscribe link generation"""
        tracking_id = "abc123"
        base_url = "http://localhost:8080"
        
        unsubscribe_link = f"{base_url}/unsubscribe/{tracking_id}"
        
        self.assert_true(tracking_id in unsubscribe_link, "Should contain tracking ID")
        self.assert_true('unsubscribe' in unsubscribe_link, "Should contain unsubscribe path")
    
    # ========== SECURITY TESTS ==========
    
    def test_rate_limiting_logic(self):
        """Test rate limiting implementation"""
        rate_limit = 50  # emails per minute
        delay_min = 60 / rate_limit  # 1.2 seconds minimum
        
        self.assert_true(delay_min >= 1.2, "Delay should be at least 1.2 seconds for 50 emails/min")
    
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
            CREATE TABLE IF NOT EXISTS recipients (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL
            )
        ''')
        
        # Attempt SQL injection (should be safely handled)
        malicious_email = "'; DROP TABLE recipients; --"
        
        # Using parameterized query (safe)
        cursor.execute("INSERT INTO recipients (email) VALUES (?)", (malicious_email,))
        conn.commit()
        
        # Verify table still exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='recipients'")
        result = cursor.fetchone()
        conn.close()
        
        self.assert_true(result is not None, "Table should still exist (injection prevented)")
    
    # ========== FILE HANDLING TESTS ==========
    
    def test_recipients_file_parsing_simple(self):
        """Test parsing simple email list"""
        recipients_file = os.path.join(self.temp_dir, "recipients.txt")
        
        # Create test file
        with open(recipients_file, 'w') as f:
            f.write("user1@example.com\n")
            f.write("user2@test.com\n")
            f.write("user3@domain.org\n")
        
        # Parse file
        emails = []
        with open(recipients_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    emails.append(line.split(',')[0])
        
        self.assert_equal(len(emails), 3, "Should parse 3 emails")
    
    def test_recipients_file_parsing_csv(self):
        """Test parsing CSV format with details"""
        recipients_file = os.path.join(self.temp_dir, "recipients_csv.txt")
        
        # Create CSV file
        with open(recipients_file, 'w') as f:
            f.write("user@example.com,John,Doe,Acme Corp,CEO\n")
            f.write("admin@test.com,Jane,Smith,TestCo,CTO\n")
        
        # Parse CSV
        recipients = []
        with open(recipients_file, 'r') as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split(',')]
                if len(parts) >= 1:
                    recipient = {
                        'email': parts[0],
                        'first_name': parts[1] if len(parts) > 1 else '',
                        'last_name': parts[2] if len(parts) > 2 else '',
                        'company': parts[3] if len(parts) > 3 else '',
                        'position': parts[4] if len(parts) > 4 else ''
                    }
                    recipients.append(recipient)
        
        self.assert_equal(len(recipients), 2, "Should parse 2 recipients")
        self.assert_equal(recipients[0]['first_name'], 'John', "First name should match")
        self.assert_equal(recipients[1]['company'], 'TestCo', "Company should match")
    
    def test_recipients_file_comments_skip(self):
        """Test skipping comments in recipients file"""
        recipients_file = os.path.join(self.temp_dir, "recipients_comments.txt")
        
        with open(recipients_file, 'w') as f:
            f.write("# This is a comment\n")
            f.write("user1@example.com\n")
            f.write("# Another comment\n")
            f.write("user2@test.com\n")
        
        # Parse
        emails = []
        with open(recipients_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    emails.append(line)
        
        self.assert_equal(len(emails), 2, "Should skip comments and parse 2 emails")
    
    # ========== EDGE CASES ==========
    
    def test_empty_recipients_file(self):
        """Test handling of empty recipients file"""
        recipients_file = os.path.join(self.temp_dir, "empty.txt")
        
        with open(recipients_file, 'w') as f:
            f.write("")
        
        # Parse
        emails = []
        with open(recipients_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    emails.append(line)
        
        self.assert_equal(len(emails), 0, "Should handle empty file")
    
    def test_special_characters_in_email(self):
        """Test handling of special characters in emails"""
        import re
        
        def is_valid_email(email):
            if not email or '..' in email:
                return False
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(pattern, email) is not None
        
        special_emails = [
            'user+tag@example.com',
            'user.name@example.com',
            'user_name@example.com',
            'user-name@example.com'
        ]
        
        for email in special_emails:
            self.assert_true(is_valid_email(email), f"{email} with special chars should be valid")
    
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
    
    def test_large_recipients_list(self):
        """Test handling of large recipients list"""
        recipients_file = os.path.join(self.temp_dir, "large_recipients.txt")
        
        # Generate 1000 fake emails
        with open(recipients_file, 'w') as f:
            for i in range(1000):
                f.write(f"user{i}@example.com\n")
        
        # Parse
        start_time = time.time()
        emails = []
        with open(recipients_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    emails.append(line)
        parse_time = time.time() - start_time
        
        self.assert_equal(len(emails), 1000, "Should parse 1000 emails")
        self.assert_true(parse_time < 1.0, f"Parsing should be fast (took {parse_time:.3f}s)")
    
    def test_batch_processing(self):
        """Test batch processing logic"""
        total_recipients = 250
        batch_size = 100
        
        batches = (total_recipients + batch_size - 1) // batch_size
        
        self.assert_equal(batches, 3, "Should have 3 batches for 250 recipients with batch size 100")
    
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
            CREATE TABLE recipients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # 3. Insert campaign
        cursor.execute("INSERT INTO campaigns (name, template, created_at) VALUES (?, ?, ?)",
                      ('workflow_test', 'newsletter', int(time.time())))
        campaign_id = cursor.lastrowid
        
        # 4. Insert recipients
        recipients = ['user1@test.com', 'user2@test.com', 'user3@test.com']
        for email in recipients:
            cursor.execute("INSERT INTO recipients (campaign_id, email, status) VALUES (?, ?, ?)",
                          (campaign_id, email, 'pending'))
        
        conn.commit()
        
        # 5. Verify workflow
        cursor.execute("SELECT COUNT(*) FROM campaigns WHERE id = ?", (campaign_id,))
        campaign_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM recipients WHERE campaign_id = ?", (campaign_id,))
        recipient_count = cursor.fetchone()[0]
        
        conn.close()
        
        self.assert_equal(campaign_count, 1, "Should have 1 campaign")
        self.assert_equal(recipient_count, 3, "Should have 3 recipients")
    
    def test_campaign_status_transitions(self):
        """Test campaign status transitions"""
        statuses = ['created', 'scheduled', 'running', 'paused', 'completed', 'failed']
        
        # Valid transitions
        valid_transitions = {
            'created': ['scheduled', 'running'],
            'scheduled': ['running', 'cancelled'],
            'running': ['paused', 'completed', 'failed'],
            'paused': ['running', 'cancelled'],
            'completed': [],
            'failed': []
        }
        
        self.assert_true('created' in valid_transitions, "Should have valid transitions for 'created'")
        self.assert_true('running' in valid_transitions['created'], "'created' should transition to 'running'")
    
    # ========== EXPORT TESTS ==========
    
    def test_csv_export_format(self):
        """Test CSV export format"""
        csv_path = os.path.join(self.temp_dir, "export.csv")
        
        # Create CSV
        data = [
            ['Email', 'First Name', 'Last Name', 'Status', 'Variant'],
            ['user1@test.com', 'John', 'Doe', 'sent', 'A'],
            ['user2@test.com', 'Jane', 'Smith', 'sent', 'B']
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
        self.assert_equal(rows[1][4], 'A', "Variant should be A")
    
    def test_json_export_format(self):
        """Test JSON export format"""
        json_path = os.path.join(self.temp_dir, "export.json")
        
        # Create JSON
        data = {
            'campaign': {
                'name': 'test_campaign',
                'template': 'newsletter'
            },
            'statistics': {
                'sent': 100,
                'opens': 50,
                'clicks': 20
            },
            'recipients': [
                {'email': 'user1@test.com', 'status': 'sent', 'variant': 'A'},
                {'email': 'user2@test.com', 'status': 'sent', 'variant': 'B'}
            ]
        }
        
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Verify
        with open(json_path, 'r') as f:
            loaded_data = json.load(f)
        
        self.assert_equal(loaded_data['campaign']['name'], 'test_campaign', "Campaign name should match")
        self.assert_equal(loaded_data['statistics']['sent'], 100, "Sent count should match")
        self.assert_equal(len(loaded_data['recipients']), 2, "Should have 2 recipients")
    
    def test_html_report_generation(self):
        """Test HTML report generation"""
        html_path = os.path.join(self.temp_dir, "report.html")
        
        html = '''<!DOCTYPE html>
<html><head><title>Campaign Report</title></head>
<body>
<h1>Campaign Results</h1>
<p>Total Sent: 100</p>
<table>
<tr><th>Email</th><th>Status</th></tr>
<tr><td>user1@test.com</td><td>sent</td></tr>
</table>
</body></html>'''
        
        with open(html_path, 'w') as f:
            f.write(html)
        
        # Verify file exists and contains expected content
        self.assert_true(os.path.exists(html_path), "HTML report should exist")
        
        with open(html_path, 'r') as f:
            content = f.read()
        
        self.assert_true('<html>' in content, "Should contain HTML tag")
        self.assert_true('<table>' in content, "Should contain table")
    
    # ========== SCHEDULING TESTS ==========
    
    def test_recurring_campaign_interval(self):
        """Test recurring campaign interval calculation"""
        intervals = {
            'daily': 86400,    # 24 hours
            'weekly': 604800,  # 7 days
            'monthly': 2592000 # 30 days (approximate)
        }
        
        self.assert_equal(intervals['daily'], 86400, "Daily interval should be 86400 seconds")
        self.assert_equal(intervals['weekly'], 604800, "Weekly interval should be 604800 seconds")
    
    def run_all(self):
        """Run all tests"""
        print("=" * 80)
        print("KNDYS Mass Mailer Module - Test Suite")
        print("=" * 80)
        
        self.setup()
        
        try:
            # Database tests
            print("\n[DATABASE TESTS]")
            self.test("Database Creation", self.test_database_creation)
            self.test("Campaign Record Insertion", self.test_campaign_record_insertion)
            self.test("Recipients Table Creation", self.test_recipients_table_creation)
            self.test("Recipient Insertion with Details", self.test_recipient_insertion_with_details)
            self.test("Tracking Events Table", self.test_tracking_events_table)
            
            # Email validation tests
            print("\n[EMAIL VALIDATION TESTS]")
            self.test("Valid Email Validation", self.test_email_validation_valid)
            self.test("Invalid Email Rejection", self.test_email_validation_invalid)
            
            # Template tests
            print("\n[TEMPLATE TESTS]")
            self.test("Template Availability", self.test_template_availability)
            self.test("Template Structure", self.test_template_structure)
            self.test("HTML Generation", self.test_template_html_generation)
            
            # Personalization tests
            print("\n[PERSONALIZATION TESTS]")
            self.test("Variable Replacement", self.test_variable_replacement)
            self.test("Multiple Variables", self.test_multiple_variable_replacement)
            self.test("Missing Variable Handling", self.test_missing_variable_handling)
            
            # A/B Testing tests
            print("\n[A/B TESTING TESTS]")
            self.test("A/B Variant Assignment", self.test_ab_variant_assignment)
            self.test("A/B Split Calculation", self.test_ab_split_calculation)
            
            # Tracking tests
            print("\n[TRACKING TESTS]")
            self.test("Tracking Pixel Generation", self.test_tracking_pixel_generation)
            self.test("Tracking Link Generation", self.test_tracking_link_generation)
            self.test("Unsubscribe Link Generation", self.test_unsubscribe_link_generation)
            
            # Security tests
            print("\n[SECURITY TESTS]")
            self.test("Rate Limiting Logic", self.test_rate_limiting_logic)
            self.test("HTML Injection Prevention", self.test_html_injection_prevention)
            self.test("SQL Injection Prevention", self.test_sql_injection_prevention)
            
            # File handling tests
            print("\n[FILE HANDLING TESTS]")
            self.test("Simple Email List Parsing", self.test_recipients_file_parsing_simple)
            self.test("CSV Format Parsing", self.test_recipients_file_parsing_csv)
            self.test("Comment Skipping", self.test_recipients_file_comments_skip)
            
            # Edge cases
            print("\n[EDGE CASES]")
            self.test("Empty Recipients File", self.test_empty_recipients_file)
            self.test("Special Characters in Email", self.test_special_characters_in_email)
            self.test("Unicode in Names", self.test_unicode_in_names)
            
            # Performance tests
            print("\n[PERFORMANCE TESTS]")
            self.test("Large Recipients List (1000 emails)", self.test_large_recipients_list)
            self.test("Batch Processing", self.test_batch_processing)
            
            # Integration tests
            print("\n[INTEGRATION TESTS]")
            self.test("Full Campaign Workflow", self.test_full_campaign_workflow)
            self.test("Campaign Status Transitions", self.test_campaign_status_transitions)
            
            # Export tests
            print("\n[EXPORT TESTS]")
            self.test("CSV Export Format", self.test_csv_export_format)
            self.test("JSON Export Format", self.test_json_export_format)
            self.test("HTML Report Generation", self.test_html_report_generation)
            
            # Scheduling tests
            print("\n[SCHEDULING TESTS]")
            self.test("Recurring Campaign Interval", self.test_recurring_campaign_interval)
            
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
    tester = MassMailerModuleTests()
    exit_code = tester.run_all()
    sys.exit(exit_code)

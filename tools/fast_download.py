#!/usr/bin/env python3
"""
1DM+ High-Performance Multi-Connection HTTP Range Downloader
Reverse-engineered architecture from 1DM+ (Download Manager Plus)
Features:
  - Multi-connection HTTP range download with dynamic chunk partitioning
  - Concurrency: default 64 threads, configurable up to 128 threads
  - Range probing (bytes=0- vs 206 Partial Content), fallback to identity stream
  - Pre-allocation (posix_fallocate with ftruncate fallback) to eliminate disk fragmentation
  - Chunk-level retry, socket resilience, session cookies, redirects follow (up to 20)
  - Google Drive / direct link resolver with virus scan confirmation bypass
  - Resumable downloads via .tmp and atomic JSON state tracking with If-Range / ETag
  - Dynamic Chunk Stealing (idle workers bisect and shoulder load from slowest active chunks)
  - Multi-Mirror Racing (concurrent segment downloads across mirror pool with latency scoring)
  - Adaptive Concurrency Throttling (rate-limit backoff on 429/403/503 via Condition variable)
  - Strict Accept-Encoding: identity on all byte-range requests
  - Separated Socket connect_timeout and read_timeout handlers
  - Strict Content-Range / status 206 verification on chunks
  - Clean CLI progress reporting with CI-friendly non-interactive mode
"""

import argparse
import concurrent.futures
import email.message
import http.client
import http.cookiejar
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

# Configuration Constants
DEFAULT_THREADS = 64
MAX_SUPPORTED_THREADS = 128
BUFFER_SIZE = 256 * 1024       # 256 KB matching 1DM+ chunk buffer size
DEFAULT_CONNECT_TIMEOUT = 10   # 10s socket connect timeout
DEFAULT_READ_TIMEOUT = 30      # 30s socket read timeout
MAX_REDIRECTS = 20             # Matching 1DM+ follow-up requests limit
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
MIN_CHUNK_STEAL_SIZE = 4 * 1024 * 1024  # 4 MB minimum remaining bytes to allow stealing


def format_bytes(num_bytes: float) -> str:
    """Format bytes into human-readable string (B, KB, MB, GB, TB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_time(seconds: float) -> str:
    """Format seconds into HH:MM:SS or MM:SS."""
    if seconds is None or seconds < 0 or math.isinf(seconds):
        return "--:--:--"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def is_safe_url(url: str) -> bool:
    """Validate URL scheme and ensure host is well-formed without embedded credentials."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        if parsed.username or parsed.password:
            return False
        return True
    except Exception:
        return False


# =====================================================================
# Networking: Separated Connect & Read Timeout Socket Handlers
# =====================================================================

class TimeoutHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, connect_timeout: float = DEFAULT_CONNECT_TIMEOUT, read_timeout: float = DEFAULT_READ_TIMEOUT, **kwargs):
        super().__init__(*args, **kwargs)
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def connect(self):
        self.sock = socket.create_connection(
            (self.host, self.port),
            timeout=self.connect_timeout,
        )
        if self.read_timeout is not None:
            self.sock.settimeout(self.read_timeout)


class TimeoutHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, connect_timeout: float = DEFAULT_CONNECT_TIMEOUT, read_timeout: float = DEFAULT_READ_TIMEOUT, **kwargs):
        super().__init__(*args, **kwargs)
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def connect(self):
        sock = socket.create_connection(
            (self.host, self.port),
            timeout=self.connect_timeout,
        )
        server_hostname = self._tunnel_host if self._tunnel_host else self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)
        if self.read_timeout is not None:
            self.sock.settimeout(self.read_timeout)


class TimeoutHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connect_timeout: float, read_timeout: float):
        super().__init__()
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def http_open(self, req):
        return self.do_open(
            lambda host, **kwargs: TimeoutHTTPConnection(
                host,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
                **kwargs,
            ),
            req,
        )


class TimeoutHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_timeout: float, read_timeout: float, context: Optional[ssl.SSLContext] = None):
        super().__init__(context=context)
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def https_open(self, req):
        return self.do_open(
            lambda host, **kwargs: TimeoutHTTPSConnection(
                host,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
                context=self._context,
                **kwargs,
            ),
            req,
        )


# =====================================================================
# Concurrency Controller (Condition-Based Throttling)
# =====================================================================

class ConcurrencyController:
    """Thread-safe adaptive concurrency controller with AIMD (Additive Increase Multiplicative Decrease)."""

    def __init__(self, initial_limit: int):
        self.max_limit = initial_limit
        self.current_limit = initial_limit
        self.active_workers = 0
        self.consecutive_successes = 0
        self.cooldown_until = 0.0
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)

    def acquire(self):
        with self.cv:
            while self.active_workers >= self.current_limit:
                self.cv.wait()
            self.active_workers += 1

    def release(self):
        with self.cv:
            self.active_workers = max(0, self.active_workers - 1)
            self.cv.notify_all()

    def reduce_limit(self, factor: float = 0.5) -> int:
        with self.cv:
            now = time.time()
            self.cooldown_until = now + 5.0
            self.consecutive_successes = 0
            new_limit = max(1, int(self.current_limit * factor))
            if new_limit < self.current_limit:
                self.current_limit = new_limit
                self.cv.notify_all()
            return self.current_limit

    def record_success(self):
        """Gradually recover concurrency after a streak of successful chunks without errors."""
        with self.cv:
            now = time.time()
            if now < self.cooldown_until:
                return
            self.consecutive_successes += 1
            if self.consecutive_successes >= 4 and self.current_limit < self.max_limit:
                self.current_limit += 1
                self.consecutive_successes = 0
                self.cv.notify_all()

    def get_active(self) -> int:
        with self.cv:
            return self.active_workers


# =====================================================================
# Multi-Mirror Racing & Latency Scorer
# =====================================================================

class MirrorPool:
    """
    Manages multiple download mirrors, evaluates connection latencies,
    and intelligently races workers toward the fastest responding endpoints.
    Enforces per-mirror connection caps to prevent overloading any single host.
    """

    def __init__(self, urls: List[str], max_conns_per_mirror: int = 16):
        clean_urls = [u.strip() for u in urls if u and is_safe_url(u.strip())]
        self.max_conns_per_mirror = max(1, max_conns_per_mirror)
        self.mirrors = [
            {"url": u, "latency": 0.0, "failures": 0, "active": 0}
            for u in clean_urls
        ]
        self.lock = threading.Lock()

    def get_best(self) -> str:
        """Select mirror with optimal health score and lowest latency within per-mirror limit."""
        with self.lock:
            if not self.mirrors:
                return ""
            available = [
                m for m in self.mirrors
                if m["failures"] < 5 and m["active"] < self.max_conns_per_mirror
            ]
            if not available:
                # If all under cap hit failure threshold, reset failures
                available = [m for m in self.mirrors if m["active"] < self.max_conns_per_mirror]
                if not available:
                    # If all mirrors are at max connection capacity, pick the least active
                    available = self.mirrors
                for m in available:
                    m["failures"] = 0

            best = min(
                available,
                key=lambda m: (m["failures"] * 3.0 + m["latency"] + m["active"] * 0.35),
            )
            best["active"] += 1
            return best["url"]

    def record_latency(self, url: str, elapsed: float, success: bool = True):
        """Record round-trip latency and failure count for a mirror."""
        with self.lock:
            for m in self.mirrors:
                if m["url"] == url:
                    if success:
                        m["latency"] = (
                            (m["latency"] * 0.7 + elapsed * 0.3)
                            if m["latency"] > 0
                            else elapsed
                        )
                        m["failures"] = max(0, m["failures"] - 1)
                    else:
                        m["failures"] += 1
                    break

    def release_connection(self, url: str):
        """Decrement active connection count for mirror."""
        with self.lock:
            for m in self.mirrors:
                if m["url"] == url:
                    m["active"] = max(0, m["active"] - 1)
                    break

    def record_result(self, url: str, elapsed: float, success: bool = True):
        """Record round-trip latency and release active connection for backward compatibility."""
        self.record_latency(url, elapsed, success)
        self.release_connection(url)


# =====================================================================
# Progress Tracker
# =====================================================================

class ProgressTracker:
    """Thread-safe progress reporter with terminal and CI log modes."""

    def __init__(self, total_size: int, active_threads_ref, quiet: bool = False):
        self.total_size = total_size
        self.active_threads_ref = active_threads_ref
        self.quiet = quiet
        self.downloaded_bytes = 0
        self.initial_bytes = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_downloaded = 0
        self.is_tty = sys.stdout.isatty() and not os.environ.get("GITHUB_ACTIONS")
        self.stop_event = threading.Event()
        self.speed = 0.0
        self.last_ci_log_time = 0.0

    def add_bytes(self, n: int):
        with self.lock:
            self.downloaded_bytes += n

    def set_initial_bytes(self, n: int):
        with self.lock:
            self.downloaded_bytes = n
            self.initial_bytes = n

    def get_progress(self) -> Tuple[int, float, float]:
        with self.lock:
            dl = self.downloaded_bytes
        elapsed = max(0.001, time.time() - self.start_time)
        net_downloaded = max(0, dl - self.initial_bytes)
        speed = net_downloaded / elapsed
        pct = (dl / self.total_size * 100.0) if self.total_size > 0 else 0.0
        return dl, speed, pct

    def render(self, force: bool = False):
        if self.quiet:
            return
        now = time.time()
        dl, speed, pct = self.get_progress()

        if self.total_size > 0:
            remaining_bytes = max(0, self.total_size - dl)
            eta = remaining_bytes / max(1.0, speed) if speed > 0 else 0
            eta_str = format_time(eta)
            dl_str = f"{format_bytes(dl)} / {format_bytes(self.total_size)}"
        else:
            eta_str = "--:--"
            dl_str = format_bytes(dl)

        active = self.active_threads_ref()
        speed_str = f"{format_bytes(speed)}/s"

        if self.is_tty:
            bar_len = 24
            if self.total_size > 0:
                filled = int(bar_len * (dl / self.total_size))
                bar = "=" * filled + (">" if filled < bar_len else "")
                bar = bar.ljust(bar_len, " ")
                line = (
                    f"\r[{bar}] {pct:5.1f}% | {dl_str} | "
                    f"{speed_str} | ETA: {eta_str} | {active} conn"
                )
            else:
                line = f"\r[Streaming] {dl_str} | {speed_str} | {active} conn"
            sys.stdout.write(line)
            sys.stdout.flush()
        else:
            if force or (now - self.last_ci_log_time >= 5.0):
                self.last_ci_log_time = now
                if self.total_size > 0:
                    print(
                        f"[Progress] {pct:5.1f}% | {dl_str} | "
                        f"{speed_str} | ETA: {eta_str} | Active: {active} threads",
                        flush=True,
                    )
                else:
                    print(
                        f"[Progress] {dl_str} | {speed_str} | Active: {active} threads",
                        flush=True,
                    )

    def close(self):
        self.stop_event.set()
        if not self.quiet:
            self.render(force=True)
            if self.is_tty:
                sys.stdout.write("\n")
                sys.stdout.flush()


# =====================================================================
# Dynamic Work Stealer
# =====================================================================

class WorkStealer:
    """
    Coordinates chunk distribution and dynamic chunk stealing.
    When idle workers finish early, they locate the slowest active chunk,
    atomically bisect its remaining byte range, and take over the second half.
    """

    def __init__(self, chunks: List[Dict], min_steal_size: int = MIN_CHUNK_STEAL_SIZE):
        self.chunks = chunks
        self.min_steal_size = min_steal_size
        self.lock = threading.RLock()

    def get_or_steal_chunk(self, worker_id: str) -> Optional[Dict]:
        """Fetch next pending chunk or steal from the slowest active chunk."""
        with self.lock:
            # 1. First assign any chunk that has never been started
            for c in self.chunks:
                if not c.get("done", False) and not c.get("active", False):
                    c["active"] = True
                    c["worker_id"] = worker_id
                    return c

            # 2. Work Stealing: find the active chunk with largest remaining byte range
            best_chunk = None
            max_remaining = 0
            for c in self.chunks:
                if c.get("active", False) and not c.get("done", False):
                    cur_pos = c["start"] + c.get("downloaded", 0)
                    rem = c["end"] - cur_pos + 1
                    if rem > max_remaining:
                        max_remaining = rem
                        best_chunk = c

            if best_chunk and max_remaining >= self.min_steal_size:
                half = max_remaining // 2
                old_end = best_chunk["end"]
                new_chunk_start = old_end - half + 1

                # Ensure new_chunk_start is strictly ahead of original worker's current download position
                cur_pos = best_chunk["start"] + best_chunk.get("downloaded", 0)
                if new_chunk_start <= cur_pos:
                    return None

                # Shrink original chunk's boundary safely
                best_chunk["end"] = new_chunk_start - 1

                stolen_chunk = {
                    "id": len(self.chunks),
                    "start": new_chunk_start,
                    "end": old_end,
                    "downloaded": 0,
                    "done": False,
                    "active": True,
                    "worker_id": worker_id,
                }
                self.chunks.append(stolen_chunk)
                return stolen_chunk

            return None

    def release_chunk(self, chunk: Dict, done: bool = True):
        with self.lock:
            chunk["active"] = False
            expected_span = chunk["end"] - chunk["start"] + 1
            if done and chunk.get("downloaded", 0) >= expected_span:
                chunk["done"] = True
            elif not chunk.get("done", False):
                chunk["done"] = False

    def get_all_chunks(self) -> List[Dict]:
        with self.lock:
            return list(self.chunks)

    def is_all_done(self) -> bool:
        with self.lock:
            return all(c.get("done", False) for c in self.chunks)


# =====================================================================
# 1DM+ Fast Downloader Engine
# =====================================================================

class FastDownloader:
    """
    High-Performance Downloader implementing 1DM+ Reverse Engineered Logic.
    """

    def __init__(
        self,
        url: str,
        mirrors: Optional[List[str]] = None,
        output_path: Optional[str] = None,
        dest_dir: Optional[str] = None,
        threads: int = DEFAULT_THREADS,
        max_threads: int = MAX_SUPPORTED_THREADS,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        retries: int = 10,
        user_agent: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        resume: bool = True,
        quiet: bool = False,
        chunk_size_mb: Optional[int] = None,
    ):
        if not is_safe_url(url):
            raise ValueError(f"Invalid URL: {url}")

        self.url = url
        raw_mirrors = [url] + (mirrors or [])
        seen_mirrors = set()
        deduped_mirrors = []
        for m in raw_mirrors:
            if m and is_safe_url(m) and m not in seen_mirrors:
                seen_mirrors.add(m)
                deduped_mirrors.append(m)

        self.raw_output_path = output_path
        self.dest_dir = dest_dir or "."
        self.max_threads = max(1, min(MAX_SUPPORTED_THREADS, max_threads))
        self.threads = max(1, min(self.max_threads, threads))
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.retries = retries
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.custom_headers = headers or {}
        self.resume = resume
        self.quiet = quiet
        self.chunk_size_mb = chunk_size_mb

        num_mirrors = max(1, len(deduped_mirrors))
        max_conns_per_mirror = max(4, (self.threads // num_mirrors) + 6)
        self.mirror_pool = MirrorPool(deduped_mirrors, max_conns_per_mirror=max_conns_per_mirror)

        # Networking components
        self.cookie_jar = http.cookiejar.CookieJar()
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            TimeoutHTTPHandler(connect_timeout=self.connect_timeout, read_timeout=self.read_timeout),
            TimeoutHTTPSHandler(connect_timeout=self.connect_timeout, read_timeout=self.read_timeout, context=self.ssl_context),
        )

        # Download metadata resolved during probe
        self.resolved_url = self.url
        self.total_size = 0
        self.range_supported = False
        self.etag: Optional[str] = None
        self.last_modified: Optional[str] = None
        self.final_filename = ""
        self.target_file_path = ""
        self.tmp_file_path = ""
        self.state_file_path = ""

        # Runtime concurrency controller
        self.controller = ConcurrencyController(self.threads)

    def _get_active_threads(self) -> int:
        return self.controller.get_active()

    def _reduce_concurrency_on_rate_limit(self, code: int):
        """Adaptive Concurrency Throttling on 429/403/503."""
        new_lim = self.controller.reduce_limit(0.5)
        if not self.quiet:
            print(
                f"\n[1DM+ Throttling] HTTP {code} rate limit detected. Backing off concurrency to {new_lim} threads...",
                flush=True,
            )

    def _build_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
    ) -> urllib.request.Request:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", self.user_agent)
        req.add_header("Accept", "*/*")
        req.add_header("Connection", "keep-alive")
        for k, v in self.custom_headers.items():
            req.add_header(k, v)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        return req

    def _open_url(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.opener.open(req)

    def _resolve_google_drive(self, url: str) -> str:
        """Handles Google Drive URLs and bypasses virus warning / confirmation."""
        match = re.search(
            r"(?:https?://(?:drive\.google\.com/(?:file/d/|open\?id=|uc\?(?:[^&]+&)*id=)|"
            r"drive\.usercontent\.google\.com/download\?(?:[^&]+&)*id=))?([a-zA-Z0-9_-]{25,})",
            url,
        )
        if not match:
            return url

        file_id = match.group(1)
        direct_url = (
            f"https://drive.usercontent.google.com/download?id={file_id}"
            f"&export=download&confirm=t"
        )
        try:
            req = self._build_request(direct_url, method="GET")
            resp = self._open_url(req)
            content_type = resp.headers.get("Content-Type", "").lower()

            if "text/html" in content_type:
                html_data = resp.read().decode("utf-8", errors="ignore")
                resp.close()

                form_match = re.search(
                    r'<form\s+[^>]*id=["\']download-form["\'][^>]*action=["\']([^"\']+)["\']',
                    html_data,
                )
                if not form_match:
                    form_match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', html_data)

                if form_match:
                    action_url = form_match.group(1)
                    inputs = dict(
                        re.findall(
                            r'<input\s+[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                            html_data,
                        )
                    )
                    if "id" in inputs or "confirm" in inputs or "uuid" in inputs:
                        action_url = urllib.parse.urljoin(direct_url, action_url)
                        query_str = urllib.parse.urlencode(inputs)
                        delim = "&" if "?" in action_url else "?"
                        return f"{action_url}{delim}{query_str}"

                link_match = re.search(
                    r'<a\s+[^>]*href=["\']([^"\']*(?:confirm=[^"\']+|download)[^"\']*)["\']',
                    html_data,
                )
                if link_match:
                    return urllib.parse.urljoin(direct_url, link_match.group(1))

                confirm_match = re.search(r'confirm=([a-zA-Z0-9_-]+)', html_data)
                if confirm_match:
                    return f"{direct_url}&confirm={confirm_match.group(1)}"

            return resp.geturl() or direct_url
        except Exception:
            return direct_url

    def _resolve_filename(self, headers: http.client.HTTPMessage, current_url: str) -> str:
        """Extract filename from Content-Disposition, URL path, or default."""
        if self.raw_output_path:
            return os.path.basename(self.raw_output_path)

        cd = headers.get("Content-Disposition")
        if cd:
            try:
                msg = email.message.EmailMessage()
                msg["content-disposition"] = cd
                fname = msg.get_filename()
                if fname:
                    return os.path.basename(fname.strip("\"' "))
            except Exception:
                pass

            m = re.search(r"filename\*=UTF-8''([^;]+)", cd, re.IGNORECASE)
            if m:
                return os.path.basename(urllib.parse.unquote(m.group(1)).strip("\"' "))
            m = re.search(r"filename=[\"']?([^;\"']+)[\"']?", cd, re.IGNORECASE)
            if m:
                return os.path.basename(m.group(1).strip("\"' "))

        parsed = urllib.parse.urlparse(current_url)
        path = urllib.parse.unquote(parsed.path)
        base = os.path.basename(path.rstrip("/"))
        if base and base != "download" and "." in base:
            return base

        return "download.bin"

    def probe(self):
        """
        Probe URL to determine:
          1. Final redirected URL
          2. Content-Length & Accept-Ranges (HTTP 206 Partial Content)
          3. Filename, ETag & Last-Modified
        """
        current_url = self.url
        if "drive.google.com" in current_url or "drive.usercontent.google.com" in current_url:
            current_url = self._resolve_google_drive(current_url)

        redirects = 0
        last_resp = None

        while redirects < MAX_REDIRECTS:
            req = self._build_request(
                current_url,
                headers={
                    "Range": "bytes=0-0",
                    "Accept-Encoding": "identity",
                },
                method="GET",
            )
            try:
                resp = self._open_url(req)
            except urllib.error.HTTPError as e:
                if e.code == 416:
                    req_head = self._build_request(
                        current_url,
                        headers={"Accept-Encoding": "identity"},
                        method="HEAD",
                    )
                    try:
                        resp = self._open_url(req_head)
                    except urllib.error.HTTPError:
                        req_get = self._build_request(
                            current_url,
                            headers={"Accept-Encoding": "identity"},
                            method="GET",
                        )
                        resp = self._open_url(req_get)
                else:
                    raise

            new_url = resp.geturl()
            if new_url and new_url != current_url:
                current_url = new_url

            status = resp.status
            headers = resp.headers

            if status == 206:
                self.range_supported = True
                cr = headers.get("Content-Range", "")
                m = re.search(r"/(\d+)$", cr)
                if m:
                    self.total_size = int(m.group(1))
                else:
                    cl = headers.get("Content-Length")
                    self.total_size = int(cl) if cl else 0
                last_resp = resp
                break

            elif status == 200:
                self.range_supported = False
                cl = headers.get("Content-Length")
                self.total_size = int(cl) if cl else 0
                last_resp = resp
                break

            elif status in (301, 302, 303, 307, 308):
                loc = headers.get("Location")
                if not loc:
                    break
                next_url = urllib.parse.urljoin(current_url, loc)
                if not is_safe_url(next_url):
                    resp.close()
                    raise ValueError(f"Insecure or invalid redirect destination: {next_url}")
                current_url = next_url
                redirects += 1
                resp.close()
                continue
            else:
                last_resp = resp
                break

        if not last_resp:
            raise RuntimeError(f"Failed to probe URL after {redirects} redirects: {self.url}")

        self.resolved_url = current_url
        self.etag = last_resp.headers.get("ETag")
        self.last_modified = last_resp.headers.get("Last-Modified")
        self.final_filename = self._resolve_filename(last_resp.headers, self.resolved_url)
        last_resp.close()

        self.mirror_pool.record_result(self.resolved_url, 0.05, success=True)

        if self.raw_output_path:
            if os.path.isdir(self.raw_output_path):
                self.target_file_path = os.path.join(self.raw_output_path, self.final_filename)
            else:
                self.target_file_path = self.raw_output_path
        else:
            self.target_file_path = os.path.join(self.dest_dir, self.final_filename)

        os.makedirs(os.path.dirname(os.path.abspath(self.target_file_path)), exist_ok=True)
        self.tmp_file_path = f"{self.target_file_path}.tmp"
        self.state_file_path = f"{self.tmp_file_path}.state.json"

    def _preallocate(self, file_path: str, size: int):
        """Pre-allocate file space using posix_fallocate or fallback to ftruncate."""
        if size <= 0:
            return
        fd = os.open(file_path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            try:
                os.posix_fallocate(fd, 0, size)
            except (AttributeError, OSError):
                os.ftruncate(fd, size)
        finally:
            os.close(fd)

    def _partition_chunks(self) -> List[Dict]:
        """Calculate chunk boundaries matching 1DM+ partitioned range allocation."""
        if self.total_size <= 0:
            return []

        if self.chunk_size_mb:
            chunk_size = self.chunk_size_mb * 1024 * 1024
        else:
            if self.total_size >= 2 * 1024 * 1024 * 1024:    # >= 2GB
                chunk_size = 16 * 1024 * 1024               # 16 MB chunks
            elif self.total_size >= 500 * 1024 * 1024:        # >= 500MB
                chunk_size = 8 * 1024 * 1024                # 8 MB chunks
            elif self.total_size >= 100 * 1024 * 1024:        # >= 100MB
                chunk_size = 4 * 1024 * 1024                # 4 MB chunks
            else:
                chunk_size = max(BUFFER_SIZE, self.total_size // self.threads)

        min_chunks = self.threads
        if (self.total_size // chunk_size) < min_chunks and self.total_size > (min_chunks * BUFFER_SIZE):
            chunk_size = max(BUFFER_SIZE, self.total_size // min_chunks)

        chunks = []
        cur = 0
        chunk_id = 0
        while cur < self.total_size:
            end = min(cur + chunk_size - 1, self.total_size - 1)
            chunks.append({
                "id": chunk_id,
                "start": cur,
                "end": end,
                "downloaded": 0,
                "done": False,
                "active": False,
            })
            cur = end + 1
            chunk_id += 1

        return chunks

    def _load_or_create_state(self, chunks: List[Dict]) -> Tuple[List[Dict], int]:
        """Load resume state or initialize new state."""
        if not self.resume:
            return chunks, 0

        if os.path.exists(self.state_file_path) and os.path.exists(self.tmp_file_path):
            try:
                with open(self.state_file_path, "r", encoding="utf-8") as f:
                    state = json.load(f)

                if (
                    state.get("total_size") == self.total_size
                    and (self.etag is None or state.get("etag") == self.etag)
                    and len(state.get("chunks", [])) >= len(chunks)
                ):
                    saved_chunks = state["chunks"]
                    for sc in saved_chunks:
                        sc["active"] = False
                    initial_bytes = sum(c.get("downloaded", 0) for c in saved_chunks)
                    return saved_chunks, initial_bytes
            except Exception:
                pass

        return chunks, 0

    def _save_state(self, chunks: List[Dict]):
        """Persist state atomically to JSON file via .swp rename."""
        tmp_state = f"{self.state_file_path}.swp"
        try:
            state = {
                "url": self.resolved_url,
                "total_size": self.total_size,
                "etag": self.etag,
                "last_modified": self.last_modified,
                "chunks": chunks,
                "timestamp": time.time(),
            }
            with open(tmp_state, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(tmp_state, self.state_file_path)
        except Exception:
            pass

    def _worker_loop(
        self,
        worker_id: int,
        fd: int,
        work_stealer: WorkStealer,
        tracker: ProgressTracker,
        save_state_callback,
    ):
        """Worker thread routine."""
        while not work_stealer.is_all_done():
            self.controller.acquire()
            try:
                chunk = work_stealer.get_or_steal_chunk(f"worker_{worker_id}")
                if not chunk:
                    break

                try:
                    self._process_chunk(
                        fd,
                        chunk,
                        work_stealer,
                        tracker,
                        save_state_callback,
                    )
                finally:
                    work_stealer.release_chunk(chunk, done=chunk.get("done", False))
                    if chunk.get("done", False):
                        self.controller.record_success()
                    save_state_callback()
            finally:
                self.controller.release()

    def _process_chunk(
        self,
        fd: int,
        chunk: Dict,
        work_stealer: WorkStealer,
        tracker: ProgressTracker,
        save_state_callback,
    ):
        """Download range segments for a single chunk with strict range validation."""
        start_offset = chunk["start"] + chunk["downloaded"]

        with work_stealer.lock:
            end_offset = chunk["end"]
            if start_offset > end_offset:
                chunk["done"] = True
                return

        retries_left = self.retries
        backoff = 1.0

        while retries_left > 0:
            with work_stealer.lock:
                start_offset = chunk["start"] + chunk["downloaded"]
                end_offset = chunk["end"]
                if start_offset > end_offset:
                    chunk["done"] = True
                    return

            current_mirror = self.mirror_pool.get_best() or self.resolved_url
            headers = {
                "Range": f"bytes={start_offset}-{end_offset}",
                "Accept-Encoding": "identity",
            }
            # Only send If-Range if using the exact primary URL where ETag was probed.
            # Alternate mirrors often have differing ETags which causes 200 OK full file response.
            if current_mirror == self.resolved_url:
                if self.etag:
                    headers["If-Range"] = self.etag
                elif self.last_modified:
                    headers["If-Range"] = self.last_modified

            t0 = time.time()
            try:
                req = self._build_request(current_mirror, headers=headers)
                resp = self._open_url(req)
                t_connect = time.time() - t0

                # Validate HTTP 206 Partial Content strictly
                if resp.status == 200:
                    resp.close()
                    raise urllib.error.HTTPError(
                        req.full_url, 200, "Server ignored Range request and returned 200 OK (full file)", resp.headers, None
                    )
                elif resp.status != 206:
                    resp.close()
                    raise urllib.error.HTTPError(
                        req.full_url, resp.status, f"Expected HTTP 206 Partial Content, got {resp.status}", resp.headers, None
                    )

                # Validate Content-Range header
                cr = resp.headers.get("Content-Range")
                if not cr:
                    resp.close()
                    raise IOError(f"Missing Content-Range header from mirror {current_mirror}")
                m = re.search(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", cr)
                if not m:
                    resp.close()
                    raise IOError(f"Malformed Content-Range '{cr}' from mirror {current_mirror}")

                cr_start, cr_end = int(m.group(1)), int(m.group(2))
                if cr_start != start_offset:
                    resp.close()
                    raise IOError(f"Content-Range start mismatch: expected {start_offset}, got {cr_start}")
                if cr_end < cr_start:
                    resp.close()
                    raise IOError(f"Content-Range end {cr_end} is before start {cr_start}")
                if cr_end > end_offset:
                    resp.close()
                    raise IOError(f"Content-Range end {cr_end} exceeds requested end {end_offset}")
                if m.group(3) != "*" and self.total_size > 0:
                    cr_total = int(m.group(3))
                    if cr_total != self.total_size:
                        resp.close()
                        raise IOError(f"Content-Range total size mismatch: expected {self.total_size}, got {cr_total}")

                self.mirror_pool.record_latency(current_mirror, t_connect, success=True)

                while True:
                    with work_stealer.lock:
                        current_end = chunk["end"]
                        stream_limit = min(current_end, cr_end)
                        if start_offset > stream_limit:
                            if start_offset > current_end and chunk["downloaded"] >= (current_end - chunk["start"] + 1):
                                chunk["done"] = True
                            break
                        to_read = min(BUFFER_SIZE, stream_limit - start_offset + 1)
                        if to_read <= 0:
                            break

                    buf = resp.read(to_read)
                    if not buf:
                        with work_stealer.lock:
                            current_end = chunk["end"]
                            stream_limit = min(current_end, cr_end)
                        if start_offset <= stream_limit:
                            raise IOError(
                                f"Premature EOF on chunk {chunk['id']}: downloaded {start_offset} of "
                                f"{stream_limit + 1} bytes in current range"
                            )
                        break

                    with work_stealer.lock:
                        current_end = chunk["end"]
                        stream_limit = min(current_end, cr_end)
                        allowed_write = stream_limit - start_offset + 1
                        if allowed_write <= 0:
                            if start_offset > current_end and chunk["downloaded"] >= (current_end - chunk["start"] + 1):
                                chunk["done"] = True
                            break

                        write_len = min(len(buf), allowed_write)
                        os.pwrite(fd, buf[:write_len], start_offset)
                        start_offset += write_len
                        chunk["downloaded"] += write_len
                        tracker.add_bytes(write_len)

                        if start_offset > current_end and chunk["downloaded"] >= (current_end - chunk["start"] + 1):
                            chunk["done"] = True
                            break
                        if start_offset > cr_end:
                            break

                resp.close()

                is_done = False
                with work_stealer.lock:
                    expected_span = chunk["end"] - chunk["start"] + 1
                    if start_offset > chunk["end"] and chunk["downloaded"] >= expected_span:
                        chunk["done"] = True
                        is_done = True
                if is_done:
                    save_state_callback()
                    return

            except urllib.error.HTTPError as e:
                self.mirror_pool.record_latency(current_mirror, time.time() - t0, success=False)
                if e.code == 416:
                    if start_offset >= self.total_size:
                        with work_stealer.lock:
                            chunk["done"] = True
                        save_state_callback()
                        return
                    req_head = self._build_request(
                        current_mirror,
                        headers={"Accept-Encoding": "identity"},
                        method="HEAD",
                    )
                    try:
                        self._open_url(req_head).close()
                    except Exception:
                        pass

                elif e.code in (429, 403, 503):
                    self._reduce_concurrency_on_rate_limit(e.code)

                retries_left -= 1
                if retries_left <= 0:
                    raise RuntimeError(
                        f"Chunk {chunk['id']} failed on mirror {current_mirror} after {self.retries} retries: {e}"
                    )
                time.sleep(backoff)
                backoff = min(16.0, backoff * 1.5)

            except (socket.timeout, urllib.error.URLError, http.client.HTTPException, OSError) as e:
                self.mirror_pool.record_latency(current_mirror, time.time() - t0, success=False)
                retries_left -= 1
                if retries_left <= 0:
                    raise RuntimeError(
                        f"Chunk {chunk['id']} socket failure after {self.retries} retries: {e}"
                    )
                time.sleep(backoff)
                backoff = min(16.0, backoff * 1.5)

            finally:
                self.mirror_pool.release_connection(current_mirror)

    def _download_fallback_stream(self, tracker: ProgressTracker):
        """Fallback to single identity stream when range requests are unsupported."""
        if not self.quiet:
            print("[1DM+] Server does not support Range requests. Streaming with identity encoding...")

        req = self._build_request(
            self.resolved_url,
            headers={"Accept-Encoding": "identity"},
        )
        resp = self._open_url(req)
        self.controller.acquire()

        try:
            with open(self.tmp_file_path, "wb") as f:
                while True:
                    buf = resp.read(BUFFER_SIZE)
                    if not buf:
                        break
                    f.write(buf)
                    tracker.add_bytes(len(buf))
        finally:
            resp.close()
            self.controller.release()

    def start(self) -> str:
        """Execute the download and return the final destination path."""
        start_time = time.time()
        self.probe()

        if not self.quiet:
            print(f"[1DM+ Engine] Target: {self.final_filename}")
            print(f"[1DM+ Engine] Size: {format_bytes(self.total_size) if self.total_size > 0 else 'Unknown'}")
            print(f"[1DM+ Engine] Range Support: {'Yes (206 Partial Content)' if self.range_supported else 'No (Identity fallback)'}")
            print(f"[1DM+ Engine] Concurrency: {self.threads} threads (max: {self.max_threads})")
            if len(self.mirror_pool.mirrors) > 1:
                print(f"[1DM+ Engine] Multi-Mirror Racing: {len(self.mirror_pool.mirrors)} mirrors active")

        tracker = ProgressTracker(
            total_size=self.total_size,
            active_threads_ref=self._get_active_threads,
            quiet=self.quiet,
        )

        def monitor_loop():
            while not tracker.stop_event.is_set():
                tracker.render()
                time.sleep(0.1 if tracker.is_tty else 1.0)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

        try:
            if not self.range_supported or self.total_size <= 0:
                self._download_fallback_stream(tracker)
            else:
                chunks = self._partition_chunks()
                chunks, initial_bytes = self._load_or_create_state(chunks)
                tracker.set_initial_bytes(initial_bytes)

                if initial_bytes > 0 and not self.quiet:
                    print(f"[1DM+] Resuming download from {format_bytes(initial_bytes)} ({initial_bytes/self.total_size*100:.1f}%)")

                self._preallocate(self.tmp_file_path, self.total_size)

                fd = os.open(self.tmp_file_path, os.O_RDWR)
                state_lock = threading.Lock()
                work_stealer = WorkStealer(chunks, min_steal_size=MIN_CHUNK_STEAL_SIZE)

                def save_state_locked():
                    with state_lock:
                        self._save_state(work_stealer.get_all_chunks())

                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                        futures = [
                            executor.submit(
                                self._worker_loop,
                                i,
                                fd,
                                work_stealer,
                                tracker,
                                save_state_locked,
                            )
                            for i in range(self.threads)
                        ]
                        for future in concurrent.futures.as_completed(futures):
                            future.result()
                finally:
                    os.fsync(fd)
                    os.close(fd)

            # Verification and atomic finalization
            if self.total_size > 0:
                all_chunks = work_stealer.get_all_chunks()
                incomplete = [c for c in all_chunks if not c.get("done", False)]
                if incomplete:
                    raise IOError(
                        f"Download incomplete: {len(incomplete)} chunk(s) not finished"
                    )
                total_dl = sum(c.get("downloaded", 0) for c in all_chunks)
                if total_dl != self.total_size:
                    raise IOError(
                        f"Byte coverage mismatch: chunks total {total_dl} bytes, expected {self.total_size} bytes"
                    )
                actual_size = os.path.getsize(self.tmp_file_path)
                if actual_size != self.total_size:
                    raise IOError(
                        f"Size mismatch: downloaded {actual_size} bytes, expected {self.total_size} bytes"
                    )

            os.replace(self.tmp_file_path, self.target_file_path)
            if os.path.exists(self.state_file_path):
                try:
                    os.unlink(self.state_file_path)
                except OSError:
                    pass

        finally:
            tracker.close()

        elapsed = time.time() - start_time
        speed = self.total_size / elapsed if elapsed > 0 else 0
        if not self.quiet:
            print(
                f"[1DM+] Complete: {self.target_file_path} "
                f"({format_bytes(os.path.getsize(self.target_file_path))}) "
                f"in {format_time(elapsed)} ({format_bytes(speed)}/s)"
            )

        return self.target_file_path


def main():
    parser = argparse.ArgumentParser(
        description="1DM+ High-Performance Multi-Connection HTTP Downloader",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", help="Download URL or Google Drive link/ID")
    parser.add_argument("-m", "--mirror", action="append", default=[], help="Additional mirror URLs to race (can be repeated)")
    parser.add_argument("-o", "--output", help="Destination file path")
    parser.add_argument("-d", "--dir", help="Destination directory", default=".")
    parser.add_argument(
        "-s", "-x", "-j", "-n", "--threads", "--concurrency",
        type=int,
        default=int(os.environ.get("DOWNLOAD_THREADS", DEFAULT_THREADS)),
        help="Number of concurrent download connections (default: 64, max: 128)",
    )
    parser.add_argument(
        "--max-threads",
        type=int,
        default=int(os.environ.get("MAX_DOWNLOAD_THREADS", MAX_SUPPORTED_THREADS)),
        help="Maximum allowable limit for thread concurrency (max: 128)",
    )
    parser.add_argument(
        "-c", "-C", "--continue", "--resume",
        dest="resume",
        action="store_true",
        default=True,
        help="Resume partially downloaded file",
    )
    parser.add_argument(
        "--no-resume",
        dest="resume",
        action="store_false",
        help="Restart download from beginning",
    )
    parser.add_argument("-U", "--user-agent", default=DEFAULT_USER_AGENT, help="Custom User-Agent")
    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help="Custom HTTP header in 'Key: Value' format (can be repeated)",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_READ_TIMEOUT, help="Connection read timeout in seconds")
    parser.add_argument("--connect-timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT, help="Connection connect timeout in seconds")
    parser.add_argument("--retries", type=int, default=10, help="Max retries per chunk on error")
    parser.add_argument("--chunk-size", type=int, default=None, help="Chunk size in MB")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no progress)")

    args = parser.parse_args()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    downloader = FastDownloader(
        url=args.url,
        mirrors=args.mirror,
        output_path=args.output,
        dest_dir=args.dir,
        threads=args.threads,
        max_threads=args.max_threads,
        connect_timeout=args.connect_timeout,
        read_timeout=args.timeout,
        retries=args.retries,
        user_agent=args.user_agent,
        headers=headers,
        resume=args.resume,
        quiet=args.quiet,
        chunk_size_mb=args.chunk_size,
    )

    try:
        downloader.start()
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"\n[1DM+ ERROR] {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

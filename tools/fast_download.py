#!/usr/bin/env python3
"""
1DM+ High-Performance Multi-Connection HTTP Range Downloader
Reverse-engineered architecture from 1DM+ (Download Manager Plus)
Features:
  - Multi-connection HTTP range download with chunk partitioning
  - Concurrency: default 32 threads, configurable up to 128 threads
  - Range probing (bytes=0- vs 206 Partial Content), fallback to identity stream
  - Pre-allocation (sparse / posix_fallocate) to eliminate disk fragmentation
  - Chunk-level retry, socket resilience, session cookies, redirects follow (up to 20)
  - Google Drive / direct link resolver with virus scan confirmation bypass
  - Resumable downloads via .tmp and JSON state tracking
  - Clean CLI progress reporting with CI-friendly non-interactive mode
"""

import argparse
import concurrent.futures
import email.message
import http.client
import http.cookiejar
import json
import math
import os
import queue
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
DEFAULT_THREADS = 32
MAX_SUPPORTED_THREADS = 128
BUFFER_SIZE = 256 * 1024  # 256 KB matching 1DM+ chunk buffer size
DEFAULT_TIMEOUT = 30      # Socket connect & read timeout in seconds
MAX_REDIRECTS = 20        # Matching 1DM+ follow-up requests limit
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)


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
            # CI / Non-interactive mode: output every 5 seconds or when forced
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


class FastDownloader:
    """
    High-Performance Downloader implementing 1DM+ Reverse Engineered Logic.
    """

    def __init__(
        self,
        url: str,
        output_path: Optional[str] = None,
        dest_dir: Optional[str] = None,
        threads: int = DEFAULT_THREADS,
        max_threads: int = MAX_SUPPORTED_THREADS,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = 10,
        user_agent: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        resume: bool = True,
        quiet: bool = False,
        chunk_size_mb: Optional[int] = None,
    ):
        self.url = url
        self.raw_output_path = output_path
        self.dest_dir = dest_dir or os.getcwd()
        self.max_threads = max(1, min(MAX_SUPPORTED_THREADS, max_threads))
        self.threads = max(1, min(self.max_threads, threads))
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.custom_headers = headers or {}
        self.resume = resume
        self.quiet = quiet
        self.chunk_size_mb = chunk_size_mb

        # Networking components
        self.cookie_jar = http.cookiejar.CookieJar()
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Download metadata resolved during probe
        self.resolved_url = self.url
        self.total_size = 0
        self.range_supported = False
        self.etag: Optional[str] = None
        self.final_filename = ""
        self.target_file_path = ""
        self.tmp_file_path = ""
        self.state_file_path = ""

        # Runtime concurrency tracking
        self.active_threads_count = 0
        self.active_lock = threading.Lock()

    def _get_active_threads(self) -> int:
        with self.active_lock:
            return self.active_threads_count

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
        # Attach cookies
        self.cookie_jar.add_cookie_header(req)
        return req

    def _open_url(
        self,
        req: urllib.request.Request,
        timeout: Optional[int] = None,
    ) -> http.client.HTTPResponse:
        t = timeout or self.timeout
        resp = urllib.request.urlopen(req, context=self.ssl_context, timeout=t)
        self.cookie_jar.extract_cookies(resp, req)
        return resp

    def _resolve_google_drive(self, url: str) -> str:
        """
        Handles Google Drive URLs and bypasses virus warning / confirmation.
        Supports:
          - drive.google.com/file/d/<id>/...
          - drive.google.com/uc?id=<id>...
          - drive.google.com/open?id=<id>
          - drive.usercontent.google.com/download?id=<id>
          - Raw file IDs
        """
        match = re.search(
            r"(?:https?://(?:drive\.google\.com/(?:file/d/|open\?id=|uc\?(?:[^&]+&)*id=)|"
            r"drive\.usercontent\.google\.com/download\?(?:[^&]+&)*id=))?([a-zA-Z0-9_-]{25,})",
            url,
        )
        if not match:
            return url

        file_id = match.group(1)
        # Direct download endpoint with confirmation token
        direct_url = (
            f"https://drive.usercontent.google.com/download?id={file_id}"
            f"&export=download&confirm=t"
        )
        try:
            req = self._build_request(direct_url, method="GET")
            resp = self._open_url(req)
            content_type = resp.headers.get("Content-Type", "").lower()

            # If response is HTML, inspect for confirmation form
            if "text/html" in content_type:
                html_data = resp.read().decode("utf-8", errors="ignore")
                resp.close()

                # 1. Search for download form with hidden inputs
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

                # 2. Search for confirmation link with confirm token
                link_match = re.search(
                    r'<a\s+[^>]*href=["\']([^"\']*(?:confirm=[^"\']+|download)[^"\']*)["\']',
                    html_data,
                )
                if link_match:
                    return urllib.parse.urljoin(direct_url, link_match.group(1))

                # 3. Direct regex match on confirm parameter
                confirm_match = re.search(r'confirm=([a-zA-Z0-9_-]+)', html_data)
                if confirm_match:
                    return f"{direct_url}&confirm={confirm_match.group(1)}"

            # Direct response ready
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

        # Fallback to URL path
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
          3. Filename & ETag
        """
        current_url = self.url
        if "drive.google.com" in current_url or "drive.usercontent.google.com" in current_url:
            current_url = self._resolve_google_drive(current_url)

        # Follow redirects up to MAX_REDIRECTS while probing
        redirects = 0
        last_resp = None

        while redirects < MAX_REDIRECTS:
            req = self._build_request(
                current_url,
                headers={"Range": "bytes=0-0"},
                method="GET",
            )
            try:
                resp = self._open_url(req)
            except urllib.error.HTTPError as e:
                # Some servers return 416 if Range header is invalid on 0-byte file
                if e.code == 416:
                    req_head = self._build_request(current_url, method="HEAD")
                    resp = self._open_url(req_head)
                else:
                    raise

            # Detect redirect (in case urllib auto-redirect didn't update URL)
            new_url = resp.geturl()
            if new_url and new_url != current_url:
                current_url = new_url

            status = resp.status
            headers = resp.headers

            # 206 Partial Content: Range supported!
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

            # 200 OK: Server does not support byte range requests (stream identity)
            elif status == 200:
                self.range_supported = False
                cl = headers.get("Content-Length")
                self.total_size = int(cl) if cl else 0
                last_resp = resp
                break

            # Redirection status code
            elif status in (301, 302, 303, 307, 308):
                loc = headers.get("Location")
                if not loc:
                    break
                current_url = urllib.parse.urljoin(current_url, loc)
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
        self.final_filename = self._resolve_filename(last_resp.headers, self.resolved_url)
        last_resp.close()

        # Resolve final filesystem paths
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
        """Pre-allocate file space using posix_fallocate or sparse ftruncate."""
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
        """
        Calculate chunk boundaries matching 1DM+ partitioned range allocation.
        """
        if self.total_size <= 0:
            return []

        # Determine optimal chunk size
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

        # Ensure we have enough chunks to saturate configured concurrency
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
                    and state.get("etag") == self.etag
                    and len(state.get("chunks", [])) == len(chunks)
                ):
                    saved_chunks = state["chunks"]
                    initial_bytes = sum(c.get("downloaded", 0) for c in saved_chunks)
                    return saved_chunks, initial_bytes
            except Exception:
                pass  # Fall back to starting fresh if state is corrupted

        return chunks, 0

    def _save_state(self, chunks: List[Dict]):
        """Persist state to JSON file."""
        tmp_state = f"{self.state_file_path}.swp"
        try:
            state = {
                "url": self.resolved_url,
                "total_size": self.total_size,
                "etag": self.etag,
                "chunks": chunks,
                "timestamp": time.time(),
            }
            with open(tmp_state, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(tmp_state, self.state_file_path)
        except Exception:
            pass

    def _download_chunk(
        self,
        fd: int,
        chunk: Dict,
        tracker: ProgressTracker,
        state_save_callback,
    ):
        """Worker function for downloading a single chunk."""
        start_offset = chunk["start"] + chunk["downloaded"]
        end_offset = chunk["end"]

        if start_offset > end_offset:
            chunk["done"] = True
            return

        retries_left = self.retries
        backoff = 1.0

        with self.active_lock:
            self.active_threads_count += 1

        try:
            while start_offset <= end_offset and retries_left > 0:
                req = self._build_request(
                    self.resolved_url,
                    headers={"Range": f"bytes={start_offset}-{end_offset}"},
                )
                try:
                    resp = self._open_url(req)
                    while start_offset <= end_offset:
                        to_read = min(BUFFER_SIZE, end_offset - start_offset + 1)
                        buf = resp.read(to_read)
                        if not buf:
                            break
                        # Atomic seek + write at OS level to preallocated file
                        os.pwrite(fd, buf, start_offset)
                        n = len(buf)
                        start_offset += n
                        chunk["downloaded"] += n
                        tracker.add_bytes(n)

                    resp.close()

                    if start_offset > end_offset:
                        chunk["done"] = True
                        state_save_callback()
                        return

                except (socket.timeout, urllib.error.URLError, http.client.HTTPException, OSError) as e:
                    retries_left -= 1
                    if retries_left <= 0:
                        raise RuntimeError(
                            f"Chunk {chunk['id']} failed after {self.retries} retries: {e}"
                        )
                    time.sleep(backoff)
                    backoff = min(16.0, backoff * 1.5)
        finally:
            with self.active_lock:
                self.active_threads_count -= 1

    def _download_fallback_stream(self, tracker: ProgressTracker):
        """Fallback to single identity stream when range requests are unsupported."""
        if not self.quiet:
            print("[1DM+] Server does not support Range requests. Streaming with identity encoding...")

        req = self._build_request(
            self.resolved_url,
            headers={"Accept-Encoding": "identity"},
        )
        resp = self._open_url(req)

        with self.active_lock:
            self.active_threads_count = 1

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
            with self.active_lock:
                self.active_threads_count = 0

    def start(self) -> str:
        """Execute the download and return the final destination path."""
        start_time = time.time()
        self.probe()

        if not self.quiet:
            print(f"[1DM+ Engine] Target: {self.final_filename}")
            print(f"[1DM+ Engine] Size: {format_bytes(self.total_size) if self.total_size > 0 else 'Unknown'}")
            print(f"[1DM+ Engine] Range Support: {'Yes (206 Partial Content)' if self.range_supported else 'No (Identity fallback)'}")
            print(f"[1DM+ Engine] Concurrency: {self.threads} threads (max: {self.max_threads})")

        tracker = ProgressTracker(
            total_size=self.total_size,
            active_threads_ref=self._get_active_threads,
            quiet=self.quiet,
        )

        # Background progress monitor thread
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

                # Pre-allocate file on disk
                self._preallocate(self.tmp_file_path, self.total_size)

                # Open target file descriptor for concurrent pwrite
                fd = os.open(self.tmp_file_path, os.O_RDWR)
                state_lock = threading.Lock()

                def save_state_locked():
                    with state_lock:
                        self._save_state(chunks)

                try:
                    pending_chunks = [c for c in chunks if not c.get("done", False)]

                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                        futures = [
                            executor.submit(
                                self._download_chunk,
                                fd,
                                c,
                                tracker,
                                save_state_locked,
                            )
                            for c in pending_chunks
                        ]
                        for future in concurrent.futures.as_completed(futures):
                            future.result()  # Propagate any chunk exception
                finally:
                    os.fsync(fd)
                    os.close(fd)

            # Verification and atomic finalization
            if self.total_size > 0:
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
    parser.add_argument("-o", "--output", help="Destination file path")
    parser.add_argument("-d", "--dir", help="Destination directory", default=".")
    parser.add_argument(
        "-s", "-x", "-j", "-n", "--threads", "--concurrency",
        type=int,
        default=int(os.environ.get("DOWNLOAD_THREADS", DEFAULT_THREADS)),
        help="Number of concurrent download connections (default: 32, max: 128)",
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
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Connection timeout in seconds")
    parser.add_argument("--retries", type=int, default=10, help="Max retries per chunk on error")
    parser.add_argument("--chunk-size", type=int, default=None, help="Chunk size in MB")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no progress)")

    args = parser.parse_args()

    # Parse custom headers
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    downloader = FastDownloader(
        url=args.url,
        output_path=args.output,
        dest_dir=args.dir,
        threads=args.threads,
        max_threads=args.max_threads,
        timeout=args.timeout,
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

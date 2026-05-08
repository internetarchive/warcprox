#!/usr/bin/env python3
"""
Demo: how warcprox responds when an upstream HTTP server slow-dribbles bytes
inside a chunked response, with and without the --fetch-timeout watchdog.

Run twice to compare:

    python demo/watchdog_demo.py --fetch-timeout 0     # watchdog DISABLED
    python demo/watchdog_demo.py --fetch-timeout 10    # watchdog kills stuck
                                                       # fetches at 10s

Press Enter to fire a single request through warcprox, then watch /status
poll output. Without the watchdog, seconds_behind grows without bound;
the request never completes (Ctrl-C to exit). With the watchdog enabled,
the request fails with 502 after fetch_timeout, /status clears, and
warcprox is healthy again.

Why this hangs warcprox without the watchdog: the slow-loris sends bytes
within the per-recv socket timeout (so it never fires) but never sends a
\\n. The handler is parked inside http.client._read_next_chunk_size's
readline call, which can't return until it sees a newline.
"""
import argparse
import http.server
import json
import logging
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request

import warcprox
import warcprox.controller
import warcprox.warcproxy

# warcprox blocks proxy requests to localhost by default; allow them here.
warcprox.warcproxy.WarcProxyHandler.allow_localhost = True


class SlowLoris(http.server.BaseHTTPRequestHandler):
    """Sends a single valid chunk, then dribbles bytes without newlines."""

    DRIBBLE_INTERVAL = 2.0  # seconds between sends; must be < socket_timeout

    def do_GET(self):
        print(f'[upstream] got request: {self.path}', flush=True)
        self.send_response(200)
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        self.wfile.write(b'5\r\nhello\r\n')
        self.wfile.flush()
        print(f'[upstream] sent first chunk; now dribbling "." every '
              f'{self.DRIBBLE_INTERVAL}s without newlines',
              flush=True)
        try:
            while True:
                self.wfile.write(b'.')
                self.wfile.flush()
                time.sleep(self.DRIBBLE_INTERVAL)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f'[upstream] client closed: {type(e).__name__}', flush=True)

    def log_message(self, fmt, *args):
        pass


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_upstream():
    server = ThreadedHTTPServer(('127.0.0.1', 0), SlowLoris)
    threading.Thread(
            target=server.serve_forever, daemon=True,
            name='SlowLorisThread').start()
    return server


def start_warcprox(fetch_timeout):
    options = warcprox.Options(
        port=0,
        address='127.0.0.1',
        dedup_db_file='/dev/null',
        stats_db_file='/dev/null',
        queue_size=100,
        max_threads=8,
        socket_timeout=3.0,
        fetch_timeout=fetch_timeout,
    )
    controller = warcprox.controller.WarcproxController(options=options)
    controller.start()
    return controller


def fetch_status(proxy_port):
    try:
        with urllib.request.urlopen(
                f'http://localhost:{proxy_port}/status', timeout=3) as r:
            return json.loads(r.read())
    except Exception as e:
        return {'error': repr(e)}


def fire_request(proxy_port, upstream_port):
    """Fire a single proxied GET in a daemon thread; return the thread."""
    url = f'http://127.0.0.1:{upstream_port}/foo'
    proxy_handler = urllib.request.ProxyHandler({
        'http': f'http://localhost:{proxy_port}'})
    opener = urllib.request.build_opener(proxy_handler)
    started = time.monotonic()

    def _go():
        try:
            with opener.open(url, timeout=600) as r:
                body = r.read()
                age = time.monotonic() - started
                print(f'[client] response complete after {age:.1f}s '
                      f'status={r.status} bytes={len(body)}', flush=True)
        except urllib.error.HTTPError as e:
            age = time.monotonic() - started
            print(f'[client] HTTP error after {age:.1f}s: '
                  f'{e.code} {e.reason}', flush=True)
        except Exception as e:
            age = time.monotonic() - started
            print(f'[client] request failed after {age:.1f}s: '
                  f'{e!r}', flush=True)

    t = threading.Thread(target=_go, daemon=True, name='ClientThread')
    t.start()
    return t


def main():
    p = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--fetch-timeout', type=float, default=0.0,
                   help='watchdog cap (seconds); 0 disables (default 0)')
    p.add_argument('--watch-seconds', type=float, default=60.0,
                   help='how long to poll /status (default 60s)')
    args = p.parse_args()

    # Surface the watchdog WARNING when it fires.
    logging.basicConfig(
        level=logging.WARNING,
        format='[warcprox %(name)s] %(levelname)s: %(message)s')

    upstream = start_upstream()
    upstream_port = upstream.server_address[1]
    print(f'[upstream] slow-loris listening on 127.0.0.1:{upstream_port}',
          flush=True)

    controller = start_warcprox(args.fetch_timeout)
    proxy_port = controller.proxy.server_port
    if args.fetch_timeout:
        mode = f'fetch-timeout={args.fetch_timeout}s (watchdog ENABLED)'
    else:
        mode = 'fetch-timeout=0 (watchdog DISABLED)'
    print(f'[warcprox] listening on 127.0.0.1:{proxy_port} {mode}',
          flush=True)

    try:
        input('Press Enter to fire request through warcprox... ')
    except (EOFError, KeyboardInterrupt):
        pass

    client = fire_request(proxy_port, upstream_port)
    fired_at = time.monotonic()

    print(f'[demo] polling /status every 2s for up to '
          f'{args.watch_seconds:.0f}s', flush=True)
    try:
        while time.monotonic() - fired_at < args.watch_seconds:
            time.sleep(2.0)
            st = fetch_status(proxy_port)
            t = time.monotonic() - fired_at
            ar = st.get('active_requests')
            sb = st.get('seconds_behind')
            earliest = st.get('earliest_still_active_fetch_start')
            print(f'[t={t:5.1f}s] active_requests={ar!s:>3} '
                  f'seconds_behind={sb!s:>5} '
                  f'earliest_still_active_fetch_start={earliest}',
                  flush=True)
            if not client.is_alive():
                print('[demo] client request thread finished',
                      flush=True)
                break
    except KeyboardInterrupt:
        print('\n[demo] interrupted by user', flush=True)
    finally:
        print('[demo] shutting down warcprox & upstream...', flush=True)
        controller.stop.set()
        try:
            controller.shutdown()
        except Exception:
            pass
        upstream.shutdown()
        upstream.server_close()


if __name__ == '__main__':
    sys.exit(main() or 0)

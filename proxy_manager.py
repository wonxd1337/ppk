# proxy_manager.py - FIXED VERSION
# Fixes applied:
#   [FIX-4] Duplicate stop() dihapus — yang pertama di-override yang kedua,
#           _cache_save() tidak pernah dipanggil saat shutdown.
#   [FIX-7] _refresh_in_progress Event: scanner bisa wait_if_refreshing()
#           sebelum memulai domain scan batch agar tidak terpotong proxy swap.
#   [FIX-8] get_proxy_for_retry: prioritaskan premium_pool (proxy terverifikasi)
#           untuk retry tinggi — setelah refresh list baru belum teruji,
#           premium_pool berisi proxy lama yang terbukti berhasil.

import threading
import time
import random
import os
import json
import requests
from queue import Queue
from collections import defaultdict
from config import Config


class ProxyManager:
    def __init__(self):
        self.proxy_list    = []
        self.socks5_proxies = []
        self.http_proxies   = []
        self.proxy_stats    = defaultdict(lambda: {
            'success': 0, 'fail': 0, 'total_time': 0,
            'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
            'proxy_type': 'http', 'consec_fail': 0, 'last_fail_time': 0
        })
        self.lock    = threading.Lock()
        self.running = True
        self.last_refresh = 0

        self.cache_file = os.path.join(Config.TEMP_DIR, Config.PROXY_CACHE_FILE)
        self._sig_file  = os.path.join(Config.TEMP_DIR, "proxy_list_signature.json")
        self._list_line_counts = {}
        self.premium_pool = set()
        self._cache_load()

        self.min_weight   = 0.1
        self.max_weight   = 3.0
        self.socks5_priority = 0.7
        self.TIER3_RECOVERY_WINDOW = getattr(Config, 'TIER3_RECOVERY_WINDOW', 1800)

        # [FIX-7] Event yang di-set saat refresh sedang berjalan.
        # scanner.process_ip memanggil wait_if_refreshing() sebelum memulai
        # ThreadPoolExecutor domain scan agar tidak terpotong proxy swap.
        self._refresh_in_progress = threading.Event()
        self._refresh_in_progress.clear()   # default: tidak refreshing

        self.start_auto_refresh()

    # ── proxy refresh status ───────────────────────────────
    def is_refreshing(self):
        return self._refresh_in_progress.is_set()

    def wait_if_refreshing(self, timeout=30):
        """Tunggu sampai refresh selesai (max timeout detik).
        Dipanggil oleh scanner sebelum memulai batch domain scan."""
        if self._refresh_in_progress.is_set():
            print(f"[~] Proxy refresh sedang berjalan, tunggu (max {timeout}s)...",
                  flush=True)
            # Event.wait() returns True jika event di-clear sebelum timeout
            cleared = not self._refresh_in_progress.wait(timeout=timeout)
            if not cleared:
                print("[!] Proxy refresh timeout — lanjut scan tanpa menunggu",
                      flush=True)

    # ── parse & download ───────────────────────────────────
    def parse_proxy_string(self, proxy_str, default_type='socks5'):
        proxy_str = proxy_str.strip()
        if '://' in proxy_str:
            if 'socks5' in proxy_str.lower():
                return {'url': proxy_str, 'type': 'socks5'}
            elif 'socks4' in proxy_str.lower():
                return {'url': proxy_str, 'type': 'socks4'}
            return {'url': proxy_str, 'type': 'http'}
        if default_type == 'socks5':
            return {'url': f'socks5://{proxy_str}', 'type': 'socks5'}
        elif default_type == 'socks4':
            return {'url': f'socks4a://{proxy_str}', 'type': 'socks4'}
        return {'url': f'http://{proxy_str}', 'type': 'http'}

    def download_proxies(self):
        import hashlib
        headers      = {"User-Agent": "Mozilla/5.0"}
        proxies      = []
        socks5_temp  = []
        http_temp    = []
        line_counts  = {}
        content_hashes = {}

        for list_url in Config.PROXY_LISTS:
            default_type = 'http'
            if 'socks5' in list_url.lower():
                default_type = 'socks5'
            elif 'socks4' in list_url.lower():
                default_type = 'socks4'
            try:
                response = requests.get(list_url, headers=headers,
                                        timeout=30, verify=False)
                if response.status_code != 200:
                    line_counts[list_url]    = -1
                    content_hashes[list_url] = None
                    continue
                content_hashes[list_url] = hashlib.blake2b(
                    response.text.encode('utf-8'), digest_size=16).hexdigest()
                lines = [l.strip() for l in response.text.split('\n') if l.strip()]
                line_counts[list_url] = len(lines)
                for line in lines:
                    parsed = self.parse_proxy_string(line, default_type)
                    proxies.append(parsed['url'])
                    if parsed['type'] in ('socks5', 'socks4'):
                        socks5_temp.append(parsed['url'])
                    else:
                        http_temp.append(parsed['url'])
                print(f"[+] list {default_type}: {len(lines)} baris "
                      f"(hash={content_hashes[list_url][:12]})", flush=True)
            except Exception:
                line_counts[list_url]    = -1
                content_hashes[list_url] = None

        changed = self._compare_line_counts(line_counts, content_hashes)
        self._last_download_changed = changed

        proxies     = list(dict.fromkeys(proxies))
        socks5_temp = list(dict.fromkeys(socks5_temp))
        http_temp   = list(dict.fromkeys(http_temp))

        if not changed or not proxies:
            print(f"[i] TheSpeedX belum update — pool lama dipakai "
                  f"(Tier 3, {len(self.proxy_list)} proxy)", flush=True)
            self._cache_save()
            return self.proxy_list

        print("[i] TheSpeedX list berubah — swap proxy pool", flush=True)

        # [FIX-7] Set flag refresh in progress sebelum swap pool
        self._refresh_in_progress.set()
        try:
            with self.lock:
                self.socks5_proxies = socks5_temp
                self.http_proxies   = http_temp
                self.proxy_list     = proxies
        finally:
            # [FIX-7] Clear flag setelah swap selesai — scanner yang waiting akan lanjut
            self._refresh_in_progress.clear()

        # Lazy-create stats untuk proxy baru (di luar lock, GIL-safe untuk key berbeda)
        for proxy in proxies:
            if proxy not in self.proxy_stats:
                self.proxy_stats[proxy] = {
                    'success': 0, 'fail': 0, 'total_time': 0,
                    'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
                    'proxy_type': 'socks5' if proxy in socks5_temp else 'http',
                    'consec_fail': 0, 'last_fail_time': 0
                }

        print(f"[+] Proxy Manager: {len(self.socks5_proxies)} SOCKS, "
              f"{len(self.http_proxies)} HTTP (total {len(self.proxy_list)})", flush=True)
        self._cache_save()
        return proxies

    # ── cache persist ──────────────────────────────────────
    def _cache_save(self):
        try:
            Config.ensure_temp_dir()
            snapshot = {
                'ts':           time.time(),
                'proxy_list':   list(self.proxy_list),
                'premium_pool': sorted(self.premium_pool),
                'stats':        {p: {k: v for k, v in s.items()}
                                 for p, s in self.proxy_stats.items()},
            }
            with open(self.cache_file, 'w') as f:
                json.dump(snapshot, f)
        except Exception as e:
            print(f"[!] cache save error: {e}", flush=True)

    def _cache_load(self):
        try:
            if not os.path.exists(self.cache_file):
                print("[i] No proxy cache yet (fresh run)", flush=True)
                return
            with open(self.cache_file) as f:
                snap = json.load(f)
            for p in snap.get('premium_pool', []):
                self.premium_pool.add(p)
            for p, s in snap.get('stats', {}).items():
                if p not in self.proxy_stats:
                    self.proxy_stats[p] = s
            if not self.proxy_list:
                cached_list = snap.get('proxy_list', [])
                for p in cached_list:
                    if p not in self.proxy_stats:
                        self.proxy_stats[p] = {
                            'success': 0, 'fail': 0, 'total_time': 0,
                            'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
                            'proxy_type': 'socks5' if p.startswith('socks5') else 'http',
                            'consec_fail': 0, 'last_fail_time': 0
                        }
                    self.proxy_list.append(p)
                    if p.startswith('socks'):
                        self.socks5_proxies.append(p)
                    else:
                        self.http_proxies.append(p)
                print(f"[+] Cache: {len(cached_list)} proxy dipulihkan", flush=True)
            print(f"[+] Cache: {len(self.premium_pool)} premium, "
                  f"{len(snap.get('stats', {}))} stats", flush=True)
        except Exception as e:
            print(f"[!] cache load error: {e}", flush=True)

    def _compare_line_counts(self, new_counts, new_hashes=None):
        new_hashes = new_hashes or {}
        old_sig    = {}
        old_streak = 0
        try:
            if os.path.exists(self._sig_file):
                raw = json.load(open(self._sig_file))
                if isinstance(raw, dict) and 'meta' in raw:
                    old_sig    = {k: v for k, v in raw.items() if k != 'meta'}
                    old_streak = raw.get('meta', {}).get('streak_unchanged', 0)
                else:
                    old_sig = {k: v for k, v in raw.items() if k != 'meta'}
        except Exception:
            pass

        changed = not old_sig
        if not changed:
            for url, n in new_counts.items():
                old      = old_sig.get(url, {})
                old_n    = old.get('lines', -1) if isinstance(old, dict) else old
                old_hash = old.get('hash') if isinstance(old, dict) else None
                new_hash = new_hashes.get(url)
                if old_n != n:
                    changed = True
                    print(f"[i] list berubah: {url.split('/')[-1]} {old_n} -> {n} baris",
                          flush=True)
                elif (old_hash is not None and new_hash is not None
                      and old_hash != new_hash):
                    changed = True
                    print(f"[i] list berubah (isi, baris sama {n}): "
                          f"{url.split('/')[-1]} hash {old_hash[:12]}->{new_hash[:12]}",
                          flush=True)

        new_streak = 0 if changed else old_streak + 1
        try:
            Config.ensure_temp_dir()
            sig_out = {'meta': {'streak_unchanged': new_streak, 'ts': time.time()}}
            for u, n in new_counts.items():
                entry = {"lines": n}
                if u in new_hashes:
                    entry["hash"] = new_hashes[u]
                sig_out[u] = entry
            with open(self._sig_file, 'w') as f:
                json.dump(sig_out, f)
        except Exception as e:
            print(f"[!] save signature error: {e}", flush=True)

        self._list_line_counts = new_counts
        return changed

    # ── refresh thread ─────────────────────────────────────
    _last_download_changed = True

    def _get_next_interval(self):
        try:
            if os.path.exists(self._sig_file):
                raw = json.load(open(self._sig_file))
                if isinstance(raw, dict) and 'meta' in raw:
                    streak     = raw.get('meta', {}).get('streak_unchanged', 0)
                    streak_max = getattr(Config, 'PROXY_STREAK_MAX', 4)
                    if streak >= streak_max:
                        return Config.PROXY_REFRESH_MAX
                    elif streak == 0:
                        return Config.PROXY_REFRESH_MIN
                    frac = streak / streak_max
                    return int(Config.PROXY_REFRESH_MIN +
                               (Config.PROXY_REFRESH_MAX - Config.PROXY_REFRESH_MIN) * frac)
        except Exception:
            pass
        return Config.PROXY_REFRESH_DEFAULT

    def refresh_proxies(self):
        while self.running:
            interval     = self._get_next_interval()
            interval_min = interval // 60
            time.sleep(interval)
            print(f"\n[*] Refreshing proxy list (interval {interval_min}m, adaptive)...",
                  flush=True)
            self.download_proxies()
            changed = self._last_download_changed
            if changed:
                print(f"[i] list BERUBAH — interval berikutnya turun ke "
                      f"{Config.PROXY_REFRESH_MIN//60}m")
            else:
                print("[i] list TIDAK berubah — interval berikutnya naik (adaptive)")

            # Cap proxy_stats
            if len(self.proxy_stats) > Config.PROXY_STATS_MAX:
                with self.lock:
                    snapshot_items = list(self.proxy_stats.items())
                    active = set(self.proxy_list)
                def sort_key(item):
                    p, s = item
                    return (0 if p in active else 1, s.get('last_used', 0))
                sorted_proxies = sorted(snapshot_items, key=sort_key)
                to_remove = [p for p, _ in
                             sorted_proxies[:len(snapshot_items) - Config.PROXY_STATS_MAX]]
                with self.lock:
                    for proxy in to_remove:
                        self.proxy_stats.pop(proxy, None)

            print(f"[+] Proxy refreshed: {len(self.socks5_proxies)} SOCKS5, "
                  f"{len(self.http_proxies)} HTTP")

    def start_auto_refresh(self):
        self.download_proxies()
        t = threading.Thread(target=self.refresh_proxies, daemon=True)
        t.start()

    # ── throttled cache save ───────────────────────────────
    _last_cache_save         = 0
    _CACHE_SAVE_MIN_INTERVAL = 60
    _cache_save_dirty        = False

    def _cache_save_outside_lock(self):
        now = time.time()
        if (not self._cache_save_dirty or
                now - self._last_cache_save < self._CACHE_SAVE_MIN_INTERVAL):
            return
        self._last_cache_save    = now
        self._cache_save_dirty   = False
        self._cache_save()

    # ── stats update ───────────────────────────────────────
    def update_stats(self, proxy, success, response_time=None):
        with self.lock:
            if proxy not in self.proxy_stats:
                self.proxy_stats[proxy] = {
                    'success': 0, 'fail': 0, 'total_time': 0,
                    'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
                    'proxy_type': 'socks5' if proxy in self.socks5_proxies else 'http',
                    'consec_fail': 0, 'last_fail_time': 0
                }
            stats = self.proxy_stats[proxy]
            stats['last_used'] = time.time()

            if success:
                stats['success']     += 1
                stats['consec_fail']  = 0
                if stats['success'] == 1:
                    self.premium_pool.add(proxy)
                    self._cache_save_dirty = True
                if response_time:
                    total = stats['total_time'] + response_time
                    count = stats['success'] + stats['fail']
                    stats['avg_time']   = total / count if count > 0 else response_time
                    stats['total_time'] = total
                if stats['proxy_type'] == 'socks5':
                    stats['weight'] *= 1.1
            else:
                stats['fail']          += 1
                stats['consec_fail']   += 1
                stats['last_fail_time'] = time.time()
                stats['weight'] *= 0.8 if stats['proxy_type'] == 'socks5' else 0.5

            total_reqs = stats['success'] + stats['fail']
            if total_reqs > 0:
                success_rate = stats['success'] / total_reqs
                speed_score  = min(1.0 / stats['avg_time'] if stats['avg_time'] > 0 else 1.0,
                                   2.0)
                weight = (success_rate * 0.6 + speed_score * 0.4) * 2
                stats['weight'] = max(self.min_weight, min(self.max_weight, weight))
                if stats['proxy_type'] == 'socks5':
                    stats['weight'] = min(self.max_weight, stats['weight'] * 1.2)

        self._cache_save_outside_lock()

    # ── proxy selection ────────────────────────────────────
    def get_proxy(self, prefer_socks5=True):
        with self.lock:
            if not self.proxy_list:
                return None
            if prefer_socks5 and self.socks5_proxies:
                if random.random() < self.socks5_priority:
                    socks5_ws = [p for p in self.socks5_proxies if p in self.proxy_stats]
                    if socks5_ws:
                        tw = sum(self.proxy_stats[p]['weight'] for p in socks5_ws)
                        if tw > 0:
                            r = random.uniform(0, tw)
                            cum = 0
                            for p in socks5_ws:
                                cum += self.proxy_stats[p]['weight']
                                if r <= cum:
                                    return {"http": p, "https": p}
                    proxy = random.choice(self.socks5_proxies)
                    return {"http": proxy, "https": proxy}
            http_ws = [p for p in self.http_proxies if p in self.proxy_stats]
            if http_ws:
                tw = sum(self.proxy_stats[p]['weight'] for p in http_ws)
                if tw > 0:
                    r = random.uniform(0, tw)
                    cum = 0
                    for p in http_ws:
                        cum += self.proxy_stats[p]['weight']
                        if r <= cum:
                            return {"http": p, "https": p}
            if self.proxy_list:
                proxy = random.choice(self.proxy_list)
                return {"http": proxy, "https": proxy}
            return None

    def get_different_proxy(self, last_proxy=None):
        with self.lock:
            if not self.proxy_list:
                return None
            available = [p for p in self.proxy_list if p != last_proxy]
            if not available:
                available = self.proxy_list
            socks5_av = [p for p in available if p in self.socks5_proxies]
            if socks5_av and random.random() < self.socks5_priority:
                proxy = random.choice(socks5_av)
                return {"http": proxy, "https": proxy}
            proxy = random.choice(available)
            return {"http": proxy, "https": proxy}

    DEAD_PROXY_THRESHOLD = 5
    DEAD_PROXY_EXPIRY    = 600
    ON_SCAN_CAP          = 150

    def get_proxy_for_retry(self, retry_count, last_proxy=None, avoid_set=None):
        with self.lock:
            if not self.proxy_list and not self.proxy_stats:
                return None

            avoid = set(avoid_set or [])
            if last_proxy:
                avoid.add(last_proxy)
            now = time.time()

            def is_non_dead(p):
                s      = self.proxy_stats.get(p, {})
                consec = s.get('consec_fail', 0)
                lf     = s.get('last_fail_time', 0)
                return (consec < self.DEAD_PROXY_THRESHOLD or
                        (lf and now - lf >= self.TIER3_RECOVERY_WINDOW))

            # [FIX-8] Untuk retry tinggi, prioritaskan premium_pool dulu.
            # Setelah proxy refresh, list baru belum teruji (success=0).
            # Premium_pool = proxy lama yang terbukti berhasil ke hackertarget.
            if retry_count >= 3 and self.premium_pool:
                premium_alive = [p for p in self.premium_pool
                                 if p not in avoid and is_non_dead(p)]
                if premium_alive:
                    socks5_prem = [p for p in premium_alive if 'socks5' in p]
                    candidates  = socks5_prem if socks5_prem else premium_alive
                    proxy = random.choice(candidates)
                    return {"http": proxy, "https": proxy}

            # Tier 1: proxy aktif TheSpeedX
            scan_pool = self.proxy_list
            if len(scan_pool) > self.ON_SCAN_CAP:
                scan_pool = random.sample(scan_pool, self.ON_SCAN_CAP)
            t1 = [p for p in scan_pool if p not in avoid and is_non_dead(p)]
            t1_total = sum(1 for p in self.proxy_list if is_non_dead(p))

            if t1_total >= Config.PROXY_MIN_T1_ALIVE:
                if t1:
                    if retry_count < 2:
                        socks5_alive = [p for p in t1 if p in self.socks5_proxies]
                        if socks5_alive:
                            return {"http": random.choice(socks5_alive),
                                    "https": random.choice(socks5_alive)}
                    proxy = random.choice(t1)
                    return {"http": proxy, "https": proxy}

            # Tier 3: last-known-good
            t3 = [p for p in self.proxy_stats
                  if p not in avoid and is_non_dead(p)
                  and self.proxy_stats[p].get('success', 0) > 0]
            if not t3:
                t3 = [p for p in (self.proxy_list +
                                   [p for p in self.proxy_stats if p not in self.proxy_list])
                      if p not in avoid]
            if t3:
                proxy = random.choice(t3)
                return {"http": proxy, "https": proxy}
            return None

    def get_alive_proxies(self):
        with self.lock:
            now = time.time()
            def is_non_dead(p):
                s = self.proxy_stats.get(p, {})
                return (s.get('consec_fail', 0) < self.DEAD_PROXY_THRESHOLD or
                        (s.get('last_fail_time', 0) and
                         now - s['last_fail_time'] >= self.TIER3_RECOVERY_WINDOW))
            result = [p for p in self.proxy_list if is_non_dead(p)]
            active_set = set(self.proxy_list)
            result += [p for p, s in self.proxy_stats.items()
                       if p not in active_set and s.get('success', 0) > 0
                       and is_non_dead(p)]
            return result

    def print_stats(self):
        print("\n" + "="*60)
        print("PROXY STATISTICS (Top 10)")
        print("="*60)
        print(f"📡 SOCKS5: {len(self.socks5_proxies)} | HTTP: {len(self.http_proxies)} "
              f"| Premium: {len(self.premium_pool)}")
        print("-"*60)
        with self.lock:
            sorted_proxies = sorted(
                [(p, s) for p, s in self.proxy_stats.items() if p in self.proxy_list],
                key=lambda x: x[1]['weight'], reverse=True)[:10]
            for proxy, stats in sorted_proxies:
                total = stats['success'] + stats['fail']
                if total > 0:
                    sr   = (stats['success'] / total) * 100
                    icon = "🔒" if stats['proxy_type'] == 'socks5' else "🌐"
                    prem = " ⭐" if proxy in self.premium_pool else ""
                    print(f"{icon}{prem} {proxy[:60]}")
                    print(f"  ✅ {stats['success']} | ❌ {stats['fail']} | "
                          f"📊 {sr:.1f}% | ⚖️ {stats['weight']:.2f}")

    # [FIX-4] stop() TUNGGAL — sebelumnya ada dua definisi, yang kedua
    # override yang pertama sehingga _cache_save() tidak pernah dipanggil.
    def stop(self):
        """Simpan cache + hentikan thread auto-refresh."""
        self.running = False
        try:
            self._cache_save()
        except Exception as e:
            print(f"[!] stop: cache save error: {e}")
        self.cleanup()

    def cleanup(self):
        self.running = False

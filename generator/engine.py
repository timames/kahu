"""The engine: runs the baseline loop and plays scenarios on demand."""
import logging
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional
from zoneinfo import ZoneInfo

from .config import cfg
from .emitters import counters
from .scenarios import SCENARIOS, baseline_tick, business_hours_factor

log = logging.getLogger("engine")


class Engine:
    def __init__(self) -> None:
        self._baseline_on = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._tz = ZoneInfo(cfg.TIMEZONE)
        self._running: Dict[str, dict] = {}
        self._history: List[dict] = []
        self._lock = threading.Lock()

    # -- baseline ---------------------------------------------------------
    def start_baseline(self) -> None:
        if self._baseline_on:
            return
        self._baseline_on = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        log.info("baseline started")

    def stop_baseline(self) -> None:
        self._baseline_on = False
        self._stop.set()
        log.info("baseline stopped")

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = datetime.now(self._tz)
            factor = business_hours_factor(now)
            # events per second = 6 * intensity * diurnal factor
            eps = max(0.2, 6.0 * cfg.INTENSITY * factor)
            for _ in range(int(eps)):
                baseline_tick()
            time.sleep(1.0)

    # -- scenarios --------------------------------------------------------
    def fire(self, name: str) -> dict:
        if name not in SCENARIOS:
            raise KeyError(name)
        with self._lock:
            if name in self._running:
                return {"status": "already_running", "scenario": name}
            self._running[name] = {"started": time.time()}
        t = threading.Thread(target=self._play, args=(name,), daemon=True)
        t.start()
        return {"status": "started", "scenario": name,
                "title": SCENARIOS[name]["title"]}

    def _play(self, name: str) -> None:
        meta = SCENARIOS[name]
        started = time.time()
        steps = 0
        log.info("scenario %s starting", name)
        try:
            for delay, action in meta["fn"]():
                if delay:
                    time.sleep(delay)
                try:
                    action()
                except Exception as exc:  # noqa: BLE001
                    log.warning("step failed in %s: %s", name, exc)
                steps += 1
        except Exception as exc:  # noqa: BLE001
            log.error("scenario %s failed: %s", name, exc)
        finally:
            with self._lock:
                self._running.pop(name, None)
                self._history.insert(0, {
                    "scenario": name,
                    "title": meta["title"],
                    "steps": steps,
                    "seconds": round(time.time() - started, 1),
                    "at": datetime.now(self._tz).strftime("%H:%M:%S"),
                })
                self._history = self._history[:20]
            log.info("scenario %s done (%d steps)", name, steps)

    # -- status -----------------------------------------------------------
    def status(self) -> dict:
        now = datetime.now(self._tz)
        with self._lock:
            running = list(self._running.keys())
            history = list(self._history)
        return {
            "baseline": self._baseline_on,
            "intensity": cfg.INTENSITY,
            "local_time": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "activity_factor": round(business_hours_factor(now), 2),
            "target": cfg.TARGET_HOST,
            "dry_run": cfg.DRY_RUN,
            "sent": counters(),
            "running": running,
            "history": history,
        }


engine = Engine()

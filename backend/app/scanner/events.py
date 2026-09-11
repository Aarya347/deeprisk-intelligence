from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List


class ScanEventManager:
    def __init__(self):
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._listeners: Dict[str, List[asyncio.Queue]] = {}

    def start_job(self, job_id: str, title: str, total_steps: int = 1) -> None:
        self._jobs[job_id] = {
            "id": job_id,
            "title": title,
            "status": "running",
            "progress": 0,
            "total_steps": total_steps,
            "current_step": 0,
            "current_repo": "",
            "phase": "initializing",
            "message": f"Starting {title}...",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "events": [],
        }
        self.emit(job_id, {
            "type": "job_start",
            "message": f"Started {title}",
            "percent": 0,
        })

    def emit(self, job_id: str, event_data: dict[str, Any]) -> None:
        if job_id not in self._jobs:
            self._jobs[job_id] = {
                "id": job_id,
                "title": "Scan Job",
                "status": "running",
                "progress": 0,
                "total_steps": 1,
                "current_step": 0,
                "current_repo": "",
                "phase": "running",
                "message": "",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "events": [],
            }

        job = self._jobs[job_id]
        event = {
            "timestamp": time.time(),
            "time_iso": datetime.now(timezone.utc).isoformat(),
            **event_data,
        }

        # Update job state from event
        if "percent" in event:
            job["progress"] = event["percent"]
        if "message" in event:
            job["message"] = event["message"]
        if "phase" in event:
            job["phase"] = event["phase"]
        if "repo" in event:
            job["current_repo"] = event["repo"]
        if "status" in event:
            job["status"] = event["status"]
            if event["status"] in ("completed", "failed"):
                job["finished_at"] = event["time_iso"]

        job["events"].append(event)
        # Keep last 200 events per job
        if len(job["events"]) > 200:
            job["events"] = job["events"][-200:]

        # Broadcast to active SSE listeners
        listeners = self._listeners.get(job_id, [])
        for q in list(listeners):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self._jobs.get(job_id)

    async def subscribe(self, job_id: str) -> AsyncGenerator[str, None]:
        queue: asyncio.Queue = asyncio.Queue()
        if job_id not in self._listeners:
            self._listeners[job_id] = []
        self._listeners[job_id].append(queue)

        try:
            # Replay historical events to catch up
            if job_id in self._jobs:
                job = self._jobs[job_id]
                for past_event in job.get("events", []):
                    yield f"data: {json.dumps(past_event)}\n\n"

                if job.get("status") in ("completed", "failed"):
                    return

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("type") in ("job_completed", "job_failed") or event.get("status") in ("completed", "failed"):
                        break
                except asyncio.TimeoutError:
                    # Send keep-alive comment
                    yield ": ping\n\n"
                    if job_id in self._jobs and self._jobs[job_id].get("status") in ("completed", "failed"):
                        break
        finally:
            if job_id in self._listeners and queue in self._listeners[job_id]:
                self._listeners[job_id].remove(queue)
                if not self._listeners[job_id]:
                    del self._listeners[job_id]


scan_events = ScanEventManager()

import io
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

from app.scanner.events import ScanEventManager
from app.scanner.local import _find_manifest_files, scan_local_path, scan_uploaded_zip


def test_find_manifest_files(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.17.1"}}')
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests==2.25.1\n")
    ignored = tmp_path / "node_modules" / "foo"
    ignored.mkdir(parents=True)
    (ignored / "package.json").write_text("{}")

    manifests = _find_manifest_files(tmp_path)
    names = [m.name for m in manifests]
    assert "package.json" in names
    assert "requirements.txt" in names
    # node_modules should be ignored
    assert len(manifests) == 2


def test_scan_events_lifecycle():
    mgr = ScanEventManager()
    job_id = "test-job-1"
    mgr.start_job(job_id, "Test Scan", total_steps=3)
    job = mgr.get_job(job_id)
    assert job is not None
    assert job["status"] == "running"
    assert len(job["events"]) == 1

    mgr.emit(job_id, {"type": "progress", "percent": 50, "message": "halfway"})
    assert job["progress"] == 50

    mgr.emit(job_id, {"type": "job_completed", "status": "completed", "percent": 100, "message": "done"})
    assert job["status"] == "completed"
    assert job["progress"] == 100

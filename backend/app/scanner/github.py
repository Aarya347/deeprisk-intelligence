from __future__ import annotations

import base64
import time

import httpx


class GitHubClient:
    def __init__(self, token: str):
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def _get(self, url: str, **kwargs) -> httpx.Response:
        for _ in range(3):
            r = self._client.get(url, **kwargs)
            if r.status_code in (403, 429) and r.headers.get("Retry-After"):
                time.sleep(int(r.headers["Retry-After"]) + 1)
                continue
            r.raise_for_status()
            return r
        r.raise_for_status()
        return r

    def list_org_repos(self, org: str) -> list[dict]:
        endpoint = f"/orgs/{org}/repos"
        try:
            r = self._get(endpoint, params={"per_page": 100, "page": 1})
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                endpoint = f"/users/{org}/repos"
                r = self._get(endpoint, params={"per_page": 100, "page": 1})
            else:
                raise

        repos = r.json()
        if not repos or len(repos) < 100:
            return repos or []

        page = 2
        while page <= 10:  # hard cap: 1000 repos for v1
            r = self._get(endpoint, params={"per_page": 100, "page": page})
            batch = r.json()
            if not batch:
                break
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return repos

    def tree_paths(self, full_name: str, branch: str) -> tuple[list[str], bool]:
        """All blob paths in the repo (recursive), plus the truncation flag."""
        r = self._get(f"/repos/{full_name}/git/trees/{branch}", params={"recursive": "1"})
        data = r.json()
        paths = [e["path"] for e in data.get("tree", []) if e.get("type") == "blob"]
        return paths, bool(data.get("truncated"))

    def get_text_file(self, full_name: str, path: str, ref: str) -> str | None:
        r = self._get(f"/repos/{full_name}/contents/{path}", params={"ref": ref})
        j = r.json()
        if j.get("encoding") == "base64" and j.get("content"):
            return base64.b64decode(j["content"]).decode("utf-8", errors="replace")
        return None  # files >1MB come back without inline content

    def download_tarball(self, full_name: str, branch: str, dest: str) -> None:
        with self._client.stream("GET", f"https://codeload.github.com/{full_name}/tar.gz/refs/heads/{branch}") as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_bytes(1 << 16):
                    f.write(chunk)

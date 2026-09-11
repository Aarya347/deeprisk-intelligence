from unittest.mock import MagicMock, patch
import httpx
import pytest

from app.scanner.github import GitHubClient


def test_list_org_repos_success():
    client = GitHubClient(token="fake-token")
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"id": 1, "name": "repo1"}]

    with patch.object(client, "_get", return_value=mock_resp) as mock_get:
        repos = client.list_org_repos("test-org")
        assert len(repos) == 1
        assert repos[0]["name"] == "repo1"
        mock_get.assert_called_once_with("/orgs/test-org/repos", params={"per_page": 100, "page": 1})


def test_list_org_repos_fallback_to_users():
    client = GitHubClient(token="fake-token")
    req = httpx.Request("GET", "https://api.github.com/orgs/personal-user/repos")
    resp_404 = httpx.Response(404, request=req)
    error_404 = httpx.HTTPStatusError(message="404 Not Found", request=req, response=resp_404)

    mock_resp_user = MagicMock(spec=httpx.Response)
    mock_resp_user.status_code = 200
    mock_resp_user.json.return_value = [{"id": 2, "name": "user-repo"}]

    def mock_get_impl(url, **kwargs):
        if url.startswith("/orgs/"):
            raise error_404
        return mock_resp_user

    with patch.object(client, "_get", side_effect=mock_get_impl) as mock_get:
        repos = client.list_org_repos("personal-user")
        assert len(repos) == 1
        assert repos[0]["name"] == "user-repo"
        assert mock_get.call_count == 2
        mock_get.assert_any_call("/orgs/personal-user/repos", params={"per_page": 100, "page": 1})
        mock_get.assert_any_call("/users/personal-user/repos", params={"per_page": 100, "page": 1})


def test_list_org_repos_other_error_raises():
    client = GitHubClient(token="fake-token")
    req = httpx.Request("GET", "https://api.github.com/orgs/some-org/repos")
    resp_500 = httpx.Response(500, request=req)
    error_500 = httpx.HTTPStatusError(message="500 Internal Server Error", request=req, response=resp_500)

    with patch.object(client, "_get", side_effect=error_500):
        with pytest.raises(httpx.HTTPStatusError):
            client.list_org_repos("some-org")

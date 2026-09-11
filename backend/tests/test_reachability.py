from app.reachability.python_ast import assess_python_dependency, build_import_index

def test_detects_import(tmp_path):
    (tmp_path / "svc.py").write_text("import requests\n\nimport os\n")
    (tmp_path / "other.py").write_text("from bs4 import BeautifulSoup\n")
    index = build_import_index(tmp_path)
    assert assess_python_dependency("requests", index).reachable
    assert assess_python_dependency("beautifulsoup4", index).reachable   # alias map
    assert not assess_python_dependency("never-imported-pkg", index).reachable

import os
import subprocess
import re
from pathlib import Path

base = Path(os.environ["LOCALAPPDATA"]) / "pgsql_depdash"
conf = base / "data" / "postgresql.conf"
if conf.exists():
    text = conf.read_text(encoding="utf-8")
    text = re.sub(r"#?\s*listen_addresses\s*=.*", "listen_addresses = '*'", text)
    text = re.sub(r"#?\s*port\s*=.*", "port = 5432", text)
    conf.write_text(text, encoding="utf-8")

pg_ctl = str(base / "pgsql" / "bin" / "pg_ctl.exe")
data = str(base / "data")
log = str(base / "postgres.log")

subprocess.run([pg_ctl, "-D", data, "stop", "-m", "fast"])
subprocess.run([pg_ctl, "-D", data, "-l", log, "start"], check=True)
print("PostgreSQL started on port 5432")

import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

PG_VERSION = "15.8-1"
PG_URL = f"https://get.enterprisedb.com/postgresql/postgresql-{PG_VERSION}-windows-x64-binaries.zip"
BASE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "pgsql_depdash"
PG_ZIP = BASE_DIR / "pgsql.zip"
PG_EXTRACTED = BASE_DIR / "pgsql"
PG_DATA = BASE_DIR / "data"
PG_BIN = PG_EXTRACTED / "bin"
PG_LOG = BASE_DIR / "postgres.log"

def setup_postgres():
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    if not (PG_BIN / "postgres.exe").exists():
        if not PG_ZIP.exists():
            print(f"Downloading PostgreSQL {PG_VERSION}...")
            urllib.request.urlretrieve(PG_URL, PG_ZIP)
            print("Download complete.")
        
        print("Extracting PostgreSQL binaries...")
        with zipfile.ZipFile(PG_ZIP, 'r') as zip_ref:
            zip_ref.extractall(BASE_DIR)
        print("Extraction complete.")
        if PG_ZIP.exists():
            PG_ZIP.unlink()

    # Check if data directory exists
    if not (PG_DATA / "PG_VERSION").exists():
        print("Initializing PostgreSQL database cluster...")
        initdb = str(PG_BIN / "initdb.exe")
        cmd = [initdb, "-D", str(PG_DATA), "-U", "depdash", "-A", "trust", "-E", "UTF8"]
        subprocess.run(cmd, check=True)
        print("Database cluster initialized.")

    # Check if postgres is running
    pg_ctl = str(PG_BIN / "pg_ctl.exe")
    status_cmd = [pg_ctl, "-D", str(PG_DATA), "status"]
    status_res = subprocess.run(status_cmd, capture_output=True, text=True)
    if "is running" not in status_res.stdout:
        print("Starting PostgreSQL server on port 5432...")
        start_cmd = [pg_ctl, "-D", str(PG_DATA), "-l", str(PG_LOG), "-o", "-p 5432", "start"]
        subprocess.run(start_cmd, check=True)
        print("PostgreSQL server started.")
    else:
        print("PostgreSQL server is already running.")

    # Create database depdash if not exists
    createdb = str(PG_BIN / "createdb.exe")
    create_cmd = [createdb, "-h", "localhost", "-p", "5432", "-U", "depdash", "depdash"]
    res = subprocess.run(create_cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print("Database 'depdash' created.")
    elif "already exists" in res.stderr:
        print("Database 'depdash' already exists.")
    else:
        print(f"createdb info: {res.stdout} {res.stderr}")

    print("PostgreSQL setup and running successfully!")

if __name__ == "__main__":
    setup_postgres()

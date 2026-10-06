"""One-time backfill: load existing logs/*.json results into findings.db."""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import database


def main():
    conn = database.connect()
    count = 0
    for path in sorted(glob.glob("logs/*.json")):
        with open(path, encoding="utf-8") as f:
            result = json.load(f)
        database.insert_finding(conn, result)
        count += 1
    conn.close()
    print(f"Imported {count} finding(s) into {database.DB_PATH}")


if __name__ == "__main__":
    main()

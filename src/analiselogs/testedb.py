import pathlib
import sqlite3

DB = pathlib.Path(__file__).resolve().parent / "events.db"


def show_last(limit: int = 5) -> None:
    conn = sqlite3.connect(DB)
    try:
        cur = conn.execute(
            "SELECT timestamp, src, country, proto, dpt FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        for row in cur.fetchall():
            print(row)
    finally:
        conn.close()


if __name__ == "__main__":
    show_last()

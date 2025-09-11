from db import get_connection

TABLES = [
    "dispense_logs",
    "doctors",
    "medicines",
    "patients",
    "pharmacists",
    "prescription_items",
    "prescriptions",
    "stock",
]

def main():
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        for t in TABLES:
            print(f"\n== {t} ==")
            cur.execute(
                """
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA
                FROM information_schema.columns
                WHERE table_schema = DATABASE() AND table_name = %s
                ORDER BY ORDINAL_POSITION
                """,
                [t],
            )
            rows = cur.fetchall()
            if not rows:
                print("(table not found)")
                continue
            for r in rows:
                print(f"{r['COLUMN_NAME']:20s} {r['DATA_TYPE']:12s} NULLABLE={r['IS_NULLABLE']} KEY={r['COLUMN_KEY']} DEFAULT={r['COLUMN_DEFAULT']} EXTRA={r['EXTRA']}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()

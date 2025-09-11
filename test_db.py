from app_clean import get_db_connection, DB_CONFIG
import traceback

print('Attempting DB connection to', DB_CONFIG['host'], DB_CONFIG['database'])
try:
    conn = get_db_connection()
    print('Connected OK')
    cur = conn.cursor()
    cur.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=%s', (DB_CONFIG['database'],))
    rows = cur.fetchall()
    print('Tables:', rows)
    if not rows:
        print('No tables found or insufficient privileges.')
except Exception as e:
    print('ERROR:', e)
    traceback.print_exc()


import os
import random
import string
import socket
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import logging

try:
    import pymysql  # Using PyMySQL for MySQL connectivity
except ImportError:  # Allow app to start even if dependency missing before install
    pymysql = None

try:
    import bcrypt  # optional password hashing support
except ImportError:
    bcrypt = None

# --- Configuration ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")  # Replace in production

# Provided CA certificate path (can be overridden with RX_DB_SSL_CA)
DEFAULT_CA_PATH = r"C:\\Users\\sabbu\\Downloads\\ca-certificate.crt"
CERT_PATH = os.environ.get("RX_DB_SSL_CA", DEFAULT_CA_PATH)

DB_CONFIG = {
    "host": os.environ.get("RX_DB_HOST", "rxpress-do-user-25725432-0.h.db.ondigitalocean.com"),
    "port": int(os.environ.get("RX_DB_PORT", 25060)),
    "user": os.environ.get("RX_DB_USER", "doadmin"),
    "password": os.environ.get("RX_DB_PASSWORD", "AVNS_fk8SEJocOJDM4hgVSaA"),
    "database": os.environ.get("RX_DB_NAME", "rxpress"),
    "cursorclass": None,
    # ssl will be set below after checking CA file
    "ssl": None,
    "connect_timeout": 5,
}

if os.path.exists(CERT_PATH):
    DB_CONFIG['ssl'] = {"ca": CERT_PATH}
else:
    # Fallback: attempt system trust store (PyMySQL accepts empty dict). Log a warning.
    DB_CONFIG['ssl'] = {"ssl": {}}
    app.logger.warning(f"CA certificate not found at {CERT_PATH}. Using generic SSL context. Set RX_DB_SSL_CA env var if needed.")

# In-memory OTP store: key -> {otp, expires}
OTP_STORE: Dict[str, Dict[str, Any]] = {}
OTP_TTL_SECONDS = 300  # 5 minutes


# --- Database Utilities ---
def _tcp_connect(host: str, port: int, timeout: float = 3.0):
    result = {"host": host, "port": port, "dns_ip": None, "tcp_connected": False, "tcp_error": None, "elapsed_ms": None}
    start = time.time()
    try:
        result['dns_ip'] = socket.gethostbyname(host)
    except Exception as e:
        result['tcp_error'] = f"DNS resolve failed: {e}"
        return result
    try:
        with socket.create_connection((result['dns_ip'], port), timeout=timeout):
            result['tcp_connected'] = True
    except Exception as e:
        result['tcp_error'] = f"TCP connect failed: {e}";
    result['elapsed_ms'] = round((time.time()-start)*1000,2)
    return result


def get_db_connection():
    """Create a new database connection. Caller must close."""
    if pymysql is None:
        raise RuntimeError("PyMySQL not installed. Run: pip install PyMySQL")
    start = time.time()
    try:
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
            ssl=DB_CONFIG['ssl'],
            connect_timeout=DB_CONFIG.get('connect_timeout', 5),
            read_timeout=6,
            write_timeout=6
        )
    except Exception as e:
        raise RuntimeError(f"MySQL connect error: {e.__class__.__name__}: {e}")
    app.logger.debug(f"DB connection established in {round((time.time()-start)*1000,2)} ms")
    return conn


def fetch_one(query: str, params: tuple) -> Optional[dict]:
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()
    except Exception as e:
        app.logger.warning(f"DB fetch_one error: {e}")
        return None


# --- OTP Helpers ---
def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def store_otp(key: str, otp: str):
    OTP_STORE[key] = {"otp": otp, "expires": time.time() + OTP_TTL_SECONDS}


def validate_otp(key: str, otp: str) -> bool:
    record = OTP_STORE.get(key)
    if not record:
        return False
    if time.time() > record['expires']:
        del OTP_STORE[key]
        return False
    if record['otp'] != otp:
        return False
    # One-time use
    del OTP_STORE[key]
    return True


# --- Utility: attempt to find a record using multiple possible column names ---
def _map_primary_id(row: dict):
    if row is None:
        return row
    if 'id' not in row:
        for k in ('patient_id','doctor_id','pharmacist_id','user_id'):
            if k in row:
                row['id'] = row[k]
                break
    return row

# Updated multi_fetch to use SELECT * (handles tables without a generic 'id' column)
def multi_fetch(table: str, id_value: str, candidate_cols: list, select_extra: str = ''):
    for col in candidate_cols:
        query = f"SELECT * FROM `{table}` WHERE `{col}`=%s LIMIT 1"
        row = fetch_one(query, (id_value,))
        if row:
            _map_primary_id(row)
            row['_identifier'] = row.get(col)
            row['_matched_column'] = col
            return row, col
    return None, None

# Updated dynamic_identifier_search to also SELECT *
def dynamic_identifier_search(table: str, id_value: str, tried: set):
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema=%s AND table_name=%s
            """, (DB_CONFIG['database'], table))
            columns = cur.fetchall() or []
            for c in columns:
                col = c['column_name']
                if col in tried:
                    continue
                if c['data_type'].lower() not in ('varchar','char','text'):
                    continue
                # Exact match
                try:
                    cur.execute(f"SELECT * FROM `{table}` WHERE `{col}`=%s LIMIT 1", (id_value,))
                    row = cur.fetchone()
                    if row:
                        _map_primary_id(row)
                        row['_identifier'] = row.get(col)
                        row['_matched_column'] = col
                        return row, col
                except Exception:
                    pass
                # Normalized numeric variant
                if id_value.isdigit():
                    try:
                        cur.execute(
                            f"SELECT * FROM `{table}` WHERE REPLACE(REPLACE(REPLACE({col},' ',''),'-',''),'/','')=%s LIMIT 1",
                            (id_value,)
                        )
                        row = cur.fetchone()
                        if row:
                            _map_primary_id(row)
                            row['_identifier'] = row.get(col)
                            row['_matched_column'] = col
                            return row, col
                    except Exception:
                        pass
    except Exception as e:
        app.logger.warning(f"dynamic_identifier_search error on {table}: {e}")
    return None, None


# Password field detection helper (added to fix NameError for doctor login)
PASSWORD_FIELD_CANDIDATES = ['password', 'passwd', 'pass', 'password_hash', 'hash', 'pwd']

def _extract_password(row: dict):
    if not row:
        return None, None
    for fld in PASSWORD_FIELD_CANDIDATES:
        if fld in row and row[fld] not in (None, ''):
            return row[fld], fld
    return None, None


# --- Routes ---
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    user_type = request.form.get('user_type')  # doctors | patients | pharmacists (aligns with template values)
    identifier = request.form.get('username', '').strip()
    secret = request.form.get('password_or_otp', '').strip()

    if not user_type or not identifier or not secret:
        flash('All fields are required', 'error')
        return redirect(url_for('login'))

    try:
        if user_type == 'doctors':
            doctor_cols = ['registration_number', 'reg_number', 'reg_no', 'regid', 'reg_id', 'registration_no']
            row, matched = multi_fetch('doctors', identifier, doctor_cols)
            if not row:
                row, matched = dynamic_identifier_search('doctors', identifier, set(doctor_cols))
            if not row:
                flash('Doctor not found (checked + fallback).', 'error')
                return redirect(url_for('login'))
            stored_pw, pw_field = _extract_password(row)
            if stored_pw is None:
                flash('Doctor password field missing', 'error')
                return redirect(url_for('login'))
            password_ok = False
            if isinstance(stored_pw, (str, bytes)):
                if stored_pw == secret:
                    password_ok = True
                elif bcrypt and str(stored_pw).startswith(('$2a$', '$2b$')):
                    try:
                        password_ok = bcrypt.checkpw(secret.encode(), stored_pw.encode() if isinstance(stored_pw, str) else stored_pw)
                    except Exception:
                        password_ok = False
            if not password_ok:
                flash('Invalid password', 'error')
                return redirect(url_for('login'))
            session['user_id'] = row['id']
            session['user_name'] = row.get('name') or row.get('_identifier')
            session['user_type'] = 'doctor'
            session['identifier_column'] = matched
            session['password_field'] = pw_field
            flash(f'Login successful (matched column: {matched})', 'success')
            return redirect(url_for('doctor_dashboard'))

        elif user_type == 'patients':
            patient_cols = ['aadhaar', 'aadhar', 'aadhaar_number', 'aadhar_number', 'aadhaar_no']
            if len(identifier) not in (12,):  # typical Aadhaar length
                flash('Aadhaar must be 12 digits', 'error')
                return redirect(url_for('login'))
            row, matched = multi_fetch('patients', identifier, patient_cols)
            if not row:
                # dynamic fallback
                row, matched = dynamic_identifier_search('patients', identifier, set(patient_cols))
            if not row:
                flash('Patient not found (checked + fallback).', 'error')
                return redirect(url_for('login'))
            key = f"patient:{identifier}"
            if not validate_otp(key, secret):
                flash('Invalid or expired OTP', 'error')
                return redirect(url_for('login'))
            session['user_id'] = row['id']
            session['user_name'] = row.get('name') or row.get('_identifier')
            session['user_type'] = 'patient'
            session['identifier_column'] = matched
            flash(f'Login successful (matched column: {matched})', 'success')
            return redirect(url_for('patient_dashboard'))

        elif user_type == 'pharmacists':
            pharm_cols = ['license_number', 'license_no', 'license', 'pharmacy_license', 'license_num']
            row, matched = multi_fetch('pharmacists', identifier, pharm_cols, 'pharmacy_name')
            if not row:
                row, matched = dynamic_identifier_search('pharmacists', identifier, set(pharm_cols))
            if not row:
                flash('Pharmacist not found (checked + fallback).', 'error')
                return redirect(url_for('login'))
            key = f"pharmacist:{identifier}"
            if not validate_otp(key, secret):
                flash('Invalid or expired OTP', 'error')
                return redirect(url_for('login'))
            session['user_id'] = row['id']
            session['user_name'] = row.get('name') or row.get('_identifier')
            session['user_type'] = 'pharmacist'
            session['pharmacy_name'] = row.get('pharmacy_name')
            session['identifier_column'] = matched
            flash(f'Login successful (matched column: {matched})', 'success')
            return redirect(url_for('pharmacist_dashboard'))
        else:
            flash('Unknown user type', 'error')
            return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        flash('Authentication error. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/generate_otp', methods=['POST'])
def generate_otp_route():
    user_type = request.form.get('user_type')  # patients | pharmacists
    identifier = (request.form.get('username') or '').strip()

    if user_type not in ('patients', 'pharmacists'):
        return jsonify(success=False, message='OTP only for patients or pharmacists'), 400

    if user_type == 'patients':
        if not identifier.isdigit() or len(identifier) != 12:
            return jsonify(success=False, message='Aadhaar must be exactly 12 digits'), 400
        patient_cols = ['aadhaar', 'aadhar', 'aadhaar_number', 'aadhar_number', 'aadhaar_no']
        row, matched = multi_fetch('patients', identifier, patient_cols)
        if not row:
            row, matched = dynamic_identifier_search('patients', identifier, set(patient_cols))
        if not row:
            return jsonify(success=False, message='Patient not registered (with fallback).'), 404
        key = f"patient:{identifier}"
    else:  # pharmacists
        if not identifier:
            return jsonify(success=False, message='License number required'), 400
        pharm_cols = ['license_number', 'license_no', 'license', 'pharmacy_license', 'license_num']
        row, matched = multi_fetch('pharmacists', identifier, pharm_cols)
        if not row:
            row, matched = dynamic_identifier_search('pharmacists', identifier, set(pharm_cols))
        if not row:
            return jsonify(success=False, message='Pharmacist not registered (with fallback).'), 404
        key = f"pharmacist:{identifier}"

    otp = generate_otp()
    store_otp(key, otp)
    return jsonify(success=True, otp=otp, expires_in=OTP_TTL_SECONDS)


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('home'))


@app.route('/db_status')
def db_status():
    """Diagnostic endpoint: connectivity + sample rows; resilient to key casing / empty schemas."""
    summary = {
        "connected": False,
        "error": None,
        "tables": [],
        "cert_in_use": os.path.exists(CERT_PATH),
        "cert_path": CERT_PATH,
        "actual_database": None,
        "raw_table_name_rows": [],
        "used_fallback_show_tables": False
    }
    try:
        start = time.time()
        with get_db_connection() as conn, conn.cursor() as cur:
            summary['connected'] = True
            summary['connect_ms'] = round((time.time()-start)*1000,2)
            # Current DB name
            try:
                cur.execute("SELECT DATABASE() AS current_db")
                db_row = cur.fetchone() or {}
                key = next((k for k in db_row.keys() if k.lower() == 'current_db'), None)
                if key:
                    summary['actual_database'] = db_row[key]
            except Exception as e_db:
                summary['actual_database'] = f"Error: {e_db}";
            # Try information_schema first
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (DB_CONFIG['database'],))
            name_rows = cur.fetchall() or []
            summary['raw_table_name_rows'] = name_rows
            tables = []
            for r in name_rows:
                key = next((k for k in r.keys() if k.lower() == 'table_name'), None)
                if key:
                    tables.append(r[key])
            # Fallback if empty
            if not tables:
                try:
                    cur.execute("SHOW TABLES")
                    rows = cur.fetchall() or []
                    summary['used_fallback_show_tables'] = True
                    for r in rows:
                        # SHOW TABLES returns single unnamed/alias key per row
                        if isinstance(r, dict):
                            if r:
                                tables.extend(list(r.values()))
                        else:
                            # If library returns tuple
                            if r and r[0]:
                                tables.append(r[0])
                except Exception as e_fb:
                    summary['error'] = summary['error'] or f"FallbackError: {e_fb}"
            # Deduplicate
            tables = list(dict.fromkeys(tables))
            summary['table_count'] = len(tables)
            for t in tables:
                info = {"name": t, "rows": []}
                try:
                    cur.execute(f"SELECT * FROM `{t}` LIMIT 5")
                    rows = cur.fetchall() or []
                    for row in rows:
                        if isinstance(row, dict):
                            for col in list(row.keys()):
                                if col.lower() in ("password", "otp", "secret"):
                                    row[col] = "***MASKED***"
                    info['rows'] = rows
                except Exception as inner_e:
                    info['error'] = str(inner_e)
                summary['tables'].append(info)
    except Exception as e:
        summary['error'] = f"{e.__class__.__name__}: {e}"
    return jsonify(summary)


@app.route('/db_net')
def db_net():
    diag = {"cert_exists": os.path.exists(CERT_PATH), "cert_path": CERT_PATH}
    tcp = _tcp_connect(DB_CONFIG['host'], DB_CONFIG['port'])
    diag['tcp'] = tcp
    if tcp['tcp_connected']:
        # Attempt lightweight MySQL handshake
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 AS ok")
                    diag['mysql'] = {"connected": True, "select1": cur.fetchone()}
        except Exception as e:
            diag['mysql'] = {"connected": False, "error": str(e)}
    else:
        diag['mysql'] = {"connected": False, "error": 'Skipped due to TCP failure'}
    return jsonify(diag)


@app.route('/auth_debug')
def auth_debug():
    """Return sample identifiers to help user know what to input. Mask sensitive fields."""
    info = {"doctors": [], "patients": [], "pharmacists": [], "errors": []}
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            for table, col_candidates, limit in [
                ('doctors', ['registration_number','reg_number','reg_no','regid','reg_id'], 5),
                ('patients', ['aadhaar','aadhar','aadhaar_number','aadhar_number','aadhaar_no'], 5),
                ('pharmacists', ['license_number','license_no','license','pharmacy_license'], 5)
            ]:
                # Find which column exists by checking information_schema
                try:
                    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s", (DB_CONFIG['database'], table))
                    available = {r['column_name'].lower(): r['column_name'] for r in cur.fetchall()}
                    chosen = None
                    for c in col_candidates:
                        if c.lower() in available:
                            chosen = available[c.lower()]
                            break
                    if not chosen:
                        info['errors'].append(f"No identifier column found in {table}")
                        continue
                    cur.execute(f"SELECT id, name, `{chosen}` AS identifier FROM `{table}` LIMIT {limit}")
                    rows = cur.fetchall() or []
                    for r in rows:
                        info[table].append({"id": r['id'], "name": r.get('name'), "identifier": r.get('identifier')})
                except Exception as inner_e:
                    info['errors'].append(f"{table}: {inner_e}")
    except Exception as e:
        info['errors'].append(str(e))
    return jsonify(info)


# Helper: fetch medicines with brand_name for doctor prescription dropdown
def get_medicines():
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            # Try common table names
            table_candidates = ['medicines', 'medicine']
            table_name = None
            for t in table_candidates:
                cur.execute("SHOW TABLES LIKE %s", (t,))
                if cur.fetchone():
                    table_name = t
                    break
            if not table_name:
                return []
            # Inspect columns
            cur.execute(f"SHOW COLUMNS FROM {table_name}")
            cols = [r.get('Field') or r.get('column_name') for r in cur.fetchall() or []]
            if 'brand_name' not in cols:
                return []  # Requirement: use brand_name only
            id_col = 'id'
            if id_col not in cols:
                # fallback possibilities
                for cand in ['medicine_id', 'drug_id']:
                    if cand in cols:
                        id_col = cand
                        break
            if id_col not in cols:
                return []
            cur.execute(f"SELECT `{id_col}` AS id, `brand_name` FROM {table_name} ORDER BY `brand_name`")
            rows = cur.fetchall() or []
            return rows
    except Exception as e:
        app.logger.warning(f"get_medicines error: {e}")
        return []


# --- Minimal dashboard placeholders (can be expanded later) ---
@app.route('/doctor/dashboard')
def doctor_dashboard():
    if session.get('user_type') != 'doctor':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    prescriptions = []
    medicines = get_medicines()
    return render_template('doctor_dashboard.html', prescriptions=prescriptions, medicines=medicines)


@app.route('/patient/dashboard')
def patient_dashboard():
    if session.get('user_type') != 'patient':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    prescriptions = []
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            pass  # TODO: add patient prescriptions query
    except Exception as e:
        app.logger.warning(f"Patient dashboard DB issue: {e}")
    return render_template('patient_dashboard.html', prescriptions=prescriptions)


@app.route('/pharmacist/dashboard')
def pharmacist_dashboard():
    if session.get('user_type') != 'pharmacist':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    pending_prescriptions = []
    stock = []
    reservations = []
    medicines = []
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            pass  # TODO: populate pharmacist data
    except Exception as e:
        app.logger.warning(f"Pharmacist dashboard DB issue: {e}")
    return render_template('pharmacist_dashboard.html', pending_prescriptions=pending_prescriptions, stock=stock, reservations=reservations, medicines=medicines)


# Create shorter aliases used in templates (if any expected "create_prescription" etc.)
@app.route('/create_prescription', methods=['POST'])
def create_prescription():
    flash('Create prescription not yet implemented', 'error')
    return redirect(url_for('doctor_dashboard'))


@app.route('/update_stock', methods=['POST'])
def update_stock():
    flash('Update stock not yet implemented', 'error')
    return redirect(url_for('pharmacist_dashboard'))


@app.route('/dispense/<int:prescription_id>')
def dispense_prescription(prescription_id):
    flash('Dispense not yet implemented', 'error')
    return redirect(url_for('pharmacist_dashboard'))


# URL helpers to match earlier template expectations if different naming
app.add_url_rule('/doctor', endpoint='doctor_dashboard', view_func=doctor_dashboard)
app.add_url_rule('/patient', endpoint='patient_dashboard', view_func=patient_dashboard)
app.add_url_rule('/pharmacist', endpoint='pharmacist_dashboard', view_func=pharmacist_dashboard)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

import os
import random
import string
import socket
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify

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
DEFAULT_CA_PATH = r"C:\Users\adies\Downloads\ca-certificate.crt"
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
    """Create a new database connection with multiple fallback methods"""
    if pymysql is None:
        raise RuntimeError("PyMySQL not installed. Run: pip install PyMySQL")
    
    start = time.time()
    
    # Method 1: Try without SSL (fastest and most reliable)
    try:
        print("🔌 Attempting database connection without SSL...")
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=3,  # Very short timeout
            read_timeout=5,
            write_timeout=5
        )
        elapsed = round((time.time()-start)*1000, 2)
        print(f"✅ Database connected without SSL in {elapsed} ms")
        app.logger.debug(f"DB connection established in {elapsed} ms")
        return conn
        
    except Exception as e:
        print(f"❌ Connection without SSL failed: {e}")
    
    # Method 2: Try with SSL (original method)
    try:
        print("🔐 Attempting database connection with SSL...")
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
            ssl=DB_CONFIG['ssl'],
            connect_timeout=5,
            read_timeout=6,
            write_timeout=6
        )
        elapsed = round((time.time()-start)*1000, 2)
        print(f"✅ Database connected with SSL in {elapsed} ms")
        app.logger.debug(f"DB connection established in {elapsed} ms")
        return conn
        
    except Exception as e:
        print(f"❌ Connection with SSL failed: {e}")
    
    # Method 3: Last resort with longer timeout
    try:
        print("⏰ Attempting database connection with extended timeout...")
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=10,
            read_timeout=15,
            write_timeout=15
        )
        elapsed = round((time.time()-start)*1000, 2)
        print(f"✅ Database connected with extended timeout in {elapsed} ms")
        app.logger.debug(f"DB connection established in {elapsed} ms")
        return conn
        
    except Exception as e:
        print(f"❌ Extended timeout connection failed: {e}")
    
    # All methods failed
    error_msg = f"All database connection methods failed. Check DigitalOcean database status and network connectivity."
    print(f"💥 {error_msg}")
    raise RuntimeError(error_msg)


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
def _safe_date_str(value):
    """Return a safe date string for templates.
    - datetime/date -> ISO string
    - str -> unchanged
    - None/other -> None
    """
    try:
        from datetime import date, datetime as _dt
        if isinstance(value, (date, _dt)):
            return str(value)
        if isinstance(value, str):
            return value
        return None
    except Exception:
        return str(value) if value is not None else None
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
    """Fetch medicines for dropdown. Flexible to schema differences.

    - Table name: prefers `medicines`, falls back to `medicine`.
    - ID column: prefers `id`, then `med_id`, `medicine_id`, `drug_id`.
    - Display column: prefers `brand_name`, falls back to `name`.
    """
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            # Resolve table name
            table_candidates = ['medicines', 'medicine']
            table_name = None
            for t in table_candidates:
                try:
                    cur.execute("SHOW TABLES LIKE %s", (t,))
                    if cur.fetchone():
                        table_name = t
                        break
                except Exception:
                    pass
            if not table_name:
                return []

            # Inspect columns
            try:
                cur.execute(f"SHOW COLUMNS FROM `{table_name}`")
                column_rows = cur.fetchall() or []
            except Exception:
                return []
            cols = []
            for r in column_rows:
                # PyMySQL returns 'Field'; some drivers may return 'column_name'
                if isinstance(r, dict):
                    cols.append((r.get('Field') or r.get('column_name') or '').strip('`'))
            cols = [c for c in cols if c]

            # Choose id column
            id_col = 'id'
            for cand in ['id', 'med_id', 'medicine_id', 'drug_id']:
                if cand in cols:
                    id_col = cand
                    break
            if id_col not in cols:
                return []

            # Choose display column
            display_col = 'brand_name' if 'brand_name' in cols else ('name' if 'name' in cols else None)
            if not display_col:
                return []

            # Fetch
            cur.execute(f"SELECT `{id_col}` AS id, `{display_col}` AS display FROM `{table_name}` ORDER BY `{display_col}`")
            rows = cur.fetchall() or []
            # Normalize to keys expected by template (brand_name or name)
            normalized = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                item = {"id": r.get('id')}
                if display_col == 'brand_name':
                    item['brand_name'] = r.get('display')
                else:
                    item['name'] = r.get('display')
                normalized.append(item)
            return normalized
    except Exception as e:
        app.logger.warning(f"get_medicines error: {e}")
        return []


# --- Prescription helpers ---
def _resolve_table_name(cur, candidates):
    for t in candidates:
        try:
            cur.execute("SHOW TABLES LIKE %s", (t,))
            if cur.fetchone():
                return t
        except Exception:
            continue
    return None


def _get_columns(cur, table_name):
    try:
        cur.execute(f"SHOW COLUMNS FROM `{table_name}`")
        rows = cur.fetchall() or []
        cols = []
        for r in rows:
            if isinstance(r, dict):
                cols.append((r.get('Field') or r.get('column_name') or '').strip('`'))
        return [c for c in cols if c]
    except Exception:
        return []


def _choose(candidates, available):
    for c in candidates:
        if c in available:
            return c
    return None


# Helper to fetch patient's Aadhaar-like identifier by patient id
def _get_patient_aadhaar_by_id(cur, patient_id):
    patient_table = _resolve_table_name(cur, ['patients'])
    if not patient_table:
        return None
    cols = _get_columns(cur, patient_table)
    id_col = 'id' if 'id' in cols else (_choose(['patient_id'], cols) or 'id')
    aad_cols = ['aadhaar', 'aadhar', 'aadhaar_number', 'aadhar_number', 'aadhaar_no']
    use_col = None
    for c in aad_cols:
        if c in cols:
            use_col = c
            break
    if not use_col:
        return None
    try:
        cur.execute(f"SELECT `{use_col}` AS aad FROM `{patient_table}` WHERE `{id_col}`=%s LIMIT 1", (patient_id,))
        row = cur.fetchone() or {}
        return row.get('aad')
    except Exception:
        return None


# --- Minimal dashboard placeholders (can be expanded later) ---
@app.route('/doctor/dashboard')
def doctor_dashboard():
    if session.get('user_type') != 'doctor':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    prescriptions = []
    medicines = get_medicines()
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            items_table = _resolve_table_name(cur, ['prescription_items','prescription_item','presc_items'])
            meds_table = _resolve_table_name(cur, ['medicines','medicine'])
            patients_table = _resolve_table_name(cur, ['patients'])
            if presc_table and items_table and meds_table and patients_table:
                pc = _get_columns(cur, presc_table)
                ic = _get_columns(cur, items_table)
                mc = _get_columns(cur, meds_table)
                ptc = _get_columns(cur, patients_table)
                presc_id = _choose(['presc_id','id'], pc) or 'id'
                presc_patient_id = _choose(['patient_id','pat_id'], pc) or 'patient_id'
                presc_doctor_id = _choose(['doctor_id','doc_id'], pc) or 'doctor_id'
                presc_status = _choose(['status','state'], pc) or 'status'
                presc_date = _choose(['presc_date','created_at','created_on','created_date'], pc)
                item_presc_fk = _choose(['presc_id','prescription_id'], ic) or 'presc_id'
                item_med = _choose(['med_id','medicine_id','drug_id'], ic) or 'med_id'
                med_id = _choose(['id','med_id','medicine_id','drug_id'], mc) or 'id'
                med_name = 'brand_name' if 'brand_name' in mc else ('name' if 'name' in mc else None)
                pt_id = _choose(['id','patient_id'], ptc) or 'id'
                pt_name = _choose(['name','full_name','display_name','username'], ptc) or 'name'

                cur.execute(
                    f"SELECT p.`{presc_id}` AS id, p.`{presc_patient_id}` AS patient_id, {('p.`'+presc_date+'` AS created_date,') if presc_date else 'NULL AS created_date,'} p.`{presc_status}` AS status FROM `{presc_table}` p WHERE p.`{presc_doctor_id}`=%s ORDER BY {('p.`'+presc_date+'` DESC') if presc_date else 'p.`'+presc_id+'` DESC'} LIMIT 50",
                    (session.get('user_id'),)
                )
                rows = cur.fetchall() or []
                for r in rows:
                    pid = r.get('id')
                    cur.execute(f"SELECT `{pt_name}` AS name FROM `{patients_table}` WHERE `{pt_id}`=%s", (r.get('patient_id'),))
                    patient_name = (cur.fetchone() or {}).get('name') or 'Unknown'
                    cur.execute(
                        f"SELECT m.`{med_name}` AS name FROM `{items_table}` i JOIN `{meds_table}` m ON m.`{med_id}`=i.`{item_med}` WHERE i.`{item_presc_fk}`=%s",
                        (pid,)
                    )
                    meds_rows = cur.fetchall() or []
                    raw_status = (r.get('status') or '').strip().lower()
                    status_display = 'Pending' if raw_status in ('issued','pending','created','new') else 'Dispensed'
                    prescriptions.append({
                        'id': pid,
                        'patient_name': patient_name,
                        'created_date': _safe_date_str(r.get('created_date')),
                        'medicines': ', '.join([m.get('name') for m in meds_rows if m.get('name')]),
                        'status': status_display
                    })
    except Exception as e:
        app.logger.warning(f"Doctor dashboard DB issue: {e}")
    return render_template('doctor_dashboard.html', prescriptions=prescriptions, medicines=medicines)


@app.route('/patient/dashboard')
def patient_dashboard():
    if session.get('user_type') != 'patient':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    prescriptions = []
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            items_table = _resolve_table_name(cur, ['prescription_items','prescription_item','presc_items'])
            meds_table = _resolve_table_name(cur, ['medicines','medicine'])
            doctors_table = _resolve_table_name(cur, ['doctors'])
            if not (presc_table and items_table and meds_table and doctors_table):
                return render_template('patient_dashboard.html', prescriptions=prescriptions)

            # Columns
            presc_cols = _get_columns(cur, presc_table)
            items_cols = _get_columns(cur, items_table)
            meds_cols = _get_columns(cur, meds_table)
            doctors_cols = _get_columns(cur, doctors_table)

            presc_id = _choose(['presc_id','id'], presc_cols) or 'id'
            presc_patient_id = _choose(['patient_id','pat_id'], presc_cols) or 'patient_id'
            presc_doctor_id = _choose(['doctor_id','doc_id'], presc_cols) or 'doctor_id'
            presc_status = _choose(['status','state'], presc_cols) or 'status'
            presc_date = _choose(['presc_date','created_at','created_on','created_date'], presc_cols)

            item_presc_fk = _choose(['presc_id','prescription_id'], items_cols) or 'presc_id'
            item_med = _choose(['med_id','medicine_id','drug_id'], items_cols) or 'med_id'
            item_dose = _choose(['dose','dosage'], items_cols)
            item_freq = _choose(['frequency','freq'], items_cols)
            item_duration = _choose(['duration_days','duration','days'], items_cols)

            med_id = _choose(['id','med_id','medicine_id','drug_id'], meds_cols) or 'id'
            med_name = 'brand_name' if 'brand_name' in meds_cols else ('name' if 'name' in meds_cols else None)

            doc_id = _choose(['id','doctor_id'], doctors_cols) or 'id'
            doc_name = _choose(['name','full_name','display_name','username'], doctors_cols) or 'name'

            # Query prescriptions for current patient
            cur.execute(
                f"""
                SELECT p.`{presc_id}` AS id,
                       d.`{doc_name}` AS doctor_name,
                       {('p.`'+presc_date+'` AS created_date,') if presc_date else 'NULL AS created_date,'}
                       p.`{presc_status}` AS status
                FROM `{presc_table}` p
                JOIN `{doctors_table}` d ON d.`{doc_id}` = p.`{presc_doctor_id}`
                WHERE p.`{presc_patient_id}`=%s
                ORDER BY {('p.`'+presc_date+'` DESC') if presc_date else 'p.`'+presc_id+'` DESC'}
                """,
                (session.get('user_id'),)
            )
            rows = cur.fetchall() or []
            # Build medicine strings
            prescriptions = []
            for r in rows:
                pid = r.get('id')
                cur.execute(
                    f"""
                    SELECT m.`{med_name}` AS name,
                           {('i.`'+item_dose+'` AS dose,') if item_dose else 'NULL AS dose,'}
                           {('i.`'+item_freq+'` AS frequency,') if item_freq else 'NULL AS frequency,'}
                           {('i.`'+item_duration+'` AS duration') if item_duration else 'NULL AS duration'}
                    FROM `{items_table}` i
                    JOIN `{meds_table}` m ON m.`{med_id}` = i.`{item_med}`
                    WHERE i.`{item_presc_fk}`=%s
                    """,
                    (pid,)
                )
                items = cur.fetchall() or []
                med_list = []
                for it in items:
                    parts = [it.get('name')]
                    if it.get('dose'): parts.append(str(it.get('dose')))
                    if it.get('frequency'): parts.append(str(it.get('frequency')))
                    if it.get('duration'): parts.append(str(it.get('duration')))
                    med_list.append(' '.join([p for p in parts if p]))
                # Normalize status for display
                raw_status = (r.get('status') or '').strip().lower()
                status_display = 'Pending' if raw_status in ('issued','pending','created','new') else 'Dispensed'
                prescriptions.append({
                    'id': r.get('id'),
                    'doctor_name': r.get('doctor_name'),
                    'created_date': _safe_date_str(r.get('created_date')),
                    'status': status_display,
                    'medicines': ', '.join(med_list)
                })
    except Exception as e:
        app.logger.warning(f"Patient dashboard DB issue: {e}")
    return render_template('patient_dashboard.html', prescriptions=prescriptions)


@app.post('/find_pharmacies')
def find_pharmacies():
    location = (request.form.get('location') or '').strip()
    pharmacies = []
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            table = _resolve_table_name(cur, ['pharmacists'])
            if not table:
                return jsonify(success=True, pharmacies=[])
            cols = _get_columns(cur, table)
            id_col = _choose(['id','pharmacist_id'], cols) or 'id'
            name_col = _choose(['name','full_name','display_name','username'], cols) or 'name'
            pharmacy_name_col = _choose(['pharmacy_name','store_name'], cols)
            lat_col = _choose(['lat','latitude'], cols)
            lng_col = _choose(['lng','longitude','lon'], cols)
            addr_col = _choose(['address','addr','location'], cols)

            # If lat/lng stored, compute distance in Python after optional geocoding of user location
            user_lat = None
            user_lng = None
            if location:
                api_key = os.environ.get('GOOGLE_MAPS_API_KEY') or os.environ.get('RX_GOOGLE_MAPS_API_KEY')
                if api_key:
                    try:
                        import requests
                        r = requests.get('https://maps.googleapis.com/maps/api/geocode/json', params={'address': location, 'key': api_key}, timeout=5)
                        data = r.json()
                        if data.get('results'):
                            ll = data['results'][0]['geometry']['location']
                            user_lat, user_lng = ll.get('lat'), ll.get('lng')
                    except Exception as _:
                        pass

            if lat_col and lng_col:
                sel = [f"`{id_col}` AS id", f"`{name_col}` AS name"]
                if pharmacy_name_col:
                    sel.append(f"`{pharmacy_name_col}` AS pharmacy_name")
                if addr_col:
                    sel.append(f"`{addr_col}` AS address")
                sel.append(f"`{lat_col}` AS lat")
                sel.append(f"`{lng_col}` AS lng")
                cur.execute(f"SELECT {', '.join(sel)} FROM `{table}` WHERE `{lat_col}` IS NOT NULL AND `{lng_col}` IS NOT NULL")
                rows = cur.fetchall() or []
                def haversine(lat1, lon1, lat2, lon2):
                    from math import radians, sin, cos, asin, sqrt
                    R = 6371.0
                    dlat = radians(lat2-lat1)
                    dlon = radians(lon2-lon1)
                    a = sin(dlat/2)**2 + cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
                    c = 2*asin(sqrt(a))
                    return R*c
                for r in rows:
                    dist_km = None
                    if user_lat is not None and user_lng is not None and r.get('lat') is not None and r.get('lng') is not None:
                        dist_km = round(haversine(float(user_lat), float(user_lng), float(r.get('lat')), float(r.get('lng'))), 2)
                    pharmacies.append({
                        'id': r.get('id'),
                        'name': r.get('name'),
                        'pharmacy_name': r.get('pharmacy_name') or (r.get('name') and (r.get('name') + ' Pharmacy')),
                        'address': r.get('address'),
                        'lat': r.get('lat'),
                        'lng': r.get('lng'),
                        'distance_km': dist_km
                    })
                # If we have user location, sort by distance
                if user_lat is not None and user_lng is not None:
                    pharmacies.sort(key=lambda x: x.get('distance_km') if x.get('distance_km') is not None else 1e9)
            else:
                # Fallback: no lat/lng columns, return basic list (as before)
                if pharmacy_name_col:
                    cur.execute(f"SELECT `{id_col}` AS id, `{name_col}` AS name, `{pharmacy_name_col}` AS pharmacy_name FROM `{table}` LIMIT 10")
                else:
                    cur.execute(f"SELECT `{id_col}` AS id, `{name_col}` AS name FROM `{table}` LIMIT 10")
                rows = cur.fetchall() or []
                for r in rows:
                    pharmacies.append({
                        'id': r.get('id'),
                        'name': r.get('name'),
                        'pharmacy_name': r.get('pharmacy_name') or (r.get('name') and (r.get('name') + ' Pharmacy'))
                    })
    except Exception as e:
        app.logger.warning(f"find_pharmacies error: {e}")
        return jsonify(success=False, message='Error searching pharmacies')
    return jsonify(success=True, pharmacies=pharmacies)


@app.post('/pharmacist/set_location')
def set_pharmacist_location():
    if session.get('user_type') != 'pharmacist':
        return jsonify(success=False, message='Unauthorized'), 403
    lat = request.form.get('lat')
    lng = request.form.get('lng')
    address = request.form.get('address')
    if not lat or not lng:
        return jsonify(success=False, message='lat/lng required'), 400
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            table = _resolve_table_name(cur, ['pharmacists'])
            if not table:
                return jsonify(success=False, message='pharmacists table missing'), 400
            cols = _get_columns(cur, table)
            id_col = _choose(['id','pharmacist_id'], cols) or 'id'
            lat_col = _choose(['lat','latitude'], cols)
            lng_col = _choose(['lng','longitude','lon'], cols)
            addr_col = _choose(['address','addr','location'], cols)
            # Add columns if missing
            def _add_col(col, sql_type):
                try:
                    cur.execute(f"ALTER TABLE `{table}` ADD COLUMN `{col}` {sql_type}")
                except Exception:
                    pass
            if not lat_col:
                _add_col('lat', 'DECIMAL(10,7) NULL')
                lat_col = 'lat'
            if not lng_col:
                _add_col('lng', 'DECIMAL(10,7) NULL')
                lng_col = 'lng'
            if not addr_col:
                _add_col('address', 'VARCHAR(255) NULL')
                addr_col = 'address'
            cur.execute(
                f"UPDATE `{table}` SET `{lat_col}`=%s, `{lng_col}`=%s, `{addr_col}`=%s WHERE `{id_col}`=%s",
                (lat, lng, address, session.get('user_id'))
            )
            conn.commit()
        return jsonify(success=True)
    except Exception as e:
        app.logger.warning(f"set_pharmacist_location error: {e}")
        return jsonify(success=False, message='DB error'), 500


@app.route('/test-db')
def test_database():
    """Test database connection route"""
    try:
        print("🧪 Testing database connection from web interface...")
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Test basic connectivity
                cur.execute("SELECT 1 as test")
                result = cur.fetchone()
                
                # Get current time
                cur.execute("SELECT NOW() as current_time")
                time_result = cur.fetchone()
                result['current_time'] = time_result['current_time']
                
                # Get version separately
                cur.execute("SELECT VERSION() as db_version")
                version_result = cur.fetchone()
                result['db_version'] = version_result['db_version']
                
                # Test table listing
                cur.execute("SHOW TABLES")
                tables = cur.fetchall()
                table_names = [list(t.values())[0] for t in tables]
                
                # Look for prescription tables
                prescription_tables = [name for name in table_names if 'presc' in name.lower()]
                
                response = {
                    'status': 'success',
                    'message': 'Database connection successful!',
                    'server_info': {
                        'current_time': str(result['current_time']),
                        'db_version': result['db_version']
                    },
                    'tables': {
                        'total_count': len(table_names),
                        'all_tables': table_names,
                        'prescription_tables': prescription_tables
                    }
                }
                
                if prescription_tables:
                    # Get prescription count
                    presc_table = prescription_tables[0]
                    cur.execute(f"SELECT COUNT(*) as total FROM `{presc_table}`")
                    count_result = cur.fetchone()
                    response['prescription_info'] = {
                        'table_name': presc_table,
                        'total_prescriptions': count_result['total']
                    }
                
                return f"""
                <html>
                <head><title>Database Test Results</title></head>
                <body style="font-family: Arial; margin: 40px;">
                    <h1>✅ Database Connection Test - SUCCESS</h1>
                    <h2>🗄️ Server Information:</h2>
                    <ul>
                        <li><strong>Database Version:</strong> {result['db_version']}</li>
                        <li><strong>Server Time:</strong> {result['current_time']}</li>
                    </ul>
                    
                    <h2>📋 Database Tables ({len(table_names)} total):</h2>
                    <ul>
                        {''.join([f'<li>{table}</li>' for table in sorted(table_names)])}
                    </ul>
                    
                    <h2>💊 Prescription Tables:</h2>
                    {f'<p><strong>Found:</strong> {prescription_tables}</p>' if prescription_tables else '<p><em>No prescription tables found</em></p>'}
                    
                    {f'<p><strong>Total Prescriptions:</strong> {response.get("prescription_info", {}).get("total_prescriptions", 0)}</p>' if prescription_tables else ''}
                    
                    <h2>🎯 What This Means:</h2>
                    <p>✅ Your database connection is working! You can now:</p>
                    <ul>
                        <li>Enable real prescription loading in the pharmacist dashboard</li>
                        <li>See actual prescriptions from doctors</li>
                        <li>Use the full RxPress functionality</li>
                    </ul>
                    
                    <p><a href="/pharmacist/dashboard">→ Go to Pharmacist Dashboard</a></p>
                    <p><a href="/">→ Go to Home</a></p>
                </body>
                </html>
                """
                
    except Exception as e:
        error_details = str(e)
        print(f"❌ Database test failed: {error_details}")
        
        return f"""
        <html>
        <head><title>Database Test Results</title></head>
        <body style="font-family: Arial; margin: 40px;">
            <h1>❌ Database Connection Test - FAILED</h1>
            <h2>🔍 Error Details:</h2>
            <pre style="background: #f5f5f5; padding: 20px; border-radius: 5px;">{error_details}</pre>
            
            <h2>🔧 Troubleshooting Steps:</h2>
            <ol>
                <li><strong>Check DigitalOcean Database Status:</strong>
                    <ul>
                        <li>Go to <a href="https://cloud.digitalocean.com/" target="_blank">DigitalOcean Dashboard</a></li>
                        <li>Navigate to Databases → Your RxPress database</li>
                        <li>Ensure status is "Active" (not "Paused" or "Suspended")</li>
                    </ul>
                </li>
                
                <li><strong>Check Network Connectivity:</strong>
                    <ul>
                        <li>Try accessing other websites to verify internet connection</li>
                        <li>Check if Windows Firewall is blocking port 25060</li>
                        <li>Temporarily disable antivirus to test</li>
                    </ul>
                </li>
                
                <li><strong>Verify Database Credentials:</strong>
                    <ul>
                        <li>Host: rxpress-do-user-25725432-0.h.db.ondigitalocean.com</li>
                        <li>Port: 25060</li>
                        <li>Database: defaultdb</li>
                        <li>User: doadmin</li>
                    </ul>
                </li>
                
                <li><strong>Alternative Solutions:</strong>
                    <ul>
                        <li>Try connecting from a different network (mobile hotspot)</li>
                        <li>Use DigitalOcean's connection pool instead</li>
                        <li>Enable trusted sources in DigitalOcean database settings</li>
                    </ul>
                </li>
            </ol>
            
            <p><a href="/pharmacist/dashboard">→ Continue with Demo Data</a></p>
            <p><a href="/">→ Go to Home</a></p>
        </body>
        </html>
        """


@app.route('/pharmacist/dashboard')
def pharmacist_dashboard():
    # Temporarily bypass auth for testing
    # if session.get('user_type') != 'pharmacist':
    #     flash('Unauthorized', 'error')
    #     return redirect(url_for('login'))
    
    # Check for dispense success message
    dispense_success_msg = session.pop('dispense_success', None)
    if dispense_success_msg:
        flash(dispense_success_msg, 'success')
    
    print("🔄 Loading pharmacist dashboard...")
    
    # Try to load real data from database first
    database_status = "checking"
    pending_prescriptions = []
    stock = []

    try:
        print("🔌 Attempting to load real prescriptions from database...")

        with get_db_connection() as conn, conn.cursor() as cur:
            # Resolve core tables
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            items_table = _resolve_table_name(cur, ['prescription_items','prescription_item','presc_items'])
            meds_table = _resolve_table_name(cur, ['medicines','medicine'])
            patients_table = _resolve_table_name(cur, ['patients'])
            doctors_table = _resolve_table_name(cur, ['doctors'])
            stock_table = _resolve_table_name(cur, ['stock','stocks'])

            if not (presc_table and items_table and meds_table and patients_table and doctors_table):
                print("❌ Required tables not found; falling back to demo")
                database_status = "no_tables"
            else:
                # Column resolution
                pc = _get_columns(cur, presc_table)
                ic = _get_columns(cur, items_table)
                mc = _get_columns(cur, meds_table)
                ptc = _get_columns(cur, patients_table)
                dc = _get_columns(cur, doctors_table)
                sc = _get_columns(cur, stock_table) if stock_table else []

                presc_id = _choose(['presc_id','id'], pc) or 'id'
                presc_patient_id = _choose(['patient_id','pat_id'], pc) or 'patient_id'
                presc_doctor_id = _choose(['doctor_id','doc_id'], pc) or 'doctor_id'
                presc_status = _choose(['status','state'], pc) or 'status'
                presc_date = _choose(['presc_date','created_at','created_on','created_date'], pc)

                item_presc_fk = _choose(['presc_id','prescription_id'], ic) or 'presc_id'
                item_med = _choose(['med_id','medicine_id','drug_id'], ic) or 'med_id'
                item_dose = _choose(['dose','dosage'], ic)

                med_id = _choose(['id','med_id','medicine_id','drug_id'], mc) or 'id'
                # Build a COALESCE expression for medicine name
                med_name_candidates = [c for c in ['brand_name','name','generic_name','title'] if c in mc]
                med_name_expr = None
                if med_name_candidates:
                    med_name_expr = "COALESCE(" + ", ".join([f"m.`{c}`" for c in med_name_candidates]) + ") AS name"

                pt_id = _choose(['id','patient_id'], ptc) or 'id'
                pt_name_candidates = [c for c in ['name','full_name','display_name','username','patient_name','first_name'] if c in ptc]
                pt_name_expr = None
                if pt_name_candidates:
                    pt_name_expr = "COALESCE(" + ", ".join([f"pt.`{c}`" for c in pt_name_candidates]) + ") AS patient_name"

                doc_id = _choose(['id','doctor_id'], dc) or 'id'
                doc_name_candidates = [c for c in ['name','full_name','display_name','username','doctor_name','first_name'] if c in dc]
                doc_name_expr = None
                if doc_name_candidates:
                    doc_name_expr = "COALESCE(" + ", ".join([f"d.`{c}`" for c in doc_name_candidates]) + ") AS doctor_name"

                st_med = _choose(['med_id','medicine_id','drug_id'], sc) if sc else None
                st_qty = _choose(['qty','quantity'], sc) if sc else None
                st_exp = _choose(['expiry','expiry_date','expires_on'], sc) if sc else None

                # Fetch recent pending prescriptions that have at least one item
                status_pending_values = ('issued','pending','created','new')
                status_placeholders = ','.join(['%s']*len(status_pending_values))

                date_select = f"p.`{presc_date}` AS created_date," if presc_date else "NULL AS created_date,"
                order_by = f"p.`{presc_date}` DESC" if presc_date else f"p.`{presc_id}` DESC"
                # Fallbacks for name exprs if no columns matched
                if not pt_name_expr:
                    pt_name_expr = f"CONCAT('Patient ', p.`{presc_patient_id}`) AS patient_name"
                if not doc_name_expr:
                    doc_name_expr = f"CONCAT('Doctor ', p.`{presc_doctor_id}`) AS doctor_name"

                cur.execute(
                    f"""
                    SELECT p.`{presc_id}` AS id,
                           {pt_name_expr},
                           {doc_name_expr},
                           {date_select}
                           p.`{presc_status}` AS status
                    FROM `{presc_table}` p
                    JOIN `{patients_table}` pt ON pt.`{pt_id}` = p.`{presc_patient_id}`
                                        JOIN `{doctors_table}` d ON d.`{doc_id}` = p.`{presc_doctor_id}`
                                        WHERE LOWER(COALESCE(p.`{presc_status}`,'')) IN ({status_placeholders})
                                            AND EXISTS (
                                                SELECT 1 FROM `{items_table}` i WHERE i.`{item_presc_fk}` = p.`{presc_id}`
                                            )
                                        ORDER BY {order_by}
                                        LIMIT 50
                                        """,
                                        tuple(status_pending_values)
                                )
                rows = cur.fetchall() or []

                # For each, get medicines and check stock
                for r in rows:
                    pid = r.get('id')
                    # Items + medicine names
                    # Build medicine select with COALESCE if needed
                    if med_name_expr:
                        med_select = med_name_expr
                    else:
                        med_select = "CONCAT('Medicine ', m.`" + med_id + "`) AS name"
                    cur.execute(
                        f"""
                        SELECT {med_select},
                               m.`{med_id}` AS med_id,
                               {('i.`'+item_dose+'` AS dose') if item_dose else 'NULL AS dose'}
                        FROM `{items_table}` i
                        JOIN `{meds_table}` m ON m.`{med_id}` = i.`{item_med}`
                        WHERE i.`{item_presc_fk}`=%s
                        """,
                        (pid,)
                    )
                    items = cur.fetchall() or []
                    med_names = []
                    meds_in_stock = []
                    meds_oos = []
                    for it in items:
                        label = it.get('name')
                        if it.get('dose'):
                            label = f"{label} {it.get('dose')}"
                        med_names.append(label)
                        # stock
                        if stock_table and st_med and st_qty:
                            try:
                                cur.execute(
                                    f"SELECT `{st_qty}` AS qty FROM `{stock_table}` WHERE `{st_med}`=%s LIMIT 1",
                                    (it.get('med_id'),)
                                )
                                row_st = cur.fetchone() or {}
                                qty_val = row_st.get('qty')
                                if qty_val and int(qty_val) > 0:
                                    meds_in_stock.append(it.get('name'))
                                else:
                                    meds_oos.append(it.get('name'))
                            except Exception:
                                # if stock lookup fails, assume in stock to avoid blocking
                                meds_in_stock.append(it.get('name'))

                    all_in_stock = (len(med_names) > 0) and (len(meds_oos) == 0)

                    # Normalize status
                    raw_status = (r.get('status') or '').strip().lower()
                    status_display = 'Pending' if raw_status in status_pending_values else 'Dispensed'

                    pending_prescriptions.append({
                        'id': pid,
                        'patient_name': r.get('patient_name'),
                        'doctor_name': r.get('doctor_name'),
                        'created_date': _safe_date_str(r.get('created_date')),
                        'medicines': ', '.join(med_names),
                        'status': status_display,
                        'all_in_stock': all_in_stock,
                        'medicines_in_stock': meds_in_stock,
                        'medicines_out_of_stock': meds_oos
                    })

                # After prescriptions, load Stock Management data from DB
                try:
                    if stock_table and st_qty:
                        expiry_select = (f"s.`{st_exp}` AS expiry_date" if st_exp else "NULL AS expiry_date")
                        if meds_table and med_id:
                            # Medicine display name (COALESCE over common name columns)
                            med_name_candidates2 = [c for c in ['brand_name','name','generic_name','title'] if c in mc]
                            med_name_for_stock = (
                                "COALESCE(" + ", ".join([f"m.`{c}`" for c in med_name_candidates2]) + ")"
                                if med_name_candidates2 else f"CONCAT('Medicine ', m.`{med_id}`)"
                            )
                            if st_med:
                                cur.execute(
                                    f"""
                                    SELECT {med_name_for_stock} AS medicine_name,
                                           s.`{st_qty}` AS quantity,
                                           {expiry_select}
                                    FROM `{stock_table}` s
                                    JOIN `{meds_table}` m ON m.`{med_id}` = s.`{st_med}`
                                    ORDER BY medicine_name
                                    """
                                )
                                stock = cur.fetchall() or []
                                # normalize expiry_date to string
                                for _row in stock:
                                    if isinstance(_row, dict):
                                        _row['expiry_date'] = _safe_date_str(_row.get('expiry_date'))
                            else:
                                # No medicine id link in stock; show generic rows
                                cur.execute(
                                    f"SELECT s.`{st_qty}` AS quantity, {expiry_select} FROM `{stock_table}` s"
                                )
                                tmp = cur.fetchall() or []
                                stock = [{"medicine_name": "Medicine", "quantity": r.get("quantity"), "expiry_date": _safe_date_str(r.get("expiry_date"))} for r in tmp]
                        else:
                            # No medicines table; show generic labels using stock ids if possible
                            if st_med:
                                cur.execute(
                                    f"SELECT CONCAT('Medicine ', s.`{st_med}`) AS medicine_name, s.`{st_qty}` AS quantity, {expiry_select} FROM `{stock_table}` s"
                                )
                                stock = cur.fetchall() or []
                                for _row in stock:
                                    if isinstance(_row, dict):
                                        _row['expiry_date'] = _safe_date_str(_row.get('expiry_date'))
                except Exception as e_stock:
                    app.logger.warning(f"Stock load error: {e_stock}")

                database_status = "connected"
                print(f"✅ Successfully loaded {len(pending_prescriptions)} real prescriptions!")
    except Exception as e:
        print(f"❌ Failed to load real prescriptions: {e}")
        database_status = "failed"

    # If we couldn't load real prescriptions, use demo data
    if not pending_prescriptions:
        print("📝 Using demo data for prescriptions")
        database_status = "demo" if database_status == "checking" else database_status
        
        pending_prescriptions = [
            {
                'id': 101,
                'patient_name': 'Alice Johnson',
                'doctor_name': 'Dr. Maria Rodriguez',
                'created_date': '2025-01-10',
                'medicines': 'Amoxicillin 500mg, Ibuprofen 200mg',
                'status': 'issued',
                'all_in_stock': True,
                'medicines_in_stock': ['Amoxicillin', 'Ibuprofen'],
                'medicines_out_of_stock': []
            },
            {
                'id': 102,
                'patient_name': 'Robert Chen',
                'doctor_name': 'Dr. James Wilson',
                'created_date': '2025-01-11',
                'medicines': 'Metformin 500mg, Lisinopril 10mg',
                'status': 'issued',
                'all_in_stock': False,
                'medicines_in_stock': ['Metformin'],
                'medicines_out_of_stock': ['Lisinopril']
            },
            {
                'id': 103,
                'patient_name': 'Sarah Williams',
                'doctor_name': 'Dr. Emily Davis',
                'created_date': '2025-01-12',
                'medicines': 'Paracetamol 500mg, Aspirin 325mg',
                'status': 'issued',
                'all_in_stock': True,
                'medicines_in_stock': ['Paracetamol', 'Aspirin'],
                'medicines_out_of_stock': []
            }
        ]
    
    print(f"📊 Loaded {len(pending_prescriptions)} demo prescriptions")
    
    # Load medicine list for stock management from DB (all medicines)
    medicines_raw = get_medicines()  # returns list with 'id' and either 'brand_name' or 'name'
    medicines = []
    for m in medicines_raw:
        display = m.get('brand_name') or m.get('name')
        if m.get('id') is not None and display:
            medicines.append({'id': m.get('id'), 'name': display})
    has_medicines = len(medicines) > 0
    
    # If stock wasn't loaded above (e.g., DB fallback), leave as empty or load a demo only when DB failed
    
    reservations = []
    
    print("✅ Dashboard loaded successfully")
    
    return render_template('pharmacist_dashboard.html', 
                         pending_prescriptions=pending_prescriptions, 
                         stock=stock, 
                         reservations=reservations, 
                         medicines=medicines, 
                         has_medicines=has_medicines,
                         database_status=database_status)
    
    # Note: Real stock loading is handled earlier; returning with current data

# Create shorter aliases used in templates (if any expected "create_prescription" etc.)
@app.route('/create_prescription', methods=['POST'])
def create_prescription():
    if session.get('user_type') != 'doctor':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))

    # Form fields per template
    patient_id_raw = (request.form.get('patient_id') or '').strip()
    med_ids = request.form.getlist('medicines[]')
    dosages = request.form.getlist('dosages[]')
    durations = request.form.getlist('durations[]')

    if not patient_id_raw or not med_ids:
        flash('Patient and at least one medicine are required.', 'error')
        return redirect(url_for('doctor_dashboard'))

    # Normalize lists to same length
    item_count = min(len(med_ids), len(dosages), len(durations))
    med_ids = med_ids[:item_count]
    dosages = dosages[:item_count]
    durations = durations[:item_count]

    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            # Resolve table and columns for prescriptions
            presc_table = _resolve_table_name(cur, ['prescriptions', 'prescription'])
            items_table = _resolve_table_name(cur, ['prescription_items', 'prescription_item', 'presc_items'])
            if not presc_table or not items_table:
                flash('Prescription tables not found in database.', 'error')
                return redirect(url_for('doctor_dashboard'))

            presc_cols = _get_columns(cur, presc_table)
            items_cols = _get_columns(cur, items_table)

            presc_id_col = _choose(['presc_id', 'id'], presc_cols) or 'id'
            doctor_id_col = _choose(['doctor_id','doc_id'], presc_cols)
            patient_id_col = _choose(['patient_id','pat_id'], presc_cols)
            status_col = _choose(['status','state'], presc_cols)
            date_col = _choose(['presc_date','created_at','created_date','created_on'], presc_cols)

            if not doctor_id_col or not patient_id_col:
                flash('Prescription table missing doctor_id/patient_id.', 'error')
                return redirect(url_for('doctor_dashboard'))

            # Insert prescription header
            cols = [doctor_id_col, patient_id_col]
            vals = [session.get('user_id'), int(patient_id_raw)]
            if status_col:
                cols.append(status_col)
                vals.append('issued')
            if date_col:
                cols.append(date_col)
                vals.append(datetime.utcnow())
            placeholders = ','.join(['%s']*len(vals))
            cur.execute(f"INSERT INTO `{presc_table}` ({','.join('`'+c+'`' for c in cols)}) VALUES ({placeholders})", tuple(vals))
            conn.commit()

            # Get inserted id
            cur.execute("SELECT LAST_INSERT_ID() AS new_id")
            new_id_row = cur.fetchone() or {}
            presc_id_val = new_id_row.get('new_id')

            # Resolve item columns
            item_presc_fk = _choose(['presc_id','prescription_id'], items_cols)
            item_med_col = _choose(['med_id','medicine_id','drug_id'], items_cols)
            item_dose_col = _choose(['dose','dosage'], items_cols)
            item_freq_col = _choose(['frequency','freq'], items_cols)
            item_duration_col = _choose(['duration_days','duration','days'], items_cols)
            item_qty_col = _choose(['qty_required','qty','quantity'], items_cols)

            if not item_presc_fk or not item_med_col:
                flash('Prescription items table missing presc_id/med_id.', 'error')
                return redirect(url_for('doctor_dashboard'))

            for idx in range(item_count):
                cols = [item_presc_fk, item_med_col]
                vals = [presc_id_val, int(med_ids[idx])]
                if item_dose_col:
                    cols.append(item_dose_col)
                    vals.append(dosages[idx])
                if item_freq_col:
                    cols.append(item_freq_col)
                    vals.append('')  # Not captured in form currently
                if item_duration_col:
                    cols.append(item_duration_col)
                    vals.append(durations[idx])
                if item_qty_col:
                    cols.append(item_qty_col)
                    vals.append(1)
                placeholders = ','.join(['%s']*len(vals))
                cur.execute(f"INSERT INTO `{items_table}` ({','.join('`'+c+'`' for c in cols)}) VALUES ({placeholders})", tuple(vals))

            conn.commit()
            flash('Prescription created.', 'success')
    except Exception as e:
        app.logger.error(f"create_prescription error: {e}")
        flash('Error creating prescription.', 'error')
    return redirect(url_for('doctor_dashboard'))


@app.route('/update_stock', methods=['POST'])
def update_stock():
    if session.get('user_type') != 'pharmacist':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    med_id = request.form.get('medicine_id')
    qty = request.form.get('quantity')
    expiry = request.form.get('expiry_date')
    if not med_id or not qty:
        flash('Medicine and quantity required', 'error')
        return redirect(url_for('pharmacist_dashboard'))
    try:
        qty_val = int(qty)
    except ValueError:
        flash('Quantity must be a number', 'error')
        return redirect(url_for('pharmacist_dashboard'))
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            stock_table = _resolve_table_name(cur, ['stock','stocks'])
            if not stock_table:
                flash('Stock table not found', 'error')
                return redirect(url_for('pharmacist_dashboard'))
            sc = _get_columns(cur, stock_table)
            st_med = _choose(['med_id','medicine_id','drug_id'], sc) or 'med_id'
            st_qty = _choose(['qty','quantity'], sc) or 'qty'
            st_exp = _choose(['expiry','expiry_date','expires_on'], sc)
            # Try update, if 0 rows then insert
            if st_exp:
                cur.execute(f"UPDATE `{stock_table}` SET `{st_qty}`=%s, `{st_exp}`=%s WHERE `{st_med}`=%s", (qty_val, expiry, int(med_id)))
            else:
                cur.execute(f"UPDATE `{stock_table}` SET `{st_qty}`=%s WHERE `{st_med}`=%s", (qty_val, int(med_id)))
            if cur.rowcount == 0:
                cols = [st_med, st_qty]
                vals = [int(med_id), qty_val]
                if st_exp:
                    cols.append(st_exp)
                    vals.append(expiry)
                cur.execute(f"INSERT INTO `{stock_table}` ({','.join('`'+c+'`' for c in cols)}) VALUES ({','.join(['%s']*len(vals))})", tuple(vals))
            conn.commit()
            flash('Stock updated.', 'success')
    except Exception as e:
        app.logger.error(f"update_stock error: {e}")
        flash('Error updating stock.', 'error')
    return redirect(url_for('pharmacist_dashboard'))


@app.post('/prescription/send_patient_otp')
def send_patient_otp_for_prescription():
    if session.get('user_type') != 'pharmacist':
        return jsonify(success=False, message='Unauthorized'), 403
    presc_id = request.form.get('prescription_id')
    try:
        presc_id_val = int(presc_id)
    except Exception:
        return jsonify(success=False, message='Invalid prescription id'), 400
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            if not presc_table:
                return jsonify(success=False, message='Prescriptions table not found'), 500
            pc = _get_columns(cur, presc_table)
            presc_id_col = _choose(['presc_id','id'], pc) or 'id'
            patient_id_col = _choose(['patient_id','pat_id'], pc) or 'patient_id'
            cur.execute(f"SELECT `{patient_id_col}` AS patient_id FROM `{presc_table}` WHERE `{presc_id_col}`=%s", (presc_id_val,))
            row = cur.fetchone()
            if not row:
                return jsonify(success=False, message='Prescription not found'), 404
            aad = _get_patient_aadhaar_by_id(cur, row.get('patient_id'))
            if not aad:
                return jsonify(success=False, message='Patient Aadhaar not found'), 400
            otp = generate_otp()
            store_otp(f"patient:{aad}", otp)
            return jsonify(success=True, otp=otp, expires_in=OTP_TTL_SECONDS)
    except Exception as e:
        app.logger.error(f"send_patient_otp_for_prescription error: {e}")
        return jsonify(success=False, message='Server error'), 500


@app.post('/dispense')
def dispense_prescription_post():
    if session.get('user_type') != 'pharmacist':
        return jsonify(success=False, message='Unauthorized'), 403
    presc_id = request.form.get('prescription_id')
    otp = (request.form.get('otp') or '').strip()
    if not presc_id or not otp:
        return jsonify(success=False, message='Prescription and OTP required'), 400
    try:
        presc_id_val = int(presc_id)
    except Exception:
        return jsonify(success=False, message='Invalid prescription id'), 400
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            # Locate prescriptions table and columns
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            if not presc_table:
                return jsonify(success=False, message='Prescriptions table not found'), 500
            pc = _get_columns(cur, presc_table)
            presc_id_col = _choose(['presc_id','id'], pc) or 'id'
            patient_id_col = _choose(['patient_id','pat_id'], pc) or 'patient_id'
            status_col = _choose(['status','state'], pc) or 'status'

            # Fetch prescription row
            cur.execute(f"SELECT `{patient_id_col}` AS patient_id, `{status_col}` AS status FROM `{presc_table}` WHERE `{presc_id_col}`=%s", (presc_id_val,))
            row = cur.fetchone()
            if not row:
                return jsonify(success=False, message='Prescription not found'), 404
            # Disallow if already dispensed
            if str(row.get('status') or '').lower() == 'dispensed':
                return jsonify(success=False, message='Already dispensed'), 400

            # Resolve patient's Aadhaar and validate OTP
            aad = _get_patient_aadhaar_by_id(cur, row.get('patient_id'))
            if not aad:
                return jsonify(success=False, message='Patient Aadhaar not found'), 400
            if not validate_otp(f"patient:{aad}", otp):
                return jsonify(success=False, message='Invalid or expired OTP'), 400

            # Mark prescription as dispensed
            cur.execute(f"UPDATE `{presc_table}` SET `{status_col}`='dispensed' WHERE `{presc_id_col}`=%s", (presc_id_val,))
            conn.commit()
            
            # Store success message in session to show on next page load
            session['dispense_success'] = f'Successfully dispensed medicines for prescription #{presc_id_val}'
            
            return jsonify(success=True)
    except Exception as e:
        app.logger.error(f"dispense_prescription_post error: {e}")
        return jsonify(success=False, message='Server error'), 500


# Keep old GET route but make it warn and redirect
@app.route('/dispense/<int:prescription_id>')
def dispense_prescription(prescription_id):
    flash('Use the Dispense button and enter Aadhaar + OTP to dispense.', 'warning')
    return redirect(url_for('pharmacist_dashboard'))


# URL helpers to match earlier template expectations if different naming
app.add_url_rule('/doctor', endpoint='doctor_dashboard', view_func=doctor_dashboard)
app.add_url_rule('/patient', endpoint='patient_dashboard', view_func=patient_dashboard)
app.add_url_rule('/pharmacist', endpoint='pharmacist_dashboard', view_func=pharmacist_dashboard)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

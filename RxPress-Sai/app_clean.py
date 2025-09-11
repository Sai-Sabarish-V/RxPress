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
                    'created_date': r.get('created_date'),
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
            if pharmacy_name_col:
                cur.execute(f"SELECT `{id_col}` AS id, `{name_col}` AS name, `{pharmacy_name_col}` AS pharmacy_name FROM `{table}` LIMIT 10")
            else:
                cur.execute(f"SELECT `{id_col}` AS id, `{name_col}` AS name FROM `{table}` LIMIT 10")
            rows = cur.fetchall() or []
            for r in rows:
                pharmacies.append({
                    'id': r.get('id'),
                    'name': r.get('name'),
                    'pharmacy_name': r.get('pharmacy_name') or (r.get('name') and (r.get('name') + " Pharmacy"))
                })
    except Exception as e:
        app.logger.warning(f"find_pharmacies error: {e}")
        return jsonify(success=False, message='Error searching pharmacies')
    return jsonify(success=True, pharmacies=pharmacies)


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
            # Medicines for stock form
            meds = get_medicines()
            medicines = [{'id': m.get('id'), 'name': m.get('brand_name') or m.get('name')} for m in meds]

            # Pending prescriptions (status='issued')
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            items_table = _resolve_table_name(cur, ['prescription_items','prescription_item','presc_items'])
            meds_table = _resolve_table_name(cur, ['medicines','medicine'])
            patients_table = _resolve_table_name(cur, ['patients'])
            doctors_table = _resolve_table_name(cur, ['doctors'])
            if presc_table and items_table and meds_table and patients_table and doctors_table:
                pc = _get_columns(cur, presc_table)
                ic = _get_columns(cur, items_table)
                mc = _get_columns(cur, meds_table)
                ptc = _get_columns(cur, patients_table)
                dc = _get_columns(cur, doctors_table)
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
                doc_id = _choose(['id','doctor_id'], dc) or 'id'
                doc_name = _choose(['name','full_name','display_name','username'], dc) or 'name'

                cur.execute(
                    f"SELECT p.`{presc_id}` AS id, p.`{presc_patient_id}` AS patient_id, p.`{presc_doctor_id}` AS doctor_id, {('p.`'+presc_date+'` AS created_date,') if presc_date else 'NULL AS created_date,'} p.`{presc_status}` AS status FROM `{presc_table}` p WHERE p.`{presc_status}` IN ('issued','Pending') ORDER BY {('p.`'+presc_date+'` DESC') if presc_date else 'p.`'+presc_id+'` DESC'}"
                )
                prescs = cur.fetchall() or []
                for r in prescs:
                    pid = r.get('id')
                    cur.execute(f"SELECT `{pt_name}` AS name FROM `{patients_table}` WHERE `{pt_id}`=%s", (r.get('patient_id'),))
                    pt = (cur.fetchone() or {}).get('name')
                    cur.execute(f"SELECT `{doc_name}` AS name FROM `{doctors_table}` WHERE `{doc_id}`=%s", (r.get('doctor_id'),))
                    dn = (cur.fetchone() or {}).get('name')
                    cur.execute(
                        f"SELECT m.`{med_name}` AS name FROM `{items_table}` i JOIN `{meds_table}` m ON m.`{med_id}`=i.`{item_med}` WHERE i.`{item_presc_fk}`=%s",
                        (pid,)
                    )
                    meds_rows = cur.fetchall() or []
                    pending_prescriptions.append({
                        'id': pid,
                        'patient_name': pt,
                        'doctor_name': dn,
                        'created_date': r.get('created_date'),
                        'medicines': ', '.join([m.get('name') for m in meds_rows if m.get('name')]),
                        'status': r.get('status')
                    })

            # Stock list if table exists
            stock_table = _resolve_table_name(cur, ['stock','stocks'])
            if stock_table and meds_table:
                sc = _get_columns(cur, stock_table)
                mc = _get_columns(cur, meds_table)
                st_med = _choose(['med_id','medicine_id','drug_id'], sc) or 'med_id'
                st_qty = _choose(['qty','quantity'], sc) or 'qty'
                st_exp = _choose(['expiry','expiry_date','expires_on'], sc)
                med_id = _choose(['id','med_id','medicine_id','drug_id'], mc) or 'id'
                med_name = 'brand_name' if 'brand_name' in mc else ('name' if 'name' in mc else None)
                cur.execute(
                    f"SELECT m.`{med_name}` AS medicine_name, s.`{st_qty}` AS quantity, {('s.`'+st_exp+'` AS expiry_date') if st_exp else 'NULL AS expiry_date'} FROM `{stock_table}` s JOIN `{meds_table}` m ON m.`{med_id}`=s.`{st_med}` ORDER BY m.`{med_name}`"
                )
                stock = cur.fetchall() or []
    except Exception as e:
        app.logger.warning(f"Pharmacist dashboard DB issue: {e}")
    return render_template('pharmacist_dashboard.html', pending_prescriptions=pending_prescriptions, stock=stock, reservations=reservations, medicines=medicines)


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


@app.route('/dispense/<int:prescription_id>')
def dispense_prescription(prescription_id):
    if session.get('user_type') != 'pharmacist':
        flash('Unauthorized', 'error')
        return redirect(url_for('login'))
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            presc_table = _resolve_table_name(cur, ['prescriptions','prescription'])
            if not presc_table:
                flash('Prescriptions table not found', 'error')
                return redirect(url_for('pharmacist_dashboard'))
            pc = _get_columns(cur, presc_table)
            presc_id = _choose(['presc_id','id'], pc) or 'id'
            status_col = _choose(['status','state'], pc) or 'status'
            cur.execute(f"UPDATE `{presc_table}` SET `{status_col}`='dispensed' WHERE `{presc_id}`=%s", (prescription_id,))
            conn.commit()
            flash('Prescription dispensed.', 'success')
    except Exception as e:
        app.logger.error(f"dispense_prescription error: {e}")
        flash('Error dispensing prescription.', 'error')
    return redirect(url_for('pharmacist_dashboard'))


# URL helpers to match earlier template expectations if different naming
app.add_url_rule('/doctor', endpoint='doctor_dashboard', view_func=doctor_dashboard)
app.add_url_rule('/patient', endpoint='patient_dashboard', view_func=patient_dashboard)
app.add_url_rule('/pharmacist', endpoint='pharmacist_dashboard', view_func=pharmacist_dashboard)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

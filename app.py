from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

from config import Config
from db import fetch_all, fetch_one, execute, execute_returning_id, table_exists, column_exists

app = Flask(__name__)
app.config.from_object(Config)


# Utilities
ROLES = {"doctor", "patient", "pharmacist"}
ROLE_TABLE = {"doctor": "doctors", "patient": "patients", "pharmacist": "pharmacists"}


def login_required(role: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("user_id") is None or session.get("role") != role:
                flash("Please log in as {}.".format(role.capitalize()), "warning")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def get_display_name_row(table: str) -> str:
    for col in ["name", "full_name", "display_name", "username"]:
        if column_exists(table, col):
            return col
    return "name"


def get_password_column(table: str) -> str:
    for col in ["password_hash", "password"]:
        if column_exists(table, col):
            return col
    return ""


def get_id_column(table: str) -> str:
    candidates_map = {
        "doctors": ["doctor_id", "id"],
        "patients": ["patient_id", "id"],
        "pharmacists": ["pharmacist_id", "id"],
        "medicines": ["med_id", "id"],
        "prescriptions": ["presc_id", "id"],
        "prescription_items": ["item_id", "id"],
        "stock": ["stock_id", "id"],
    }
    candidates = candidates_map.get(table, ["id"])
    for col in candidates:
        if column_exists(table, col):
            return col
    return candidates[0]


def find_user_by_identifier(table: str, identifier: str):
    for col in ["registration_no", "username", "email", "phone"]:
        if column_exists(table, col):
            row = fetch_one(f"SELECT * FROM {table} WHERE {col}=%s LIMIT 1", [identifier])
            if row:
                return row
    id_col = get_id_column(table)
    try:
        identifier_int = int(identifier)
        return fetch_one(f"SELECT * FROM {table} WHERE {id_col}=%s LIMIT 1", [identifier_int])
    except ValueError:
        return None


# Optional demo seeding only if these tables exist and are empty
_seed_done = False

def _seed_minimal_data():
    # Only seed if tables exist and are empty
    if table_exists("doctors"):
        count = fetch_one("SELECT COUNT(*) c FROM doctors")
        if count and count["c"] == 0 and column_exists("doctors", "username") and column_exists("doctors", "password_hash"):
            pwd = generate_password_hash("test1234")
            execute("INSERT INTO doctors (username, password_hash, name) VALUES (%s,%s,%s)", ["doc1", pwd, "Dr. Jane Doe"])
    if table_exists("patients"):
        count = fetch_one("SELECT COUNT(*) c FROM patients")
        if count and count["c"] == 0 and column_exists("patients", "username") and column_exists("patients", "password_hash"):
            pwd = generate_password_hash("test1234")
            execute("INSERT INTO patients (username, password_hash, name) VALUES (%s,%s,%s)", ["pat1", pwd, "John Patient"])
    if table_exists("pharmacists"):
        count = fetch_one("SELECT COUNT(*) c FROM pharmacists")
        if count and count["c"] == 0 and column_exists("pharmacists", "username") and column_exists("pharmacists", "password_hash"):
            pwd = generate_password_hash("test1234")
            execute("INSERT INTO pharmacists (username, password_hash, name) VALUES (%s,%s,%s)", ["pharm1", pwd, "Good Health Pharmacy"])
    if table_exists("medicines"):
        meds = fetch_all("SELECT med_id FROM medicines LIMIT 1")
        if not meds:
            for name in ["Paracetamol", "Amoxicillin", "Ibuprofen"]:
                execute("INSERT INTO medicines (name) VALUES (%s)", [name])


@app.before_request
def _ensure_seed_once():
    global _seed_done
    if _seed_done:
        return
    try:
        _seed_minimal_data()
        _seed_done = True
    except Exception:
        pass


@app.get("/")
def index():
    if session.get("user_id") and session.get("role") in ROLES:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("role")
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if role not in ROLES:
            flash("Invalid role selected.", "danger")
            return redirect(url_for("login"))
        table = ROLE_TABLE[role]
        if not table_exists(table):
            flash(f"{table} table not found in database.", "warning")
            return redirect(url_for("login"))

        user = find_user_by_identifier(table, identifier)
        if not user:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        pwd_col = get_password_column(table)
        supplied_ok = True
        if pwd_col == "password_hash":
            supplied_ok = check_password_hash(user.get(pwd_col, ""), password)
        elif pwd_col == "password":
            supplied_ok = (str(user.get(pwd_col, "")) == password)
        if not supplied_ok:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        id_col = get_id_column(table)
        session["user_id"] = user.get(id_col)
        session["username"] = identifier
        name_col = get_display_name_row(table)
        session["display_name"] = user.get(name_col, identifier) or identifier
        session["role"] = role
        flash("Welcome, {}!".format(session["display_name"]), "success")
        return redirect(url_for(f"{role}_dashboard"))

    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# Doctor
@app.get("/doctor")
@login_required("doctor")
def doctor_dashboard():
    medicines = []
    my_prescriptions = []
    if table_exists("medicines"):
        medicines = fetch_all("SELECT med_id, brand_name FROM medicines ORDER BY brand_name")
    if table_exists("prescriptions") and table_exists("prescription_items") and table_exists("patients") and table_exists("medicines"):
        pt_name_col = get_display_name_row("patients")
        my_prescriptions = fetch_all(
            f"""
            SELECT p.presc_id AS id, pt.{pt_name_col} AS patient_name, p.presc_date AS created_at, p.status,
                   GROUP_CONCAT(CONCAT(m.brand_name, ' (', COALESCE(i.dose,''), ' ', COALESCE(i.frequency,''), ', ', COALESCE(i.duration_days,''), 'd, qty ', COALESCE(i.qty_required,''), ')') SEPARATOR ', ') AS med_list
            FROM prescriptions p
            JOIN patients pt ON pt.{get_id_column('patients')} = p.patient_id
            JOIN prescription_items i ON i.presc_id = p.presc_id
            JOIN medicines m ON m.med_id = i.med_id
            WHERE p.doctor_id = %s
            GROUP BY p.presc_id, pt.{pt_name_col}, p.presc_date, p.status
            ORDER BY p.presc_date DESC
            """,
            [session["user_id"]],
        )
    return render_template("doctor.html", medicines=medicines, prescriptions=my_prescriptions)


@app.post("/doctor/prescriptions")
@login_required("doctor")
def create_prescription():
    if not (table_exists("patients") and table_exists("prescriptions") and table_exists("prescription_items")):
        flash("Prescription tables not found.", "warning")
        return redirect(url_for("doctor_dashboard"))

    patient_identifier = request.form.get("patient")
    med_id = request.form.get("medicine_id")
    dose = request.form.get("dose")
    frequency = request.form.get("frequency")
    duration_days = request.form.get("duration_days")
    qty_required = request.form.get("qty_required")

    patient = find_user_by_identifier("patients", patient_identifier)
    if not patient:
        flash("Patient not found.", "danger")
        return redirect(url_for("doctor_dashboard"))

    presc_id = execute_returning_id(
        "INSERT INTO prescriptions (doctor_id, patient_id, status) VALUES (%s, %s, 'issued')",
        [session["user_id"], patient[get_id_column("patients")]],
    )
    execute(
        "INSERT INTO prescription_items (presc_id, med_id, dose, frequency, duration_days, qty_required) VALUES (%s, %s, %s, %s, %s, %s)",
        [presc_id, med_id, dose, frequency, duration_days, qty_required],
    )
    flash("Prescription created.", "success")
    return redirect(url_for("doctor_dashboard"))


# Patient
@app.get("/patient")
@login_required("patient")
def patient_dashboard():
    my_prescriptions = []
    if table_exists("prescriptions") and table_exists("prescription_items") and table_exists("doctors") and table_exists("medicines"):
        d_name_col = get_display_name_row("doctors")
        my_prescriptions = fetch_all(
            f"""
            SELECT p.presc_id AS id, d.{d_name_col} AS doctor_name, p.status,
                   GROUP_CONCAT(CONCAT(m.brand_name, ' (', COALESCE(i.dose,''), ' ', COALESCE(i.frequency,''), ', ', COALESCE(i.duration_days,''), 'd, qty ', COALESCE(i.qty_required,''), ')') SEPARATOR ', ') AS med_list
            FROM prescriptions p
            JOIN doctors d ON d.{get_id_column('doctors')} = p.doctor_id
            JOIN prescription_items i ON i.presc_id = p.presc_id
            JOIN medicines m ON m.med_id = i.med_id
            WHERE p.patient_id = %s
            GROUP BY p.presc_id, d.{d_name_col}, p.status
            ORDER BY p.presc_date DESC
            """,
            [session["user_id"]],
        )
    return render_template("patient.html", prescriptions=my_prescriptions)


# Pharmacist
@app.get("/pharmacist")
@login_required("pharmacist")
def pharmacist_dashboard():
    pending = []
    stock = []
    medicines = []

    if table_exists("prescriptions") and table_exists("prescription_items") and table_exists("patients") and table_exists("doctors") and table_exists("medicines"):
        pt_name = get_display_name_row("patients")
        d_name = get_display_name_row("doctors")
        pending = fetch_all(
            f"""
            SELECT p.presc_id AS id, pt.{pt_name} AS patient_name, d.{d_name} AS doctor_name,
                   GROUP_CONCAT(CONCAT(m.brand_name, ' ', COALESCE(i.dose,''), ' ', COALESCE(i.frequency,''), ' x ', COALESCE(i.duration_days,''), 'd') SEPARATOR ', ') AS med_list
            FROM prescriptions p
            JOIN doctors d ON d.{get_id_column('doctors')} = p.doctor_id
            JOIN patients pt ON pt.{get_id_column('patients')} = p.patient_id
            JOIN prescription_items i ON i.presc_id = p.presc_id
            JOIN medicines m ON m.med_id = i.med_id
            WHERE p.status = 'issued'
            GROUP BY p.presc_id, pt.{pt_name}, d.{d_name}
            ORDER BY p.presc_date ASC
            """
        )

    if table_exists("stock") and table_exists("medicines"):
        stock = fetch_all(
            "SELECT s.stock_id AS id, m.brand_name AS medicine, s.qty AS quantity, s.expiry FROM stock s JOIN medicines m ON m.med_id=s.med_id ORDER BY m.brand_name"
        )

    if table_exists("medicines"):
        medicines = fetch_all("SELECT med_id AS id, brand_name AS name FROM medicines ORDER BY brand_name")

    return render_template("pharmacist.html", pending=pending, stock=stock, reservations=[], medicines=medicines)


@app.post("/pharmacist/dispense")
@login_required("pharmacist")
def dispense():
    if not table_exists("prescriptions"):
        flash("Prescriptions table not found.", "warning")
        return redirect(url_for("pharmacist_dashboard"))
    presc_id = request.form.get("prescription_id")
    # Log a row per prescription item to satisfy NOT NULL med_id in dispense_logs
    items = []
    if table_exists("prescription_items"):
        items = fetch_all("SELECT item_id, med_id, qty_required FROM prescription_items WHERE presc_id=%s", [presc_id])
    if table_exists("dispense_logs") and items:
        for it in items:
            execute(
                "INSERT INTO dispense_logs (presc_id, item_id, med_id, pharmacist_id, qty_dispensed) VALUES (%s, %s, %s, %s, %s)",
                [presc_id, it.get("item_id"), it.get("med_id"), session["user_id"], it.get("qty_required") or 0],
            )
    execute("UPDATE prescriptions SET status='dispensed' WHERE presc_id=%s", [presc_id])
    flash("Prescription dispensed.", "success")
    return redirect(url_for("pharmacist_dashboard"))


@app.post("/pharmacist/stock")
@login_required("pharmacist")
def update_stock():
    if not table_exists("stock"):
        flash("Stock table not found.", "warning")
        return redirect(url_for("pharmacist_dashboard"))

    med_id = request.form.get("medicine_id")
    qty = int(request.form.get("quantity", "0"))
    expiry = request.form.get("expiry")
    affected = execute(
        "UPDATE stock SET qty=%s, expiry=%s WHERE med_id=%s",
        [qty, expiry, med_id],
    )
    if affected == 0:
        execute(
            "INSERT INTO stock (med_id, qty, expiry) VALUES (%s, %s, %s)",
            [med_id, qty, expiry],
        )
    flash("Stock updated.", "success")
    return redirect(url_for("pharmacist_dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

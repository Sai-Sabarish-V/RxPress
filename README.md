# RxPress

## Setup

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure environment variables (or edit `config.py` defaults):

- `SECRET_KEY` – Flask secret key
- `DB_HOST` – `db-mysql-nyc3-12345-do-user-987654-0.b.db.ondigitalocean.com`
- `DB_PORT` – `25060`
- `DB_USER` – `doadmin`
- `DB_PASSWORD` – your DB password
- `DB_NAME` – `RxPress`
- `SSL_CA` – path to `certs/ca-certificate.crt`

On Windows PowerShell:

```powershell
$env:DB_PASSWORD = "your_password_here"
$env:SSL_CA = "${PWD}\certs\ca-certificate.crt"
$env:SECRET_KEY = "change-me"
```

4. Initialize the database (run in your MySQL console connected to the DO cluster):

```sql
SOURCE schema.sql;
```

5. Run the app:

```bash
python app.py
```

Visit http://localhost:5000

## Roles and Login
- Single login for Doctor, Patient, Pharmacist.
- Users are in `users` table with `role` field. Insert users manually for now.

Example user:

```sql
INSERT INTO users (username, password_hash, display_name, role)
VALUES ('doc1', '$pbkdf2-sha256$...', 'Dr. Jane', 'doctor');
```

Generate password hash in Python REPL:

```python
from werkzeug.security import generate_password_hash
print(generate_password_hash('yourpassword'))
```

## Features
- Doctor: create prescriptions, view list
- Patient: view prescriptions, search pharmacies, reserve
- Pharmacist: dispense pending prescriptions, manage stock, view reservations

## Notes
- Ensure your DO MySQL requires SSL and `certs/ca-certificate.crt` exists.
- For pharmacists, create a matching row in `pharmacies` with `user_id` of the pharmacist.

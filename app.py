from flask import Flask, request, jsonify, render_template
import mysql.connector

app = Flask(__name__)

# Database connection (your existing setup)
db = mysql.connector.connect(
    host="host_link_here",
    user="doadmin",
    password="Your_Password_Here",
    port=25060,
    database="rxpress",
    ssl_ca="Folder_link_here"
)

cursor = db.cursor(dictionary=True)

@app.route("/", methods=["GET"])
def home():
    # Render the HTML page from the templates folder
    return render_template("PatientLoginPage.html")

# Example POST route for getting patient info
@app.route("/get_patient", methods=["POST"])
def get_patient():
    aadhaar = str(request.form.get("aadhaar_no", "")).strip()
    phone = str(request.form.get("phone", "")).strip()

    if not aadhaar or not phone:
        return jsonify({"status": "error", "message": "Aadhaar and phone are required"}), 400

    query = "SELECT patient_id, aadhaar_no, name, phone, dob, gender, address FROM patients WHERE aadhaar_no = %s AND phone = %s"
    cursor.execute(query, (aadhaar, phone))
    patient = cursor.fetchone()

    if not patient:
        return jsonify({"status": "error", "message": "Patient not found"}), 404

    return jsonify({"status": "success", "patient": patient})

if __name__ == "__main__":
    app.run(debug=True)




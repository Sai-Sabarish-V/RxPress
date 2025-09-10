from flask import Flask, render_template, request, redirect, url_for, flash
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flash messages

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        aadhar = request.form.get('aadhar')
        otp = request.form.get('otp')
        generated_otp = request.form.get('generatedOtp')

        # Validate Aadhar number (exactly 12 digits)
        if not aadhar or not re.match(r'^\d{12}$', aadhar):
            flash('Aadhar number must be exactly 12 digits.', 'error')
            return render_template('login.html')

        # Validate OTP (exactly 6 digits)
        if not otp or not re.match(r'^\d{6}$', otp):
            flash('OTP must be exactly 6 digits.', 'error')
            return render_template('login.html')

        # Validate that entered OTP matches generated OTP
        if not generated_otp or otp != generated_otp:
            flash('Invalid OTP. Please enter the correct OTP.', 'error')
            return render_template('login.html')

        # If all validations pass
        flash(f'Login successful for Aadhar: {aadhar}!', 'success')
        return redirect(url_for('home'))

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

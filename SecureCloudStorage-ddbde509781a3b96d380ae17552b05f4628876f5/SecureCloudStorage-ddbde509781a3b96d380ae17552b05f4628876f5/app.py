from flask import Flask, render_template, request, redirect, session, send_file
from models import db, User, File
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import bcrypt
import os
import tempfile
import pyotp
import random
import boto3

from aws_config import (
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    BUCKET_NAME,
    REGION
)

otp_store = {}
activity_logs = []

app = Flask(__name__)

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)

app.secret_key = "securecloud123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        hashed_password = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        ).decode()
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return "Email already registered. Please login."

        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.checkpw(
            password.encode(),
            user.password_hash.encode()
        ):

            otp = str(random.randint(100000, 999999))

            otp_store[user.email] = otp

            print(f"OTP for {user.email}: {otp}")

            session['temp_user_id'] = user.id
            session['temp_email'] = user.email

            return redirect('/mfa')

        return "Invalid Email or Password"

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])

    file_count = File.query.filter_by(
        owner_id=session['user_id']
    ).count()

    return render_template(
        'dashboard.html',
        user=user,
        file_count=file_count
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload():

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':

        file = request.files['file']

        if file.filename == '':
            return "No file selected"

        if not os.path.exists('uploads'):
            os.makedirs('uploads')

        filename = secure_filename(file.filename)

        filepath = os.path.join(
            'uploads',
            filename
        )

        file_data = file.read()

        with open("key.key", "rb") as key_file:
            key = key_file.read()

        cipher = Fernet(key)

        encrypted_data = cipher.encrypt(file_data)

        with open(filepath, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        try:
            s3.upload_file(
                filepath,
                BUCKET_NAME,
                f"encrypted/{filename}"
            )
            print("File uploaded to S3 successfully")

        except Exception as e:
            print("S3 Upload Skipped:", e)

        new_file = File(
            filename=filename,
            encrypted_path=filepath,
            owner_id=session['user_id']
        )

        db.session.add(new_file)
        db.session.commit()
        activity_logs.append(
    f"User {session['user_id']} uploaded {filename}"
)

        return redirect('/files')

    return render_template('upload.html')

@app.route('/files')
def files():


    if 'user_id' not in session:
        return redirect('/login')

    user_files = File.query.filter_by(
        owner_id=session['user_id']
    ).all()

    return render_template(
        'files.html',
        files=user_files
    )


@app.route('/download/<int:file_id>')
def download(file_id):

    if 'user_id' not in session:
        return redirect('/login')

    file_record = File.query.get_or_404(file_id)
    activity_logs.append(
    f"User {session['user_id']} downloaded {file_record.filename}"
)

    with open("key.key", "rb") as key_file:
        key = key_file.read()

    cipher = Fernet(key)

    with open(file_record.encrypted_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    temp_file = tempfile.NamedTemporaryFile(
        delete=False
    )

    temp_file.write(decrypted_data)
    temp_file.close()

    return send_file(
        temp_file.name,
        as_attachment=True,
        download_name=file_record.filename
    )


@app.route('/mfa', methods=['GET', 'POST'])
def mfa():

    if 'temp_user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':

        entered_otp = request.form.get('otp')
        email = session['temp_email']

        if otp_store.get(email) == entered_otp:

            session['user_id'] = session['temp_user_id']
            activity_logs.append(
    f"{session['temp_email']} logged in"
)

            session.pop('temp_user_id', None)
            session.pop('temp_email', None)

            return redirect('/dashboard')

        return "Invalid OTP"

    return render_template('mfa.html')


@app.route('/admin')
def admin():

    if 'user_id' not in session:
        return redirect('/login')

    current_user = User.query.get(
        session['user_id']
    )

    if current_user.role != 'admin':
        return "Access Denied"

    users = User.query.all()

    return render_template(
        'admin.html',
        users=users
    )

@app.route('/logs')
def logs():

    if 'user_id' not in session:
        return redirect('/login')

    return render_template(
        'logs.html',
        logs=activity_logs
    )

@app.route('/test-s3')
def test_s3():

    try:
        response = s3.list_buckets()

        bucket_names = []

        for bucket in response['Buckets']:
            bucket_names.append(bucket['Name'])

        return "<br>".join(bucket_names)

    except Exception as e:
        return str(e)
    
if __name__ == '__main__':
    app.run(debug=True)
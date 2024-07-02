from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
from cryptography.fernet import Fernet
from flask_bcrypt import Bcrypt
import base64
import os
import modules.streaming

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = 'mysecretkey'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306

app.config['UPLOAD_FOLDER'] = 'static/face_images'

mysql = MySQL(app)

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username=%s', (username,))
        account = cursor.fetchone()
        if account and bcrypt.check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

@app.route('/face_login', methods=['POST'])
def face_login():
    msg = ''
    if 'face_recognition' in request.form:
        try:
            result = modules.streaming.analysis(
                db_path='static/face_images',
                model_name='VGG-Face',
                detector_backend='opencv',
                distance_metric='cosine',
                enable_face_analysis=False,
                source=0,  # This should be the index of the camera
                time_threshold=5,
                frame_threshold=5,
                anti_spoofing=False
            )
            if result['status'] == 'success' and result['verified']:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE face_image = %s', (result['target_label'],))
                account = cursor.fetchone()
                if account:
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                    return redirect(url_for('home'))
                else:
                    msg = 'Face recognition failed! Account not found.'
            else:
                msg = 'Face recognition failed!'
        except Exception as e:
            msg = f'Spoof Detected'
        return render_template('index.html', msg=msg)

    return render_template('index.html', msg="Face recognition not attempted")

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        face_image_data = request.form['face_image_data']
        face_image_file = request.files.get('face_image_file')

        if face_image_data or face_image_file:
            if face_image_data:
                face_image_data = face_image_data.split(',')[1]
                face_image = base64.b64decode(face_image_data)
                face_image_filename = os.path.join(app.config['UPLOAD_FOLDER'], f'{username}.jpg')
                with open(face_image_filename, 'wb') as f:
                    f.write(face_image)
            elif face_image_file:
                face_image_filename = os.path.join(app.config['UPLOAD_FOLDER'], f'{username}.jpg')
                face_image_file.save(face_image_filename)

            key = Fernet.generate_key()
            with open("symmetric.key", "wb") as fo:
                fo.write(key)
            f = Fernet(key)

            encrypted_email = f.encrypt(email.encode())
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO accounts (username, password, email, face_image) VALUES (%s, %s, %s, %s)',
                           (username, hashed_password, encrypted_email, face_image_filename))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
        else:
            msg = 'Please take a picture or upload an image!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'

    return render_template('register.html', msg=msg)

@app.route('/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

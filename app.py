from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from flask import send_file
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)

import config_email
app.config['MAIL_SERVER'] = config_email.MAIL_SERVER
app.config['MAIL_PORT'] = config_email.MAIL_PORT
app.config['MAIL_USE_TLS'] = config_email.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config_email.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config_email.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config_email.MAIL_DEFAULT_SENDER

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

DB_NAME = 'parcurs.db'

def init_db():
    created = False
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''CREATE TABLE parcurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            zona TEXT NOT NULL,
            scop TEXT,
            km INTEGER NOT NULL,
            data TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        conn.commit()
        conn.close()
        created = True
    # Migrare: adaugă coloana data dacă nu există
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("PRAGMA table_info(parcurs)")
    columns = [col[1] for col in c.fetchall()]
    if 'data' not in columns:
        c.execute('ALTER TABLE parcurs ADD COLUMN data TEXT NOT NULL DEFAULT ""')
        conn.commit()
    if 'scop' not in columns:
        c.execute('ALTER TABLE parcurs ADD COLUMN scop TEXT')
        conn.commit()

    c.execute('SELECT * FROM users WHERE username=?', ('Admin',))
    if not c.fetchone():
        from werkzeug.security import generate_password_hash
        hash_pw = generate_password_hash('Baumit123')
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('Admin', hash_pw))
        conn.commit()
    conn.close()

def migrate_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Migrare tabel parcurs
    c.execute("PRAGMA table_info(parcurs)")
    columns = [col[1] for col in c.fetchall()]
    if 'nume' in columns:
        c.execute('SELECT id, zona, km FROM parcurs')
        old_rows = c.fetchall()
        c.execute('DROP TABLE parcurs')
        c.execute('''CREATE TABLE parcurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            zona TEXT NOT NULL,
            km INTEGER NOT NULL
        )''')
        for row in old_rows:
            c.execute('INSERT INTO parcurs (id, username, zona, km) VALUES (?, ?, ?, ?)', (row[0], '', row[1], row[2]))
        conn.commit()
    # Migrare tabel users
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not c.fetchone():
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        conn.commit()
    conn.close()

init_db()
migrate_db()


# Înregistrare
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash_pw = generate_password_hash(password)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hash_pw))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username-ul există deja!')
            return render_template('register.html')
        conn.close()
        flash('Cont creat! Acum te poți loga.')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Username sau parolă greșită!')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    import datetime
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    if request.method == 'POST':
        zona = request.form['zona']
        scop = request.form.get('scop', '')
        km = request.form['km']
        data = request.form.get('data') or datetime.date.today().isoformat()
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('INSERT INTO parcurs (username, zona, scop, km, data) VALUES (?, ?, ?, ?, ?)', (username, zona, scop, km, data))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if username == 'Admin':
        c.execute('SELECT * FROM parcurs ORDER BY data DESC, id DESC')
        export_btn = True
    else:
        c.execute('SELECT * FROM parcurs WHERE username=? ORDER BY data DESC, id DESC', (username,))
        export_btn = False
    rows = c.fetchall()
    conn.close()
    today = datetime.date.today().isoformat()
    return render_template('index.html', rows=rows, username=username, today=today, export_btn=export_btn)

# Export Excel pentru admin
@app.route('/export')
def export():
    if 'username' not in session or session['username'] != 'Admin':
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query('SELECT * FROM parcurs', conn)
    conn.close()
    # Reordonez coloanele pentru export
    df = df[['username', 'zona', 'scop', 'km', 'data']]
    file_path = 'foaie_parcurs.xlsx'
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if username == 'Admin':
        # Admin poate edita orice
        if request.method == 'POST':
            zona = request.form['zona']
            scop = request.form.get('scop', '')
            data = request.form.get('data')
            km = request.form['km']
            new_username = request.form.get('username')
            c.execute('UPDATE parcurs SET username=?, zona=?, scop=?, data=?, km=? WHERE id=?', (new_username, zona, scop, data, km, id))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        c.execute('SELECT * FROM parcurs WHERE id=?', (id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return "Nu există această înregistrare!", 404
        return render_template('edit.html', row=row, is_admin=True)
    else:
        # Utilizatorul poate edita doar propriile înregistrări
        if request.method == 'POST':
            zona = request.form['zona']
            scop = request.form.get('scop', '')
            data = request.form.get('data')
            km = request.form['km']
            c.execute('UPDATE parcurs SET zona=?, scop=?, data=?, km=? WHERE id=? AND username=?', (zona, scop, data, km, id, username))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        c.execute('SELECT * FROM parcurs WHERE id=? AND username=?', (id, username))
        row = c.fetchone()
        conn.close()
        if not row:
            return "Nu ai acces la această înregistrare!", 403
        return render_template('edit.html', row=row, is_admin=False)


# Forgot password (request reset)

# Forgot password (request reset)
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    message = None
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE username=?', (email,))
        user = c.fetchone()
        conn.close()
        if user:
            # Generate token
            token = serializer.dumps(email, salt='reset-password')
            reset_url = url_for('reset_password', token=token, _external=True)
            # Send email
            try:
                msg = Message('Resetare parolă Foaie Parcurs', recipients=[email])
                msg.body = f"Salut!\n\nPentru a reseta parola, accesează linkul: {reset_url}\n\nDacă nu ai cerut resetarea, ignoră acest mesaj."
                mail.send(msg)
                message = 'Un link de resetare a fost trimis pe email.'
            except Exception as e:
                message = f'Eroare la trimiterea emailului: {e}'
        else:
            message = 'Acest email nu există în sistem.'
        return render_template('forgot.html', message=message)
    return render_template('forgot.html')

# Password reset form
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    message = None
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except Exception:
        return 'Link expirat sau invalid!', 400
    if request.method == 'POST':
        password = request.form['password']
        hash_pw = generate_password_hash(password)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('UPDATE users SET password=? WHERE username=?', (hash_pw, email))
        conn.commit()
        conn.close()
        message = 'Parola a fost resetată! Acum te poți loga.'
        return render_template('reset.html', message=message)
    return render_template('reset.html', email=email)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

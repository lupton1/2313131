from flask import Flask
from flask import request
from flask import render_template
from flask import redirect
from flask import session

import re
import secrets
import sqlite3
import os
import random
import string
import bleach
import hashlib # for sha256 password hashing

app = Flask(__name__,static_folder='static', static_url_path='')

# set the app secret key to something cryptographically random
app.secret_key = secrets.token_hex(32)

# get the directory where this python file lives
APP_PATH = os.path.dirname(os.path.abspath(__file__))

# generate a random value for password hashing
APP_PEPPER = secrets.token_urlsafe(22)

def generate_password_hash(username, password, salt=""):
    hash = hashlib.sha256((APP_PEPPER + username + password + salt).encode()).hexdigest()
    return hash

def store_password_hash(hash):
    connection = sqlite3.connect("database.db")
    sql = 'INSERT INTO passwords (password) VALUES (?);'
    cursor = connection.cursor()
    cursor.execute(sql, [hash])
    connection.commit()
    connection.close()

def generate_salt():
    return secrets.token_hex(32)

# we simulate an administrator to chooses a strong password
admin_password = ''.join(random.choices(string.ascii_letters+string.digits+string.punctuation, k=16))
admin_salt = generate_salt()
admin_password_hash = generate_password_hash("admin", admin_password, admin_salt)

app.logger.debug(f"admin password: {admin_password}")


def init_database():
    if os.path.isfile("database.db"):
        raise Exception("Database already exists!")
    
    connection = sqlite3.connect("database.db")
    sql = """
                DROP TABLE IF EXISTS messages;
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    postedby VARCHAR(32),
                    content VARCHAR(140),
                    timestamp TIMESTAMP DEFAULT (datetime('now','localtime')));
                DROP TABLE IF EXISTS users;
                CREATE TABLE users ( 
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username VARCHAR(32),
                    salt VARCHAR(64),
                    login_attempts INTEGER DEFAULT 0);
                INSERT INTO users (username, salt) VALUES ("admin", "%s");
                
                DROP TABLE IF EXISTS passwords;
                CREATE TABLE passwords ( 
                    password VARCHAR(64));

              """ % (admin_salt)
    cursor = connection.cursor()
    cursor.executescript(sql)
    connection.close()

    k = random.randint(100,400)
    for i in range(500):
        if i == k:
            store_password_hash(admin_password_hash)
        username = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
        password = ''.join(random.choices(string.ascii_letters+string.digits+string.punctuation, k=16))
        salt = generate_salt()
        store_password_hash(generate_password_hash(username, password, salt))

# re-initialise the database on app startup
init_database()

def get_messages_for_user(username):
    connection = sqlite3.connect("database.db")    
    sql = "SELECT * FROM messages WHERE postedby=?;"
    cursor = connection.cursor()
    cursor.execute(sql,[username])
    result = cursor.fetchall()
    messages = []
    for r in result:
        msg = {"id": r[0], "postedby": r[1], "content": r[2], "timestamp": r[3]}
        messages.append(msg)
    return messages

def get_messages(query=""):
    connection = sqlite3.connect("database.db")
    if query:
        sql = f"SELECT * FROM messages WHERE content LIKE '%{query}%'"
    else:
        sql = "SELECT * FROM messages"
    cursor = connection.cursor()
    cursor.execute(sql)
    result = cursor.fetchall()
    messages = []
    for r in result:
        msg = {"id": r[0], "postedby": r[1], "content": r[2], "timestamp": r[3]}
        messages.append(msg)
    return messages

@app.route('/')
def index():
    if 'username' not in session:
        return render_template("login.html")
    
    try:
        page = int(request.args.get('page'))
    except:
        page = 1
    
    messages = get_messages()
    msg = messages[(page-1)*10:page*10]

    total_page = (len(messages) + 9) // 10
    previous_page = next_page = 0
    if page-1 >= 1:
        previous_page = min(page - 1, total_page)
    if page+1 <= total_page:
        next_page = max(page + 1, 1)
    
    return render_template('app.html', session=session, messages=msg, previous_page=previous_page, next_page=next_page)

@app.route('/search', methods=['GET'])
def search():
    if 'username' not in session:
        return '<a href="/login">Log in</a> first'

    query = request.args.get('query')
    query = query.replace(" ", "")
    if not query:
        return redirect('/')
    
    messages = get_messages(query)
    
    return render_template('app.html', session=session, messages=messages, query=query)

@app.route('/deletemsg', methods=['POST'])
def delete_msg():
    if 'username' not in session:
        return '<a href="/login">Log in</a> first'

    id = request.form['id']
    if not id:
        return "No id parameter set"
    
    sql = "SELECT postedby FROM messages WHERE id=?"
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    cursor.execute(sql,[id])
    result = cursor.fetchall()
    connection.close()

    if len(result) == 0:
        return "Message not found", 404
    
    if result[0][0] != session['username'] and session['username'] != 'admin':
        return "Cannot delete others' messages", 401
    
    sql = "DELETE FROM messages WHERE id=?"
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()            
    cursor.execute(sql,[id])
    connection.commit()
    connection.close()

    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'][:32]
        connection = sqlite3.connect("database.db")
        sql = "SELECT username,salt,login_attempts FROM users WHERE username=?;"
        cursor = connection.cursor()
        cursor.execute(sql,[username])
        result = cursor.fetchall()
        connection.close()
        
        lockout=False
        if len(result) != 0:
            if result[0][2] < 3:
                attempt_hash = generate_password_hash(username,password,result[0][1])
                connection = sqlite3.connect("database.db")
                sql = "SELECT * FROM passwords WHERE password=?;"
                cursor = connection.cursor()
                cursor.execute(sql,[attempt_hash])
                pwd_result = cursor.fetchall()
                connection.close()

                if len(pwd_result) > 0:
                    session['username'] = result[0][0]

                    # reset invalid login attempts counter
                    sql = "UPDATE users SET login_attempts = 0 WHERE username = ?"
                    connection = sqlite3.connect("database.db")
                    cursor = connection.cursor()            
                    cursor.execute(sql,[username])
                    connection.commit()
                    connection.close()
                
                    return redirect('/')
            
                # invalid login attempt
                sql = "UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?"
                connection = sqlite3.connect("database.db")
                cursor = connection.cursor()            
                cursor.execute(sql,[username])
                connection.commit()
                connection.close()
            else:
                lockout=True                
        return render_template('login.html', error=True, lockout=lockout, user=None), 401
    else:
        return render_template('login.html',error=False,lockout=False,user=None), 200

@app.route('/changepassword', methods=['POST','GET'])
def changepassword():
    if 'username' not in session:
        return "Access denied", 403
    
    if request.method == 'GET':
        return render_template("changepassword.html", user=session["username"])
    
    username = request.form['username']
    password = request.form['password']
    salt = generate_salt()

    connection = sqlite3.connect("database.db")
    sql = f"UPDATE users SET salt='{salt}' WHERE username='{username}'"
    cursor = connection.cursor()
    cursor.execute(sql)
    connection.commit()
    connection.close()

    store_password_hash(generate_password_hash(username, password, salt))

    # add some dummy password hashes
    for i in range(random.randint(0,5)):
        store_password_hash(generate_password_hash(''.join(random.choices(string.ascii_letters+string.digits, k=12)), ''.join(random.choices(string.ascii_letters+string.digits+string.punctuation, k=16)), generate_salt()))

    return "Password changed. <a href='/'>Home</a>", 200

@app.route('/post', methods=['POST'])
def post():
    if 'username' in session and request.form['msg']:
        username = session['username']
        msg = request.form['msg']
        # sanitise all messages
        msg = bleach.clean(msg)
        if len(msg) <= 140:
            connection = sqlite3.connect("database.db")
            sql = 'INSERT INTO messages (postedby, content) VALUES (?, ?);'
            cursor = connection.cursor()
            cursor.execute(sql,[username,msg])
            connection.commit()
            connection.close()
            return redirect('/')
    if 'username' not in session:
        return f'<a href="/login">Log in</a> first.', 401
    else:
        return "No msg provided or msg is too long.", 400

def sanitize_username(username):
    # Remove any potential HTML tags
    sanitized_username = re.sub(r'<.*>', '', username)
    # Limit length to 12 characters    
    sanitized_username = sanitized_username[:12]
    return sanitized_username

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'][:32]

        s = sanitize_username(username)
        if s != username:
            return "Invalid username, no HTML tag allowed.", 400
        
        connection = sqlite3.connect("database.db")
        sql = "SELECT * FROM users WHERE username=?"
        cursor = connection.cursor()
        cursor.execute(sql,[username])
        result = cursor.fetchall()
        connection.close()
        if len(result) > 0:
            # user already exists
            return render_template('signup.html', error=True), 400
        else:
            salt = generate_salt()
            connection = sqlite3.connect("database.db")
            sql = 'INSERT INTO users (username, salt) VALUES (?, ?);'
            cursor = connection.cursor()
            cursor.execute(sql,[username,salt])
            connection.commit()
            connection.close()
            store_password_hash(generate_password_hash(username, password, salt))
            return redirect('login')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    # Clear the session cookie
    session.pop('username', None)
    return redirect('/')

if __name__ == "__main__":
    # when debug=True, use_reloader needs to be False to prevent the
    # initialisation code (which generates the admin password, etc.)
    # from being executed more than once
    app.run(debug=True,host='0.0.0.0',port=80,use_reloader=False)

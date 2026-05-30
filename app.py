from argon2 import PasswordHasher
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_session import Session
from helpers import connect_to_db, login_required
import os


# Instatiate Flask object creating an application instance.
app = Flask(__name__)

# Read variables from .env file and set them in os.environ
load_dotenv()

# Setup cookie configuration.
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY")
app.config["SESSION_PERMANENT"] = False

# Initializes flask-session.
Session(app)


# Routes
@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if username is None:
        flash("Missing username", category="flash_error")
        return render_template("index.html")
    if password is None:
        flash("Missing password", category="flash_error")
        return render_template("index.html")

    ph = PasswordHasher()

    connect_to_db()

    user_info = g.db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username, )).fetchone()
    
    if user_info is None:
        flash("No user detected")
        return render_template("login.html")
    
    try:
        ph.verify(user_info["password"], password)
        session["user_id"] = user_info["id"]
        return redirect(url_for("index"))
    except:
        flash("Incorrect password")
        return render_template("login.html")
    


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if username is None:
        flash("Username required", category="flash_error")
        return render_template("register.html")
    if password is None: 
        flash("Password required", category="flash_error")
        return render_template("register.html")
    if password != confirmation:
        flash("Password does not match password confirmation")
        return render_template("index.html")
    
    # Connect to db.
    connect_to_db()

    # Make sure username isnt already in use.
    if g.db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone() is not None:
        flash("Username already taken", category="flash_error")
        return render_template("register.html")
    
    # Create instance if PasswordHasher.
    ph = PasswordHasher()

    # Create new user.
    g.db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, ph.hash(password)))

    flash("Registered Successfully", category="flash_success")
    return redirect(url_for("login"))


# Close db connection after every request.
@app.teardown_request
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()
    
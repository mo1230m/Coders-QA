import os

from datetime import datetime
import jinja2
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///qa.db")

# time formating
def datetimeformat(value):
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d %B, %Y")
jinja2.filters.FILTERS['dtf'] = datetimeformat

@app.route("/")
def index():
    if session.get("user_id") is None:
        raws = db.execute("SELECT questions.id, title, content, answers, time, username FROM questions JOIN users ON users.id=questions.uid ORDER BY time DESC LIMIT 20;")
        return render_template("home.html", questions=raws)
    else:
        raws = db.execute("SELECT questions.id, title, content, answers, time, username FROM questions JOIN users ON users.id=questions.uid WHERE uid=? ORDER BY time DESC;", session["user_id"])
        empty = False
        if len(raws) == 0:
            empty = True
        return render_template("index.html", questions=raws, empty=empty)


@app.route("/home")
def home():
    raws = db.execute("SELECT questions.id, title, content, answers, time, username FROM questions JOIN users ON users.id=questions.uid ORDER BY time DESC LIMIT 20;")
    return render_template("home.html", questions=raws)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    # """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# Change password
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def password():
    # """Change Password"""
    if request.method == "GET":
        return render_template("change-password.html")
    else:
        rows = db.execute("SELECT hash FROM users WHERE id=?", session["user_id"])
        password = request.form.get("password")
        password_confirmation = request.form.get("confirmation")
        if not check_password_hash(rows[0]["hash"], request.form.get("current")):
            return apology("Password is incorrect!")
        elif not password or password != password_confirmation:
            return apology("Passwords doesn't match!")
        db.execute("UPDATE users SET hash=:hashpass WHERE id=:uid;", hashpass=generate_password_hash(password), uid=session["user_id"])
        return redirect("/logout")


# New user validation & registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        usercheck = db.execute("SELECT username FROM users WHERE username=?;", username)
        if not username or len(usercheck) == 1:
            flash('Username is already taken!')
            return redirect(url_for('register'))
        if len(db.execute("SELECT username FROM users WHERE username=?", username)) == 1:
            return render_template("register.html", message="Username already exists!")
        password = request.form.get("password")
        password_confirmation = request.form.get("confirmation")
        if not password or password != password_confirmation:
            return render_template("register.html", passerr="Passwords doesn't match!")
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashpass)", username=username, hashpass=generate_password_hash(password))
        row = db.execute("SELECT id FROM users WHERE username=?", username)
        # Remember which user has logged in
        session["user_id"] = row[0]["id"]
        flash('You have been successfully registered!')
        return redirect(url_for('home'))


# Add question
@app.route("/ask", methods=["GET", "POST"])
@login_required
def ask():
    """Ask a question"""

    if request.method == "GET":
        return render_template("ask.html")
    else:
        # Time now
        now = datetime.now()
        if len(request.form.get("title")) < 15:
            return apology("You must enter a describing title!")
        db.execute("INSERT INTO questions (uid, title, content, time) VALUES (?, ?, ?, ?);",
                    session["user_id"], request.form.get("title"), request.form.get("question"), now.strftime("%Y-%m-%d %H:%M:%S"))
        return redirect("/")

# Question page
@app.route('/<question_id>', methods=["GET", "POST"])
def question_page(question_id):
    if request.method == "GET":
        question = db.execute("SELECT title, content, time, answers, username FROM questions JOIN users ON users.id=questions.uid WHERE questions.id=?;", question_id)
        if len(question) == 0:
            return apology("Not Found", 404)
        answers = db.execute("SELECT content, time, username FROM answers JOIN users ON users.id=answers.uid WHERE answers.id=?;", question_id)
        return render_template("question.html", title=question[0]["title"], content=question[0]["content"], qid=question_id, time=question[0]["time"], answers_count=question[0]["answers"], user=question[0]["username"], answers=answers)
    else:
        if session.get("user_id") is None:
            return redirect("/login")
        # Time now
        now = datetime.now()
        db.execute("INSERT INTO answers (uid, id, content, time) VALUES (?, ?, ?, ?);",
                    session["user_id"], question_id, request.form.get("answer"), now.strftime("%Y-%m-%d %H:%M:%S"))
        db.execute("UPDATE questions SET answers = answers+1 WHERE id=?;", question_id)
        return redirect(f"/{question_id}")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

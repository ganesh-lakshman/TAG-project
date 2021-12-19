import os
import re
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, mrp

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

# Custom filter
app.jinja_env.filters["mrp"] = mrp

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
#if not os.environ.get("API_KEY"):
 #   raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])
    cash = cash[0]["cash"]
    values = db.execute("SELECT sum(value), name FROM shares WHERE id = ? GROUP BY name",session["user_id"])
    print(values)
    prices = []
    total = 0
    for value in values:
        number = value["sum(value)"]
        name = value["name"]
        #quote = lookup(symbol)
        quote = db.execute("SELECT * FROM product WHERE name = ?", name)
        if number != 0:
            prices.append({'name':quote[0]["name"], 'number':value["sum(value)"], 'price':mrp(quote[0]["price"]), 'total':mrp(quote[0]["price"] * number)})
        total = number * quote[0]["price"] + total
    total = total + cash
    cash = mrp(cash)
    total = mrp(total)
    if session['key'] != 0 :
        alert = session['key']
    else:
        alert = 0
    #alert = request.args.get("alert")
    return render_template("index.html", prices = prices,cash = cash, total = total, alert = alert)





@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":

        name = request.form.get("name")
        #if not lookup(symbol):
         #   return apology("symbol does not exist")
        number = int(request.form.get("number"))
        if number <= 0:
            return apology("input is not a positive integer")
        quote = db.execute("SELECT * FROM product WHERE name = ?", name)
        print(quote)
        name = quote[0]["name"]
        price = quote[0]["price"]
        #symbol = quote["symbol"]
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])
        # user_id symbol of stock bought number of stocks money spent remaining money
        cash = cash[0]["cash"]
        if cash >= (number * price):

            #db.execute("UPDATE users SET cash = :cash WHERE id = :id",cash = cash - (shares * price), id = session["user_id"])
            db.execute("INSERT INTO buy (id, name, price, number, total) VALUES (?,?,?,?,?)", session["user_id"], quote[0]["name"], quote[0]["price"], number, number * price )
            db.execute("INSERT INTO shares (id, number, name, cash, value) VALUES (?,?,?,?,?)", session["user_id"], number, quote[0]["name"], cash - (number * price), 1 * number)
            db.execute("UPDATE users SET cash = ? WHERE id = ?",cash - (number * price), session["user_id"])
            alert = "Bought!"
            session['key'] = alert
            return redirect("/")
        else:
            return  apology("not enough cash", 403)



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    values = db.execute("SELECT value, name, timestamp FROM shares WHERE id = ? ",session["user_id"])
    print(values)
    prices = []
    for value in values:
        name = value["name"]
        timestamp = value["timestamp"]
        #quote[0] = lookup(symbol)
        quote = db.execute("SELECT * FROM product WHERE name = ?", name)
        prices.append({'name':quote[0]["name"],'timestamp':timestamp, 'number':value["value"], 'price':quote[0]["price"]})

    print(prices)

    return render_template("history.html", prices = prices)



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
        session["key"] = 0

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("search.html")
    else:
        name = request.form.get("name")
        if not name:
            return apology("must provide a name", 403)
        #quote = lookup(symbol)
        #price = mrp(quote["price"])
        details = db.execute("SELECT * FROM product WHERE name = ?", name)
        print(details)

        return render_template("searched.html",details = details)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 403)
        if username in db.execute("SELECT username FROM users"):
            return apology("username already exists", 403)

        password = request.form.get("password")
        if not password:
            return apology("must provide password", 403)
        def password_check(password):

        #Verify the strength of 'password'
        #Returns a dict indicating the wrong criteria
        #A password is considered strong if:
        #8 characters length or more
        #1 digit or more
        #1 symbol or more
        #1 uppercase letter or more
        #1 lowercase letter or more

            # calculating the length
            length_error = len(password) < 8 or len(password) > 30

            # searching for digits
            digit_error = re.search(r"\d", password) is None

            # searching for uppercase
            uppercase_error = re.search(r"[A-Z]", password) is None

            # searching for lowercase
            lowercase_error = re.search(r"[a-z]", password) is None

            # searching for symbols
            symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

            # overall result
            password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

            return {
                'password_ok' : password_ok,
                'length_error' : length_error,
                'digit_error' : digit_error,
                'uppercase_error' : uppercase_error,
                'lowercase_error' : lowercase_error,
                'symbol_error' : symbol_error,
                }
        check = password_check(password)
        if check['password_ok'] == 1:
            confirmation = request.form.get("confirmation")
            if confirmation != password:
                return apology("passwords donot match", 403)
            hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)",request.form.get("username"),generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            return redirect("/")
        else:
            return apology("password constraint didnt match",403)

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        row = db.execute("SELECT DISTINCT name FROM shares WHERE id = ?",session["user_id"])
        print(row)
        return render_template("sell.html",row=row)
    elif request.method == "POST":
        name = request.form.get("name")
        number = int(request.form.get("number"))
        #quote = lookup(symbol)
        quote = db.execute("SELECT * FROM product WHERE name = ?", name)
        name = quote[0]["name"]
        price = quote[0]["price"]
        #symbol = quote["symbol"]
        value = db.execute("SELECT sum(value) FROM shares WHERE id = ? AND name = ?",session["user_id"], name)
        if number <= value[0]['sum(value)']:
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])
            cash = cash[0]["cash"]
            db.execute("INSERT INTO sell (id, name, price, number, total) VALUES (?,?,?,?,?)", session["user_id"], quote[0]["name"], quote[0]["price"], number, number * price )
            db.execute("INSERT INTO shares (id, number, name, cash, value) VALUES (?,?,?,?,?)", session["user_id"], number, quote[0]["name"], cash + (number * price), (-1) * number)
            db.execute("UPDATE users SET cash = ? WHERE id = ?",cash + (number * price), session["user_id"])
            alert = "Sold!"
            session['key'] = alert
            return redirect("/")
        else:
            return apology("not enough shares",403)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return render_template("add.html")
    else:
        cash = int(request.form.get("cash"))
        rows = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])
        cash = cash + rows[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        alert = "Added!"
        session['key'] = alert
        return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        return render_template("change.html")
    else:
        rows = db.execute("SELECT * FROM users WHERE id = ?",session["user_id"])
        if check_password_hash(rows[0]["hash"], request.form.get("password")):
            new = request.form.get("newpassword")
            if check_password_hash(rows[0]["hash"], new):
                return apology("this is same as the previos password")

            else:
                hash = generate_password_hash(new, method='pbkdf2:sha256', salt_length=8)
                db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new, method='pbkdf2:sha256', salt_length=8), session["user_id"])
                alert = "Changed!"
                session['key'] = alert
                return redirect("/")


        else:
            apology("enter correct password",403)

    return apology("todo",403)
@app.route("/list", methods=["GET", "POST"])
@login_required
def list():
    if request.method == "GET":
        product = db.execute("SELECT * FROM product")
        return render_template("list.html", product = product)
@app.route("/item", methods=["GET", "POST"])
@login_required
def item():
    if request.method == "GET":
        return render_template("item.html")
    else:
        name = request.form.get("name")
        if name in db.execute("SELECT name FROM product"):
            return apology("item already exist", 403)
        else:
            price = request.form.get("price")
            description = request.form.get("description")
            db.execute("INSERT INTO product (name, price, description) VALUES (?, ?, ?)", name, price, description)
            return redirect("/list")





def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

import os
import time

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, pass_scope, name_scope, shares_scope

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]

    # Query the database for portfolio and account balance based on user id
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = ?", user_id)
    balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total_stock = 0

    # Portfolio is empty
    if [] == portfolio:
        return render_template("index.html", stock=usd(total_stock), cash=usd(balance), total=usd(balance))

    else:
        i = 0
        # Iterate through the portfolio and format values in USD for rendering
        for stock in portfolio:
            current_price = lookup(stock["symbol"])["price"]
            portfolio[i]["current_price"] = usd(current_price)
            total_price = current_price * portfolio[i]["shares"]
            portfolio[i]["total_price"] = usd(round(total_price, 2))
            total_stock += total_price
            i += 1

    # Format calculated values in USD
    total = usd(round(total_stock + balance))
    total_stock = usd(round(total_stock))
    balance = usd(balance)

    # Export to template formatted values
    return render_template("index.html", portfolio=portfolio, stock=total_stock, cash=balance, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            flash("symbol does not exist", "warning")
            return apology("no symbol", 403)

        # Ensure shares was submitted
        elif not request.form.get("shares"):
            flash("number of shares not provided", "warning")
            return apology("no shares", 403)

        # Ensure shares are in scope
        elif not shares_scope(request.form.get("shares")):
            flash("number of shares must be a positive integer", "danger")
            return apology("no shares", 400)

        try:
            # Call API for input symbol
            symbol = lookup(request.form.get("symbol"))
            price = symbol["price"]
            name = symbol["name"]
            the_symbol = symbol["symbol"]

        # Handle bad symbol
        except TypeError:
            flash("symbol does not exist", "warning")
            return apology("no symbol", 400)

        # Prepare the rest of the required data
        activity = "buy"
        user_id = session["user_id"]
        shares = int(request.form.get("shares"))
        total_price = round(price * float(shares), 2)

        # Make a timestamp in unix time
        epoch_time = int(time.time())

        # Query the database for account balance
        balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        # User has cash to trade
        if balance >= total_price:
            # Calculate the new account balance and update the database
            balance = round(balance - total_price, 2)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)

            # Insert the trade history into the database
            db.execute("INSERT INTO exchange (symbol, name, shares, activity, at_price, total_price, epoch_time, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       the_symbol, name, shares, activity, price, total_price, epoch_time, user_id)

            # Query the database for portfolio
            portfolio = db.execute("SELECT shares FROM portfolio WHERE symbol = ? AND user_id = ?", the_symbol, user_id)

            # The user does not have shares of input symbol in portfolio
            if [] == portfolio:
                # Insert it into the database
                db.execute("INSERT INTO portfolio (symbol, name, shares, user_id) VALUES (?, ?, ?, ?)",
                           the_symbol, name, shares, user_id)

            # Shares of input symbol already exist in the user's portfolio
            else:
                # Update the new value of the total shares in the database
                portfolio_shares = int(portfolio[0]["shares"])
                shares = portfolio_shares + shares
                db.execute("UPDATE portfolio SET shares = ? WHERE symbol = ? AND user_id = ?", shares, the_symbol, user_id)

            # Bought
            flash("successful purchase", "success")
            return redirect("/")

        # The account balance is less than the total price
        else:
            flash("cannot afford the number of shares", "danger")
            return apology("no cash", 403)

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user_id = session["user_id"]
    # Query the database for exchange history based on user id
    exchange = db.execute("SELECT * FROM exchange WHERE user_id = ?;", user_id)

    i = 0
    # Iterate through the exchange history to format price and timestamps values
    for stock in exchange:
        exchange[i]["price"] = usd(stock["at_price"])
        exchange[i]["time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stock["epoch_time"]))
        i += 1

    return render_template("history.html", ex=exchange)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        flash("you were successfully logged in", "success")
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST
    if request.method == "POST":
        try:
            # Call API for input symbol
            symbol = lookup(request.form.get("symbol"))
            formated_price = usd(symbol["price"])
            #latestTime = symbol["latestTime"]
            return render_template("quotes.html", s=symbol, f=formated_price)

        # Handle bad symbol
        except TypeError:
            flash("symbol does not exist", "warning")
            return apology("no symbol", 400)

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password is the same
        elif not request.form.get("confirmation"):
            return apology("must provide password", 400)

        # Keep the values
        username = request.form.get("username")
        password = request.form.get("password")
        #valid_name = name_scope(username)

        # Compare passwords and check if is in defined scope
        valid_pass = pass_scope(password, request.form.get("confirmation"))

        # if not valid_name:
        # #flash("username is not valid", "warning")
        # #return apology("must provide username", 400)

        # Password is not in scope
        if not valid_pass:
            flash("password is not typed correctly", "warning")
            return apology("must provide password", 400)

        # The username exists in the database
        elif [] != db.execute("SELECT * FROM users WHERE username = ?", username):
            flash("username is not available", "warning")
            return apology("duplicate username", 400)
        else:
            # Hash the password with SHA-256 and a salt length of 32
            # then insert the registered user into the database and assign ongoing session
            hashed_pass = generate_password_hash(password, method='pbkdf2:sha256:524288', salt_length=32)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_pass)
            session["user_id"] = db.execute("SELECT * FROM users WHERE username = ?", username)[0]["id"]

            flash("you were successfully registered", "success")
            return render_template("index.html")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    # Query the database for portfolio
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = ?", user_id)

    # User reached route via POST
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            flash("symbol does not exist", "warning")
            return apology("no symbol")

        # Ensure shares was submitted
        elif not request.form.get("shares"):
            flash("number of shares not provided", "warning")
            return apology("no shares")

        # Ensure shares are in defined scope
        elif not shares_scope(request.form.get("shares")):
            flash("number of shares must be a positive integer", "danger")
            return apology("no shares")

        try:
            # Call API for input symbol
            symbol = lookup(request.form.get("symbol"))
            price = symbol["price"]
            name = symbol["name"]
            the_symbol = symbol["symbol"]

        # Handle bad symbol
        except TypeError:
            flash("symbol does not exist", "warning")
            return apology("no symbol", 403)

        # Prepare the rest of the required data
        activity = "sell"
        shares = int(request.form.get("shares"))
        total_price = round(price * float(shares), 2)

        # Query the database to load the balance of the stock portfolio
        shares_portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, the_symbol)[0]["shares"]

        # Query the database for account balance
        balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        # Make a timestamp in unix time
        epoch_time = int(time.time())

        # User has shares to trade
        if shares_portfolio > shares:
            # Calculate the new account balance and update the database
            balance = round(balance + total_price, 2)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)

            # Insert the trade history into the database
            db.execute("INSERT INTO exchange (symbol, name, shares, activity, at_price, total_price, epoch_time, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       the_symbol, name, shares, activity, price, total_price, epoch_time, user_id)

            # Calculate the new balance of the stock portfolio and update the database
            shares_portfolio = shares_portfolio - shares
            db.execute("UPDATE portfolio SET shares = ? WHERE symbol = ? AND user_id = ?", shares_portfolio, the_symbol, user_id)

            # Sold
            flash("successfully sold", "success")
            return redirect("/")

        # User will sell all shares
        elif shares_portfolio == shares:
            # Calculate the new account balance and update the database
            balance = round(balance + total_price, 2)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)

            # Insert the trade history into the database
            db.execute("INSERT INTO exchange (symbol, name, shares, activity, at_price, total_price, epoch_time, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       the_symbol, name, shares, activity, price, total_price, epoch_time, user_id)

            # Delete the stock symbol from the portfolio since there is zero left
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, the_symbol)

            # Sold
            flash("successfully sold", "success")
            return redirect("/")

        # Balance of the stock portfolio is less than user input
        else:
            flash("not enough number of shares", "danger")
            return apology("no shares")

    # User reached route via GET
    else:
        return render_template("sell.html", portfolio=portfolio)
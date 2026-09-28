"""Million Euro Wallet.

University of Helsinki Cyber Security Base coursework project.

This application is intentionally vulnerable.
It demonstrates five OWASP Top 10:2021 security flaws.

Each vulnerable implementation is ACTIVE.
A corresponding secure implementation is included immediately below
the flaw as commented-out code.
"""

import hashlib
import logging
from pathlib import Path
import secrets
import sqlite3

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    DATABASE=str(Path(__file__).with_name("wallet.sqlite3")),

    # These controls are deliberately left secure because they are
    # not among the five vulnerabilities demonstrated in this project.
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    MAX_CONTENT_LENGTH=8192,
)

logging.basicConfig(level=logging.INFO)


# ============================================================
# DATABASE
# ============================================================

def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    connection = g.pop("db", None)

    if connection is not None:
        connection.close()


def init_db():
    with app.app_context():
        connection = db()

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                balance_cents INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                description TEXT NOT NULL,
                amount_cents INTEGER NOT NULL
            );
            """
        )

        users = [
            (1, "bob", 100000000),
            (2, "alice", 25000000),
        ]

        for user_id, name, balance in users:
            existing = connection.execute(
                "SELECT id FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

            if existing:
                continue

            connection.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?)",
                (
                    user_id,
                    name,
                    hash_password(f"{name}-demo-password"),
                    balance,
                ),
            )

            connection.execute(
                """
                INSERT INTO transactions
                    (owner_id, description, amount_cents)
                VALUES (?, ?, ?)
                """,
                (
                    user_id,
                    "Opening balance",
                    balance,
                ),
            )

        connection.commit()


# ============================================================
# A02:2021 - CRYPTOGRAPHIC FAILURES
# ============================================================

def hash_password(password):
    # --------------------------------------------------------
    # VULNERABLE IMPLEMENTATION
    #
    # SHA-256 is a fast general-purpose hash and no salt is used.
    # If the database is stolen, attackers can perform efficient
    # offline dictionary or brute-force attacks against passwords.
    # --------------------------------------------------------

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    # --------------------------------------------------------
    # FIX
    #
    # Use a salted, deliberately expensive password hashing
    # algorithm designed for password storage.
    #
    # return generate_password_hash(
    #     password,
    #     method="scrypt",
    # )
    # --------------------------------------------------------


def verify_password(stored_hash, password):
    # --------------------------------------------------------
    # VULNERABLE IMPLEMENTATION
    # --------------------------------------------------------

    candidate_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    return stored_hash == candidate_hash

    # --------------------------------------------------------
    # FIX
    #
    # return check_password_hash(
    #     stored_hash,
    #     password,
    # )
    # --------------------------------------------------------


# ============================================================
# A09:2021 - SECURITY LOGGING AND MONITORING FAILURES
# ============================================================

def security_event(event, user_id=None):
    # --------------------------------------------------------
    # VULNERABLE IMPLEMENTATION
    #
    # Security-sensitive events are discarded.
    #
    # Failed logins, denied access attempts and password changes
    # therefore leave no useful audit trail.
    # --------------------------------------------------------

    return

    # --------------------------------------------------------
    # FIX
    #
    # Record relevant security events without logging passwords
    # or other secret information.
    #
    # app.logger.warning(
    #     "security event=%s user_id=%s",
    #     event,
    #     user_id,
    # )
    # --------------------------------------------------------


# ============================================================
# CSRF PROTECTION
#
# This protection is intentionally working normally.
# CSRF is NOT one of the five vulnerabilities demonstrated here.
# ============================================================

@app.before_request
def csrf_protection():
    session.setdefault(
        "csrf",
        secrets.token_urlsafe(32),
    )

    if request.method == "POST":
        token = request.form.get(
            "csrf",
            "",
        )

        if not secrets.compare_digest(
            token,
            session["csrf"],
        ):
            security_event(
                "csrf_rejected",
                session.get("user_id"),
            )

            abort(400)


# ============================================================
# HTML
# ============================================================

PAGE = """
<!doctype html>

<html lang="en">

<head>
    <meta charset="utf-8">
    <meta
        name="viewport"
        content="width=device-width"
    >

    <title>Million Euro Wallet</title>

    <style>
        body {
            font: 17px system-ui;
            max-width: 680px;
            margin: 48px auto;
            padding: 0 20px;
            background: #f6f8fa;
            color: #142333;
        }

        input,
        button {
            font: inherit;
            padding: 9px;
            margin: 6px 0;
        }

        label {
            display: block;
        }

        table {
            width: 100%;
            text-align: left;
        }

        td,
        th {
            padding: 9px;
            border-bottom: 1px solid #ddd;
        }

        .balance {
            font-size: 38px;
            font-weight: bold;
        }

        .notice {
            color: #555;
        }
    </style>
</head>

<body>

<h1>Million Euro Wallet</h1>

<p class="notice">
    Local cybersecurity coursework demo · fictional money
</p>

{% if message %}
    <p role="status">
        {{ message }}
    </p>
{% endif %}


{% if not account %}

    <h2>Login</h2>

    <form
        method="post"
        action="{{ url_for('login') }}"
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ session.csrf }}"
        >

        <label>
            Username

            <input
                name="username"
                required
                autocomplete="username"
            >
        </label>

        <label>
            Password

            <input
                name="password"
                type="password"
                required
                autocomplete="current-password"
            >
        </label>

        <button>
            Login
        </button>

    </form>

{% else %}

    <h2>
        Welcome, {{ account.username }}
    </h2>

    <p class="balance">
        {{ money(account.balance_cents) }}
    </p>


    <h2>Transactions</h2>

    <form method="get">

        <label>
            Search transactions

            <input
                name="q"
                value="{{ query }}"
                maxlength="200"
            >
        </label>

        <button>
            Search
        </button>

    </form>


    <table>

        <tr>
            <th>Description</th>
            <th>Amount</th>
        </tr>

        {% for row in transactions %}

            <tr>
                <td>
                    {{ row.description }}
                </td>

                <td>
                    {{ money(row.amount_cents) }}
                </td>
            </tr>

        {% else %}

            <tr>
                <td colspan="2">
                    No matching transactions.
                </td>
            </tr>

        {% endfor %}

    </table>


    <h2>Change password</h2>

    <form
        method="post"
        action="{{ url_for('change_password') }}"
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ session.csrf }}"
        >

        <label>
            Current password

            <input
                name="current_password"
                type="password"
                required
                autocomplete="current-password"
            >
        </label>

        <label>
            New password

            <input
                name="new_password"
                type="password"
                minlength="12"
                maxlength="128"
                required
                autocomplete="new-password"
            >
        </label>

        <button>
            Change password
        </button>

    </form>


    <form
        method="post"
        action="{{ url_for('logout') }}"
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ session.csrf }}"
        >

        <button>
            Logout
        </button>

    </form>

{% endif %}

</body>

</html>
"""


def money(cents):
    return (
        f"€{cents // 100:,}."
        f"{cents % 100:02d}"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"],
)
def login():
    if request.method == "POST":

        account = db().execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (
                request.form.get(
                    "username",
                    "",
                ),
            ),
        ).fetchone()

        password = request.form.get(
            "password",
            "",
        )

        if account and verify_password(
            account["password_hash"],
            password,
        ):
            session.clear()

            session["user_id"] = account["id"]

            session["csrf"] = (
                secrets.token_urlsafe(32)
            )

            security_event(
                "login_succeeded",
                account["id"],
            )

            return redirect(
                url_for(
                    "wallet",
                    wallet_id=account["id"],
                )
            )

        security_event(
            "login_failed",
        )

        return (
            render_template_string(
                PAGE,
                account=None,
                message="Invalid username or password.",
            ),
            401,
        )

    if "user_id" in session:
        return redirect(
            url_for(
                "wallet",
                wallet_id=session["user_id"],
            )
        )

    return render_template_string(
        PAGE,
        account=None,
    )


# ============================================================
# A01:2021 - BROKEN ACCESS CONTROL
# ============================================================

@app.get(
    "/wallet/<int:wallet_id>"
)
def wallet(wallet_id):
    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    # --------------------------------------------------------
    # VULNERABLE IMPLEMENTATION
    #
    # The application trusts wallet_id supplied in the URL.
    #
    # Any authenticated user can request another wallet simply
    # by changing the numeric identifier.
    #
    # Example:
    #
    # Bob normally sees:
    # /wallet/1
    #
    # Bob can manually request:
    # /wallet/2
    #
    # and receive Alice's wallet.
    # --------------------------------------------------------

    account = db().execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (
            wallet_id,
        ),
    ).fetchone()

    # --------------------------------------------------------
    # FIX
    #
    # Bind the resource lookup to both the requested wallet and
    # the authenticated user.
    #
    # account = db().execute(
    #     '''
    #     SELECT *
    #     FROM users
    #     WHERE id = ?
    #       AND id = ?
    #     ''',
    #     (
    #         wallet_id,
    #         session["user_id"],
    #     ),
    # ).fetchone()
    # --------------------------------------------------------

    if account is None:
        security_event(
            "wallet_access_denied",
            session["user_id"],
        )

        abort(404)


    query = request.args.get(
        "q",
        "",
    )[:200]


    # ========================================================
    # A03:2021 - INJECTION
    # ========================================================

    # --------------------------------------------------------
    # VULNERABLE IMPLEMENTATION
    #
    # User-controlled search text is concatenated directly into
    # the SQL statement.
    #
    # SQL syntax supplied in the search field therefore becomes
    # part of the executed query.
    # --------------------------------------------------------

    sql = (
        "SELECT * "
        "FROM transactions "
        f"WHERE owner_id = {account['id']} "
        f"AND description LIKE '%{query}%' "
        "ORDER BY id DESC"
    )

    transactions = db().execute(
        sql
    ).fetchall()


    # --------------------------------------------------------
    # FIX
    #
    # Use parameterized SQL.
    #
    # The search term is then treated only as data and cannot
    # modify SQL syntax.
    #
    # transactions = db().execute(
    #     '''
    #     SELECT *
    #     FROM transactions
    #     WHERE owner_id = ?
    #       AND instr(description, ?) > 0
    #     ORDER BY id DESC
    #     ''',
    #     (
    #         account["id"],
    #         query,
    #     ),
    # ).fetchall()
    # --------------------------------------------------------


    return render_template_string(
        PAGE,
        account=account,
        transactions=transactions,
        query=query,
        money=money,
    )


# ============================================================
# A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
# ============================================================

@app.post(
    "/password"
)
def change_password():
    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    account = db().execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (
            session["user_id"],
        ),
    ).fetchone()


    # --------------------------------------------------------
    # VULNERABLE IMPLEMENTATION
    #
    # The current_password form field exists, but the server
    # completely ignores it.
    #
    # Possession of an existing authenticated session is enough
    # to change the account password.
    #
    # Sensitive credential changes should require appropriate
    # re-authentication.
    # --------------------------------------------------------

    # No current password validation takes place here.


    # --------------------------------------------------------
    # FIX
    #
    # Re-authenticate the user before changing credentials.
    #
    # if (
    #     not account
    #     or not verify_password(
    #         account["password_hash"],
    #         request.form.get(
    #             "current_password",
    #             "",
    #         ),
    #     )
    # ):
    #     security_event(
    #         "password_change_denied",
    #         session["user_id"],
    #     )
    #
    #     abort(403)
    # --------------------------------------------------------


    password = request.form.get(
        "new_password",
        "",
    )

    if not 12 <= len(password) <= 128:
        abort(
            400,
            "New password must contain 12 to 128 characters.",
        )


    db().execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (
            hash_password(password),
            account["id"],
        ),
    )

    db().commit()


    security_event(
        "password_changed",
        account["id"],
    )


    session.clear()


    return redirect(
        url_for("login")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.post(
    "/logout"
)
def logout():

    security_event(
        "logout",
        session.get("user_id"),
    )

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# STARTUP
# ============================================================

init_db()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
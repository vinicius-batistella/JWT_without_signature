import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from flask import Flask, make_response, redirect, render_template_string, request, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))

# Server-side secret used only when *signing* tokens at login.
JWT_SIGNING_SECRET = os.environ.get("JWT_SIGNING_SECRET", "dev-signing-secret-change-me")
JWT_COOKIE_NAME = "access_token"
JWT_ALG = "HS256"

USERS = {
    "john": {"password": "johnpass", "role": "user"},
    "rick": {"password": "rickpass", "role": "admin"},
}


def issue_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=8),
    }
    return jwt.encode(payload, JWT_SIGNING_SECRET, algorithm=JWT_ALG)


def read_role_without_verifying_signature(token: str) -> Tuple[Optional[str], Optional[str]]:
    """
    INSECURE: trusts whatever is in the payload. Anyone can forge a token
    with the same shape and set role to 'admin' if they know the app only
    decodes without verification.
    """
    try:
        decoded = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": True},
            algorithms=[JWT_ALG],
        )
    except jwt.ExpiredSignatureError:
        return None, "expired"
    except jwt.InvalidTokenError:
        return None, "invalid"
    role = decoded.get("role")
    if not isinstance(role, str):
        return None, "invalid"
    return role, None


LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login — JWT demo</title>
  <style>
    :root { font-family: system-ui, sans-serif; background: #0f1419; color: #e7ecf1; }
    body { display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card {
      background: #1a2332;
      padding: 2rem 2.25rem;
      border-radius: 12px;
      width: min(100% - 2rem, 360px);
      box-shadow: 0 12px 40px rgba(0,0,0,.35);
    }
    h1 { font-size: 1.25rem; margin: 0 0 1rem; font-weight: 600; }
    label { display: block; font-size: .85rem; margin-bottom: .35rem; color: #9fb0c3; }
    input {
      width: 100%;
      box-sizing: border-box;
      padding: .65rem .75rem;
      border-radius: 8px;
      border: 1px solid #2d3a4d;
      background: #0f1419;
      color: #e7ecf1;
      margin-bottom: 1rem;
    }
    button {
      width: 100%;
      padding: .75rem;
      border: none;
      border-radius: 8px;
      background: #3b82f6;
      color: #fff;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { filter: brightness(1.06); }
    .hint { font-size: .8rem; color: #7d8fa3; margin-top: 1.25rem; line-height: 1.45; }
    .err { color: #f87171; font-size: .875rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign in</h1>
    {% if error %}<p class="err">{{ error }}</p>{% endif %}
    <form method="post" action="{{ url_for('login') }}">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>
"""

HOME_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Home — JWT demo</title>
  <style>
    :root { font-family: system-ui, sans-serif; background: #0f1419; color: #e7ecf1; }
    body { margin: 0; min-height: 100vh; }
    header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 1rem 1.5rem; border-bottom: 1px solid #2d3a4d; background: #141c28;
    }
    main { padding: 1.5rem; max-width: 640px; }
    .badge {
      display: inline-block; padding: .35rem .65rem; border-radius: 999px;
      font-size: .75rem; font-weight: 600; background: #7c3aed; color: #f5f3ff;
    }
    .user { background: #334155; color: #e2e8f0; }
    a { color: #93c5fd; }
    .warn {
      margin-top: 1.5rem; padding: 1rem; border-radius: 8px;
      background: #422006; border: 1px solid #92400e; color: #fed7aa; font-size: .875rem;
    }
  </style>
</head>
<body>
  <header>
    <span>JWT demo</span>
    <a href="{{ url_for('logout') }}">Log out</a>
  </header>
  <main>
    <h1>Welcome home</h1>
    <p>You are signed in as <strong>{{ username }}</strong>.</p>
    {% if is_admin %}
      <p><span class="badge">Administrator</span></p>
      <p>You have elevated privileges according to the <code>role</code> claim in your JWT.</p>
    {% else %}
      <p><span class="badge user">Standard user</span></p>
    {% endif %}
    <div class="warn">
      This demo reads <code>role</code> from the JWT <strong>without verifying the signature</strong>,
      which is unsafe: anyone who can set a cookie or present a token could forge <code>role: admin</code>.
    </div>
  </main>
</body>
</html>
"""


@app.get("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE, error=None)

    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    account = USERS.get(username)
    if not account or account["password"] != password:
        return render_template_string(
            LOGIN_PAGE,
            error="Invalid username or password.",
        ), 401

    token = issue_token(username, account["role"])
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie(
        JWT_COOKIE_NAME,
        token,
        httponly=True,
        samesite="Lax",
        max_age=8 * 60 * 60,
        secure=request.is_secure,
    )
    return resp


@app.get("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(JWT_COOKIE_NAME)
    return resp


@app.get("/home")
def home():
    token = request.cookies.get(JWT_COOKIE_NAME)
    if not token:
        return redirect(url_for("login"))

    role, err = read_role_without_verifying_signature(token)
    if err == "expired":
        resp = make_response(redirect(url_for("login")))
        resp.delete_cookie(JWT_COOKIE_NAME)
        return resp
    if err or role is None:
        return redirect(url_for("login"))

    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        username = unverified.get("sub") or "unknown"
    except jwt.InvalidTokenError:
        username = "unknown"

    is_admin = role == "admin"
    return render_template_string(HOME_PAGE, username=username, is_admin=is_admin)


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", "5000")))

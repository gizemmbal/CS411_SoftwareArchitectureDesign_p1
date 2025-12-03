from flask import Flask, render_template, request, redirect, session, url_for
import os, requests
from dotenv import load_dotenv

# .env yükle
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_key")

SUPABASE_URL = os.getenv("SUPABASE_URL", "http://localhost:8000")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

def supabase_password_login(email: str, password: str):
    """
    Supabase Auth (GoTrue) password grant.
    DOC: POST /auth/v1/token?grant_type=password
    Headers: apikey (ANON_KEY), Content-Type: application/json
    Body: { email, password }
    """
    url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }
    payload = {"email": email, "password": password}
    return requests.post(url, json=payload, headers=headers, timeout=15)

@app.route("/", methods=["GET"])
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    if not email or not password:
        return render_template("login.html", error="Email and password are required.")

    try:
        resp = supabase_password_login(email, password)
    except requests.RequestException as e:
        return render_template("login.html", error=f"Unable to connect to auth service: {e}")

    if resp.status_code == 200:
        data = resp.json()
        # data contains access_token, token_type, user etc.
        session["user"] = {
            "email": email,
            "access_token": data.get("access_token"),
            "token_type": data.get("token_type"),
            "refresh_token": data.get("refresh_token"),
            "expires_in": data.get("expires_in"),
            "user": data.get("user"),
        }
        return redirect(url_for("dashboard"))
    else:
        # Provide user-friendly error message
        try:
            err = resp.json()
        except Exception:
            err = {"error": resp.text}
        if resp.status_code == 400 and "invalid_credentials" in resp.text:
            return render_template("login.html", error="Invalid email or password. Please try again.")

        elif resp.status_code == 400 and "email_not_confirmed" in resp.text:
            return render_template("login.html",
                                   error="Email not confirmed. Please check your inbox for the verification link.")

        else:
            try:
                err = resp.json()
            except Exception:
                err = {"error": resp.text}
            return render_template("login.html", error=f"Login failed: {err.get('msg', 'Unknown error occurred.')}")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirm", "").strip()

    if not email or not password:
        return render_template("signup.html", error="Email and password are required.")
    if password != confirm:
        return render_template("signup.html", error="Passwords do not match.")

    url = f"{SUPABASE_URL}/auth/v1/signup"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }
    payload = {"email": email, "password": password}

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        if resp.status_code in (200, 201):
            # Signup başarılı -> otomatik login yap
            login_resp = supabase_password_login(email, password)
            if login_resp.status_code == 200:
                data = login_resp.json()
                session["user"] = {
                    "email": email,
                    "access_token": data.get("access_token"),
                    "token_type": data.get("token_type"),
                    "refresh_token": data.get("refresh_token"),
                    "expires_in": data.get("expires_in"),
                    "user": data.get("user"),
                }
                return redirect(url_for("dashboard"))
            else:
                return render_template("login.html", success="Account created. Please log in.")
        else:
            err = resp.json()
            msg = err.get("msg") or err.get("error_description") or str(err)
            return render_template("signup.html", error=f"Sign-up failed: {msg}")
    except requests.RequestException as e:
        return render_template("signup.html", error=f"Unable to connect to auth service: {e}")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    u = session.get("user")
    if not u:
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=u)
@app.route("/goto/studio")
def goto_studio():
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    
    access_token = user.get("access_token")
    target_url = f"http://localhost:8000/project/default?access_token={access_token}"

    return render_template(
        "redirect.html",
        title="Supabase Studio",
        description="You are being redirected to Supabase Studio...",
        target_url=target_url,
        button_text="Open Studio"
    )

@app.route("/goto/<service>")
def goto_service(service):
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    
    service_urls = {
        "auth": "http://localhost:8000/project/default/auth/users",
        "rest": "http://localhost:8000",
        "storage": "http://localhost:8000/project/default/storage/buckets",
        "realtime": "http://localhost:8000/project/default/realtime/inspector",
        "studio": "http://localhost:8000/project/default",
        "kong": "http://localhost:8000",
        "postgres": "http://localhost:8000/project/default/database/schemas",
        "meta": "http://localhost:8000",
        "analytics": "http://localhost:4000",
        "functions": "http://localhost:8000/project/default/functions",
        "imgproxy": "http://localhost:8000",
        "vector": "http://localhost:8000",
        "pooler": "http://localhost:6543"
    }
    
    service_names = {
        "auth": "Auth API (GoTrue)",
        "rest": "REST API (PostgREST)",
        "storage": "Storage API", 
        "realtime": "Realtime",
        "studio": "Supabase Studio",
        "kong": "Kong Gateway",
        "postgres": "PostgreSQL",
        "meta": "PostgREST Meta",
        "analytics": "Analytics (Logflare)",
        "functions": "Edge Functions",
        "imgproxy": "Image Proxy",
        "vector": "Vector Search",
        "pooler": "Connection Pooler"
    }
    
    if service not in service_urls:
        return redirect(url_for("dashboard"))
    
    return render_template("redirect.html",
                         title=service_names[service],
                         description=f"You are being redirected to {service_names[service]}",
                         target_url=service_urls[service],
                         button_text=f"Open {service_names[service]}")
@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

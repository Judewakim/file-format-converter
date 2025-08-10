from flask import Flask, render_template, request, send_file, redirect, url_for, after_this_request, session, abort
import os
import secrets
from werkzeug.utils import secure_filename
from PIL import Image
import PyPDF2
from docx import Document
import io
import datetime
import requests
import urllib.parse
import jwt
from jwt.algorithms import RSAAlgorithm
from functools import wraps
from dotenv import load_dotenv

if os.getenv("FLASK_ENV") != "production":
    load_dotenv()  # loads .env in dev only

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# -------------------------------
# Cognito Configuration (from .env)
# -------------------------------
COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_REDIRECT_URI = os.getenv("COGNITO_REDIRECT_URI")
COGNITO_LOGOUT_REDIRECT = os.getenv("COGNITO_LOGOUT_REDIRECT")
COGNITO_REGION = os.getenv("COGNITO_REGION")
COGNITO_USERPOOL_ID = os.getenv("COGNITO_USERPOOL_ID")

JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}/.well-known/jwks.json"
JWKS = requests.get(JWKS_URL).json()["keys"]

# -------------------------------
# Helper: Verify JWT
# -------------------------------
def verify_token(token):
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    key_data = next((k for k in JWKS if k["kid"] == kid), None)
    if not key_data:
        raise Exception("Public key not found for token.")

    public_key = RSAAlgorithm.from_jwk(key_data)
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=COGNITO_CLIENT_ID,
        issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}"
    )

# -------------------------------
# Decorator: Require Login
# -------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        id_token = session.get("id_token")
        if not id_token:
            return redirect(url_for("login"))
        try:
            verify_token(id_token)
        except Exception:
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------
# File paths
# -------------------------------
UPLOAD_FOLDER = "uploads"
CONVERTED_FOLDER = "converted"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)
download_history = []

# -------------------------------
# Auth Routes
# -------------------------------
@app.route("/login")
def login():
    auth_url = (
        f"{COGNITO_DOMAIN}/login"
        f"?client_id={COGNITO_CLIENT_ID}"
        f"&response_type=code"
        f"&scope=openid+profile+email"
        f"&redirect_uri={urllib.parse.quote(COGNITO_REDIRECT_URI)}"
    )
    return redirect(auth_url)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    token_url = f"{COGNITO_DOMAIN}/oauth2/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": COGNITO_REDIRECT_URI,
        "code": code
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(token_url, data=data, headers=headers)

    if token_response.status_code != 200:
        return "Failed to get tokens", 400

    tokens = token_response.json()
    session["access_token"] = tokens.get("access_token")
    session["id_token"] = tokens.get("id_token")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    logout_url = (
        f"{COGNITO_DOMAIN}/logout"
        f"?client_id={COGNITO_CLIENT_ID}"
        f"&logout_uri={urllib.parse.quote(COGNITO_LOGOUT_REDIRECT)}"
    )
    return redirect(logout_url)

@app.route("/account")
@login_required
def account():
    user_info = verify_token(session["id_token"])
    return render_template("account.html", user=user_info)

# -------------------------------
# Main App Routes
# -------------------------------
@app.route("/")
def index():
    for fname in os.listdir(CONVERTED_FOLDER):
        try:
            os.remove(os.path.join(CONVERTED_FOLDER, fname))
        except Exception as e:
            app.logger.error(f"Error deleting converted file {fname}: {e}")

    return render_template("index.html", history=download_history, logged_in="id_token" in session)

@app.route("/convert", methods=["POST"])
def convert_file():
    if "file" not in request.files:
        return "No file uploaded", 400

    file = request.files["file"]
    conversion_type = request.form.get("conversion_type")
    if file.filename == "":
        return "No selected file", 400

    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    output_path = None
    if conversion_type == "txt_to_pdf":
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        with open(input_path, "r") as f:
            for line in f:
                pdf.cell(200, 10, txt=line, ln=True)
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".pdf")
        pdf.output(output_path)

    elif conversion_type == "jpg_to_png":
        img = Image.open(input_path)
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".png")
        img.save(output_path, "PNG")

    elif conversion_type == "pdf_to_word":
        pdf_reader = PyPDF2.PdfReader(open(input_path, "rb"))
        doc = Document()
        for page in pdf_reader.pages:
            text = page.extract_text()
            if text:
                doc.add_paragraph(text)
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".docx")
        doc.save(output_path)

    else:
        return "Unsupported conversion type", 400

    download_history.append({
        "filename": os.path.basename(output_path),
        "conversion_type": conversion_type,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    @after_this_request
    def cleanup(response):
        try:
            os.remove(input_path)
        except Exception as e:
            app.logger.error(f"Error deleting uploaded file {input_path}: {e}")
        return response

    return send_file(output_path, as_attachment=True)

# Feedback route
@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    feedback = request.form.get('feedback', '').strip()
    if feedback:
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        try:
            with open('feedback.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {feedback}\n\n")
        except Exception as e:
            app.logger.error(f"Error saving feedback: {e}")
        return render_template("index.html", history=download_history, feedback_message="Thank you for your feedback!")
    return redirect(url_for('index'))

# Blog routes
@app.route('/blog/pdf-to-word.html')
def blog_pdf_to_word():
    return render_template('blog/pdf-to-word.html')

@app.route('/blog/jpg-to-png.html')
def blog_jpg_to_png():
    return render_template('blog/jpg-to-png.html')

@app.route('/blog/txt-to-pdf.html')
def blog_txt_to_pdf():
    return render_template('blog/txt-to-pdf.html')

# Cache control
@app.after_request
def add_cache_control(response):
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=2592000'
    else:
        response.headers['Cache-Control'] = 'public, max-age=300'
    return response

# 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == "__main__":
    app.run(debug=True)

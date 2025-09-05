# ========================================
# IMPORTS AND DEPENDENCIES
# ========================================
from flask import Flask, render_template, request, send_file, redirect, url_for, session
import os
import secrets
import time
import threading
from werkzeug.utils import secure_filename
import datetime

# File processing libraries
from PIL import Image
import PyPDF2
from docx import Document

# Character encoding detection
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False

# PDF processing libraries
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Authentication libraries
import requests
import urllib.parse
import jwt
from jwt.algorithms import RSAAlgorithm
from functools import wraps

# Load environment variables
from dotenv import load_dotenv
if os.getenv("FLASK_ENV") != "production":
    load_dotenv()

# ========================================
# FLASK APPLICATION INITIALIZATION
# ========================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ========================================
# AWS COGNITO AUTHENTICATION CONFIGURATION
# ========================================
COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_REDIRECT_URI = os.getenv("COGNITO_REDIRECT_URI")
COGNITO_LOGOUT_REDIRECT = os.getenv("COGNITO_LOGOUT_REDIRECT")
COGNITO_REGION = os.getenv("COGNITO_REGION")
COGNITO_USERPOOL_ID = os.getenv("COGNITO_USERPOOL_ID")

# JWT token verification setup
JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}/.well-known/jwks.json"
try:
    JWKS = requests.get(JWKS_URL).json()["keys"]
except Exception as e:
    print(f"Warning: Could not fetch JWKS keys: {e}")
    JWKS = []

# ========================================
# AUTHENTICATION HELPER FUNCTIONS
# ========================================
def verify_token(token):
    """Verify JWT token from AWS Cognito using public keys"""
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
        issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}",
        leeway=60
    )

def login_required(f):
    """Decorator to require user authentication for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        id_token = session.get("id_token")
        if not id_token:
            return redirect(url_for("login"))
        
        try:
            verify_token(id_token)
        except Exception as e:
            print(f"Token validation failed: {e}")
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ========================================
# FILE SYSTEM CONFIGURATION
# ========================================
UPLOAD_FOLDER = "uploads"
CONVERTED_FOLDER = "converted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)

def force_delete_file(file_path, max_attempts=5, delay=0.5):
    """Force delete a file with retries if it's locked by another process"""
    for attempt in range(max_attempts):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            return
        except PermissionError:
            if attempt < max_attempts - 1:
                time.sleep(delay)
            else:
                app.logger.error(f"Failed to delete {file_path} after {max_attempts} attempts")
        except Exception as e:
            app.logger.error(f"Error deleting {file_path}: {e}")
            break

# ========================================
# AUTHENTICATION ROUTES
# ========================================
@app.route("/login")
def login():
    """Redirect user to AWS Cognito hosted login page"""
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
    """Handle OAuth callback from AWS Cognito after user login"""
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
    """Clear user session and redirect to Cognito logout"""
    session.clear()
    
    logout_url = (
        f"{COGNITO_DOMAIN}/logout"
        f"?client_id={COGNITO_CLIENT_ID}"
        f"&logout_uri={urllib.parse.quote(COGNITO_LOGOUT_REDIRECT)}"
    )
    return redirect(logout_url)

# ========================================
# MAIN APPLICATION ROUTES
# ========================================
@app.route("/")
def index():
    """Main homepage with file conversion interface"""
    # Clean up old converted files on each page load
    for fname in os.listdir(CONVERTED_FOLDER):
        try:
            os.remove(os.path.join(CONVERTED_FOLDER, fname))
        except Exception as e:
            app.logger.error(f"Error deleting converted file {fname}: {e}")

    # Get user's conversion history from session
    session_history = session.get('conversion_history', [])
    
    return render_template("index.html", 
                         history=session_history,
                         logged_in="id_token" in session)

@app.route("/convert", methods=["POST"])
def convert_file():
    """Handle file conversion requests - supports TXT→PDF, JPG→PNG, PDF→Word, SVG→PNG"""
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
    
    # TXT to PDF conversion
    if conversion_type == "txt_to_pdf":
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".pdf")
        convert_txt_to_pdf(input_path, output_path)

    # JPG to PNG conversion
    elif conversion_type == "jpg_to_png":
        img = Image.open(input_path)
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".png")
        img.save(output_path, "PNG")

    # PDF to Word conversion
    elif conversion_type == "pdf_to_word":
        pdf_reader = PyPDF2.PdfReader(open(input_path, "rb"))
        doc = Document()
        for page in pdf_reader.pages:
            text = page.extract_text()
            if text:
                doc.add_paragraph(text)
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".docx")
        doc.save(output_path)

    # SVG to PNG conversion
    elif conversion_type == "svg_to_png":
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".png")
        
        try:
            import cairosvg
            cairosvg.svg2png(url=input_path, write_to=output_path)
        except ImportError:
            try:
                from reportlab.graphics import renderPM
                from svglib.svglib import renderSVG
                drawing = renderSVG.renderSVG(input_path)
                renderPM.drawToFile(drawing, output_path, fmt="PNG")
            except ImportError:
                # Basic fallback
                from PIL import Image, ImageDraw
                img = Image.new('RGB', (800, 600), color='white')
                draw = ImageDraw.Draw(img)
                draw.text((10, 10), f"SVG: {os.path.basename(filename)}", fill='black')
                img.save(output_path, "PNG")

    else:
        return "Unsupported conversion type", 400

    # Add conversion to user's session history
    if 'conversion_history' not in session:
        session['conversion_history'] = []
    
    session['conversion_history'].append({
        "filename": os.path.basename(output_path),
        "conversion_type": conversion_type,
        "timestamp": datetime.datetime.now().strftime("%y/%m/%d")
    })
    
    # Keep only last 5 conversions per session
    session['conversion_history'] = session['conversion_history'][-5:]

    # Schedule file cleanup after 3 minutes
    def delayed_cleanup():
        time.sleep(180)
        force_delete_file(input_path)
    
    cleanup_thread = threading.Thread(target=delayed_cleanup)
    cleanup_thread.start()
    
    return send_file(output_path, as_attachment=True)

def convert_txt_to_pdf(input_path, output_path):
    """Convert TXT file to PDF with proper Unicode support and formatting"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for TXT to PDF conversion")
    
    # Auto-detect file encoding
    if CHARDET_AVAILABLE:
        with open(input_path, 'rb') as f:
            raw_data = f.read()
            encoding_result = chardet.detect(raw_data)
            encoding = encoding_result['encoding'] or 'utf-8'
    else:
        encoding = 'utf-8'
    
    # Read text with detected encoding
    try:
        with open(input_path, 'r', encoding=encoding) as f:
            text_content = f.read()
    except UnicodeDecodeError:
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            text_content = f.read()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=1*inch,
        bottomMargin=1*inch
    )
    
    # Define styles
    styles = getSampleStyleSheet()
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        alignment=TA_LEFT,
        spaceAfter=6,
        fontName='Helvetica'
    )
    
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        alignment=TA_LEFT,
        spaceAfter=8,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    # Process text content
    story = []
    lines = text_content.split('\n')
    
    for line in lines:
        line = line.strip()
        
        if not line:
            story.append(Spacer(1, 6))
            continue
        
        # Detect if line looks like a header
        is_header = (
            len(line) < 50 and 
            (line.isupper() or 
             line.endswith(':') or 
             any(word in line.upper() for word in ['EXPERIENCE', 'EDUCATION', 'SKILLS', 'CONTACT', 'SUMMARY', 'OBJECTIVE']))
        )
        
        style = header_style if is_header else body_style
        
        try:
            para = Paragraph(line, style)
            story.append(para)
        except Exception as e:
            app.logger.warning(f"PDF encoding issue for line: {line[:50]}... Error: {e}")
            fallback_text = f"[Text encoding issue - {len(line)} characters]"
            para = Paragraph(fallback_text, style)
            story.append(para)
    
    doc.build(story)

# ========================================
# USER FEEDBACK SYSTEM
# ========================================
@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    """Handle user feedback submission and save to file"""
    feedback = request.form.get('feedback', '').strip()
    if feedback:
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        try:
            with open('feedback.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {feedback}\n\n")
        except Exception as e:
            app.logger.error(f"Error saving feedback: {e}")
        
        session_history = session.get('conversion_history', [])
        return render_template("index.html", history=session_history, 
                             logged_in="id_token" in session,
                             feedback_message="Thank you for your feedback!")
    return redirect(url_for('index'))

# ========================================
# ACCOUNT ROUTE
# ========================================
@app.route("/account")
@login_required
def account():
    """User account page"""
    user_info = verify_token(session["id_token"])
    return render_template("account.html", user=user_info)

# ========================================
# CONTENT ROUTES
# ========================================
@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/blog/pdf-to-word.html')
def blog_pdf_to_word():
    return render_template('blog/pdf-to-word.html')

@app.route('/blog/jpg-to-png.html')
def blog_jpg_to_png():
    return render_template('blog/jpg-to-png.html')

@app.route('/blog/txt-to-pdf.html')
def blog_txt_to_pdf():
    return render_template('blog/txt-to-pdf.html')

# ========================================
# ERROR HANDLING
# ========================================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.after_request
def add_cache_control(response):
    """Add appropriate cache headers"""
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=2592000'
    else:
        response.headers['Cache-Control'] = 'public, max-age=300'
    return response

# ========================================
# APPLICATION STARTUP
# ========================================
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
# ========================================
# IMPORTS AND DEPENDENCIES
# ========================================
# Flask framework and utilities
from flask import Flask, render_template, request, send_file, redirect, url_for, after_this_request, session, abort, jsonify
import os
import secrets
import time
import threading
from werkzeug.utils import secure_filename

# File processing libraries
from PIL import Image  # Image conversion (JPG to PNG)
import PyPDF2  # PDF reading and processing
from docx import Document  # Word document creation
import io
import datetime
# Character encoding detection (with fallback)
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False

# PDF processing libraries (with fallback handling)
try:
    from reportlab.lib.pagesizes import letter  # type: ignore
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer  # type: ignore
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore
    from reportlab.lib.units import inch  # type: ignore
    from reportlab.lib.enums import TA_LEFT  # type: ignore
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import fitz  # type: ignore # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

# Authentication and API libraries
import requests
import urllib.parse
import jwt  # JWT token verification for AWS Cognito
import stripe  # Stripe payment processing
from jwt.algorithms import RSAAlgorithm
from functools import wraps

# Database operations for subscription management
from stripe_db import (
    get_subscription, save_subscription, has_active_subscription,
    create_or_update_user, update_subscription_status, init_db
)

# ========================================
# DATABASE AND ENVIRONMENT SETUP
# ========================================
# Initialize database tables for subscription management
init_db()

# Load environment variables from .env file (development only)
from dotenv import load_dotenv

if os.getenv("FLASK_ENV") != "production":
    load_dotenv()  # loads .env in dev only

# ========================================
# FLASK APPLICATION INITIALIZATION
# ========================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate secure session key

# ========================================
# AWS SERVICES CONFIGURATION
# ========================================
# Configure AWS credentials from environment variables
os.environ['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID', '')
os.environ['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY', '')
os.environ['AWS_DEFAULT_REGION'] = os.getenv('AWS_REGION', 'us-east-1')

# ========================================
# STRIPE PAYMENT CONFIGURATION
# ========================================
# Initialize Stripe with secret key from environment variables
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Webhook secret for verifying Stripe webhook signatures
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Application domain for payment redirects
YOUR_DOMAIN = os.getenv("YOUR_DOMAIN") or "http://localhost:5000"

# ========================================
# AWS COGNITO AUTHENTICATION CONFIGURATION
# ========================================
# AWS Cognito settings for user authentication
COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")  # Cognito hosted UI domain
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")  # App client ID
COGNITO_REDIRECT_URI = os.getenv("COGNITO_REDIRECT_URI")  # OAuth callback URL
COGNITO_LOGOUT_REDIRECT = os.getenv("COGNITO_LOGOUT_REDIRECT")  # Post-logout redirect
COGNITO_REGION = os.getenv("COGNITO_REGION")  # AWS region
COGNITO_USERPOOL_ID = os.getenv("COGNITO_USERPOOL_ID")  # User pool ID

# JWT token verification setup
JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}/.well-known/jwks.json"
JWKS = requests.get(JWKS_URL).json()["keys"]  # Public keys for JWT verification

# ========================================
# AUTHENTICATION HELPER FUNCTIONS
# ========================================
def verify_token(token):
    """Verify JWT token from AWS Cognito using public keys"""
    # Extract token header to get key ID
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    
    # Find matching public key from JWKS
    key_data = next((k for k in JWKS if k["kid"] == kid), None)
    if not key_data:
        raise Exception("Public key not found for token.")

    # Verify and decode JWT token with clock skew tolerance
    public_key = RSAAlgorithm.from_jwk(key_data)
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=COGNITO_CLIENT_ID,
        issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}",
        leeway=60  # Allow 60 seconds clock skew tolerance
    )

def login_required(f):
    """Decorator to require user authentication for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user has valid session token
        id_token = session.get("id_token")
        if not id_token:
            return redirect(url_for("login"))
        
        # Verify token is still valid
        try:
            verify_token(id_token)
        except Exception as e:
            print(f"Token validation failed in login_required: {e}")
            session.clear()  # Clear invalid session
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ========================================
# FILE SYSTEM CONFIGURATION
# ========================================
# Directory paths for file operations
UPLOAD_FOLDER = "uploads"  # Temporary storage for uploaded files
CONVERTED_FOLDER = "converted"  # Temporary storage for converted files

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)

def force_delete_file(file_path, max_attempts=5, delay=0.5):
    """Force delete a file with retries if it's locked by another process"""
    for attempt in range(max_attempts):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                app.logger.info(f"Successfully deleted {file_path} on attempt {attempt + 1}")
            return
        except PermissionError:
            if attempt < max_attempts - 1:
                app.logger.warning(f"File {file_path} locked, retrying in {delay}s (attempt {attempt + 1}/{max_attempts})")
                time.sleep(delay)
            else:
                app.logger.error(f"Failed to delete {file_path} after {max_attempts} attempts")
        except Exception as e:
            app.logger.error(f"Error deleting {file_path}: {e}")
            break

# Note: Conversion history is stored per user session, not globally

# ========================================
# AUTHENTICATION ROUTES
# ========================================
@app.route("/login")
def login():
    """Redirect user to AWS Cognito hosted login page"""
    # Build OAuth authorization URL with required parameters
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
    # Extract authorization code from callback URL
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    # Exchange authorization code for access and ID tokens
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

    # Store tokens in user session
    tokens = token_response.json()
    session["access_token"] = tokens.get("access_token")
    session["id_token"] = tokens.get("id_token")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    """Clear user session and redirect to Cognito logout"""
    # Clear all session data
    session.clear()
    
    # Redirect to Cognito logout URL
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

    # Check if user has active subscription
    has_subscription = False
    if "id_token" in session:
        try:
            user_info = verify_token(session["id_token"])
            user_id = user_info.get("sub")
            has_subscription = has_active_subscription(user_id)
        except Exception as e:
            # Token expired or invalid - clear session but don't redirect
            print(f"Token validation failed in index: {e}")
            session.clear()

    # Get user's conversion history from session
    session_history = session.get('conversion_history', [])
    text_history = session.get('text_conversion_history', [])
    
    return render_template("index.html", 
                         history=session_history,
                         text_history=text_history,
                         logged_in="id_token" in session,
                         has_subscription=has_subscription)

@app.route("/convert", methods=["POST"])
def convert_file():
    """Handle file conversion requests - supports TXT→PDF, JPG→PNG, PDF→Word"""
    # Validate file upload
    if "file" not in request.files:
        return "No file uploaded", 400

    file = request.files["file"]
    conversion_type = request.form.get("conversion_type")
    if file.filename == "":
        return "No selected file", 400

    # Save uploaded file securely
    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    # ========================================
    # FILE CONVERSION LOGIC
    # ========================================
    output_path = None
    
    # TXT to PDF conversion with ReportLab
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

    else:
        return "Unsupported conversion type", 400

    # ========================================
    # CONVERSION HISTORY TRACKING
    # ========================================
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
        time.sleep(180)  # 3 minutes
        force_delete_file(input_path)
    
    cleanup_thread = threading.Thread(target=delayed_cleanup)
    cleanup_thread.start()
    
    return send_file(output_path, as_attachment=True)

    return send_file(output_path, as_attachment=True)

# ========================================
# USER FEEDBACK SYSTEM
# ========================================
@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    """Handle user feedback submission and save to file"""
    feedback = request.form.get('feedback', '').strip()
    if feedback:
        # Add timestamp to feedback
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        try:
            # Append feedback to text file
            with open('feedback.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {feedback}\n\n")
        except Exception as e:
            app.logger.error(f"Error saving feedback: {e}")
        
        # Return to homepage with success message
        session_history = session.get('conversion_history', [])
        return render_template("index.html", history=session_history, feedback_message="Thank you for your feedback!")
    return redirect(url_for('index'))

# ========================================
# PREMIUM FEATURES (SUBSCRIPTION REQUIRED)
# ========================================
@app.route("/text-convert", methods=["POST"])
@login_required
def text_convert():
    """Premium text conversion feature using AWS services"""
    user_info = verify_token(session["id_token"])
    user_id = user_info.get("sub")
    
    # Check if user has active subscription
    if not has_active_subscription(user_id):
        return jsonify({"error": "Active subscription required"}), 403
    
    # Validate file upload
    if "text_file" not in request.files:
        return "No file uploaded", 400

    file = request.files["text_file"]
    conversion_type = request.form.get("text_conversion_type")
    if file.filename == "":
        return "No selected file", 400

    # Save uploaded file securely
    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    # Get file extension early
    file_ext = filename.lower().split('.')[-1]
    base_filename = filename.rsplit('.', 1)[0]

    try:
        # Initialize AWS clients
        import boto3  # type: ignore
        aws_region = os.getenv('AWS_REGION', 'us-east-1')
        
        translate_client = boto3.client('translate', region_name=aws_region)
        textract_client = boto3.client('textract', region_name=aws_region)
        
        # Extract text from file
        extracted_text = extract_text_from_file(input_path, textract_client)
        
        if not extracted_text:
            return "Could not extract text from file", 400
        
        # Process based on conversion type
        if conversion_type.startswith("translate_"):
            target_lang_map = {
                "translate_chinese": ("zh", "chinese"),
                "translate_spanish": ("es", "spanish"),
                "translate_arabic": ("ar", "arabic"),
                "translate_french": ("fr", "french")
            }
            
            lang_code, lang_name = target_lang_map.get(conversion_type, (None, None))
            if not lang_code:
                return "Unsupported translation language", 400
            
            # Use format preservation for translation
            output_path = translate_with_format_preservation(
                input_path, file_ext, base_filename, lang_code, lang_name, 
                translate_client, textract_client
            )
            
            # Add note for Arabic/Chinese users about TXT format
            if lang_code in ['ar', 'zh'] and 'text_conversion_history' in session:
                session['text_conversion_history'][-1]['note'] = 'Returned as TXT due to font limitations'
        
        elif conversion_type == "ocr_extract_txt":
            output_filename = f"{base_filename}-extracted.txt"
            output_path = os.path.join(CONVERTED_FOLDER, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(extracted_text)
        
        elif conversion_type == "ocr_extract_pdf":
            output_filename = f"{base_filename}-extracted.pdf"
            output_path = os.path.join(CONVERTED_FOLDER, output_filename)
            convert_txt_to_pdf_from_text(extracted_text, output_path)
        
        else:
            return "Unsupported conversion type", 400
        
        # Add to text conversion history
        if 'text_conversion_history' not in session:
            session['text_conversion_history'] = []
        
        session['text_conversion_history'].append({
            "filename": os.path.basename(output_path),
            "conversion_type": conversion_type,
            "timestamp": datetime.datetime.now().strftime("%y/%m/%d")
        })
        
        # Keep only last 5 conversions per session
        session['text_conversion_history'] = session['text_conversion_history'][-5:]
        
        # Schedule file cleanup after 3 minutes
        def delayed_cleanup():
            time.sleep(180)  # 3 minutes
            force_delete_file(input_path)
        
        cleanup_thread = threading.Thread(target=delayed_cleanup)
        cleanup_thread.start()
        
        return send_file(output_path, as_attachment=True)
        
    except Exception as e:
        app.logger.error(f"Text conversion error: {e}")
        return f"Text conversion failed. Please try again.", 500

@app.route("/conversion-progress/<conversion_id>")
@login_required
def conversion_progress(conversion_id):
    """Get conversion progress"""
    progress_data = session.get(f'conversion_{conversion_id}', {'status': 'not_found', 'progress': 0})
    return jsonify(progress_data)

def process_text_conversion(conversion_id, form_data, files_data):
    """Background text conversion with progress updates"""
    try:
        # Update progress
        session[f'conversion_{conversion_id}'] = {'status': 'processing', 'progress': 20}
        
        # Simulate file processing (replace with actual file handling)
        file_data = files_data.get('text_file')
        if not file_data:
            session[f'conversion_{conversion_id}'] = {'status': 'failed', 'error': 'No file uploaded'}
            return
            
        conversion_type = form_data.get('text_conversion_type')
        if not conversion_type:
            session[f'conversion_{conversion_id}'] = {'status': 'failed', 'error': 'No conversion type selected'}
            return
            
        # Save file temporarily
        filename = secure_filename(file_data.filename)
        input_path = os.path.join(UPLOAD_FOLDER, f"{conversion_id}_{filename}")
        file_data.save(input_path)
        
        session[f'conversion_{conversion_id}'] = {'status': 'processing', 'progress': 40}
        
        # Process conversion (existing logic)
        user_info = verify_token(session["id_token"])
        user_id = user_info.get("sub")
        
        if not has_active_subscription(user_id):
            session[f'conversion_{conversion_id}'] = {'status': 'failed', 'error': 'Active subscription required'}
            return
            
        session[f'conversion_{conversion_id}'] = {'status': 'processing', 'progress': 60}
        
        # Initialize AWS clients
        import boto3  # type: ignore
        translate_client = boto3.client('translate', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        textract_client = boto3.client('textract', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        
        session[f'conversion_{conversion_id}'] = {'status': 'processing', 'progress': 80}
        
        # Extract and translate text (simplified)
        file_ext = filename.lower().split('.')[-1]
        base_filename = filename.rsplit('.', 1)[0]
        
        extracted_text = extract_text_from_file(input_path, textract_client)
        if not extracted_text:
            session[f'conversion_{conversion_id}'] = {'status': 'failed', 'error': 'Could not extract text from file'}
            return
            
        # Process conversion
        target_lang_map = {
            "translate_chinese": ("zh", "chinese"),
            "translate_spanish": ("es", "spanish"),
            "translate_arabic": ("ar", "arabic"),
            "translate_french": ("fr", "french")
        }
        
        if conversion_type.startswith("translate_"):
            lang_code, lang_name = target_lang_map.get(conversion_type, (None, None))
            if lang_code:
                output_path = translate_with_format_preservation(
                    input_path, file_ext, base_filename, lang_code, lang_name, 
                    translate_client, textract_client
                )
        elif conversion_type == "ocr_extract_txt":
            output_filename = f"{base_filename}-extracted.txt"
            output_path = os.path.join(CONVERTED_FOLDER, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(extracted_text)
        elif conversion_type == "ocr_extract_pdf":
            output_filename = f"{base_filename}-extracted.pdf"
            output_path = os.path.join(CONVERTED_FOLDER, output_filename)
            convert_txt_to_pdf_from_text(extracted_text, output_path)
        else:
            session[f'conversion_{conversion_id}'] = {'status': 'failed', 'error': 'Unsupported conversion type'}
            return
            
        # Schedule cleanup
        def delayed_cleanup():
            time.sleep(180)
            force_delete_file(input_path)
        threading.Thread(target=delayed_cleanup).start()
        
        # Mark as completed
        session[f'conversion_{conversion_id}'] = {
            'status': 'completed', 
            'progress': 100,
            'download_url': f'/download/{os.path.basename(output_path)}'
        }
        
    except Exception as e:
        session[f'conversion_{conversion_id}'] = {'status': 'failed', 'error': str(e)}

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    """Download converted file"""
    file_path = os.path.join(CONVERTED_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        abort(404)

def text_convert_old_backup():
    user_info = verify_token(session["id_token"])
    user_id = user_info.get("sub")
    
    # Check if user has active subscription
    if not has_active_subscription(user_id):
        return jsonify({"error": "Active subscription required"}), 403
    
    # Validate file upload
    if "text_file" not in request.files:
        return "No file uploaded", 400

    file = request.files["text_file"]
    conversion_type = request.form.get("text_conversion_type")
    if file.filename == "":
        return "No selected file", 400

    # Save uploaded file securely
    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    # Get file extension early
    file_ext = filename.lower().split('.')[-1]
    base_filename = filename.rsplit('.', 1)[0]

    try:
        # Initialize AWS clients with debugging
        import boto3  # type: ignore
        aws_region = os.getenv('AWS_REGION', 'us-east-1')
        app.logger.info(f"Initializing AWS clients in region: {aws_region}")
        
        translate_client = boto3.client('translate', region_name=aws_region)
        textract_client = boto3.client('textract', region_name=aws_region)
        comprehend_client = boto3.client('comprehend', region_name=aws_region)
        
        # Test AWS credentials
        try:
            translate_client.list_text_translation_jobs(MaxResults=1)
            app.logger.info("AWS Translate client initialized successfully")
        except Exception as cred_error:
            app.logger.error(f"AWS credentials issue: {cred_error}")
        
        # Extract text from file with detailed logging
        app.logger.info(f"Extracting text from {filename} (type: {file_ext})")
        extracted_text = extract_text_from_file(input_path, textract_client)
        
        if not extracted_text:
            app.logger.error(f"Text extraction failed for {filename}")
            return "Could not extract text from file", 400
        
        app.logger.info(f"Extracted {len(extracted_text)} characters from {filename}")
        
        # Process based on conversion type
        result_text = ""
        output_filename = ""
        
        # Handle translation with format preservation
        if conversion_type.startswith("translate_"):
            target_lang_map = {
                "translate_chinese": ("zh", "chinese"),
                "translate_spanish": ("es", "spanish"),
                "translate_arabic": ("ar", "arabic"),
                "translate_french": ("fr", "french")
            }
            
            lang_code, lang_name = target_lang_map.get(conversion_type, (None, None))
            if not lang_code:
                return "Unsupported translation language", 400
            
            app.logger.info(f"Starting translation to {lang_name} ({lang_code})")
            
            # Use PyMuPDF for all PDF translations to preserve formatting
            output_path = translate_with_format_preservation(
                input_path, file_ext, base_filename, lang_code, lang_name, 
                translate_client, textract_client
            )
            app.logger.info(f"Translation completed, output: {os.path.basename(output_path)}")
        
        elif conversion_type == "ocr_extract_txt":
            result_text = extracted_text
            output_filename = f"{base_filename}-extracted.txt"
            output_path = os.path.join(CONVERTED_FOLDER, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(result_text)
        
        elif conversion_type == "ocr_extract_pdf":
            output_filename = f"{base_filename}-extracted.pdf"
            output_path = os.path.join(CONVERTED_FOLDER, output_filename)
            convert_txt_to_pdf_from_text(extracted_text, output_path)
        
        else:
            return "Unsupported conversion type", 400
        
        # Add to text conversion history
        if 'text_conversion_history' not in session:
            session['text_conversion_history'] = []
        
        session['text_conversion_history'].append({
            "filename": os.path.basename(output_path),
            "conversion_type": conversion_type,
            "timestamp": datetime.datetime.now().strftime("%y/%m/%d")
        })
        
        # Keep only last 5 conversions per session
        session['text_conversion_history'] = session['text_conversion_history'][-5:]
        
        # Clean up input file
        @after_this_request
        def cleanup(response):
            force_delete_file(input_path)
            return response
        
        return send_file(output_path, as_attachment=True)
        
    except Exception as e:
        app.logger.error(f"Text conversion error: {e}")
        
        # Provide detailed error messages to user
        error_msg = str(e)
        app.logger.error(f"Text conversion error details: {error_msg}")
        
        if "TextSizeLimitExceededException" in error_msg:
            return "Error: Document is too large for translation. Please try a smaller document or contact support.", 400
        elif "UnsupportedDocumentException" in error_msg:
            return "Error: This PDF format is not supported. The document may be corrupted, password-protected, or have complex formatting.", 400
        elif "UnsupportedLanguagePairException" in error_msg:
            return "Error: This language combination is not supported by the translation service.", 400
        elif "AccessDeniedException" in error_msg:
            return "Error: AWS service access denied. Please contact support.", 500
        elif "translate_text" in error_msg:
            return "Error: Translation service failed. The document may be too large or contain unsupported content.", 400
        elif "Could not extract text" in error_msg:
            return "Error: No text could be extracted from this document. Please ensure the file contains readable text.", 400
        elif "PyMuPDF" in error_msg or "reportlab" in error_msg:
            return "Error: PDF processing libraries not available. Please contact support.", 500
        elif "Textract" in error_msg:
            return "Error: Text extraction service failed. The document may be in an unsupported format or too complex.", 400
        else:
            return f"Error: {error_msg[:200]}{'...' if len(error_msg) > 200 else ''}", 500

def convert_txt_to_pdf(input_path, output_path):
    """Convert TXT file to PDF with proper Unicode support and formatting"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for TXT to PDF conversion. Please install: pip install reportlab")
    
    # Auto-detect file encoding
    if CHARDET_AVAILABLE:
        with open(input_path, 'rb') as f:
            raw_data = f.read()
            encoding_result = chardet.detect(raw_data)
            encoding = encoding_result['encoding'] or 'utf-8'
    else:
        encoding = 'utf-8'  # Default to UTF-8 if chardet not available
    
    # Read text with detected encoding
    try:
        with open(input_path, 'r', encoding=encoding) as f:
            text_content = f.read()
    except UnicodeDecodeError:
        # Fallback to utf-8 with error handling
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
    
    # Custom style for body text with better formatting
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,  # Line spacing
        alignment=TA_LEFT,
        spaceAfter=6,
        fontName='Helvetica'  # Will fallback to DejaVu for Unicode
    )
    
    # Custom style for headers (lines that look like headers)
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
        
        if not line:  # Empty line - add space
            story.append(Spacer(1, 6))
            continue
        
        # Detect if line looks like a header (all caps, short, or ends with colon)
        is_header = (
            len(line) < 50 and 
            (line.isupper() or 
             line.endswith(':') or 
             any(word in line.upper() for word in ['EXPERIENCE', 'EDUCATION', 'SKILLS', 'CONTACT', 'SUMMARY', 'OBJECTIVE']))
        )
        
        # Choose appropriate style
        style = header_style if is_header else body_style
        
        # Create paragraph with proper encoding for non-Latin scripts
        try:
            # For Arabic/Chinese text, use a more permissive approach
            if any(ord(c) > 255 for c in line):  # Non-Latin characters detected
                # Use HTML entities for better compatibility
                import html
                escaped_line = html.escape(line)
                para = Paragraph(escaped_line, style)
                story.append(para)
            else:
                # Standard Latin text
                para = Paragraph(line, style)
                story.append(para)
        except Exception as e:
            # If ReportLab can't handle the text, create a readable fallback
            app.logger.warning(f"PDF encoding issue for line: {line[:50]}... Error: {e}")
            # Create a note about the untranslatable content
            fallback_text = f"[Arabic/Chinese text - {len(line)} characters - ReportLab cannot display]"
            para = Paragraph(fallback_text, style)
            story.append(para)
    
    # Build PDF
    doc.build(story)

def translate_with_format_preservation(input_path, file_ext, base_filename, lang_code, lang_name, translate_client, textract_client):
    """Translate file while preserving original format"""
    # For Arabic/Chinese, use text-based translation due to font limitations
    if lang_code in ['ar', 'zh']:
        return translate_to_text_based(input_path, file_ext, base_filename, lang_code, lang_name, translate_client, textract_client)
    
    # For Latin scripts, try PyMuPDF format preservation
    if file_ext == 'pdf':
        return translate_pdf_pymupdf(input_path, base_filename, lang_code, lang_name, translate_client)
    elif file_ext == 'txt':
        return translate_txt_preserve_format(input_path, base_filename, lang_code, lang_name, translate_client)
    elif file_ext in ['jpg', 'jpeg', 'png']:
        return translate_image_to_pdf(input_path, base_filename, lang_code, lang_name, translate_client, textract_client)
    else:
        raise ValueError(f"Unsupported file format: {file_ext}")

def translate_pdf_pymupdf(input_path, base_filename, lang_code, lang_name, translate_client):
    """Translate PDF while preserving formatting (Latin scripts only)"""
    if not PYMUPDF_AVAILABLE:
        raise ImportError("PyMuPDF is required for format-preserving PDF translation")
    
    output_filename = f"{base_filename}-{lang_name}.pdf"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    
    # Open the PDF
    doc = fitz.open(input_path)
    
    for page_num in range(len(doc)):
        page = doc[page_num]
        text_dict = page.get_text("dict")
        
        # Process each text block
        for block in text_dict["blocks"]:
            if "lines" not in block:
                continue
                
            for line in block["lines"]:
                for span in line["spans"]:
                    original_text = span["text"].strip()
                    if not original_text or len(original_text) < 2:
                        continue
                    
                    try:
                        translated_text = translate_text_chunked(original_text, translate_client, lang_code)
                        bbox = span["bbox"]
                        size = span["size"]
                        
                        # Clear original text with larger rectangle to avoid remnants
                        expanded_rect = fitz.Rect(bbox[0]-2, bbox[1]-2, bbox[2]+2, bbox[3]+2)
                        page.draw_rect(expanded_rect, color=(1, 1, 1), fill=True)
                        
                        # Insert translated text with better positioning
                        page.insert_text(
                            (bbox[0], bbox[3] - 2),  # Better baseline positioning
                            translated_text,
                            fontname="helv",
                            fontsize=size,
                            color=0
                        )
                        
                    except Exception as e:
                        app.logger.warning(f"Translation failed for '{original_text[:20]}...': {e}")
                        continue
    
    doc.save(output_path)
    doc.close()
    return output_path

def translate_pdf_preserve_format_old(input_path, base_filename, lang_code, lang_name, translate_client):
    """Translate PDF while preserving layout and form fields"""
    if not PYMUPDF_AVAILABLE:
        raise ImportError("PyMuPDF is required for PDF translation. Please install: pip install PyMuPDF")
    
    output_filename = f"{base_filename}-{lang_name}.pdf"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    
    try:
        # Open PDF with PyMuPDF
        doc = fitz.open(input_path)
        new_doc = fitz.open()
        
        for page_num in range(len(doc)):
            page = doc[page_num]
            new_page = new_doc.new_page(width=page.rect.width, height=page.rect.height)
            
            # Extract text blocks with positioning
            text_dict = page.get_text("dict")
            
            # Copy images and graphics
            new_page.show_pdf_page(page.rect, doc, page_num)
            
            # Process text blocks
            for block in text_dict["blocks"]:
                if "lines" in block:
                    for line in block["lines"]:
                        for span in line["spans"]:
                            text = span["text"].strip()
                            if text:
                                # Translate text in chunks
                                translated_text = translate_text_chunked(text, translate_client, lang_code)
                                
                                # Place translated text at original position
                                new_page.insert_text(
                                    (span["bbox"][0], span["bbox"][1]),
                                    translated_text,
                                    fontname=span["font"],
                                    fontsize=span["size"],
                                    color=span.get("color", 0)
                                )
        
        # Save translated PDF
        new_doc.save(output_path)
        new_doc.close()
        doc.close()
        
        return output_path
        
    except Exception as e:
        # Fallback to text-based translation with warning
        app.logger.warning(f"PDF translation fallback for {input_path}: {e}")
        return translate_pdf_fallback(input_path, base_filename, lang_code, lang_name, translate_client)

def translate_txt_preserve_format(input_path, base_filename, lang_code, lang_name, translate_client):
    """Translate TXT file while preserving structure"""
    output_filename = f"{base_filename}-{lang_name}.txt"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    
    # Read text with encoding detection
    if CHARDET_AVAILABLE:
        with open(input_path, 'rb') as f:
            raw_data = f.read()
            encoding_result = chardet.detect(raw_data)
            encoding = encoding_result['encoding'] or 'utf-8'
    else:
        encoding = 'utf-8'
    
    with open(input_path, 'r', encoding=encoding, errors='replace') as f:
        content = f.read()
    
    # Translate while preserving line structure
    lines = content.split('\n')
    translated_lines = []
    
    for line in lines:
        if line.strip():
            translated_line = translate_text_chunked(line, translate_client, lang_code)
            translated_lines.append(translated_line)
        else:
            translated_lines.append('')  # Preserve empty lines
    
    # Save translated text
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(translated_lines))
    
    return output_path

def translate_to_text_based(input_path, file_ext, base_filename, lang_code, lang_name, translate_client, textract_client):
    """Fallback to text-based translation for Arabic/Chinese"""
    # Extract text from file
    extracted_text = extract_text_from_file(input_path, textract_client)
    if not extracted_text:
        raise Exception("Could not extract text from file")
    
    # Translate text
    translated_text = translate_text_chunked(extracted_text, translate_client, lang_code)
    
    # Return as TXT file for Arabic/Chinese
    output_filename = f"{base_filename}-{lang_name}.txt"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(translated_text)
    
    return output_path

def translate_image_to_pdf(input_path, base_filename, lang_code, lang_name, translate_client, textract_client):
    """Extract text from image and translate"""
    # Extract text using Textract
    with open(input_path, 'rb') as f:
        response = textract_client.detect_document_text(
            Document={'Bytes': f.read()}
        )
    
    extracted_text = ""
    for item in response['Blocks']:
        if item['BlockType'] == 'LINE':
            extracted_text += item['Text'] + '\n'
    
    # Translate extracted text
    translated_text = translate_text_chunked(extracted_text, translate_client, lang_code)
    
    # For Arabic/Chinese from images, return as TXT
    if lang_code in ['ar', 'zh']:
        output_filename = f"{base_filename}-{lang_name}.txt"
        output_path = os.path.join(CONVERTED_FOLDER, output_filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(translated_text)
    else:
        # For Latin scripts, create PDF
        output_filename = f"{base_filename}-{lang_name}.pdf"
        output_path = os.path.join(CONVERTED_FOLDER, output_filename)
        convert_txt_to_pdf_from_text(translated_text, output_path)
    
    return output_path

def translate_pdf_fallback(input_path, base_filename, lang_code, lang_name, translate_client):
    """Fallback PDF translation using text extraction"""
    output_filename = f"{base_filename}-{lang_name}.pdf"
    output_path = os.path.join(CONVERTED_FOLDER, output_filename)
    
    app.logger.info(f"Using PDF fallback translation for {input_path}")
    
    # Extract text using PyPDF2 with better encoding handling
    pdf_reader = PyPDF2.PdfReader(open(input_path, "rb"))
    extracted_text = ""
    for page_num, page in enumerate(pdf_reader.pages):
        try:
            text = page.extract_text()
            if text:
                extracted_text += text + "\n"
                app.logger.info(f"Extracted {len(text)} chars from page {page_num + 1}")
        except Exception as e:
            app.logger.warning(f"Failed to extract text from page {page_num + 1}: {e}")
    
    if not extracted_text.strip():
        raise Exception("No text could be extracted from PDF using PyPDF2")
    
    # Clean up PyPDF2's fragmented text
    extracted_text = clean_pypdf2_text(extracted_text)
    app.logger.info(f"Total extracted and cleaned text: {len(extracted_text)} characters")
    
    # Translate text
    translated_text = translate_text_chunked(extracted_text, translate_client, lang_code)
    
    # Create formatted PDF
    convert_txt_to_pdf_from_text(translated_text, output_path)
    
    return output_path

def translate_text_chunked(text, translate_client, target_lang):
    """Translate text in chunks to handle AWS Translate limits"""
    if not text or not text.strip():
        return ""
    
    # Clean and validate input text
    text = text.strip()
    if len(text) < 3:  # Skip very short text
        return text
    
    app.logger.info(f"Translating {len(text)} characters to {target_lang}")
    
    # Handle single small text
    if len(text) <= 4000:  # More conservative limit
        try:
            response = translate_client.translate_text(
                Text=text,
                SourceLanguageCode='auto',
                TargetLanguageCode=target_lang
            )
            translated = response['TranslatedText']
            app.logger.info(f"Successfully translated small text ({len(text)} -> {len(translated)} chars)")
            return translated
        except Exception as e:
            app.logger.error(f"Translation failed for small text: {str(e)[:200]}...")
            # Check if it's a specific AWS error
            if "UnsupportedLanguagePairException" in str(e):
                raise Exception(f"Language pair not supported for translation to {target_lang}")
            elif "TextSizeLimitExceededException" in str(e):
                raise Exception("Text is too large for translation")
            else:
                raise e
    
    # For large text, split by paragraphs first
    paragraphs = text.split('\n\n')
    translated_paragraphs = []
    current_chunk = ""
    chunk_count = 0
    
    for paragraph in paragraphs:
        paragraph = paragraph.strip()
        if not paragraph:
            continue
            
        # If single paragraph is too large, split by sentences
        if len(paragraph) > 3500:
            sentences = paragraph.split('. ')
            for sentence in sentences:
                sentence = sentence.strip()
                if not sentence:
                    continue
                    
                if len(current_chunk + sentence) <= 3000:  # Conservative buffer
                    current_chunk += sentence + ". "
                else:
                    if current_chunk.strip():
                        try:
                            chunk_count += 1
                            app.logger.info(f"Translating chunk {chunk_count} ({len(current_chunk)} chars)")
                            response = translate_client.translate_text(
                                Text=current_chunk.strip(),
                                SourceLanguageCode='auto',
                                TargetLanguageCode=target_lang
                            )
                            translated_paragraphs.append(response['TranslatedText'])
                        except Exception as e:
                            app.logger.error(f"Translation failed for chunk {chunk_count}: {str(e)[:200]}...")
                            raise e
                    current_chunk = sentence + ". "
        else:
            # Normal paragraph processing
            if len(current_chunk + paragraph) <= 3000:
                current_chunk += paragraph + "\n\n"
            else:
                if current_chunk.strip():
                    try:
                        chunk_count += 1
                        app.logger.info(f"Translating chunk {chunk_count} ({len(current_chunk)} chars)")
                        response = translate_client.translate_text(
                            Text=current_chunk.strip(),
                            SourceLanguageCode='auto',
                            TargetLanguageCode=target_lang
                        )
                        translated_paragraphs.append(response['TranslatedText'])
                    except Exception as e:
                        app.logger.error(f"Translation failed for chunk {chunk_count}: {str(e)[:200]}...")
                        raise e
                current_chunk = paragraph + "\n\n"
    
    # Translate remaining chunk
    if current_chunk.strip():
        try:
            chunk_count += 1
            app.logger.info(f"Translating final chunk {chunk_count} ({len(current_chunk)} chars)")
            response = translate_client.translate_text(
                Text=current_chunk.strip(),
                SourceLanguageCode='auto',
                TargetLanguageCode=target_lang
            )
            translated_paragraphs.append(response['TranslatedText'])
        except Exception as e:
            app.logger.error(f"Translation failed for final chunk: {str(e)[:200]}...")
            raise e
    
    final_result = '\n\n'.join(translated_paragraphs)
    app.logger.info(f"Translation completed: {chunk_count} chunks, {len(final_result)} final chars")
    return final_result

def convert_txt_to_pdf_from_text(text_content, output_path):
    """Convert text content directly to PDF with formatting"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for PDF creation. Please install: pip install reportlab")
    
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
        
        # Detect headers
        is_header = (
            len(line) < 50 and 
            (line.isupper() or 
             line.endswith(':') or 
             any(word in line.upper() for word in ['EXPERIENCE', 'EDUCATION', 'SKILLS', 'CONTACT', 'SUMMARY', 'OBJECTIVE']))
        )
        
        style = header_style if is_header else body_style
        
        try:
            # For Arabic/Chinese text, use a more permissive approach
            if any(ord(c) > 255 for c in line):  # Non-Latin characters detected
                # Use HTML entities for better compatibility
                import html
                escaped_line = html.escape(line)
                para = Paragraph(escaped_line, style)
                story.append(para)
            else:
                # Standard Latin text
                para = Paragraph(line, style)
                story.append(para)
        except Exception as e:
            # If ReportLab can't handle the text, create a readable fallback
            app.logger.warning(f"PDF encoding issue for line: {line[:50]}... Error: {e}")
            # Create a note about the untranslatable content
            fallback_text = f"[Arabic/Chinese text - {len(line)} characters - ReportLab cannot display]"
            para = Paragraph(fallback_text, style)
            story.append(para)
    
    doc.build(story)

def format_text_for_readability(text):
    """Format translated text for better readability"""
    if not text:
        return text
    
    # Split into paragraphs
    paragraphs = text.split('\n\n')
    formatted_paragraphs = []
    
    for para in paragraphs:
        para = para.strip()
        if para:
            # Ensure proper line breaks for long paragraphs
            sentences = para.split('. ')
            if len(sentences) > 1:
                # Rejoin sentences with proper spacing
                formatted_para = '. '.join(sentences)
                if not formatted_para.endswith('.'):
                    formatted_para += '.'
                formatted_paragraphs.append(formatted_para)
            else:
                formatted_paragraphs.append(para)
    
    return '\n\n'.join(formatted_paragraphs)

def clean_pypdf2_text(text):
    """Clean up PyPDF2's fragmented text extraction"""
    if not text:
        return text
    
    lines = text.split('\n')
    cleaned_lines = []
    current_paragraph = []
    
    for line in lines:
        line = line.strip()
        if not line:
            # Empty line - end current paragraph
            if current_paragraph:
                cleaned_lines.append(' '.join(current_paragraph))
                current_paragraph = []
            cleaned_lines.append('')  # Preserve paragraph breaks
        else:
            # Check if this looks like a continuation of previous line
            if (current_paragraph and 
                len(line) > 3 and 
                not line[0].isupper() and 
                not line.endswith('.') and
                not line.endswith(':')):
                # Likely continuation - add to current paragraph
                current_paragraph.append(line)
            else:
                # New sentence/paragraph
                if current_paragraph:
                    cleaned_lines.append(' '.join(current_paragraph))
                current_paragraph = [line]
    
    # Don't forget the last paragraph
    if current_paragraph:
        cleaned_lines.append(' '.join(current_paragraph))
    
    # Join with proper spacing
    result = '\n'.join(cleaned_lines)
    
    # Remove excessive whitespace
    import re
    result = re.sub(r'\n\s*\n\s*\n', '\n\n', result)  # Max 2 consecutive newlines
    result = re.sub(r' +', ' ', result)  # Multiple spaces to single space
    
    return result.strip()

def extract_text_from_file(file_path, textract_client):
    """Extract text from various file types using AWS Textract or direct reading"""
    file_ext = file_path.lower().split('.')[-1]
    
    try:
        if file_ext == 'txt':
            # Direct text file reading with encoding detection
            if CHARDET_AVAILABLE:
                with open(file_path, 'rb') as f:
                    raw_data = f.read()
                    encoding_result = chardet.detect(raw_data)
                    encoding = encoding_result['encoding'] or 'utf-8'
            else:
                encoding = 'utf-8'
            
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                return f.read()
        
        elif file_ext == 'pdf':
            # Try Textract first, fallback to PyPDF2
            try:
                with open(file_path, 'rb') as f:
                    file_bytes = f.read()
                    # Check file size (Textract limit is 10MB)
                    if len(file_bytes) > 10 * 1024 * 1024:
                        app.logger.info(f"PDF file too large ({len(file_bytes)} bytes) for Textract, using PyPDF2")
                        raise Exception("File too large for Textract")
                    
                    app.logger.info(f"Attempting Textract on PDF ({len(file_bytes)} bytes)")
                    response = textract_client.detect_document_text(
                        Document={'Bytes': file_bytes}
                    )
                
                text = ""
                for item in response['Blocks']:
                    if item['BlockType'] == 'LINE':
                        text += item['Text'] + '\n'
                
                if text.strip():
                    app.logger.info(f"Textract successfully extracted {len(text)} characters from PDF")
                    return text
                else:
                    app.logger.warning("Textract returned no text, falling back to PyPDF2")
                    raise Exception("Textract returned no text")
                    
            except Exception as e:
                # Fallback to PyPDF2 for unsupported PDFs
                app.logger.warning(f"Textract failed for PDF: {str(e)[:200]}... Using PyPDF2 fallback")
                try:
                    pdf_reader = PyPDF2.PdfReader(open(file_path, "rb"))
                    text = ""
                    for page in pdf_reader.pages:
                        page_text = page.extract_text()
                        if page_text:
                            text += page_text + "\n"
                    
                    if text.strip():
                        # Clean up PyPDF2's fragmented text extraction
                        cleaned_text = clean_pypdf2_text(text)
                        app.logger.info(f"PyPDF2 extracted {len(text)} chars, cleaned to {len(cleaned_text)} chars")
                        return cleaned_text
                    else:
                        app.logger.warning("PyPDF2 extracted no text from PDF")
                        return "[No text could be extracted from this PDF]"
                except Exception as pdf_error:
                    app.logger.error(f"Both Textract and PyPDF2 failed: {pdf_error}")
                    return "[Error: Could not extract text from this PDF]"
        
        elif file_ext in ['jpg', 'jpeg', 'png']:
            # Use Textract for images with better error handling
            try:
                with open(file_path, 'rb') as f:
                    file_bytes = f.read()
                    app.logger.info(f"Attempting Textract on image ({len(file_bytes)} bytes)")
                    response = textract_client.detect_document_text(
                        Document={'Bytes': file_bytes}
                    )
                
                text = ""
                for item in response['Blocks']:
                    if item['BlockType'] == 'LINE':
                        text += item['Text'] + '\n'
                
                if text.strip():
                    app.logger.info(f"Textract successfully extracted {len(text)} characters from image")
                    return text
                else:
                    app.logger.warning("Textract returned no text from image")
                    return "[No text could be extracted from this image]"
                    
            except Exception as e:
                app.logger.error(f"Textract failed for image: {str(e)[:200]}...")
                return f"[Error: Could not extract text from this image: {str(e)[:100]}...]"
        
        else:
            return None
            
    except Exception as e:
        app.logger.error(f"Text extraction error: {e}")
        return None

# ========================================
# BLOG AND SEO CONTENT ROUTES
# ========================================
@app.route('/blog/pdf-to-word.html')
def blog_pdf_to_word():
    """Blog post about PDF to Word conversion"""
    return render_template('blog/pdf-to-word.html')

@app.route('/blog/jpg-to-png.html')
def blog_jpg_to_png():
    """Blog post about JPG to PNG conversion"""
    return render_template('blog/jpg-to-png.html')

@app.route('/blog/txt-to-pdf.html')
def blog_txt_to_pdf():
    """Blog post about TXT to PDF conversion"""
    return render_template('blog/txt-to-pdf.html')

# ========================================
# HTTP RESPONSE OPTIMIZATION
# ========================================
@app.after_request
def add_cache_control(response):
    """Add appropriate cache headers for performance optimization"""
    if request.path.startswith('/static/'):
        # Cache static files (CSS, JS, images) for 30 days
        response.headers['Cache-Control'] = 'public, max-age=2592000'
    else:
        # Cache other pages for 5 minutes
        response.headers['Cache-Control'] = 'public, max-age=300'
    return response

# ========================================
# ERROR HANDLING
# ========================================
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page"""
    return render_template('404.html'), 404

# ========================================
# STRIPE PAYMENT AND SUBSCRIPTION ROUTES
# ========================================

@app.route("/account")
@login_required
def account():
    """User account page showing subscription status and management options"""
    user_info = verify_token(session["id_token"])
    user_id = user_info.get("sub")

    # Get subscription status from local database
    user_stripe = get_subscription(user_id)
    subscription_status = user_stripe['subscription_status'] if user_stripe else 'inactive'

    # Sync with Stripe API to get latest subscription status
    if user_stripe and user_stripe.get("stripe_customer_id"):
        try:
            stripe_subs = stripe.Subscription.list(customer=user_stripe["stripe_customer_id"], limit=1)
            if stripe_subs.data:
                stripe_sub = stripe_subs.data[0]
                subscription_status = stripe_sub.status
                # Keep local database in sync with Stripe
                update_subscription_status(user_id, subscription_status)
        except Exception as e:
            app.logger.warning(f"Stripe API sync failed for user {user_id}: {e}")

    # Determine if subscription is currently active
    subscription_active = subscription_status in ["active", "trialing"]

    return render_template(
        "account.html",
        user=user_info,
        subscription_active=subscription_active,
        subscription_status=subscription_status,
        stripe_publishable_key=os.getenv("STRIPE_PUBLISHABLE_KEY"),
        stripe_price_subscription=os.getenv("STRIPE_PRICE_SUBSCRIPTION_MONTHLY"),
    )

@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    """Create Stripe checkout session for subscription purchase"""
    user_info = verify_token(session["id_token"])
    user_id = user_info["sub"]
    
    try:
        # Create or retrieve existing Stripe customer
        user_sub = get_subscription(user_id)
        if user_sub and user_sub.get("stripe_customer_id"):
            customer_id = user_sub["stripe_customer_id"]
        else:
            # Create new Stripe customer
            customer = stripe.Customer.create(
                email=user_info.get("email"),
                metadata={"user_id": user_id}
            )
            customer_id = customer.id
            # Save customer ID to database
            create_or_update_user(user_id, stripe_customer_id=customer_id)
        
        # Create Stripe checkout session for monthly subscription
        session_id = stripe.checkout.Session.create(
            customer=customer_id,
            line_items=[{
                "price": os.getenv("STRIPE_PRICE_SUBSCRIPTION_MONTHLY"),
                "quantity": 1,
            }],
            mode="subscription",
            success_url=url_for('purchase_success', _external=True),
            cancel_url=url_for('purchase_cancel', _external=True),
            metadata={"user_id": user_id}
        )

    # user_info = verify_token(session["id_token"])
    # user_id = user_info["sub"]

    # data = request.json
    # product_type = data.get("product_type")  # should be 'subscription' only now
    # price_id = data.get("price_id")
    # quantity = data.get("quantity", 1)

    # if product_type != "subscription" or not price_id:
    #     return jsonify({"error": "Invalid purchase info"}), 400

    # try:
    #     # Create or retrieve Stripe customer
    #     user = get_subscription(user_id)
    #     if user and user["stripe_customer_id"]:
    #         customer_id = user["stripe_customer_id"]
    #     else:
    #         stripe_customer = stripe.Customer.create(
    #             email=user_info.get("email"),
    #             metadata={"user_id": user_id}
    #         )
    #         customer_id = stripe_customer.id
    #         create_or_update_user(user_id, stripe_customer_id=customer_id)

    #     # Create Stripe Checkout session for subscription only
    #     checkout_session = stripe.checkout.Session.create(
    #         customer=customer_id,
    #         payment_method_types=["card"],
    #         line_items=[{
    #             "price": price_id,
    #             "quantity": quantity,
    #         }],
    #         mode="subscription",
    #         success_url=url_for('purchase_success', _external=True),
    #         cancel_url=url_for('purchase_cancel', _external=True),
    #         metadata={"user_id": user_id, "product_type": product_type, "quantity": quantity}
    #     )

    #     return jsonify({"checkout_url": checkout_session.url})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({"checkout_url": session_id.url})

# ========================================
# STRIPE WEBHOOK HANDLER
# ========================================
@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events for subscription management"""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    print(f"Webhook received: {len(payload)} bytes")
    print(f"Signature header: {sig_header[:50] if sig_header else 'None'}...")

    # Verify webhook signature for security
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError as e:
        print(f"Invalid payload: {e}")
        app.logger.warning("Invalid Stripe webhook payload")
        abort(400)
    except stripe.error.SignatureVerificationError as e:
        print(f"Invalid signature: {e}")
        app.logger.warning("Invalid Stripe webhook signature")
        abort(400)

    # Extract event information
    event_type = event.get('type')
    data_object = event.get('data', {}).get('object', {})
    
    print(f"Processing webhook event: {event_type}")
    app.logger.info(f"Received webhook event: {event_type}")

    try:
        # ========================================
        # WEBHOOK EVENT PROCESSING
        # ========================================
        
        # Handle successful checkout completion
        if event_type == 'checkout.session.completed':
            session_obj = data_object
            mode = session_obj.get('mode')
            metadata = session_obj.get('metadata', {}) or {}

            # Prefer user_id from metadata (you set this when creating the session)
            user_id = metadata.get('user_id')
            subscription_id = session_obj.get('subscription')  # subscription id (if mode == subscription)
            customer_id = session_obj.get('customer')

            if mode == 'subscription' and subscription_id:
                # fetch subscription details from Stripe (status, current_period_end, etc.)
                try:
                    subscription = stripe.Subscription.retrieve(subscription_id)
                except Exception as e:
                    app.logger.warning(f"Failed to retrieve subscription {subscription_id}: {e}")
                    subscription = None

                status = subscription.status if subscription else None
                current_period_end = getattr(subscription, "current_period_end", None) if subscription else None

                # If no user_id in metadata, try to find by stripe_customer_id
                if not user_id and customer_id:
                    from stripe_db import get_db_connection
                    with get_db_connection() as conn:
                        c = conn.cursor()
                        c.execute("SELECT user_id FROM subscriptions WHERE stripe_customer_id = %s", (customer_id,))
                        row = c.fetchone()
                        if row:
                            user_id = row[0]

                # If we found a user_id, persist mapping and subscription info
                if user_id:
                    # ensure stripe_customer_id stored for this user
                    if customer_id:
                        try:
                            create_or_update_user(user_id, stripe_customer_id=customer_id)
                        except Exception as e:
                            app.logger.warning(f"create_or_update_user failed for {user_id}: {e}")

                    # save_subscription keeps subscription id, status and current_period_end in DB
                    try:
                        save_subscription(user_id, customer_id, subscription_id, status, current_period_end)
                    except Exception as e:
                        app.logger.warning(f"save_subscription failed for {user_id}: {e}")

                    # Also update subscription_status field
                    try:
                        update_subscription_status(user_id, status)
                    except Exception as e:
                        app.logger.warning(f"update_subscription_status failed for {user_id}: {e}")

                    app.logger.info(f"checkout.session.completed handled for user {user_id}, subscription {subscription_id}, status {status}")

        # Handle subscription lifecycle events
        elif event_type in ('customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted'):
            subscription = data_object
            customer_id = subscription.get('customer')
            subscription_id = subscription.get('id')
            status = subscription.get('status')
            current_period_end = subscription.get('current_period_end')

            # find application user_id by stripe_customer_id
            user_id = None
            if customer_id:
                from stripe_db import get_db_connection
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT user_id FROM subscriptions WHERE stripe_customer_id = %s", (customer_id,))
                    row = c.fetchone()
                    if row:
                        user_id = row[0]

            if user_id:
                # persist/update sub info in DB
                try:
                    save_subscription(user_id, customer_id, subscription_id, status, current_period_end)
                except Exception as e:
                    app.logger.warning(f"save_subscription failed for {user_id}: {e}")

                try:
                    update_subscription_status(user_id, status)
                except Exception as e:
                    app.logger.warning(f"update_subscription_status failed for {user_id}: {e}")

                app.logger.info(f"Handled {event_type} for user {user_id}, status {status}")

        # Handle successful payment events
        elif event_type == 'invoice.payment_succeeded':
            invoice = data_object
            subscription_id = invoice.get('subscription')
            # find customer_id and user_id if possible and mark active
            if subscription_id:
                try:
                    sub = stripe.Subscription.retrieve(subscription_id)
                    customer_id = sub.get('customer')
                    status = sub.get('status')
                    current_period_end = sub.get('current_period_end')

                    user_id = None
                    if customer_id:
                        from stripe_db import get_db_connection
                        with get_db_connection() as conn:
                            c = conn.cursor()
                            c.execute("SELECT user_id FROM subscriptions WHERE stripe_customer_id = %s", (customer_id,))
                            row = c.fetchone()
                            if row:
                                user_id = row[0]

                    if user_id:
                        save_subscription(user_id, customer_id, subscription_id, status, current_period_end)
                        update_subscription_status(user_id, status)
                        app.logger.info(f"invoice.payment_succeeded: updated user {user_id} to {status}")
                except Exception as e:
                    app.logger.warning(f"invoice.payment_succeeded handling failed: {e}")

        # Handle failed payment events
        elif event_type == 'invoice.payment_failed':
            invoice = data_object
            subscription_id = invoice.get('subscription')
            if subscription_id:
                try:
                    sub = stripe.Subscription.retrieve(subscription_id)
                    customer_id = sub.get('customer')
                    status = sub.get('status')
                    user_id = None
                    if customer_id:
                        from stripe_db import get_db_connection
                        with get_db_connection() as conn:
                            c = conn.cursor()
                            c.execute("SELECT user_id FROM subscriptions WHERE stripe_customer_id = %s", (customer_id,))
                            row = c.fetchone()
                            if row:
                                user_id = row[0]
                    if user_id:
                        update_subscription_status(user_id, status or 'past_due')
                        app.logger.info(f"invoice.payment_failed: set status {status} for user {user_id}")
                except Exception as e:
                    app.logger.warning(f"invoice.payment_failed handling failed: {e}")

    except Exception as ex:
        app.logger.exception(f"Unhandled exception in stripe_webhook: {ex}")
        # still respond 200 to avoid repeated retries only if you decide so.
        # but better to return 500 so Stripe retries. We return 500 here.
        abort(500)

    print(f"Webhook {event_type} processed successfully")
    return jsonify({'status': 'success'})

# ========================================
# PAYMENT METHOD SETUP
# ========================================
@app.route("/create-setup-intent", methods=["POST"])
@login_required
def create_setup_intent():
    """Create Stripe SetupIntent for collecting payment methods"""
    user_info = verify_token(session["id_token"])
    user_id = user_info.get("sub")

    data = request.get_json()
    price_id = data.get("price_id")

    if not price_id:
        return jsonify({"error": "Missing price_id"}), 400

    # Get or create Stripe customer
    user_sub = get_subscription(user_id)

    if user_sub and user_sub.get("stripe_customer_id"):
        customer_id = user_sub["stripe_customer_id"]
    else:
        # Create new Stripe customer
        customer = stripe.Customer.create(
            email=user_info.get("email"),
            metadata={"user_id": user_id}
        )
        customer_id = customer.id
        # Save customer ID to database
        create_or_update_user(user_id, stripe_customer_id=customer_id)

    # Create SetupIntent for future payment collection
    setup_intent = stripe.SetupIntent.create(
        customer=customer_id,
        payment_method_types=["card"],
    )

    return jsonify({"client_secret": setup_intent.client_secret})


# ========================================
# SUBSCRIPTION PURCHASE FLOW PAGES
# ========================================
@app.route('/purchase')
@login_required
def purchase():
    """Subscription purchase page with Stripe integration"""
    return render_template('purchase.html',
                           stripe_publishable_key=os.getenv("STRIPE_PUBLISHABLE_KEY"),
                           stripe_price_subscription=os.getenv("STRIPE_PRICE_SUBSCRIPTION_MONTHLY"))

@app.route('/purchase-success')
@login_required
def purchase_success():
    """Success page after successful subscription purchase"""
    return render_template('purchase_success.html')

@app.route('/purchase-cancel')
@login_required
def purchase_cancel():
    """Cancel page when user cancels subscription purchase"""
    return render_template('purchase_cancel.html')




# ========================================
# DEBUG AND TESTING ROUTES
# ========================================
@app.route('/debug/aws-test')
@login_required
def debug_aws_test():
    """Debug route to test AWS services connectivity"""
    import boto3
    results = {}
    
    try:
        # Test Translate
        translate_client = boto3.client('translate', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        test_response = translate_client.translate_text(
            Text="Hello world",
            SourceLanguageCode='en',
            TargetLanguageCode='es'
        )
        results['translate'] = f"✓ Working: {test_response['TranslatedText']}"
    except Exception as e:
        results['translate'] = f"✗ Failed: {str(e)[:100]}..."
    
    try:
        # Test Textract
        textract_client = boto3.client('textract', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        # Create a simple test image with text
        from PIL import Image, ImageDraw, ImageFont
        import io
        
        img = Image.new('RGB', (200, 100), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((10, 10), "Test text", fill='black')
        
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        response = textract_client.detect_document_text(
            Document={'Bytes': img_bytes.getvalue()}
        )
        
        text_found = any(block.get('Text', '').strip() for block in response.get('Blocks', []))
        results['textract'] = f"✓ Working: Found text = {text_found}"
    except Exception as e:
        results['textract'] = f"✗ Failed: {str(e)[:100]}..."
    
    # Test region and credentials
    results['region'] = os.getenv('AWS_REGION', 'us-east-1')
    results['access_key'] = f"{os.getenv('AWS_ACCESS_KEY_ID', 'Not set')[:10]}..."
    
    return f"<pre>{chr(10).join(f'{k}: {v}' for k, v in results.items())}</pre>"

# ========================================
# APPLICATION STARTUP
# ========================================
if __name__ == "__main__":
    # Development server configuration
    # Note: Use gunicorn or similar WSGI server in production
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

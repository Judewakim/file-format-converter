# ========================================
# IMPORTS AND DEPENDENCIES
# ========================================
# Flask framework and utilities
from flask import Flask, render_template, request, send_file, redirect, url_for, after_this_request, session, abort, jsonify
import os
import secrets
from werkzeug.utils import secure_filename

# File processing libraries
from PIL import Image  # Image conversion (JPG to PNG)
import PyPDF2  # PDF reading and processing
from docx import Document  # Word document creation
import io
import datetime

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

    # Verify and decode JWT token
    public_key = RSAAlgorithm.from_jwk(key_data)
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=COGNITO_CLIENT_ID,
        issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}"
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
    
    return render_template("index.html", 
                         history=session_history, 
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
    
    # TXT to PDF conversion
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
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    # Keep only last 5 conversions per session
    session['conversion_history'] = session['conversion_history'][-5:]

    # Clean up uploaded file after response
    @after_this_request
    def cleanup(response):
        try:
            os.remove(input_path)
        except Exception as e:
            app.logger.error(f"Error deleting uploaded file {input_path}: {e}")
        return response

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

    try:
        # Initialize AWS clients
        import boto3
        translate_client = boto3.client('translate', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        textract_client = boto3.client('textract', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        comprehend_client = boto3.client('comprehend', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        
        # Extract text from file
        extracted_text = extract_text_from_file(input_path, textract_client)
        
        if not extracted_text:
            return "Could not extract text from file", 400
        
        # Process based on conversion type
        result_text = ""
        output_filename = ""
        
        if conversion_type.startswith("translate_"):
            target_lang = {
                "translate_spanish": "es",
                "translate_french": "fr", 
                "translate_german": "de",
                "translate_chinese": "zh"
            }.get(conversion_type)
            
            if target_lang:
                response = translate_client.translate_text(
                    Text=extracted_text[:5000],  # AWS Translate limit
                    SourceLanguageCode='auto',
                    TargetLanguageCode=target_lang
                )
                result_text = response['TranslatedText']
                output_filename = f"{filename.rsplit('.', 1)[0]}_translated_{target_lang}.txt"
        
        elif conversion_type == "ocr_extract":
            result_text = extracted_text
            output_filename = f"{filename.rsplit('.', 1)[0]}_extracted.txt"
        
        elif conversion_type == "detect_language":
            response = comprehend_client.detect_dominant_language(
                Text=extracted_text[:5000]
            )
            languages = response['Languages']
            result_text = f"Detected Languages:\n"
            for lang in languages:
                result_text += f"- {lang['LanguageCode']}: {lang['Score']:.2%} confidence\n"
            output_filename = f"{filename.rsplit('.', 1)[0]}_language_detection.txt"
        
        else:
            return "Unsupported conversion type", 400
        
        # Save result to file
        output_path = os.path.join(CONVERTED_FOLDER, output_filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result_text)
        
        # Clean up input file
        @after_this_request
        def cleanup(response):
            try:
                os.remove(input_path)
            except Exception as e:
                app.logger.error(f"Error deleting uploaded file {input_path}: {e}")
            return response
        
        return send_file(output_path, as_attachment=True)
        
    except Exception as e:
        app.logger.error(f"Text conversion error: {e}")
        return f"Conversion failed: {str(e)}", 500

def extract_text_from_file(file_path, textract_client):
    """Extract text from various file types using AWS Textract or direct reading"""
    file_ext = file_path.lower().split('.')[-1]
    
    try:
        if file_ext == 'txt':
            # Direct text file reading
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        elif file_ext == 'pdf':
            # Use Textract for PDF
            with open(file_path, 'rb') as f:
                response = textract_client.detect_document_text(
                    Document={'Bytes': f.read()}
                )
            
            text = ""
            for item in response['Blocks']:
                if item['BlockType'] == 'LINE':
                    text += item['Text'] + '\n'
            return text
        
        elif file_ext in ['jpg', 'jpeg', 'png']:
            # Use Textract for images
            with open(file_path, 'rb') as f:
                response = textract_client.detect_document_text(
                    Document={'Bytes': f.read()}
                )
            
            text = ""
            for item in response['Blocks']:
                if item['BlockType'] == 'LINE':
                    text += item['Text'] + '\n'
            return text
        
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
# APPLICATION STARTUP
# ========================================
if __name__ == "__main__":
    # Development server configuration
    # Note: Use gunicorn or similar WSGI server in production
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

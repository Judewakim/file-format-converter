# File Format Converter

A professional online file converter with user authentication and subscription billing. Convert JPG, PNG, PDF, Word, TXT files with secure user accounts and premium AI-powered text processing features.

## Features

### Core File Conversions (Free)
- **TXT → PDF**: Convert plain text files to PDF documents
- **JPG → PNG**: Convert JPEG images to PNG format
- **PDF → Word**: Extract PDF content to Word documents
- **Drag & Drop Interface**: User-friendly file upload
- **Progress Tracking**: Real-time conversion progress
- **Session History**: Track recent conversions per session

### Premium Text Processing (Subscription Required)
- **Language Translation**: Translate text to Spanish, French, German, Chinese using AWS Translate
- **OCR Text Extraction**: Extract text from images and PDFs using AWS Textract
- **Multi-format Support**: Process PDF, JPG, PNG, TXT files for text operations
- **AI/ML Powered**: Advanced text processing capabilities

### User Management
- **AWS Cognito Authentication**: Secure OAuth login/logout
- **User Accounts**: Personal account management
- **JWT Token Verification**: Secure session management
- **Account Dashboard**: Subscription status and management

### Subscription System
- **Stripe Integration**: Secure payment processing with PCI compliance
- **Monthly Subscriptions**: $9.99/month recurring billing
- **Webhook Handling**: Real-time subscription status updates
- **PostgreSQL Database**: Robust subscription and user data management
- **Customer Portal**: Subscription management through Stripe

### Additional Features
- **SEO Blog System**: Conversion guides for organic traffic
- **User Feedback System**: Collect and store user feedback
- **Responsive Design**: Mobile and desktop optimized
- **File Cleanup**: Automatic temporary file management
- **Error Handling**: Comprehensive error pages and logging

## Tech Stack

- **Backend**: Flask (Python 3.12.7)
- **Authentication**: AWS Cognito with JWT
- **Payments**: Stripe Checkout & Webhooks
- **Database**: PostgreSQL (Supabase)
- **File Processing**: PIL, PyPDF2, python-docx, fpdf
- **AWS Services**: Translate, Textract, Comprehend
- **Frontend**: HTML/CSS/JavaScript
- **Deployment**: Gunicorn WSGI server

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/file-format-converter.git
   cd file-format-converter
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   Create a `.env` file with:
   ```env
   FLASK_ENV=development
   SECRET_KEY=your_secret_key
   
   # AWS Cognito
   COGNITO_DOMAIN=https://your-domain.auth.region.amazoncognito.com
   COGNITO_CLIENT_ID=your_client_id
   COGNITO_REDIRECT_URI=http://localhost:5000/callback
   COGNITO_LOGOUT_REDIRECT=http://localhost:5000/
   COGNITO_REGION=us-east-1
   COGNITO_USERPOOL_ID=your_userpool_id
   
   # Stripe
   STRIPE_SECRET_KEY=sk_test_your_secret_key
   STRIPE_PUBLISHABLE_KEY=pk_test_your_publishable_key
   STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
   STRIPE_PRICE_SUBSCRIPTION_MONTHLY=price_your_price_id
   
   # AWS Services (for premium features)
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   AWS_REGION=us-east-1
   
   # Database
   DATABASE_URL=postgresql://user:password@host:port/database
   
   # Domain
   YOUR_DOMAIN=http://localhost:5000
   ```

5. **Set up PostgreSQL database**:
   - Create a PostgreSQL database (or use Supabase)
   - Update `DATABASE_URL` in your `.env` file
   - Database tables will be created automatically on first run

6. **Run the application**:
   ```bash
   python app.py
   ```

7. **Set up Stripe webhooks** (for local development):
   ```bash
   stripe listen --forward-to localhost:5000/stripe/webhook
   ```

## Usage

### For Users
1. **Free Conversions**:
   - Upload files via drag & drop or file selection
   - Choose conversion type (TXT→PDF, JPG→PNG, PDF→Word)
   - Download converted files instantly
   - View recent conversion history

2. **Premium Features** (Subscription Required):
   - Sign up/Login using AWS Cognito
   - Access AI-powered text processing
   - Translate documents to multiple languages
   - Extract text from images and PDFs using OCR
   - Subscribe for $9.99/month

### For Developers
- PostgreSQL database auto-initializes on first run
- Stripe webhook events update subscription status in real-time
- Temporary files are automatically cleaned up after conversion
- JWT tokens manage secure user sessions
- AWS services integration for premium text processing
- Comprehensive error handling and logging

## Production Deployment

1. **Update environment variables** for production:
   - Set `FLASK_ENV=production`
   - Use production database URL
   - Configure production domain URLs

2. **Switch to live Stripe keys**:
   - Replace test keys with live Stripe keys
   - Update webhook endpoint URL
   - Configure production webhook secret

3. **Configure AWS services**:
   - Set up production AWS credentials
   - Configure appropriate IAM permissions for Translate, Textract, Comprehend

4. **Use production WSGI server**:
   ```bash
   gunicorn --bind 0.0.0.0:8000 app:app
   ```

5. **Set up HTTPS/SSL certificate**
6. **Configure database backups** for PostgreSQL
7. **Set up monitoring and logging**

## Project Structure

```
file-format-converter/
├── app.py                    # Main Flask application with all routes
├── stripe_db.py             # PostgreSQL database operations
├── requirements.txt         # Python dependencies
├── runtime.txt             # Python version (3.12.7)
├── .env                    # Environment variables (not in repo)
├── feedback.txt            # User feedback storage
├── templates/              # Jinja2 HTML templates
│   ├── index.html          # Main conversion interface
│   ├── account.html        # User account dashboard
│   ├── purchase.html       # Stripe subscription page
│   ├── purchase_success.html # Payment success page
│   ├── purchase_cancel.html  # Payment cancel page
│   ├── 404.html            # Custom error page
│   └── blog/               # SEO blog templates
│       ├── txt-to-pdf.html
│       ├── jpg-to-png.html
│       └── pdf-to-word.html
├── static/                 # Static assets
│   ├── styles.css          # Main stylesheet
│   ├── favicon.png         # Site icon
│   ├── robots.txt          # SEO robots file
│   └── sitemap.xml         # SEO sitemap
├── uploads/                # Temporary upload storage
├── converted/              # Temporary converted file storage
└── .mypy_cache/           # Type checking cache
```

## API Endpoints

### Public Routes
- `GET /` - Main conversion interface
- `POST /convert` - File conversion (free features)
- `POST /submit-feedback` - User feedback submission
- `GET /blog/*` - SEO blog pages

### Authentication Routes
- `GET /login` - Redirect to AWS Cognito login
- `GET /callback` - OAuth callback handler
- `GET /logout` - Clear session and logout

### Protected Routes (Login Required)
- `GET /account` - User account dashboard
- `POST /text-convert` - Premium text processing
- `GET /purchase` - Subscription purchase page
- `POST /create-checkout-session` - Create Stripe checkout

### Webhook Routes
- `POST /stripe/webhook` - Stripe webhook handler

## Environment Variables

Required environment variables for full functionality:
- AWS Cognito configuration (6 variables)
- Stripe configuration (4 variables)
- AWS services credentials (3 variables)
- Database URL (1 variable)
- Application domain (1 variable)

## Contributing

Feel free to submit issues and pull requests to improve this project!

## License

This project is licensed under the MIT License.
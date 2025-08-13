# File Format Converter

A professional online file converter with user authentication and subscription billing. Convert JPG, PNG, PDF, Word, TXT files with secure user accounts and premium subscriptions.

## Features

### Core Functionality
- **File Conversion**: TXT → PDF, JPG → PNG, PDF → Word
- **Drag & Drop Interface**: User-friendly file upload
- **Progress Tracking**: Real-time conversion progress
- **Download History**: Track recent conversions

### User Management
- **AWS Cognito Authentication**: Secure login/logout
- **User Accounts**: Personal account management
- **Session Management**: JWT token verification

### Subscription System
- **Stripe Integration**: Secure payment processing
- **Monthly Subscriptions**: Recurring billing
- **Webhook Handling**: Real-time subscription updates
- **Database Tracking**: SQLite subscription management

### Additional Features
- **Blog Content**: SEO-friendly conversion guides
- **User Feedback**: Feedback collection system
- **Responsive Design**: Mobile and desktop optimized
- **Security**: PCI compliant payment processing

## Tech Stack

- **Backend**: Flask (Python)
- **Authentication**: AWS Cognito
- **Payments**: Stripe
- **Database**: SQLite
- **File Processing**: PIL, PyPDF2, python-docx, fpdf
- **Frontend**: HTML/CSS/JavaScript

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
   COGNITO_DOMAIN=your_cognito_domain
   COGNITO_CLIENT_ID=your_client_id
   COGNITO_REDIRECT_URI=http://localhost:5000/callback
   COGNITO_LOGOUT_REDIRECT=http://localhost:5000/
   COGNITO_REGION=your_region
   COGNITO_USERPOOL_ID=your_userpool_id
   
   # Stripe
   STRIPE_SECRET_KEY=sk_test_your_secret_key
   STRIPE_PUBLISHABLE_KEY=pk_test_your_publishable_key
   STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
   STRIPE_PRICE_SUBSCRIPTION_MONTHLY=price_your_price_id
   
   # Domain
   YOUR_DOMAIN=http://localhost:5000
   ```

5. **Run the application**:
   ```bash
   python app.py
   ```

6. **Set up Stripe webhooks** (for local development):
   ```bash
   stripe listen --forward-to localhost:5000/stripe/webhook
   ```

## Usage

### For Users
1. **Sign up/Login** using AWS Cognito
2. **Upload files** via drag & drop or file selection
3. **Choose conversion type** (TXT→PDF, JPG→PNG, PDF→Word)
4. **Download converted files**
5. **Subscribe** for unlimited conversions

### For Developers
- Database auto-initializes on first run
- Webhook events update subscription status
- Files are automatically cleaned up after conversion
- User sessions managed via JWT tokens

## Production Deployment

1. **Update environment variables** for production
2. **Switch to live Stripe keys**
3. **Configure production webhook endpoint**
4. **Use production WSGI server**:
   ```bash
   gunicorn --bind 0.0.0.0:8000 app:app
   ```
5. **Set up HTTPS/SSL certificate**
6. **Configure database backups**

## Project Structure

```
file-format-converter/
├── app.py                 # Main Flask application
├── stripe_db.py          # Database operations
├── requirements.txt      # Python dependencies
├── templates/           # HTML templates
│   ├── index.html       # Main page
│   ├── account.html     # User account
│   ├── purchase.html    # Subscription page
│   └── blog/           # Blog templates
├── static/             # CSS, images, etc.
└── uploads/            # Temporary file storage
```

## Contributing

Feel free to submit issues and pull requests to improve this project!

## License

This project is licensed under the MIT License.
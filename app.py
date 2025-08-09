from flask import Flask, render_template, request, send_file, redirect, url_for, after_this_request
import os
from werkzeug.utils import secure_filename
from PIL import Image
import PyPDF2
from docx import Document
import io
import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
CONVERTED_FOLDER = "converted"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)

# In-memory download history (will reset when app restarts)
download_history = []

@app.route("/")
def index():
    # Cleanup all converted files on page load
    for fname in os.listdir(CONVERTED_FOLDER):
        try:
            os.remove(os.path.join(CONVERTED_FOLDER, fname))
        except Exception as e:
            app.logger.error(f"Error deleting converted file {fname}: {e}")

    return render_template("index.html", history=download_history)

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

    # TXT -> PDF
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

    # JPG -> PNG
    elif conversion_type == "jpg_to_png":
        img = Image.open(input_path)
        output_path = os.path.join(CONVERTED_FOLDER, filename.rsplit(".", 1)[0] + ".png")
        img.save(output_path, "PNG")

    # PDF -> Word
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

    # Record in history
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

if __name__ == "__main__":
    app.run(debug=True)

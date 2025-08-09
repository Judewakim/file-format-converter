import os
from flask import Flask, render_template, request, send_from_directory
from PIL import Image
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
CONVERTED_FOLDER = 'converted'
ALLOWED_EXTENSIONS = {'png'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CONVERTED_FOLDER'] = CONVERTED_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/convert", methods=["POST"])
def convert():
    if 'file' not in request.files:
        return "No file uploaded", 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        img = Image.open(upload_path)
        converted_filename = filename.rsplit('.', 1)[0] + ".jpg"
        converted_path = os.path.join(app.config['CONVERTED_FOLDER'], converted_filename)
        rgb_img = img.convert('RGB')
        rgb_img.save(converted_path)

        return render_template("index.html", download_url=f"/download/{converted_filename}")
    return "Invalid file type", 400

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(app.config['CONVERTED_FOLDER'], filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)


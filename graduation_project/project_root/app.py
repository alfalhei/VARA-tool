import os
import cv2
import numpy as np
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import uuid
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Session(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('session.id'), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def save_image(username, session_id, image_file):
    filename = secure_filename(image_file.filename)
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, session_id)
    os.makedirs(folder_path, exist_ok=True)
    file_path = os.path.join(folder_path, filename)
    image_file.save(file_path)
    return os.path.join(username, session_id, filename)

def process_image(image_path):

    img = cv2.imread(image_path)
    if img is None:
        logger.error(f"Failed to read image from {image_path}")
        return None

    original = img.copy()
    height, width = img.shape[:2]
    logger.info(f"Original image dimensions: {width}x{height}")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    blurred = cv2.GaussianBlur(gray, (5, 5), 0)

    edges = cv2.Canny(blurred, 50, 150)

    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    contours = sorted(contours, key=cv2.contourArea, reverse=True)

    address_bar_height = 0
    main_content_area = None

    for contour in contours:
        x, y, w, h = cv2.boundingRect(contour)
        aspect_ratio = w / h

        if 3 < aspect_ratio < 20 and y < height * 0.2:
            address_bar_height = max(address_bar_height, y + h)

        elif 0.5 < aspect_ratio < 2 and w > width * 0.5 and h > height * 0.5:
            main_content_area = (x, y, w, h)
            break

    if main_content_area:
        x, y, w, h = main_content_area

        y = max(y, address_bar_height)
        cropped = original[y:y+h, x:x+w]
        logger.info("Cropped to main content area, excluding address bar")
    else:

        cropped = original[address_bar_height:, :]
        logger.info("Cropped out address bar only")

    cropped_path = image_path.replace('.', '_cropped.')
    cv2.imwrite(cropped_path, cropped)

    logger.info(f"Cropped image saved to {cropped_path}")
    logger.info(f"Cropped image dimensions: {cropped.shape[1]}x{cropped.shape[0]}")

    return cropped_path

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            session['session_id'] = str(uuid.uuid4())
            new_session = Session(id=session['session_id'], user_id=user.id)
            db.session.add(new_session)
            db.session.commit()
            return redirect(url_for('index'))
        return 'Invalid username or password', 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('session_id', None)
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already exists', 400
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400
    
    image_file = request.files['image']
    
    if image_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        image_path = save_image(current_user.username, session['session_id'], image_file)
        logger.info(f"Original image saved to {image_path}")

        full_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_path)
        cropped_image_path = process_image(full_image_path)
        
        if cropped_image_path is None:
            return jsonify({'error': 'Failed to process image'}), 500

        analysis = Analysis(
            session_id=session['session_id'],
            image_path=cropped_image_path
        )
        db.session.add(analysis)
        db.session.commit()
        
        result = {
            "vulnerability_type": "Example Vulnerability",
            "confidence": 0.95,
            "top3_predictions": [
                ["Example Vulnerability", 0.95],
                ["Other Vulnerability", 0.03],
                ["Another Vulnerability", 0.02]
            ],
            "original_image_path": image_path,
            "cropped_image_path": cropped_image_path
        }
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in analyze_image: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

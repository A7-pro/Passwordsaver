from flask import Flask, request, jsonify, session, render_template
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os
import secrets
import string
from cryptography.fernet import Fernet

# إنشاء التطبيق وتهيئة Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# إنشاء مفتاح التشفير
key = Fernet.generate_key()
cipher = Fernet(key)

# نموذج المستخدمين
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# نموذج كلمات المرور المحفوظة
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password = db.Column(db.String(500), nullable=False)

# توليد كلمة مرور عشوائية
@app.route('/generate', methods=['POST'])
def generate_password():
    data = request.json
    length = int(data.get('length', 12))
    uppercase = data.get('uppercase', True)
    lowercase = data.get('lowercase', True)
    numbers = data.get('numbers', True)
    symbols = data.get('symbols', True)

    char_pool = ''
    if uppercase:
        char_pool += string.ascii_uppercase
    if lowercase:
        char_pool += string.ascii_lowercase
    if numbers:
        char_pool += string.digits
    if symbols:
        char_pool += string.punctuation

    password = ''.join(secrets.choice(char_pool) for _ in range(length))
    return jsonify({'password': password})

# تسجيل مستخدم جديد
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data['email']
    password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(email=email, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

# تسجيل الدخول
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        session['user_id'] = user.id
        return jsonify({'message': 'Login successful'})
    return jsonify({'message': 'Invalid credentials'}), 401

# حفظ كلمة مرور مشفرة
@app.route('/save', methods=['POST'])
def save_password():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.json
    encrypted_password = cipher.encrypt(data['password'].encode()).decode()
    new_password = Password(user_id=session['user_id'], password=encrypted_password)
    db.session.add(new_password)
    db.session.commit()
    return jsonify({'message': 'Password saved successfully'})

# استعراض كلمات المرور
@app.route('/passwords', methods=['GET'])
def get_passwords():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 403
    passwords = Password.query.filter_by(user_id=session['user_id']).all()
    decrypted_passwords = [cipher.decrypt(p.password.encode()).decode() for p in passwords]
    return jsonify({'passwords': decrypted_passwords})

# إعداد الصفحة الرئيسية
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

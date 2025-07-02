import os
import random
import string
import json
from flask import Flask, render_template, request, send_from_directory, url_for, jsonify, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "frilat-secret-key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///frilat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

### ADMIN JSON LOAD ###
def load_admins():
    try:
        with open('admins.json', 'r') as f:
            data = json.load(f)
            return set(data.get('admins', []))
    except Exception:
        return set()
admins = load_admins()

### MODELS ###
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(256), default='/static/default_avatar.png')
    fullname = db.Column(db.String(100), default="")
    bio = db.Column(db.Text, default="")
    website = db.Column(db.String(200), default="")
    last_password_change = db.Column(db.DateTime, nullable=True)
    private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    uploads = db.relationship('Upload', backref='uploader', lazy=True)
    albums = db.relationship('Album', backref='owner', lazy=True)
    is_pro = db.Column(db.Boolean, default=False)

    @property
    def is_admin(self):
        # JSON dosyasındaki admin listesine göre kontrol
        return self.username in admins

class Album(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    uploads = db.relationship('Upload', backref='album', lazy=True)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(20), unique=True, nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    savedname = db.Column(db.String(200), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    mimetype = db.Column(db.String(50))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    album_id = db.Column(db.Integer, db.ForeignKey('album.id'), nullable=True)
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=db.func.now())
    expire_at = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

def random_id(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return dict(current_user=user)

@app.route('/update_user_profile', methods=['POST'])
def update_user_profile():
    if 'user_id' not in session:
        flash("Please log in to update profile.", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user.location = request.form.get('location', '').strip()
    user.occupation = request.form.get('occupation', '').strip()
    user.interests = request.form.get('interests', '').strip()
    db.session.commit()
    flash("User profile updated!", "success")
    return redirect(url_for('settings') + "#tab-profile")

@app.route('/buy-pro')
def buy_pro():
    if 'user_id' not in session:
        flash("Please log in to upgrade!", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('login'))
    user.is_pro = True
    db.session.commit()
    flash("Congrats! You are now a FriLat Pro member! 🎉", "success")
    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin_badge_page():
    # Admin/tif/staff badge’leri json’dan yükle (örnek json: {"admins": ["ahmet"], "tif": ["pozix"], "staff": ["baran"]})
    try:
        with open('admins.json', 'r') as f:
            admins_config = json.load(f)
    except Exception:
        admins_config = {}

    badge_users = []
    # Topla tüm badge'leri ve tek tek badge türünü belirle
    for badge_type in ["admins", "tif", "staff"]:
        usernames = admins_config.get(badge_type, [])
        for username in usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                badge_label = {
                    "admins": "Admin",
                    "tif": "TIF",
                    "staff": "Staff"
                }.get(badge_type, badge_type.capitalize())
                badge_users.append({
                    "username": user.username,
                    "fullname": user.fullname,
                    "avatar": user.avatar,
                    "badge": badge_label
                })

    return render_template('admin.html', active_admins=badge_users)


@app.route('/private-shield')
def private_shield():
    return render_template('private-shield.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/about')
def about():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return render_template('about.html', current_user=user)

@app.route('/pro')
def pro_page():
    pro_users = User.query.filter_by(is_pro=True).all()
    return render_template('pro.html', pro_users=pro_users)

### AUTH ###
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        if not username or not email or not password:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('signup'))
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=pw_hash)
        db.session.add(user)
        db.session.commit()
        flash("Account created! You can now sign in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('index'))

### DASHBOARD ###
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please sign in first.", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    now = datetime.utcnow()
    uploads = Upload.query.filter(
        Upload.uploader_id==user.id,
        (Upload.expire_at==None) | (Upload.expire_at > now)
    ).order_by(Upload.created_at.desc()).all()
    albums = Album.query.filter_by(owner_id=user.id).all()
    return render_template('dashboard.html', username=user.username, uploads=uploads, albums=albums, current_user=user)

### SETTINGS & PROFILE ###
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash("Please log in!", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST' and 'profile_save' in request.form:
        user.private = 'private' in request.form
        user.fullname = request.form.get('fullname', '').strip()
        user.website = request.form.get('website', '').strip()
        user.bio = request.form.get('bio', '').strip()
        db.session.commit()
        flash("Profile updated!", "success")
        return redirect(url_for('settings'))
    return render_template('settings.html', current_user=user)

@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    uploads_count = Upload.query.filter_by(uploader_id=user.id).count()
    return render_template(
        'overview_profile.html',
        profile_user=user,
        uploads_count=uploads_count,
        admin_badge=user.is_admin
    )

@app.route('/profile/avatar', methods=['POST'])
def upload_avatar():
    if 'user_id' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))
    file = request.files.get('avatar')
    if not file or file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('settings'))
    ext = os.path.splitext(file.filename)[-1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.gif']:
        flash("Invalid file type.", "danger")
        return redirect(url_for('settings'))
    fname = f"avatar_{session['user_id']}{ext}"
    avatar_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars')
    os.makedirs(avatar_folder, exist_ok=True)
    path = os.path.join(avatar_folder, fname)
    file.save(path)
    user = User.query.get(session['user_id'])
    user.avatar = f"/uploads/avatars/{fname}"
    db.session.commit()
    flash("Profile photo updated!", "success")
    return redirect(url_for('settings'))

@app.route('/profile/avatar/remove', methods=['POST'])
def remove_avatar():
    if 'user_id' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.avatar and not user.avatar.startswith('/static'):
        avatar_path = user.avatar.lstrip('/')
        if os.path.isfile(avatar_path):
            os.remove(avatar_path)
    user.avatar = '/static/default_avatar.png'
    db.session.commit()
    flash("Profile photo removed.", "info")
    return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])

    # 3 saat kontrolü
    if user.last_password_change and (datetime.utcnow() - user.last_password_change) < timedelta(hours=3):
        remaining = timedelta(hours=3) - (datetime.utcnow() - user.last_password_change)
        minutes_left = int(remaining.total_seconds() // 60)
        flash(f"You can change your password again in {minutes_left} minute(s).", "warning")
        return redirect(url_for('settings') + "#tab-password")

    current_pw = request.form.get('current_password')
    new_pw = request.form.get('new_password')
    confirm_pw = request.form.get('confirm_password')

    if not (current_pw and new_pw and confirm_pw):
        flash("Please fill in all fields.", "danger")
        return redirect(url_for('settings') + "#tab-password")

    if not bcrypt.check_password_hash(user.password, current_pw):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for('settings') + "#tab-password")

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('settings') + "#tab-password")

    if len(new_pw) < 6:
        flash("New password must be at least 6 characters.", "danger")
        return redirect(url_for('settings') + "#tab-password")

    user.password = bcrypt.generate_password_hash(new_pw).decode('utf-8')
    user.last_password_change = datetime.utcnow()
    db.session.commit()

    flash("Password changed successfully!", "success")
    return redirect(url_for('settings') + "#tab-password")

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        email = request.form.get('email', '')
        msg_type = request.form.get('type', 'other')
        message = request.form.get('message', '').strip()
        flash("Thank you for your message! Our support team will reply as soon as possible.", "success")
        return redirect(url_for('support'))
    return render_template('support.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/terms')
@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms.html')

### AVATAR SERVİSİ ###
@app.route('/uploads/avatars/<filename>')
def uploaded_avatar(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), filename)

### DOSYA UPLOAD ###
@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'user_id' not in session:
        return jsonify({'error': 'You must be logged in to upload!'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    ext = os.path.splitext(file.filename)[-1]
    file_id = random_id(7)
    fname = f"{file_id}{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    file.save(path)

    size = os.path.getsize(path)

    expire_minutes = request.form.get('expire_minutes', '0')
    try:
        expire_minutes = int(expire_minutes)
    except ValueError:
        return jsonify({'error': 'Invalid expire time value.'}), 400

    # 1MB altı dosyalar için 0 (süresiz), 5, 10 kabul edilir
    if size <= 1 * 1024 * 1024:
        if expire_minutes not in [0, 5, 10]:
            return jsonify({'error': 'Expire time must be 0 (No expiration), 5 or 10 minutes for files 1MB or less.'}), 400
    else:
        if expire_minutes not in [5, 10]:
            return jsonify({'error': 'Expire time must be 5 or 10 minutes for files larger than 1MB.'}), 400

    expire_at = None
    if expire_minutes > 0:
        expire_at = datetime.utcnow() + timedelta(minutes=expire_minutes)

    upload = Upload(
        file_id=file_id,
        filename=file.filename,
        savedname=fname,
        size=size,
        mimetype=file.mimetype,
        uploader_id=session['user_id'],
        expire_at=expire_at
    )
    db.session.add(upload)
    db.session.commit()

    download_url = url_for('download_page', file_id=file_id, _external=True)
    return jsonify({'link': download_url})

### DOSYA SİLME ###
@app.route('/delete/<file_id>', methods=['POST'])
def delete_upload(file_id):
    if 'user_id' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))
    upload = Upload.query.filter_by(file_id=file_id, uploader_id=session['user_id']).first()
    if not upload:
        flash("File not found or not allowed.", "danger")
        return redirect(url_for('dashboard'))
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], upload.savedname))
    except Exception:
        pass
    db.session.delete(upload)
    db.session.commit()
    flash("File deleted.", "info")
    return redirect(url_for('dashboard'))

### ALBÜM OLUŞTURMA ###
@app.route('/album/create', methods=['POST'])
def create_album():
    if 'user_id' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))
    name = request.form.get('album_name')
    if not name or len(name) < 2:
        flash("Invalid album name.", "danger")
        return redirect(url_for('dashboard'))
    album = Album(name=name, owner_id=session['user_id'])
    db.session.add(album)
    db.session.commit()
    flash("Album created!", "success")
    return redirect(url_for('dashboard'))

### DOSYA İNDİRME & SAYFA ###
@app.route('/d/<file_id>')
def download_page(file_id):
    upload = Upload.query.filter_by(file_id=file_id).first()
    if not upload or not os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], upload.savedname)):
        return "File not found.", 404
    uploader_name = upload.uploader.username if upload.uploader else "Anonymous"
    uploader_avatar = upload.uploader.avatar if upload.uploader and upload.uploader.avatar else "/static/default_avatar.png"
    return render_template('download_page.html', file_id=file_id, meta={
        'filename': upload.filename,
        'savedname': upload.savedname,
        'size': upload.size,
        'uploader': uploader_name,
        'type': upload.mimetype
    }, uploader_avatar=uploader_avatar)

@app.route('/go/<file_id>')
def download_progress(file_id):
    upload = Upload.query.filter_by(file_id=file_id).first()
    if not upload or not os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], upload.savedname)):
        return "File not found.", 404
    return render_template('download_progress.html', file_id=file_id, meta={
        'filename': upload.filename,
        'savedname': upload.savedname,
        'size': upload.size,
        'uploader': upload.uploader.username if upload.uploader else "Anonymous",
        'type': upload.mimetype
    })

@app.route('/download/<file_id>')
def real_download(file_id):
    upload = Upload.query.filter_by(file_id=file_id).first()
    if not upload or not os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], upload.savedname)):
        return "File not found.", 404
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        upload.savedname,
        as_attachment=True,
        download_name=upload.filename  # Orijinal dosya adıyla indirme
    )

### ANASAYFA ###
@app.route('/')
def index():
    return render_template('index.html')

### UPLOAD SAYFASI ###
@app.route('/upload')
def upload():
    if 'user_id' not in session:
        flash("Please sign in to upload files.", "warning")
        return redirect(url_for('login'))
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def clean_expired_uploads():
    now = datetime.utcnow()
    expired = Upload.query.filter(Upload.expire_at != None, Upload.expire_at < now).all()
    for up in expired:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], up.savedname))
        except Exception:
            pass
        db.session.delete(up)
    db.session.commit()

@app.before_request
def cleanup_hook():
    clean_expired_uploads()

if __name__ == '__main__':
    app.run(debug=True)

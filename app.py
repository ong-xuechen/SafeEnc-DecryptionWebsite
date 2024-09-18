import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'tmp'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Access denied. You are not an admin.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        if action == 'add':
            if not username or not password:
                flash('Username and password are required.', 'error')
                return redirect(url_for('admin_users'))
            if len(username) < 3 or len(username) > 150:
                flash('Username must be between 3 and 150 characters.', 'error')
                return redirect(url_for('admin_users'))
            if len(password) < 6 or len(password) > 150:
                flash('Password must be between 6 and 150 characters.', 'error')
                return redirect(url_for('admin_users'))

            # Generate a new encryption key for the new user
            encryption_key = Fernet.generate_key()

            # Add new user
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, encryption_key=encryption_key, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')

        elif action == 'edit':
            user = User.query.get(user_id)
            if user:
                if username:
                    user.username = username
                if password:
                    user.password = generate_password_hash(password, method='pbkdf2:sha256')
                user.is_admin = is_admin
                db.session.commit()
                flash('User updated successfully!', 'success')
            else:
                flash('User not found.', 'danger')

        elif action == 'delete':
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
            else:
                flash('User not found.', 'danger')

    # Query all users for display
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if len(username) < 3 or len(username) > 150:
            flash('Username must be between 3 and 150 characters.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6 or len(password) > 150:
            flash('Password must be between 6 and 150 characters.', 'error')
            return redirect(url_for('register'))

        encrypted_key = Fernet.generate_key()
        hashed_password = generate_password_hash(password)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_password, encryption_key=encrypted_key)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if len(username) < 3 or len(username) > 150:
            flash('Username must be between 3 and 150 characters.', 'error')
            return redirect(url_for('login'))

        if len(password) < 6 or len(password) > 150:
            flash('Password must be between 6 and 150 characters.', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your username and/or password.', 'error')

    return render_template('login.html')

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            user = current_user
            filename = secure_filename(file.filename)
            metadata_filename = f"{user.id}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], metadata_filename)
            file.save(file_path)

            key = user.encryption_key
            fernet = Fernet(key)

            # Encrypt the file
            with open(file_path, 'rb') as f:
                original_data = f.read()
            encrypted_data = fernet.encrypt(original_data)

            # Save the encrypted file with .enc extension
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            # Remove the original file
            os.remove(file_path)

            return send_file(encrypted_file_path, as_attachment=True)
        else:
            flash('No file selected for encryption.', 'error')

    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            user = current_user
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            key = user.encryption_key
            fernet = Fernet(key)

            try:
                # Read the encrypted file
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()

                # Ensure the file is properly named
                if not filename.endswith('.enc'):
                    flash('Invalid file format. Expected an encrypted file.', 'danger')
                    os.remove(file_path)
                    return redirect(url_for('decrypt'))

                # Check if the user is authorized to decrypt the file
                user_id_from_filename = filename.split('_', 1)[0]
                if user_id_from_filename != str(user.id):
                    flash('You are not authorized to decrypt this file.', 'danger')
                    os.remove(file_path)
                    return redirect(url_for('decrypt'))

                # Decrypt the file
                decrypted_data = fernet.decrypt(encrypted_data)

                # Restore the original filename (remove .enc extension)
                original_filename = filename[:-4]  # Remove .enc extension
                decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_data)

                # Clean up the encrypted file
                os.remove(file_path)

                return send_file(decrypted_file_path, as_attachment=True)
            except Exception as e:
                flash('Failed to decrypt file. It may be corrupted or encrypted with a different key.', 'danger')
                print(f"Decryption error: {e}")
                os.remove(file_path)
                return redirect(url_for('decrypt'))
        else:
            flash('No file selected for decryption.', 'danger')

    return render_template('decrypt.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)

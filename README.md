# SafeEnc Decryption Website

**SafeEnc Decryption Website** is a web application built with Flask that allows users to securely encrypt and decrypt files and the user can only decrypt the files they encrypted as it uses a secret key attached to the user to encrypt the data. 

It supports user registration and login, with roles for regular users and administrators. Administrators can manage users and perform CRUD operations on user accounts.

## Disclaimer

**Important:** This project is intended for educational and demonstration purposes only. It is not intended for use in real-world applications or production environments.

This project may have limitations in terms of security, performance, and scalability. Use it as a learning tool or for personal experimentation only. Always follow best practices and conduct proper security reviews for any real-world application.

## Features

- **User Authentication**: Register, login, and manage user sessions.
- **User Roles**: Differentiate between regular users and administrators.
- **File Encryption/Decryption**: Securely encrypt and decrypt files using Fernet symmetric encryption.
- **Admin Panel**: Manage user accounts, including adding, editing, and deleting users.

(**NOTE:** Administrator Account Details: *username* - admin, *password* - admin. The administrator account was created manually, and any new creation of administrator accounts will be done via the 'Manage Users' page accessible through the administrator account.)

## Technologies Used

- **Flask**: Web framework for building the application.
- **Flask-SQLAlchemy**: ORM for managing the SQLite database.
- **Flask-Login**: User session management.
- **Cryptography**: Provides encryption and decryption functionality.
- **Werkzeug**: Password hashing and other utility functions.
- **SQLite**: Database used to store user information.

## Installation

To run this project locally, follow these steps:

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/SafeEnc-DecryptionWebsite.git
2. **Navigate into the project directory:**
   ```sh
   cd SafeEnc-DecryptionWebsite
3. **Create a virtual environment and activate it:**
   ```sh
   python -m venv venv
   venv\Scripts\activate
4. **Install the required dependencies:**
   ```sh
   pip install -r requirements.txt
5. **Run the application:**
   ```sh
   python app.py

*The application will start on http://127.0.0.1:5000.*

## Configuration

- **SECRET_KEY:** Set in app.config['SECRET_KEY']. Change this to a secure random key for production.
- **SQLALCHEMY_DATABASE_URI:** Set to 'sqlite:///site.db' for SQLite database. You can switch to other databases by updating this URI.
- **UPLOAD_FOLDER:** Directory where encrypted and decrypted files are temporarily stored. Make sure this directory exists or is created at runtime.

## Usage
1. **Register:** Create a new account by providing a username and password.
2. **Login:** Access the site using your credentials.
3. **Encrypt Files:** Upload files to encrypt, the encrypted files will be available for download.
4. **Decrypt Files:** Upload encrypted files to decrypt. *(Do note that only the user encrypting the data can decrypt it, on the same account)*

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure that your code adheres to the existing style and passes all tests.

## Contact
For any questions or feedback, please contact me on my socials.

## Socials
**E-Mail Address:** ongxuechen@outlook.com

**Linkedin:** www.linkedin.com/in/ong-xue-chen


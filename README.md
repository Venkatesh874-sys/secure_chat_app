# 🔐 Secure Chat App

A real-time encrypted messaging system built using Flask, SocketIO, RSA, and AES. This project demonstrates secure communication between users with end-to-end encryption.

---

## 📦 Features

- RSA key generation for secure key exchange
- AES encryption for message confidentiality
- Real-time messaging using Flask-SocketIO
- Simple UI for registration, recipient selection, and message sending
- Decryption endpoint for testing encrypted messages

---

## 🛠️ Technologies Used

- Python 3
- Flask
- Flask-SocketIO
- Cryptography library
- HTML, JavaScript

---

## 🚀 How to Run

1. Clone or download the project folder.
2. Open Command Prompt and navigate to the project directory:

   ```bash
   cd Secure_Chat_App
   pip install flask flask-socketio cryptography
python app.py
http://localhost:5000
🧪 Testing Decryption
Use the test_decrypt.py script to test decryption manually by pasting the encrypted AES key and message printed in the terminal.
📁 Project Structure
Secure_Chat_App
├── app.py
├── crypto_utils.py
├── test_decrypt.py
├── templates/
│   └── chat.html
├── static/
│   └── script.js
├── screenshots/
│   └── interface.png
│   └── encrypted_output.png
│   └── decryption_result.png
├── README.md
📌 Notes
This app is for educational purposes and local testing.

HTTPS and user authentication are recommended for production use.
👨‍💻 Developed By
Golla Venkatesh Internship Project – Cybersecurity & Web Development October 2025


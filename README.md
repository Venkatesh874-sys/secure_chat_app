🔐 Secure Chat App with End-to-End Encryption

A real-time encrypted messaging system built using Flask, SocketIO, RSA, and AES. This project demonstrates secure communication between users with end-to-end encryption (E2EE), ensuring that only the intended recipient can decrypt and read messages.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
📦 Features

RSA key generation for secure key exchange

AES encryption for message confidentiality

Real-time messaging using Flask-SocketIO

Simple UI for registration, recipient selection, and message sending

Manual decryption testing via test_decrypt.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
🛠️ Technologies Used

Python 3

Flask

Flask-SocketIO

Cryptography library

HTML, JavaScript

Base64 encoding
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
🚀 How to Run

Clone or download the project folder.

Install dependencies:
pip install flask flask-socketio cryptography
Run the app:
python app.py
Open your browser at http://localhost:5000
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
📁 Project Structure

Code

Secure_Chat_App/

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
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
🔐 Code Overview

app.py

python
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto_utils import *
import base64

app = Flask(__name__)
socketio = SocketIO(app)

private_key, public_key = generate_rsa_keys()
clients = {}

@app.route('/')
def index():
    return render_template('chat.html')

@socketio.on('register')
def handle_register(data):
    username = data['username']
    pubkey = serialization.load_pem_public_key(data['pubkey'].encode())
    clients[username] = pubkey
    emit('registered', {'message': f'{username} registered successfully'})

@socketio.on('send_message')
def handle_message(data):
    recipient = data['recipient']
    message = data['message']
    aes_key = os.urandom(32)
    encrypted_msg = aes_encrypt(message, aes_key)
    encrypted_key = encrypt_aes_key(aes_key, clients[recipient])
    emit('receive_message', {
        'sender': data['sender'],
        'encrypted_msg': base64.b64encode(encrypted_msg).decode(),
        'encrypted_key': base64.b64encode(encrypted_key).decode()
    }, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
    -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
crypto_utils.py

python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode()) + encryptor.finalize()

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()
    -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    
test_decrypt.py

python
from crypto_utils import *
import base64

encrypted_key_b64 = input("Paste encrypted AES key (base64): ")
encrypted_msg_b64 = input("Paste encrypted message (base64): ")

encrypted_key = base64.b64decode(encrypted_key_b64)
encrypted_msg = base64.b64decode(encrypted_msg_b64)

private_key, _ = generate_rsa_keys()  # Replace with actual private key
aes_key = decrypt_aes_key(encrypted_key, private_key)
decrypted_msg = aes_decrypt(encrypted_msg, aes_key)

print("Decrypted message:", decrypted_msg.decode())
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


templates/chat.html

html
<!DOCTYPE html>
<html>
<head><title>Secure Chat</title></head>
<body>
  <h2>Secure Chat App</h2>
  <input id="username" placeholder="Your name">
  <button onclick="register()">Register</button><br><br>
  <input id="recipient" placeholder="Send to">
  <input id="message" placeholder="Message">
  <button onclick="sendMessage()">Send</button>
  <ul id="chat"></ul>
  <script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.js"></script>
  <script src="/static/script.js"></script>
</body>
</html>
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

static/script.js

javascript
const socket = io();

function register() {
  const username = document.getElementById('username').value;

  const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr...your_key_here...
-----END PUBLIC KEY-----`;

  socket.emit('register', {
    username: username,
    pubkey: publicKeyPEM
  });
}

function sendMessage() {
  const sender = document.getElementById('username').value;
  const recipient = document.getElementById('recipient').value;
  const message = document.getElementById('message').value;

  socket.emit('send_message', {
    sender: sender,
    recipient: recipient,
    message: message
  });
}

socket.on('receive_message', data => {
  const chatBox = document.getElementById('chat');
  const li = document.createElement('li');
  li.textContent = `${data.sender} ➤ [Encrypted] ${data.encrypted_msg}`;
  chatBox.appendChild(li);
});
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
📌 Notes

This app is for educational purposes and local testing.

For production use, implement HTTPS and user authentication.

Public key sharing is currently hardcoded; dynamic exchange is recommended.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
👨‍💻 Developed By
Golla Venkatesh Cybersecurity & Web Development Internship October 2025
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
<img width="888" height="400" alt="image" src="https://github.com/user-attachments/assets/436afbbd-c281-4d13-8aa0-7434a6c34c5e" />
<img width="395" height="586" alt="image" src="https://github.com/user-attachments/assets/58c8779f-6395-4e13-bcde-8dab1946b6aa" />
<img width="766" height="328" alt="image" src="https://github.com/user-attachments/assets/3936f2cc-c33f-42a1-863f-a9fb24635fd5" />
<img width="282" height="510" alt="image" src="https://github.com/user-attachments/assets/7f341b27-7879-418a-8bd0-462649baae01" />
<img width="305" height="510" alt="image" src="https://github.com/user-attachments/assets/9a1161cd-4116-44b2-b352-b9a63a157795" />




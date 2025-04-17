import streamlit as st
import time
import bcrypt
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64
import uuid

# Initialize session state variables if they don't exist
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'user_keys' not in st.session_state:
    st.session_state.user_keys = {}
if 'algorithm' not in st.session_state:
    st.session_state.algorithm = "AES"
if 'last_message_time' not in st.session_state:
    st.session_state.last_message_time = 0
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

# File paths
USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"
KEYS_FILE = "keys.json"

# Load data from files if they exist
def load_data():
    # Load users
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            st.session_state.users = json.load(f)
    
    # Load messages
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, 'r') as f:
            st.session_state.messages = json.load(f)
    
    # Load keys
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            st.session_state.user_keys = json.load(f)

# Save data to files
def save_data():
    # Save users
    with open(USERS_FILE, 'w') as f:
        json.dump(st.session_state.users, f)
    
    # Save messages
    with open(MESSAGES_FILE, 'w') as f:
        json.dump(st.session_state.messages, f)
    
    # Save keys
    with open(KEYS_FILE, 'w') as f:
        json.dump(st.session_state.user_keys, f)

# Load data at startup
load_data()

# Encryption functions
def generate_aes_key():
    return Fernet.generate_key().decode()

def encrypt_aes(message, key):
    f = Fernet(key.encode())
    return f.encrypt(message.encode()).decode()

def decrypt_aes(encrypted_message, key):
    try:
        f = Fernet(key.encode())
        return f.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        st.error(f"Decryption failed: {e}")
        return None

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return {"private": private_pem, "public": public_pem}

def encrypt_rsa(message, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        st.error(f"RSA encryption failed: {e}")
        return None

def decrypt_rsa(encrypted_message, private_key_pem):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        st.error(f"RSA decryption failed: {e}")
        return None

def generate_chacha20_key():
    return base64.b64encode(ChaCha20Poly1305.generate_key()).decode()

def encrypt_chacha20(message, key):
    try:
        key_bytes = base64.b64decode(key)
        chacha = ChaCha20Poly1305(key_bytes)
        nonce = os.urandom(12)  # 96-bit nonce
        encrypted = chacha.encrypt(nonce, message.encode(), None)
        # Return nonce + encrypted data
        return base64.b64encode(nonce + encrypted).decode()
    except Exception as e:
        st.error(f"ChaCha20 encryption failed: {e}")
        return None

def decrypt_chacha20(encrypted_message, key):
    try:
        key_bytes = base64.b64decode(key)
        data = base64.b64decode(encrypted_message)
        nonce = data[:12]  # First 12 bytes are the nonce
        ciphertext = data[12:]  # Rest is the ciphertext
        chacha = ChaCha20Poly1305(key_bytes)
        decrypted = chacha.decrypt(nonce, ciphertext, None)
        return decrypted.decode()
    except Exception as e:
        st.error(f"ChaCha20 decryption failed: {e}")
        return None

# Authentication functions
def register_user(username, password):
    if username in st.session_state.users:
        return False, "Username already exists"
    
    # Hash the password
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    # Generate keys for the user
    aes_key = generate_aes_key()
    rsa_keys = generate_rsa_keys()
    chacha20_key = generate_chacha20_key()
    
    # Store user and keys
    st.session_state.users[username] = {"password": hashed_pw}
    st.session_state.user_keys[username] = {
        "AES": aes_key,
        "RSA": rsa_keys,
        "ChaCha20": chacha20_key
    }
    
    # Save data
    save_data()
    return True, "Registration successful"

def login_user(username, password):
    if username not in st.session_state.users:
        return False, "Username not found"
    
    stored_pw = st.session_state.users[username]["password"]
    if bcrypt.checkpw(password.encode(), stored_pw.encode()):
        st.session_state.logged_in = True
        st.session_state.username = username
        return True, "Login successful"
    else:
        return False, "Incorrect password"

# Message functions
def send_message(sender, recipient, message, algorithm):
    if recipient not in st.session_state.users:
        return False, "Recipient not found"
    
    encrypted_message = ""
    
    try:
        if algorithm == "AES":
            recipient_key = st.session_state.user_keys[recipient]["AES"]
            encrypted_message = encrypt_aes(message, recipient_key)
        elif algorithm == "RSA":
            recipient_public_key = st.session_state.user_keys[recipient]["RSA"]["public"]
            encrypted_message = encrypt_rsa(message, recipient_public_key)
        elif algorithm == "ChaCha20":
            recipient_key = st.session_state.user_keys[recipient]["ChaCha20"]
            encrypted_message = encrypt_chacha20(message, recipient_key)
        
        if encrypted_message:
            # Add message to the chat history
            st.session_state.messages.append({
                "id": str(uuid.uuid4()),
                "sender": sender,
                "recipient": recipient,
                "message": encrypted_message,
                "algorithm": algorithm,
                "timestamp": time.time()
            })
            save_data()
            return True, "Message sent"
        else:
            return False, "Encryption failed"
    except Exception as e:
        return False, f"Error sending message: {e}"

def get_messages(username):
    # Get messages where the user is either sender or recipient
    return [msg for msg in st.session_state.messages 
            if msg["sender"] == username or msg["recipient"] == username]

def decrypt_message(message, username):
    try:
        algorithm = message["algorithm"]
        encrypted_text = message["message"]
        
        if algorithm == "AES":
            key = st.session_state.user_keys[username]["AES"]
            return decrypt_aes(encrypted_text, key)
        elif algorithm == "RSA":
            # If user is recipient, use their private key
            if message["recipient"] == username:
                private_key = st.session_state.user_keys[username]["RSA"]["private"]
                return decrypt_rsa(encrypted_text, private_key)
            else:
                # Cannot decrypt messages sent by the user to others with RSA
                return "[Encrypted with recipient's public key]"
        elif algorithm == "ChaCha20":
            key = st.session_state.user_keys[username]["ChaCha20"]
            return decrypt_chacha20(encrypted_text, key)
        else:
            return "[Unknown encryption algorithm]"
    except Exception as e:
        return f"[Decryption failed: {e}]"

# UI Functions
def show_login_page():
    st.title("Secure Chat Application")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            success, message = login_user(username, password)
            if success:
                st.success(message)
                st.experimental_rerun()
            else:
                st.error(message)
    
    with tab2:
        st.subheader("Register")
        new_username = st.text_input("Username", key="register_username")
        new_password = st.text_input("Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
        
        if st.button("Register"):
            if new_password != confirm_password:
                st.error("Passwords do not match")
            elif not new_username or not new_password:
                st.error("Username and password cannot be empty")
            else:
                success, message = register_user(new_username, new_password)
                if success:
                    st.success(message)
                else:
                    st.error(message)

def show_chat_page():
    st.title(f"Secure Chat - Welcome {st.session_state.username}")
    
    # Logout button
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.experimental_rerun()
    
    # Algorithm selection
    algorithm_descriptions = {
        "AES": "Advanced Encryption Standard - Symmetric encryption using the same key for encryption and decryption.",
        "RSA": "Rivest-Shamir-Adleman - Asymmetric encryption using public and private keys.",
        "ChaCha20": "ChaCha20-Poly1305 - Modern stream cipher with high performance on software implementations."
    }
    
    st.sidebar.subheader("Encryption Settings")
    selected_algorithm = st.sidebar.selectbox(
        "Select Encryption Algorithm",
        options=["AES", "RSA", "ChaCha20"],
        index=["AES", "RSA", "ChaCha20"].index(st.session_state.algorithm)
    )
    
    st.session_state.algorithm = selected_algorithm
    st.sidebar.info(algorithm_descriptions[selected_algorithm])
    
    # Display user's keys
    with st.sidebar.expander("Your Encryption Keys"):
        if selected_algorithm == "AES":
            st.code(st.session_state.user_keys[st.session_state.username]["AES"], language="text")
        elif selected_algorithm == "RSA":
            st.text("Public Key:")
            st.code(st.session_state.user_keys[st.session_state.username]["RSA"]["public"], language="text")
            st.text("Private Key:")
            st.code(st.session_state.user_keys[st.session_state.username]["RSA"]["private"], language="text")
        elif selected_algorithm == "ChaCha20":
            st.code(st.session_state.user_keys[st.session_state.username]["ChaCha20"], language="text")
    
    # Chat interface
    st.subheader("Chat")
    
    # Get list of users for recipient selection
    recipients = [user for user in st.session_state.users.keys() if user != st.session_state.username]
    
    # Display messages first
    st.subheader("Message History")
    messages = get_messages(st.session_state.username)
    
    # Auto-refresh toggle
    auto_refresh = st.checkbox("Auto-refresh messages", value=st.session_state.auto_refresh)
    if auto_refresh != st.session_state.auto_refresh:
        st.session_state.auto_refresh = auto_refresh
    
    if not messages:
        st.info("No messages yet")
    else:
        # Sort messages by timestamp
        messages.sort(key=lambda x: x["timestamp"])
        
        # Update last message time
        if messages:
            st.session_state.last_message_time = max([msg.get("timestamp", 0) for msg in messages])
        
        for msg in messages:
            is_sent = msg["sender"] == st.session_state.username
            other_user = msg["recipient"] if is_sent else msg["sender"]
            
            # Decrypt the message
            decrypted_text = decrypt_message(msg, st.session_state.username)
            
            # Display the message
            message_container = st.container()
            with message_container:
                cols = st.columns([1, 4])
                with cols[0]:
                    st.write(f"{'You → ' + other_user if is_sent else other_user + ' → You'}:")
                with cols[1]:
                    st.text_area(
                        "",
                        value=decrypted_text,
                        height=50,
                        key=f"msg_{msg['id']}",
                        disabled=True
                    )
                st.caption(f"Algorithm: {msg['algorithm']} | Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(msg['timestamp']))}")
        
        # Manual refresh button at the bottom of the chat
        if st.button("Refresh Messages"):
            # Update the last message time to force a refresh
            if os.path.exists(MESSAGES_FILE):
                with open(MESSAGES_FILE, 'r') as f:
                    latest_messages = json.load(f)
                    st.session_state.messages = latest_messages
    
    # Message input box at the bottom
    if recipients:
        recipient = st.selectbox("Select recipient", options=recipients)
        
        # Create a form for message input to handle clearing properly
        with st.form(key="message_form"):
            message = st.text_input("Type your message", key="message_input")
            submit_button = st.form_submit_button("Send")
            
        if submit_button and message:
            success, result = send_message(
                st.session_state.username,
                recipient,
                message,
                selected_algorithm
            )
            if success:
                st.success(result)
                # The form will automatically clear on rerun
            else:
                st.error(result)
    else:
        st.info("No other users registered yet. Ask someone to register!")

# Main app logic
def check_for_new_messages():
    """Check for new messages without refreshing the entire page"""
    # Only check for new messages if user is logged in
    if st.session_state.logged_in and st.session_state.auto_refresh:
        # Load the latest messages from file
        if os.path.exists(MESSAGES_FILE):
            with open(MESSAGES_FILE, 'r') as f:
                latest_messages = json.load(f)
                
            # Update session state messages if there are new ones
            if latest_messages and len(latest_messages) > len(st.session_state.messages):
                st.session_state.messages = latest_messages
                st.experimental_rerun()
            
            # Check if there are new messages based on timestamp
            if latest_messages:
                latest_time = max([msg.get("timestamp", 0) for msg in latest_messages])
                if latest_time > st.session_state.last_message_time:
                    st.session_state.last_message_time = latest_time
                    st.session_state.messages = latest_messages
                    st.experimental_rerun()

def main():
    # Check for new messages (this runs on each rerender)
    check_for_new_messages()
    
    if not st.session_state.logged_in:
        show_login_page()
    else:
        show_chat_page()

if __name__ == "__main__":
    main()
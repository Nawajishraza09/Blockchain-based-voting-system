import sys
import hashlib
import time
import datetime
import sqlite3
import serial  # For R307 communication
from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QFileDialog, QMessageBox, QRadioButton, QButtonGroup, QApplication
from PySide6.QtGui import QIntValidator, QRegularExpressionValidator, QPixmap
from PySide6.QtCore import Qt, QRegularExpression
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import matplotlib.pyplot as plt
from io import BytesIO
from PIL import Image, ImageQt
import json
import logging
import base64
import os
    
# Configure logging
logging.basicConfig(filename="action_logs.txt", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
                    
class Blockchain:
    def __init__(self):
        self.chain = []
        self.voter_records = set()  # Track voters who have cast their vote
        self.create_block(voter_id='Genesis', candidate_id='Genesis')  # Genesis block

    def create_block(self, voter_id, candidate_id):
        """Create a new block containing voter, candidate data validate validate double voting."""
        try:
            # Check for double voting
            if voter_id in self.voter_records:
                logging.error(f"Double Voting Attempt Detected: Voter ID {voter_id}")
                raise Exception(f"Double voting attempt detected for Voter ID {voter_id}")

            # Prepare the block data
            block = {
                'index': len(self.chain) + 1,
                'timestamp': str(datetime.datetime.now()),
                'voter_id': voter_id,
                'candidate_id': candidate_id,
                'previous_hash': self.get_last_block_hash(),
            }

             # Calculate block's hash
            block['hash'] = self.hash_block(block)

            # Add block to the blockchain
            self.chain.append(block)

            # Record the voter as having cast their vote
            self.voter_records.add(voter_id)

            logging.info(f"Blockchain: New block created for Voter ID: {voter_id}, Candidate ID: {candidate_id}")
            return block
        except Exception as e:
            QMessageBox.critical(None, "Blockchain Error", f"Failed to create blockchain block: {e}")
            logging.error(f"Blockchain Error: Failed to create block - {e}")
            return None

    def get_last_block_hash(self):
        """Retrieve the hash of the last block in the chain."""
        if self.chain:
            return self.chain[-1]['hash']
        logging.warning("Blockchain is empty, returning '0' as the previous hash.")
        return '0'

    @staticmethod
    def hash_block(block):
        """Generate hash for a block."""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()    
    
    def generate_hash(self, voter_id, candidate_id, previous_hash, timestamp):
        """Generate a SHA-256 hash for a block."""
        block_string = f"{voter_id}{candidate_id}{previous_hash}{timestamp}"
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def validate_chain(self):
        """Validate the integrity of the blockchain."""
        if len(self.chain) < 2:  # Only the Genesis block, no validation needed
            return True

        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Recalculate the hash and compare
            recalculated_hash = self.generate_hash(
                current_block['voter_id'],
                current_block['candidate_id'],
                current_block['previous_hash'],
                current_block['timestamp']
            )
            
            # Check the current block's hash matches the stored hash
            if current_block['hash'] != self.hash_block(current_block):
                logging.error(f"Invalid block hash at index {i}")
                return False

            # Check that the previous block's hash matches the current block's previous_hash
            if current_block['previous_hash'] != previous_block['hash']:
                logging.error(f"Block linkage failed at index {i}")
                return False

        logging.info("Blockchain validation successful.")
        # If all blocks are valid, return True
        return True

class AES_Encryption:
    """Class to handle AES encryption and decryption."""
    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long.")
        self.key = key

    def encrypt(self, plaintext):
        """Encrypt plaintext using AES."""
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')  # Ensure plaintext is in bytes

            iv = os.urandom(16)  # Generate a random initialization vector (IV)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad plaintext to block size (16 bytes)
            padder = aes_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(iv + ciphertext)  # Return base64 encoded (IV + ciphertext)
        except Exception as e:
            QMessageBox.critical(None, "Encryption Error", f"Failed to encrypt data: {e}")
            return None

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using AES."""
        try:
            ciphertext = base64.b64decode(ciphertext)
            iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(actual_ciphertext) + decryptor.finalize()

            # Remove padding
            unpadder = aes_padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
            return decrypted_data.decode('utf-8')  # Convert byte data back to string
        except Exception as e:
            QMessageBox.critical(None, "Decryption Error", f"Failed to decrypt data: {e}")
            return None

class FingerprintHandler:
    def __init__(self, private_key, public_key, serial_connection):
        self.private_key = private_key
        self.public_key = public_key
        self.serial_connection = serial_connection  # Use the serial connection to interact with the fingerprint device

class AdminPanel(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            self.conn = sqlite3.connect("voting_system.db")
            self.create_tables() 
            logging.info("Database connection established.")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            QMessageBox.critical(self, "Error", f"Database connection failed: {e}")
            sys.exit()

        self.fingerprint_template = None
        self.fingerprint_hash = None
        self.fingerprint_signature = None

        # Initialize Blockchain
        self.blockchain = Blockchain()

        self.setWindowTitle("Voting System")
        self.setGeometry(200, 200, 600, 400)
        
        # Tabbed Layout for Candidate and Voter Registration
        self.tab_widget = QTabWidget()
        
        self.voter_registration_tab = QWidget()
        self.candidate_registration_tab = QWidget()
        self.voting_tab = QWidget()
        self.results_tab = QWidget()
        
        self.init_voter_registration_tab()
        self.init_candidate_registration_tab()
        self.init_voting_tab()
        self.init_results_tab()
        
        self.tab_widget.addTab(self.voter_registration_tab, "Voter Registration")
        self.tab_widget.addTab(self.candidate_registration_tab, "Candidate Registration")
        self.tab_widget.addTab(self.voting_tab, "Voting")
        self.tab_widget.addTab(self.results_tab, "Results")

        self.setCentralWidget(self.tab_widget) 

        # RSA key pair for digital signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()  

        # AES key for encryption (In practice, use a secure key derivation or storage mechanism)
        self.aes_key = os.urandom(32)  # 256-bit AES key for encryption
        self.aes_encryption = AES_Encryption(self.aes_key)

        # Initialize serial communication with R307 (Adjust COM port if necessary)
        try:
            self.ser = serial.Serial('COM5', baudrate=57600, timeout=1)
        except serial.SerialException as e:
            QMessageBox.critical(None, "Serial Connection Error", f"Failed to connect to fingerprint device: {e}")
            logging.error(f"Serial connection error: {e}")   

    def create_tables(self):
        """Create necessary tables for voters and candidates."""
        try:
            cursor = self.conn.cursor()

            # Enable foreign key constraints
            self.conn.execute('PRAGMA foreign_keys = ON')

            # Voters table
            cursor.execute('''CREATE TABLE IF NOT EXISTS voters (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          voter_id INTEGER NOT NULL UNIQUE,
                          aadhaar_id INTEGER NOT NULL UNIQUE,
                          name TEXT,
                          fingerprint_template BLOB,
                          fingerprint_hash BLOB,
                          fingerprint_signature BLOB)''')

            # Candidates table
            cursor.execute('''CREATE TABLE IF NOT EXISTS candidates (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          candidate_id INTEGER NOT NULL UNIQUE,
                          aadhaar_id INTEGER NOT NULL UNIQUE,
                          name TEXT,
                          party TEXT)''')

            # Votes table
            cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          voter_id INTEGER NOT NULL,
                          candidate_id INTEGER NOT NULL,
                          timestamp TEXT,
                          FOREIGN KEY(voter_id) REFERENCES voters(voter_id),
                          FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id))''')
            self.conn.commit()
            logging.info("Database tables created successfully.")
        except sqlite3.Error as e:
            logging.error(f"Database Error: {e}")
            QMessageBox.critical(self, "Database Error", f"Failed to create tables: {e}")

    # Voter Registration Tab
    def init_voter_registration_tab(self):
        layout = QVBoxLayout()

        # Labels and Inputs
        self.voter_name_label = QLabel("Name:")
        self.voter_name_input = QLineEdit()

        self.voter_aadhaar_id_label = QLabel("Aadhaar ID:")
        self.voter_aadhaar_id_input = QLineEdit()
        aadhaar_validator = QRegularExpressionValidator(QRegularExpression(r"^\d{12}$"))
        self.voter_aadhaar_id_input.setValidator(aadhaar_validator)

        self.voter_id_label = QLabel("Voter ID:")
        self.voter_id_input = QLineEdit()
        voter_id_validator = QRegularExpressionValidator(QRegularExpression(r"^[A-Za-z0-9]{6,10}$"))
        self.voter_id_input.setValidator(None)

        # Button
        self.capture_fingerprint_button = QPushButton("Capture Fingerprint")
        self.capture_fingerprint_button.clicked.connect(self.capture_fingerprint)

        self.submit_voter_button = QPushButton("Submit Voter Registration")
        self.submit_voter_button.clicked.connect(self.submit_voter_registration)

        # Layout
        layout.addWidget(self.voter_name_label)
        layout.addWidget(self.voter_name_input)
        layout.addWidget(self.voter_aadhaar_id_label)
        layout.addWidget(self.voter_aadhaar_id_input)
        layout.addWidget(self.voter_id_label)
        layout.addWidget(self.voter_id_input)
        layout.addWidget(self.capture_fingerprint_button)
        layout.addWidget(self.submit_voter_button)

        self.voter_registration_tab.setLayout(layout)

    # Candidate Registration Tab
    def init_candidate_registration_tab(self):
        layout = QVBoxLayout()

        # Labels and Inputs
        self.candidate_name_label = QLabel("Name:")
        self.candidate_name_input = QLineEdit()

        self.candidate_aadhaar_id_label = QLabel("Aadhaar ID:")
        self.candidate_aadhaar_id_input = QLineEdit()
        aadhaar_validator = QRegularExpressionValidator(QRegularExpression(r"^\d{12}$"))
        self.candidate_aadhaar_id_input.setValidator(aadhaar_validator)

        self.candidate_id_label = QLabel("Candidate ID:")
        self.candidate_id_input = QLineEdit()
        candidate_id_validator = QRegularExpressionValidator(QRegularExpression(r"^[A-Za-z0-9]{6,10}$"))
        self.candidate_id_input.setValidator(candidate_id_validator)

        self.candidate_party_label = QLabel("Party/Group Affiliation:")
        self.candidate_party_input = QLineEdit()

        # Button
        self.submit_candidate_button = QPushButton("Submit Candidate Registration")
        self.submit_candidate_button.clicked.connect(self.submit_candidate_registration)

        # Layout
        layout.addWidget(self.candidate_name_label)
        layout.addWidget(self.candidate_name_input)
        layout.addWidget(self.candidate_aadhaar_id_label)
        layout.addWidget(self.candidate_aadhaar_id_input)
        layout.addWidget(self.candidate_id_label)
        layout.addWidget(self.candidate_id_input)
        layout.addWidget(self.candidate_party_label)
        layout.addWidget(self.candidate_party_input)
        layout.addWidget(self.submit_candidate_button)

        self.candidate_registration_tab.setLayout(layout)

    # Voting Tab
    def init_voting_tab(self):
        layout = QVBoxLayout()

        # Voter ID Verification Section
        self.voter_verification_label = QLabel("Voter ID for Verification:")
        self.voter_verification_input = QLineEdit()
        voter_verification_validator = QRegularExpressionValidator(QRegularExpression(r"^[A-Za-z0-9]{6,10}$"))
        self.voter_verification_input.setValidator(voter_verification_validator)

        self.verify_voter_button = QPushButton("Verify Voter")
        self.verify_voter_button.clicked.connect(self.verify_voter)

        # Candidate List Section
        self.candidate_list_label = QLabel("Candidate List:")
        
        # Radio button group to display candidates for selection
        self.candidate_radio_group = QButtonGroup(self)
        self.candidate_radio_group.setExclusive(True)  # Ensure only one candidate can be selected

        # Container widget and layout for candidates' radio buttons
        self.candidate_radio_layout = QVBoxLayout()
        self.candidate_container = QWidget()
        self.candidate_container.setLayout(self.candidate_radio_layout)

        # Load and display candidates dynamically
        self.load_candidate()

        # Add candidate radio buttons layout to main voting layout
        layout.addWidget(self.voter_verification_label)
        layout.addWidget(self.voter_verification_input)
        layout.addWidget(self.verify_voter_button)
        layout.addWidget(self.candidate_list_label)
        layout.addWidget(self.candidate_container)

        # Cast Vote Button
        self.cast_vote_button = QPushButton("Cast Vote")
        self.cast_vote_button.setEnabled(False)  # Initially disabled until voter verification
        self.cast_vote_button.clicked.connect(self.cast_vote)
        layout.addWidget(self.cast_vote_button)

        self.voting_tab = QWidget()
        self.voting_tab.setLayout(layout)
        self.setCentralWidget(self.voting_tab)
    
    # Results Tab (Graphical Representation/for visualizing vote statistics)
    def init_results_tab(self):
        layout = QVBoxLayout()
        self.view_results_button = QPushButton("View Results")
        self.view_results_button.clicked.connect(self.display_results)
        layout.addWidget(self.view_results_button)
        self.results_tab.setLayout(layout)

    # Blockchain Validation Tab
    def init_validation_tab(self):
        """Initialize the blockchain validation tab."""
        layout = QVBoxLayout()
    
        # Button to trigger blockchain validation
        self.validate_button = QPushButton("Validate Blockchain")
        self.validate_button.clicked.connect(self.validate_blockchain)
    
        layout.addWidget(self.validate_button)
        self.validation_tab.setLayout(layout)

    def generate_fingerprint_signature(self, fingerprint_data):
        """Generate SHA-512 hash of the fingerprint and sign with RSA private key."""
        fingerprint_hash = hashlib.sha512(fingerprint_data).digest()
        signature = self.private_key.sign(
            fingerprint_hash,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA512()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return fingerprint_hash, signature

    def verify_fingerprint_signature(self, fingerprint_data, signature):
        """Verify fingerprint integrity using SHA-512 and RSA signature."""
        fingerprint_hash = hashlib.sha512(fingerprint_data).digest()
        try:
            self.public_key.verify(
                signature,
                fingerprint_hash,
                rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(hashes.SHA512()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except Exception as e:
            logging.error(f"Signature verification failed: {e}")
            return False

    def capture_fingerprint(self,):
        """Capture fingerprint using R307 sensor and encrypt it with AES."""
        try:
            self.ser.write(b'\xEF\x01\xFF\xFF\xFF\xFF\x01\x00\x03\x01\x00\x05')  # Send capture command to R307
            response = self.ser.read()  # Read response (256/512 bytes template data)
            # Simulated fingerprint template storage for now

            # Encrypt the fingerprint template using AES before storing it
            if response and len(response) > 0:
                logging.info(f"Raw fingerprint data received: {response}")

                # Encrypt the fingerprint template using AES before storing it
                encrypted_template = self.aes_encryption.encrypt(response)

                # Generate the fingerprint hash and signature
                fingerprint_hash, signature = self.generate_fingerprint_signature(response)
                
                # Store the encrypted fingerprint template and signature
                self.fingerprint_template = encrypted_template
                logging.info(f"Encrypted fingerprint template: {self.fingerprint_template}")

                self.fingerprint_hash = fingerprint_hash
                logging.info(f"Fingerprint Hash: {self.fingerprint_hash}")

                self.fingerprint_signature = signature
                logging.info(f"Fingerprint Signature: {self.fingerprint_signature}")

                logging.info("Fingerprint captured, ecrypted, and signed successfully.")
                QMessageBox.information(self, "Success", "Fingerprint captured, encrypted and signed successfully.")
            else:
                QMessageBox.critical(self,"Error","Failed to capture fingerprint.")
        except Exception as e:
            logging.error(f"Error capturing fingerprint: {e}")
            QMessageBox.critical(self, "Error", f"Failed to capture fingerprint: {e}")

    def submit_voter_registration(self):
        """Submit voter registration details to the database."""
        try:
            # Log all input values to verify
            logging.info(f"Voter Name Field Value: {self.voter_name_input.text()}")
            logging.info(f"Voter Aadhaar ID Field Value: {self.voter_aadhaar_id_input.text()}")
            logging.info(f"Voter ID Field Value: {self.voter_id_input.text()}")

            # Validation check
            if not self.voter_id_input.text().strip():
                logging.warning("Voter ID field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Voter ID is missing.")
                return

            if not self.voter_aadhaar_id_input.text().strip():
                logging.warning("Voter Aadhaar ID field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Aadhaar ID is missing.")
                return

            if not self.voter_name_input.text().strip():
                logging.warning("Voter Name field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Name is missing.")
                return

            if not self.fingerprint_template:
                logging.warning("Please capture the fingerprint.")
                QMessageBox.warning(self, "Fingerprint Missing", "Please capture the fingerprint before submitting.")
                return 
                
            if not self.fingerprint_hash or not self.fingerprint_signature:
                QMessageBox.warning(self, "Input Error", "Fingerprint data is incomplete. Please capture the fingerprint.")
                return
            
            # Insert data into database
            cursor = self.conn.cursor()
            cursor.execute("""INSERT INTO voters (voter_id, aadhaar_id, name, fingerprint_template, fingerprint_hash, fingerprint_signature)
                              VALUES (?, ?, ?, ?, ?, ?)""",
                            (self.voter_id_input.text(), self.voter_aadhaar_id_input.text(), self.voter_name_input.text(), 
                             self.fingerprint_template, self.fingerprint_hash, self.fingerprint_signature))
            self.conn.commit()

            logging.info(f"Voter Registration: Voter ID {self.voter_id_input.text()} registered with RSA signature and SHA-512 hash successfull.")
            QMessageBox.information(self, "Success", "Voter registered with RSA signature and SHA-512 has successfull.")
            
            # Clear inputs
            self.voter_id_input.clear()
            self.voter_aadhaar_id_input.clear()
            self.voter_name_input.clear()
            self.fingerprint_template = None  # Reset fingerprint data
            self.fingerprint_hash = None
            self.fingerprint_signature = None
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Database Error", "Voter ID or Aadhaar ID already exists.")
            logging.error("Duplicate voter ID or Aadhaar ID registration attempt.")
        except Exception as e:
            logging.error(f"Failed to register voter: {e}")
            QMessageBox.critical(self, "Error", f"Failed to register voter: {e}")

    def submit_candidate_registration(self):
        """Submit candidate registration details to the database."""
        try:
            # Log all input values to verify
            logging.info(f"Candidate Name Field Value: {self.candidate_name_input.text()}")
            logging.info(f"Candidate Aadhaar ID Field Value: {self.candidate_aadhaar_id_input.text()}")
            logging.info(f"Candidate ID Field Value: {self.candidate_id_input.text()}")
            logging.info(f"Candidate Party/Group Affilation Field value: {self.candidate_party_input.text()}")

            # Validation check
            if not self.candidate_id_input.text().strip():
                logging.warning("Candidate ID field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Candidate ID is missing.")
                return

            if not self.candidate_aadhaar_id_input.text().strip():
                logging.warning("Candidate Aadhaar ID field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Aadhaar ID is missing.")
                return

            if not self.candidate_name_input.text().strip():
                logging.warning("Candidate Name field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Name is missing.")
                return

            if not self.candidate_party_input.text().strip():
                logging.warning("Candidate Part/Group Affiliation field is empty or invalid.")
                QMessageBox.warning(self, "Input Error", "Party/Group Affilation name is missing.")
                return

            # Insert data into database
            cursor = self.conn.cursor()
            cursor.execute("""INSERT INTO candidates (candidate_id, aadhaar_id, name, party)
                              VALUES (?, ?, ?, ?)""",
                            (self.candidate_id_input.text(), self.candidate_aadhaar_id_input.text(), self.candidate_name_input.text(),
                             self.candidate_party_input.text()))
            self.conn.commit()

            logging.info(f"Candidate Registration: Candidate ID {self.candidate_id_input.text()} registered successfully.")
            QMessageBox.information(self, "Success", "Candidate registered successfully.")
        
            # Clear inputs
            self.candidate_id_input.clear()
            self.candidate_aadhaar_id_input.clear()
            self.candidate_name_input.clear()
            self.candidate_party_input.clear()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Database Error", "Candidate ID or Aadhaar ID already exists.")
            logging.error("Duplicate candidate ID or Aadhaar ID registration attempt.")
        except Exception as e:
            logging.error(f"Failed to register candidate: {e}")
            QMessageBox.critical(self, "Error", f"Failed to register candidate: {e}")

    def verify_voter(self):
        """Verify voter using AES-decrypted fingerprint and display candidates."""
        # Retrieve voter data from database and compare fingerprint
        try:
            # Retrieve voter data
            cursor = self.conn.cursor()
            cursor.execute("SELECT fingerprint_template, fingerprint_hash, fingerprint_signature FROM voters WHERE voter_id=?",
                            (self.voter_id_input.text(),))
            voter_data = cursor.fetchone()

            if voter_data:
                decrypted_fingerprint = self.aes_encryption.decrypt(voter_data[0])

                # Validate fingerprint signature and hash
                if self.verify_fingerprint_signature(decrypted_fingerprint, voter_data[2]) and \
                    voter_data[1] == hashlib.sha512(decrypted_fingerprint).digest():

                    logging.info(f"Voter Verification: Voter ID {self.voter_id_input.text()} verified successfully.")
                    QMessageBox.information(self, "Verified", "Voter verified successfully.")

                    # Populate candidate list
                    self.populate_candidate_list()
                else:
                    QMessageBox.critical(self, "Error", "Fingerprint does not match.")
                    logging.warning(f"Verification failed for Voter ID {self.voter_id_input.text()}.")
            else:
                logging.warning(f"Voter Verification Failed: Voter ID {self.voter_id_input.text()} voter not found.")
                QMessageBox.critical(self, "Error", "Voter not found.")
        except Exception as e:
            logging.error(f"Voter Verification Error: {e}")
            QMessageBox.critical(self,"Verification Failed",f"Failed to verify voter: {e}")

    def load_candidate(self):
        """Load candidates from the database and create radio buttons for each candidate."""
        self.clear_candidate()  # Clear existing candidates if any
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT candidate_id, name FROM candidates")
            candidates = cursor.fetchall()

            if not candidates:
                logging.info("No candidates found in the database.")
                QMessageBox.information(self, "No Candidates", "No candidates are registered yet.")
                return

            for candidate in candidates:
                candidate_id, candidate_name = candidate
                radio_button = QRadioButton(f"{candidate_name} (ID: {candidate_id})")
                radio_button.candidate_id = candidate_id  # Attach candidate_id to each button

                self.candidate_radio_group.addButton(radio_button)
                self.candidate_radio_layout.addWidget(radio_button)

            logging.info(f"{len(candidates)} candidates loaded successfully.")
        except sqlite3.Error as db_error:
            logging.error(f"Database Error: Failed to load candidates - {db_error}")
            QMessageBox.critical(self, "Database Error", f"Failed to load candidates from database: {db_error}")
        except Exception as e:
            logging.error(f"Failed to load candidates: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load candidates: {e}")

    def toggle_cast_vote_button(self):
        """Enable or disable the cast vote button based on candidate availability."""
        self.cast_vote_button.setEnabled(bool(self.candidate_radio_group.buttons()))

    def clear_candidate(self):
        """Clear candidate radio buttons from the layout."""
        while self.candidate_radio_layout.count():
            item = self.candidate_radio_layout.takeAt(0)
            widget = item.widget()
            if widget:
                self.candidate_radio_group.removeButton(widget)
                widget.deleteLater()
        logging.info("Candidate radio buttons cleared.")

    def toggle_cast_vote_button(self):
        """Enable or disable the cast vote button based on candidate availability."""
        self.cast_vote_button.setEnabled(bool(self.candidate_radio_group.buttons()))

    def cast_vote(self):
        """Cast a vote for the selected candidate and add it to the blockchain."""
        try:
            # Ensure a voter ID is entered
            voter_id = self.voter_id_input.text().strip()
            if not voter_id:
                QMessageBox.warning(self, "Input Error", "Please enter a Voter ID.")
                return

            # Find the selected candidate
            selected_button = self.candidate_radio_group.checkedButton()
            if not selected_button:
                QMessageBox.warning(self, "Selection Error", "Please select a candidate to cast the vote.")
                return

            candidate_id = selected_button.candidate_id
            
            # Check for duplicate voting
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM votes WHERE voter_id = ?", (voter_id,))
            if cursor.fetchone():
                QMessageBox.critical(self, "Voting Error", "You have already cast your vote.")
                return

            # Insert vote record into the database
            timestamp = str(datetime.datetime.now())
            new_block = self.blockchain.create_block(voter_id, candidate_id)
            if new_block:
                cursor.execute("INSERT INTO votes (voter_id, candidate_id, timestamp) VALUES (?, ?, ?)",
                                (voter_id, candidate_id, timestamp))
                self.conn.commit()

                # UI Updates
                QMessageBox.information(self, "Vote Cast", "Your vote has been cast successfully!")
                self.cast_vote_button.setEnabled(False)  # Disable voting button
                self.voter_id_input.clear()  # Clear voter ID input field
                self.candidate_radio_group.setExclusive(False)  # Temporarily disable exclusivity
                for button in self.candidate_radio_group.buttons():
                    button.setChecked(False)  # Uncheck all radio buttons
                self.candidate_radio_group.setExclusive(True)  # Re-enable exclusivity

                logging.info(f"Vote Cast: Voter ID {voter_id} voted for Candidate ID {candidate_id}")
            else:
                QMessageBox.critical(self, "Blockchain Error", "Failed to record vote on the blockchain.")
                logging.error("Failed to add vote to the blockchain.")

        except sqlite3.Error as db_error:
            logging.error(f"Database Error: {db_error}")
            QMessageBox.critical(self, "Database Error", "An error occurred while recording your vote. Please try again.")
            self.conn.rollback()
        except Exception as e:
            logging.error(f"Unexpected Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to cast vote: {e}")

    def validate_blockchain(self):
        """Validate the blockchain integrity and display result."""
        try:
            is_valid = self.blockchain.validate_chain()
            if is_valid:
                QMessageBox.information(self, "Blockchain Validation", "Blockchain is valid and intact.")
                logging.info("Blockchain validation successful: Chain is intact.")
            else:
                QMessageBox.critical(self, "Blockchain Validation", "Blockchain integrity compromised!")
                logging.error("Blockchain validation failed: Chain integrity is compromised.")
        except Exception as e:
            logging.error(f"Error during blockchain validation: {e}")
            QMessageBox.critical(self, "Error", "An error occurred while validating the blockchain.")

    def display_results(self):
        """Display voting statistics as both bar chart and pie chart inside the application and save the charts."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
            SELECT candidates.name, candidates.party, COUNT(votes.id) AS vote_count
            FROM votes
            INNER JOIN candidates ON votes.candidate_id = candidates.candidate_id
            GROUP BY candidates.candidate_id
            ORDER BY vote_count DESC
            """)
            result = cursor.fetchall()

            if not result:
                QMessageBox.information(self, "No Data", "No votes have been cast yet.")
                logging.info("Results Viewed: No votes have been cast yet.")
                return
        
            # Prepare data for the charts
            candidate_names = [f"{row[0]} ({row[1]})" for row in result]
            vote_counts = [row[2] for row in result]

            # Bar Chart
            plt.figure(figsize=(8, 6))
            plt.bar(candidate_names, vote_counts, color='skyblue')
            plt.title("Election Results", fontsize=16)
            plt.xlabel("Candidates", fontsize=12)
            plt.ylabel("Votes", fontsize=12)
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()

            # Save Bar Chart to a buffer and display it
            buffer = BytesIO()
            plt.savefig(buffer, format="png")
            buffer.seek(0)
            bar_chart_image = Image.open(buffer)
            pixmap_bar = QPixmap.fromImage(ImageQt(bar_chart_image))
            self.bar_chart_label.setPixmap(pixmap_bar)  # Assuming self.bar_chart_label is the QLabel to show the bar chart
            buffer.close()

            # Save Bar Chart to disk
            bar_chart_filename = "bar_chart.png"
            plt.savefig(bar_chart_filename)
            logging.info(f"Bar chart saved as {bar_chart_filename}")
            plt.close()

            # Pie Chart
            plt.figure(figsize=(8, 6))
            plt.pie(vote_counts, labels=candidate_names, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
            plt.title("Vote Share Per Candidate", fontsize=16)
  
            # Save Pie Chart to a buffer and display it
            buffer = BytesIO()
            plt.savefig(buffer, format="png")
            buffer.seek(0)
            pie_chart_image = Image.open(buffer)
            pixmap_pie = QPixmap.fromImage(ImageQt(pie_chart_image))
            self.pie_chart_label.setPixmap(pixmap_pie)  # Assuming self.pie_chart_label is the QLabel to show the pie chart
            buffer.close()

            # Save Pie Chart to disk
            pie_chart_filename = "pie_chart.png"
            plt.savefig(pie_chart_filename)
            logging.info(f"Pie chart saved as {pie_chart_filename}")
            plt.close()

            logging.info("Results Viewed: Vote statistics displayed.")
            QMessageBox.information(self, "Results", "Results displayed.")

        except Exception as e:
            logging.error(f"Results Display Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to display results: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    admin_panel = AdminPanel()
    admin_panel.show()
    sys.exit(app.exec())

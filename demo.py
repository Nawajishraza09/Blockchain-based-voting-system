import os
import sys
import logging
import sqlite3
import serial  # For R307 communication
import time
import datetime
import json
import hashlib
import adafruit_fingerprint
from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QFileDialog, QMessageBox, QRadioButton, QButtonGroup, QApplication
from PySide6.QtGui import QIntValidator, QRegularExpressionValidator, QPixmap
from PySide6.QtCore import Qt, QRegularExpression
import numpy as np
import matplotlib.pyplot as plt
from io import BytesIO
from PIL import Image
from PIL.ImageQt import ImageQt
import base64
    
# Configure logging
logging.basicConfig(filename="action_logs.txt", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
                    
class Block:
    def __init__(self, index, timestamp, data, previous_hash, hash = None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = hash or self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_blockchain()

    def create_genesis_block(self):
        """Create the first block in the blockchain."""
        return Block(0, str(datetime.datetime.now()), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        """Add a new block to the blockchain"""
        try:
            latest_block = self.get_latest_block()
            new_block = Block(
                index=len(self.chain),
                timestamp=str(datetime.datetime.now()),
                data=data,
                previous_hash=latest_block.hash,
            )
            self.chain.append(new_block)
            self.save_blockchain()  # Save the updated blockchain
            return new_block # Return the new block to indicate success
        except Exception as e:
            logging.error(f"Error adding block: {e}")
            return None # Indicate failure
    
    def is_chain_valid(self):
        """Check if the blockchain is valid and integrity is maintained."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check if the current block's hash is correct
            if current_block.hash != current_block.calculate_hash():
                logging.error(f"Blockchain Integrity Compromised: Block {current_block.index} has been tampered.")
                QMessageBox.critical(self, "Blockchain Error", f"Blockchain Integrity Compromised: Block {current_block.index} has been tampered.")
                return False

            # Check if the previous hash matches the hash of the previous block
            if current_block.previous_hash != previous_block.hash:
                logging.error(f"Blockchain Integrity Compromised: Block {current_block.index} has an invalid previous hash.")
                QMessageBox.critical(self, "Blockchain Error", f"Blockchain Integrity Compromised: Block {current_block.index} has an invalid previous hash.")
                return False

        logging.info("Blockchain integrity verified: No tampering detected.")
        return True

    def save_blockchain(self):
        """Save the blockchain to a file."""
        try:
            with open("blockchain.json", "w") as file:
                chain_data = [block.__dict__ for block in self.chain]
                json.dump(chain_data, file, indent=4)
            logging.info("Blockchain saved successfully.")
        except Exception as e:
            logging.error(f"Error saving blockchain: {e}")

    def load_blockchain(self):
        """Load the blockchain from a file."""
        try:
            with open("blockchain.json", "r") as file:
                chain_data = json.load(file)
                self.chain = [Block(**block) for block in chain_data]
            logging.info("Blockchain loaded successfully.")
        except FileNotFoundError:
            logging.warning("Blockchain file not found. Creating a new genesis block.")
            self.chain = [self.create_genesis_block()]
        except Exception as e:
            logging.error(f"Error loading blockchain: {e}")
            self.chain = [self.create_genesis_block()]

class BlockchainPanel(QWidget):
    def __init__(self, blockchain_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Blockchain Data")
        self.setGeometry(200, 100, 1200, 600)

        layout = QVBoxLayout()
        table = QTableWidget(len(blockchain_data), 5)
        table.setHorizontalHeaderLabels(["Index", "Timestamp", "Data", "Hash", "Previous Hash"])

        for row, block in enumerate(blockchain_data):
            table.setItem(row, 0, QTableWidgetItem(str(block["Index"])))
            table.setItem(row, 1, QTableWidgetItem(block["Timestamp"]))
            table.setItem(row, 2, QTableWidgetItem(str(block["Data"])))
            table.setItem(row, 3, QTableWidgetItem(block["Hash"]))
            table.setItem(row, 4, QTableWidgetItem(block["Previous Hash"]))

        table.resizeColumnsToContents()
        layout.addWidget(table)
        self.setLayout(layout)

class ResultsPanel(QWidget):
    """Popup window to display voting results as charts."""

    def __init__(self, candidate_names, vote_counts, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Voting Results")
        self.setGeometry(160, 80, 1200, 600)

        # Layout for the popup
        layout = QVBoxLayout()

        # QLabel for bar chart
        self.bar_chart_label = QLabel()
        self.bar_chart_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.bar_chart_label)

        # QLabel for pie chart
        self.pie_chart_label = QLabel()
        self.pie_chart_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.pie_chart_label)

        self.setLayout(layout)

        # Display the charts
        self.display_charts(candidate_names, vote_counts)

    def display_charts(self, candidate_names, vote_counts):
        """Generate and display bar and pie charts."""
        try:
            # Bar Chart
            plt.figure(figsize=(7, 3.5))
            plt.bar(candidate_names, vote_counts, color='skyblue')
            plt.title("Election Results", fontsize=16)
            plt.xlabel("Candidates", fontsize=12)
            plt.ylabel("Votes", fontsize=12)
            plt.tight_layout()

            # Save Bar Chart to a buffer
            buffer = BytesIO()
            plt.savefig(buffer, format="png")
            buffer.seek(0)
            bar_chart_image = Image.open(buffer)
            pixmap_bar = QPixmap.fromImage(ImageQt(bar_chart_image))
            self.bar_chart_label.setPixmap(pixmap_bar)  # Set the bar chart image
            buffer.close()
            plt.close()

            # Pie Chart
            colors = plt.cm.Paired(np.linspace(0, 1, len(vote_counts)))
            plt.figure(figsize=(7, 3.5))
            plt.pie(vote_counts, labels=candidate_names, autopct='%1.1f%%', startangle=140, colors=colors)
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
            plt.title("Vote Share Per Candidate", fontsize=16)

            # Save Pie Chart to a buffer
            buffer = BytesIO()
            plt.savefig(buffer, format="png")
            buffer.seek(0)
            pie_chart_image = Image.open(buffer)
            pixmap_pie = QPixmap.fromImage(ImageQt(pie_chart_image))
            self.pie_chart_label.setPixmap(pixmap_pie)  # Set the pie chart image
            buffer.close()
            plt.close()
        except Exception as e:
            logging.error(f"Error displaying charts: {e}")
            QMessageBox.critical(self, "Error", f"Failed to display charts: {e}")

class AdminPanel(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize Blockchain
        self.blockchain = Blockchain()        

        # Database connection
        try:
            self.conn = sqlite3.connect("voting_system.db")
            self.create_tables() # Create tables if they don't exist
            logging.info("Database connection established and schema validated.")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            QMessageBox.critical(self, "Error", f"Database connection failed: {e}")
            sys.exit()

        self.setWindowTitle("Voting System")
        self.setGeometry(300, 100, 1000, 600)
        self.init_ui()
    
    def calculate_hash(self, data):
        """Generate a SHA-256 hash for the given data."""
        hash_object = hashlib.sha256(data.encode())
        return hash_object.hexdigest()
    
    def enable_wal_mode(self):
        """Enable Write-Ahead Logging (WAL) mode for SQLite."""
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            logging.info("Write-Ahead Logging (WAL) mode enabled.")
        except Exception as e:
            logging.error(f"Failed to enable WAL mode: {e}")

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
                          name TEXT NOT NULL,
                          fingerprint_location INTEGER NOT NULL UNIQUE,
                          record_hash TEXT NOT NULL UNIQUE)''')

            # Candidates table
            cursor.execute('''CREATE TABLE IF NOT EXISTS candidates (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          candidate_id INTEGER NOT NULL UNIQUE,
                          aadhaar_id INTEGER NOT NULL UNIQUE,
                          name TEXT NOT NULL,
                          party TEXT NOT NULL,
                          record_hash TEXT NOT NULL UNIQUE)''')

            # Votes table
            cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          voter_id INTEGER NOT NULL,
                          candidate_id INTEGER NOT NULL,
                          timestamp TEXT,
                          record_hash TEXT NOT NULL UNIQUE,
                          FOREIGN KEY(voter_id) REFERENCES voters(voter_id),
                          FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id))''')
            self.conn.commit()
            logging.info("Database tables created successfully.")
        except sqlite3.Error as e:
            logging.error(f"Database Error: {e}")
            QMessageBox.critical(self, "Database Error", f"Failed to create tables: {e}")

    def init_ui(self):
        # Initializing the UI componenet
        self.tab_widget = QTabWidget()
        
        self.voter_registration_tab = QWidget()
        self.candidate_registration_tab = QWidget()
        self.voting_tab = QWidget()
        self.results_tab = QWidget()
        self.blockchain_monitoring_tab = QWidget()
        
        self.init_voter_registration_tab()
        self.init_candidate_registration_tab()
        self.init_voting_tab()
        self.init_results_tab()
        self.init_blockchain_monitoring_tab()
        
        self.tab_widget.addTab(self.voter_registration_tab, "Voter Registration")
        self.tab_widget.addTab(self.candidate_registration_tab, "Candidate Registration")
        self.tab_widget.addTab(self.voting_tab, "Voting")
        self.tab_widget.addTab(self.results_tab, "Results")
        self.tab_widget.addTab(self.blockchain_monitoring_tab, "Monitor Blockchain")

        self.setCentralWidget(self.tab_widget) 

    def init_voter_registration_tab(self):
        # Initializing UI for voter registration
        layout = QVBoxLayout()

        # Layout, Labels and Inputs
        layout.addWidget(QLabel("Name:"))
        self.voter_name_input = QLineEdit()
        self.voter_name_input.setPlaceholderText("Enter Name")
        layout.addWidget(self.voter_name_input)

        layout.addWidget(QLabel("Aadhaar ID:"))
        self.voter_aadhaar_id_input = QLineEdit()
        self.voter_aadhaar_id_input.setPlaceholderText("Enter Aadhaar ID")
        aadhaar_validator = QRegularExpressionValidator(QRegularExpression(r"^\d{12}$"))
        self.voter_aadhaar_id_input.setValidator(aadhaar_validator)
        layout.addWidget(self.voter_aadhaar_id_input)

        layout.addWidget(QLabel("Voter ID:"))
        self.voter_id_input = QLineEdit()
        self.voter_id_input.setPlaceholderText("Enter Voter ID")
        voter_id_validator = QRegularExpressionValidator(QRegularExpression(r"^[A-Za-z0-9]{6,10}$"))
        self.voter_id_input.setValidator(voter_id_validator)
        layout.addWidget(self.voter_id_input)

        # Button
        self.submit_voter_button = QPushButton("Submit Voter Registration")
        self.submit_voter_button.clicked.connect(self.submit_voter_registration)
        layout.addWidget(self.submit_voter_button)

        self.voter_registration_tab.setLayout(layout)

    def init_candidate_registration_tab(self):
        # Initializing UI for candidate registration
        layout = QVBoxLayout()

        # Layout, Labels and Inputs
        layout.addWidget(QLabel("Name:"))
        self.candidate_name_input = QLineEdit()
        self.candidate_name_input.setPlaceholderText("Enter Name")
        layout.addWidget(self.candidate_name_input)

        layout.addWidget(QLabel("Aadhaar ID:"))
        self.candidate_aadhaar_id_input = QLineEdit()
        self.candidate_aadhaar_id_input.setPlaceholderText("Enter Aadhaar ID")
        aadhaar_validator = QRegularExpressionValidator(QRegularExpression(r"^\d{12}$"))
        self.candidate_aadhaar_id_input.setValidator(aadhaar_validator)
        layout.addWidget(self.candidate_aadhaar_id_input)

        layout.addWidget(QLabel("Candidate ID:"))
        self.candidate_id_input = QLineEdit()
        self.candidate_id_input.setPlaceholderText("Enter Candidate ID")
        candidate_id_validator = QRegularExpressionValidator(QRegularExpression(r"^[A-Za-z0-9]{6,10}$"))
        self.candidate_id_input.setValidator(candidate_id_validator)
        layout.addWidget(self.candidate_id_input)

        layout.addWidget(QLabel("Party/Group/Members Affiliation"))
        self.candidate_party_input = QLineEdit()
        self.candidate_party_input.setPlaceholderText("Enter name of the party/groups/members associated")
        layout.addWidget(self.candidate_party_input)

        # Button
        self.submit_candidate_button = QPushButton("Submit Candidate Registration")
        self.submit_candidate_button.clicked.connect(self.submit_candidate_registration)
        layout.addWidget(self.submit_candidate_button)

        self.candidate_registration_tab.setLayout(layout)

    # Voting Tab
    def init_voting_tab(self):
        layout = QVBoxLayout()

        # Voter ID Verification Section/Layout/Label
        layout.addWidget(QLabel("Voter ID for Verification:"))
        self.voter_verification_input = QLineEdit()
        self.voter_verification_input.setPlaceholderText("Enter Voter ID")
        voter_verification_validator = QRegularExpressionValidator(QRegularExpression(r"^[A-Za-z0-9]{6,10}$"))
        self.voter_verification_input.setValidator(voter_verification_validator)
        layout.addWidget(self.voter_verification_input)

        self.verify_voter_button = QPushButton("Verify Voter")
        self.verify_voter_button.clicked.connect(self.verify_voter)
        layout.addWidget(self.verify_voter_button)

        # Candidate List Section
        layout.addWidget(QLabel("Candidate List:"))
        
        # Radio button group/Layout to display candidates for selection
        self.candidate_radio_group = QButtonGroup(self)
        self.candidate_radio_group.setExclusive(True)  # Ensure only one candidate can be selected

        # Container widget, button and layout for candidates' radio buttons
        self.candidate_radio_layout = QVBoxLayout()
        self.candidate_container = QWidget()
        self.candidate_container.setLayout(self.candidate_radio_layout)
        layout.addWidget(self.candidate_container)

        # Cast Vote Button
        self.cast_vote_button = QPushButton("Cast Vote")
        self.cast_vote_button.setEnabled(False)  # Initially disabled until voter verification
        self.cast_vote_button.clicked.connect(self.cast_vote)
        layout.addWidget(self.cast_vote_button)

        self.voting_tab.setLayout(layout)
    
    # Results Tab (Graphical Representation/for visualizing vote statistics)
    def init_results_tab(self):
        """Initialize the Results tab with bar and pie chart placeholders."""
        layout = QVBoxLayout()

        self.view_results_button = QPushButton("View Results")
        self.view_results_button.clicked.connect(self.display_results)
        layout.addWidget(self.view_results_button)

        self.results_tab.setLayout(layout)

    # Blockchain Validation Tab
    def init_blockchain_monitoring_tab(self):
        """Initialize the blockchain validation tab."""
        layout = QVBoxLayout()
    
        # Button to display the blockchain
        self.View_blockchain_button = QPushButton("View Blockchain")
        self.View_blockchain_button.clicked.connect(self.View_blockchain)
        layout.addWidget(self.View_blockchain_button)

        self.check_integrity_button = QPushButton("Check Blockchain Integrity")
        self.check_integrity_button.clicked.connect(self.check_blockchain_integrity)
        layout.addWidget(self.check_integrity_button)

        self.database_integrity_button = QPushButton("Check Database Integrity")
        self.database_integrity_button.clicked.connect(self.verify_database_integrity)
        layout.addWidget(self.database_integrity_button)

        self.blockchain_monitoring_tab.setLayout(layout)

    # Fingerprint sensor initialization with R307 module
    def initialize_fingerprint_sensor(self):
        if not hasattr(self, 'finger') or self.finger is None:
            try:
                self.uart = serial.Serial("COM5", baudrate=57600, timeout=1)  # Adjust COM port if needed
                self.finger = adafruit_fingerprint.Adafruit_Fingerprint(self.uart)
                logging.info("Fingerprint sensor initialized successfully.")
            except serial.SerialException as e:
                self.finger = None
                logging.error(f"Serial connection error: {e}")
                raise Exception("Fingerprint sensor not connected. Please connect the device and try again.")
            except Exception as e:
                self.finger = None
                logging.error(f"Failed to initialize fingerprint sensor: {e}")
                QMessageBox.critical(self, "Error", f"Failed to initialize fingerprint sensor: {e}")
                raise Exception (f"Failed to initialize fingerprint sensor: {e}")

    def check_sensor_connection(self):
        """Check if the fingerprint sensor is connected and initialized."""
        try:
            self.initialize_fingerprint_sensor()
            QMessageBox.information(self, "Sensor Connected", "Fingerprint sensor is connected and ready.")
        except Exception as e:
            retry = QMessageBox.question(
                self, "Sensor Error", 
                f"Sensor not connected: {e}\n\nDo you want to retry?", 
                QMessageBox.Yes | QMessageBox.No
            )
            if retry == QMessageBox.Yes:
                self.check_sensor_connection()
            QMessageBox.critical(self, "Sensor Error", f"Sensor not connected: {e}")

    def submit_voter_registration(self):
        """Register voters and enroll their fingerprint to the database only upon successful fingerprint enrollment."""
        voter_id = self.voter_id_input.text().strip()
        name = self.voter_name_input.text().strip()
        aadhaar_id = self.voter_aadhaar_id_input.text().strip()

        # Validation check
        if not voter_id or not name or not aadhaar_id:
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return

        try:
            # use a unique location for fingerprint storage based on the voter ID
            location = hash(voter_id) % 1000  # Generate  a unique integer location (limit to 1000 IDs)
            if self.enroll_finger(location): # Attemt to enroll fingerprint

                # Calculate hash for candidates
                data = f"{voter_id}{aadhaar_id}{name}{location}"
                record_hash = self.calculate_hash(data)

                cursor = self.conn.cursor()
                cursor.execute(
                    "INSERT INTO voters (voter_id, aadhaar_id, name, fingerprint_location, record_hash) VALUES (?, ?, ?, ?, ?)",
                    (voter_id, aadhaar_id, name, location, record_hash)
                )
                self.conn.commit()
                QMessageBox.information(self, "Success", "Voter registered successfully!")

                # Clear inputs if success
                self.voter_id_input.clear()
                self.voter_aadhaar_id_input.clear()
                self.voter_name_input.clear()
            else:
                QMessageBox.critical(self, "Error", "Fingerprint enrollment failed.")
                
        except sqlite3.IntegrityError as e:
            QMessageBox.critical(self, "Database Error", f"Database Error: {e}.")
            logging.error(f"IntegrityError: {e}")
            self.conn.rollback()
            # Clear inputs if fails
            self.voter_id_input.clear()
            self.voter_aadhaar_id_input.clear()
            self.voter_name_input.clear()
        except Exception as e:
            logging.error(f"Error registering voter: {e}")
            QMessageBox.critical(self, "Error", f"Failed to register voter: {e}")
            self.conn.rollback()
            # Clear inputs if fails
            self.voter_id_input.clear()
            self.voter_aadhaar_id_input.clear()
            self.voter_name_input.clear()

    def enroll_finger(self, location):
        """Enroll multiple fingerprint for a voter."""
        try:
            self.check_sensor_connection()  # Ensure the sensor is connected and then initialized.
            QMessageBox.information(self, "Enrollment", "Place your finger on the sensor...")

            # Capture first fingerprint
            while self.finger.get_image() != adafruit_fingerprint.OK:
                pass

            if self.finger.image_2_tz(1) != adafruit_fingerprint.OK:
                QMessageBox.warning(self, "Error", "Failed to process the first fingerprint scan.")
                logging.warning("Failed to process the first fingerprint scan.")
                return False

            # Promt user to remove their finger
            QMessageBox.information(self, "Enrollment", "Remove your finger...")
            time.sleep(0.5) # Add a small delay for clarity
            while self.finger.get_image() != adafruit_fingerprint.NOFINGER:
                pass

            # Capture second fingerprint
            QMessageBox.information(self, "Enrollment", "Place the same finger again...")
            while self.finger.get_image() != adafruit_fingerprint.OK:
                pass
            if self.finger.image_2_tz(2) != adafruit_fingerprint.OK:
                QMessageBox.warning(self, "Error", "Failed to process the second fingerprint scan.")
                logging.warning("Failed to process the second fingerprint scan.")
                return False

            # Create and store fingerprint model
            if self.finger.create_model() != adafruit_fingerprint.OK:
                QMessageBox.warning(self, "Error", "Failed to create fingerprint model.")
                logging.warning("Failed to create fingerprint model.")
                return False
            if self.finger.store_model(location) != adafruit_fingerprint.OK:
                QMessageBox.warning(self, "Error", "Failed to store fingerprint model.")
                logging.warning(f"Failed to store fingerprint model at location {location}.")
                return False

            QMessageBox.information(self, "Enrollment", "Fingerprint enrolled successfully!")
            logging.info(f"Fingerprint enrolled successfully at location {location}.")
            return True # Indicate successful capture
        except Exception as e:
            logging.error(f"Error during fingerprint enrollment: {e}")
            QMessageBox.critical(self, "Error", f"Failed to enroll fingerprint: {e}")
            return False

    def list_stored_templates(self):
        """List all stored fingerprint templates on the sensor."""
        try:
            templates = self.finger.read_templates()
            if templates:
                logging.info(f"Stored Templates: {templates}")
                QMessageBox.information(self, "Stored Templates", f"Stored Templates: {templates}")
            else:
                logging.warning("No templates found on the fingerprint sensor.")
                QMessageBox.information(self, "Stored Templates", "No templates found on the sensor.")
        except Exception as e:
            logging.error(f"Error reading stored templates: {e}")
            QMessageBox.critical(self, "Error", f"Failed to read stored templates: {e}")

    def submit_candidate_registration(self):
        """Submit candidate registration details to the database."""
        candidate_id = self.candidate_id_input.text().strip()
        candidate_name = self.candidate_name_input.text().strip()
        candidate_aadhaar_id = self.candidate_aadhaar_id_input.text().strip()
        candidate_party = self.candidate_party_input.text().strip()

        # Validation check
        if not candidate_id or not candidate_name or not candidate_aadhaar_id or not candidate_party:
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return

        try:
            # Calculate hash for candidates
            data = f"{candidate_id}{candidate_aadhaar_id}{candidate_name}{candidate_party}"
            record_hash = self.calculate_hash(data)

            # Insert data into database
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO candidates (candidate_id, aadhaar_id, name, party, record_hash) VALUES (?, ?, ?, ?, ?)",
                (candidate_id, candidate_aadhaar_id, candidate_name, candidate_party, record_hash)
            )
            self.conn.commit()
            logging.info(f"Candidate Registration: Candidate ID {self.candidate_id_input.text()} registered successfully.")
            QMessageBox.information(self, "Success", "Candidate registered successfully.")
        
            # Clear inputs if success
            self.candidate_id_input.clear()
            self.candidate_aadhaar_id_input.clear()
            self.candidate_name_input.clear()
            self.candidate_party_input.clear()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Database Error", "Candidate ID or Aadhaar ID already exists.")
            logging.error("Duplicate candidate ID or Aadhaar ID registration attempt.")
            self.conn.rollback()
            # Clear inputs if fails
            self.candidate_id_input.clear()
            self.candidate_aadhaar_id_input.clear()
            self.candidate_name_input.clear()
            self.candidate_party_input.clear()
        except Exception as e:
            logging.error(f"Failed to register candidate: {e}")
            QMessageBox.critical(self, "Error", f"Failed to register candidate: {e}")
            self.conn.rollback()
            # Clear inputs if fails
            self.candidate_id_input.clear()
            self.candidate_aadhaar_id_input.clear()
            self.candidate_name_input.clear()
            self.candidate_party_input.clear()

    def verify_voter(self):
        """Verify voter using fingerprint."""
        try:
            voter_id = self.voter_verification_input.text().strip()

            # Validate Voter ID
            if not voter_id:
                QMessageBox.warning(self, "Input Error", "Please enter a Voter ID for verification.")
                logging.warning("Voter verification failed: No Voter ID entered.")
                return

            self.initialize_fingerprint_sensor()  # Ensure the sensor is initialized

            # Check if voter ID exists in the database
            cursor = self.conn.cursor()
            cursor.execute("SELECT fingerprint_location FROM voters WHERE voter_id=?", (voter_id,))
            result = cursor.fetchone()

            if result is None:
                QMessageBox.critical(self, "Error", "Voter ID not found in the database.")
                logging.warning(f"Voter verification failed: Voter ID {voter_id} not found.")
                return

            # Extract fingerprint location
            location = result[0] if isinstance(result, tuple) else result
            logging.info(f"Voter ID {voter_id} validated. Proceeding to fingerprint verification.")

            # Procced to fingerprint verification
            QMessageBox.information(self, "Verification", "Place your finger on the sensor...")
            
            # Capture fingerprint image
            while self.finger.get_image() != adafruit_fingerprint.OK:
                pass

            # Convert fingerprint image to a template
            if self.finger.image_2_tz(1) != adafruit_fingerprint.OK:
                QMessageBox.warning(self, "Error", "Failed to process the fingerprint.")
                logging.warning("Failed to convert fingerprint image to template.")
                return

            # Perform fingerprint search and verify
            if self.finger.finger_search() == adafruit_fingerprint.OK and self.finger.finger_id == location:
                QMessageBox.information(self, "Verified", f"Voter verified successfully! Template ID: {location}")
                logging.info(f"Fingerprint matched successfully with Template ID: {location}")

                # Clear previous candidate and reload for new voter
                self.clear_candidate()
                self.load_candidate() # Populate candidates
                self.cast_vote_button.setEnabled(True) # Re-enable the cast vote button
            else:
                QMessageBox.critical(self, "Error", "Fingerprint does not match.")
                logging.warning("Fingerprint verification failed: No matching fingerprint found.")
                self.clear_candidate()
        except Exception as e:
            logging.error(f"Error during fingerprint verification: {e}")
            QMessageBox.critical(self, "Error", f"Failed to verify voter: {e}")
            self.clear_candidate()

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
        
        # Reset caste vote button
        self.cast_vote_button.setEnabled(False)

    def toggle_cast_vote_button(self):
        """Enable or disable the cast vote button based on candidate availability."""
        self.cast_vote_button.setEnabled(bool(self.candidate_radio_group.buttons()))

    def cast_vote(self):
        """Cast a vote for the selected candidate and add it to the blockchain."""
        try:
            # Use the verified voter ID from voter_verification_input
            voter_id = self.voter_verification_input.text().strip()
            if not voter_id:
                QMessageBox.warning(self, "Input Error", "No verified voter ID. Please verify first.")
                logging.warning("Vote casting failed: No verified voter ID.")
                return

            # Find the selected candidate
            selected_button = self.candidate_radio_group.checkedButton()
            if not selected_button:
                QMessageBox.warning(self, "Selection Error", "Please select a candidate to cast the vote.")
                logging.warning("Vote casting failed: No candidate selected.")
                return

            candidate_id = selected_button.candidate_id
            
            # Check for duplicate voting
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM votes WHERE voter_id = ?", (voter_id,))
            if cursor.fetchone():
                QMessageBox.critical(self, "Voting Error", "You have already cast your vote.")
                logging.warning(f"Vote casting failed: Duplicate vote attempt by Voter ID {voter_id}.")
                self.clear_candidate()
                self.cast_vote_button.setEnabled(False)
                return

            vote_data = {"voter_id": voter_id, "candidate_id": candidate_id}

            # Insert vote record into the blockchain
            new_block = self.blockchain.add_block(vote_data)
            if new_block is None:  # Check if block creation failed
                QMessageBox.critical(self, "Blockchain Error", "Failed to record vote on the blockchain.")
                logging.error("Failed to add vote to the blockchain.")
                return

            # Insert vote record into the database
            timestamp = str(datetime.datetime.now())

            # Calculate hash for votes
            data = f"{voter_id}{candidate_id}{timestamp}"
            record_hash = self.calculate_hash(data)

            cursor.execute("INSERT INTO votes (voter_id, candidate_id, timestamp, record_hash) VALUES (?, ?, ?, ?)",
                            (voter_id, candidate_id, timestamp, record_hash))
            self.conn.commit()

            QMessageBox.information(self, "Success", "Vote cast successfully and recorded in blockchain.")

            self.clear_candidate()
            self.cast_vote_button.setEnabled(False)  # Disable voting button
            self.voter_verification_input.clear()  # Clear voter ID input field
            self.candidate_radio_group.setExclusive(False)  # Temporarily disable exclusivity
            for button in self.candidate_radio_group.buttons():
                button.setChecked(False)  # Uncheck all radio buttons
            self.candidate_radio_group.setExclusive(True)  # Re-enable exclusivity

            logging.info(f"Vote Cast: Voter ID {voter_id} voted for Candidate ID {candidate_id}")

        except sqlite3.Error as db_error:
            logging.error(f"Database Error: {db_error}")
            QMessageBox.critical(self, "Database Error", "An error occurred while recording your vote. Please try again.")
            self.clear_candidate()
            self.conn.rollback()
        except Exception as e:
            logging.error(f"Unexpected Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to cast vote: {e}")
            self.clear_candidate()
            self.conn.rollback()
    
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

            # Open the ResultsPopup with the data
            self.results_panel = ResultsPanel(candidate_names, vote_counts)
            self.results_panel.show()

            logging.info("Results Viewed: Vote statistics displayed.")
        except Exception as e:
            logging.error(f"Results Display Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to display results: {e}")

    def View_blockchain(self):
        """Display the enitre blockchain in the seperate window (UI)."""
        try:
            blockchain_data = []
            for block in self.blockchain.chain:
                blockchain_data.append({
                    "Index": block.index,
                    "Timestamp": block.timestamp,
                    "Data": block.data,
                    "Hash": block.hash,
                    "Previous Hash": block.previous_hash,
                })
                
            # Display blockchain in a separate popup or table (as per UI design)
            self.blockchain_window = BlockchainPanel(blockchain_data)
            self.blockchain_window.show()
        except Exception as e:
            logging.error(f"Error displaying blockchain: {e}")
            QMessageBox.critical(self, "Error", f"Failed to display blockchain: {e}")

    def check_blockchain_integrity(self):
        """Check and display blockchain integrity."""
        try:
            if self.blockchain.is_chain_valid():
                QMessageBox.information(self, "Blockchain Integrity", "Blockchain integrity is valid. No tampering detected.")
                logging.info("Blockchain integrity validated successfully.")
            else:
                QMessageBox.critical(self, "Blockchain Integrity", "Blockchain integrity is compromised!")
                logging.warning("Blockchain integrity validation failed.")
        except Exception as e:
            logging.error(f"Blockchain Integrity Check Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to validate blockchain integrity: {e}")

    def verify_database_integrity(self):
        """Verify the integrity of database records."""
        try:
            cursor = self.conn.cursor()
            
            # Check voter records
            cursor.execute("SELECT voter_id, aadhaar_id, name, fingerprint_location, record_hash FROM voters")
            for row in cursor.fetchall():
                voter_id, aadhaar_id, name, location, record_hash = row
                data = f"{voter_id}{aadhaar_id}{name}{location}"
                if self.calculate_hash(data) != record_hash:
                    QMessageBox.critical(self, "Database Integrity", f"Data tampering detected for Voter ID {voter_id}, Aadhaar Id {aadhaar_id}, Name {name}.")
                    logging.warning(f"Database tampering detected for Voter ID {voter_id} and Aadhaar Id {aadhaar_id}, Name {name}.")
                    return

            # Check candidate records
            cursor.execute("SELECT candidate_id, aadhaar_id, name, party, record_hash FROM candidates")
            for row in cursor.fetchall():
                candidate_id, aadhaar_id, name, party, record_hash = row
                data = f"{candidate_id}{aadhaar_id}{name}{party}"
                if self.calculate_hash(data) != record_hash:
                    QMessageBox.critical(self, "Database Integrity", f"Data tampering detected for Candidate ID {candidate_id}, Aadhaar Id {aadhaar_id}, Name {name}, Party {party}.")
                    logging.warning(f"Database tampering detected for candidate ID {candidate_id} and Aadhaar Id {aadhaar_id}, Name {name}, Party {party}.")
                    return

            # Check votes records
            cursor.execute("SELECT voter_id, candidate_id, timestamp, record_hash FROM votes")
            for row in cursor.fetchall():
                voter_id, candidate_id, timestamp, record_hash = row
                data = f"{voter_id}{candidate_id}{timestamp}"
                if self.calculate_hash(data) != record_hash:
                    QMessageBox.critical(self, "Database Integrity", f"Data tampering detected for Candidate ID {candidate_id} and Voter Id {voter_id}.")
                    logging.warning(f"Database tampering detected for Candidate ID {candidate_id} and Voter ID {voter_id}.")
                    return

            QMessageBox.information(self, "Database Integrity", "Database integrity is intact.")
            logging.info("Database integrity validated successfully.")
        except Exception as e:
            logging.error(f"Database Integrity Check Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to verify database integrity: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    admin_panel = AdminPanel()
    admin_panel.show()
    sys.exit(app.exec())

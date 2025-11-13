# Blockchain-Based-Voting-System
This project is a Blockchain-Based Voting System designed to ensure the integrity, transparency, and security of the voting process using modern cryptographic techniques and biometric authentication. Key Features

Blockchain Integration: -> Ensures secure and immutable records of votes. -> Provides transparency and resistance to tampering.

Biometric Authentication: Voter and admin authentication using the R307 optical fingerprint reader for secure identity verification.

i-Cryptographic Security: -> RSA/ECC algorithms for digitally signing voter and candidate details. -> SHA-256/512 hashing for ensuring document and vote integrity.

ii-Comprehensive User Management: -> Voter registration includes Aadhaar ID, Voter ID, biometric fingerprint, photo, and signature, all securely stored. -> Candidate registration supports personal details, Aadhaar ID, Candidate ID, and party/group affiliation.

iii-Intuitive GUI: -> Developed using PySide6 and PySide6-designer for a user-friendly experience. -> Admin panel for managing elections, registering voters and candidates, and viewing election statistics.

iv-Data Validation: -> Aadhaar ID: 12-digit numerical format. -> Voter ID and Candidate ID: Alphanumeric format (6-10 characters). -> Other fields validated to ensure proper data entry.

v-Fingerprint Management: -> Integration of biometric devices for capturing and validating fingerprints. -> Fingerprint data stored as encrypted templates and verified during authentication.

vi-Admin Controls: -> Admin login using unique ID and fingerprint authentication. -> Ability to start/stop the voting process and view real-time election results.

Technologies Used

-> Programming Language: Python -> GUI Framework: PySide6 -> Database: SQLite -> Blockchain: (Implementation specific details here, e.g., Ethereum, Hyperledger, or custom blockchain logic) -> Biometric Device: R307 Optical Fingerprint Reader -> Cryptographic Tools: PyCrypto or similar libraries for RSA/ECC and SHA-256/512 -> Validation: QRegularExpressionValidator for input validation

Setup

i-Clone the repository: -> git clone

ii-Run the application: -> python demo.py

Biometric Setup

-> Ensure that the R307 fingerprint reader is connected via a USB-to-TTL UART converter (e.g., CP2102 module). -> Install the necessary drivers and libraries provided by the manufacturer. -> Update the code to ensure the correct COM port is configured.

Usage

i-Admin Panel: -> Admin logs in with their fingerprint and unique ID. -> Manage voters and candidates. -> Start/stop elections and view results.

ii-Voter Registration: -> Enter Aadhaar ID, Voter ID, Name, and capture a fingerprint. -> Register voters securely with cryptographic signing and data hashing.

iii-Voting Process: -> Voters log in with Aadhaar ID and fingerprint. -> Cast votes securely, recorded on the blockchain.

iv-Election Results: -> Admins can view and export the results securely.

8 .Future Enhancements

-> Integration with iris scanners for added security. -> Advanced analytics for election results. -> Cross-platform compatibility for distributed voting systems.

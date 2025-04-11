# Crypt+ - Secure and Expressive Data Access Control for Storage

Crypt+ is a comprehensive web-based platform that provides secure and expressive data access control for storage systems. It combines attribute-based encryption with flexible access control policies to ensure data confidentiality while enabling controlled sharing.

## Key Features

- **Attribute-Based Encryption**: Secure your data with advanced encryption techniques that ensure only authorized users with the right attributes can access your information.
- **Flexible Access Control**: Create expressive access control policies based on user attributes, roles, and context to ensure the right people have access to the right data.
- **Secure Key Management**: Robust key management service (KMS) for secure generation, storage, and distribution of encryption keys.
- **Policy Decision Point (PDP)**: Intelligent evaluation of access control policies based on user attributes and request context.
- **Policy Enforcement Point (PEP)**: Strict enforcement of access control decisions across all data operations.
- **Comprehensive Auditing**: Detailed logging of all access attempts, policy changes, and security-related operations.

## System Architecture

The Crypt+ system is built with a modular architecture consisting of several core components:

- **Authentication Services**: Secure user authentication and management.
- **Encryption Services**: Attribute-based encryption implementation for data protection.
- **Key Management Service (KMS)**: Secure management of encryption keys.
- **Policy Decision Point (PDP)**: Evaluation of access control policies.
- **Policy Enforcement Point (PEP)**: Enforcement of access control decisions.
- **Data Management**: Secure storage and retrieval of encrypted data.
- **Audit Services**: Comprehensive logging and monitoring.

## File Structure

```
crypt_plus/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── requirements.txt       # Dependencies
├── README.md              # Documentation
├── models/
│   ├── __init__.py
│   ├── user.py            # User model
│   ├── data.py            # Data model
│   └── policy.py          # Policy model
├── services/
│   ├── __init__.py
│   ├── encryption.py      # Encryption service
│   ├── key_management.py  # Key Management Service (KMS)
│   ├── policy_decision.py # Policy Decision Point (PDP)
│   └── policy_enforcement.py # Policy Enforcement Point (PEP)
├── controllers/
│   ├── __init__.py
│   ├── auth.py            # Authentication controller
│   ├── data.py            # Data management controller
│   └── policy.py          # Policy management controller
├── static/
│   ├── css/
│   │   └── main.css       # Styles
│   └── js/
│       └── main.js        # Frontend JavaScript
└── templates/
    ├── base.html          # Base template
    ├── login.html         # Login page
    ├── dashboard.html     # User dashboard
    ├── upload.html        # Data upload page
    └── policies.html      # Policy management page
```

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- SQLite (for development) or PostgreSQL (for production)
- Modern web browser

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/crypt-plus.git
   cd crypt-plus
   ```

2. Set up a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file with your configuration:
   ```
   SECRET_KEY=your-secret-key
   DATABASE_URI=sqlite:///crypt_plus.db
   ```

5. Initialize the database:
   ```
   python -c "from app import create_app; create_app().app_context().push()"
   ```

6. Run the application:
   ```
   python app.py
   ```

7. Access the application at `http://localhost:5000`

## Usage

1. **Register an Account**: Create a new user account with username, email, and password.
2. **Login**: Authenticate to access the system.
3. **Upload Files**: Upload files and optionally encrypt them with attribute-based encryption.
4. **Create Policies**: Define access control policies based on user attributes.
5. **Share Files**: Apply policies to files to enable secure sharing with other users.
6. **Manage Attributes**: Add or remove attributes from your user profile.
7. **Access Shared Files**: Access files shared with you based on your attributes.
8. **View Audit Logs**: Track all access activities for your files.

## Security Considerations

- **Key Security**: Private keys should be securely stored, preferably encrypted with the user's password or in a hardware security module.
- **Secure Deployment**: When deploying to production, use HTTPS and follow security best practices.
- **Regular Updates**: Keep all dependencies updated to address potential security vulnerabilities.
- **Backup Strategy**: Implement a secure backup strategy for the key store and database.

## Future Scope

The future scope of Crypt+ includes:

- Advanced encryption techniques compatible with post-quantum cryptography
- Dynamic policy adaptation based on context and risk assessment
- Integration with blockchain for immutable audit trails
- AI-enhanced security for anomaly detection
- Multi-cloud support for distributed storage environments
- Enhanced interoperability with standardized APIs
- User-centric access control with simplified interfaces

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- This project implements concepts from attribute-based encryption research
- Security architecture inspired by NIST recommendations for access control
- UI design leverages Bootstrap framework for responsive design



admin user-admin


password-SecurePassword123




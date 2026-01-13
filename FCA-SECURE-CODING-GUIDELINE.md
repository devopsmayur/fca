# FCA Secure Coding Guidelines for UK Financial Services Applications

> **Classification**: MANDATORY | **Compliance**: FCA Handbook (SYSC, PRIN, COBS)  
> **Scope**: All code for FCA-regulated firms and financial services applications  
> **Enforcement**: Code reviews MUST reject non-compliant code

---

## 1. CRITICAL: Prohibited Patterns - IMMEDIATE REJECTION

### 1.1 Hardcoded Credentials and Secrets

**REJECT any code containing hardcoded:**
- Database passwords or connection strings with credentials
- API keys (patterns: `api_key`, `apikey`, `API_KEY`)
- Encryption keys or secrets
- JWT secrets or tokens
- Authentication credentials
- Third-party service credentials (AWS, Azure, GCP)
- Payment gateway credentials
- Banking API credentials (Open Banking, SWIFT)

**Detection Patterns:**
```
password = "..."
PASSWORD = "..."
api_key = "..."
secret_key = "..."
encryption_key = "..."
JWT_SECRET = "..."
DB_CONFIG = {..., "password": "..."}
SWIFT_KEY = "..."
OPEN_BANKING_SECRET = "..."
```

**FCA Reference**: SYSC 3.2.6R, SYSC 4.1, SYSC 13 (IT security and operational risk)

---

### 1.2 Sensitive Data Logging and Exposure

**REJECT any logging, printing, console output, or error messages containing:**
- Customer personal identifiable information (PII)
- Financial account numbers (bank accounts, sort codes, IBANs)
- Card payment details (PAN, CVV, expiry dates)
- Customer financial positions or transaction details
- Authentication credentials or session tokens
- Passwords (plaintext or hashed)
- National Insurance numbers
- Passport/driving license numbers
- Customer vulnerabilities or protected characteristics

**Detection Patterns:**
```python
# REJECT these patterns:
logger.info(f"Account Number: {account_number}")
logger.debug(f"Customer balance: {balance}")
print(f"Card details: {card_data}")
console.log(`NI Number: ${ni_number}`)
logger.info(f"User password: {password}")
print(f"Customer vulnerability: {vulnerability_flag}")
logger.error(f"Transaction failed for account {iban}")
```

**FCA Reference**: 
- PRIN 8 (Treating customers fairly)
- SYSC 3.2.6R (Data security)
- UK GDPR Article 5 (Data processing principles)
- Consumer Duty Outcome 2 (Consumer understanding)

---

### 1.3 Prohibited Data Storage and Retention

**REJECT code that stores sensitive data without proper protection:**
- Unencrypted customer PII in databases
- Unencrypted financial data
- Customer data beyond regulatory retention periods
- Customer vulnerabilities without proper controls
- Plaintext passwords or authentication tokens
- CVV/CVC after authorization
- Full card details without PCI-DSS compliance

**Detection Patterns:**
```python
# REJECT: Storing sensitive data unencrypted
INSERT INTO customers (name, account_number, balance) VALUES ...
# Without encryption at rest

# REJECT: No data retention policy
CREATE TABLE customer_data (
    created_date TIMESTAMP,
    -- Missing: retention_until, deletion_date
)

# REJECT: Storing CVV post-authorization
cvv_encrypted = encrypt(cvv)
db.store(cvv_encrypted)  # CVV must not be stored

# REJECT: Plaintext password storage
user.password = password
db.save(user)
```

**FCA Reference**: 
- SYSC 9 (Record keeping)
- UK GDPR Article 5(1)(e) (Storage limitation)
- Consumer Duty Principle 12

---

## 2. SQL Injection Prevention (SYSC 3.2.6R Compliance)

### 2.1 Prohibited SQL Patterns

**REJECT any SQL query using:**
- String concatenation with user input
- f-strings with user input
- `.format()` with user input
- `%` formatting with user input
- Dynamic SQL without parameterization

**Detection Patterns to REJECT:**
```python
# REJECT: String concatenation
query = "SELECT * FROM accounts WHERE customer_id = '" + customer_id + "'"

# REJECT: f-string interpolation
query = f"SELECT balance FROM accounts WHERE iban = '{iban}'"

# REJECT: .format() method
query = "SELECT * FROM transactions WHERE id = '{}'".format(txn_id)

# REJECT: % formatting
query = "SELECT * FROM customers WHERE email = '%s'" % email

# REJECT: Dynamic WHERE clause construction
for key, value in filters.items():
    where_clauses.append(f"{key} = '{value}'")
query = "SELECT * FROM accounts WHERE " + " AND ".join(where_clauses)
```

### 2.2 Required SQL Patterns

**REQUIRE parameterized queries:**
```python
# CORRECT: Parameterized query
cursor.execute("SELECT * FROM accounts WHERE customer_id = ?", (customer_id,))

# CORRECT: Named parameters
cursor.execute(
    "SELECT balance FROM accounts WHERE iban = :iban", 
    {"iban": iban}
)

# CORRECT: ORM with safe query builders
Account.objects.filter(customer_id=customer_id)
```

**FCA Reference**: SYSC 3.2.6R (IT security controls), SYSC 4.1 (Risk management)

---

## 3. Cryptographic Requirements (SYSC 13 Compliance)

### 3.1 Prohibited Algorithms - REJECT

**REJECT usage of weak or deprecated cryptographic algorithms:**
- `MD5` - for any purpose
- `SHA-1` / `sha1` - for cryptographic operations
- `DES` - deprecated encryption
- `3DES` / `Triple DES` - deprecated
- `RC4` - broken cipher
- `ECB` mode - insecure block cipher mode
- `Blowfish` with key < 256 bits
- Weak key sizes (RSA < 2048, ECC < 256)

**Detection Patterns:**
```python
# REJECT: MD5 usage
hashlib.md5(data.encode())
hashlib.md5(customer_id).hexdigest()

# REJECT: SHA-1 usage
hashlib.sha1(account_number.encode())

# REJECT: DES encryption
from Crypto.Cipher import DES
DES.new(key, DES.MODE_ECB)

# REJECT: ECB mode
AES.new(key, AES.MODE_ECB)

# REJECT: Weak RSA key
rsa_key = RSA.generate(1024)  # Too weak
```

### 3.2 Required Algorithms

**REQUIRE strong, industry-standard cryptography:**
- `AES-256` with `GCM` or `CBC` mode (with proper IV)
- `SHA-256` or stronger for hashing
- `bcrypt` (cost >= 12) or `Argon2id` for passwords
- `RSA-2048` minimum (RSA-4096 preferred) for asymmetric encryption
- `ECDSA` with P-256 or stronger curves
- Cryptographically secure random: `secrets`, `os.urandom`, `crypto.getRandomValues()`

**Required Patterns:**
```python
# CORRECT: AES-256 with GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
cipher = AESGCM(key)  # 256-bit key
encrypted = cipher.encrypt(nonce, plaintext, associated_data)

# CORRECT: bcrypt for passwords
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# CORRECT: Secure random generation
import secrets
token = secrets.token_urlsafe(32)
```

**FCA Reference**: SYSC 13.6 (Technology and security), SYSC 3.2.6R

---

### 3.3 Weak Random Number Generation

**REJECT for security purposes:**
```python
# REJECT: Predictable random
random.randint(...)
random.random()
random.choice(...)
Math.random()  # JavaScript

# REJECT: Time-based seeding
random.seed(time.time())
random.seed(datetime.now())

# REJECT: Predictable token generation
str(random.randint(100000, 999999))
hashlib.md5(f"{data}{datetime.now()}").hexdigest()
```

**REQUIRE:**
```python
# CORRECT: Cryptographically secure
import secrets
token = secrets.token_urlsafe(32)
otp = secrets.randbelow(1000000)

import os
random_bytes = os.urandom(32)

# JavaScript
crypto.getRandomValues(new Uint8Array(32))
```

---

## 4. Authentication and Session Security (SYSC 3.2.6R, COBS)

### 4.1 Password Storage

**REJECT:**
```python
# REJECT: MD5/SHA hashing for passwords
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()

# REJECT: No salt
hash(password)

# REJECT: Reversible encryption
encrypted_password = encrypt(password)  # Passwords must be hashed, not encrypted
```

**REQUIRE:**
```python
# CORRECT: bcrypt with appropriate cost
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# CORRECT: Argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
```

### 4.2 Session Management

**REJECT:**
```python
# REJECT: Weak session ID
session_id = str(random.randint(100000000, 999999999))
session_id = hashlib.md5(username.encode()).hexdigest()

# REJECT: Long session expiry for financial operations
expires_at = datetime.now() + timedelta(days=30)
SESSION_TIMEOUT = 86400  # 24 hours too long for banking

# REJECT: Session ID in URL
return redirect(f"/dashboard?session={session_id}")

# REJECT: Session fixation vulnerability
if not session.get('id'):
    session['id'] = request.args.get('session_id')  # User-provided
```

**REQUIRE:**
```python
# CORRECT: Cryptographically secure session ID
session_id = secrets.token_urlsafe(32)

# CORRECT: Appropriate timeout for financial services
# High-value operations: 5-15 minutes
# Standard operations: 15-30 minutes
SESSION_TIMEOUT = 900  # 15 minutes

# CORRECT: Regenerate session on authentication
def login(username, password):
    # ... verify credentials ...
    session.clear()
    session.regenerate_id()
    session['user_id'] = user.id
```

**FCA Reference**: SYSC 3.2.6R, COBS 2.1 (Client best interests)

---

## 5. Network Security and TLS (SYSC 13.6)

### 5.1 Transport Layer Security

**REJECT:**
```python
# REJECT: HTTP for any financial data
url = "http://api.bank.example.com"
requests.post("http://payment-gateway.example.com", data=payment_data)

# REJECT: Disabled SSL verification
requests.post(url, verify=False)
requests.post(url, verify=None)
urllib.request.urlopen(url, context=ssl._create_unverified_context())

# REJECT: Weak TLS versions
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS 1.0 deprecated
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)  # TLS 1.1 deprecated

# REJECT: Weak cipher suites
ssl_context.set_ciphers('DES-CBC3-SHA')
```

**REQUIRE:**
```python
# CORRECT: HTTPS only with TLS 1.2+
url = "https://api.bank.example.com"
requests.post(url, verify=True)

# CORRECT: Enforce strong TLS
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS')

# CORRECT: Certificate pinning for critical APIs
requests.post(url, verify='/path/to/trusted-cert.pem')
```

**FCA Reference**: SYSC 13.6 (IT security), SYSC 8 (Outsourcing)

---

## 6. Input Validation and Data Sanitization (SYSC 3.2.6R)

### 6.1 Financial Data Validation

**REJECT:**
```python
# REJECT: No validation of financial amounts
amount = request.get("amount")
process_payment(amount)  # No validation

# REJECT: Client-side only validation
# HTML: <input type="number" min="0" max="10000">
# Backend accepts any value without validation

# REJECT: Insufficient account number validation
def validate_account(account_number):
    return len(account_number) == 8  # Only length check

# REJECT: No input sanitization
customer_name = request.get("name")
db.execute(f"INSERT INTO customers (name) VALUES ('{customer_name}')")
```

**REQUIRE:**
```python
# CORRECT: Comprehensive validation
def validate_payment_amount(amount):
    """Validate payment amount per FCA requirements"""
    try:
        amount_decimal = Decimal(amount)
    except (ValueError, InvalidOperation):
        raise ValidationError("Invalid amount format")
    
    if amount_decimal <= 0:
        raise ValidationError("Amount must be positive")
    
    if amount_decimal > Decimal('1000000'):  # Business rule
        raise ValidationError("Amount exceeds limit")
    
    # Check decimal places (max 2 for GBP)
    if amount_decimal.as_tuple().exponent < -2:
        raise ValidationError("Invalid decimal precision")
    
    return amount_decimal

# CORRECT: Account number validation with checksum
def validate_uk_account(sort_code, account_number):
    """Validate UK bank account with modulus check"""
    # Remove spaces and validate format
    sort_code = ''.join(sort_code.split())
    account_number = ''.join(account_number.split())
    
    if not (re.match(r'^\d{6}$', sort_code) and 
            re.match(r'^\d{8}$', account_number)):
        return False
    
    # Perform modulus 11 check
    return perform_modulus_check(sort_code, account_number)

# CORRECT: Input sanitization
from bleach import clean
customer_name = clean(request.get("name"), strip=True)
```

### 6.2 IBAN Validation

**REQUIRE:**
```python
# CORRECT: Full IBAN validation
def validate_iban(iban):
    """Validate IBAN per ISO 13616"""
    iban = iban.replace(' ', '').upper()
    
    # Check length
    if not 15 <= len(iban) <= 34:
        return False
    
    # Check format
    if not re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]+$', iban):
        return False
    
    # Check country code
    country_code = iban[:2]
    expected_length = IBAN_LENGTHS.get(country_code)
    if not expected_length or len(iban) != expected_length:
        return False
    
    # Modulus 97 check
    reordered = iban[4:] + iban[:4]
    numeric = ''.join(str(int(c, 36)) for c in reordered)
    return int(numeric) % 97 == 1
```

**FCA Reference**: SYSC 3.2.6R (Risk management), COBS 2.1

---

## 7. Error Handling and Information Disclosure (SYSC 3.2.6R)

### 7.1 Prohibited Error Responses

**REJECT error responses containing:**
- Customer account numbers or financial details
- SQL queries or database structure
- Stack traces in production
- Internal system paths or server details
- Authentication credentials
- Detailed error messages that aid attackers
- User enumeration information

**Detection Patterns:**
```python
# REJECT: Exposing account details
return {"error": f"Insufficient funds in account {account_number}"}

# REJECT: Exposing SQL
try:
    cursor.execute(query)
except Exception as e:
    return {"error": str(e), "query": query}

# REJECT: Stack trace in production
@app.errorhandler(500)
def handle_error(e):
    return {"error": traceback.format_exc()}  # NEVER in production

# REJECT: User enumeration
def login(username, password):
    user = db.get_user(username)
    if not user:
        return {"error": "Username not found"}  # Reveals valid usernames
    if not verify_password(user, password):
        return {"error": "Invalid password"}  # Reveals username exists

# REJECT: Exposing internal details
return {
    "error": "Database connection failed",
    "host": "db.internal.bank.com",
    "port": 5432
}
```

### 7.2 Required Error Handling

**REQUIRE:**
```python
# CORRECT: Generic error messages for production
return {
    "error": "Payment processing failed",
    "reference": generate_error_reference(),  # For support tracking
    "message": "Please contact customer support"
}

# CORRECT: Detailed logging (server-side only)
logger.error(
    "Payment failed",
    extra={
        "customer_id": customer_id,
        "account": account_number,
        "amount": amount,
        "error": str(e),
        "traceback": traceback.format_exc()
    }
)

# CORRECT: Prevent user enumeration
def login(username, password):
    user = db.get_user(username)
    
    # Use constant-time comparison
    if not user or not verify_password_constant_time(user, password):
        # Same error for both invalid username and password
        time.sleep(random.uniform(0.1, 0.3))  # Timing attack mitigation
        return {"error": "Invalid credentials"}
    
    return {"success": True, "session": create_session(user)}

# CORRECT: Environment-aware error responses
if app.config['DEBUG']:
    # Detailed errors in development only
    error_response = {"error": str(e), "traceback": traceback.format_exc()}
else:
    # Generic errors in production
    error_response = {"error": "An error occurred", "reference": error_ref}
```

**FCA Reference**: SYSC 3.2.6R (Security controls), PRIN 11 (Consumer Duty)

---

## 8. Access Control and Authorization (SYSC 4.1, SYSC 5)

### 8.1 Authorization Checks Required

**REJECT functions without authorization:**
```python
# REJECT: No auth check on sensitive operations
def get_customer_accounts(customer_id):
    # Missing: verify requester can access this customer's data
    return db.query(f"SELECT * FROM accounts WHERE customer_id = {customer_id}")

# REJECT: IDOR (Insecure Direct Object Reference) vulnerability
@app.route('/api/account/<account_id>')
def get_account(account_id):
    # No verification that requester owns this account
    return db.get_account(account_id)

# REJECT: No authorization on financial operations
def transfer_funds(from_account, to_account, amount):
    # Missing: verify requester authorized to transfer from from_account
    # Missing: verify transfer limits
    # Missing: verify account status
    db.transfer(from_account, to_account, amount)

# REJECT: No auth on sensitive data export
def export_customer_data(customer_id):
    # Missing: verify requester has right to export this data
    # Missing: log access for audit trail
    return db.get_all_customer_data(customer_id)
```

### 8.2 Required Authorization Patterns

**REQUIRE:**
```python
# CORRECT: Comprehensive authorization
@require_authentication
def get_customer_accounts(customer_id):
    # Verify requester is the customer or authorized staff
    if not (current_user.id == customer_id or 
            current_user.has_permission('view_customer_accounts')):
        audit_log.log_unauthorized_access(
            user=current_user.id,
            attempted_action='view_accounts',
            target_customer=customer_id
        )
        raise UnauthorizedError("Insufficient permissions")
    
    # Log authorized access
    audit_log.log_access(
        user=current_user.id,
        action='view_accounts',
        customer=customer_id
    )
    
    return db.query_accounts(customer_id)

# CORRECT: Object-level authorization
@app.route('/api/account/<account_id>')
@require_authentication
def get_account(account_id):
    account = db.get_account(account_id)
    
    if not account:
        return {"error": "Not found"}, 404
    
    # Verify ownership
    if account.customer_id != current_user.customer_id:
        if not current_user.has_permission('view_any_account'):
            audit_log.log_unauthorized_access(
                user=current_user.id,
                action='view_account',
                account_id=account_id
            )
            return {"error": "Unauthorized"}, 403
    
    return account.to_safe_dict()  # Excludes sensitive internal fields

# CORRECT: Multi-layer authorization for transfers
@require_authentication
@require_mfa_verification
def transfer_funds(from_account, to_account, amount):
    # 1. Verify account ownership
    account = db.get_account(from_account)
    if account.customer_id != current_user.customer_id:
        raise UnauthorizedError("Not your account")
    
    # 2. Verify account status
    if account.status != 'ACTIVE':
        raise ValidationError("Account not active")
    
    # 3. Verify transfer limits
    if amount > account.daily_transfer_limit:
        raise ValidationError("Exceeds daily limit")
    
    # 4. Check for suspicious activity
    if fraud_detection.is_suspicious(current_user, from_account, to_account, amount):
        fraud_alert.trigger(current_user, from_account, to_account, amount)
        raise SecurityError("Transfer blocked for review")
    
    # 5. Execute transfer with audit trail
    transaction_id = db.transfer(
        from_account=from_account,
        to_account=to_account,
        amount=amount,
        initiated_by=current_user.id,
        ip_address=request.remote_addr,
        device_fingerprint=request.headers.get('X-Device-ID')
    )
    
    # 6. Log for regulatory reporting
    audit_log.log_transaction(
        transaction_id=transaction_id,
        type='TRANSFER',
        amount=amount,
        user=current_user.id
    )
    
    return {"transaction_id": transaction_id}
```

**FCA Reference**: 
- SYSC 4.1 (Governance)
- SYSC 5 (Senior management arrangements)
- SYSC 6.1 (Compliance)

---

## 9. Dangerous Functions and Code Execution (SYSC 3.2.6R)

### 9.1 Code Execution - IMMEDIATE REJECTION

**REJECT any usage of:**
```python
# REJECT: eval with any input
eval(request.get("expression"))
eval(user_formula)

# REJECT: exec with any input
exec(request.get("code"))
exec(code_string)

# REJECT: Command injection
import subprocess
subprocess.run(user_command, shell=True)  # NEVER use shell=True with user input
subprocess.Popen(command, shell=True)
os.system(user_input)

# REJECT: Unsafe code compilation
compile(user_code, '<string>', 'exec')

# JavaScript
# REJECT: eval
eval(userInput)
new Function(userCode)()
```

### 9.2 Unsafe Deserialization

**REJECT:**
```python
# REJECT: Pickle with untrusted data
import pickle
pickle.load(file)  # If file source is user-controlled
pickle.loads(request.data)

# REJECT: YAML unsafe load
import yaml
yaml.load(user_data)  # Without Loader=SafeLoader

# REJECT: PHP unserialize
unserialize($user_input)
```

**REQUIRE:**
```python
# CORRECT: Safe deserialization
import json
data = json.loads(user_input)  # JSON is safe

# CORRECT: Safe YAML
import yaml
data = yaml.safe_load(user_input)

# CORRECT: If pickle needed, sign and verify
import hmac
import hashlib
signature = hmac.new(secret_key, pickle_data, hashlib.sha256).hexdigest()
# Only unpickle if signature verifies
```

### 9.3 Path Traversal Prevention

**REJECT:**
```python
# REJECT: Unvalidated file paths
file_path = os.path.join(base_dir, request.get('filename'))
open(file_path, 'r')

# REJECT: User-controlled file operations
filename = request.get('file')
open(f"/var/reports/{filename}", 'r')
```

**REQUIRE:**
```python
# CORRECT: Validate and sanitize file paths
import pathlib

def safe_file_access(base_dir, requested_file):
    # Resolve to absolute path and check it's within base_dir
    base_path = pathlib.Path(base_dir).resolve()
    requested_path = (base_path / requested_file).resolve()
    
    if not str(requested_path).startswith(str(base_path)):
        raise SecurityError("Path traversal detected")
    
    # Additional validation
    if '..' in requested_file or requested_file.startswith('/'):
        raise ValidationError("Invalid filename")
    
    # Whitelist allowed extensions
    allowed_extensions = {'.pdf', '.csv', '.xlsx'}
    if requested_path.suffix not in allowed_extensions:
        raise ValidationError("File type not allowed")
    
    return requested_path
```

**FCA Reference**: SYSC 3.2.6R (IT security controls), SYSC 13.6

---

## 10. Data Protection and GDPR Compliance (UK GDPR, DPA 2018)

### 10.1 Personal Data Processing

**REJECT code that:**
```python
# REJECT: Processing without lawful basis
def collect_customer_data(customer):
    # Missing: lawful basis check
    # Missing: consent verification if required
    db.store_customer_data(customer)

# REJECT: No purpose limitation
def share_customer_data(customer_id, third_party):
    # Missing: verify data sharing is for legitimate purpose
    # Missing: data minimization
    third_party_api.send(db.get_all_customer_data(customer_id))

# REJECT: No data retention policy
def store_transaction(transaction):
    # Missing: retention period
    # Missing: automated deletion mechanism
    db.save(transaction)  # Stored indefinitely

# REJECT: Processing special category data without safeguards
def store_vulnerability_data(customer_id, vulnerability):
    # Missing: explicit consent
    # Missing: additional security measures
    db.customers.update(customer_id, {'vulnerability': vulnerability})
```

### 10.2 Required Data Protection Patterns

**REQUIRE:**
```python
# CORRECT: Lawful basis and consent management
def process_customer_data(customer_id, purpose, data):
    """Process customer data with GDPR compliance"""
    # 1. Check lawful basis
    lawful_basis = check_lawful_basis(customer_id, purpose)
    if not lawful_basis:
        raise GDPRError("No lawful basis for processing")
    
    # 2. Check consent if required
    if lawful_basis == 'CONSENT':
        consent = get_consent(customer_id, purpose)
        if not consent or not consent.is_valid():
            raise GDPRError("Valid consent required")
    
    # 3. Data minimization
    minimal_data = minimize_data(data, purpose)
    
    # 4. Log processing
    gdpr_audit_log.log(
        customer_id=customer_id,
        purpose=purpose,
        lawful_basis=lawful_basis,
        data_categories=get_data_categories(minimal_data)
    )
    
    return db.process(minimal_data)

# CORRECT: Data retention and deletion
def store_transaction(transaction):
    """Store transaction with retention policy"""
    retention_period = get_retention_period(transaction.type)
    deletion_date = datetime.now() + retention_period
    
    transaction.deletion_scheduled_date = deletion_date
    db.save(transaction)
    
    # Schedule automated deletion
    deletion_queue.schedule(transaction.id, deletion_date)

# CORRECT: Special category data handling
@require_explicit_consent(purpose='vulnerability_support')
def store_vulnerability_data(customer_id, vulnerability_info):
    """Store customer vulnerability with enhanced protections"""
    # 1. Verify explicit consent
    consent = consent_manager.get_consent(
        customer_id, 
        'special_category_vulnerability'
    )
    if not consent or not consent.is_explicit():
        raise GDPRError("Explicit consent required for special category data")
    
    # 2. Encrypt special category data
    encrypted_vulnerability = encrypt_special_category_data(vulnerability_info)
    
    # 3. Enhanced access controls
    db.customers.update(
        customer_id,
        {
            'vulnerability_encrypted': encrypted_vulnerability,
            'vulnerability_stored_date': datetime.now(),
            'access_restricted': True,
            'requires_justification': True
        }
    )
    
    # 4. Log access
    gdpr_audit_log.log_special_category_processing(
        customer_id=customer_id,
        category='vulnerability',
        purpose='customer_support',
        consent_id=consent.id
    )
```

### 10.3 Data Subject Rights

**REQUIRE implementation of:**
```python
# CORRECT: Right to access (DSAR)
def handle_data_subject_access_request(customer_id):
    """Handle customer data access request (GDPR Article 15)"""
    # 1. Verify identity
    if not verify_customer_identity(customer_id):
        raise SecurityError("Identity verification required")
    
    # 2. Collect all personal data
    customer_data = {
        'basic_info': db.customers.get(customer_id),
        'accounts': db.accounts.get_by_customer(customer_id),
        'transactions': db.transactions.get_by_customer(customer_id),
        'communications': db.communications.get_by_customer(customer_id),
        'consents': consent_manager.get_all_consents(customer_id),
        'processing_activities': gdpr_audit_log.get_activities(customer_id)
    }
    
    # 3. Redact third-party data
    redacted_data = redact_third_party_info(customer_data)
    
    # 4. Log DSAR
    gdpr_audit_log.log_dsar(customer_id)
    
    # 5. Provide in machine-readable format
    return generate_dsar_response(redacted_data)

# CORRECT: Right to erasure
def handle_right_to_erasure(customer_id, reason):
    """Handle right to be forgotten (GDPR Article 17)"""
    # 1. Verify identity
    if not verify_customer_identity(customer_id):
        raise SecurityError("Identity verification required")
    
    # 2. Check if erasure is legally possible
    if not can_erase_data(customer_id, reason):
        return {
            "erasure_possible": False,
            "reason": get_retention_reason(customer_id)
        }
    
    # 3. Anonymize or delete data
    erasure_result = {
        'customers': anonymize_customer_record(customer_id),
        'accounts': anonymize_account_records(customer_id),
        'transactions': anonymize_transactions(customer_id),
        'communications': delete_communications(customer_id),
        'consents': revoke_all_consents(customer_id)
    }
    
    # 4. Notify third parties
    notify_third_parties_of_erasure(customer_id)
    
    # 5. Log erasure
    gdpr_audit_log.log_erasure(customer_id, reason, erasure_result)
    
    return {"erasure_completed": True, "details": erasure_result}
```

**FCA Reference**: 
- UK GDPR Articles 5, 6, 9, 15, 17
- DPA 2018
- SYSC 3.2.6R (Data security)
- Consumer Duty cross-cutting rules

---

## 11. Operational Resilience (SYSC 15A - PS21/3)

### 11.1 Important Business Services Identification

**REQUIRE:**
```python
# CORRECT: Identifying and protecting important business services
class ImportantBusinessService:
    """
    Model for FCA Important Business Services (SYSC 15A.2.1R)
    """
    def __init__(self, name, impact_tolerance, mapping):
        self.name = name
        self.impact_tolerance = impact_tolerance  # Max tolerable disruption
        self.supporting_resources = mapping
        self.last_tested = None
        self.test_results = []
    
    def test_resilience(self, scenario):
        """Test resilience against severe but plausible disruption"""
        test_result = {
            'scenario': scenario,
            'timestamp': datetime.now(),
            'within_tolerance': None,
            'recovery_time': None,
            'issues_identified': []
        }
        
        # Simulate disruption and measure recovery
        start_time = time.time()
        disruption_result = simulate_disruption(self.name, scenario)
        recovery_time = time.time() - start_time
        
        test_result['recovery_time'] = recovery_time
        test_result['within_tolerance'] = recovery_time <= self.impact_tolerance
        test_result['issues_identified'] = disruption_result.issues
        
        self.test_results.append(test_result)
        self.last_tested = datetime.now()
        
        if not test_result['within_tolerance']:
            # Trigger remediation process
            self.trigger_remediation(test_result)
        
        return test_result
    
    def trigger_remediation(self, test_result):
        """Create and track remediation plan (SYSC 15A.5.1R)"""
        remediation_plan = {
            'service': self.name,
            'issues': test_result['issues_identified'],
            'actions': self.identify_remediation_actions(test_result),
            'owner': self.get_responsible_senior_manager(),
            'deadline': datetime.now() + timedelta(days=90),
            'status': 'IN_PROGRESS'
        }
        
        # Log for board reporting
        operational_resilience_log.log_remediation(remediation_plan)
        
        return remediation_plan

# CORRECT: Mapping dependencies (SYSC 15A.4.1R)
def map_service_dependencies(service_name):
    """Map all resources supporting an important business service"""
    mapping = {
        'people': identify_critical_staff(service_name),
        'processes': identify_critical_processes(service_name),
        'technology': identify_critical_systems(service_name),
        'facilities': identify_critical_facilities(service_name),
        'data': identify_critical_data(service_name),
        'third_parties': identify_critical_third_parties(service_name)
    }
    
    # Identify single points of failure
    single_points_of_failure = identify_single_points_of_failure(mapping)
    
    # Document for FCA reporting
    document_mapping(service_name, mapping, single_points_of_failure)
    
    return mapping
```

### 11.2 Incident Management and Reporting

**REQUIRE:**
```python
# CORRECT: Operational incident handling
class OperationalIncident:
    """Handle operational incidents per FCA requirements"""
    
    def __init__(self, incident_type, severity, affected_services):
        self.id = generate_incident_id()
        self.type = incident_type
        self.severity = severity
        self.affected_services = affected_services
        self.start_time = datetime.now()
        self.status = 'ACTIVE'
        self.communications = []
    
    def assess_impact(self):
        """Assess if incident breaches impact tolerances"""
        for service in self.affected_services:
            ibs = get_important_business_service(service)
            disruption_duration = datetime.now() - self.start_time
            
            if disruption_duration > ibs.impact_tolerance:
                # Breach detected
                self.escalate_to_senior_management()
                self.notify_fca_if_required()
    
    def notify_fca_if_required(self):
        """Notify FCA of material incidents"""
        # Determine if notification required based on:
        # - Impact tolerance breach
        # - Number of customers affected
        # - Duration of disruption
        # - Potential harm to customers
        
        if self.requires_fca_notification():
            notification = {
                'incident_id': self.id,
                'firm_reference': FCA_FIRM_REFERENCE,
                'incident_type': self.type,
                'start_time': self.start_time,
                'affected_services': self.affected_services,
                'customers_affected': self.count_affected_customers(),
                'impact_assessment': self.assess_customer_harm(),
                'remediation_status': self.get_remediation_status()
            }
            
            fca_reporting.submit_incident_notification(notification)
            self.communications.append({
                'type': 'FCA_NOTIFICATION',
                'timestamp': datetime.now(),
                'details': notification
            })
    
    def requires_fca_notification(self):
        """Determine if FCA notification required"""
        # Material incidents requiring notification
        return (
            self.severity in ['CRITICAL', 'HIGH'] or
            self.count_affected_customers() > 10000 or
            self.has_breach_impact_tolerance() or
            self.poses_systemic_risk()
        )
```

**FCA Reference**: 
- SYSC 15A (Operational resilience)
- PS21/3 (Building operational resilience)
- SUP 15 (Notifications to FCA)

---

## 12. Financial Crime Prevention (SYSC 6.3, FCG)

### 12.1 Anti-Money Laundering Controls

**REQUIRE:**
```python
# CORRECT: Transaction monitoring for AML
class AMLMonitoring:
    """Anti-Money Laundering transaction monitoring"""
    
    def monitor_transaction(self, transaction):
        """Monitor transaction for suspicious activity (SYSC 6.3.1R)"""
        risk_score = 0
        red_flags = []
        
        # 1. Check transaction amount thresholds
        if transaction.amount > AML_THRESHOLD_HIGH:
            risk_score += 30
            red_flags.append('HIGH_VALUE_TRANSACTION')
        
        # 2. Check transaction patterns
        if self.is_unusual_pattern(transaction):
            risk_score += 25
            red_flags.append('UNUSUAL_PATTERN')
        
        # 3. Check customer risk profile
        customer_risk = self.get_customer_risk_rating(transaction.customer_id)
        risk_score += customer_risk
        
        # 4. Check geographical risk
        if self.is_high_risk_jurisdiction(transaction):
            risk_score += 20
            red_flags.append('HIGH_RISK_JURISDICTION')
        
        # 5. Check for structuring
        if self.possible_structuring(transaction):
            risk_score += 40
            red_flags.append('POSSIBLE_STRUCTURING')
        
        # 6. Check against sanctions lists
        if self.sanctions_match(transaction):
            risk_score = 100
            red_flags.append('SANCTIONS_MATCH')
            self.block_transaction(transaction)
        
        # Log monitoring result
        aml_log.log_monitoring(
            transaction_id=transaction.id,
            risk_score=risk_score,
            red_flags=red_flags,
            decision=self.make_decision(risk_score)
        )
        
        # Escalate if needed
        if risk_score >= AML_THRESHOLD_SAR:
            self.escalate_to_mlro(transaction, risk_score, red_flags)
        
        return risk_score, red_flags
    
    def escalate_to_mlro(self, transaction, risk_score, red_flags):
        """Escalate suspicious activity to MLRO (SYSC 6.3.9R)"""
        sar_report = {
            'transaction_id': transaction.id,
            'customer_id': transaction.customer_id,
            'risk_score': risk_score,
            'red_flags': red_flags,
            'analysis': self.generate_detailed_analysis(transaction),
            'recommendation': 'REVIEW_FOR_SAR',
            'escalated_by': current_user.id,
            'escalated_at': datetime.now()
        }
        
        mlro_queue.add(sar_report)
        
        # Notification to MLRO
        notify_mlro(sar_report)
        
        return sar_report

# CORRECT: Customer Due Diligence
class CustomerDueDiligence:
    """Implement CDD requirements"""
    
    def perform_cdd(self, customer_id, risk_level='STANDARD'):
        """Perform Customer Due Diligence (MLRs 2017 Reg 28)"""
        cdd_result = {
            'customer_id': customer_id,
            'risk_level': risk_level,
            'checks_performed': [],
            'passed': False
        }
        
        # 1. Identity verification
        identity_check = self.verify_identity(customer_id)
        cdd_result['checks_performed'].append(identity_check)
        
        # 2. Beneficial ownership (if applicable)
        if self.requires_beneficial_ownership_check(customer_id):
            bo_check = self.verify_beneficial_owners(customer_id)
            cdd_result['checks_performed'].append(bo_check)
        
        # 3. Source of funds/wealth (for high-risk)
        if risk_level in ['HIGH', 'PEP']:
            sof_check = self.verify_source_of_funds(customer_id)
            cdd_result['checks_performed'].append(sof_check)
        
        # 4. PEP screening
        pep_check = self.screen_for_pep(customer_id)
        cdd_result['checks_performed'].append(pep_check)
        if pep_check['is_pep']:
            cdd_result['risk_level'] = 'PEP'
            self.apply_enhanced_dd(customer_id)
        
        # 5. Sanctions screening
        sanctions_check = self.screen_sanctions(customer_id)
        cdd_result['checks_performed'].append(sanctions_check)
        
        # 6. Adverse media check
        adverse_media = self.check_adverse_media(customer_id)
        cdd_result['checks_performed'].append(adverse_media)
        
        # Determine if CDD passed
        cdd_result['passed'] = all(
            check['status'] == 'PASS' 
            for check in cdd_result['checks_performed']
        )
        
        # Log CDD
        aml_log.log_cdd(cdd_result)
        
        # Store for ongoing monitoring
        self.store_cdd_result(cdd_result)
        
        return cdd_result
    
    def apply_enhanced_dd(self, customer_id):
        """Apply Enhanced Due Diligence for high-risk customers"""
        edd_measures = {
            'senior_management_approval': self.get_senior_approval(customer_id),
            'source_of_wealth': self.verify_source_of_wealth(customer_id),
            'source_of_funds': self.verify_source_of_funds(customer_id),
            'ongoing_monitoring_enhanced': True,
            'transaction_monitoring_enhanced': True,
            'periodic_review_frequency': 'QUARTERLY'  # Instead of annual
        }
        
        db.customers.update(
            customer_id,
            {
                'edd_applied': True,
                'edd_measures': edd_measures,
                'edd_applied_date': datetime.now()
            }
        )
        
        return edd_measures
```

### 12.2 Sanctions Screening

**REQUIRE:**
```python
# CORRECT: Sanctions screening implementation
class SanctionsScreening:
    """Implement sanctions screening (SYSC 6.3, FCG 7)"""
    
    def screen_entity(self, entity_type, entity_data):
        """Screen entity against sanctions lists"""
        screening_result = {
            'entity_type': entity_type,
            'entity_id': entity_data.get('id'),
            'screening_timestamp': datetime.now(),
            'lists_checked': [],
            'matches': [],
            'risk_score': 0,
            'action_required': None
        }
        
        # 1. UK HMT Sanctions List
        hmt_match = self.check_hmt_list(entity_data)
        screening_result['lists_checked'].append('UK_HMT')
        if hmt_match:
            screening_result['matches'].append(hmt_match)
        
        # 2. UN Sanctions List
        un_match = self.check_un_list(entity_data)
        screening_result['lists_checked'].append('UN')
        if un_match:
            screening_result['matches'].append(un_match)
        
        # 3. EU Sanctions List
        eu_match = self.check_eu_list(entity_data)
        screening_result['lists_checked'].append('EU')
        if eu_match:
            screening_result['matches'].append(eu_match)
        
        # 4. OFAC List (if dealing with USD)
        if self.involves_usd_transactions(entity_data):
            ofac_match = self.check_ofac_list(entity_data)
            screening_result['lists_checked'].append('OFAC')
            if ofac_match:
                screening_result['matches'].append(ofac_match)
        
        # Determine action
        if screening_result['matches']:
            if any(m['match_confidence'] > 0.9 for m in screening_result['matches']):
                screening_result['action_required'] = 'BLOCK'
                self.block_entity(entity_data)
            else:
                screening_result['action_required'] = 'REVIEW'
                self.flag_for_manual_review(entity_data, screening_result)
        else:
            screening_result['action_required'] = 'CLEAR'
        
        # Log screening
        sanctions_log.log_screening(screening_result)
        
        return screening_result
    
    def check_hmt_list(self, entity_data):
        """Check against UK HM Treasury sanctions list"""
        # Perform fuzzy matching against name, aliases
        name_matches = self.fuzzy_match(
            entity_data.get('name'),
            self.get_hmt_sanctioned_names()
        )
        
        # Check date of birth if available
        if entity_data.get('date_of_birth'):
            dob_matches = self.match_date_of_birth(
                entity_data['date_of_birth'],
                name_matches
            )
        else:
            dob_matches = name_matches
        
        # Check address/nationality
        if dob_matches and entity_data.get('nationality'):
            final_matches = self.match_nationality(
                entity_data['nationality'],
                dob_matches
            )
        else:
            final_matches = dob_matches
        
        if final_matches:
            return {
                'list': 'UK_HMT',
                'matched_entity': final_matches[0],
                'match_confidence': self.calculate_confidence(
                    entity_data,
                    final_matches[0]
                ),
                'match_date': datetime.now()
            }
        
        return None
```

**FCA Reference**: 
- SYSC 6.3 (Financial crime systems)
- FCG 3 (Money laundering)
- FCG 7 (Financial sanctions)
- Money Laundering Regulations 2017

---

## 13. Consumer Duty Compliance (PRIN 11, PRIN 12)

### 13.1 Fair Value and Good Outcomes

**REQUIRE:**
```python
# CORRECT: Consumer Duty outcome monitoring
class ConsumerDutyMonitoring:
    """Monitor consumer outcomes per Consumer Duty"""
    
    def monitor_product_value(self, product_id):
        """Monitor if product provides fair value (PRIN 2A.4)"""
        monitoring_result = {
            'product_id': product_id,
            'assessment_date': datetime.now(),
            'fair_value_indicators': {},
            'customer_understanding': {},
            'customer_support': {},
            'issues_identified': []
        }
        
        # 1. Price fairness assessment
        price_analysis = self.analyze_pricing(product_id)
        monitoring_result['fair_value_indicators']['pricing'] = price_analysis
        
        if price_analysis['relative_to_market'] > 1.2:  # 20% above market
            monitoring_result['issues_identified'].append({
                'type': 'PRICING',
                'severity': 'HIGH',
                'description': 'Product priced significantly above market'
            })
        
        # 2. Customer understanding assessment
        understanding_metrics = self.assess_customer_understanding(product_id)
        monitoring_result['customer_understanding'] = understanding_metrics
        
        if understanding_metrics['comprehension_score'] < 0.7:
            monitoring_result['issues_identified'].append({
                'type': 'UNDERSTANDING',
                'severity': 'MEDIUM',
                'description': 'Low customer comprehension scores'
            })
        
        # 3. Customer support quality
        support_metrics = self.assess_customer_support(product_id)
        monitoring_result['customer_support'] = support_metrics
        
        if support_metrics['avg_resolution_time'] > SLA_THRESHOLD:
            monitoring_result['issues_identified'].append({
                'type': 'SUPPORT',
                'severity': 'MEDIUM',
                'description': 'Support response times exceed standards'
            })
        
        # 4. Vulnerable customer outcomes
        vulnerable_outcomes = self.assess_vulnerable_customer_outcomes(product_id)
        monitoring_result['vulnerable_customer_outcomes'] = vulnerable_outcomes
        
        if vulnerable_outcomes['harm_indicators_present']:
            monitoring_result['issues_identified'].append({
                'type': 'VULNERABLE_CUSTOMERS',
                'severity': 'HIGH',
                'description': 'Potential harm to vulnerable customers detected'
            })
        
        # Log for board reporting
        consumer_duty_log.log_monitoring(monitoring_result)
        
        # Trigger remediation if issues found
        if monitoring_result['issues_identified']:
            self.trigger_remediation(monitoring_result)
        
        return monitoring_result
    
    def assess_vulnerable_customer_outcomes(self, product_id):
        """Assess outcomes for vulnerable customers"""
        vulnerable_customers = self.identify_vulnerable_customers(product_id)
        
        outcomes = {
            'total_vulnerable_customers': len(vulnerable_customers),
            'complaint_rate': 0,
            'average_outcome_score': 0,
            'harm_indicators': [],
            'harm_indicators_present': False
        }
        
        for customer in vulnerable_customers:
            # Analyze outcomes
            customer_outcomes = self.analyze_customer_outcomes(
                customer.id,
                product_id
            )
            
            # Check for harm indicators
            if customer_outcomes['complaint_filed']:
                outcomes['harm_indicators'].append({
                    'customer_id': customer.id,
                    'indicator': 'COMPLAINT',
                    'details': customer_outcomes['complaint_details']
                })
            
            if customer_outcomes['financial_loss']:
                outcomes['harm_indicators'].append({
                    'customer_id': customer.id,
                    'indicator': 'FINANCIAL_LOSS',
                    'amount': customer_outcomes['loss_amount']
                })
            
            if customer_outcomes['service_issue']:
                outcomes['harm_indicators'].append({
                    'customer_id': customer.id,
                    'indicator': 'SERVICE_ISSUE',
                    'details': customer_outcomes['issue_description']
                })
        
        if outcomes['harm_indicators']:
            outcomes['harm_indicators_present'] = True
        
        return outcomes
```

### 13.2 Communication Standards

**REQUIRE:**
```python
# CORRECT: Consumer-friendly communications
class ConsumerCommunications:
    """Ensure communications meet Consumer Duty standards"""
    
    def validate_communication(self, communication_content, communication_type):
        """Validate communication meets Consumer Duty requirements"""
        validation_result = {
            'content': communication_content,
            'type': communication_type,
            'timestamp': datetime.now(),
            'checks': [],
            'passed': False,
            'issues': []
        }
        
        # 1. Readability check (Consumer understanding outcome)
        readability = self.check_readability(communication_content)
        validation_result['checks'].append(readability)
        
        if readability['flesch_reading_ease'] < 60:  # Too complex
            validation_result['issues'].append({
                'type': 'READABILITY',
                'severity': 'HIGH',
                'message': 'Communication too complex for average consumer'
            })
        
        # 2. Clear and not misleading
        misleading_check = self.check_for_misleading_content(communication_content)
        validation_result['checks'].append(misleading_check)
        
        if misleading_check['potentially_misleading']:
            validation_result['issues'].append({
                'type': 'MISLEADING',
                'severity': 'CRITICAL',
                'message': misleading_check['reason']
            })
        
        # 3. Key information prominent
        prominence_check = self.check_key_info_prominence(
            communication_content,
            communication_type
        )
        validation_result['checks'].append(prominence_check)
        
        if not prominence_check['key_info_prominent']:
            validation_result['issues'].append({
                'type': 'PROMINENCE',
                'severity': 'MEDIUM',
                'message': 'Key information not sufficiently prominent'
            })
        
        # 4. Accessible format check
        accessibility_check = self.check_accessibility(communication_content)
        validation_result['checks'].append(accessibility_check)
        
        if not accessibility_check['wcag_compliant']:
            validation_result['issues'].append({
                'type': 'ACCESSIBILITY',
                'severity': 'MEDIUM',
                'message': 'Communication not accessible to all users'
            })
        
        # 5. Timely communication check (for time-sensitive matters)
        if communication_type in ['ACCOUNT_CHANGE', 'TERMS_UPDATE', 'FEES_CHANGE']:
            timing_check = self.check_notification_timing(communication_content)
            validation_result['checks'].append(timing_check)
            
            if not timing_check['adequate_notice']:
                validation_result['issues'].append({
                    'type': 'TIMING',
                    'severity': 'HIGH',
                    'message': 'Insufficient notice period for customer'
                })
        
        # Determine if validation passed
        validation_result['passed'] = not any(
            issue['severity'] in ['CRITICAL', 'HIGH']
            for issue in validation_result['issues']
        )
        
        # Log validation
        consumer_duty_log.log_communication_validation(validation_result)
        
        return validation_result
```

**FCA Reference**: 
- PRIN 11 (Consumer Duty)
- PRIN 12 (Consumer Duty - Retail customers)
- PRIN 2A.2 (Consumer understanding outcome)
- PRIN 2A.3 (Consumer support outcome)
- PRIN 2A.4 (Price and value outcome)

---

## 14. Code Review Checklist

Before approving any PR for FCA-regulated financial services, verify:

### Security and Data Protection
- [ ] No hardcoded passwords, API keys, or secrets
- [ ] No hardcoded encryption keys
- [ ] Secrets loaded from secure vault/environment variables
- [ ] No logging of customer PII or financial data
- [ ] Sensitive data encrypted at rest (AES-256)
- [ ] Sensitive data encrypted in transit (TLS 1.2+)
- [ ] Customer data has appropriate retention policy

### SQL Security
- [ ] All queries use parameterized statements
- [ ] No string concatenation in SQL
- [ ] No f-strings or .format() in SQL queries
- [ ] Input validation on all user-supplied data

### Cryptography
- [ ] No MD5 or SHA-1 for security purposes
- [ ] No DES or 3DES encryption
- [ ] No ECB mode encryption
- [ ] Passwords use bcrypt (cost >= 12) or Argon2
- [ ] Random generation uses secrets/os.urandom
- [ ] TLS 1.2 or higher enforced

### Authentication and Authorization
- [ ] Session tokens cryptographically random
- [ ] Session expiry appropriate for operation type (5-30 minutes)
- [ ] Authorization checks on all sensitive operations
- [ ] No IDOR vulnerabilities
- [ ] MFA enforced for high-value transactions
- [ ] No user enumeration in error messages

### Access Control (SYSC 4.1, SYSC 5)
- [ ] Object-level authorization implemented
- [ ] Principle of least privilege enforced
- [ ] Audit logging for all sensitive operations
- [ ] Customer can only access their own data

### Dangerous Functions
- [ ] No eval() or exec() with any input
- [ ] No pickle deserialization of untrusted data
- [ ] No shell=True with user input
- [ ] No unvalidated file paths
- [ ] Path traversal prevention implemented

### Data Protection (UK GDPR, DPA 2018)
- [ ] Lawful basis documented for data processing
- [ ] Data minimization applied
- [ ] Retention periods defined and enforced
- [ ] Data subject rights implementation (access, erasure, rectification)
- [ ] Special category data has additional protections
- [ ] GDPR audit logging in place

### Financial Crime (SYSC 6.3, FCG)
- [ ] AML transaction monitoring implemented
- [ ] Sanctions screening in place
- [ ] Customer due diligence checks implemented
- [ ] Suspicious activity reporting mechanism present
- [ ] PEP screening implemented
- [ ] Source of funds verification for high-risk customers

### Operational Resilience (SYSC 15A)
- [ ] Important business services identified
- [ ] Impact tolerances defined
- [ ] Dependency mapping completed
- [ ] Resilience testing scheduled
- [ ] Incident management procedures in place
- [ ] FCA notification process defined

### Consumer Duty (PRIN 11, PRIN 12)
- [ ] Fair value assessment documented
- [ ] Customer understanding considered
- [ ] Communications clear and not misleading
- [ ] Vulnerable customer protections in place
- [ ] Customer support standards met
- [ ] Outcome monitoring implemented

### Error Handling
- [ ] No customer data in error messages
- [ ] No SQL queries or database details exposed
- [ ] No stack traces in production
- [ ] Generic error messages for authentication failures
- [ ] Error reference codes for support tracking

### Audit and Compliance
- [ ] Regulatory audit trail maintained
- [ ] Senior management accountability clear
- [ ] Compliance documentation updated
- [ ] Record retention meets FCA requirements (SYSC 9)

---

## 15. Regulatory References

### Primary FCA Handbook Modules

| Module | Description | Key Requirements |
|--------|-------------|------------------|
| **PRIN** | Principles for Businesses | 11 principles including Consumer Duty (PRIN 11, 12) |
| **SYSC** | Senior Management Arrangements, Systems and Controls | Governance, risk management, IT security, operational resilience |
| **SYSC 3.2.6R** | Systems and controls | Effective systems to counter financial crime |
| **SYSC 4.1** | General organisational requirements | Risk management framework |
| **SYSC 6.1** | Compliance function | Effective compliance monitoring |
| **SYSC 6.3** | Financial crime | AML, sanctions, financial crime controls |
| **SYSC 9** | Record keeping | Adequate records of business activities |
| **SYSC 13** | Operational risk | IT security, business continuity |
| **SYSC 15A** | Operational resilience | Important business services, impact tolerances |
| **COBS** | Conduct of Business Sourcebook | Client best interests, fair treatment |
| **FCG** | Financial Crime Guide | Money laundering, sanctions guidance |
| **SUP 15** | Notifications to FCA | Incident reporting requirements |

### Supporting Regulations

- **UK GDPR** (General Data Protection Regulation)
- **DPA 2018** (Data Protection Act 2018)
- **Money Laundering Regulations 2017**
- **Payment Services Regulations 2017**
- **Electronic Money Regulations 2011**
- **Sanctions and Anti-Money Laundering Act 2018**

### Key Policy Statements

- **PS21/3** - Building operational resilience (March 2021)
- **FG21/1** - Guidance for firms on the Consumer Duty (July 2022)
- **FG16/5** - Cloud and third-party IT services

---

## 16. Document Information

| Version | Date | Changes | Author |
|---------|------|---------|---------|
| 1.0 | 2025-01 | Initial FCA secure coding guidelines | CodeRabbit.ai Compliance Team |

**Document Purpose:**
This document provides secure coding standards for financial services applications regulated by the UK Financial Conduct Authority (FCA). It translates FCA Handbook requirements into practical, enforceable coding standards for code review.

**Scope:**
- All firms regulated by the FCA
- Payment institutions and e-money institutions
- FinTech applications handling customer data
- Open Banking API implementations
- Any code processing financial transactions or customer PII

**Maintenance:**
This document should be reviewed quarterly and updated to reflect:
- FCA Handbook changes
- New policy statements
- Emerging threats and vulnerabilities
- Lessons learned from enforcement actions

**References:**
- FCA Handbook: https://handbook.fca.org.uk
- FCA Website: https://www.fca.org.uk
- UK GDPR and DPA 2018
- Money Laundering Regulations 2017
- OWASP Top 10 2021
- CWE/SANS Top 25

---

## IMPORTANT NOTES FOR CODE REVIEWERS

1. **Risk-Based Approach**: Apply requirements proportionately based on:
   - Nature and scale of business
   - Customer base (retail vs wholesale)
   - Complexity of products
   - Level of customer risk

2. **Consumer Duty Priority**: As of July 2023, Consumer Duty (PRIN 11, 12) is the FCA's highest priority. Ensure all code changes consider:
   - Impact on consumer outcomes
   - Fair value delivery
   - Consumer understanding
   - Support for vulnerable customers

3. **Operational Resilience Deadline**: March 2025 is the compliance deadline for operational resilience (SYSC 15A). Ensure:
   - Important business services identified
   - Impact tolerances set
   - Resilience testing implemented

4. **Data Protection**: UK GDPR is directly enforceable with severe penalties (up to £17.5M or 4% of turnover). Treat data protection as business-critical.

5. **Escalation**: When in doubt:
   - Escalate to MLRO for financial crime questions
   - Escalate to DPO for data protection questions
   - Escalate to Compliance for regulatory interpretation
   - Document all decisions for audit trail

"""
UK Banking Application - Customer Data Management Module

INTENTIONAL VULNERABILITIES FOR CODERABBIT DEMO
This code contains multiple FCA compliance violations for demonstration purposes.
"""

import hashlib
import random
import sqlite3
from datetime import datetime, timedelta
import requests
import pickle


# ============================================================================
# VULNERABILITY 1: Hardcoded Credentials (SYSC 3.2.6R, SYSC 13.6)
# ============================================================================

DB_CONFIG = {
    "host": "prod-db.ukbank.internal",
    "database": "customer_data",
    "user": "admin",
    "password": "UKBank2024!Production",  # CRITICAL: Hardcoded password
    "port": 5432
}

# Open Banking API credentials hardcoded
OPEN_BANKING_API_KEY = "sk_live_51HyLK2eZvKYlo2C8qhQZ9xYz"  # CRITICAL
OPEN_BANKING_SECRET = "whsec_a3d8f7b2c1e4d5a6b7c8d9e0f1"  # CRITICAL

# AML screening API key
AML_SCREENING_KEY = "aml_prod_key_x7y8z9"  # CRITICAL

# Encryption key hardcoded
CUSTOMER_DATA_ENCRYPTION_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"  # CRITICAL


# ============================================================================
# VULNERABILITY 2: Customer PII Logging (UK GDPR Art 5, SYSC 3.2.6R)
# ============================================================================

class CustomerService:
    """Customer data management service"""
    
    def create_customer(self, customer_data):
        """Create new customer account"""
        
        # CRITICAL: Logging customer PII
        print(f"Creating customer: {customer_data['name']}")
        print(f"Account Number: {customer_data['account_number']}")
        print(f"Sort Code: {customer_data['sort_code']}")
        print(f"National Insurance: {customer_data['ni_number']}")
        print(f"Address: {customer_data['address']}")
        print(f"Phone: {customer_data['phone']}")
        
        # CRITICAL: Logging financial information
        logger.info(f"Opening balance: £{customer_data['opening_balance']}")
        logger.debug(f"Customer email: {customer_data['email']}")
        
        # CRITICAL: Logging vulnerability information
        if customer_data.get('is_vulnerable'):
            print(f"Customer {customer_data['name']} flagged as vulnerable: {customer_data['vulnerability_type']}")
        
        return self._save_customer(customer_data)
    
    def get_customer_details(self, customer_id):
        """Retrieve customer details"""
        customer = self._fetch_customer(customer_id)
        
        # CRITICAL: Logging sensitive data in error
        if not customer:
            logger.error(f"Customer not found: ID {customer_id}, checked accounts: {self._get_all_account_numbers()}")
        
        return customer


# ============================================================================
# VULNERABILITY 3: Plaintext PII Storage (UK GDPR Art 32, SYSC 3.2.6R)
# ============================================================================

def store_customer_data(customer):
    """Store customer data in database"""
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    
    # CRITICAL: Storing customer PII without encryption
    cursor.execute("""
        INSERT INTO customers (
            name, 
            account_number, 
            sort_code, 
            iban,
            date_of_birth,
            national_insurance_number,
            address,
            phone,
            email,
            balance,
            vulnerability_flag,
            vulnerability_details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        customer['name'],  # Plaintext
        customer['account_number'],  # Plaintext
        customer['sort_code'],  # Plaintext
        customer['iban'],  # Plaintext
        customer['dob'],  # Plaintext
        customer['ni_number'],  # Plaintext - CRITICAL
        customer['address'],  # Plaintext
        customer['phone'],  # Plaintext
        customer['email'],  # Plaintext
        customer['balance'],  # Plaintext
        customer['is_vulnerable'],  # Special category data
        customer['vulnerability_type']  # Special category data - CRITICAL
    ))
    
    conn.commit()
    conn.close()


# ============================================================================
# VULNERABILITY 4: SQL Injection (SYSC 3.2.6R, SYSC 4.1)
# ============================================================================

def get_customer_by_account(account_number):
    """Retrieve customer by account number"""
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL injection via f-string
    query = f"SELECT * FROM customers WHERE account_number = '{account_number}'"
    cursor.execute(query)
    
    return cursor.fetchone()


def search_customers(search_term):
    """Search customers by name"""
    
    # CRITICAL: SQL injection via concatenation
    query = "SELECT * FROM customers WHERE name LIKE '%" + search_term + "%'"
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute(query)
    
    return cursor.fetchall()


def get_transactions_by_date(customer_id, start_date, end_date):
    """Get customer transactions in date range"""
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL injection via .format()
    query = "SELECT * FROM transactions WHERE customer_id = {} AND date BETWEEN '{}' AND '{}'".format(
        customer_id, start_date, end_date
    )
    
    cursor.execute(query)
    return cursor.fetchall()


# ============================================================================
# VULNERABILITY 5: Weak Cryptography (SYSC 13.6, SYSC 3.2.6R)
# ============================================================================

def hash_customer_id(customer_id):
    """Generate hash for customer ID"""
    
    # CRITICAL: Using MD5 for security purposes
    return hashlib.md5(str(customer_id).encode()).hexdigest()


def encrypt_account_number(account_number):
    """Encrypt account number for storage"""
    
    # CRITICAL: Using SHA-1 for encryption (not suitable)
    return hashlib.sha1(account_number.encode()).hexdigest()


def generate_api_token(customer_id):
    """Generate API token for customer"""
    
    # CRITICAL: Predictable token using MD5 and timestamp
    token_data = f"{customer_id}_{datetime.now().isoformat()}"
    return hashlib.md5(token_data.encode()).hexdigest()


# ============================================================================
# VULNERABILITY 6: Weak Random Generation (SYSC 13.6)
# ============================================================================

def generate_customer_reference():
    """Generate unique customer reference number"""
    
    # CRITICAL: Using predictable random
    return f"CUS{random.randint(100000, 999999)}"


def generate_account_number():
    """Generate new account number"""
    
    # CRITICAL: Time-based seeding makes it predictable
    random.seed(int(datetime.now().timestamp()))
    return f"{random.randint(10000000, 99999999)}"


def generate_otp():
    """Generate one-time password for customer"""
    
    # CRITICAL: Weak random for security-critical OTP
    return str(random.randint(100000, 999999))


def create_reset_token(customer_id):
    """Create password reset token"""
    
    # CRITICAL: Predictable token
    return f"{customer_id}_{random.randint(1000, 9999)}"


# ============================================================================
# VULNERABILITY 7: Insecure Transport (SYSC 13.6, SYSC 8)
# ============================================================================

def verify_customer_identity(customer_id, identity_data):
    """Verify customer identity with third-party service"""
    
    # CRITICAL: Using HTTP for sensitive data transmission
    response = requests.post(
        "http://identity-verification.example.com/verify",
        json={
            "customer_id": customer_id,
            "name": identity_data['name'],
            "dob": identity_data['dob'],
            "address": identity_data['address'],
            "ni_number": identity_data['ni_number']
        }
    )
    
    return response.json()


def submit_kyc_data(customer_data):
    """Submit KYC data to regulatory system"""
    
    # CRITICAL: Disabled SSL verification
    response = requests.post(
        "https://kyc-system.fca.org.uk/submit",
        json=customer_data,
        verify=False  # CRITICAL
    )
    
    return response.json()


# ============================================================================
# VULNERABILITY 8: Weak Password Hashing (SYSC 3.2.6R)
# ============================================================================

def hash_password(password):
    """Hash customer password"""
    
    # CRITICAL: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    """Verify customer password"""
    
    # CRITICAL: MD5 password verification
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


def create_password_hash(password):
    """Create password hash with salt"""
    
    # CRITICAL: Using SHA-256 without proper salt/iterations
    salt = "static_salt_value"  # CRITICAL: Static salt
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


# ============================================================================
# VULNERABILITY 9: Missing Authorization (SYSC 4.1, SYSC 5, COBS 2.1)
# ============================================================================

def get_customer_balance(customer_id):
    """Get customer account balance"""
    
    # CRITICAL: No authorization check - IDOR vulnerability
    # Any authenticated user can access any customer's balance
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM customers WHERE id = ?", (customer_id,))
    
    result = cursor.fetchone()
    return result[0] if result else None


def update_customer_address(customer_id, new_address):
    """Update customer address"""
    
    # CRITICAL: No authorization - anyone can update any customer's address
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE customers SET address = ? WHERE id = ?",
        (new_address, customer_id)
    )
    conn.commit()


def export_customer_data(customer_id):
    """Export all customer data (GDPR DSAR)"""
    
    # CRITICAL: No authorization check
    # CRITICAL: No identity verification before data export
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
    
    customer = cursor.fetchone()
    
    # CRITICAL: No audit log for data export
    return customer


def delete_customer_account(customer_id):
    """Delete customer account (GDPR right to erasure)"""
    
    # CRITICAL: No authorization
    # CRITICAL: Hard delete instead of soft delete (no audit trail)
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    conn.commit()


# ============================================================================
# VULNERABILITY 10: UK GDPR Violations (UK GDPR, DPA 2018)
# ============================================================================

def process_marketing_consent(customer_id, consent_data):
    """Process customer marketing consent"""
    
    # CRITICAL: No verification of consent validity
    # CRITICAL: No timestamp or audit trail
    # CRITICAL: No mechanism to withdraw consent
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE customers SET marketing_consent = 1 WHERE id = ?",
        (customer_id,)
    )
    conn.commit()
    
    # CRITICAL: No documentation of lawful basis


def store_customer_indefinitely(customer_data):
    """Store customer data"""
    
    # CRITICAL: No retention period defined
    # CRITICAL: No automated deletion mechanism
    # CRITICAL: Data stored indefinitely violates GDPR storage limitation
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO customers (name, account_number, dob, address)
        VALUES (?, ?, ?, ?)
    """, (
        customer_data['name'],
        customer_data['account_number'],
        customer_data['dob'],
        customer_data['address']
    ))
    # Missing: retention_until, deletion_scheduled_date
    conn.commit()


def share_customer_data_with_partner(customer_id, partner_name):
    """Share customer data with third party"""
    
    # CRITICAL: No consent check for data sharing
    # CRITICAL: No verification of legitimate interest
    # CRITICAL: No data processing agreement verification
    # CRITICAL: No data minimization
    
    customer = get_customer_details(customer_id)
    
    # CRITICAL: Sending all customer data, not just necessary fields
    response = requests.post(
        f"https://partner-api.example.com/receive-data",
        json=customer  # All fields shared
    )
    
    return response.json()


# ============================================================================
# VULNERABILITY 11: Missing Financial Crime Controls (SYSC 6.3, FCG)
# ============================================================================

def process_transaction(from_account, to_account, amount):
    """Process customer transaction"""
    
    # CRITICAL: No AML transaction monitoring
    # CRITICAL: No sanctions screening
    # CRITICAL: No high-value transaction checks
    # CRITICAL: No suspicious activity detection
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    
    # Just process the transaction without any checks
    cursor.execute(
        "UPDATE accounts SET balance = balance - ? WHERE account_number = ?",
        (amount, from_account)
    )
    cursor.execute(
        "UPDATE accounts SET balance = balance + ? WHERE account_number = ?",
        (amount, to_account)
    )
    
    conn.commit()
    
    # CRITICAL: No audit trail with sufficient detail


def onboard_customer(customer_data):
    """Onboard new customer"""
    
    # CRITICAL: No KYC/CDD checks
    # CRITICAL: No identity verification
    # CRITICAL: No PEP screening
    # CRITICAL: No sanctions screening
    # CRITICAL: No source of funds verification
    
    customer_id = store_customer_data(customer_data)
    
    # Customer immediately active without checks
    return {"customer_id": customer_id, "status": "active"}


def check_sanctions(customer_name):
    """Check customer against sanctions lists"""
    
    # CRITICAL: Very basic check, no fuzzy matching
    # CRITICAL: Only checking UK list, missing UN, OFAC
    # CRITICAL: No date of birth or address matching
    
    sanctioned_names = ["Bad Actor", "Sanctioned Person"]
    
    return customer_name in sanctioned_names  # Simple exact match only


# ============================================================================
# VULNERABILITY 12: Information Disclosure in Errors
# ============================================================================

def authenticate_customer(account_number, password):
    """Authenticate customer"""
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    
    # CRITICAL: User enumeration vulnerability
    cursor.execute(
        "SELECT * FROM customers WHERE account_number = ?",
        (account_number,)
    )
    customer = cursor.fetchone()
    
    if not customer:
        # CRITICAL: Reveals that account doesn't exist
        return {"error": f"Account {account_number} not found"}
    
    if not verify_password(password, customer['password_hash']):
        # CRITICAL: Reveals that account exists but password is wrong
        return {"error": "Invalid password"}
    
    return {"success": True, "customer_id": customer['id']}


def get_account_balance_api(account_number):
    """API endpoint to get account balance"""
    
    try:
        balance = get_customer_balance(account_number)
        return {"balance": balance}
    except Exception as e:
        # CRITICAL: Exposing SQL error details
        return {
            "error": str(e),
            "query": "SELECT balance FROM customers WHERE account_number = ?",
            "database": "customers.db"
        }


# ============================================================================
# VULNERABILITY 13: Code Injection (SYSC 3.2.6R)
# ============================================================================

def execute_custom_query(customer_id, query_template):
    """Execute custom query for reporting"""
    
    # CRITICAL: eval() with user input
    query = eval(f"f'{query_template}'")
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute(query)
    
    return cursor.fetchall()


def process_customer_data_import(file_path):
    """Import customer data from file"""
    
    # CRITICAL: pickle.load() with untrusted data
    with open(file_path, 'rb') as f:
        customer_data = pickle.load(f)  # Arbitrary code execution risk
    
    for customer in customer_data:
        store_customer_data(customer)


# ============================================================================
# VULNERABILITY 14: Missing Audit Trail (SYSC 9)
# ============================================================================

def change_customer_password(customer_id, new_password):
    """Change customer password"""
    
    # CRITICAL: No audit log for password change
    # CRITICAL: No verification of old password
    # CRITICAL: No MFA requirement
    # CRITICAL: No notification to customer
    
    password_hash = hash_password(new_password)
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE customers SET password_hash = ? WHERE id = ?",
        (password_hash, customer_id)
    )
    conn.commit()


def update_customer_email(customer_id, new_email):
    """Update customer email address"""
    
    # CRITICAL: No audit trail
    # CRITICAL: No verification email to old address
    # CRITICAL: No verification email to new address
    
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE customers SET email = ? WHERE id = ?",
        (new_email, customer_id)
    )
    conn.commit()


# ============================================================================
# VULNERABILITY 15: Consumer Duty Violations (PRIN 11, PRIN 12)
# ============================================================================

def calculate_overdraft_fee(customer_id, overdraft_amount):
    """Calculate overdraft fee"""
    
    # CRITICAL: Complex fee structure not clearly communicated
    # CRITICAL: May not provide fair value
    # CRITICAL: No vulnerable customer protection
    
    base_fee = 35.00
    daily_fee = 5.00
    
    # Potentially unfair for vulnerable customers
    total_fee = base_fee + (daily_fee * 7)  # £70 in fees
    
    # CRITICAL: No check if customer is vulnerable
    # CRITICAL: No assessment of proportionality
    
    return total_fee


def send_account_closure_notification(customer_id):
    """Send account closure notification"""
    
    # CRITICAL: Complex legal language
    # CRITICAL: Short notice period (may violate Consumer Duty)
    # CRITICAL: No accessible format options
    
    message = """
    Dear Customer,
    
    Pursuant to Clause 14.3(b) of the Terms and Conditions (as amended),
    we hereby give notice of our intention to terminate the Agreement
    with effect from 7 days from the date hereof, without prejudice to
    any accrued rights or obligations.
    """
    
    # CRITICAL: Not clear or understandable for average consumer
    send_email(customer_id, "Account Closure", message)


# ============================================================================
# VULNERABILITY 16: Missing Input Validation
# ============================================================================

def validate_iban(iban):
    """Validate IBAN"""
    
    # CRITICAL: Only length check, no modulus 97 validation
    return len(iban) >= 15 and len(iban) <= 34


def validate_uk_account(sort_code, account_number):
    """Validate UK account number"""
    
    # CRITICAL: No modulus 11 check
    # CRITICAL: Only length validation
    return len(sort_code) == 6 and len(account_number) == 8


def process_payment_amount(amount):
    """Process payment amount"""
    
    # CRITICAL: No validation of decimal places
    # CRITICAL: No maximum amount check
    # CRITICAL: No negative amount check
    
    # Direct use without validation
    return float(amount)


# ============================================================================
# Example Usage (with vulnerabilities)
# ============================================================================

if __name__ == "__main__":
    # Example showing multiple vulnerabilities in action
    
    # Hardcoded test data with real-looking PII
    test_customer = {
        "name": "John Smith",
        "account_number": "12345678",
        "sort_code": "12-34-56",
        "iban": "GB29NWBK60161331926819",
        "dob": "1985-05-15",
        "ni_number": "AB123456C",
        "address": "123 High Street, London, SW1A 1AA",
        "phone": "+44 20 7123 4567",
        "email": "john.smith@email.com",
        "opening_balance": 5000.00,
        "is_vulnerable": True,
        "vulnerability_type": "mental_health"
    }
    
    # CRITICAL: All these operations have vulnerabilities
    customer_service = CustomerService()
    customer_service.create_customer(test_customer)
    
    print("Customer created with multiple FCA compliance violations!")

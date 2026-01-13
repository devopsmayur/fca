"""
UK Banking Application - Payment Processing Module

INTENTIONAL VULNERABILITIES FOR CODERABBIT DEMO
This code contains payment-related FCA and PCI-DSS violations.
"""

import hashlib
import random
import json
import sqlite3
from datetime import datetime, timedelta
import requests


# ============================================================================
# VULNERABILITY 1: Card Data Handling (PCI-DSS 3.2, FCA SYSC 13.6)
# ============================================================================

class PaymentCard:
    """Payment card data model"""
    
    def __init__(self, card_number, cvv, expiry_date, cardholder_name):
        # CRITICAL: Storing CVV (violates PCI-DSS 3.2.2)
        self.card_number = card_number
        self.cvv = cvv  # CRITICAL: CVV must NEVER be stored
        self.expiry_date = expiry_date
        self.cardholder_name = cardholder_name
        self.stored_date = datetime.now()
    
    def to_dict(self):
        """Convert to dictionary"""
        # CRITICAL: Exposing CVV in serialization
        return {
            "card_number": self.card_number,
            "cvv": self.cvv,  # CRITICAL
            "expiry": self.expiry_date,
            "name": self.cardholder_name
        }
    
    def display(self):
        """Display card details"""
        # CRITICAL: Logging CVV and full PAN
        print(f"Card: {self.card_number}")
        print(f"CVV: {self.cvv}")
        print(f"Expiry: {self.expiry_date}")
        print(f"Name: {self.cardholder_name}")


def save_card_details(customer_id, card_data):
    """Save customer card details"""
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # CRITICAL: Storing CVV after authorization (PCI-DSS 3.2.2)
    # CRITICAL: Storing card data unencrypted
    cursor.execute("""
        INSERT INTO stored_cards (
            customer_id,
            card_number,
            cvv,
            expiry_date,
            cardholder_name
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        customer_id,
        card_data['card_number'],
        card_data['cvv'],  # CRITICAL: CVV storage
        card_data['expiry'],
        card_data['name']
    ))
    
    # CRITICAL: Logging card details
    print(f"Stored card ending {card_data['card_number'][-4:]} with CVV {card_data['cvv']}")
    
    conn.commit()
    conn.close()


# ============================================================================
# VULNERABILITY 2: Payment Gateway Integration (SYSC 13.6, SYSC 8)
# ============================================================================

# CRITICAL: Hardcoded payment gateway credentials
STRIPE_API_KEY = "sk_live_51HyLK2eZvKYlo2CwDd4wSFDyhD3FSA7i"  # CRITICAL
STRIPE_SECRET = "whsec_pzgZ8Ks7D8F3d9sYT9pV4cN3wQ2xR5yU"  # CRITICAL

WORLDPAY_MERCHANT_ID = "UKBANKMERCHANT001"  # CRITICAL
WORLDPAY_INSTALLATION_ID = "1234567"  # CRITICAL
WORLDPAY_PASSWORD = "WorldPay2024!Prod"  # CRITICAL


def process_card_payment(card_data, amount, currency="GBP"):
    """Process card payment"""
    
    # CRITICAL: Logging full card details
    logger.info(f"Processing payment for card {card_data['card_number']}")
    logger.debug(f"Card CVV: {card_data['cvv']}")
    logger.info(f"Amount: {currency} {amount}")
    
    # CRITICAL: Sending over HTTP instead of HTTPS
    response = requests.post(
        "http://payment-gateway.example.com/charge",  # CRITICAL: HTTP
        json={
            "card_number": card_data['card_number'],
            "cvv": card_data['cvv'],
            "expiry": card_data['expiry'],
            "amount": amount,
            "currency": currency,
            "api_key": STRIPE_API_KEY  # CRITICAL: Exposing API key in request
        }
    )
    
    return response.json()


def refund_payment(transaction_id, amount):
    """Process payment refund"""
    
    # CRITICAL: Disabled SSL verification
    response = requests.post(
        "https://payment-gateway.example.com/refund",
        json={
            "transaction_id": transaction_id,
            "amount": amount,
            "api_key": STRIPE_API_KEY
        },
        verify=False  # CRITICAL: SSL disabled
    )
    
    return response.json()


# ============================================================================
# VULNERABILITY 3: Open Banking Payment Initiation (RTS, SYSC 13.6)
# ============================================================================

# CRITICAL: Hardcoded Open Banking credentials
OPEN_BANKING_CLIENT_ID = "obb_client_ukbank_prod_12345"  # CRITICAL
OPEN_BANKING_CLIENT_SECRET = "obb_secret_a1b2c3d4e5f6g7h8"  # CRITICAL
OPEN_BANKING_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef...
-----END RSA PRIVATE KEY-----"""  # CRITICAL


def initiate_open_banking_payment(customer_id, payment_data):
    """Initiate Open Banking payment"""
    
    # CRITICAL: No Strong Customer Authentication (SCA) check
    # CRITICAL: No dynamic linking verification
    # CRITICAL: Missing consent validation
    
    # CRITICAL: Logging customer bank details
    print(f"Initiating payment for customer {customer_id}")
    print(f"From account: {payment_data['debtor_account']}")
    print(f"To account: {payment_data['creditor_account']}")
    print(f"Amount: £{payment_data['amount']}")
    
    access_token = get_open_banking_token()
    
    # CRITICAL: No fraud checks
    response = requests.post(
        "https://ob.openbanking.org.uk/v3.1/pisp/domestic-payments",
        headers={
            "Authorization": f"Bearer {access_token}",
            "x-fapi-financial-id": "ukbank001",
            "x-idempotency-key": str(random.randint(100000, 999999))  # CRITICAL: Weak random
        },
        json=payment_data
    )
    
    return response.json()


def get_open_banking_token():
    """Get Open Banking access token"""
    
    # CRITICAL: Storing token without encryption
    # CRITICAL: No token expiry check
    
    token = requests.post(
        "https://auth.openbanking.org.uk/token",
        data={
            "client_id": OPEN_BANKING_CLIENT_ID,
            "client_secret": OPEN_BANKING_CLIENT_SECRET,  # CRITICAL: Exposed
            "grant_type": "client_credentials"
        }
    ).json()
    
    # CRITICAL: Token stored in plaintext file
    with open("ob_token.txt", "w") as f:
        f.write(token['access_token'])
    
    return token['access_token']


# ============================================================================
# VULNERABILITY 4: AML Transaction Monitoring (SYSC 6.3, FCG)
# ============================================================================

def process_transaction(from_account, to_account, amount, currency="GBP"):
    """Process bank transfer"""
    
    # CRITICAL: No AML monitoring
    # CRITICAL: No transaction threshold checks
    # CRITICAL: No sanctions screening
    # CRITICAL: No velocity checks
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL injection vulnerability
    query = f"INSERT INTO transactions (from_account, to_account, amount, currency, timestamp) VALUES ('{from_account}', '{to_account}', {amount}, '{currency}', '{datetime.now()}')"
    cursor.execute(query)
    
    # Just process without any checks
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
    # CRITICAL: Logging full account numbers
    print(f"Transferred £{amount} from {from_account} to {to_account}")
    
    return {"status": "completed", "transaction_id": cursor.lastrowid}


def detect_suspicious_activity(customer_id, transaction):
    """Detect suspicious transaction activity"""
    
    # CRITICAL: Very basic checks, no real AML monitoring
    # CRITICAL: No ML-based pattern detection
    # CRITICAL: No velocity checks
    # CRITICAL: No geographic checks
    
    # Only checking if amount is over £10,000
    if transaction['amount'] > 10000:
        # CRITICAL: No proper SAR (Suspicious Activity Report) mechanism
        print(f"Large transaction detected: £{transaction['amount']}")
        return True
    
    return False


def screen_transaction_parties(from_customer_id, to_account):
    """Screen transaction parties against sanctions"""
    
    # CRITICAL: No actual sanctions screening
    # CRITICAL: Not checking UK HMT, UN, OFAC lists
    # CRITICAL: No PEP screening
    
    # Placeholder - no real checks
    return {"screened": True, "matches": []}


# ============================================================================
# VULNERABILITY 5: Payment Authorization (SYSC 4.1, Consumer Duty)
# ============================================================================

def authorize_payment(customer_id, payment_request):
    """Authorize payment request"""
    
    # CRITICAL: No authorization check (IDOR)
    # CRITICAL: No MFA for high-value payments
    # CRITICAL: No velocity checks
    # CRITICAL: No fraud detection
    
    amount = payment_request['amount']
    
    # CRITICAL: No check if customer owns the source account
    # CRITICAL: No check if customer has sufficient balance
    # CRITICAL: No check if account is active
    
    # Process immediately without proper checks
    return process_transaction(
        payment_request['from_account'],
        payment_request['to_account'],
        amount
    )


def process_high_value_payment(customer_id, payment_data):
    """Process high-value payment (>£1000)"""
    
    # CRITICAL: No additional authentication for high-value
    # CRITICAL: No customer confirmation
    # CRITICAL: No cooling-off period
    # CRITICAL: No enhanced fraud checks
    
    if payment_data['amount'] > 1000:
        # Should require MFA but doesn't
        print(f"Processing high-value payment: £{payment_data['amount']}")
    
    return authorize_payment(customer_id, payment_data)


# ============================================================================
# VULNERABILITY 6: Direct Debit Processing (FCA PRIN 11 Consumer Duty)
# ============================================================================

def setup_direct_debit(customer_id, merchant_id, max_amount):
    """Setup direct debit mandate"""
    
    # CRITICAL: No clear communication to customer
    # CRITICAL: No explicit consent confirmation
    # CRITICAL: No vulnerable customer protection
    # CRITICAL: No cooling-off period
    
    mandate_id = f"DD{random.randint(100000, 999999)}"  # CRITICAL: Weak random
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO direct_debits (
            mandate_id,
            customer_id,
            merchant_id,
            max_amount,
            status
        ) VALUES (?, ?, ?, ?, 'ACTIVE')
    """, (mandate_id, customer_id, merchant_id, max_amount))
    
    conn.commit()
    
    # CRITICAL: No audit trail
    # CRITICAL: No notification to customer
    
    return {"mandate_id": mandate_id, "status": "active"}


def process_direct_debit(mandate_id, amount):
    """Process direct debit payment"""
    
    # CRITICAL: No checks if amount exceeds mandate limit
    # CRITICAL: No customer notification before collection
    # CRITICAL: No vulnerable customer protection
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL injection
    query = f"SELECT * FROM direct_debits WHERE mandate_id = '{mandate_id}'"
    cursor.execute(query)
    mandate = cursor.fetchone()
    
    # Just process without checks
    customer_id = mandate['customer_id']
    
    # CRITICAL: No balance check
    # CRITICAL: No failed payment handling
    
    return {"status": "collected", "amount": amount}


# ============================================================================
# VULNERABILITY 7: Payment Data in Logs and Errors (UK GDPR, SYSC 3.2.6R)
# ============================================================================

def log_payment_details(payment):
    """Log payment details for audit"""
    
    # CRITICAL: Logging full payment details
    logger.info(f"Payment from account: {payment['from_account']}")
    logger.info(f"Payment to account: {payment['to_account']}")
    logger.info(f"Amount: £{payment['amount']}")
    logger.info(f"Reference: {payment['reference']}")
    logger.debug(f"Customer name: {payment['customer_name']}")
    
    # CRITICAL: Logging card details if card payment
    if payment.get('card_number'):
        logger.info(f"Card used: {payment['card_number']}")
        logger.debug(f"CVV: {payment['cvv']}")


def handle_payment_error(payment_data, error):
    """Handle payment processing error"""
    
    # CRITICAL: Exposing payment details in error
    error_message = f"""
    Payment failed for customer {payment_data['customer_id']}
    From account: {payment_data['from_account']}
    To account: {payment_data['to_account']}
    Amount: £{payment_data['amount']}
    Error: {str(error)}
    Database query: SELECT * FROM accounts WHERE account_number = '{payment_data['from_account']}'
    """
    
    # CRITICAL: Returning detailed error to client
    return {
        "error": error_message,
        "payment_data": payment_data,  # CRITICAL: Full payment data
        "timestamp": datetime.now().isoformat()
    }


# ============================================================================
# VULNERABILITY 8: Faster Payments Processing (Operational Resilience)
# ============================================================================

def process_faster_payment(payment_request):
    """Process UK Faster Payment"""
    
    # CRITICAL: No resilience testing
    # CRITICAL: No impact tolerance defined
    # CRITICAL: Single point of failure
    # CRITICAL: No fallback mechanism
    
    try:
        response = requests.post(
            "https://faster-payments-api.example.com/submit",
            json=payment_request,
            timeout=5  # CRITICAL: Low timeout, no retry logic
        )
        return response.json()
    except Exception as e:
        # CRITICAL: No incident reporting
        # CRITICAL: No FCA notification for material incident
        # CRITICAL: Complete failure with no recovery
        print(f"Faster Payment system down: {e}")
        return {"error": "System unavailable"}


# ============================================================================
# VULNERABILITY 9: Payment Fee Calculation (Consumer Duty PRIN 11)
# ============================================================================

def calculate_payment_fee(payment_type, amount, customer_id):
    """Calculate payment processing fee"""
    
    # CRITICAL: No vulnerable customer check
    # CRITICAL: Unclear fee structure
    # CRITICAL: Potentially unfair fees
    
    fees = {
        "domestic": 0,
        "international": 25.00,
        "same_day": 15.00,
        "instant": 10.00
    }
    
    base_fee = fees.get(payment_type, 0)
    
    # CRITICAL: Additional percentage fee not clearly communicated
    percentage_fee = amount * 0.015  # 1.5% - potentially excessive
    
    total_fee = base_fee + percentage_fee
    
    # CRITICAL: No fair value assessment
    # CRITICAL: No comparison to market rates
    # CRITICAL: No cap on fees for vulnerable customers
    
    return total_fee


def apply_overdraft_charges(account_number, overdraft_amount):
    """Apply overdraft charges"""
    
    # CRITICAL: No vulnerable customer protection
    # CRITICAL: Charges may cause harm to vulnerable customers
    # CRITICAL: Not proportionate to customer circumstances
    
    daily_charge = 5.00
    monthly_charge = 35.00
    
    # CRITICAL: Complex charging structure
    total_charges = monthly_charge + (daily_charge * 30)  # £185/month
    
    # Just apply charges without any checks
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE accounts SET balance = balance - ? WHERE account_number = ?",
        (total_charges, account_number)
    )
    conn.commit()
    
    # CRITICAL: No clear communication to customer
    # CRITICAL: No notification before charges applied


# ============================================================================
# VULNERABILITY 10: International Payment Processing (AML Risk)
# ============================================================================

def process_international_payment(payment_data):
    """Process international payment via SWIFT"""
    
    # CRITICAL: No sanctions screening on recipient country
    # CRITICAL: No high-risk jurisdiction checks
    # CRITICAL: No enhanced due diligence for high-risk countries
    # CRITICAL: No source of funds verification
    
    recipient_country = payment_data['recipient_country']
    amount = payment_data['amount']
    
    # CRITICAL: Logging SWIFT details
    logger.info(f"SWIFT payment to {recipient_country}")
    logger.info(f"Recipient BIC: {payment_data['recipient_bic']}")
    logger.info(f"Amount: {amount} {payment_data['currency']}")
    
    # CRITICAL: No AML monitoring for international transfers
    # CRITICAL: No enhanced checks for large amounts
    
    swift_message = generate_swift_message(payment_data)
    
    # CRITICAL: SQL injection in SWIFT logging
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    query = f"INSERT INTO swift_payments (swift_message, timestamp) VALUES ('{swift_message}', '{datetime.now()}')"
    cursor.execute(query)
    conn.commit()
    
    return {"status": "sent", "swift_reference": f"SWIFT{random.randint(100000, 999999)}"}


def generate_swift_message(payment_data):
    """Generate SWIFT MT103 message"""
    
    # CRITICAL: Hardcoded SWIFT credentials
    SWIFT_BIC = "UKBKGB2LXXX"  # CRITICAL
    SWIFT_PASSWORD = "Swift2024Prod!"  # CRITICAL
    
    # Simplified SWIFT message generation
    swift_message = f"""
    :20:{random.randint(100000, 999999)}
    :32A:{datetime.now().strftime('%y%m%d')}{payment_data['currency']}{payment_data['amount']}
    :50K:{payment_data['sender_name']}
    :59:{payment_data['recipient_name']}
    """
    
    return swift_message


# ============================================================================
# VULNERABILITY 11: Payment Card Tokenization (PCI-DSS 3.5)
# ============================================================================

def tokenize_card(card_number, cvv):
    """Generate token for card"""
    
    # CRITICAL: Weak tokenization using MD5
    token = hashlib.md5(f"{card_number}{cvv}".encode()).hexdigest()
    
    # CRITICAL: Storing mapping between token and card unencrypted
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO card_tokens (token, card_number, cvv, created_at)
        VALUES (?, ?, ?, ?)
    """, (token, card_number, cvv, datetime.now()))  # CRITICAL: Storing CVV
    conn.commit()
    
    return token


def detokenize_card(token):
    """Get original card from token"""
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL injection
    query = f"SELECT card_number, cvv FROM card_tokens WHERE token = '{token}'"
    cursor.execute(query)
    result = cursor.fetchone()
    
    if result:
        # CRITICAL: Returning CVV (should never be retrievable)
        return {
            "card_number": result[0],
            "cvv": result[1]  # CRITICAL
        }
    
    return None


# ============================================================================
# VULNERABILITY 12: Recurring Payment Management (Consumer Duty)
# ============================================================================

def setup_recurring_payment(customer_id, merchant_id, amount, frequency):
    """Setup recurring payment"""
    
    # CRITICAL: No clear terms communication
    # CRITICAL: No easy cancellation mechanism
    # CRITICAL: No reminder before collection
    # CRITICAL: No vulnerable customer protection
    
    recurring_id = f"REC{random.randint(100000, 999999)}"
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO recurring_payments (
            recurring_id, customer_id, merchant_id, amount, frequency, status
        ) VALUES (?, ?, ?, ?, ?, 'ACTIVE')
    """, (recurring_id, customer_id, merchant_id, amount, frequency))
    conn.commit()
    
    # CRITICAL: No confirmation email
    # CRITICAL: No audit trail
    
    return {"recurring_id": recurring_id}


def process_recurring_payment(recurring_id):
    """Process scheduled recurring payment"""
    
    conn = sqlite3.connect('payments.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM recurring_payments WHERE recurring_id = ?",
        (recurring_id,)
    )
    recurring = cursor.fetchone()
    
    # CRITICAL: No balance check before collection
    # CRITICAL: No failed payment handling
    # CRITICAL: No customer notification
    # CRITICAL: No retry logic that could cause multiple debits
    
    customer_id = recurring['customer_id']
    amount = recurring['amount']
    
    # Just process without checks
    result = process_transaction(
        recurring['from_account'],
        recurring['merchant_account'],
        amount
    )
    
    return result


# ============================================================================
# Example Usage (demonstrating vulnerabilities)
# ============================================================================

if __name__ == "__main__":
    # Example showing payment vulnerabilities
    
    # CRITICAL: Card data with CVV
    card_data = {
        "card_number": "4532123456789012",
        "cvv": "123",  # Should never be stored
        "expiry": "12/25",
        "name": "John Smith"
    }
    
    # CRITICAL: Storing CVV
    save_card_details(customer_id=12345, card_data=card_data)
    
    # CRITICAL: Processing payment without proper checks
    payment = {
        "from_account": "12345678",
        "to_account": "87654321",
        "amount": 5000.00,
        "customer_id": 12345
    }
    
    result = authorize_payment(12345, payment)
    print(f"Payment processed with FCA and PCI-DSS violations: {result}")

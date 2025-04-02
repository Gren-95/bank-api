# Bank Interoperability Specifications

This document outlines the technical specifications required for implementing a bank system that can interoperate with barBank for processing transactions between banks.

## Bank Registration

All banks must register with the Central Bank to participate in the interbank network.

### Central Bank Requirements

1. Each bank must register with the Central Bank to receive:
   - A unique bank prefix (3-character code)
   - An API key for secure communication

2. Each bank must provide to the Central Bank:
   - Bank name
   - Transaction URL endpoint (for receiving transactions)
   - JWKS URL endpoint (for public key sharing)
   - Owner information

## Account Number Format

- Account numbers must start with the bank's prefix
- Example: `843eaf7076184bdb8b74faea17d1c3c3287`
- The first 3 characters are the bank prefix

## Transaction Processing

### Outgoing Transaction Flow

1. Bank A initiates a transfer to Bank B
2. Bank A creates a transaction record with status "pending"
3. Bank A retrieves Bank B's details from Central Bank
4. Bank A generates a JWT with the transaction payload
5. Bank A signs the JWT with its private key
6. Bank A sends the JWT to Bank B's transaction endpoint
7. Bank A processes Bank B's response
8. Bank A updates transaction status and debits sender's account

### Incoming Transaction Flow

1. Bank B receives a JWT from Bank A
2. Bank B validates the JWT structure
3. Bank B extracts the transaction payload
4. Bank B verifies the receiving account exists
5. Bank B validates the sending bank (Bank A) with Central Bank
6. Bank B retrieves Bank A's public key from its JWKS endpoint
7. Bank B verifies JWT signature using Bank A's public key
8. Bank B credits receiver's account
9. Bank B returns the receiver's name to Bank A

## API Endpoints

### Bank-to-Bank Transaction Endpoint

```
POST /transactions/b2b
```

**Request Body:**
```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhY2NvdW50RnJvbSI6Ijg0M2VhZjcwNzYxODRiZGI4Yjc0ZmFlYTE3ZDFjM2MzMjg3IiwiYWNjb3VudFRvIjoiQUJDMTIzNDU2IiwiY3VycmVuY3kiOiJFVVIiLCJhbW91bnQiOjEwMDAwLCJleHBsYW5hdGlvbiI6IlBheW1lbnQgZm9yIHNlcnZpY2VzIiwic2VuZGVyTmFtZSI6IkpvaG4gRG9lIn0.signature"
}
```

**JWT Payload Structure:**
```json
{
  "accountFrom": "843eaf7076184bdb8b74faea17d1c3c3287",
  "accountTo": "ABC123456",
  "currency": "EUR",
  "amount": 10000,
  "explanation": "Payment for services",
  "senderName": "John Doe"
}
```

**Successful Response (200):**
```json
{
  "receiverName": "Jane Smith"
}
```

**Error Responses:**
- 400: Bad request (parsing JWT failed, invalid signature)
- 404: Account not found
- 500: Internal server error
- 502: Central Bank error

### JWKS Endpoint

```
GET /transactions/jwks
```

**Response:**
JSON Web Key Set (JWKS) containing the bank's public key.

## Security Requirements

1. **Authentication:**
   - All banks must authenticate using JWT signed with RSA-256

2. **Key Management:**
   - Each bank must generate and securely store an RSA key pair
   - Public key must be exposed via JWKS endpoint
   - Private key must be used to sign all outgoing transactions

3. **Transaction Validation:**
   - Verify the sender bank's signature using its public key
   - Validate account numbers exist and follow correct format
   - Verify sufficient funds before processing transactions

## Currency Support

- Multiple currencies must be supported (EUR, USD, GBP, etc.)
- Currency conversion must be implemented when source and target accounts use different currencies
- Exchange rates should be obtained from a reliable external service

## Error Handling

Banks must respond with appropriate HTTP status codes and clear error messages:
- 400: Invalid request format
- 401: Authentication failure
- 402: Insufficient funds
- 404: Account not found
- 500: Internal server error
- 502: Central Bank connectivity issues

## Testing

Implement TEST_MODE functionality to mock Central Bank responses and test interbank transactions without actual network calls.
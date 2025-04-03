# Bank API

A robust banking API implementation that supports internal and external (B2B) transactions, following the specifications provided in `SPECIFICATIONS.md`.

## Features

- **Account Management**
  - Create and manage bank accounts
  - Support for multiple currencies (EUR, USD, GBP)
  - Account balance tracking
  - Transaction history

- **Transaction Processing**
  - Internal transfers between accounts
  - External (B2B) transfers between banks
  - Currency conversion support
  - Transaction status tracking

- **Security**
  - JWT-based authentication
  - RSA key pair management
  - JWKS (JSON Web Key Set) support
  - Rate limiting
  - Input validation

- **Resilience**
  - Retry logic for external transfers
  - Comprehensive error handling
  - Detailed logging
  - Transaction status tracking

## Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)
- MongoDB (for data storage)

## Environment Variables

Create a `.env` file with the following variables:

```env
PORT=9000
MONGODB_URI=mongodb://localhost:27017/bank-api
JWT_SECRET=your-secret-key
BANK_PREFIX=your-bank-prefix
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Gren-95/bank-api
cd bank-api
```

1. Cope example env to production

```bash
cp .env.example .env
```


1. Start the server (dependencies are installed at start):

```bash
npm start
```

The API will be available at `http://localhost:9000`

## Running as a Service (Optional)

To run the API as a systemd service, create a service file at `/etc/systemd/system/bank-api.service`:

```ini
[Unit]
Description=Bank API Service
After=network.target

[Service]
WorkingDirectory=/public/bank-api
ExecStart=/bin/sh -c 'npm start'
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl enable bank-api
sudo systemctl start bank-api
```

Check the service status:

```bash
sudo systemctl status bank-api
```

## API Documentation

API documentation is available at `http://localhost:9000/docs` when the server is running.

### Key Endpoints

- `POST /auth/login` - User authentication
- `POST /accounts` - Create new account
- `GET /accounts/:id` - Get account details
- `POST /transactions/internal` - Process internal transfer
- `POST /transactions/b2b` - Process external (B2B) transfer
- `GET /transactions/:id` - Get transaction details
- `GET /transactions/jwks` - Get bank's public keys (JWKS)

## B2B Transaction Flow

1. **Sending Bank**
   - Creates JWT with transaction details
   - Signs JWT with private key
   - Sends to receiving bank

2. **Receiving Bank**
   - Verifies JWT using sender's public key
   - Validates transaction details
   - Processes transaction if valid
   - Returns success/failure response

## Error Handling

The API implements comprehensive error handling:

- HTTP Status Codes
  - 200: Success
  - 201: Created
  - 400: Bad Request
  - 401: Unauthorized
  - 403: Forbidden
  - 404: Not Found
  - 402: Payment Required
  - 500: Server Error

- Detailed Error Messages
  - Validation errors
  - Authentication failures
  - Transaction processing errors
  - External service errors

## Logging

The API implements detailed logging for:

- Authentication attempts
- Transaction processing
- External service interactions
- Error scenarios
- JWT verification
- Currency conversions

## Security Features

- JWT-based authentication
- RSA key pair management
- JWKS support for B2B transactions
- Rate limiting
- Input validation
- Secure password handling

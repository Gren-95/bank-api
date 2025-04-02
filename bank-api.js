require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Load OpenAPI specification
const swaggerSpec = YAML.load(path.join(__dirname, './openapi.yaml'));

// In-memory data store
const dataStore = {
  users: [],
  accounts: [],
  transactions: [],
  nextUserId: 1,
  nextAccountId: 1,
  nextTransactionId: 1
};

// Helper functions for data store
const dataStoreHelpers = {
  // User helpers
  createUser: async (userData) => {
    const user = {
      id: dataStore.nextUserId++,
      ...userData,
      is_active: true,
      created_at: new Date().toISOString()
    };
    dataStore.users.push(user);
    return user;
  },

  findUserById: (id) => {
    return dataStore.users.find(user => user.id === id);
  },

  findUserByUsername: (username) => {
    return dataStore.users.find(user => user.username === username);
  },

  // Account helpers
  createAccount: (accountData) => {
    const account = {
      id: dataStore.nextAccountId++,
      ...accountData,
      balance: 1000,
      is_active: true,
      created_at: new Date().toISOString()
    };
    dataStore.accounts.push(account);
    return account;
  },

  findAccountById: (id) => {
    return dataStore.accounts.find(account => account.id === id);
  },

  findUserAccounts: (userId) => {
    return dataStore.accounts.filter(account => account.user_id === userId);
  },

  updateAccountBalance: (accountNumber, amount) => {
    const account = dataStore.accounts.find(acc => acc.account_number === accountNumber);
    if (account) {
      account.balance += amount;
      return true;
    }
    return false;
  },

  // Transaction helpers
  createTransaction: (transactionData) => {
    const transaction = {
      id: dataStore.nextTransactionId++,
      from_account: transactionData.from_account,
      to_account: transactionData.to_account,
      amount: transactionData.amount,
      currency: transactionData.currency,
      explanation: transactionData.explanation,
      sender_name: transactionData.sender_name,
      receiver_name: transactionData.receiver_name,
      is_external: transactionData.is_external || false,
      status: transactionData.status || 'pending',
      created_at: new Date().toISOString(),
      exchanged_amount: transactionData.exchanged_amount,
      exchanged_currency: transactionData.exchanged_currency
    };
    dataStore.transactions.push(transaction);
    return transaction;
  },

  findAccountTransactions: (accountNumber) => {
    return dataStore.transactions
      .filter(transaction => 
        transaction.from_account === accountNumber || 
        transaction.to_account === accountNumber
      )
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  },

  findAccountByNumber: (accountNumber) => {
    return dataStore.accounts.find(acc => acc.account_number === accountNumber);
  }
};

// Exchange rates data
const exchangeRates = {
  EUR: {
    USD: 1.09,
    GBP: 0.86,
    SEK: 11.21
  },
  USD: {
    EUR: 0.92,
    GBP: 0.79,
    SEK: 10.28
  },
  GBP: {
    EUR: 1.16,
    USD: 1.27,
    SEK: 13.03
  },
  SEK: {
    EUR: 0.089,
    USD: 0.097,
    GBP: 0.077
  }
};

// Express app setup
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Swagger UI
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ status: 'error', message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = dataStoreHelpers.findUserById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ status: 'error', message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ status: 'error', message: 'Invalid token' });
  }
};

// Key management setup
const privateKeyPath = path.join(__dirname, 'keys', 'private.pem');
const publicKeyPath = path.join(__dirname, 'keys', 'public.pem');

// Ensure keys directory exists
const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
  fs.mkdirSync(keysDir);
}

// Read or generate keys
let privateKey, publicKey;
try {
  privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  publicKey = fs.readFileSync(publicKeyPath, 'utf8');
  console.log('[Key Management] Loaded existing keys');
} catch (err) {
  console.log('[Key Management] No keys found, generating new keys...');
  const { privateKey: newPrivateKey, publicKey: newPublicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // Save the keys
  fs.writeFileSync(privateKeyPath, newPrivateKey);
  fs.writeFileSync(publicKeyPath, newPublicKey);
  
  privateKey = newPrivateKey;
  publicKey = newPublicKey;
  console.log('[Key Management] Generated and saved new keys');
}

// Generate JWKS from public key
const getJwks = () => {
  try {
    // Parse the public key
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const pemContents = publicKey
      .replace(pemHeader, '')
      .replace(pemFooter, '')
      .replace(/\s/g, '');

    // Create modulus and exponent components
    const publicKeyObject = crypto.createPublicKey({
      key: publicKey,
      format: 'pem'
    });

    const keyData = publicKeyObject.export({ format: 'jwk' });

    // Create a key ID if it doesn't exist
    const kid = uuidv4();

    // Return JWKS format
    return {
      keys: [
        {
          kty: "RSA",
          kid: kid,
          use: "sig",
          alg: "RS256",
          n: keyData.n,
          e: keyData.e
        }
      ]
    };
  } catch (error) {
    console.error('[Key Management] Error generating JWKS:', error);
    return { keys: [] };
  }
};

// JWT Key Management
const jwtKeys = getJwks();

// Add key manager
const keyManager = {
  sign: (payload) => {
    try {
      // Create JWT with proper claims
      const token = jwt.sign({
        accountFrom: payload.accountFrom,
        accountTo: payload.accountTo,
        amount: payload.amount,
        currency: payload.currency,
        senderName: payload.senderName,
        explanation: payload.explanation
      }, privateKey, {
        algorithm: 'RS256',
        keyid: jwtKeys.keys[0].kid,
        header: {
          alg: 'RS256',
          kid: jwtKeys.keys[0].kid,
          typ: 'JWT'
        }
      });

      console.log('[JWT Sign] Generated token');
      return token;
    } catch (error) {
      console.error('[JWT Sign] Error signing JWT:', error);
      throw error;
    }
  }
};

// Routes
app.get('/bank-info', (req, res) => {
  res.json({
    name: process.env.BANK_NAME || 'Bank API',
    prefix: process.env.BANK_PREFIX || 'BANK'
  });
});

app.get('/jwks.json', (req, res) => {
  res.json(jwtKeys);
});

app.post('/users', [
  body('username').isString().trim().isLength({ min: 3 }),
  body('password').isString().isLength({ min: 6 }),
  body('fullName').isString().trim().notEmpty(),
  body('email').isString().trim().isEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ status: 'error', errors: errors.array() });
    }

    const { username, password, fullName, email } = req.body;

    // Check if user exists
    if (dataStoreHelpers.findUserByUsername(username)) {
      return res.status(400).json({
        status: 'error',
        message: 'Username already exists'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await dataStoreHelpers.createUser({
      username,
      password: hashedPassword,
      full_name: fullName,
      email
    });

    res.status(201).json({
      status: 'success',
      message: 'User registered successfully'
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error during registration'
    });
  }
});

app.post('/sessions', [
  body('username').isString().trim(),
  body('password').isString()
], async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = dataStoreHelpers.findUserByUsername(username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      status: 'success',
      token,
      user: {
        id: user.id,
        username: user.username,
        fullName: user.full_name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error during login'
    });
  }
});

app.delete('/sessions', authenticate, (req, res) => {
  res.json({
    status: 'success',
    message: 'Successfully logged out'
  });
});

app.get('/users/me', authenticate, async (req, res) => {
  try {
    const user = dataStoreHelpers.findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Remove password from response
    const { password, ...userData } = user;
    res.json({ status: 'success', data: userData });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error fetching profile'
    });
  }
});

app.post('/accounts', authenticate, [
  body('currency').isIn(['EUR', 'USD', 'GBP', 'SEK']),
  body('name').isString().trim().notEmpty()
], async (req, res) => {
  try {
    const { currency, name } = req.body;
    const account = dataStoreHelpers.createAccount({
      account_number: `${process.env.BANK_PREFIX || 'BANK'}${Date.now()}`,
      user_id: req.user.id,
      currency,
      name,
      balance: 1000
    });

    res.status(201).json({
      status: 'success',
      data: account,
      message: 'Account created successfully with initial balance of 1000'
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error creating account'
    });
  }
});

app.get('/accounts', authenticate, async (req, res) => {
  try {
    const { currency, sort } = req.query;
    let accounts = dataStoreHelpers.findUserAccounts(req.user.id);

    // Filter by currency if specified
    if (currency) {
      accounts = accounts.filter(account => account.currency === currency);
    }

    // Sort accounts if specified
    if (sort) {
      const [field, direction] = sort.startsWith('-') ? [sort.slice(1), -1] : [sort, 1];
      accounts.sort((a, b) => {
        if (field === 'balance') return direction * (a.balance - b.balance);
        if (field === 'name') return direction * a.name.localeCompare(b.name);
        if (field === 'createdAt') return direction * (new Date(a.created_at) - new Date(b.created_at));
        return 0;
      });
    }

    res.json({ status: 'success', data: accounts });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error fetching accounts'
    });
  }
});

app.post('/transfers/internal', authenticate, [
  body('fromAccount').isString(),
  body('toAccount').isString(),
  body('amount').isFloat({ min: 0 }),
  body('explanation').isString().trim().notEmpty()
], async (req, res) => {
  try {
    const { fromAccount, toAccount, amount, explanation } = req.body;
    
    // Find source and destination accounts
    const sourceAccount = dataStoreHelpers.findAccountByNumber(fromAccount);
    if (!sourceAccount) {
      return res.status(404).json({
        status: 'error',
        message: 'Source account not found'
      });
    }

    const destAccount = dataStoreHelpers.findAccountByNumber(toAccount);
    if (!destAccount) {
      return res.status(404).json({
        status: 'error',
        message: 'Destination account not found'
      });
    }

    // Verify ownership
    if (sourceAccount.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access forbidden - not your account'
      });
    }

    // Check sufficient funds
    if (sourceAccount.balance < amount) {
      return res.status(402).json({
        status: 'error',
        message: 'Insufficient funds'
      });
    }

    // Check same currency
    if (sourceAccount.currency !== destAccount.currency) {
      return res.status(400).json({
        status: 'error',
        message: 'Cannot transfer between accounts with different currencies'
      });
    }

    // Create transaction record
    const transaction = dataStoreHelpers.createTransaction({
      from_account: fromAccount,
      to_account: toAccount,
      amount,
      currency: sourceAccount.currency,
      explanation,
      sender_name: req.user.full_name || 'User',
      receiver_name: destAccount.name,
      is_external: false
    });

    // Update account balances
    dataStoreHelpers.updateAccountBalance(fromAccount, -amount);
    dataStoreHelpers.updateAccountBalance(toAccount, amount);

    res.status(201).json({
      status: 'success',
      data: transaction,
      message: 'Internal transfer completed successfully'
    });
  } catch (error) {
    console.error('Internal transfer error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Server error processing internal transfer'
    });
  }
});

app.get('/transfers', authenticate, async (req, res) => {
  try {
    const userAccounts = dataStoreHelpers.findUserAccounts(req.user.id);
    const accountNumbers = userAccounts.map(account => account.account_number);
    
    const transactions = dataStore.transactions.filter(transaction => 
      accountNumbers.includes(transaction.from_account) || 
      accountNumbers.includes(transaction.to_account)
    ).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({
      status: 'success',
      data: transactions
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error fetching transactions'
    });
  }
});

app.get('/transfers/:id', authenticate, async (req, res) => {
  try {
    const transaction = dataStore.transactions.find(t => t.id === parseInt(req.params.id));
    
    if (!transaction) {
      return res.status(404).json({
        status: 'error',
        message: 'Transaction not found'
      });
    }

    const userAccounts = dataStoreHelpers.findUserAccounts(req.user.id);
    const accountNumbers = userAccounts.map(account => account.account_number);

    if (!accountNumbers.includes(transaction.from_account) && !accountNumbers.includes(transaction.to_account)) {
      return res.status(403).json({
        status: 'error',
        message: 'Access forbidden'
      });
    }

    res.json({
      status: 'success',
      data: transaction
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error fetching transaction'
    });
  }
});

app.get('/exchange-rates', (req, res) => {
  const { base, target } = req.query;
  const validCurrencies = ['EUR', 'USD', 'GBP', 'SEK'];

  if (!base || !validCurrencies.includes(base)) {
    return res.status(400).json({
      status: 'error',
      errors: [{
        msg: 'Base currency must be EUR, USD, GBP, or SEK'
      }]
    });
  }

  if (target && !validCurrencies.includes(target)) {
    return res.status(400).json({
      status: 'error',
      errors: [{
        msg: 'Target currency must be EUR, USD, GBP, or SEK'
      }]
    });
  }

  const response = {
    status: 'success',
    base,
    timestamp: new Date().toISOString(),
    rates: target ? { [target]: exchangeRates[base][target] } : exchangeRates[base]
  };

  res.json(response);
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'API is operational',
    timestamp: new Date().toISOString()
  });
});

// Bank-to-Bank transaction processing
const processB2BTransaction = async (jwt) => {
  try {
    console.log('[B2B Transaction] Starting JWT verification...');

    // Verify the JWT
    console.log('[B2B Transaction] Verifying JWT signature...');
    const decoded = jwt.verify(jwt, publicKey, { 
      algorithms: ['RS256']
    });
    
    console.log('[B2B Transaction] JWT verified successfully. Decoded payload:', JSON.stringify(decoded, null, 2));

    const { toAccount, fromAccount, amount, currency, senderName, explanation } = decoded;
    console.log(`[B2B Transaction] Processing transfer from ${fromAccount} to ${toAccount} for amount ${amount} ${currency}`);

    // Find the destination account
    const targetAccount = dataStoreHelpers.findAccountByNumber(toAccount);
    if (!targetAccount) {
      console.error(`[B2B Transaction] Destination account ${toAccount} not found`);
      throw new Error('Destination account not found');
    }

    // Convert amount if currencies differ
    let finalAmount = amount;
    if (targetAccount.currency !== currency) {
      console.log(`[B2B Transaction] Converting amount from ${currency} to ${targetAccount.currency}`);
      const rate = exchangeRates[currency][targetAccount.currency];
      if (!rate) {
        console.error(`[B2B Transaction] Unsupported currency conversion from ${currency} to ${targetAccount.currency}`);
        throw new Error('Unsupported currency conversion');
      }
      finalAmount = amount * rate;
      console.log(`[B2B Transaction] Converted amount: ${finalAmount} ${targetAccount.currency}`);
    }

    // Create and process the transaction
    console.log('[B2B Transaction] Creating transaction record...');
    const transaction = dataStoreHelpers.createTransaction({
      from_account: fromAccount,
      to_account: toAccount,
      amount: finalAmount,
      currency: targetAccount.currency,
      explanation: explanation || `External transfer from ${senderName}`,
      sender_name: senderName,
      receiver_name: targetAccount.name,
      is_external: true,
      status: 'completed'
    });

    // Update account balance
    console.log(`[B2B Transaction] Updating account balance for ${toAccount} with ${finalAmount}`);
    dataStoreHelpers.updateAccountBalance(toAccount, finalAmount);

    console.log('[B2B Transaction] Transaction completed successfully');
    return {
      status: 'success',
      receiverName: targetAccount.name,
      transactionId: transaction.id
    };
  } catch (error) {
    console.error('[B2B Transaction] Error processing transaction:', error);
    console.error('[B2B Transaction] Error stack:', error.stack);
    
    if (error.name === 'JsonWebTokenError') {
      console.error('[B2B Transaction] JWT verification failed:', error.message);
      throw new Error('Invalid JWT or signature');
    }
    if (error.name === 'TokenExpiredError') {
      console.error('[B2B Transaction] JWT has expired');
      throw new Error('JWT has expired');
    }
    throw error;
  }
};

// Routes
app.post('/transactions/b2b', async (req, res) => {
  try {
    const { jwt } = req.body;
    if (!jwt) {
      return res.status(400).json({
        status: 'error',
        message: 'JWT is required'
      });
    }

    const result = await processB2BTransaction(jwt);
    res.json(result);
  } catch (error) {
    if (error.message === 'Destination account not found') {
      return res.status(404).json({
        status: 'error',
        message: 'Destination account not found'
      });
    }
    if (error.message === 'Unsupported currency conversion') {
      return res.status(400).json({
        status: 'error',
        message: 'Unsupported currency conversion'
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid JWT or signature'
      });
    }
    res.status(500).json({
      status: 'error',
      message: 'Error processing transaction'
    });
  }
});

app.post('/transfers/incoming', async (req, res) => {
  try {
    const { jwt } = req.body;
    if (!jwt) {
      return res.status(400).json({
        status: 'error',
        message: 'JWT is required'
      });
    }

    const result = await processB2BTransaction(jwt);
    res.json(result);
  } catch (error) {
    if (error.message === 'Destination account not found') {
      return res.status(404).json({
        status: 'error',
        message: 'Destination account not found'
      });
    }
    if (error.message === 'Unsupported currency conversion') {
      return res.status(400).json({
        status: 'error',
        message: 'Unsupported currency conversion'
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid JWT or signature'
      });
    }
    res.status(500).json({
      status: 'error',
      message: 'Error processing transaction'
    });
  }
});

// Add central bank service
const centralBankService = {
  getBankDetails: async (bankPrefix) => {
    try {
      console.log(`[Central Bank] Starting bank lookup for prefix: ${bankPrefix}`);
      console.log(`[Central Bank] Fetching from: https://henno.cfd/central-bank/banks`);
      
      // Query the central bank's API for all banks
      const response = await fetch('https://henno.cfd/central-bank/banks');
      
      if (!response.ok) {
        console.error(`[Central Bank] Failed to get bank details. Status: ${response.status}`);
        console.error(`[Central Bank] Response headers:`, JSON.stringify(Object.fromEntries(response.headers.entries()), null, 2));
        return null;
      }

      const banks = await response.json();
      console.log(`[Central Bank] Retrieved ${banks.length} banks from registry`);
      
      // Find the bank with matching prefix
      const bankDetails = banks.find(bank => bank.bankPrefix === bankPrefix);
      
      if (!bankDetails) {
        console.error(`[Central Bank] Bank with prefix ${bankPrefix} not found in registry`);
        console.log(`[Central Bank] Available prefixes:`, banks.map(b => b.bankPrefix).join(', '));
        return null;
      }

      console.log(`[Central Bank] Found bank: ${bankDetails.name} (${bankDetails.bankPrefix})`);
      console.log(`[Central Bank] Transaction URL: ${bankDetails.transactionUrl}`);
      console.log(`[Central Bank] JWKS URL: ${bankDetails.jwksUrl}`);
      return bankDetails;
    } catch (error) {
      console.error(`[Central Bank] Error querying central bank for ${bankPrefix}:`, error);
      console.error(`[Central Bank] Error stack:`, error.stack);
      return null;
    }
  }
};

app.post('/transfers/external', authenticate, [
  body('fromAccount').isString(),
  body('toAccount').isString(),
  body('amount').isFloat({ min: 0 }),
  body('explanation').isString().trim().notEmpty()
], async (req, res) => {
  try {
    console.log('\n[External Transfer] Starting external transfer process...');
    console.log('[External Transfer] Request body:', JSON.stringify(req.body, null, 2));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('[External Transfer] Validation errors:', errors.array());
      return res.status(400).json({
        status: 'error',
        errors: errors.array()
      });
    }

    const { fromAccount, toAccount, amount, explanation } = req.body;
    console.log(`[External Transfer] Processing transfer from ${fromAccount} to ${toAccount} for amount ${amount}`);
    
    const sourceAccount = dataStoreHelpers.findAccountByNumber(fromAccount);
    if (!sourceAccount) {
      console.log(`[External Transfer] Source account ${fromAccount} not found`);
      return res.status(404).json({
        status: 'error',
        message: 'Source account not found'
      });
    }

    console.log('[External Transfer] Source account details:', {
      accountNumber: sourceAccount.account_number,
      balance: sourceAccount.balance,
      currency: sourceAccount.currency
    });

    if (sourceAccount.user_id !== req.user.id) {
      console.log(`[External Transfer] Access forbidden: User ${req.user.id} does not own account ${fromAccount}`);
      return res.status(403).json({
        status: 'error',
        message: 'Access forbidden - not your account'
      });
    }

    // Check sufficient funds
    if (sourceAccount.balance < amount) {
      console.log(`[External Transfer] Insufficient funds: Required ${amount}, Available ${sourceAccount.balance}`);
      return res.status(402).json({
        status: 'error',
        message: 'Insufficient funds'
      });
    }

    // Extract the bank prefix from toAccount (first 3 characters)
    const bankPrefix = toAccount.substring(0, 3);
    console.log(`[External Transfer] Extracted bank prefix: ${bankPrefix}`);
    
    // Check if this is actually an external transaction
    if (bankPrefix === process.env.BANK_PREFIX) {
      console.log('[External Transfer] Internal transfer detected, redirecting to internal endpoint');
      return res.status(400).json({
        status: 'error',
        message: 'For internal transfers please use /internal endpoint'
      });
    }

    // Create initial transaction record with pending status
    console.log('[External Transfer] Creating pending transaction record...');
    const transaction = dataStoreHelpers.createTransaction({
      from_account: fromAccount,
      to_account: toAccount,
      amount,
      currency: sourceAccount.currency,
      explanation,
      sender_name: req.user.full_name || 'User',
      receiver_name: 'External Account',
      is_external: true,
      status: 'pending',
      type: 'outgoing'
    });
    console.log('[External Transfer] Created transaction:', JSON.stringify(transaction, null, 2));

    try {
      console.log(`[External Transfer] Looking up bank with prefix: ${bankPrefix}`);
      
      // Get destination bank details from central bank
      const bankDetails = await centralBankService.getBankDetails(bankPrefix);
      
      if (!bankDetails) {
        console.error(`[External Transfer] No bank found with prefix ${bankPrefix}`);
        // Update transaction status to failed
        transaction.status = 'failed';
        transaction.explanation = explanation + ' (Destination bank not found)';
        
        return res.status(404).json({
          status: 'error',
          message: 'Destination bank not found'
        });
      }

      console.log('[External Transfer] Bank details retrieved:', JSON.stringify(bankDetails, null, 2));

      // Prepare payload for B2B transaction - simplified like Brigita Bank
      const payload = {
        accountFrom: fromAccount,
        accountTo: toAccount,
        amount: parseFloat(amount),
        currency: sourceAccount.currency,
        explanation,
        senderName: req.user.full_name || 'User'
      };
      console.log('[External Transfer] Prepared payload:', JSON.stringify(payload, null, 2));

      // Sign the payload with our private key
      console.log('[External Transfer] Signing JWT...');
      const jwtToken = keyManager.sign(payload);
      console.log('[External Transfer] JWT signed successfully');
      
      console.log(`[External Transfer] Sending transaction to ${bankDetails.transactionUrl}`);
      
      // Add retry logic for the external transfer
      const maxRetries = 3;
      const retryDelay = 5000; // 5 seconds
      let lastError = null;

      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          console.log(`[External Transfer] Attempt ${attempt} of ${maxRetries}`);
          const controller = new AbortController();
          const timeoutId = setTimeout(() => {
            console.log(`[External Transfer] Request timeout after 30 seconds on attempt ${attempt}`);
            controller.abort();
          }, 30000); // 30 second timeout

          // Prepare the request body exactly as shown in the example
          const requestBody = {
            jwt: jwtToken
          };
          console.log('[External Transfer] Request body:', JSON.stringify(requestBody, null, 2));

          console.log('[External Transfer] Sending request to destination bank...');
          console.log('[External Transfer] Request details:', {
            url: bankDetails.transactionUrl,
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            }
          });

          const response = await fetch(bankDetails.transactionUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify(requestBody),
            signal: controller.signal,
            timeout: 30000,
            keepalive: true,
            dnsTimeout: 5000,
            connectTimeout: 5000
          });

          clearTimeout(timeoutId);
          console.log(`[External Transfer] Response status: ${response.status}`);
          console.log('[External Transfer] Response headers:', JSON.stringify(Object.fromEntries(response.headers.entries()), null, 2));

          if (!response.ok) {
            const errorText = await response.text();
            console.error(`[External Transfer] Destination bank responded with error: ${response.status}`, errorText);
            
            if (response.status === 504 && attempt < maxRetries) {
              console.log(`[External Transfer] Attempt ${attempt} failed with timeout, retrying in ${retryDelay/1000} seconds...`);
              await new Promise(resolve => setTimeout(resolve, retryDelay));
              continue;
            }
            
            throw new Error(`Destination bank responded with status: ${response.status} - ${errorText}`);
          }

          const result = await response.json();
          console.log(`[External Transfer] Transaction successful:`, JSON.stringify(result, null, 2));
          
          // Update transaction with receiver name and status
          transaction.status = 'completed';
          if (result && result.receiverName) {
            transaction.receiver_name = result.receiverName;
          }

          // Update source account balance
          console.log(`[External Transfer] Updating source account balance: ${fromAccount} -${amount}`);
          dataStoreHelpers.updateAccountBalance(fromAccount, -amount);

          // Format response data
          const transactionData = {
            id: transaction.id,
            fromAccount: transaction.from_account,
            toAccount: transaction.to_account,
            amount: parseFloat(transaction.amount),
            currency: transaction.currency,
            explanation: transaction.explanation,
            senderName: transaction.sender_name,
            receiverName: transaction.receiver_name,
            status: transaction.status,
            createdAt: transaction.created_at,
            isExternal: true
          };

          console.log('[External Transfer] Sending success response:', JSON.stringify(transactionData, null, 2));
          return res.status(201).json({
            status: 'success',
            data: transactionData
          });

        } catch (error) {
          console.error(`[External Transfer] Error on attempt ${attempt}:`, error);
          console.error(`[External Transfer] Error details:`, {
            name: error.name,
            message: error.message,
            code: error.code,
            stack: error.stack
          });
          lastError = error;
          
          // Handle different types of errors
          if (error.name === 'AbortError' || error.code === 'ETIMEDOUT' || error.code === 'ECONNRESET') {
            if (attempt < maxRetries) {
              console.log(`[External Transfer] Attempt ${attempt} failed with timeout/connection error, retrying in ${retryDelay/1000} seconds...`);
              await new Promise(resolve => setTimeout(resolve, retryDelay));
              continue;
            }
          }
          
          throw error;
        }
      }

      // If we get here, all retries failed
      console.error('[External Transfer] All retry attempts failed:', lastError);
      throw lastError;

    } catch (error) {
      // Transaction failed
      console.error('[External Transfer] External transfer error:', error);
      console.error('[External Transfer] Error stack:', error.stack);
      
      // Update transaction as failed with specific error message
      transaction.status = 'failed';
      let errorMessage = error.message;
      if (error.name === 'AbortError') {
        errorMessage = 'Connection timeout - destination bank not responding';
      } else if (error.code === 'ETIMEDOUT') {
        errorMessage = 'Connection timeout - destination bank not responding';
      } else if (error.code === 'ECONNRESET') {
        errorMessage = 'Connection reset - destination bank closed the connection';
      }
      
      transaction.explanation = explanation + ` (Error: ${errorMessage})`;
      
      res.status(500).json({
        status: 'error',
        message: `External transfer failed: ${errorMessage}`,
        transactionData: transaction
      });
    }
  } catch (error) {
    console.error('[External Transfer] Error creating external transaction:', error);
    console.error('[External Transfer] Error stack:', error.stack);
    res.status(500).json({
      status: 'error',
      message: 'Error creating external transaction'
    });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`API Documentation available at http://localhost:${PORT}/docs`);
}); 
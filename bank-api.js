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
      id: dataStore.transactions.length + 1,
      from_account: transactionData.from_account,
      to_account: transactionData.to_account,
      amount: transactionData.amount,
      currency: transactionData.currency,
      explanation: transactionData.explanation,
      sender_name: transactionData.sender_name,
      receiver_name: transactionData.receiver_name,
      is_external: transactionData.is_external || false,
      status: 'COMPLETED',
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
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

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

// JWT Key Management
const jwtKeys = {
  keys: [
    {
      kty: 'RSA',
      kid: '1',
      use: 'sig',
      alg: 'RS256',
      n: process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n') || 'your-public-key',
      e: 'AQAB'
    }
  ]
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
    const decoded = jwt.verify(jwt, process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n') || 'your-public-key');
    const { toAccount, amount, currency, senderName } = decoded;

    const targetAccount = dataStoreHelpers.findAccountById(toAccount);
    if (!targetAccount) {
      throw new Error('Destination account not found');
    }

    // Convert amount if currencies differ
    let finalAmount = amount;
    if (targetAccount.currency !== currency) {
      const rate = exchangeRates[currency][targetAccount.currency];
      if (!rate) {
        throw new Error('Unsupported currency conversion');
      }
      finalAmount = amount * rate;
    }

    // Create and process the transaction
    const transaction = dataStoreHelpers.createTransaction({
      from_account: 'EXTERNAL',
      to_account: toAccount,
      amount: finalAmount,
      currency: targetAccount.currency,
      explanation: `External transfer from ${senderName}`,
      sender_name: senderName,
      receiver_name: targetAccount.name,
      is_external: true
    });

    // Update account balance
    dataStoreHelpers.updateAccountBalance(toAccount, finalAmount);

    return {
      status: 'success',
      receiverName: targetAccount.name,
      transactionId: transaction.id
    };
  } catch (error) {
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

app.post('/transfers/external', authenticate, [
  body('fromAccount').isString(),
  body('toAccount').isString(),
  body('amount').isFloat({ min: 0 }),
  body('currency').isIn(['EUR', 'USD', 'GBP', 'SEK']),
  body('explanation').isString().trim().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: 'error',
        errors: errors.array()
      });
    }

    const { fromAccount, toAccount, amount, currency, explanation } = req.body;
    
    const sourceAccount = dataStoreHelpers.findAccountByNumber(fromAccount);
    if (!sourceAccount) {
      return res.status(404).json({
        status: 'error',
        message: 'Source account not found'
      });
    }

    if (sourceAccount.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access forbidden - not your account'
      });
    }

    // Calculate final amount with currency conversion if needed
    let debitAmount = amount;
    if (sourceAccount.currency !== currency) {
      try {
        // First convert to EUR if source is not EUR
        let amountInEUR = amount;
        if (currency !== 'EUR') {
          if (!exchangeRates[currency] || !exchangeRates[currency]['EUR']) {
            return res.status(400).json({
              status: 'error',
              message: `Unsupported currency conversion from ${currency} to EUR`
            });
          }
          const rateToEUR = exchangeRates[currency]['EUR'];
          amountInEUR = amount * rateToEUR;
        }
        
        // Then convert from EUR to source account currency if needed
        if (sourceAccount.currency !== 'EUR') {
          if (!exchangeRates['EUR'] || !exchangeRates['EUR'][sourceAccount.currency]) {
            return res.status(400).json({
              status: 'error',
              message: `Unsupported currency conversion from EUR to ${sourceAccount.currency}`
            });
          }
          const rateFromEUR = exchangeRates['EUR'][sourceAccount.currency];
          debitAmount = amountInEUR * rateFromEUR;
        } else {
          debitAmount = amountInEUR;
        }
      } catch (conversionError) {
        console.error('Currency conversion error:', conversionError);
        return res.status(400).json({
          status: 'error',
          message: 'Error during currency conversion'
        });
      }
    }

    // Check sufficient funds using amount in source account's currency
    if (sourceAccount.balance < debitAmount) {
      return res.status(402).json({
        status: 'error',
        message: 'Insufficient funds'
      });
    }

    // Create transaction record
    const transaction = dataStoreHelpers.createTransaction({
      from_account: fromAccount,
      to_account: toAccount,
      amount: debitAmount,
      currency: sourceAccount.currency,
      explanation,
      sender_name: req.user.full_name || 'User',
      receiver_name: 'External Account',
      is_external: true,
      exchanged_amount: amount,
      exchanged_currency: currency
    });

    if (!transaction) {
      throw new Error('Failed to create transaction record');
    }

    // Update source account balance
    const balanceUpdated = dataStoreHelpers.updateAccountBalance(fromAccount, -debitAmount);
    if (!balanceUpdated) {
      throw new Error('Failed to update account balance');
    }

    res.status(201).json({
      status: 'success',
      data: transaction,
      message: 'External transfer initiated successfully'
    });
  } catch (error) {
    console.error('External transfer error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Server error processing external transfer',
      details: error.message
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
  console.log(`API Documentation available at http://localhost:${PORT}/api-docs`);
}); 
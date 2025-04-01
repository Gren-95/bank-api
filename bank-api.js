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
      balance: 0,
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

  updateAccountBalance: (accountId, amount) => {
    const account = dataStore.accounts.find(acc => acc.id === accountId);
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
      ...transactionData,
      status: 'COMPLETED',
      created_at: new Date().toISOString()
    };
    dataStore.transactions.push(transaction);
    return transaction;
  },

  findAccountTransactions: (accountId) => {
    return dataStore.transactions
      .filter(transaction => transaction.account_id === accountId)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
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
      name
    });

    res.status(201).json({
      status: 'success',
      data: account,
      message: 'Account created successfully'
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
    
    const sourceAccount = dataStoreHelpers.findAccountById(fromAccount);
    const targetAccount = dataStoreHelpers.findAccountById(toAccount);

    if (!sourceAccount || !targetAccount) {
      return res.status(404).json({
        status: 'error',
        message: 'Account not found'
      });
    }

    if (sourceAccount.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access forbidden'
      });
    }

    if (sourceAccount.balance < amount) {
      return res.status(402).json({
        status: 'error',
        message: 'Insufficient funds'
      });
    }

    const transaction = dataStoreHelpers.createTransaction({
      from_account: fromAccount,
      to_account: toAccount,
      amount,
      explanation,
      sender_name: req.user.full_name,
      receiver_name: targetAccount.name,
      is_external: false
    });

    // Update account balances
    dataStoreHelpers.updateAccountBalance(fromAccount, -amount);
    dataStoreHelpers.updateAccountBalance(toAccount, amount);

    res.status(201).json({
      status: 'success',
      data: transaction
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Server error creating transaction'
    });
  }
});

app.get('/transfers', authenticate, async (req, res) => {
  try {
    const userAccounts = dataStoreHelpers.findUserAccounts(req.user.id);
    const accountIds = userAccounts.map(account => account.id);
    
    const transactions = dataStore.transactions.filter(transaction => 
      accountIds.includes(transaction.from_account) || 
      accountIds.includes(transaction.to_account)
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

app.get('/transfers/{id}', authenticate, async (req, res) => {
  try {
    const transaction = dataStore.transactions.find(t => t.id === parseInt(req.params.id));
    
    if (!transaction) {
      return res.status(404).json({
        status: 'error',
        message: 'Transaction not found'
      });
    }

    const userAccounts = dataStoreHelpers.findUserAccounts(req.user.id);
    const accountIds = userAccounts.map(account => account.id);

    if (!accountIds.includes(transaction.from_account) && !accountIds.includes(transaction.to_account)) {
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

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'API is operational',
    timestamp: new Date().toISOString()
  });
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
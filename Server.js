const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000', 
  credentials: true
}));


const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'pennyplan_db',
  password: 'admin123',
  port: 5432,
});


const jwtSecret = 'your_very_secure_secret_key_123!';


const createToken = (userId) => {
  return jwt.sign({ userId }, jwtSecret, { expiresIn: '1h' });
};


const authenticateUser = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ error: 'Authorization token required' });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err); 
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.userId = decoded.userId;
    console.log('Authenticated user ID:', req.userId); 
    next();
  });
};


app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

 
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

 
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);


    const newUser = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hashedPassword]
    );

  
    const token = createToken(newUser.rows[0].id);

    console.log('User signed up:', newUser.rows[0].id); 
    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: newUser.rows[0].id,
        username: newUser.rows[0].username,
        email: newUser.rows[0].email,
      },
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = createToken(user.id);

    console.log('User logged in:', user.id); 
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});


app.get('/api/verify', authenticateUser, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [req.userId]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('Token verified for user:', req.userId); 
    res.json({ user: rows[0] });
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/transactions', authenticateUser, async (req, res) => {
  try {
    console.log('Fetching transactions for user:', req.userId); 
    const { rows } = await pool.query(
      `SELECT id, date, type, category, amount, description 
       FROM transactions 
       WHERE user_id = $1 
       ORDER BY date DESC`,
      [req.userId]
    );

    const transactions = rows.map((t) => ({
      ...t,
      amount: parseFloat(t.amount),
    }));

    console.log('Transactions found:', transactions); 
    res.json(transactions);
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ error: 'Failed to retrieve transactions' });
  }
});

app.post('/api/transactions', authenticateUser, async (req, res) => {
  const { date, type, category, amount, description } = req.body;

  try {
 
    if (!date || !type || !category || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (isNaN(amount)) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    console.log('Adding transaction for user:', req.userId, 'Data:', req.body);
 
    const { rows } = await pool.query(
      `INSERT INTO transactions 
       (user_id, date, type, category, amount, description)
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, date, type, category, amount, description`,
      [req.userId, date, type, category, amount, description || null]
    );

    console.log('Transaction added:', rows[0]); 
    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Error adding transaction:', error);
    res.status(500).json({ error: 'Failed to create transaction' });
  }
});


app.delete('/api/transactions/:id', authenticateUser, async (req, res) => {
  try {
    console.log('Deleting transaction ID:', req.params.id, 'for user:', req.userId);
    const result = await pool.query(
      'DELETE FROM transactions WHERE id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );

    if (result.rowCount === 0) {
      console.log('Transaction not found or unauthorized'); 
      return res.status(404).json({ error: 'Transaction not found or unauthorized' });
    }

    console.log('Transaction deleted successfully'); 
    res.json({ message: 'Transaction deleted successfully' });
  } catch (error) {
    console.error('Error deleting transaction:', error);
    res.status(500).json({ error: 'Server error deleting transaction' });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
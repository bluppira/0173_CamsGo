require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./src/config/db');
const verifyToken = require('./src/middleware/auth');

const app = express();
app.use(cors());
app.use(express.json());

app.use('/auth', require('./src/routes/auth'));

app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ message: 'CamsGo API jalan', time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/users/me', verifyToken, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, nama, email, role FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json(r.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server jalan di port ${PORT}`));
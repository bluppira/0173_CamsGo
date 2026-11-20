const { Pool } = require('pg');
require('dotenv').config();

const raw = process.env.DATABASE_URL || '';
const url = raw.split('?')[0];
const isLocal = url.includes('localhost') || url.includes('127.0.0.1');

const pool = new Pool({
  connectionString: url,
  ssl: isLocal ? false : { rejectUnauthorized: false },
});

module.exports = pool;
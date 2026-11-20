const bcrypt = require('bcrypt'); // kalau gagal install, pakai 'bcryptjs'
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
require('dotenv').config();

const makeAccessToken = (user) =>
  jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });

const makeRefreshToken = (user) =>
  jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

exports.register = async (req, res) => {
  try {
    const { nama, email, password } = req.body;
    if (!nama || !email || !password)
      return res.status(400).json({ error: 'Nama, email, dan password wajib diisi' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password minimal 6 karakter' });

    const domain = process.env.ALLOWED_EMAIL_DOMAIN;
    if (!email.toLowerCase().endsWith('@' + domain))
      return res.status(400).json({ error: `Gunakan email kampus (@${domain})` });

    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length > 0)
      return res.status(409).json({ error: 'Email sudah terdaftar' });

    const hash = await bcrypt.hash(password, 10);
    const user = await pool.query(
      'INSERT INTO users (nama, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [nama, email.toLowerCase(), hash]
    );

    const kode = String(Math.floor(100000 + Math.random() * 900000));
    await pool.query(
      `INSERT INTO otp_codes (user_id, kode, expired_at)
       VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`,
      [user.rows[0].id, kode]
    );

    // Sementara OTP ditampilkan di console. Ganti dengan kirim email (nodemailer) nanti.
    console.log(`OTP untuk ${email}: ${kode}`);

    res.status(201).json({ message: 'Registrasi berhasil, cek email untuk kode OTP' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.verifyOtp = async (req, res) => {
  try {
    const { email, kode } = req.body;
    const u = await pool.query('SELECT id FROM users WHERE email = $1', [(email || '').toLowerCase()]);
    if (u.rows.length === 0) return res.status(404).json({ error: 'Akun tidak ditemukan' });

    const otp = await pool.query(
      `SELECT id FROM otp_codes
       WHERE user_id = $1 AND kode = $2 AND expired_at > NOW()`,
      [u.rows[0].id, kode]
    );
    if (otp.rows.length === 0)
      return res.status(400).json({ error: 'Kode OTP salah atau sudah kedaluwarsa' });

    await pool.query('UPDATE users SET is_verified = TRUE WHERE id = $1', [u.rows[0].id]);
    await pool.query('DELETE FROM otp_codes WHERE user_id = $1', [u.rows[0].id]);
    res.json({ message: 'Verifikasi berhasil, silakan login' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email = $1', [(email || '').toLowerCase()]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password || '', user.password_hash)))
      return res.status(401).json({ error: 'Email atau password salah' });
    if (!user.is_verified)
      return res.status(403).json({ error: 'Akun belum diverifikasi' });

    const accessToken = makeAccessToken(user);
    const refreshToken = makeRefreshToken(user);
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token, expired_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [user.id, refreshToken]
    );

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, nama: user.nama, email: user.email, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token wajib diisi' });

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      return res.status(401).json({ error: 'Refresh token tidak valid' });
    }

    const t = await pool.query(
      `SELECT id FROM refresh_tokens
       WHERE token = $1 AND revoked = FALSE AND expired_at > NOW()`,
      [refreshToken]
    );
    if (t.rows.length === 0)
      return res.status(401).json({ error: 'Refresh token sudah dicabut atau kedaluwarsa' });

    const u = await pool.query('SELECT id, role FROM users WHERE id = $1', [payload.id]);
    res.json({ accessToken: makeAccessToken(u.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    await pool.query('UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1', [refreshToken]);
    res.json({ message: 'Logout berhasil' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
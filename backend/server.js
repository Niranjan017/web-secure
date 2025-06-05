require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/authcheck');
const scanRoutes = require('./routes/scan');
const userRoutes = require('./routes/user');        // <-- Added user routes here
const authenticateToken = require('./middleware/authenticateToken');

const app = express();

// Setup PostgreSQL pool and export it for reuse
const pool = new Pool();
// If you want to use pool elsewhere, export from a separate file like db.js
// module.exports = pool;

app.use(cors());
app.use(express.json());

// Serve frontend static files without authentication
app.use(express.static(path.join(__dirname, '../frontend')));

// Public routes (no auth required)
app.use('/api/auth', authRoutes);

// Protected API routes with JWT authentication middleware
app.use('/api/dashboard', authenticateToken, dashboardRoutes);
app.use('/api/scan', authenticateToken, scanRoutes);
app.use('/api/user', authenticateToken, userRoutes);   // <-- Mounted user routes with auth
app.use('/api/report', authenticateToken, dashboardRoutes);

// Secure frontend pages with authentication
const protectedPages = [
  '/',
  '/about.html',
  '/blog.html',
  '/career.html',
  '/contact.html',
  '/dash.html',
  '/report.html',
  '/scan.html',
  '/terms.html'
];

app.get(protectedPages, authenticateToken, (req, res) => {
  const filePath = req.path === '/' ? 'index.html' : req.path;
  res.sendFile(path.join(__dirname, '../frontend', filePath));
});

// Public login page (no auth)
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

// 404 fallback for unknown routes
app.use((req, res) => {
  res.status(404).send('Page not found');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});

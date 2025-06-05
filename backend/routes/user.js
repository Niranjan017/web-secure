const express = require('express');
const pool = require('../db'); // DB connection file ka sahi path set karein
const authenticateToken = require('../middleware/authenticateToken');

const router = express.Router();

// GET /api/user — authenticated user info fetch karne ke liye
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId; // JWT token se userId uthayein
    const userQuery = `
      SELECT id, name, email, profile_picture, role
      FROM users
      WHERE id = $1
    `;
    const { rows } = await pool.query(userQuery, [userId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

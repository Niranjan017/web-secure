const express = require('express');
const router = express.Router();
const pool = require('../db'); // Your PostgreSQL pool or client setup

// POST /api/scansave
router.post('/scansave', async (req, res) => {
  const { scanName, url, status, critical, high, medium, low, duration, pdf_report } = req.body;

  if (!scanName || !url) {
    return res.status(400).json({ error: 'Missing scanName or url' });
  }

  try {
    // base64 pdf_report ko buffer mein convert karo (agar diya ho)
    const pdfBuffer = pdf_report ? Buffer.from(pdf_report, 'base64') : null;

    const query = `
      INSERT INTO scan (title, url, status, critical, high, medium, low, duration, pdf_report)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id
    `;

    const values = [
      scanName,
      url,
      status || 'pending',
      critical || 0,
      high || 0,
      medium || 0,
      low || 0,
      duration || null,
      pdfBuffer
    ];

    const result = await pool.query(query, values);

    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error saving scan data:', err);
    res.status(500).json({ error: 'Database insert failed' });
  }
});

module.exports = router;

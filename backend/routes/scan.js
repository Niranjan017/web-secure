const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const path = require('path');
const pool = require('../db'); // Your DB connection

// JWT auth middleware for protected routes
const authenticateToken = require('../middleware/authenticateToken');

// Python script paths
const scannerScripts = {
  xss: path.join(__dirname, '../scanner/x.py'),
  sqli: path.join(__dirname, '../scanner/si.py'),
  headers: path.join(__dirname, '../scanner/security_headers.py'),
  csrf: path.join(__dirname, '../scanner/cs.py'),
  port: path.join(__dirname, '../scanner/ps.py')
};

// Run shell command helper
function runCommand(command) {
  return new Promise((resolve) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error running command: ${command}`, error.message);
        return resolve({ success: false, error: error.message });
      }
      return resolve({ success: true, output: stdout || stderr });
    });
  });
}

// Ensure URL has http/https scheme
function ensureUrlHasScheme(url) {
  if (!/^https?:\/\//i.test(url)) {
    return 'http://' + url;
  }
  return url;
}

// POST /api/scan — run scan
router.post('/', async (req, res) => {
  let { target, selectedChecks = [], portScan = {} } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'Target (URL or IP) is required.' });
  }

  target = ensureUrlHasScheme(target);
  console.log('Scan request:', { target, selectedChecks, portScan });

  const results = {};
  const scanPromises = [];

  try {
    for (const check of selectedChecks) {
      const scriptPath = scannerScripts[check];
      if (!scriptPath) {
        results[check] = { success: false, error: 'Unknown scanner type' };
        continue;
      }
      const command = `python "${scriptPath}" ${target}`;
      console.log(`Running command: ${command}`);
      scanPromises.push(
        runCommand(command).then(result => {
          results[check] = result;
        })
      );
    }

    if (portScan.enabled) {
      const start = Number(portScan.start);
      const end = Number(portScan.end);
      if (start > 0 && end > 0 && start <= end) {
        const range = `${start}-${end}`;
        const portCommand = `python "${scannerScripts.port}" --range ${range} ${target}`;
        console.log(`Running port scan: ${portCommand}`);
        scanPromises.push(
          runCommand(portCommand).then(result => {
            results.port = result;
          })
        );
      } else {
        results.port = { success: false, error: 'Invalid port range' };
      }
    }

    await Promise.all(scanPromises);

    res.json({
      message: 'Scan completed',
      target,
      results
    });

  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ error: 'Failed to process scan.' });
  }
});

// GET /api/scan — test API
router.get('/', (req, res) => {
  res.json({ message: 'Scan API is working' });
});

// GET /api/scan/data — get saved scans (latest 50) for logged-in user only
router.get('/data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized: Missing user ID' });
    }

    const query = `
      SELECT id, title, url, status, critical, high, medium, low, duration, user_id, scan_date
      FROM scan
      WHERE user_id = $1
      ORDER BY scan_date DESC
      LIMIT 50
    `;
    const values = [userId];
    const result = await pool.query(query, values);

    res.json(result.rows);
  } catch (err) {
    console.error('DB fetch error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/scan/scansave — save scan results with PDF (protected)
router.post('/scansave', authenticateToken, async (req, res) => {
  const userId = req.user?.userId;
  console.log('User ID from token:', userId);

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized: Missing user ID' });
  }

  const {
    scanName,
    url,
    status,
    critical,
    high,
    medium,
    low,
    duration,
    pdf_report // base64 string
  } = req.body;

  if (!scanName || !url) {
    return res.status(400).json({ error: 'Missing scanName or url' });
  }

  if (!pdf_report) {
    return res.status(400).json({ error: 'Missing pdf_report data' });
  }

  try {
    // Convert base64 string to Buffer for bytea column
    const pdfBuffer = Buffer.from(pdf_report, 'base64');

    const query = `
      INSERT INTO scan (title, url, status, critical, high, medium, low, duration, user_id, pdf_report, scan_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING id
    `;

    const values = [
      scanName,
      url,
      status,
      critical || 0,
      high || 0,
      medium || 0,
      low || 0,
      duration || null,
      userId,
      pdfBuffer
    ];

    const result = await pool.query(query, values);
    res.json({ success: true, id: result.rows[0].id });

  } catch (err) {
    console.error('DB insert error:', err);
    res.status(500).json({ error: 'Failed to save scan data' });
  }
});

// NEW ROUTE: GET /api/scan/report/:scanId — download PDF report (protected)
router.get('/report/:scanId', authenticateToken, async (req, res) => {
  const userId = req.user?.userId;
  const scanId = req.params.scanId;

  // Add debug logs here:
  console.log('Token userId:', userId, 'Requested scanId:', scanId);

  try {
    const query = `
      SELECT pdf_report, user_id
      FROM scan
      WHERE id = $1
    `;
    const values = [scanId];
    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      console.log('No report found for scanId:', scanId);
      return res.status(404).json({ error: 'Report not found' });
    }

    const report = result.rows[0];

    console.log('Report userId:', report.user_id);

    if (report.user_id !== userId) {
      console.log('User ID mismatch. Access denied.');
      return res.status(403).json({ error: 'Access denied' });
    }

    if (!report.pdf_report) {
      console.log('PDF report is empty for scanId:', scanId);
      return res.status(404).json({ error: 'PDF report not available' });
    }

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="scan_report_${scanId}.pdf"`,
    });

    res.send(report.pdf_report);

  } catch (err) {
    console.error('DB fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch PDF report' });
  }
});


module.exports = router;

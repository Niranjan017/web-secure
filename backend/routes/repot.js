const express = require('express');
const router = express.Router();
const pool = require('../db');

// Get all scan reports for authenticated user
router.get('/', async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const query = `
      SELECT 
        scan_id as id,
        scan_name as title,
        url,
        status,
        critical,
        high,
        medium,
        low,
        duration,
        created_at as date,
        EXTRACT(EPOCH FROM created_at) as timestamp
      FROM scans 
      WHERE user_id = $1
      ORDER BY created_at DESC
    `;
    
    const { rows } = await pool.query(query, [userId]);
    
    // Format data for chart
    const chartData = {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [
          rows.reduce((sum, report) => sum + (report.critical || 0), 0),
          rows.reduce((sum, report) => sum + (report.high || 0), 0),
          rows.reduce((sum, report) => sum + (report.medium || 0), 0),
          rows.reduce((sum, report) => sum + (report.low || 0), 0)
        ],
        backgroundColor: [
          '#dc3545', // Critical - red
          '#fd7e14', // High - orange
          '#ffc107', // Medium - yellow
          '#28a745'  // Low - green
        ]
      }]
    };
    
    res.json({
      reports: rows,
      chartData
    });
    
  } catch (err) {
    console.error('Error fetching reports:', err);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

module.exports = router;
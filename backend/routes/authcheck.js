const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/authenticateToken');


router.get('/', authenticateToken, (req, res) => {
  res.json({
    message: `Welcome to your dashboard, ${req.user.email}!`,
    user: req.user,
  });
});

module.exports = router;

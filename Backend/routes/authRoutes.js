const express = require('express');
const router = express.Router();
const { loginDashboardA, loginDashboardB } = require('../controllers/loginController');
const { getDashboardA, getDashboardB } = require('../controllers/dashboardController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/dashboardA/login', loginDashboardA);
router.post('/dashboardB/login', loginDashboardB);

router.get('/dashboardA/data', authMiddleware, getDashboardA);
router.get('/dashboardB/data', authMiddleware, getDashboardB);

router.get('/verify-token', authMiddleware, (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Token is valid',
    user: req.user,
  });
});

module.exports = router;

const { verifyToken } = require('../utils/jwt');

const authMiddleware = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const result = verifyToken(token);

    if (!result.valid) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = result.decoded;
    next();
  } catch (error) {
    res.status(500).json({ error: 'Authentication error' });
  }
};

module.exports = authMiddleware;

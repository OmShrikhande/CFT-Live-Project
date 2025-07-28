import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { logger } from '../utils/logger.js';

// Verify JWT token
export const authenticate = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    // Make sure token exists
    if (!token) {
      return res.status(401).json({
        status: 'error',
        message: 'Access denied. No token provided.'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from token
      const user = await User.findById(decoded.id)
        .populate('organization', 'name code isActive')
        .select('-password -refreshTokens');

      if (!user) {
        return res.status(401).json({
          status: 'error',
          message: 'Token is not valid. User not found.'
        });
      }

      // Check if user is active
      if (!user.isActive) {
        return res.status(401).json({
          status: 'error',
          message: 'Account is deactivated.'
        });
      }

      // Check if user account is locked
      if (user.isLocked) {
        return res.status(401).json({
          status: 'error',
          message: 'Account is temporarily locked due to too many failed login attempts.'
        });
      }

      // Check if organization is active
      if (!user.organization.isActive) {
        return res.status(401).json({
          status: 'error',
          message: 'Organization is not active.'
        });
      }

      req.user = user;
      next();
    } catch (error) {
      logger.error(`Token verification failed: ${error.message}`);
      return res.status(401).json({
        status: 'error',
        message: 'Token is not valid.'
      });
    }
  } catch (error) {
    logger.error(`Authentication error: ${error.message}`);
    res.status(500).json({
      status: 'error',
      message: 'Server error during authentication'
    });
  }
};

// Check if user has required role
export const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        message: 'Access denied. Please authenticate first.'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        message: `Access denied. Required role: ${roles.join(' or ')}`
      });
    }

    next();
  };
};

// Check if user belongs to the same organization
export const checkOrganization = async (req, res, next) => {
  try {
    const { organizationId } = req.params;
    
    if (!organizationId) {
      return next(); // Skip if no organization ID in params
    }

    if (req.user.organization._id.toString() !== organizationId) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied. You can only access resources from your organization.'
      });
    }

    next();
  } catch (error) {
    logger.error(`Organization check error: ${error.message}`);
    res.status(500).json({
      status: 'error',
      message: 'Server error during organization verification'
    });
  }
};

// Check if admin can access user data
export const checkAdminAccess = async (req, res, next) => {
  try {
    const { userId } = req.params;
    
    if (!userId) {
      return next(); // Skip if no user ID in params
    }

    // Super admin can access all users in their organization
    if (req.user.role === 'super_admin') {
      return next();
    }

    // Admin can only access users assigned to them
    if (req.user.role === 'admin') {
      const user = await User.findById(userId).select('assignedAdmin organization');
      
      if (!user) {
        return res.status(404).json({
          status: 'error',
          message: 'User not found'
        });
      }

      // Check if user belongs to same organization
      if (user.organization.toString() !== req.user.organization._id.toString()) {
        return res.status(403).json({
          status: 'error',
          message: 'Access denied. User belongs to different organization.'
        });
      }

      // Check if user is assigned to this admin
      if (user.assignedAdmin.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          status: 'error',
          message: 'Access denied. User is not assigned to you.'
        });
      }
    }

    next();
  } catch (error) {
    logger.error(`Admin access check error: ${error.message}`);
    res.status(500).json({
      status: 'error',
      message: 'Server error during access verification'
    });
  }
};

// Check if user has specific permission
export const checkPermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        message: 'Access denied. Please authenticate first.'
      });
    }

    if (!req.user.permissions[permission]) {
      return res.status(403).json({
        status: 'error',
        message: `Access denied. Missing permission: ${permission}`
      });
    }

    next();
  };
};

// Rate limiting for sensitive operations
export const sensitiveOperationLimit = (req, res, next) => {
  // This would typically use Redis for distributed rate limiting
  // For now, we'll use a simple in-memory approach
  const key = `${req.user._id}-${req.route.path}`;
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute
  const maxAttempts = 5;

  if (!req.app.locals.rateLimitStore) {
    req.app.locals.rateLimitStore = new Map();
  }

  const store = req.app.locals.rateLimitStore;
  const userAttempts = store.get(key) || [];

  // Remove old attempts outside the window
  const recentAttempts = userAttempts.filter(timestamp => now - timestamp < windowMs);

  if (recentAttempts.length >= maxAttempts) {
    return res.status(429).json({
      status: 'error',
      message: 'Too many sensitive operations. Please try again later.'
    });
  }

  // Add current attempt
  recentAttempts.push(now);
  store.set(key, recentAttempts);

  next();
};

// Middleware to log user actions
export const logUserAction = (action) => {
  return (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log the action after successful response
      if (res.statusCode < 400) {
        logger.info(`User Action: ${req.user.email} performed ${action}`, {
          userId: req.user._id,
          action,
          method: req.method,
          url: req.originalUrl,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          timestamp: new Date().toISOString()
        });
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};
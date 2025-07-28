import express from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.js';
import Organization from '../models/Organization.js';
import { authenticate, authorize } from '../middleware/auth.js';
import { catchAsync, AppError, validationError } from '../middleware/errorHandler.js';
import { logger } from '../utils/logger.js';

const router = express.Router();

// Validation rules
const registerValidation = [
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('organizationCode')
    .trim()
    .isLength({ min: 3, max: 10 })
    .withMessage('Organization code must be between 3 and 10 characters')
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// @desc    Register user
// @route   POST /api/v1/auth/register
// @access  Public
router.post('/register', registerValidation, catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { firstName, lastName, email, password, organizationCode, role = 'user' } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User with this email already exists', 400));
  }

  // Find organization
  const organization = await Organization.findByCode(organizationCode);
  if (!organization) {
    return next(new AppError('Invalid organization code', 400));
  }

  // Check if organization is active
  if (!organization.isActive) {
    return next(new AppError('Organization is not active', 400));
  }

  // For admin registration, check if organization can add more admins
  if (role === 'admin' && !organization.canAddAdmin()) {
    return next(new AppError('Organization has reached maximum admin limit', 400));
  }

  // Create user
  const userData = {
    firstName,
    lastName,
    email,
    password,
    role,
    organization: organization._id,
    metadata: {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    }
  };

  // If registering as user, assign to an admin (for now, assign to first available admin)
  if (role === 'user') {
    const availableAdmin = await User.findOne({
      organization: organization._id,
      role: 'admin',
      isActive: true
    });

    if (!availableAdmin) {
      return next(new AppError('No available admin to assign user to', 400));
    }

    userData.assignedAdmin = availableAdmin._id;
  }

  const user = await User.create(userData);

  // Add admin to organization if role is admin
  if (role === 'admin') {
    organization.admins.push(user._id);
    await organization.save();
  }

  // Generate tokens
  const token = user.generateAuthToken();
  const refreshToken = user.generateRefreshToken();
  await user.save();

  logger.info(`New user registered: ${email} as ${role} in organization ${organizationCode}`);

  res.status(201).json({
    status: 'success',
    message: 'User registered successfully',
    data: {
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        organization: {
          id: organization._id,
          name: organization.name,
          code: organization.code
        }
      },
      token,
      refreshToken
    }
  });
}));

// @desc    Login user
// @route   POST /api/v1/auth/login
// @access  Public
router.post('/login', loginValidation, catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { email, password } = req.body;

  // Check if user exists and get password
  const user = await User.findOne({ email, isActive: true })
    .select('+password')
    .populate('organization', 'name code isActive');

  if (!user) {
    return next(new AppError('Invalid email or password', 401));
  }

  // Check if account is locked
  if (user.isLocked) {
    return next(new AppError('Account is temporarily locked due to too many failed login attempts', 423));
  }

  // Check if organization is active
  if (!user.organization.isActive) {
    return next(new AppError('Organization is not active', 401));
  }

  // Check password
  const isPasswordCorrect = await user.comparePassword(password);

  if (!isPasswordCorrect) {
    // Increment login attempts
    await user.incLoginAttempts();
    return next(new AppError('Invalid email or password', 401));
  }

  // Reset login attempts on successful login
  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }

  // Update last login
  user.lastLogin = new Date();
  user.metadata.ipAddress = req.ip;
  user.metadata.userAgent = req.get('User-Agent');

  // Generate tokens
  const token = user.generateAuthToken();
  const refreshToken = user.generateRefreshToken();
  await user.save();

  logger.info(`User logged in: ${email}`);

  res.json({
    status: 'success',
    message: 'Login successful',
    data: {
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        organization: {
          id: user.organization._id,
          name: user.organization.name,
          code: user.organization.code
        },
        permissions: user.permissions,
        lastLogin: user.lastLogin
      },
      token,
      refreshToken
    }
  });
}));

// @desc    Refresh token
// @route   POST /api/v1/auth/refresh
// @access  Public
router.post('/refresh', catchAsync(async (req, res, next) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return next(new AppError('Refresh token is required', 400));
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Find user and check if refresh token exists
    const user = await User.findById(decoded.id)
      .populate('organization', 'name code isActive');

    if (!user || !user.refreshTokens.some(token => token.token === refreshToken)) {
      return next(new AppError('Invalid refresh token', 401));
    }

    // Check if user and organization are active
    if (!user.isActive || !user.organization.isActive) {
      return next(new AppError('Account or organization is not active', 401));
    }

    // Generate new tokens
    const newToken = user.generateAuthToken();
    const newRefreshToken = user.generateRefreshToken();

    // Remove old refresh token
    user.refreshTokens = user.refreshTokens.filter(token => token.token !== refreshToken);
    await user.save();

    res.json({
      status: 'success',
      message: 'Token refreshed successfully',
      data: {
        token: newToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    return next(new AppError('Invalid refresh token', 401));
  }
}));

// @desc    Logout user
// @route   POST /api/v1/auth/logout
// @access  Private
router.post('/logout', authenticate, catchAsync(async (req, res, next) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    // Remove specific refresh token
    req.user.refreshTokens = req.user.refreshTokens.filter(
      token => token.token !== refreshToken
    );
  } else {
    // Remove all refresh tokens (logout from all devices)
    req.user.refreshTokens = [];
  }

  await req.user.save();

  logger.info(`User logged out: ${req.user.email}`);

  res.json({
    status: 'success',
    message: 'Logout successful'
  });
}));

// @desc    Get current user
// @route   GET /api/v1/auth/me
// @access  Private
router.get('/me', authenticate, catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user._id)
    .populate('organization', 'name code')
    .populate('assignedAdmin', 'firstName lastName email');

  res.json({
    status: 'success',
    data: {
      user
    }
  });
}));

// @desc    Update user profile
// @route   PUT /api/v1/auth/profile
// @access  Private
router.put('/profile', authenticate, [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  body('profile.phone')
    .optional()
    .matches(/^\+?[\d\s-()]+$/)
    .withMessage('Please enter a valid phone number'),
  body('profile.bio')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Bio cannot exceed 500 characters')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const allowedFields = ['firstName', 'lastName', 'profile'];
  const updates = {};

  Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  updates['metadata.lastModifiedBy'] = req.user._id;

  const user = await User.findByIdAndUpdate(
    req.user._id,
    updates,
    { new: true, runValidators: true }
  ).populate('organization', 'name code');

  logger.info(`User profile updated: ${req.user.email}`);

  res.json({
    status: 'success',
    message: 'Profile updated successfully',
    data: {
      user
    }
  });
}));

// @desc    Change password
// @route   PUT /api/v1/auth/change-password
// @access  Private
router.put('/change-password', authenticate, [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { currentPassword, newPassword } = req.body;

  // Get user with password
  const user = await User.findById(req.user._id).select('+password');

  // Check current password
  const isCurrentPasswordCorrect = await user.comparePassword(currentPassword);
  if (!isCurrentPasswordCorrect) {
    return next(new AppError('Current password is incorrect', 400));
  }

  // Update password
  user.password = newPassword;
  user.metadata.lastModifiedBy = req.user._id;
  
  // Clear all refresh tokens (force re-login on all devices)
  user.refreshTokens = [];
  
  await user.save();

  logger.info(`Password changed for user: ${req.user.email}`);

  res.json({
    status: 'success',
    message: 'Password changed successfully. Please log in again.'
  });
}));

// @desc    Forgot password
// @route   POST /api/v1/auth/forgot-password
// @access  Public
router.post('/forgot-password', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { email } = req.body;

  const user = await User.findOne({ email, isActive: true });

  if (!user) {
    // Don't reveal if user exists or not
    return res.json({
      status: 'success',
      message: 'If an account with that email exists, a password reset link has been sent.'
    });
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  await user.save({ validateBeforeSave: false });

  // TODO: Send email with reset token
  // For now, we'll just log it
  logger.info(`Password reset requested for: ${email}, token: ${resetToken}`);

  res.json({
    status: 'success',
    message: 'If an account with that email exists, a password reset link has been sent.'
  });
}));

// @desc    Reset password
// @route   POST /api/v1/auth/reset-password/:token
// @access  Public
router.post('/reset-password/:token', [
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { token } = req.params;
  const { password } = req.body;

  // Hash token
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  // Find user with valid reset token
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
    isActive: true
  });

  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  // Update password
  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  user.refreshTokens = []; // Clear all refresh tokens

  await user.save();

  logger.info(`Password reset completed for user: ${user.email}`);

  res.json({
    status: 'success',
    message: 'Password has been reset successfully. Please log in with your new password.'
  });
}));

export default router;
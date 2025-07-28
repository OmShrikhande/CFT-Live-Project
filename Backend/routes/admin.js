import express from 'express';
import { body, query, validationResult } from 'express-validator';
import User from '../models/User.js';
import TransferRequest from '../models/TransferRequest.js';
import { authenticate, authorize, checkAdminAccess, checkPermission, logUserAction } from '../middleware/auth.js';
import { catchAsync, AppError, validationError } from '../middleware/errorHandler.js';
import { logger } from '../utils/logger.js';

const router = express.Router();

// Apply authentication and admin authorization to all routes
router.use(authenticate);
router.use(authorize('admin', 'super_admin'));

// @desc    Get admin dashboard data
// @route   GET /api/v1/admin/dashboard
// @access  Private (Admin)
router.get('/dashboard', catchAsync(async (req, res, next) => {
  const adminId = req.user._id;
  const organizationId = req.user.organization._id;

  // Get user statistics
  const userStats = await req.user.getUserStats();

  // Get recent transfer requests
  const recentTransfers = await TransferRequest.findByAdmin(adminId)
    .limit(10)
    .sort({ createdAt: -1 });

  // Get pending transfer requests
  const pendingTransfers = await TransferRequest.find({
    $or: [
      { fromAdmin: adminId },
      { toAdmin: adminId }
    ],
    status: 'pending',
    isActive: true
  }).countDocuments();

  // Get organization transfer statistics
  const transferStats = await TransferRequest.getStats(organizationId, 30);

  res.json({
    status: 'success',
    data: {
      userStats,
      transferStats,
      pendingTransfers,
      recentTransfers
    }
  });
}));

// @desc    Get all users assigned to admin
// @route   GET /api/v1/admin/users
// @access  Private (Admin)
router.get('/users', [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status'),
  query('search').optional().isLength({ min: 1, max: 100 }).withMessage('Search term must be between 1 and 100 characters')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  const { status, search } = req.query;

  // Build query
  const query = {
    assignedAdmin: req.user._id,
    role: 'user',
    isActive: true
  };

  if (status) {
    query.status = status;
  }

  if (search) {
    query.$or = [
      { firstName: { $regex: search, $options: 'i' } },
      { lastName: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } }
    ];
  }

  // Get users with pagination
  const users = await User.find(query)
    .select('-password -refreshTokens')
    .populate('organization', 'name code')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

  // Get total count
  const total = await User.countDocuments(query);

  res.json({
    status: 'success',
    data: {
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// @desc    Get specific user details
// @route   GET /api/v1/admin/users/:userId
// @access  Private (Admin)
router.get('/users/:userId', checkAdminAccess, catchAsync(async (req, res, next) => {
  const { userId } = req.params;

  const user = await User.findById(userId)
    .select('-password -refreshTokens')
    .populate('organization', 'name code')
    .populate('assignedAdmin', 'firstName lastName email')
    .populate('metadata.createdBy', 'firstName lastName email')
    .populate('metadata.lastModifiedBy', 'firstName lastName email');

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  res.json({
    status: 'success',
    data: {
      user
    }
  });
}));

// @desc    Create new user
// @route   POST /api/v1/admin/users
// @access  Private (Admin)
router.post('/users', checkPermission('canCreateUsers'), logUserAction('create_user'), [
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
  body('profile.phone')
    .optional()
    .matches(/^\+?[\d\s-()]+$/)
    .withMessage('Please enter a valid phone number')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { firstName, lastName, email, password, profile } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User with this email already exists', 400));
  }

  // Create user
  const userData = {
    firstName,
    lastName,
    email,
    password,
    role: 'user',
    organization: req.user.organization._id,
    assignedAdmin: req.user._id,
    profile: profile || {},
    metadata: {
      createdBy: req.user._id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    }
  };

  const user = await User.create(userData);

  // Populate user data for response
  await user.populate('organization', 'name code');
  await user.populate('assignedAdmin', 'firstName lastName email');

  logger.info(`New user created by admin ${req.user.email}: ${email}`);

  // Emit socket event for real-time updates
  if (req.io) {
    req.io.to(`admin-${req.user.organization._id}`).emit('user-created', {
      user: user.toJSON(),
      createdBy: req.user._id
    });
  }

  res.status(201).json({
    status: 'success',
    message: 'User created successfully',
    data: {
      user
    }
  });
}));

// @desc    Update user
// @route   PUT /api/v1/admin/users/:userId
// @access  Private (Admin)
router.put('/users/:userId', checkAdminAccess, checkPermission('canEditUsers'), logUserAction('update_user'), [
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
  body('status')
    .optional()
    .isIn(['active', 'inactive', 'suspended'])
    .withMessage('Invalid status'),
  body('profile.phone')
    .optional()
    .matches(/^\+?[\d\s-()]+$/)
    .withMessage('Please enter a valid phone number')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { userId } = req.params;
  const allowedFields = ['firstName', 'lastName', 'status', 'profile'];
  const updates = {};

  Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  updates['metadata.lastModifiedBy'] = req.user._id;

  const user = await User.findByIdAndUpdate(
    userId,
    updates,
    { new: true, runValidators: true }
  )
    .populate('organization', 'name code')
    .populate('assignedAdmin', 'firstName lastName email');

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  logger.info(`User updated by admin ${req.user.email}: ${user.email}`);

  // Emit socket event for real-time updates
  if (req.io) {
    req.io.to(`admin-${req.user.organization._id}`).emit('user-updated', {
      user: user.toJSON(),
      updatedBy: req.user._id
    });
  }

  res.json({
    status: 'success',
    message: 'User updated successfully',
    data: {
      user
    }
  });
}));

// @desc    Request user transfer
// @route   POST /api/v1/admin/users/:userId/transfer
// @access  Private (Admin)
router.post('/users/:userId/transfer', checkAdminAccess, checkPermission('canTransferUsers'), logUserAction('request_user_transfer'), [
  body('toAdminId')
    .isMongoId()
    .withMessage('Valid target admin ID is required'),
  body('reason')
    .trim()
    .isLength({ min: 10, max: 500 })
    .withMessage('Reason must be between 10 and 500 characters'),
  body('priority')
    .optional()
    .isIn(['low', 'medium', 'high', 'urgent'])
    .withMessage('Invalid priority level')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { userId } = req.params;
  const { toAdminId, reason, priority = 'medium' } = req.body;

  // Get user to be transferred
  const user = await User.findById(userId);
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  // Check if user can be transferred
  if (!user.canBeTransferred()) {
    return next(new AppError('User cannot be transferred in current state', 400));
  }

  // Check if target admin exists and is in same organization
  const targetAdmin = await User.findOne({
    _id: toAdminId,
    role: 'admin',
    organization: req.user.organization._id,
    isActive: true
  });

  if (!targetAdmin) {
    return next(new AppError('Target admin not found or not in same organization', 404));
  }

  // Check if trying to transfer to same admin
  if (user.assignedAdmin.toString() === toAdminId) {
    return next(new AppError('User is already assigned to this admin', 400));
  }

  // Check for existing pending transfer request
  const existingRequest = await TransferRequest.findOne({
    user: userId,
    status: 'pending',
    isActive: true
  });

  if (existingRequest) {
    return next(new AppError('There is already a pending transfer request for this user', 400));
  }

  // Create transfer request
  const transferRequest = await TransferRequest.create({
    user: userId,
    fromAdmin: req.user._id,
    toAdmin: toAdminId,
    organization: req.user.organization._id,
    requestedBy: req.user._id,
    reason,
    priority,
    metadata: {
      userDataSnapshot: user.toJSON(),
      fromAdminSnapshot: req.user.toJSON(),
      toAdminSnapshot: targetAdmin.toJSON(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      transferMethod: 'manual'
    }
  });

  // Populate transfer request for response
  await transferRequest.populate([
    { path: 'user', select: 'firstName lastName email' },
    { path: 'fromAdmin', select: 'firstName lastName email' },
    { path: 'toAdmin', select: 'firstName lastName email' },
    { path: 'requestedBy', select: 'firstName lastName email' }
  ]);

  logger.info(`Transfer request created by admin ${req.user.email} for user ${user.email} to admin ${targetAdmin.email}`);

  // Emit socket events for real-time notifications
  if (req.io) {
    // Notify super admin
    req.io.to(`super_admin-${req.user.organization._id}`).emit('new-transfer-request', {
      transferRequest: transferRequest.toJSON(),
      requestedBy: req.user._id
    });

    // Notify target admin
    req.io.to(`admin-${req.user.organization._id}`).emit('transfer-request-notification', {
      type: 'incoming',
      transferRequest: transferRequest.toJSON()
    });
  }

  res.status(201).json({
    status: 'success',
    message: 'Transfer request submitted successfully',
    data: {
      transferRequest
    }
  });
}));

// @desc    Get transfer requests
// @route   GET /api/v1/admin/transfers
// @access  Private (Admin)
router.get('/transfers', [
  query('status').optional().isIn(['pending', 'approved', 'rejected', 'cancelled']).withMessage('Invalid status'),
  query('type').optional().isIn(['incoming', 'outgoing', 'all']).withMessage('Invalid type'),
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  const { status, type = 'all' } = req.query;

  // Build query based on type
  let query = { isActive: true };

  switch (type) {
    case 'incoming':
      query.toAdmin = req.user._id;
      break;
    case 'outgoing':
      query.fromAdmin = req.user._id;
      break;
    default:
      query.$or = [
        { fromAdmin: req.user._id },
        { toAdmin: req.user._id }
      ];
  }

  if (status) {
    query.status = status;
  }

  // Get transfer requests with pagination
  const transfers = await TransferRequest.find(query)
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .populate('approvedBy', 'firstName lastName email')
    .populate('rejectedBy', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

  // Get total count
  const total = await TransferRequest.countDocuments(query);

  res.json({
    status: 'success',
    data: {
      transfers,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// @desc    Cancel transfer request
// @route   DELETE /api/v1/admin/transfers/:transferId
// @access  Private (Admin)
router.delete('/transfers/:transferId', logUserAction('cancel_transfer_request'), catchAsync(async (req, res, next) => {
  const { transferId } = req.params;

  const transferRequest = await TransferRequest.findOne({
    _id: transferId,
    fromAdmin: req.user._id, // Only the requesting admin can cancel
    status: 'pending',
    isActive: true
  });

  if (!transferRequest) {
    return next(new AppError('Transfer request not found or cannot be cancelled', 404));
  }

  await transferRequest.cancel();

  logger.info(`Transfer request cancelled by admin ${req.user.email}: ${transferId}`);

  // Emit socket event
  if (req.io) {
    req.io.to(`super_admin-${req.user.organization._id}`).emit('transfer-request-cancelled', {
      transferId,
      cancelledBy: req.user._id
    });
  }

  res.json({
    status: 'success',
    message: 'Transfer request cancelled successfully'
  });
}));

// @desc    Get admin statistics
// @route   GET /api/v1/admin/stats
// @access  Private (Admin)
router.get('/stats', catchAsync(async (req, res, next) => {
  const { timeframe = 30 } = req.query;
  const days = parseInt(timeframe);

  if (isNaN(days) || days < 1 || days > 365) {
    return next(new AppError('Timeframe must be between 1 and 365 days', 400));
  }

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  // Get user statistics
  const userStats = await req.user.getUserStats();

  // Get user creation trend
  const userTrend = await User.aggregate([
    {
      $match: {
        assignedAdmin: req.user._id,
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  // Get transfer statistics
  const transferStats = await TransferRequest.aggregate([
    {
      $match: {
        $or: [
          { fromAdmin: req.user._id },
          { toAdmin: req.user._id }
        ],
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 }
      }
    }
  ]);

  res.json({
    status: 'success',
    data: {
      userStats,
      userTrend,
      transferStats,
      timeframe: days
    }
  });
}));

export default router;
import express from 'express';
import { query, validationResult } from 'express-validator';
import User from '../models/User.js';
import TransferRequest from '../models/TransferRequest.js';
import { authenticate, authorize } from '../middleware/auth.js';
import { catchAsync, AppError, validationError } from '../middleware/errorHandler.js';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticate);

// @desc    Get all users (for admins and super admins)
// @route   GET /api/v1/users
// @access  Private (Admin, Super Admin)
router.get('/', authorize('admin', 'super_admin'), [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status'),
  query('role').optional().isIn(['user', 'admin']).withMessage('Invalid role'),
  query('search').optional().isLength({ min: 1, max: 100 }).withMessage('Search term must be between 1 and 100 characters'),
  query('adminId').optional().isMongoId().withMessage('Invalid admin ID')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  const { status, role, search, adminId } = req.query;

  // Build query based on user role
  let query = {
    organization: req.user.organization._id,
    isActive: true
  };

  // If admin, only show users assigned to them
  if (req.user.role === 'admin') {
    query.assignedAdmin = req.user._id;
    query.role = 'user'; // Admins can only see regular users
  } else if (req.user.role === 'super_admin') {
    // Super admin can see all users except other super admins
    query.role = { $in: ['user', 'admin'] };
  }

  // Apply filters
  if (status) {
    query.status = status;
  }

  if (role && req.user.role === 'super_admin') {
    query.role = role;
  }

  if (adminId && req.user.role === 'super_admin') {
    query.assignedAdmin = adminId;
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
    .populate('assignedAdmin', 'firstName lastName email')
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

// @desc    Get user by ID
// @route   GET /api/v1/users/:userId
// @access  Private (Admin, Super Admin, Own User)
router.get('/:userId', catchAsync(async (req, res, next) => {
  const { userId } = req.params;

  // Check if user is trying to access their own data
  const isOwnData = req.user._id.toString() === userId;

  // Build query based on user role and access rights
  let query = { _id: userId, isActive: true };

  if (!isOwnData) {
    // If not own data, check permissions
    if (req.user.role === 'user') {
      return next(new AppError('Access denied. You can only view your own profile.', 403));
    } else if (req.user.role === 'admin') {
      // Admin can only see users assigned to them
      query.assignedAdmin = req.user._id;
      query.role = 'user';
    } else if (req.user.role === 'super_admin') {
      // Super admin can see all users in their organization except other super admins
      query.organization = req.user.organization._id;
      query.role = { $in: ['user', 'admin'] };
    }
  }

  const user = await User.findOne(query)
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

// @desc    Get user's transfer history
// @route   GET /api/v1/users/:userId/transfers
// @access  Private (Admin, Super Admin, Own User)
router.get('/:userId/transfers', catchAsync(async (req, res, next) => {
  const { userId } = req.params;

  // Check access permissions
  const isOwnData = req.user._id.toString() === userId;

  if (!isOwnData) {
    if (req.user.role === 'user') {
      return next(new AppError('Access denied. You can only view your own transfer history.', 403));
    } else if (req.user.role === 'admin') {
      // Check if user is assigned to this admin
      const user = await User.findOne({
        _id: userId,
        assignedAdmin: req.user._id,
        role: 'user',
        isActive: true
      });

      if (!user) {
        return next(new AppError('User not found or not assigned to you', 404));
      }
    } else if (req.user.role === 'super_admin') {
      // Check if user belongs to same organization
      const user = await User.findOne({
        _id: userId,
        organization: req.user.organization._id,
        isActive: true
      });

      if (!user) {
        return next(new AppError('User not found in your organization', 404));
      }
    }
  }

  // Get transfer history
  const transfers = await TransferRequest.find({
    user: userId,
    isActive: true
  })
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .populate('approvedBy', 'firstName lastName email')
    .populate('rejectedBy', 'firstName lastName email')
    .sort({ createdAt: -1 });

  res.json({
    status: 'success',
    data: {
      transfers
    }
  });
}));

// @desc    Get users by admin (for super admin)
// @route   GET /api/v1/users/admin/:adminId
// @access  Private (Super Admin)
router.get('/admin/:adminId', authorize('super_admin'), [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { adminId } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  const { status } = req.query;

  // Check if admin exists and belongs to same organization
  const admin = await User.findOne({
    _id: adminId,
    role: 'admin',
    organization: req.user.organization._id,
    isActive: true
  });

  if (!admin) {
    return next(new AppError('Admin not found in your organization', 404));
  }

  // Build query
  const query = {
    assignedAdmin: adminId,
    role: 'user',
    isActive: true
  };

  if (status) {
    query.status = status;
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
      admin: {
        id: admin._id,
        firstName: admin.firstName,
        lastName: admin.lastName,
        email: admin.email
      },
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

// @desc    Get user statistics
// @route   GET /api/v1/users/stats/overview
// @access  Private (Admin, Super Admin)
router.get('/stats/overview', authorize('admin', 'super_admin'), catchAsync(async (req, res, next) => {
  const { timeframe = 30 } = req.query;
  const days = parseInt(timeframe);

  if (isNaN(days) || days < 1 || days > 365) {
    return next(new AppError('Timeframe must be between 1 and 365 days', 400));
  }

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  let matchQuery = {
    organization: req.user.organization._id,
    createdAt: { $gte: startDate }
  };

  // If admin, only show stats for their users
  if (req.user.role === 'admin') {
    matchQuery.assignedAdmin = req.user._id;
    matchQuery.role = 'user';
  } else {
    // Super admin can see all users except super admins
    matchQuery.role = { $in: ['user', 'admin'] };
  }

  // Get user statistics
  const stats = await User.aggregate([
    { $match: matchQuery },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 }
      }
    }
  ]);

  // Get user creation trend
  const userTrend = await User.aggregate([
    { $match: matchQuery },
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

  // Format statistics
  const result = {
    total: 0,
    active: 0,
    inactive: 0,
    suspended: 0,
    pending: 0
  };

  stats.forEach(stat => {
    result.total += stat.count;
    result[stat._id] = stat.count;
  });

  res.json({
    status: 'success',
    data: {
      stats: result,
      trend: userTrend,
      timeframe: days
    }
  });
}));

export default router;
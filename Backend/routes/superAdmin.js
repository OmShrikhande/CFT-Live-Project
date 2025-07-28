import express from 'express';
import { body, query, validationResult } from 'express-validator';
import User from '../models/User.js';
import Organization from '../models/Organization.js';
import TransferRequest from '../models/TransferRequest.js';
import { authenticate, authorize, checkPermission, logUserAction, sensitiveOperationLimit } from '../middleware/auth.js';
import { catchAsync, AppError, validationError } from '../middleware/errorHandler.js';
import { logger } from '../utils/logger.js';

const router = express.Router();

// Apply authentication and super admin authorization to all routes
router.use(authenticate);
router.use(authorize('super_admin'));

// @desc    Get super admin dashboard data
// @route   GET /api/v1/super-admin/dashboard
// @access  Private (Super Admin)
router.get('/dashboard', catchAsync(async (req, res, next) => {
  const organizationId = req.user.organization._id;

  // Get organization statistics
  const orgStats = await req.user.organization.getStats();

  // Get pending transfer requests
  const pendingTransfers = await TransferRequest.findPendingForSuperAdmin(organizationId);

  // Get recent activities (last 10 transfer requests)
  const recentActivities = await TransferRequest.find({
    organization: organizationId,
    isActive: true
  })
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .sort({ createdAt: -1 })
    .limit(10);

  // Get transfer statistics for the last 30 days
  const transferStats = await TransferRequest.getStats(organizationId, 30);

  // Get admin performance metrics
  const adminPerformance = await User.aggregate([
    {
      $match: {
        organization: organizationId,
        role: 'admin',
        isActive: true
      }
    },
    {
      $lookup: {
        from: 'users',
        localField: '_id',
        foreignField: 'assignedAdmin',
        as: 'managedUsers'
      }
    },
    {
      $project: {
        firstName: 1,
        lastName: 1,
        email: 1,
        userCount: { $size: '$managedUsers' },
        lastLogin: 1
      }
    },
    { $sort: { userCount: -1 } }
  ]);

  res.json({
    status: 'success',
    data: {
      organizationStats: orgStats,
      pendingTransfers: pendingTransfers.length,
      transferStats,
      recentActivities,
      adminPerformance
    }
  });
}));

// @desc    Get all admins in organization
// @route   GET /api/v1/super-admin/admins
// @access  Private (Super Admin)
router.get('/admins', [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'inactive', 'suspended']).withMessage('Invalid status'),
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
    organization: req.user.organization._id,
    role: 'admin',
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

  // Get admins with their user counts
  const admins = await User.aggregate([
    { $match: query },
    {
      $lookup: {
        from: 'users',
        localField: '_id',
        foreignField: 'assignedAdmin',
        as: 'managedUsers'
      }
    },
    {
      $addFields: {
        userCount: { $size: '$managedUsers' }
      }
    },
    {
      $project: {
        password: 0,
        refreshTokens: 0,
        managedUsers: 0
      }
    },
    { $sort: { createdAt: -1 } },
    { $skip: skip },
    { $limit: limit }
  ]);

  // Get total count
  const total = await User.countDocuments(query);

  res.json({
    status: 'success',
    data: {
      admins,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  });
}));

// @desc    Create new admin
// @route   POST /api/v1/super-admin/admins
// @access  Private (Super Admin)
router.post('/admins', checkPermission('canManageAdmins'), logUserAction('create_admin'), sensitiveOperationLimit, [
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

  // Check if organization can add more admins
  const organization = await Organization.findById(req.user.organization._id);
  if (!organization.canAddAdmin()) {
    return next(new AppError('Organization has reached maximum admin limit', 400));
  }

  const { firstName, lastName, email, password, profile } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User with this email already exists', 400));
  }

  // Create admin
  const adminData = {
    firstName,
    lastName,
    email,
    password,
    role: 'admin',
    organization: req.user.organization._id,
    profile: profile || {},
    metadata: {
      createdBy: req.user._id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    }
  };

  const admin = await User.create(adminData);

  // Add admin to organization
  organization.admins.push(admin._id);
  await organization.save();

  // Populate admin data for response
  await admin.populate('organization', 'name code');

  logger.info(`New admin created by super admin ${req.user.email}: ${email}`);

  // Emit socket event for real-time updates
  if (req.io) {
    req.io.to(`super_admin-${req.user.organization._id}`).emit('admin-created', {
      admin: admin.toJSON(),
      createdBy: req.user._id
    });
  }

  res.status(201).json({
    status: 'success',
    message: 'Admin created successfully',
    data: {
      admin
    }
  });
}));

// @desc    Update admin
// @route   PUT /api/v1/super-admin/admins/:adminId
// @access  Private (Super Admin)
router.put('/admins/:adminId', checkPermission('canManageAdmins'), logUserAction('update_admin'), [
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

  const { adminId } = req.params;

  // Check if admin exists and belongs to same organization
  const admin = await User.findOne({
    _id: adminId,
    role: 'admin',
    organization: req.user.organization._id
  });

  if (!admin) {
    return next(new AppError('Admin not found', 404));
  }

  const allowedFields = ['firstName', 'lastName', 'status', 'profile'];
  const updates = {};

  Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  updates['metadata.lastModifiedBy'] = req.user._id;

  const updatedAdmin = await User.findByIdAndUpdate(
    adminId,
    updates,
    { new: true, runValidators: true }
  )
    .populate('organization', 'name code')
    .select('-password -refreshTokens');

  logger.info(`Admin updated by super admin ${req.user.email}: ${updatedAdmin.email}`);

  // Emit socket event for real-time updates
  if (req.io) {
    req.io.to(`super_admin-${req.user.organization._id}`).emit('admin-updated', {
      admin: updatedAdmin.toJSON(),
      updatedBy: req.user._id
    });
  }

  res.json({
    status: 'success',
    message: 'Admin updated successfully',
    data: {
      admin: updatedAdmin
    }
  });
}));

// @desc    Delete admin
// @route   DELETE /api/v1/super-admin/admins/:adminId
// @access  Private (Super Admin)
router.delete('/admins/:adminId', checkPermission('canManageAdmins'), logUserAction('delete_admin'), sensitiveOperationLimit, catchAsync(async (req, res, next) => {
  const { adminId } = req.params;

  // Check if admin exists and belongs to same organization
  const admin = await User.findOne({
    _id: adminId,
    role: 'admin',
    organization: req.user.organization._id
  });

  if (!admin) {
    return next(new AppError('Admin not found', 404));
  }

  // Check if admin has assigned users
  const assignedUsersCount = await User.countDocuments({
    assignedAdmin: adminId,
    isActive: true
  });

  if (assignedUsersCount > 0) {
    return next(new AppError(`Cannot delete admin. ${assignedUsersCount} users are still assigned to this admin. Please transfer users first.`, 400));
  }

  // Soft delete admin
  admin.isActive = false;
  admin.metadata.lastModifiedBy = req.user._id;
  await admin.save();

  // Remove admin from organization
  const organization = await Organization.findById(req.user.organization._id);
  organization.admins = organization.admins.filter(id => id.toString() !== adminId);
  await organization.save();

  logger.info(`Admin deleted by super admin ${req.user.email}: ${admin.email}`);

  // Emit socket event for real-time updates
  if (req.io) {
    req.io.to(`super_admin-${req.user.organization._id}`).emit('admin-deleted', {
      adminId,
      deletedBy: req.user._id
    });
  }

  res.json({
    status: 'success',
    message: 'Admin deleted successfully'
  });
}));

// @desc    Get all transfer requests
// @route   GET /api/v1/super-admin/transfers
// @access  Private (Super Admin)
router.get('/transfers', [
  query('status').optional().isIn(['pending', 'approved', 'rejected', 'cancelled']).withMessage('Invalid status'),
  query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']).withMessage('Invalid priority'),
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
  const { status, priority } = req.query;

  // Build query
  const query = {
    organization: req.user.organization._id,
    isActive: true
  };

  if (status) {
    query.status = status;
  }

  if (priority) {
    query.priority = priority;
  }

  // Get transfer requests with pagination
  const transfers = await TransferRequest.find(query)
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .populate('approvedBy', 'firstName lastName email')
    .populate('rejectedBy', 'firstName lastName email')
    .sort({ priority: -1, createdAt: -1 })
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

// @desc    Approve transfer request
// @route   POST /api/v1/super-admin/transfers/:transferId/approve
// @access  Private (Super Admin)
router.post('/transfers/:transferId/approve', logUserAction('approve_transfer'), [
  body('reason')
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Approval reason must be between 5 and 500 characters')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { transferId } = req.params;
  const { reason } = req.body;

  // Find transfer request
  const transferRequest = await TransferRequest.findOne({
    _id: transferId,
    organization: req.user.organization._id,
    status: 'pending',
    isActive: true
  })
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email');

  if (!transferRequest) {
    return next(new AppError('Transfer request not found or cannot be processed', 404));
  }

  // Check if request can be processed
  if (!transferRequest.canBeProcessed()) {
    return next(new AppError('Transfer request cannot be processed', 400));
  }

  // Approve the transfer
  await transferRequest.approve(req.user._id, reason);

  logger.info(`Transfer request approved by super admin ${req.user.email}: ${transferId}`);

  // Emit socket events for real-time notifications
  if (req.io) {
    // Notify all admins in organization
    req.io.to(`admin-${req.user.organization._id}`).emit('transfer-approved', {
      transferRequest: transferRequest.toJSON(),
      approvedBy: req.user._id
    });

    // Notify super admins
    req.io.to(`super_admin-${req.user.organization._id}`).emit('transfer-processed', {
      transferId,
      status: 'approved',
      processedBy: req.user._id
    });
  }

  res.json({
    status: 'success',
    message: 'Transfer request approved successfully',
    data: {
      transferRequest
    }
  });
}));

// @desc    Reject transfer request
// @route   POST /api/v1/super-admin/transfers/:transferId/reject
// @access  Private (Super Admin)
router.post('/transfers/:transferId/reject', logUserAction('reject_transfer'), [
  body('reason')
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Rejection reason must be between 5 and 500 characters')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { transferId } = req.params;
  const { reason } = req.body;

  // Find transfer request
  const transferRequest = await TransferRequest.findOne({
    _id: transferId,
    organization: req.user.organization._id,
    status: 'pending',
    isActive: true
  })
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email');

  if (!transferRequest) {
    return next(new AppError('Transfer request not found or cannot be processed', 404));
  }

  // Check if request can be processed
  if (!transferRequest.canBeProcessed()) {
    return next(new AppError('Transfer request cannot be processed', 400));
  }

  // Reject the transfer
  await transferRequest.reject(req.user._id, reason);

  logger.info(`Transfer request rejected by super admin ${req.user.email}: ${transferId}`);

  // Emit socket events for real-time notifications
  if (req.io) {
    // Notify all admins in organization
    req.io.to(`admin-${req.user.organization._id}`).emit('transfer-rejected', {
      transferRequest: transferRequest.toJSON(),
      rejectedBy: req.user._id
    });

    // Notify super admins
    req.io.to(`super_admin-${req.user.organization._id}`).emit('transfer-processed', {
      transferId,
      status: 'rejected',
      processedBy: req.user._id
    });
  }

  res.json({
    status: 'success',
    message: 'Transfer request rejected successfully',
    data: {
      transferRequest
    }
  });
}));

// @desc    Get organization statistics
// @route   GET /api/v1/super-admin/stats
// @access  Private (Super Admin)
router.get('/stats', [
  query('timeframe').optional().isInt({ min: 1, max: 365 }).withMessage('Timeframe must be between 1 and 365 days')
], catchAsync(async (req, res, next) => {
  const { timeframe = 30 } = req.query;
  const days = parseInt(timeframe);

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const organizationId = req.user.organization._id;

  // Get organization statistics
  const orgStats = await req.user.organization.getStats();

  // Get user growth trend
  const userGrowth = await User.aggregate([
    {
      $match: {
        organization: organizationId,
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          role: '$role'
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.date': 1 } }
  ]);

  // Get transfer statistics
  const transferStats = await TransferRequest.getStats(organizationId, days);

  // Get admin performance
  const adminPerformance = await User.aggregate([
    {
      $match: {
        organization: organizationId,
        role: 'admin',
        isActive: true
      }
    },
    {
      $lookup: {
        from: 'users',
        localField: '_id',
        foreignField: 'assignedAdmin',
        as: 'managedUsers'
      }
    },
    {
      $lookup: {
        from: 'transferrequests',
        localField: '_id',
        foreignField: 'fromAdmin',
        as: 'outgoingTransfers'
      }
    },
    {
      $lookup: {
        from: 'transferrequests',
        localField: '_id',
        foreignField: 'toAdmin',
        as: 'incomingTransfers'
      }
    },
    {
      $project: {
        firstName: 1,
        lastName: 1,
        email: 1,
        userCount: { $size: '$managedUsers' },
        outgoingTransferCount: { $size: '$outgoingTransfers' },
        incomingTransferCount: { $size: '$incomingTransfers' },
        lastLogin: 1
      }
    },
    { $sort: { userCount: -1 } }
  ]);

  res.json({
    status: 'success',
    data: {
      organizationStats: orgStats,
      userGrowth,
      transferStats,
      adminPerformance,
      timeframe: days
    }
  });
}));

// @desc    Update organization settings
// @route   PUT /api/v1/super-admin/organization
// @access  Private (Super Admin)
router.put('/organization', logUserAction('update_organization'), [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Organization name must be between 2 and 100 characters'),
  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('settings.maxAdmins')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Max admins must be between 1 and 100'),
  body('settings.maxUsersPerAdmin')
    .optional()
    .isInt({ min: 1, max: 10000 })
    .withMessage('Max users per admin must be between 1 and 10000'),
  body('settings.allowUserTransfer')
    .optional()
    .isBoolean()
    .withMessage('Allow user transfer must be a boolean'),
  body('settings.requireSuperAdminApproval')
    .optional()
    .isBoolean()
    .withMessage('Require super admin approval must be a boolean')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const allowedFields = ['name', 'description', 'address', 'contact', 'settings'];
  const updates = {};

  Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
      updates[key] = req.body[key];
    }
  });

  const organization = await Organization.findByIdAndUpdate(
    req.user.organization._id,
    updates,
    { new: true, runValidators: true }
  );

  logger.info(`Organization updated by super admin ${req.user.email}`);

  res.json({
    status: 'success',
    message: 'Organization updated successfully',
    data: {
      organization
    }
  });
}));

export default router;
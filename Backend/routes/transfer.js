import express from 'express';
import { body, query, validationResult } from 'express-validator';
import User from '../models/User.js';
import TransferRequest from '../models/TransferRequest.js';
import { authenticate, authorize, logUserAction } from '../middleware/auth.js';
import { catchAsync, AppError, validationError } from '../middleware/errorHandler.js';
import { logger } from '../utils/logger.js';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticate);

// @desc    Get all transfer requests (filtered by user role)
// @route   GET /api/v1/transfers
// @access  Private (Admin, Super Admin)
router.get('/', authorize('admin', 'super_admin'), [
  query('status').optional().isIn(['pending', 'approved', 'rejected', 'cancelled']).withMessage('Invalid status'),
  query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']).withMessage('Invalid priority'),
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
  const { status, priority, type = 'all' } = req.query;

  // Build query based on user role
  let query = {
    organization: req.user.organization._id,
    isActive: true
  };

  // Apply role-based filtering
  if (req.user.role === 'admin') {
    // Admin can see transfers involving them
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
  }
  // Super admin can see all transfers in organization (no additional filtering needed)

  // Apply status and priority filters
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

// @desc    Get transfer request by ID
// @route   GET /api/v1/transfers/:transferId
// @access  Private (Admin, Super Admin)
router.get('/:transferId', authorize('admin', 'super_admin'), catchAsync(async (req, res, next) => {
  const { transferId } = req.params;

  // Build query based on user role
  let query = {
    _id: transferId,
    organization: req.user.organization._id,
    isActive: true
  };

  // If admin, only show transfers involving them
  if (req.user.role === 'admin') {
    query.$or = [
      { fromAdmin: req.user._id },
      { toAdmin: req.user._id }
    ];
  }

  const transfer = await TransferRequest.findOne(query)
    .populate('user', 'firstName lastName email profile')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .populate('approvedBy', 'firstName lastName email')
    .populate('rejectedBy', 'firstName lastName email')
    .populate('history.performedBy', 'firstName lastName email');

  if (!transfer) {
    return next(new AppError('Transfer request not found', 404));
  }

  res.json({
    status: 'success',
    data: {
      transfer
    }
  });
}));

// @desc    Create bulk transfer request
// @route   POST /api/v1/transfers/bulk
// @access  Private (Admin)
router.post('/bulk', authorize('admin'), logUserAction('create_bulk_transfer'), [
  body('userIds')
    .isArray({ min: 1, max: 50 })
    .withMessage('User IDs must be an array with 1-50 items'),
  body('userIds.*')
    .isMongoId()
    .withMessage('Each user ID must be valid'),
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

  const { userIds, toAdminId, reason, priority = 'medium' } = req.body;

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
  if (req.user._id.toString() === toAdminId) {
    return next(new AppError('Cannot transfer users to yourself', 400));
  }

  // Get all users to be transferred
  const users = await User.find({
    _id: { $in: userIds },
    assignedAdmin: req.user._id,
    role: 'user',
    isActive: true
  });

  if (users.length !== userIds.length) {
    return next(new AppError('Some users not found or not assigned to you', 400));
  }

  // Check if any users cannot be transferred
  const nonTransferableUsers = users.filter(user => !user.canBeTransferred());
  if (nonTransferableUsers.length > 0) {
    return next(new AppError(`${nonTransferableUsers.length} users cannot be transferred in their current state`, 400));
  }

  // Check for existing pending transfer requests
  const existingRequests = await TransferRequest.find({
    user: { $in: userIds },
    status: 'pending',
    isActive: true
  });

  if (existingRequests.length > 0) {
    return next(new AppError(`${existingRequests.length} users already have pending transfer requests`, 400));
  }

  // Create transfer requests for all users
  const transferRequests = [];
  const targetAdminSnapshot = targetAdmin.toJSON();

  for (const user of users) {
    const transferRequest = await TransferRequest.create({
      user: user._id,
      fromAdmin: req.user._id,
      toAdmin: toAdminId,
      organization: req.user.organization._id,
      requestedBy: req.user._id,
      reason,
      priority,
      metadata: {
        userDataSnapshot: user.toJSON(),
        fromAdminSnapshot: req.user.toJSON(),
        toAdminSnapshot: targetAdminSnapshot,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        transferMethod: 'bulk'
      }
    });

    // Populate for response
    await transferRequest.populate([
      { path: 'user', select: 'firstName lastName email' },
      { path: 'fromAdmin', select: 'firstName lastName email' },
      { path: 'toAdmin', select: 'firstName lastName email' },
      { path: 'requestedBy', select: 'firstName lastName email' }
    ]);

    transferRequests.push(transferRequest);
  }

  logger.info(`Bulk transfer request created by admin ${req.user.email} for ${users.length} users to admin ${targetAdmin.email}`);

  // Emit socket events for real-time notifications
  if (req.io) {
    // Notify super admin
    req.io.to(`super_admin-${req.user.organization._id}`).emit('bulk-transfer-request', {
      transferRequests: transferRequests.map(tr => tr.toJSON()),
      requestedBy: req.user._id,
      count: transferRequests.length
    });

    // Notify target admin
    req.io.to(`admin-${req.user.organization._id}`).emit('bulk-transfer-notification', {
      type: 'incoming',
      count: transferRequests.length,
      fromAdmin: req.user._id,
      toAdmin: toAdminId
    });
  }

  res.status(201).json({
    status: 'success',
    message: `${transferRequests.length} transfer requests created successfully`,
    data: {
      transferRequests,
      summary: {
        total: transferRequests.length,
        priority,
        targetAdmin: {
          id: targetAdmin._id,
          name: `${targetAdmin.firstName} ${targetAdmin.lastName}`,
          email: targetAdmin.email
        }
      }
    }
  });
}));

// @desc    Get transfer statistics
// @route   GET /api/v1/transfers/stats/overview
// @access  Private (Admin, Super Admin)
router.get('/stats/overview', authorize('admin', 'super_admin'), [
  query('timeframe').optional().isInt({ min: 1, max: 365 }).withMessage('Timeframe must be between 1 and 365 days')
], catchAsync(async (req, res, next) => {
  const { timeframe = 30 } = req.query;
  const days = parseInt(timeframe);

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  // Build base query
  let baseQuery = {
    organization: req.user.organization._id,
    createdAt: { $gte: startDate }
  };

  // Apply role-based filtering
  if (req.user.role === 'admin') {
    baseQuery.$or = [
      { fromAdmin: req.user._id },
      { toAdmin: req.user._id }
    ];
  }

  // Get transfer statistics by status
  const statusStats = await TransferRequest.aggregate([
    { $match: baseQuery },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        avgProcessingTime: {
          $avg: {
            $cond: [
              { $in: ['$status', ['approved', 'rejected']] },
              { $subtract: ['$processedAt', '$createdAt'] },
              null
            ]
          }
        }
      }
    }
  ]);

  // Get transfer trend by day
  const transferTrend = await TransferRequest.aggregate([
    { $match: baseQuery },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          status: '$status'
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.date': 1 } }
  ]);

  // Get priority distribution
  const priorityStats = await TransferRequest.aggregate([
    { $match: baseQuery },
    {
      $group: {
        _id: '$priority',
        count: { $sum: 1 }
      }
    }
  ]);

  // Get top admins involved in transfers
  let adminStats = [];
  if (req.user.role === 'super_admin') {
    adminStats = await TransferRequest.aggregate([
      { $match: { organization: req.user.organization._id, createdAt: { $gte: startDate } } },
      {
        $group: {
          _id: '$fromAdmin',
          outgoingCount: { $sum: 1 }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'admin'
        }
      },
      {
        $unwind: '$admin'
      },
      {
        $project: {
          adminId: '$_id',
          adminName: { $concat: ['$admin.firstName', ' ', '$admin.lastName'] },
          adminEmail: '$admin.email',
          outgoingCount: 1
        }
      },
      { $sort: { outgoingCount: -1 } },
      { $limit: 10 }
    ]);
  }

  // Format status statistics
  const statusResult = {
    total: 0,
    pending: 0,
    approved: 0,
    rejected: 0,
    cancelled: 0,
    avgProcessingTimeHours: 0
  };

  let totalProcessingTime = 0;
  let processedCount = 0;

  statusStats.forEach(stat => {
    statusResult.total += stat.count;
    statusResult[stat._id] = stat.count;
    
    if (stat.avgProcessingTime) {
      totalProcessingTime += stat.avgProcessingTime * stat.count;
      processedCount += stat.count;
    }
  });

  if (processedCount > 0) {
    statusResult.avgProcessingTimeHours = Math.round(
      (totalProcessingTime / processedCount) / (1000 * 60 * 60) * 100
    ) / 100;
  }

  // Format priority statistics
  const priorityResult = {
    low: 0,
    medium: 0,
    high: 0,
    urgent: 0
  };

  priorityStats.forEach(stat => {
    priorityResult[stat._id] = stat.count;
  });

  res.json({
    status: 'success',
    data: {
      statusStats: statusResult,
      priorityStats: priorityResult,
      transferTrend,
      adminStats,
      timeframe: days
    }
  });
}));

// @desc    Get pending transfers requiring attention
// @route   GET /api/v1/transfers/pending/urgent
// @access  Private (Admin, Super Admin)
router.get('/pending/urgent', authorize('admin', 'super_admin'), catchAsync(async (req, res, next) => {
  // Build query based on user role
  let query = {
    organization: req.user.organization._id,
    status: 'pending',
    isActive: true,
    expiresAt: { $gt: new Date() }
  };

  // Apply role-based filtering
  if (req.user.role === 'admin') {
    query.$or = [
      { fromAdmin: req.user._id },
      { toAdmin: req.user._id }
    ];
  }

  // Get urgent and high priority transfers
  const urgentTransfers = await TransferRequest.find({
    ...query,
    priority: { $in: ['urgent', 'high'] }
  })
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .sort({ priority: -1, createdAt: 1 })
    .limit(20);

  // Get transfers expiring soon (within 24 hours)
  const expiringSoon = await TransferRequest.find({
    ...query,
    expiresAt: {
      $gt: new Date(),
      $lt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
    }
  })
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .sort({ expiresAt: 1 })
    .limit(10);

  res.json({
    status: 'success',
    data: {
      urgentTransfers,
      expiringSoon,
      counts: {
        urgent: urgentTransfers.length,
        expiring: expiringSoon.length
      }
    }
  });
}));

// @desc    Export transfer data
// @route   GET /api/v1/transfers/export
// @access  Private (Super Admin)
router.get('/export', authorize('super_admin'), [
  query('format').optional().isIn(['json', 'csv']).withMessage('Format must be json or csv'),
  query('status').optional().isIn(['pending', 'approved', 'rejected', 'cancelled']).withMessage('Invalid status'),
  query('startDate').optional().isISO8601().withMessage('Start date must be valid ISO date'),
  query('endDate').optional().isISO8601().withMessage('End date must be valid ISO date')
], catchAsync(async (req, res, next) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(validationError(errors));
  }

  const { format = 'json', status, startDate, endDate } = req.query;

  // Build query
  let query = {
    organization: req.user.organization._id,
    isActive: true
  };

  if (status) {
    query.status = status;
  }

  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }

  // Get transfer data
  const transfers = await TransferRequest.find(query)
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .populate('approvedBy', 'firstName lastName email')
    .populate('rejectedBy', 'firstName lastName email')
    .sort({ createdAt: -1 });

  if (format === 'csv') {
    // Convert to CSV format
    const csvHeaders = [
      'Transfer ID',
      'User Name',
      'User Email',
      'From Admin',
      'To Admin',
      'Status',
      'Priority',
      'Reason',
      'Requested Date',
      'Processed Date',
      'Requested By',
      'Processed By'
    ];

    const csvRows = transfers.map(transfer => [
      transfer._id,
      `${transfer.user.firstName} ${transfer.user.lastName}`,
      transfer.user.email,
      `${transfer.fromAdmin.firstName} ${transfer.fromAdmin.lastName}`,
      `${transfer.toAdmin.firstName} ${transfer.toAdmin.lastName}`,
      transfer.status,
      transfer.priority,
      transfer.reason,
      transfer.createdAt.toISOString(),
      transfer.processedAt ? transfer.processedAt.toISOString() : '',
      `${transfer.requestedBy.firstName} ${transfer.requestedBy.lastName}`,
      transfer.approvedBy ? `${transfer.approvedBy.firstName} ${transfer.approvedBy.lastName}` :
      transfer.rejectedBy ? `${transfer.rejectedBy.firstName} ${transfer.rejectedBy.lastName}` : ''
    ]);

    const csvContent = [csvHeaders, ...csvRows]
      .map(row => row.map(field => `"${field}"`).join(','))
      .join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="transfers-${Date.now()}.csv"`);
    return res.send(csvContent);
  }

  // Return JSON format
  res.json({
    status: 'success',
    data: {
      transfers,
      exportInfo: {
        totalRecords: transfers.length,
        exportDate: new Date().toISOString(),
        filters: { status, startDate, endDate }
      }
    }
  });
}));

export default router;
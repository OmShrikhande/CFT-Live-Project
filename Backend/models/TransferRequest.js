import mongoose from 'mongoose';

const transferRequestSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User to be transferred is required']
  },
  fromAdmin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Source admin is required']
  },
  toAdmin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Target admin is required']
  },
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: [true, 'Organization is required']
  },
  requestedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Requester is required']
  },
  reason: {
    type: String,
    required: [true, 'Transfer reason is required'],
    trim: true,
    maxlength: [500, 'Reason cannot exceed 500 characters']
  },
  status: {
    type: String,
    enum: {
      values: ['pending', 'approved', 'rejected', 'cancelled'],
      message: 'Status must be pending, approved, rejected, or cancelled'
    },
    default: 'pending'
  },
  priority: {
    type: String,
    enum: {
      values: ['low', 'medium', 'high', 'urgent'],
      message: 'Priority must be low, medium, high, or urgent'
    },
    default: 'medium'
  },
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return this.status === 'approved';
    }
  },
  rejectedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return this.status === 'rejected';
    }
  },
  approvalReason: {
    type: String,
    trim: true,
    maxlength: [500, 'Approval reason cannot exceed 500 characters'],
    required: function() {
      return this.status === 'approved' || this.status === 'rejected';
    }
  },
  processedAt: {
    type: Date,
    required: function() {
      return this.status === 'approved' || this.status === 'rejected';
    }
  },
  transferCompletedAt: {
    type: Date,
    required: function() {
      return this.status === 'approved';
    }
  },
  metadata: {
    userDataSnapshot: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    fromAdminSnapshot: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    toAdminSnapshot: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    ipAddress: String,
    userAgent: String,
    transferMethod: {
      type: String,
      enum: ['manual', 'bulk', 'automated'],
      default: 'manual'
    }
  },
  notifications: {
    userNotified: {
      type: Boolean,
      default: false
    },
    fromAdminNotified: {
      type: Boolean,
      default: false
    },
    toAdminNotified: {
      type: Boolean,
      default: false
    },
    superAdminNotified: {
      type: Boolean,
      default: false
    }
  },
  history: [{
    action: {
      type: String,
      enum: ['created', 'approved', 'rejected', 'cancelled', 'completed'],
      required: true
    },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    notes: String,
    metadata: mongoose.Schema.Types.Mixed
  }],
  expiresAt: {
    type: Date,
    default: function() {
      // Transfer requests expire after 7 days if not processed
      return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    }
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better performance
transferRequestSchema.index({ user: 1, status: 1 });
transferRequestSchema.index({ fromAdmin: 1, status: 1 });
transferRequestSchema.index({ toAdmin: 1, status: 1 });
transferRequestSchema.index({ organization: 1, status: 1 });
transferRequestSchema.index({ requestedBy: 1 });
transferRequestSchema.index({ status: 1, createdAt: -1 });
transferRequestSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Virtual for request age in hours
transferRequestSchema.virtual('ageInHours').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60));
});

// Virtual for time until expiry
transferRequestSchema.virtual('timeUntilExpiry').get(function() {
  if (this.status !== 'pending') return null;
  const timeLeft = this.expiresAt - Date.now();
  return timeLeft > 0 ? timeLeft : 0;
});

// Virtual to check if request is expired
transferRequestSchema.virtual('isExpired').get(function() {
  return this.status === 'pending' && this.expiresAt < Date.now();
});

// Pre-save middleware to add history entry
transferRequestSchema.pre('save', function(next) {
  if (this.isNew) {
    this.history.push({
      action: 'created',
      performedBy: this.requestedBy,
      timestamp: new Date(),
      notes: `Transfer request created for user ${this.user}`,
      metadata: {
        reason: this.reason,
        priority: this.priority
      }
    });
  } else if (this.isModified('status')) {
    let action = this.status;
    let performedBy;
    let notes;

    switch (this.status) {
      case 'approved':
        performedBy = this.approvedBy;
        notes = `Transfer request approved: ${this.approvalReason}`;
        this.processedAt = new Date();
        break;
      case 'rejected':
        performedBy = this.rejectedBy;
        notes = `Transfer request rejected: ${this.approvalReason}`;
        this.processedAt = new Date();
        break;
      case 'cancelled':
        performedBy = this.requestedBy;
        notes = 'Transfer request cancelled';
        break;
    }

    if (performedBy) {
      this.history.push({
        action,
        performedBy,
        timestamp: new Date(),
        notes,
        metadata: {
          approvalReason: this.approvalReason
        }
      });
    }
  }
  next();
});

// Static method to find pending requests for super admin
transferRequestSchema.statics.findPendingForSuperAdmin = function(organizationId) {
  return this.find({
    organization: organizationId,
    status: 'pending',
    isActive: true,
    expiresAt: { $gt: new Date() }
  })
  .populate('user', 'firstName lastName email')
  .populate('fromAdmin', 'firstName lastName email')
  .populate('toAdmin', 'firstName lastName email')
  .populate('requestedBy', 'firstName lastName email')
  .sort({ priority: -1, createdAt: -1 });
};

// Static method to find requests by admin
transferRequestSchema.statics.findByAdmin = function(adminId, status = null) {
  const query = {
    $or: [
      { fromAdmin: adminId },
      { toAdmin: adminId }
    ],
    isActive: true
  };

  if (status) {
    query.status = status;
  }

  return this.find(query)
    .populate('user', 'firstName lastName email')
    .populate('fromAdmin', 'firstName lastName email')
    .populate('toAdmin', 'firstName lastName email')
    .populate('requestedBy', 'firstName lastName email')
    .sort({ createdAt: -1 });
};

// Instance method to approve transfer
transferRequestSchema.methods.approve = async function(approvedBy, reason) {
  this.status = 'approved';
  this.approvedBy = approvedBy;
  this.approvalReason = reason;
  this.processedAt = new Date();
  
  // Update the user's assigned admin
  const User = mongoose.model('User');
  await User.findByIdAndUpdate(this.user, {
    assignedAdmin: this.toAdmin,
    'metadata.lastModifiedBy': approvedBy
  });

  this.transferCompletedAt = new Date();
  return await this.save();
};

// Instance method to reject transfer
transferRequestSchema.methods.reject = async function(rejectedBy, reason) {
  this.status = 'rejected';
  this.rejectedBy = rejectedBy;
  this.approvalReason = reason;
  this.processedAt = new Date();
  
  return await this.save();
};

// Instance method to cancel transfer
transferRequestSchema.methods.cancel = async function() {
  this.status = 'cancelled';
  return await this.save();
};

// Instance method to check if request can be processed
transferRequestSchema.methods.canBeProcessed = function() {
  return this.status === 'pending' && 
         this.isActive && 
         this.expiresAt > new Date();
};

// Static method to get transfer statistics
transferRequestSchema.statics.getStats = async function(organizationId, timeframe = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - timeframe);

  const stats = await this.aggregate([
    {
      $match: {
        organization: new mongoose.Types.ObjectId(organizationId),
        createdAt: { $gte: startDate }
      }
    },
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

  const result = {
    total: 0,
    pending: 0,
    approved: 0,
    rejected: 0,
    cancelled: 0,
    avgProcessingTimeHours: 0
  };

  let totalProcessingTime = 0;
  let processedCount = 0;

  stats.forEach(stat => {
    result.total += stat.count;
    result[stat._id] = stat.count;
    
    if (stat.avgProcessingTime) {
      totalProcessingTime += stat.avgProcessingTime * stat.count;
      processedCount += stat.count;
    }
  });

  if (processedCount > 0) {
    result.avgProcessingTimeHours = Math.round(
      (totalProcessingTime / processedCount) / (1000 * 60 * 60) * 100
    ) / 100;
  }

  return result;
};

export default mongoose.model('TransferRequest', transferRequestSchema);
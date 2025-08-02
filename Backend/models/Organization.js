import mongoose from 'mongoose';

const organizationSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Organization name is required'],
    trim: true,
    maxlength: [100, 'Organization name cannot exceed 100 characters']
  },
  code: {
    type: String,
    required: [true, 'Organization code is required'],
    unique: true,
    uppercase: true,
    trim: true,
    match: [/^[A-Z0-9]{3,10}$/, 'Organization code must be 3-10 alphanumeric characters']
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  contact: {
    email: {
      type: String,
      required: [true, 'Contact email is required'],
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    phone: {
      type: String,
      match: [/^\+?[\d\s-()]+$/, 'Please enter a valid phone number']
    },
    website: {
      type: String,
      match: [/^https?:\/\/.+/, 'Please enter a valid website URL']
    }
  },
  settings: {
    maxAdmins: {
      type: Number,
      default: 10,
      min: [1, 'Organization must have at least 1 admin'],
      max: [100, 'Organization cannot have more than 100 admins']
    },
    maxUsersPerAdmin: {
      type: Number,
      default: 1000,
      min: [1, 'Admin must be able to manage at least 1 user'],
      max: [10000, 'Admin cannot manage more than 10000 users']
    },
    allowUserTransfer: {
      type: Boolean,
      default: true
    },
    requireSuperAdminApproval: {
      type: Boolean,
      default: true
    }
  },
  superAdmin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Organization must have a super admin']
  },
  admins: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for better performance (code index is already created by unique: true)
organizationSchema.index({ superAdmin: 1 });
organizationSchema.index({ admins: 1 });
organizationSchema.index({ isActive: 1 });

// Virtual for total users count
organizationSchema.virtual('totalUsers', {
  ref: 'User',
  localField: '_id',
  foreignField: 'organization',
  count: true
});

// Virtual for active admins count
organizationSchema.virtual('activeAdminsCount').get(function() {
  return this.admins ? this.admins.length : 0;
});

// Pre-save middleware to update updatedAt
organizationSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Static method to find organization by code
organizationSchema.statics.findByCode = function(code) {
  return this.findOne({ code: code.toUpperCase(), isActive: true });
};

// Instance method to check if organization can add more admins
organizationSchema.methods.canAddAdmin = function() {
  return this.admins.length < this.settings.maxAdmins;
};

// Instance method to get organization stats
organizationSchema.methods.getStats = async function() {
  const User = mongoose.model('User');
  
  const stats = await User.aggregate([
    { $match: { organization: this._id } },
    {
      $group: {
        _id: '$role',
        count: { $sum: 1 }
      }
    }
  ]);

  const result = {
    totalUsers: 0,
    admins: 0,
    users: 0
  };

  stats.forEach(stat => {
    result.totalUsers += stat.count;
    if (stat._id === 'admin') result.admins = stat.count;
    if (stat._id === 'user') result.users = stat.count;
  });

  return result;
};

export default mongoose.model('Organization', organizationSchema);
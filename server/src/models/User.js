// 📁 server/src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  role: {
    type: String,
    enum: ['technician', 'supervisor', 'admin'],
    default: 'technician'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  // Profile information
  phoneNumber: {
    type: String,
    trim: true
  },
  department: {
    type: String,
    trim: true,
    default: 'Laboratory'
  },
  licenseNumber: {
    type: String,
    trim: true // For medical technician license
  },
  // Permissions
  permissions: {
    canUploadSamples: {
      type: Boolean,
      default: true
    },
    canViewAllTests: {
      type: Boolean,
      default: false // Only supervisors/admins by default
    },
    canDeleteTests: {
      type: Boolean,
      default: false // Only admins by default
    },
    canManageUsers: {
      type: Boolean,
      default: false // Only admins by default
    },
    canExportReports: {
      type: Boolean,
      default: true
    }
  }
}, {
  timestamps: true // Adds createdAt and updatedAt
});

// Indexes for performance
// userSchema.index({ email: 1 });
// userSchema.index({ username: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Pre-save hook to set permissions based on role
userSchema.pre('save', async function(next) {
  // Set permissions based on role if they haven't been explicitly set
  if (this.isModified('role') || this.isNew) {
    const { DEFAULT_PERMISSIONS } = require('../utils/constants');
    
    if (DEFAULT_PERMISSIONS[this.role]) {
      // Set default permissions for the role
      Object.keys(DEFAULT_PERMISSIONS[this.role]).forEach(permission => {
        if (this.permissions[permission] === undefined) {
          this.permissions[permission] = DEFAULT_PERMISSIONS[this.role][permission];
        }
      });
    }
  }

  // Only hash password if it's modified
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to get user without sensitive data
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  return user;
};

// Static method to find active users
userSchema.statics.findActive = function() {
  return this.find({ isActive: true });
};

// Static method to find by role
userSchema.statics.findByRole = function(role) {
  return this.find({ role, isActive: true });
};

// Static method to update permissions for all users based on their role
userSchema.statics.updatePermissionsForAllUsers = async function() {
  const { DEFAULT_PERMISSIONS } = require('../utils/constants');
  
  const users = await this.find({});
  const updatePromises = [];
  
  users.forEach(user => {
    if (DEFAULT_PERMISSIONS[user.role]) {
      const updatedPermissions = { ...user.permissions };
      let hasChanges = false;
      
      Object.keys(DEFAULT_PERMISSIONS[user.role]).forEach(permission => {
        if (updatedPermissions[permission] !== DEFAULT_PERMISSIONS[user.role][permission]) {
          updatedPermissions[permission] = DEFAULT_PERMISSIONS[user.role][permission];
          hasChanges = true;
        }
      });
      
      if (hasChanges) {
        updatePromises.push(
          this.findByIdAndUpdate(user._id, { permissions: updatedPermissions })
        );
      }
    }
  });
  
  if (updatePromises.length > 0) {
    await Promise.all(updatePromises);
    console.log(`Updated permissions for ${updatePromises.length} users`);
  }
  
  return updatePromises.length;
};

module.exports = mongoose.model('User', userSchema);
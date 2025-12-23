// 📁 server/src/models/UploadSession.js
const mongoose = require('mongoose');

const uploadSessionSchema = new mongoose.Schema({
  sessionId: {
    type: String,
    required: true,
    unique: true,
    default: function() {
      return `upload_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
  },
  
  // User who initiated the upload
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Associated test (if test is created before upload)
  test: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test'
  },
  testId: String,
  
  // Patient information
  patientId: {
    type: String,
    trim: true,
    uppercase: true
  },
  
  // Upload session status
  status: {
    type: String,
    enum: ['active', 'completed', 'failed', 'cancelled', 'expired'],
    default: 'active'
  },
  
  // Files in this upload session
  files: [{
    filename: {
      type: String,
      required: true
    },
    originalName: String,
    path: String,
    size: Number,
    mimetype: String,
    uploadedAt: {
      type: Date,
      default: Date.now
    },
    status: {
      type: String,
      enum: ['uploading', 'completed', 'failed', 'processing'],
      default: 'uploading'
    },
    errorMessage: String,
    
    // File validation
    isValid: {
      type: Boolean,
      default: true
    },
    validationErrors: [String],
    
    // Image metadata
    imageMetadata: {
      width: Number,
      height: Number,
      format: String,
      quality: Number,
      fileSize: Number
    }
  }],
  
  // Upload progress
  progress: {
    totalFiles: {
      type: Number,
      default: 0
    },
    uploadedFiles: {
      type: Number,
      default: 0
    },
    failedFiles: {
      type: Number,
      default: 0
    },
    percentComplete: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    }
  },
  
  // Upload configuration
  config: {
    maxFiles: {
      type: Number,
      default: 10
    },
    maxFileSize: {
      type: Number,
      default: 10485760 // 10MB in bytes
    },
    allowedTypes: {
      type: [String],
      default: ['image/jpeg', 'image/jpg', 'image/png', 'image/tiff']
    }
  },
  
  // Processing information
  processing: {
    isProcessing: {
      type: Boolean,
      default: false
    },
    startedAt: Date,
    completedAt: Date,
    processingTime: Number, // in milliseconds
    
    // Processing stages
    stages: {
      fileValidation: {
        status: {
          type: String,
          enum: ['pending', 'in_progress', 'completed', 'failed'],
          default: 'pending'
        },
        completedAt: Date,
        errors: [String]
      },
      imagePreparation: {
        status: {
          type: String,
          enum: ['pending', 'in_progress', 'completed', 'failed'],
          default: 'pending'
        },
        completedAt: Date,
        errors: [String]
      },
      apiSubmission: {
        status: {
          type: String,
          enum: ['pending', 'in_progress', 'completed', 'failed'],
          default: 'pending'
        },
        completedAt: Date,
        errors: [String]
      }
    }
  },
  
  // Error handling
  errorMessages: [String],
  lastError: {
    message: String,
    timestamp: Date,
    code: String
  },
  
  // Session expiry
  expiresAt: {
    type: Date,
    default: function() {
      // Sessions expire after 1 hour
      return new Date(Date.now() + 60 * 60 * 1000);
    }
  },
  
  // Cleanup flags
  isCleanedUp: {
    type: Boolean,
    default: false
  },
  cleanupAt: Date,
  
  // Additional metadata
  metadata: {
    clientInfo: {
      userAgent: String,
      ipAddress: String,
      platform: String
    },
    uploadMethod: {
      type: String,
      enum: ['drag_drop', 'file_select', 'api'],
      default: 'file_select'
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
// uploadSessionSchema.index({ sessionId: 1 });
uploadSessionSchema.index({ user: 1, createdAt: -1 });
uploadSessionSchema.index({ status: 1 });
uploadSessionSchema.index({ test: 1 });
uploadSessionSchema.index({ patientId: 1 });
// uploadSessionSchema.index({ expiresAt: 1 }); // For cleanup
uploadSessionSchema.index({ isCleanedUp: 1, cleanupAt: 1 });

// Compound indexes
uploadSessionSchema.index({ user: 1, status: 1 });
uploadSessionSchema.index({ createdAt: -1, status: 1 });

// TTL index for automatic session cleanup
uploadSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Virtual for total upload time
uploadSessionSchema.virtual('totalUploadTime').get(function() {
  if (this.status === 'completed' && this.updatedAt && this.createdAt) {
    return this.updatedAt.getTime() - this.createdAt.getTime();
  }
  return null;
});

// Virtual for upload speed (MB/s)
uploadSessionSchema.virtual('averageUploadSpeed').get(function() {
  if (this.totalUploadTime) {
    const totalSizeMB = this.files.reduce((total, file) => total + (file.size || 0), 0) / (1024 * 1024);
    const timeInSeconds = this.totalUploadTime / 1000;
    return totalSizeMB / timeInSeconds;
  }
  return null;
});

// Virtual for start time (ISO string format)
uploadSessionSchema.virtual('startTime').get(function() {
  const startTime = this.createdAt ? this.createdAt.toISOString() : null;
  console.log('🔍 Debug: Virtual startTime called:', {
    sessionId: this.sessionId,
    createdAt: this.createdAt,
    startTime: startTime,
    createdAtType: typeof this.createdAt,
    startTimeType: typeof startTime
  });
  return startTime;
});

// Pre-save middleware to update progress
uploadSessionSchema.pre('save', function(next) {
  // Calculate progress
  this.progress.totalFiles = this.files.length;
  this.progress.uploadedFiles = this.files.filter(f => f.status === 'completed').length;
  this.progress.failedFiles = this.files.filter(f => f.status === 'failed').length;
  
  if (this.progress.totalFiles > 0) {
    this.progress.percentComplete = Math.round(
      (this.progress.uploadedFiles / this.progress.totalFiles) * 100
    );
  }
  
  // Auto-complete session if all files are processed
  if (this.progress.totalFiles > 0 && 
      this.progress.uploadedFiles + this.progress.failedFiles === this.progress.totalFiles &&
      this.status === 'active') {
    this.status = this.progress.failedFiles === 0 ? 'completed' : 'failed';
  }
  
  next();
});

// Static methods
uploadSessionSchema.statics.findActiveByUser = function(userId) {
  return this.find({ 
    user: userId, 
    status: 'active',
    expiresAt: { $gt: new Date() }
  }).sort({ createdAt: -1 });
};

uploadSessionSchema.statics.findExpiredSessions = function() {
  return this.find({
    $or: [
      { expiresAt: { $lt: new Date() } },
      { status: { $in: ['completed', 'failed', 'cancelled'] }, updatedAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }
    ],
    isCleanedUp: false
  });
};

uploadSessionSchema.statics.getUploadStatistics = function(startDate, endDate) {
  const matchCondition = {};
  
  if (startDate || endDate) {
    matchCondition.createdAt = {};
    if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
    if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
  }
  
  return this.aggregate([
    { $match: matchCondition },
    {
      $group: {
        _id: null,
        totalSessions: { $sum: 1 },
        completedSessions: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
        failedSessions: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
        totalFiles: { $sum: { $size: '$files' } },
        avgFilesPerSession: { $avg: { $size: '$files' } },
        totalUploadSize: {
          $sum: {
            $reduce: {
              input: '$files',
              initialValue: 0,
              in: { $add: ['$$value', { $ifNull: ['$$this.size', 0] }] }
            }
          }
        }
      }
    }
  ]);
};

// Instance methods
uploadSessionSchema.methods.addFile = function(fileData) {
  this.files.push(fileData);
  return this.save();
};

uploadSessionSchema.methods.updateFileStatus = function(filename, status, errorMessage = null) {
  const file = this.files.find(f => f.filename === filename);
  if (file) {
    file.status = status;
    if (errorMessage) {
      file.errorMessage = errorMessage;
    }
    if (status === 'completed') {
      file.uploadedAt = new Date();
    }
  }
  return this.save();
};

uploadSessionSchema.methods.markProcessingStage = function(stage, status, errors = []) {
  if (this.processing.stages[stage]) {
    this.processing.stages[stage].status = status;
    this.processing.stages[stage].errors = errors;
    
    if (status === 'completed' || status === 'failed') {
      this.processing.stages[stage].completedAt = new Date();
    }
  }
  return this.save();
};

uploadSessionSchema.methods.startProcessing = function() {
  this.processing.isProcessing = true;
  this.processing.startedAt = new Date();
  this.status = 'active';
  return this.save();
};

uploadSessionSchema.methods.completeProcessing = function(success = true) {
  this.processing.isProcessing = false;
  this.processing.completedAt = new Date();
  
  if (this.processing.startedAt) {
    this.processing.processingTime = this.processing.completedAt.getTime() - this.processing.startedAt.getTime();
  }
  
  this.status = success ? 'completed' : 'failed';
  return this.save();
};

uploadSessionSchema.methods.cancel = function(reason = 'User cancelled') {
  this.status = 'cancelled';
  this.errors.push(reason);
  this.lastError = {
    message: reason,
    timestamp: new Date(),
    code: 'USER_CANCELLED'
  };
  return this.save();
};

uploadSessionSchema.methods.extend = function(additionalMinutes = 60) {
  this.expiresAt = new Date(this.expiresAt.getTime() + additionalMinutes * 60 * 1000);
  return this.save();
};

uploadSessionSchema.methods.cleanup = function() {
  // Mark for file system cleanup
  this.isCleanedUp = true;
  this.cleanupAt = new Date();
  return this.save();
};

uploadSessionSchema.methods.getValidFiles = function() {
  return this.files.filter(f => f.isValid && f.status === 'completed');
};

uploadSessionSchema.methods.getFailedFiles = function() {
  return this.files.filter(f => f.status === 'failed' || !f.isValid);
};

uploadSessionSchema.methods.getSummary = function() {
  return {
    sessionId: this.sessionId,
    status: this.status,
    totalFiles: this.progress.totalFiles,
    uploadedFiles: this.progress.uploadedFiles,
    failedFiles: this.progress.failedFiles,
    percentComplete: this.progress.percentComplete,
    isProcessing: this.processing.isProcessing,
    uploadTime: this.totalUploadTime,
    validFiles: this.getValidFiles().length,
    errors: this.errors
  };
};

// Method to get session with guaranteed startTime
uploadSessionSchema.methods.toSafeObject = function() {
  const sessionObj = this.toObject();
  const startTime = this.createdAt ? this.createdAt.toISOString() : null;
  
  console.log('🔍 Debug: toSafeObject called:', {
    sessionId: this.sessionId,
    createdAt: this.createdAt,
    startTime: startTime,
    createdAtType: typeof this.createdAt,
    startTimeType: typeof startTime,
    hasVirtuals: !!this.startTime
  });
  
  sessionObj.startTime = startTime;
  return sessionObj;
};

module.exports = mongoose.model('UploadSession', uploadSessionSchema);
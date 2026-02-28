// 📁 server/src/models/AuditLog.js
const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  // Core audit information
  action: {
    type: String,
    required: true,
    enum: [
      // Authentication actions
      'login', 'logout', 'failed_login', 'password_change',
      
      // User management
      'user_created', 'user_updated', 'user_deleted', 'user_activated', 'user_deactivated',
      
      // Patient management
      'patient_created', 'patient_updated', 'patient_deleted', 'patient_viewed',
      
      // Test operations
      'test_created', 'test_updated', 'test_deleted', 'test_started', 'test_completed', 'test_cancelled',
      'test_status_changed', 'test_assigned',
      
      // Upload operations
      'upload_session_created', 'files_uploaded', 'upload_session_cancelled', 'upload_cleanup',
      
      // Sample operations
      'sample_uploaded', 'sample_deleted', 'sample_downloaded',
      
      // Diagnosis operations
      'diagnosis_completed', 'diagnosis_reviewed', 'diagnosis_overridden', 'diagnosis_failed', 'diagnosis_viewed',
      
      // Report operations
      'report_generated', 'report_exported', 'report_printed', 'report_shared',
      
      // Integration operations
      'data_exported_to_hospital', 'api_call_made', 'integration_failed',
      
      // System operations
      'system_backup', 'system_maintenance', 'database_cleanup',
      
      // Security events
      'unauthorized_access_attempt', 'data_breach_detected', 'suspicious_activity',

      //patient data export
      'patient_data_exported',
      
      // Socket operations
      'socket_connected', 'socket_disconnected'
    ]
  },
  
  // User who performed the action
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  userInfo: {
    username: String,
    email: String,
    role: String,
    fullName: String
  },
  
  // Target resource information
  resourceType: {
    type: String,
    enum: ['user', 'patient', 'test', 'diagnosis', 'sample', 'report', 'system', 'upload'],
    required: true
  },
  resourceId: {
    type: String, // Can be ObjectId string or custom ID like testId/patientId
    required: true
  },
  resourceName: String, // Human readable name
  
  // Action details
  details: {
    description: String,
    previousValue: mongoose.Schema.Types.Mixed,
    newValue: mongoose.Schema.Types.Mixed,
    changes: [String], // Array of field names that changed
    additionalInfo: mongoose.Schema.Types.Mixed,
    // Test-specific details
    testData: mongoose.Schema.Types.Mixed,
    patientName: String,
    previousStatus: String,
    newStatus: String,
    notes: String,
    patientId: String,
    previousTechnician: String,
    newTechnician: String,
    technicianName: String,
    deletedTestData: mongoose.Schema.Types.Mixed,
    reason: String,
    // Upload-specific details
    uploadedFiles: Number,
    failedFiles: Number,
    totalFiles: Number,
    testId: String,
    maxFiles: Number,
    maxFileSize: Number,
    sessionId: String,
    result: String,
    parasiteType: String,
    confidence: Number,
    filesProcessed: Number,
    filesAttempted: Number,
    error: String,
    cleanedSessions: Number,
    cleanedFiles: Number,
    freedSpace: String
  },
  
  // Request information
  requestInfo: {
    ipAddress: String,
    userAgent: String,
    method: String, // GET, POST, PUT, DELETE
    endpoint: String,
    statusCode: Number,
    responseTime: Number // in milliseconds
  },
  
  // Session information
  sessionId: String,
  
  // Risk assessment
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  
  // Success/failure status
  status: {
    type: String,
    enum: ['success', 'failure', 'partial'],
    default: 'success'
  },
  errorMessage: String,
  
  // Compliance and retention
  retentionPeriod: {
    type: Number,
    default: 2555 // 7 years in days for medical records
  },
  isCompliant: {
    type: Boolean,
    default: true
  },
  complianceNotes: String,
  
  // Metadata
  source: {
    type: String,
    enum: ['web_app', 'mobile_app', 'api', 'system', 'integration'],
    default: 'web_app'
  },
  environment: {
    type: String,
    enum: ['development', 'staging', 'production'],
    default: 'production'
  },
  
  // Geolocation (optional)
  location: {
    country: String,
    city: String,
    latitude: Number,
    longitude: Number
  }
}, {
  timestamps: true
});

// Indexes for performance and querying
auditLogSchema.index({ user: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ resourceType: 1, resourceId: 1 });
auditLogSchema.index({ riskLevel: 1, createdAt: -1 });
auditLogSchema.index({ status: 1 });
auditLogSchema.index({ createdAt: -1 }); // For log retention cleanup
auditLogSchema.index({ sessionId: 1 });

// Compound indexes
auditLogSchema.index({ user: 1, action: 1, createdAt: -1 });
auditLogSchema.index({ resourceType: 1, action: 1, createdAt: -1 });
auditLogSchema.index({ riskLevel: 1, status: 1 });

// TTL index for automatic log cleanup (optional)
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 220752000 }); // 7 years

// Pre-save middleware to set derived fields
auditLogSchema.pre('save', function(next) {
  // Set risk level based on action type
  if (!this.riskLevel || this.riskLevel === 'low') {
    const highRiskActions = [
      'user_deleted', 'patient_deleted', 'test_deleted', 'diagnosis_overridden',
      'unauthorized_access_attempt', 'data_breach_detected', 'suspicious_activity'
    ];
    const mediumRiskActions = [
      'user_created', 'user_updated', 'password_change', 'diagnosis_reviewed',
      'data_exported_to_hospital', 'failed_login', 'test_assigned', 'test_status_changed',
      'upload_session_created', 'files_uploaded', 'diagnosis_failed'
    ];
    
    if (highRiskActions.includes(this.action)) {
      this.riskLevel = 'high';
    } else if (mediumRiskActions.includes(this.action)) {
      this.riskLevel = 'medium';
    }
  }
  
  // Ensure user info is populated if user is referenced
  if (this.user && !this.userInfo.username) {
    // This would be populated by the controller when creating the log
  }
  
  next();
});

// Static methods for querying logs
auditLogSchema.statics.findByUser = function(userId, limit = 50) {
  return this.find({ user: userId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('user', 'username email role');
};

auditLogSchema.statics.findByAction = function(action, startDate = null, endDate = null) {
  const query = { action };
  
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .populate('user', 'username email role');
};

auditLogSchema.statics.findByResource = function(resourceType, resourceId) {
  return this.find({ resourceType, resourceId })
    .sort({ createdAt: -1 })
    .populate('user', 'username email role');
};

auditLogSchema.statics.findHighRisk = function(limit = 100) {
  return this.find({ riskLevel: { $in: ['high', 'critical'] } })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('user', 'username email role');
};

auditLogSchema.statics.findFailures = function(startDate = null, endDate = null) {
  const query = { status: 'failure' };
  
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }
  
  return this.find(query)
    .sort({ createdAt: -1 })
    .populate('user', 'username email role');
};

auditLogSchema.statics.getActivitySummary = function(startDate, endDate) {
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
        _id: {
          action: '$action',
          status: '$status'
        },
        count: { $sum: 1 },
        users: { $addToSet: '$user' }
      }
    },
    {
      $group: {
        _id: '$_id.action',
        totalCount: { $sum: '$count' },
        successCount: { 
          $sum: { 
            $cond: [{ $eq: ['$_id.status', 'success'] }, '$count', 0] 
          } 
        },
        failureCount: { 
          $sum: { 
            $cond: [{ $eq: ['$_id.status', 'failure'] }, '$count', 0] 
          } 
        },
        uniqueUsers: { $sum: { $size: '$users' } }
      }
    },
    { $sort: { totalCount: -1 } }
  ]);
};

// Instance methods
auditLogSchema.methods.anonymize = function() {
  // Remove PII for compliance
  this.userInfo = {
    role: this.userInfo?.role || 'unknown'
  };
  this.requestInfo.ipAddress = 'anonymized';
  this.requestInfo.userAgent = 'anonymized';
  this.location = undefined;
  
  return this.save();
};

auditLogSchema.methods.isExpired = function() {
  const expiryDate = new Date(this.createdAt);
  expiryDate.setDate(expiryDate.getDate() + this.retentionPeriod);
  return new Date() > expiryDate;
};

// Virtual for human-readable timestamp
auditLogSchema.virtual('readableTimestamp').get(function() {
  return this.createdAt.toLocaleString();
});

// Static helper method to create audit logs easily
auditLogSchema.statics.createLog = function(logData) {
  return this.create({
    action: logData.action,
    user: logData.userId,
    userInfo: logData.userInfo,
    resourceType: logData.resourceType,
    resourceId: logData.resourceId,
    resourceName: logData.resourceName,
    details: logData.details,
    requestInfo: logData.requestInfo,
    sessionId: logData.sessionId,
    status: logData.status || 'success',
    errorMessage: logData.errorMessage,
    source: logData.source || 'web_app',
    riskLevel: logData.riskLevel
  });
};

module.exports = mongoose.model('AuditLog', auditLogSchema);
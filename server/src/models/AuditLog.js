// // 📁 server/src/models/AuditLog.js
// const mongoose = require('mongoose');
// const { AUDIT_ACTIONS, RISK_LEVELS } = require('../utils/constants');

// const auditLogSchema = new mongoose.Schema({
//   // Core audit information
//   action: {
//     type: String,
//     required: [true, 'Action is required'],
//     enum: {
//       values: Object.values(AUDIT_ACTIONS),
//       message: 'Invalid audit action'
//     },
//     index: true
//   },
  
//   // User information
//   userId: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'User',
//     index: true
//   },
  
//   userInfo: {
//     username: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Username cannot exceed 100 characters']
//     },
//     email: {
//       type: String,
//       lowercase: true,
//       trim: true,
//       maxlength: [255, 'Email cannot exceed 255 characters']
//     },
//     role: {
//       type: String,
//       enum: ['technician', 'supervisor', 'admin', 'system'],
//       index: true
//     },
//     fullName: {
//       type: String,
//       trim: true,
//       maxlength: [200, 'Full name cannot exceed 200 characters']
//     },
//     sessionId: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Session ID cannot exceed 100 characters']
//     }
//   },
  
//   // Resource information
//   resourceType: {
//     type: String,
//     required: [true, 'Resource type is required'],
//     enum: [
//       'user', 'patient', 'test', 'diagnosis', 'upload', 'report', 
//       'system', 'integration', 'file', 'session', 'configuration'
//     ],
//     index: true
//   },
  
//   resourceId: {
//     type: String,
//     required: [true, 'Resource ID is required'],
//     trim: true,
//     maxlength: [100, 'Resource ID cannot exceed 100 characters'],
//     index: true
//   },
  
//   resourceName: {
//     type: String,
//     trim: true,
//     maxlength: [200, 'Resource name cannot exceed 200 characters']
//   },
  
//   // Action details
//   details: {
//     type: mongoose.Schema.Types.Mixed,
//     validate: {
//       validator: function(value) {
//         // Ensure details object is not too large (max 16MB BSON limit)
//         return JSON.stringify(value).length <= 1048576; // 1MB limit for details
//       },
//       message: 'Details object is too large'
//     }
//   },
  
//   // Request information
//   requestInfo: {
//     ipAddress: {
//       type: String,
//       trim: true,
//       match: [/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/, 'Invalid IP address format'],
//       index: true
//     },
//     userAgent: {
//       type: String,
//       trim: true,
//       maxlength: [1000, 'User agent cannot exceed 1000 characters']
//     },
//     method: {
//       type: String,
//       enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
//       uppercase: true
//     },
//     endpoint: {
//       type: String,
//       trim: true,
//       maxlength: [500, 'Endpoint cannot exceed 500 characters']
//     },
//     requestId: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Request ID cannot exceed 100 characters']
//     },
//     duration: {
//       type: Number, // in milliseconds
//       min: [0, 'Duration cannot be negative']
//     },
//     statusCode: {
//       type: Number,
//       min: [100, 'Status code must be at least 100'],
//       max: [599, 'Status code cannot exceed 599']
//     }
//   },
  
//   // Classification
//   status: {
//     type: String,
//     enum: ['success', 'failure', 'warning', 'info'],
//     default: 'success',
//     required: true,
//     index: true
//   },
  
//   riskLevel: {
//     type: String,
//     enum: {
//       values: Object.values(RISK_LEVELS),
//       message: 'Invalid risk level'
//     },
//     default: RISK_LEVELS.LOW,
//     required: true,
//     index: true
//   },
  
//   // Context information
//   context: {
//     environment: {
//       type: String,
//       enum: ['development', 'staging', 'production'],
//       default: 'development'
//     },
//     applicationVersion: {
//       type: String,
//       trim: true,
//       maxlength: [20, 'Application version cannot exceed 20 characters']
//     },
//     component: {
//       type: String,
//       enum: ['frontend', 'backend', 'api', 'database', 'file_system', 'external_service'],
//       default: 'backend'
//     },
//     module: {
//       type: String,
//       trim: true,
//       maxlength: [50, 'Module cannot exceed 50 characters']
//     }
//   },
  
//   // Error information (if applicable)
//   error: {
//     message: {
//       type: String,
//       trim: true,
//       maxlength: [1000, 'Error message cannot exceed 1000 characters']
//     },
//     code: {
//       type: String,
//       trim: true,
//       uppercase: true,
//       maxlength: [50, 'Error code cannot exceed 50 characters']
//     },
//     stack: {
//       type: String,
//       trim: true,
//       maxlength: [5000, 'Error stack cannot exceed 5000 characters']
//     },
//     type: {
//       type: String,
//       enum: [
//         'ValidationError', 'AuthenticationError', 'AuthorizationError',
//         'NetworkError', 'DatabaseError', 'FileSystemError', 'BusinessLogicError',
//         'ExternalServiceError', 'SystemError', 'UnknownError'
//       ]
//     }
//   },
  
//   // Compliance and security
//   compliance: {
//     hipaaRelevant: {
//       type: Boolean,
//       default: false
//     },
//     piiInvolved: {
//       type: Boolean,
//       default: false
//     },
//     gdprRelevant: {
//       type: Boolean,
//       default: false
//     },
//     dataClassification: {
//       type: String,
//       enum: ['public', 'internal', 'confidential', 'restricted'],
//       default: 'internal'
//     },
//     retentionPeriod: {
//       type: Number, // in days
//       min: [1, 'Retention period must be at least 1 day'],
//       default: 2555 // 7 years default for medical records
//     }
//   },
  
//   // Data changes (for modification actions)
//   changes: {
//     before: {
//       type: mongoose.Schema.Types.Mixed
//     },
//     after: {
//       type: mongoose.Schema.Types.Mixed
//     },
//     fields: [{
//       field: {
//         type: String,
//         required: true,
//         trim: true
//       },
//       oldValue: {
//         type: mongoose.Schema.Types.Mixed
//       },
//       newValue: {
//         type: mongoose.Schema.Types.Mixed
//       },
//       changeType: {
//         type: String,
//         enum: ['created', 'updated', 'deleted'],
//         required: true
//       }
//     }]
//   },
  
//   // Correlation and tracing
//   correlation: {
//     traceId: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Trace ID cannot exceed 100 characters']
//     },
//     spanId: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Span ID cannot exceed 100 characters']
//     },
//     parentEventId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'AuditLog'
//     },
//     relatedEvents: [{
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'AuditLog'
//     }],
//     businessProcessId: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Business process ID cannot exceed 100 characters']
//     }
//   },
  
//   // Geolocation (if available)
//   location: {
//     country: {
//       type: String,
//       trim: true,
//       maxlength: [50, 'Country cannot exceed 50 characters']
//     },
//     region: {
//       type: String,
//       trim: true,
//       maxlength: [50, 'Region cannot exceed 50 characters']
//     },
//     city: {
//       type: String,
//       trim: true,
//       maxlength: [50, 'City cannot exceed 50 characters']
//     },
//     coordinates: {
//       latitude: {
//         type: Number,
//         min: [-90, 'Latitude must be between -90 and 90'],
//         max: [90, 'Latitude must be between -90 and 90']
//       },
//       longitude: {
//         type: Number,
//         min: [-180, 'Longitude must be between -180 and 180'],
//         max: [180, 'Longitude must be between -180 and 180']
//       }
//     },
//     timezone: {
//       type: String,
//       trim: true,
//       maxlength: [50, 'Timezone cannot exceed 50 characters']
//     }
//   },
  
//   // Archival information
//   archived: {
//     type: Boolean,
//     default: false,
//     index: true
//   },
  
//   archivedAt: {
//     type: Date
//   },
  
//   archiveReason: {
//     type: String,
//     enum: ['retention_policy', 'user_request', 'legal_requirement', 'admin_action'],
//     trim: true
//   },
  
//   // Hash for integrity verification
//   integrity: {
//     hash: {
//       type: String,
//       trim: true,
//       match: [/^[a-f0-9]{64}$/, 'Hash must be 64 hexadecimal characters']
//     },
//     algorithm: {
//       type: String,
//       enum: ['SHA256', 'SHA512'],
//       default: 'SHA256'
//     },
//     verified: {
//       type: Boolean,
//       default: true
//     },
//     verifiedAt: {
//       type: Date,
//       default: Date.now
//     }
//   }
// }, {
//   timestamps: true,
//   // Audit logs should be immutable after creation
//   strict: 'throw',
//   // Add version key for concurrency control
//   versionKey: '__v'
// });

// // Indexes for performance and compliance queries
// auditLogSchema.index({ action: 1, createdAt: -1 });
// auditLogSchema.index({ userId: 1, createdAt: -1 });
// auditLogSchema.index({ resourceType: 1, resourceId: 1, createdAt: -1 });
// auditLogSchema.index({ status: 1, riskLevel: 1, createdAt: -1 });
// auditLogSchema.index({ 'requestInfo.ipAddress': 1, createdAt: -1 });
// auditLogSchema.index({ 'userInfo.role': 1, action: 1, createdAt: -1 });
// auditLogSchema.index({ 'compliance.hipaaRelevant': 1, createdAt: -1 });
// auditLogSchema.index({ 'compliance.piiInvolved': 1, createdAt: -1 });
// auditLogSchema.index({ archived: 1, createdAt: -1 });

// // Compound indexes for complex queries
// auditLogSchema.index({ 
//   userId: 1, 
//   resourceType: 1, 
//   action: 1, 
//   createdAt: -1 
// });

// auditLogSchema.index({ 
//   riskLevel: 1, 
//   status: 1, 
//   'userInfo.role': 1, 
//   createdAt: -1 
// });

// // Text index for search functionality
// auditLogSchema.index({
//   action: 'text',
//   resourceId: 'text',
//   resourceName: 'text',
//   'userInfo.username': 'text',
//   'details': 'text'
// });

// // TTL index for automatic cleanup based on retention period
// auditLogSchema.index({ 
//   createdAt: 1 
// }, { 
//   expireAfterSeconds: 220752000, // 7 years in seconds
//   partialFilterExpression: { archived: true }
// });

// // Pre-save middleware to generate integrity hash
// auditLogSchema.pre('save', function(next) {
//   if (this.isNew) {
//     this.generateIntegrityHash();
//   }
//   next();
// });

// // Prevent modifications after creation (immutable audit logs)
// auditLogSchema.pre('save', function(next) {
//   if (!this.isNew) {
//     const error = new Error('Audit logs are immutable and cannot be modified');
//     error.code = 'AUDIT_LOG_IMMUTABLE';
//     return next(error);
//   }
//   next();
// });

// // Instance method to generate integrity hash
// auditLogSchema.methods.generateIntegrityHash = function() {
//   const crypto = require('crypto');
  
//   // Create a deterministic string representation
//   const dataToHash = {
//     action: this.action,
//     userId: this.userId?.toString(),
//     resourceType: this.resourceType,
//     resourceId: this.resourceId,
//     timestamp: this.createdAt?.toISOString(),
//     details: this.details,
//     userInfo: this.userInfo,
//     requestInfo: this.requestInfo
//   };
  
//   const dataString = JSON.stringify(dataToHash, Object.keys(dataToHash).sort());
//   this.integrity.hash = crypto.createHash('sha256').update(dataString).digest('hex');
//   this.integrity.algorithm = 'SHA256';
//   this.integrity.verified = true;
//   this.integrity.verifiedAt = new Date();
// };

// // Instance method to verify integrity
// auditLogSchema.methods.verifyIntegrity = function() {
//   const crypto = require('crypto');
  
//   const dataToHash = {
//     action: this.action,
//     userId: this.userId?.toString(),
//     resourceType: this.resourceType,
//     resourceId: this.resourceId,
//     timestamp: this.createdAt?.toISOString(),
//     details: this.details,
//     userInfo: this.userInfo,
//     requestInfo: this.requestInfo
//   };
  
//   const dataString = JSON.stringify(dataToHash, Object.keys(dataToHash).sort());
//   const computedHash = crypto.createHash('sha256').update(dataString).digest('hex');
  
//   return computedHash === this.integrity.hash;
// };

// // Instance method to anonymize PII data
// auditLogSchema.methods.anonymize = function() {
//   if (this.compliance.piiInvolved) {
//     // Anonymize user information
//     if (this.userInfo.email) {
//       this.userInfo.email = this.hashValue(this.userInfo.email);
//     }
//     if (this.userInfo.fullName) {
//       this.userInfo.fullName = '[ANONYMIZED]';
//     }
    
//     // Anonymize IP address
//     if (this.requestInfo.ipAddress) {
//       this.requestInfo.ipAddress = this.anonymizeIP(this.requestInfo.ipAddress);
//     }
    
//     // Remove or anonymize PII from details
//     if (this.details) {
//       this.details = this.anonymizeDetails(this.details);
//     }
    
//     // Mark as anonymized
//     this.compliance.anonymized = true;
//     this.compliance.anonymizedAt = new Date();
//   }
  
//   return this.save();
// };

// // Helper method to hash sensitive values
// auditLogSchema.methods.hashValue = function(value) {
//   const crypto = require('crypto');
//   return crypto.createHash('sha256').update(value).digest('hex').substring(0, 16) + '...';
// };

// // Helper method to anonymize IP address
// auditLogSchema.methods.anonymizeIP = function(ip) {
//   if (ip.includes('.')) {
//     // IPv4 - mask last octet
//     const parts = ip.split('.');
//     return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
//   } else if (ip.includes(':')) {
//     // IPv6 - mask last 64 bits
//     const parts = ip.split(':');
//     return `${parts.slice(0, 4).join(':')}:xxxx:xxxx:xxxx:xxxx`;
//   }
//   return 'xxx.xxx.xxx.xxx';
// };

// // Helper method to anonymize details object
// auditLogSchema.methods.anonymizeDetails = function(details) {
//   const sensitiveFields = [
//     'email', 'firstName', 'lastName', 'fullName', 'phoneNumber', 
//     'address', 'ssn', 'nationalId', 'passport', 'creditCard'
//   ];
  
//   const anonymized = JSON.parse(JSON.stringify(details));
  
//   const anonymizeObject = (obj) => {
//     for (const key in obj) {
//       if (obj.hasOwnProperty(key)) {
//         if (typeof obj[key] === 'object' && obj[key] !== null) {
//           anonymizeObject(obj[key]);
//         } else if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
//           obj[key] = '[ANONYMIZED]';
//         }
//       }
//     }
//   };
  
//   anonymizeObject(anonymized);
//   return anonymized;
// };

// // Static method to create audit log
// auditLogSchema.statics.createLog = function(logData) {
//   const auditLog = new this(logData);
//   return auditLog.save();
// };

// // Static method to find logs by user
// auditLogSchema.statics.findByUser = function(userId, startDate, endDate, limit = 100) {
//   const query = { userId };
  
//   if (startDate || endDate) {
//     query.createdAt = {};
//     if (startDate) query.createdAt.$gte = new Date(startDate);
//     if (endDate) query.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.find(query)
//     .sort({ createdAt: -1 })
//     .limit(limit);
// };

// // Static method to find logs by resource
// auditLogSchema.statics.findByResource = function(resourceType, resourceId, limit = 50) {
//   return this.find({
//     resourceType,
//     resourceId
//   })
//   .populate('userId', 'username firstName lastName role')
//   .sort({ createdAt: -1 })
//   .limit(limit);
// };

// // Static method to find high-risk activities
// auditLogSchema.statics.findHighRiskActivities = function(startDate, endDate, limit = 100) {
//   const query = {
//     riskLevel: { $in: [RISK_LEVELS.HIGH, RISK_LEVELS.CRITICAL] }
//   };
  
//   if (startDate || endDate) {
//     query.createdAt = {};
//     if (startDate) query.createdAt.$gte = new Date(startDate);
//     if (endDate) query.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.find(query)
//     .populate('userId', 'username firstName lastName role')
//     .sort({ createdAt: -1 })
//     .limit(limit);
// };

// // Static method to find failed actions
// auditLogSchema.statics.findFailedActions = function(startDate, endDate, limit = 100) {
//   const query = { status: 'failure' };
  
//   if (startDate || endDate) {
//     query.createdAt = {};
//     if (startDate) query.createdAt.$gte = new Date(startDate);
//     if (endDate) query.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.find(query)
//     .populate('userId', 'username firstName lastName role')
//     .sort({ createdAt: -1 })
//     .limit(limit);
// };

// // Static method to get audit statistics
// auditLogSchema.statics.getAuditStatistics = function(startDate, endDate) {
//   const matchStage = {};
  
//   if (startDate || endDate) {
//     matchStage.createdAt = {};
//     if (startDate) matchStage.createdAt.$gte = new Date(startDate);
//     if (endDate) matchStage.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.aggregate([
//     { $match: matchStage },
//     {
//       $group: {
//         _id: null,
//         totalLogs: { $sum: 1 },
//         successfulActions: {
//           $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
//         },
//         failedActions: {
//           $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
//         },
//         highRiskActions: {
//           $sum: { $cond: [{ $in: ['$riskLevel', [RISK_LEVELS.HIGH, RISK_LEVELS.CRITICAL]] }, 1, 0] }
//         },
//         actionsByType: { $push: '$action' },
//         usersByRole: { $push: '$userInfo.role' },
//         resourcesByType: { $push: '$resourceType' },
//         ipAddresses: { $addToSet: '$requestInfo.ipAddress' }
//       }
//     }
//   ]);
// };

// // Static method to find unusual patterns
// auditLogSchema.statics.findUnusualPatterns = function(timeWindow = 24) {
//   const windowStart = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
  
//   return this.aggregate([
//     { $match: { createdAt: { $gte: windowStart } } },
//     {
//       $group: {
//         _id: {
//           userId: '$userId',
//           ipAddress: '$requestInfo.ipAddress',
//           action: '$action'
//         },
//         count: { $sum: 1 },
//         firstOccurrence: { $min: '$createdAt' },
//         lastOccurrence: { $max: '$createdAt' }
//       }
//     },
//     {
//       $match: {
//         $or: [
//           { count: { $gte: 100 } }, // High frequency
//           { 
//             $expr: {
//               $lt: [
//                 { $subtract: ['$lastOccurrence', '$firstOccurrence'] },
//                 60000 // Actions within 1 minute
//               ]
//             }
//           }
//         ]
//       }
//     },
//     { $sort: { count: -1 } }
//   ]);
// };

// // Static method to cleanup old logs
// auditLogSchema.statics.cleanupOldLogs = function(daysToKeep = 2555) { // 7 years
//   const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
  
//   return this.updateMany(
//     {
//       createdAt: { $lt: cutoffDate },
//       archived: false
//     },
//     {
//       $set: {
//         archived: true,
//         archivedAt: new Date(),
//         archiveReason: 'retention_policy'
//       }
//     }
//   );
// };

// // Static method to export audit trail for compliance
// auditLogSchema.statics.exportAuditTrail = function(userId, startDate, endDate, format = 'json') {
//   const query = {};
  
//   if (userId) query.userId = userId;
//   if (startDate || endDate) {
//     query.createdAt = {};
//     if (startDate) query.createdAt.$gte = new Date(startDate);
//     if (endDate) query.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.find(query)
//     .populate('userId', 'username firstName lastName role')
//     .sort({ createdAt: -1 })
//     .lean(); // Return plain objects for export
// };

// // Create the model
// const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// module.exports = AuditLog;
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
      
      // Sample operations
      'sample_uploaded', 'sample_deleted', 'sample_downloaded',
      
      // Diagnosis operations
      'diagnosis_completed', 'diagnosis_reviewed', 'diagnosis_overridden',
      
      // Report operations
      'report_generated', 'report_exported', 'report_printed', 'report_shared',
      
      // Integration operations
      'data_exported_to_hospital', 'api_call_made', 'integration_failed',
      
      // System operations
      'system_backup', 'system_maintenance', 'database_cleanup',
      
      // Security events
      'unauthorized_access_attempt', 'data_breach_detected', 'suspicious_activity'
    ]
  },
  
  // User who performed the action
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
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
    enum: ['user', 'patient', 'test', 'diagnosis', 'sample', 'report', 'system'],
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
    additionalInfo: mongoose.Schema.Types.Mixed
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
      'data_exported_to_hospital', 'failed_login'
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
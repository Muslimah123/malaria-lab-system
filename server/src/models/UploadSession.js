// // 📁 server/src/models/UploadSession.js
// const mongoose = require('mongoose');
// const crypto = require('crypto');
// const { UPLOAD_STATUS, FILE_STATUS } = require('../utils/constants');

// const uploadSessionSchema = new mongoose.Schema({
//   sessionId: {
//     type: String,
//     required: [true, 'Session ID is required'],
//     unique: true,
//     trim: true,
//     index: true
//   },
  
//   user: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'User',
//     required: true
//   },
  
//   test: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'Test',
//     required: true
//   },
  
//   testId: {
//     type: String,
//     required: [true, 'Test ID is required'],
//     uppercase: true,
//     trim: true,
//     match: [/^TEST-\d{8}-\d{3}$/, 'Test ID must be in format TEST-YYYYMMDD-XXX']
//   },
  
//   patientId: {
//     type: String,
//     required: [true, 'Patient ID is required'],
//     uppercase: true,
//     trim: true,
//     match: [/^PAT-\d{8}-\d{3}$/, 'Patient ID must be in format PAT-YYYYMMDD-XXX']
//   },
  
//   status: {
//     type: String,
//     enum: {
//       values: Object.values(UPLOAD_STATUS),
//       message: 'Status must be one of: active, completed, failed, cancelled, expired'
//     },
//     default: UPLOAD_STATUS.ACTIVE,
//     required: true
//   },
  
//   // Session configuration
//   config: {
//     maxFiles: {
//       type: Number,
//       min: [1, 'Max files must be at least 1'],
//       max: [50, 'Max files cannot exceed 50'],
//       default: 10
//     },
//     maxFileSize: {
//       type: Number,
//       min: [1024, 'Max file size must be at least 1KB'],
//       max: [104857600, 'Max file size cannot exceed 100MB'], // 100MB
//       default: 10485760 // 10MB
//     },
//     allowedTypes: [{
//       type: String,
//       enum: [
//         'image/jpeg',
//         'image/jpg', 
//         'image/png',
//         'image/tiff',
//         'image/tif',
//         'image/bmp'
//       ]
//     }],
//     autoProcess: {
//       type: Boolean,
//       default: true
//     },
//     requireManualTrigger: {
//       type: Boolean,
//       default: false
//     }
//   },
  
//   // Uploaded files
//   files: [{
//     filename: {
//       type: String,
//       required: true,
//       trim: true
//     },
//     originalName: {
//       type: String,
//       required: true,
//       trim: true
//     },
//     path: {
//       type: String,
//       required: true,
//       trim: true
//     },
//     size: {
//       type: Number,
//       required: true,
//       min: [0, 'File size cannot be negative']
//     },
//     mimetype: {
//       type: String,
//       required: true,
//       trim: true
//     },
//     status: {
//       type: String,
//       enum: {
//         values: Object.values(FILE_STATUS),
//         message: 'File status must be one of: pending, uploading, completed, failed, processing'
//       },
//       default: FILE_STATUS.PENDING
//     },
//     uploadedAt: {
//       type: Date,
//       default: Date.now
//     },
//     isValid: {
//       type: Boolean,
//       default: false
//     },
//     validationErrors: [{
//       type: String,
//       trim: true
//     }],
//     imageMetadata: {
//       width: {
//         type: Number,
//         min: [1, 'Width must be positive']
//       },
//       height: {
//         type: Number,
//         min: [1, 'Height must be positive']
//       },
//       channels: {
//         type: Number,
//         min: [1, 'Channels must be positive']
//       },
//       depth: {
//         type: String,
//         enum: ['uchar', 'char', 'ushort', 'short', 'uint', 'int', 'float', 'double']
//       },
//       density: {
//         type: Number,
//         min: [1, 'Density must be positive']
//       },
//       hasProfile: {
//         type: Boolean,
//         default: false
//       },
//       isAnimated: {
//         type: Boolean,
//         default: false
//       },
//       pages: {
//         type: Number,
//         min: [1, 'Pages must be positive'],
//         default: 1
//       },
//       format: {
//         type: String,
//         trim: true
//       },
//       space: {
//         type: String,
//         enum: ['srgb', 'rgb', 'cmyk', 'lab', 'grey', 'b-w']
//       }
//     },
//     checksums: {
//       md5: {
//         type: String,
//         trim: true,
//         match: [/^[a-f0-9]{32}$/, 'MD5 checksum must be 32 hexadecimal characters']
//       },
//       sha256: {
//         type: String,
//         trim: true,
//         match: [/^[a-f0-9]{64}$/, 'SHA256 checksum must be 64 hexadecimal characters']
//       }
//     },
//     thumbnailPath: {
//       type: String,
//       trim: true
//     },
//     analysisData: {
//       type: mongoose.Schema.Types.Mixed
//     }
//   }],
  
//   // Processing information
//   processing: {
//     isProcessing: {
//       type: Boolean,
//       default: false
//     },
//     startedAt: {
//       type: Date
//     },
//     completedAt: {
//       type: Date
//     },
//     processingTime: {
//       type: Number, // in seconds
//       min: [0, 'Processing time cannot be negative']
//     },
//     success: {
//       type: Boolean
//     },
//     stages: {
//       fileValidation: {
//         status: {
//           type: String,
//           enum: ['pending', 'in_progress', 'completed', 'failed'],
//           default: 'pending'
//         },
//         startedAt: {
//           type: Date
//         },
//         completedAt: {
//           type: Date
//         },
//         errors: [{
//           type: String,
//           trim: true
//         }],
//         duration: {
//           type: Number // in seconds
//         }
//       },
//       imagePreperation: {
//         status: {
//           type: String,
//           enum: ['pending', 'in_progress', 'completed', 'failed'],
//           default: 'pending'
//         },
//         startedAt: {
//           type: Date
//         },
//         completedAt: {
//           type: Date
//         },
//         errors: [{
//           type: String,
//           trim: true
//         }],
//         duration: {
//           type: Number
//         }
//       },
//       apiSubmission: {
//         status: {
//           type: String,
//           enum: ['pending', 'in_progress', 'completed', 'failed'],
//           default: 'pending'
//         },
//         startedAt: {
//           type: Date
//         },
//         completedAt: {
//           type: Date
//         },
//         errors: [{
//           type: String,
//           trim: true
//         }],
//         duration: {
//           type: Number
//         },
//         requestId: {
//           type: String,
//           trim: true
//         },
//         responseSize: {
//           type: Number,
//           min: [0, 'Response size cannot be negative']
//         }
//       },
//       resultProcessing: {
//         status: {
//           type: String,
//           enum: ['pending', 'in_progress', 'completed', 'failed'],
//           default: 'pending'
//         },
//         startedAt: {
//           type: Date
//         },
//         completedAt: {
//           type: Date
//         },
//         errors: [{
//           type: String,
//           trim: true
//         }],
//         duration: {
//           type: Number
//         }
//       }
//     },
//     retryCount: {
//       type: Number,
//       min: [0, 'Retry count cannot be negative'],
//       default: 0
//     },
//     maxRetries: {
//       type: Number,
//       min: [0, 'Max retries cannot be negative'],
//       default: 3
//     }
//   },
  
//   // Progress tracking
//   progress: {
//     currentStage: {
//       type: String,
//       enum: ['upload', 'validation', 'preparation', 'analysis', 'processing', 'completed'],
//       default: 'upload'
//     },
//     percentComplete: {
//       type: Number,
//       min: [0, 'Percent complete cannot be negative'],
//       max: [100, 'Percent complete cannot exceed 100'],
//       default: 0
//     },
//     filesUploaded: {
//       type: Number,
//       min: [0, 'Files uploaded cannot be negative'],
//       default: 0
//     },
//     filesProcessed: {
//       type: Number,
//       min: [0, 'Files processed cannot be negative'],
//       default: 0
//     },
//     estimatedTimeRemaining: {
//       type: Number, // in seconds
//       min: [0, 'Estimated time remaining cannot be negative']
//     }
//   },
  
//   // Error handling
//   errors: [{
//     type: String,
//     trim: true,
//     maxlength: [500, 'Error message cannot exceed 500 characters']
//   }],
  
//   lastError: {
//     message: {
//       type: String,
//       trim: true,
//       maxlength: [500, 'Error message cannot exceed 500 characters']
//     },
//     timestamp: {
//       type: Date
//     },
//     code: {
//       type: String,
//       trim: true,
//       uppercase: true
//     },
//     recoverable: {
//       type: Boolean,
//       default: true
//     }
//   },
  
//   // Session metadata
//   metadata: {
//     clientInfo: {
//       userAgent: {
//         type: String,
//         trim: true,
//         maxlength: [500, 'User agent cannot exceed 500 characters']
//       },
//       ipAddress: {
//         type: String,
//         trim: true,
//         match: [/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/, 'Invalid IP address format']
//       },
//       platform: {
//         type: String,
//         trim: true,
//         maxlength: [50, 'Platform cannot exceed 50 characters']
//       },
//       browserName: {
//         type: String,
//         trim: true,
//         maxlength: [50, 'Browser name cannot exceed 50 characters']
//       },
//       browserVersion: {
//         type: String,
//         trim: true,
//         maxlength: [20, 'Browser version cannot exceed 20 characters']
//       }
//     },
//     uploadMethod: {
//       type: String,
//       enum: ['drag_drop', 'file_select', 'api_upload', 'bulk_upload'],
//       default: 'file_select'
//     },
//     connectionType: {
//       type: String,
//       enum: ['wifi', 'cellular', 'ethernet', 'unknown'],
//       default: 'unknown'
//     },
//     uploadLocation: {
//       type: String,
//       trim: true,
//       maxlength: [100, 'Upload location cannot exceed 100 characters']
//     }
//   },
  
//   // Expiration and cleanup
//   expiresAt: {
//     type: Date,
//     default: function() {
//       // Sessions expire after 24 hours
//       return new Date(Date.now() + 24 * 60 * 60 * 1000);
//     },
//     index: { expireAfterSeconds: 0 }
//   },
  
//   isCleanedUp: {
//     type: Boolean,
//     default: false
//   },
  
//   cleanedUpAt: {
//     type: Date
//   },
  
//   // Archive information
//   archived: {
//     type: Boolean,
//     default: false
//   },
  
//   archivedAt: {
//     type: Date
//   },
  
//   archiveReason: {
//     type: String,
//     enum: ['completed', 'expired', 'cancelled', 'failed', 'admin_action'],
//     trim: true
//   },
  
//   // Integration tracking
//   integration: {
//     flaskApiCalled: {
//       type: Boolean,
//       default: false
//     },
//     flaskApiCallTime: {
//       type: Date
//     },
//     flaskApiResponse: {
//       type: mongoose.Schema.Types.Mixed
//     },
//     flaskApiError: {
//       type: String,
//       trim: true
//     },
//     diagnosisResultId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'DiagnosisResult'
//     }
//   }
// }, {
//   timestamps: true,
//   toJSON: { virtuals: true },
//   toObject: { virtuals: true }
// });

// // Virtual for session duration
// uploadSessionSchema.virtual('sessionDuration').get(function() {
//   const start = this.createdAt;
//   const end = this.processing.completedAt || new Date();
//   return Math.round((end - start) / 1000); // in seconds
// });

// // Virtual for upload speed
// uploadSessionSchema.virtual('uploadSpeed').get(function() {
//   if (this.files.length === 0 || !this.processing.completedAt) return 0;
  
//   const totalSize = this.files.reduce((sum, file) => sum + file.size, 0);
//   const duration = this.sessionDuration;
  
//   return duration > 0 ? Math.round(totalSize / duration) : 0; // bytes per second
// });

// // Virtual for success rate
// uploadSessionSchema.virtual('successRate').get(function() {
//   if (this.files.length === 0) return 0;
  
//   const successfulFiles = this.files.filter(file => file.status === FILE_STATUS.COMPLETED).length;
//   return (successfulFiles / this.files.length) * 100;
// });

// // Virtual for is expired
// uploadSessionSchema.virtual('isExpired').get(function() {
//   return this.expiresAt && this.expiresAt < new Date();
// });

// // Indexes for performance
// uploadSessionSchema.index({ sessionId: 1 }, { unique: true });
// uploadSessionSchema.index({ user: 1 });
// uploadSessionSchema.index({ test: 1 });
// uploadSessionSchema.index({ testId: 1 });
// uploadSessionSchema.index({ status: 1 });
// uploadSessionSchema.index({ createdAt: -1 });
// uploadSessionSchema.index({ expiresAt: 1 });
// uploadSessionSchema.index({ isCleanedUp: 1 });

// // Compound indexes
// uploadSessionSchema.index({ user: 1, status: 1, createdAt: -1 });
// uploadSessionSchema.index({ status: 1, 'processing.isProcessing': 1 });
// uploadSessionSchema.index({ archived: 1, createdAt: -1 });

// // Pre-save middleware to generate session ID
// uploadSessionSchema.pre('save', function(next) {
//   if (!this.sessionId) {
//     this.sessionId = this.constructor.generateSessionId();
//   }
//   next();
// });

// // Pre-save middleware to update progress
// uploadSessionSchema.pre('save', function(next) {
//   this.updateProgress();
//   next();
// });

// // Pre-save middleware to calculate stage durations
// uploadSessionSchema.pre('save', function(next) {
//   Object.keys(this.processing.stages).forEach(stageName => {
//     const stage = this.processing.stages[stageName];
//     if (stage.startedAt && stage.completedAt && !stage.duration) {
//       stage.duration = Math.round((stage.completedAt - stage.startedAt) / 1000);
//     }
//   });
//   next();
// });

// // Instance method to generate session ID
// uploadSessionSchema.statics.generateSessionId = function() {
//   const timestamp = Date.now().toString(36);
//   const randomBytes = crypto.randomBytes(6).toString('hex');
//   return `upload_${timestamp}_${randomBytes}`.toUpperCase();
// };

// // Instance method to update progress
// uploadSessionSchema.methods.updateProgress = function() {
//   const totalFiles = this.files.length;
  
//   if (totalFiles === 0) {
//     this.progress.percentComplete = 0;
//     return;
//   }
  
//   const completedFiles = this.files.filter(file => 
//     file.status === FILE_STATUS.COMPLETED
//   ).length;
  
//   const failedFiles = this.files.filter(file => 
//     file.status === FILE_STATUS.FAILED
//   ).length;
  
//   this.progress.filesUploaded = totalFiles;
//   this.progress.filesProcessed = completedFiles + failedFiles;
  
//   // Calculate overall progress based on stage
//   let stageProgress = 0;
  
//   if (this.progress.currentStage === 'upload') {
//     stageProgress = 20;
//   } else if (this.progress.currentStage === 'validation') {
//     stageProgress = 40;
//   } else if (this.progress.currentStage === 'preparation') {
//     stageProgress = 60;
//   } else if (this.progress.currentStage === 'analysis') {
//     stageProgress = 80;
//   } else if (this.progress.currentStage === 'processing') {
//     stageProgress = 90;
//   } else if (this.progress.currentStage === 'completed') {
//     stageProgress = 100;
//   }
  
//   // Adjust based on file completion
//   const fileProgress = totalFiles > 0 ? (this.progress.filesProcessed / totalFiles) * 20 : 0;
  
//   this.progress.percentComplete = Math.min(100, stageProgress + fileProgress);
// };

// // Instance method to get valid files
// uploadSessionSchema.methods.getValidFiles = function() {
//   return this.files.filter(file => 
//     file.isValid && 
//     file.status === FILE_STATUS.COMPLETED &&
//     file.validationErrors.length === 0
//   );
// };

// // Instance method to get failed files
// uploadSessionSchema.methods.getFailedFiles = function() {
//   return this.files.filter(file => 
//     file.status === FILE_STATUS.FAILED ||
//     file.validationErrors.length > 0
//   );
// };

// // Instance method to start processing
// uploadSessionSchema.methods.startProcessing = function() {
//   this.processing.isProcessing = true;
//   this.processing.startedAt = new Date();
//   this.progress.currentStage = 'validation';
//   this.status = UPLOAD_STATUS.PROCESSING;
  
//   return this.save();
// };

// // Instance method to complete processing
// uploadSessionSchema.methods.completeProcessing = function(success = true) {
//   this.processing.isProcessing = false;
//   this.processing.completedAt = new Date();
//   this.processing.success = success;
  
//   if (this.processing.startedAt) {
//     this.processing.processingTime = Math.round(
//       (this.processing.completedAt - this.processing.startedAt) / 1000
//     );
//   }
  
//   this.status = success ? UPLOAD_STATUS.COMPLETED : UPLOAD_STATUS.FAILED;
//   this.progress.currentStage = success ? 'completed' : 'failed';
//   this.progress.percentComplete = success ? 100 : this.progress.percentComplete;
  
//   return this.save();
// };

// // Instance method to mark processing stage
// uploadSessionSchema.methods.markProcessingStage = function(stage, status, errors = []) {
//   if (this.processing.stages[stage]) {
//     const stageObj = this.processing.stages[stage];
//     stageObj.status = status;
    
//     if (status === 'in_progress' && !stageObj.startedAt) {
//       stageObj.startedAt = new Date();
//     }
    
//     if (['completed', 'failed'].includes(status)) {
//       stageObj.completedAt = new Date();
      
//       if (stageObj.startedAt) {
//         stageObj.duration = Math.round((stageObj.completedAt - stageObj.startedAt) / 1000);
//       }
//     }
    
//     if (errors.length > 0) {
//       stageObj.errors = errors;
//     }
    
//     // Update current stage
//     const stageOrder = ['fileValidation', 'imagePreperation', 'apiSubmission', 'resultProcessing'];
//     const currentIndex = stageOrder.indexOf(stage);
    
//     if (status === 'in_progress') {
//       this.progress.currentStage = ['validation', 'preparation', 'analysis', 'processing'][currentIndex];
//     } else if (status === 'completed' && currentIndex < stageOrder.length - 1) {
//       const nextStage = stageOrder[currentIndex + 1];
//       this.processing.stages[nextStage].status = 'pending';
//     }
//   }
  
//   return this.save();
// };

// // Instance method to add file
// uploadSessionSchema.methods.addFile = function(fileData) {
//   // Check if we're at max files
//   if (this.files.length >= this.config.maxFiles) {
//     throw new Error(`Maximum file limit of ${this.config.maxFiles} reached`);
//   }
  
//   // Check file size
//   if (fileData.size > this.config.maxFileSize) {
//     throw new Error(`File size exceeds maximum limit of ${this.config.maxFileSize} bytes`);
//   }
  
//   // Check file type
//   if (this.config.allowedTypes.length > 0 && !this.config.allowedTypes.includes(fileData.mimetype)) {
//     throw new Error(`File type ${fileData.mimetype} is not allowed`);
//   }
  
//   this.files.push(fileData);
//   this.updateProgress();
  
//   return this.save();
// };

// // Instance method to remove file
// uploadSessionSchema.methods.removeFile = function(filename) {
//   const fileIndex = this.files.findIndex(file => file.filename === filename);
  
//   if (fileIndex === -1) {
//     throw new Error('File not found');
//   }
  
//   this.files.splice(fileIndex, 1);
//   this.updateProgress();
  
//   return this.save();
// };

// // Instance method to cancel session
// uploadSessionSchema.methods.cancel = function(reason = 'User cancelled') {
//   this.status = UPLOAD_STATUS.CANCELLED;
//   this.processing.isProcessing = false;
//   this.processing.completedAt = new Date();
//   this.archiveReason = 'cancelled';
  
//   this.errors.push(`Session cancelled: ${reason}`);
  
//   return this.save();
// };

// // Instance method to cleanup session
// uploadSessionSchema.methods.cleanup = function() {
//   this.isCleanedUp = true;
//   this.cleanedUpAt = new Date();
//   this.archived = true;
//   this.archivedAt = new Date();
  
//   if (!this.archiveReason) {
//     this.archiveReason = 'expired';
//   }
  
//   return this.save();
// };

// // Instance method to get session summary
// uploadSessionSchema.methods.getSummary = function() {
//   return {
//     sessionId: this.sessionId,
//     testId: this.testId,
//     patientId: this.patientId,
//     status: this.status,
//     totalFiles: this.files.length,
//     validFiles: this.getValidFiles().length,
//     failedFiles: this.getFailedFiles().length,
//     progress: this.progress,
//     processing: {
//       isProcessing: this.processing.isProcessing,
//       success: this.processing.success,
//       processingTime: this.processing.processingTime
//     },
//     createdAt: this.createdAt,
//     completedAt: this.processing.completedAt,
//     isExpired: this.isExpired,
//     errors: this.errors.length,
//     lastError: this.lastError
//   };
// };

// // Static method to find expired sessions
// uploadSessionSchema.statics.findExpiredSessions = function() {
//   return this.find({
//     expiresAt: { $lt: new Date() },
//     isCleanedUp: false
//   });
// };

// // Static method to find sessions for cleanup
// uploadSessionSchema.statics.findSessionsForCleanup = function(daysOld = 7) {
//   const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
  
//   return this.find({
//     $or: [
//       { status: { $in: [UPLOAD_STATUS.COMPLETED, UPLOAD_STATUS.FAILED, UPLOAD_STATUS.CANCELLED] } },
//       { expiresAt: { $lt: new Date() } }
//     ],
//     createdAt: { $lt: cutoffDate },
//     isCleanedUp: false
//   });
// };

// // Static method to get upload statistics
// uploadSessionSchema.statics.getUploadStatistics = function(startDate, endDate) {
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
//         totalSessions: { $sum: 1 },
//         completedSessions: {
//           $sum: { $cond: [{ $eq: ['$status', UPLOAD_STATUS.COMPLETED] }, 1, 0] }
//         },
//         failedSessions: {
//           $sum: { $cond: [{ $eq: ['$status', UPLOAD_STATUS.FAILED] }, 1, 0] }
//         },
//         cancelledSessions: {
//           $sum: { $cond: [{ $eq: ['$status', UPLOAD_STATUS.CANCELLED] }, 1, 0] }
//         },
//         totalFiles: { $sum: { $size: '$files' } },
//         avgFilesPerSession: { $avg: { $size: '$files' } },
//         avgProcessingTime: { $avg: '$processing.processingTime' },
//         totalUploadSize: {
//           $sum: {
//             $reduce: {
//               input: '$files',
//               initialValue: 0,
//               in: { $add: ['$$value', '$$this.size'] }
//             }
//           }
//         }
//       }
//     }
//   ]);
// };

// // Static method to get sessions by user
// uploadSessionSchema.statics.getSessionsByUser = function(userId, status = null, limit = 20) {
//   const query = { user: userId };
  
//   if (status) {
//     query.status = status;
//   }
  
//   return this.find(query)
//     .populate('test', 'testId status')
//     .sort({ createdAt: -1 })
//     .limit(limit);
// };

// // Static method to get active sessions count
// uploadSessionSchema.statics.getActiveSessionsCount = function() {
//   return this.countDocuments({
//     status: { $in: [UPLOAD_STATUS.ACTIVE, UPLOAD_STATUS.PROCESSING] },
//     isCleanedUp: false
//   });
// };

// // Create the model
// const UploadSession = mongoose.model('UploadSession', uploadSessionSchema);

// module.exports = UploadSession;
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
      imagePreperation: {
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
  errors: [String],
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
  timestamps: true
});

// Indexes for performance
uploadSessionSchema.index({ sessionId: 1 });
uploadSessionSchema.index({ user: 1, createdAt: -1 });
uploadSessionSchema.index({ status: 1 });
uploadSessionSchema.index({ test: 1 });
uploadSessionSchema.index({ patientId: 1 });
uploadSessionSchema.index({ expiresAt: 1 }); // For cleanup
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

module.exports = mongoose.model('UploadSession', uploadSessionSchema);
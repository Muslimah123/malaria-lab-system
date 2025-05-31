// // 📁 server/src/models/DiagnosisResult.js
// const mongoose = require('mongoose');
// const { PARASITE_TYPES, SEVERITY_LEVELS } = require('../utils/constants');

// const diagnosisResultSchema = new mongoose.Schema({
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
  
//   // Main diagnosis result
//   status: {
//     type: String,
//     enum: {
//       values: ['POS', 'NEG'],
//       message: 'Status must be either POS (positive) or NEG (negative)'
//     },
//     required: [true, 'Diagnosis status is required']
//   },
  
//   // Most probable parasite information
//   mostProbableParasite: {
//     type: {
//       type: String,
//       enum: {
//         values: Object.values(PARASITE_TYPES),
//         message: 'Parasite type must be one of: PF, PM, PO, PV'
//       },
//       required: function() { return this.status === 'POS'; }
//     },
//     confidence: {
//       type: Number,
//       min: [0, 'Confidence cannot be negative'],
//       max: [1, 'Confidence cannot exceed 1'],
//       required: function() { return this.status === 'POS'; }
//     },
//     name: {
//       type: String,
//       enum: [
//         'Plasmodium falciparum',
//         'Plasmodium malariae', 
//         'Plasmodium ovale',
//         'Plasmodium vivax'
//       ]
//     }
//   },
  
//   // Overall parasite to WBC ratio
//   parasiteWbcRatio: {
//     type: Number,
//     min: [0, 'Parasite WBC ratio cannot be negative'],
//     default: 0
//   },
  
//   // Individual image detections
//   detections: [{
//     imageId: {
//       type: String,
//       required: true,
//       trim: true
//     },
//     originalFilename: {
//       type: String,
//       trim: true
//     },
//     parasitesDetected: [{
//       type: {
//         type: String,
//         enum: Object.values(PARASITE_TYPES),
//         required: true
//       },
//       confidence: {
//         type: Number,
//         min: [0, 'Confidence cannot be negative'],
//         max: [1, 'Confidence cannot exceed 1'],
//         required: true
//       },
//       bbox: {
//         x1: { type: Number, required: true },
//         y1: { type: Number, required: true },
//         x2: { type: Number, required: true },
//         y2: { type: Number, required: true }
//       },
//       area: {
//         type: Number,
//         min: [0, 'Area cannot be negative']
//       }
//     }],
//     whiteBloodCellsDetected: {
//       type: Number,
//       min: [0, 'WBC count cannot be negative'],
//       default: 0
//     },
//     parasiteCount: {
//       type: Number,
//       min: [0, 'Parasite count cannot be negative'],
//       default: 0
//     },
//     parasiteWbcRatio: {
//       type: Number,
//       min: [0, 'Parasite WBC ratio cannot be negative'],
//       default: 0
//     }
//   }],
  
//   // Severity assessment
//   severity: {
//     level: {
//       type: String,
//       enum: {
//         values: Object.values(SEVERITY_LEVELS),
//         message: 'Severity level must be one of: mild, moderate, severe'
//       }
//     },
//     score: {
//       type: Number,
//       min: [0, 'Severity score cannot be negative'],
//       max: [100, 'Severity score cannot exceed 100']
//     },
//     factors: [{
//       factor: {
//         type: String,
//         enum: [
//           'parasite_density',
//           'parasite_type',
//           'patient_age',
//           'clinical_symptoms',
//           'complications'
//         ],
//         required: true
//       },
//       value: {
//         type: mongoose.Schema.Types.Mixed
//       },
//       weight: {
//         type: Number,
//         min: [0, 'Weight cannot be negative'],
//         max: [1, 'Weight cannot exceed 1']
//       },
//       contribution: {
//         type: Number,
//         min: [0, 'Contribution cannot be negative']
//       }
//     }],
//     recommendations: [{
//       type: String,
//       trim: true,
//       maxlength: [200, 'Recommendation cannot exceed 200 characters']
//     }],
//     urgency: {
//       type: String,
//       enum: ['low', 'medium', 'high', 'critical'],
//       default: 'medium'
//     }
//   },
  
//   // Statistical analysis
//   statistics: {
//     totalParasites: {
//       type: Number,
//       min: [0, 'Total parasites cannot be negative'],
//       default: 0
//     },
//     totalWBC: {
//       type: Number,
//       min: [0, 'Total WBC cannot be negative'],
//       default: 0
//     },
//     averageConfidence: {
//       type: Number,
//       min: [0, 'Average confidence cannot be negative'],
//       max: [1, 'Average confidence cannot exceed 1']
//     },
//     parasitesByType: {
//       PF: { type: Number, default: 0 },
//       PM: { type: Number, default: 0 },
//       PO: { type: Number, default: 0 },
//       PV: { type: Number, default: 0 }
//     },
//     confidenceDistribution: {
//       high: { type: Number, default: 0 }, // > 0.8
//       medium: { type: Number, default: 0 }, // 0.5-0.8
//       low: { type: Number, default: 0 } // < 0.5
//     }
//   },
  
//   // Flask API response data
//   apiResponse: {
//     rawResponse: {
//       type: mongoose.Schema.Types.Mixed,
//       required: true
//     },
//     processingTime: {
//       type: Number, // in seconds
//       min: [0, 'Processing time cannot be negative']
//     },
//     callTimestamp: {
//       type: Date,
//       required: true
//     },
//     apiVersion: {
//       type: String,
//       trim: true
//     },
//     modelVersion: {
//       type: String,
//       trim: true
//     },
//     requestId: {
//       type: String,
//       trim: true
//     }
//   },
  
//   // Quality metrics
//   quality: {
//     overallScore: {
//       type: Number,
//       min: [0, 'Quality score cannot be negative'],
//       max: [100, 'Quality score cannot exceed 100']
//     },
//     imageQuality: {
//       type: Number,
//       min: [0, 'Image quality score cannot be negative'],
//       max: [100, 'Image quality score cannot exceed 100']
//     },
//     detectionReliability: {
//       type: Number,
//       min: [0, 'Detection reliability cannot be negative'],
//       max: [100, 'Detection reliability cannot exceed 100']
//     },
//     flagged: {
//       type: Boolean,
//       default: false
//     },
//     flagReasons: [{
//       type: String,
//       enum: [
//         'low_confidence',
//         'poor_image_quality',
//         'conflicting_detections',
//         'unusual_pattern',
//         'requires_manual_review'
//       ]
//     }]
//   },
  
//   // Review information
//   review: {
//     required: {
//       type: Boolean,
//       default: false
//     },
//     completed: {
//       type: Boolean,
//       default: false
//     },
//     reviewedBy: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'User'
//     },
//     reviewDate: {
//       type: Date
//     },
//     reviewNotes: {
//       type: String,
//       maxlength: [1000, 'Review notes cannot exceed 1000 characters']
//     },
//     reviewDecision: {
//       type: String,
//       enum: ['approved', 'rejected', 'modified'],
//     },
//     modifications: [{
//       field: {
//         type: String,
//         required: true
//       },
//       originalValue: {
//         type: mongoose.Schema.Types.Mixed
//       },
//       newValue: {
//         type: mongoose.Schema.Types.Mixed
//       },
//       reason: {
//         type: String,
//         maxlength: [200, 'Modification reason cannot exceed 200 characters']
//       }
//     }]
//   },
  
//   // Follow-up recommendations
//   followUp: {
//     required: {
//       type: Boolean,
//       default: false
//     },
//     timeframe: {
//       type: String,
//       enum: ['immediate', '24_hours', '48_hours', '1_week', '2_weeks', '1_month']
//     },
//     recommendations: [{
//       type: String,
//       trim: true,
//       maxlength: [200, 'Follow-up recommendation cannot exceed 200 characters']
//     }],
//     nextTestDate: {
//       type: Date
//     },
//     notified: {
//       type: Boolean,
//       default: false
//     },
//     notificationDate: {
//       type: Date
//     }
//   },
  
//   // Integration data
//   integration: {
//     sentToEMR: {
//       type: Boolean,
//       default: false
//     },
//     emrTransactionId: {
//       type: String,
//       trim: true
//     },
//     sentToEMRAt: {
//       type: Date
//     },
//     emrError: {
//       type: String,
//       trim: true
//     },
//     reportGenerated: {
//       type: Boolean,
//       default: false
//     },
//     reportPath: {
//       type: String,
//       trim: true
//     },
//     reportGeneratedAt: {
//       type: Date
//     }
//   },
  
//   // Notifications sent
//   notifications: [{
//     type: {
//       type: String,
//       enum: ['technician', 'supervisor', 'patient', 'physician'],
//       required: true
//     },
//     method: {
//       type: String,
//       enum: ['email', 'sms', 'push', 'system'],
//       required: true
//     },
//     sentAt: {
//       type: Date,
//       default: Date.now
//     },
//     status: {
//       type: String,
//       enum: ['sent', 'delivered', 'failed'],
//       default: 'sent'
//     },
//     recipientId: {
//       type: String,
//       trim: true
//     }
//   }],
  
//   // System fields
//   isActive: {
//     type: Boolean,
//     default: true
//   },
  
//   version: {
//     type: Number,
//     default: 1
//   },
  
//   // Additional metadata
//   notes: {
//     type: String,
//     maxlength: [1000, 'Notes cannot exceed 1000 characters']
//   },
  
//   tags: [{
//     type: String,
//     trim: true,
//     lowercase: true,
//     maxlength: [30, 'Tag cannot exceed 30 characters']
//   }]
// }, {
//   timestamps: true,
//   toJSON: { virtuals: true },
//   toObject: { virtuals: true }
// });

// // Virtual for parasite density classification
// diagnosisResultSchema.virtual('parasiteDensityClass').get(function() {
//   if (this.parasiteWbcRatio === 0) return 'none';
//   if (this.parasiteWbcRatio < 0.01) return 'low';
//   if (this.parasiteWbcRatio < 0.05) return 'moderate';
//   return 'high';
// });

// // Virtual for risk level
// diagnosisResultSchema.virtual('riskLevel').get(function() {
//   if (this.status === 'NEG') return 'none';
  
//   const severity = this.severity?.level;
//   const parasiteType = this.mostProbableParasite?.type;
  
//   if (severity === 'severe' || parasiteType === 'PF') return 'high';
//   if (severity === 'moderate') return 'medium';
//   return 'low';
// });

// // Virtual for requires immediate action
// diagnosisResultSchema.virtual('requiresImmediateAction').get(function() {
//   return this.status === 'POS' && 
//          (this.severity?.urgency === 'critical' || 
//           this.severity?.level === 'severe' ||
//           this.mostProbableParasite?.type === 'PF');
// });

// // Indexes for performance
// diagnosisResultSchema.index({ testId: 1 }, { unique: true });
// diagnosisResultSchema.index({ patientId: 1 });
// diagnosisResultSchema.index({ status: 1 });
// diagnosisResultSchema.index({ 'mostProbableParasite.type': 1 });
// diagnosisResultSchema.index({ 'severity.level': 1 });
// diagnosisResultSchema.index({ createdAt: -1 });
// diagnosisResultSchema.index({ isActive: 1 });

// // Compound indexes
// diagnosisResultSchema.index({ status: 1, createdAt: -1 });
// diagnosisResultSchema.index({ patientId: 1, createdAt: -1 });
// diagnosisResultSchema.index({ 'mostProbableParasite.type': 1, 'severity.level': 1 });
// diagnosisResultSchema.index({ 'review.required': 1, 'review.completed': 1 });
// diagnosisResultSchema.index({ 'followUp.required': 1, 'followUp.notified': 1 });

// // Pre-save middleware to calculate statistics
// diagnosisResultSchema.pre('save', function(next) {
//   this.calculateStatistics();
//   next();
// });

// // Pre-save middleware to determine severity
// diagnosisResultSchema.pre('save', function(next) {
//   if (this.status === 'POS' && this.isModified('detections')) {
//     this.calculateSeverity();
//   }
//   next();
// });

// // Pre-save middleware to set parasite name
// diagnosisResultSchema.pre('save', function(next) {
//   if (this.mostProbableParasite?.type) {
//     const typeToName = {
//       'PF': 'Plasmodium falciparum',
//       'PM': 'Plasmodium malariae',
//       'PO': 'Plasmodium ovale',
//       'PV': 'Plasmodium vivax'
//     };
//     this.mostProbableParasite.name = typeToName[this.mostProbableParasite.type];
//   }
//   next();
// });

// // Instance method to calculate statistics
// diagnosisResultSchema.methods.calculateStatistics = function() {
//   let totalParasites = 0;
//   let totalWBC = 0;
//   let totalConfidence = 0;
//   let confidenceCount = 0;
  
//   const parasitesByType = { PF: 0, PM: 0, PO: 0, PV: 0 };
//   const confidenceDistribution = { high: 0, medium: 0, low: 0 };
  
//   this.detections.forEach(detection => {
//     totalParasites += detection.parasiteCount;
//     totalWBC += detection.whiteBloodCellsDetected;
    
//     detection.parasitesDetected.forEach(parasite => {
//       parasitesByType[parasite.type]++;
//       totalConfidence += parasite.confidence;
//       confidenceCount++;
      
//       // Classify confidence
//       if (parasite.confidence > 0.8) {
//         confidenceDistribution.high++;
//       } else if (parasite.confidence > 0.5) {
//         confidenceDistribution.medium++;
//       } else {
//         confidenceDistribution.low++;
//       }
//     });
//   });
  
//   this.statistics = {
//     totalParasites,
//     totalWBC,
//     averageConfidence: confidenceCount > 0 ? totalConfidence / confidenceCount : 0,
//     parasitesByType,
//     confidenceDistribution
//   };
// };

// // Instance method to calculate severity
// diagnosisResultSchema.methods.calculateSeverity = function() {
//   if (this.status === 'NEG') {
//     this.severity = {
//       level: null,
//       score: 0,
//       urgency: 'low'
//     };
//     return;
//   }
  
//   let severityScore = 0;
//   const factors = [];
  
//   // Factor 1: Parasite density (40% weight)
//   const densityWeight = 0.4;
//   let densityScore = 0;
  
//   if (this.parasiteWbcRatio > 0.1) {
//     densityScore = 100;
//   } else if (this.parasiteWbcRatio > 0.05) {
//     densityScore = 75;
//   } else if (this.parasiteWbcRatio > 0.02) {
//     densityScore = 50;
//   } else if (this.parasiteWbcRatio > 0.01) {
//     densityScore = 25;
//   }
  
//   factors.push({
//     factor: 'parasite_density',
//     value: this.parasiteWbcRatio,
//     weight: densityWeight,
//     contribution: densityScore * densityWeight
//   });
  
//   severityScore += densityScore * densityWeight;
  
//   // Factor 2: Parasite type (30% weight)
//   const typeWeight = 0.3;
//   let typeScore = 0;
  
//   if (this.mostProbableParasite?.type === 'PF') {
//     typeScore = 80; // P. falciparum is most dangerous
//   } else if (this.mostProbableParasite?.type === 'PV') {
//     typeScore = 40; // P. vivax can cause relapses
//   } else {
//     typeScore = 20; // P. malariae and P. ovale are generally milder
//   }
  
//   factors.push({
//     factor: 'parasite_type',
//     value: this.mostProbableParasite?.type,
//     weight: typeWeight,
//     contribution: typeScore * typeWeight
//   });
  
//   severityScore += typeScore * typeWeight;
  
//   // Factor 3: Detection confidence (20% weight)
//   const confidenceWeight = 0.2;
//   const avgConfidence = this.statistics?.averageConfidence || 0;
//   const confidenceScore = avgConfidence * 100;
  
//   factors.push({
//     factor: 'detection_confidence',
//     value: avgConfidence,
//     weight: confidenceWeight,
//     contribution: confidenceScore * confidenceWeight
//   });
  
//   severityScore += confidenceScore * confidenceWeight;
  
//   // Factor 4: Multiple parasite detection (10% weight)
//   const multipleWeight = 0.1;
//   const parasiteTypes = Object.values(this.statistics?.parasitesByType || {});
//   const multipleTypesDetected = parasiteTypes.filter(count => count > 0).length;
//   const multipleScore = multipleTypesDetected > 1 ? 60 : 0;
  
//   factors.push({
//     factor: 'multiple_species',
//     value: multipleTypesDetected,
//     weight: multipleWeight,
//     contribution: multipleScore * multipleWeight
//   });
  
//   severityScore += multipleScore * multipleWeight;
  
//   // Determine severity level and recommendations
//   let level, urgency, recommendations;
  
//   if (severityScore >= 70) {
//     level = SEVERITY_LEVELS.SEVERE;
//     urgency = 'critical';
//     recommendations = [
//       'Immediate medical attention required',
//       'Consider hospitalization',
//       'Monitor for complications',
//       'Start antimalarial treatment immediately'
//     ];
//   } else if (severityScore >= 40) {
//     level = SEVERITY_LEVELS.MODERATE;
//     urgency = 'high';
//     recommendations = [
//       'Prompt medical evaluation needed',
//       'Begin antimalarial treatment',
//       'Monitor closely for 24-48 hours',
//       'Consider outpatient management'
//     ];
//   } else {
//     level = SEVERITY_LEVELS.MILD;
//     urgency = 'medium';
//     recommendations = [
//       'Medical evaluation recommended',
//       'Start antimalarial treatment',
//       'Follow-up in 1-2 days',
//       'Monitor symptoms'
//     ];
//   }
  
//   this.severity = {
//     level,
//     score: Math.round(severityScore),
//     factors,
//     recommendations,
//     urgency
//   };
  
//   // Set follow-up requirements
//   if (level === SEVERITY_LEVELS.SEVERE) {
//     this.followUp.required = true;
//     this.followUp.timeframe = 'immediate';
//   } else if (level === SEVERITY_LEVELS.MODERATE) {
//     this.followUp.required = true;
//     this.followUp.timeframe = '24_hours';
//   } else {
//     this.followUp.required = true;
//     this.followUp.timeframe = '48_hours';
//   }
  
//   // Set review requirement for severe cases or low confidence
//   if (level === SEVERITY_LEVELS.SEVERE || this.statistics?.averageConfidence < 0.6) {
//     this.review.required = true;
//   }
// };

// // Instance method to generate report summary
// diagnosisResultSchema.methods.generateReport = function() {
//   return {
//     testId: this.testId,
//     patientId: this.patientId,
//     status: this.status,
//     result: this.status === 'POS' ? 'Positive for Malaria' : 'Negative for Malaria',
//     mostProbableParasite: this.mostProbableParasite,
//     severity: this.severity,
//     parasiteCount: this.statistics?.totalParasites || 0,
//     wbcCount: this.statistics?.totalWBC || 0,
//     parasiteWbcRatio: this.parasiteWbcRatio,
//     confidence: this.statistics?.averageConfidence || 0,
//     requiresImmediateAction: this.requiresImmediateAction,
//     followUpRequired: this.followUp?.required || false,
//     reviewRequired: this.review?.required || false,
//     processedAt: this.createdAt,
//     recommendations: this.severity?.recommendations || []
//   };
// };

// // Instance method to add notification
// diagnosisResultSchema.methods.addNotification = function(type, method, recipientId = null) {
//   this.notifications.push({
//     type,
//     method,
//     recipientId,
//     sentAt: new Date()
//   });
  
//   return this.save();
// };

// // Instance method to mark notification as delivered/failed
// diagnosisResultSchema.methods.updateNotificationStatus = function(notificationId, status) {
//   const notification = this.notifications.id(notificationId);
//   if (notification) {
//     notification.status = status;
//   }
  
//   return this.save();
// };

// // Static method to get positive results
// diagnosisResultSchema.statics.getPositiveResults = function(startDate, endDate, limit = 100) {
//   const query = {
//     status: 'POS',
//     isActive: true
//   };
  
//   if (startDate || endDate) {
//     query.createdAt = {};
//     if (startDate) query.createdAt.$gte = new Date(startDate);
//     if (endDate) query.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.find(query)
//     .populate('test', 'testId technician')
//     .sort({ createdAt: -1 })
//     .limit(limit);
// };

// // Static method to get results requiring review
// diagnosisResultSchema.statics.getResultsRequiringReview = function() {
//   return this.find({
//     'review.required': true,
//     'review.completed': false,
//     isActive: true
//   })
//   .populate('test', 'testId technician')
//   .sort({ createdAt: 1 }); // Oldest first
// };

// // Static method to get follow-up required results
// diagnosisResultSchema.statics.getFollowUpRequired = function() {
//   return this.find({
//     'followUp.required': true,
//     'followUp.notified': false,
//     isActive: true
//   })
//   .populate('test', 'testId technician')
//   .sort({ createdAt: 1 });
// };

// // Static method to get diagnosis statistics
// diagnosisResultSchema.statics.getDiagnosisStatistics = function(startDate, endDate) {
//   const matchStage = { isActive: true };
  
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
//         totalDiagnoses: { $sum: 1 },
//         positiveResults: {
//           $sum: { $cond: [{ $eq: ['$status', 'POS'] }, 1, 0] }
//         },
//         negativeResults: {
//           $sum: { $cond: [{ $eq: ['$status', 'NEG'] }, 1, 0] }
//         },
//         severityDistribution: {
//           $push: '$severity.level'
//         },
//         parasiteTypeDistribution: {
//           $push: '$mostProbableParasite.type'
//         },
//         avgConfidence: { $avg: '$statistics.averageConfidence' },
//         avgProcessingTime: { $avg: '$apiResponse.processingTime' },
//         reviewRequired: {
//           $sum: { $cond: ['$review.required', 1, 0] }
//         }
//       }
//     }
//   ]);
// };

// // Static method to get parasite distribution
// diagnosisResultSchema.statics.getParasiteDistribution = function(startDate, endDate) {
//   const matchStage = { 
//     status: 'POS',
//     isActive: true 
//   };
  
//   if (startDate || endDate) {
//     matchStage.createdAt = {};
//     if (startDate) matchStage.createdAt.$gte = new Date(startDate);
//     if (endDate) matchStage.createdAt.$lte = new Date(endDate);
//   }
  
//   return this.aggregate([
//     { $match: matchStage },
//     {
//       $group: {
//         _id: '$mostProbableParasite.type',
//         count: { $sum: 1 },
//         avgConfidence: { $avg: '$mostProbableParasite.confidence' },
//         avgSeverityScore: { $avg: '$severity.score' }
//       }
//     },
//     { $sort: { count: -1 } }
//   ]);
// };

// // Create the model
// const DiagnosisResult = mongoose.model('DiagnosisResult', diagnosisResultSchema);

// module.exports = DiagnosisResult;
// 📁 server/src/models/DiagnosisResult.js
const mongoose = require('mongoose');

const diagnosisResultSchema = new mongoose.Schema({
  test: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test',
    required: true,
    unique: true // One diagnosis result per test
  },
  testId: {
    type: String,
    required: true,
    trim: true,
    uppercase: true
  },
  
  // Main diagnosis result (from Flask API)
  status: {
    type: String,
    enum: ['POS', 'NEG'],
    required: true
  },
  
  // Most probable parasite information
  mostProbableParasite: {
    type: {
      type: String,
      enum: ['PF', 'PM', 'PO', 'PV'], // Plasmodium types
      required: function() {
        return this.status === 'POS';
      }
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      required: function() {
        return this.status === 'POS';
      }
    },
    fullName: {
      type: String,
      required: function() {
        return this.status === 'POS';
      }
    }
  },
  
  // Overall parasite to WBC ratio
  parasiteWbcRatio: {
    type: Number,
    min: 0,
    default: 0
  },
  
  // Detailed detections per image
  detections: [{
    imageId: {
      type: String,
      required: true
    },
    originalFilename: String,
    
    // Parasites detected in this image
    parasitesDetected: [{
      type: {
        type: String,
        enum: ['PF', 'PM', 'PO', 'PV']
      },
      confidence: {
        type: Number,
        min: 0,
        max: 1
      },
      bbox: {
        x1: Number,
        y1: Number,
        x2: Number,
        y2: Number
      }
    }],
    
    // White blood cells detected
    whiteBloodCellsDetected: {
      type: Number,
      min: 0,
      default: 0
    },
    
    // Summary for this image
    parasiteCount: {
      type: Number,
      min: 0,
      default: 0
    },
    parasiteWbcRatio: {
      type: Number,
      min: 0,
      default: 0
    }
  }],
  
  // Severity classification (calculated from API results)
  severity: {
    level: {
      type: String,
      enum: ['negative', 'mild', 'moderate', 'severe'],
      required: true
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1
    },
    basis: {
      type: String,
      enum: ['parasite_density', 'wbc_ratio', 'parasite_count', 'clinical_assessment'],
      default: 'parasite_density'
    }
  },
  
  // Aggregate statistics
  totalParasitesDetected: {
    type: Number,
    min: 0,
    default: 0
  },
  totalWbcDetected: {
    type: Number,
    min: 0,
    default: 0
  },
  totalImagesAnalyzed: {
    type: Number,
    min: 1,
    required: true
  },
  
  // Parasite type distribution
  parasiteDistribution: {
    PF: { type: Number, default: 0 },  // Plasmodium Falciparum
    PM: { type: Number, default: 0 },  // Plasmodium Malariae
    PO: { type: Number, default: 0 },  // Plasmodium Ovale
    PV: { type: Number, default: 0 }   // Plasmodium Vivax
  },
  
  // Quality metrics
  analysisQuality: {
    overallScore: {
      type: Number,
      min: 0,
      max: 100
    },
    imageQualityScores: [{
      imageId: String,
      score: Number,
      issues: [String]
    }],
    confidenceLevel: {
      type: String,
      enum: ['low', 'medium', 'high'],
      default: 'medium'
    }
  },
  
  // API call information
  apiResponse: {
    rawResponse: mongoose.Schema.Types.Mixed, // Store the full Flask API response
    processingTime: Number, // Time taken by Flask API in ms
    modelVersion: String,
    apiVersion: String,
    callTimestamp: {
      type: Date,
      default: Date.now
    }
  },
  
  // Manual review/override
  manualReview: {
    isReviewed: {
      type: Boolean,
      default: false
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    reviewedAt: Date,
    reviewNotes: String,
    overriddenStatus: {
      type: String,
      enum: ['POS', 'NEG']
    },
    overriddenSeverity: {
      type: String,
      enum: ['negative', 'mild', 'moderate', 'severe']
    },
    reviewerConfidence: {
      type: String,
      enum: ['low', 'medium', 'high']
    }
  },
  
  // Flags and metadata
  flags: {
    requiresManualReview: {
      type: Boolean,
      default: false
    },
    lowConfidence: {
      type: Boolean,
      default: false
    },
    inconsistentResults: {
      type: Boolean,
      default: false
    },
    qualityIssues: {
      type: Boolean,
      default: false
    }
  },
  
  // Integration tracking
  exportedToHospital: {
    type: Boolean,
    default: false
  },
  exportedAt: Date,
  hospitalReferenceId: String
  
}, {
  timestamps: true
});

// Indexes for performance
diagnosisResultSchema.index({ test: 1 });
diagnosisResultSchema.index({ testId: 1 });
diagnosisResultSchema.index({ status: 1 });
diagnosisResultSchema.index({ 'severity.level': 1 });
diagnosisResultSchema.index({ createdAt: -1 });
diagnosisResultSchema.index({ 'mostProbableParasite.type': 1 });
diagnosisResultSchema.index({ 'flags.requiresManualReview': 1 });

// Compound indexes
diagnosisResultSchema.index({ status: 1, 'severity.level': 1 });
diagnosisResultSchema.index({ createdAt: -1, status: 1 });

// Virtual for final status (considering manual override)
diagnosisResultSchema.virtual('finalStatus').get(function() {
  return this.manualReview.overriddenStatus || this.status;
});

// Virtual for final severity (considering manual override)
diagnosisResultSchema.virtual('finalSeverity').get(function() {
  return this.manualReview.overriddenSeverity || this.severity.level;
});

// Virtual for parasite type full names
diagnosisResultSchema.virtual('parasiteTypeNames').get(function() {
  const typeNames = {
    'PF': 'Plasmodium Falciparum',
    'PM': 'Plasmodium Malariae', 
    'PO': 'Plasmodium Ovale',
    'PV': 'Plasmodium Vivax'
  };
  return typeNames;
});

// Pre-save middleware to calculate derived fields
diagnosisResultSchema.pre('save', function(next) {
  // Calculate total parasites and WBCs
  this.totalParasitesDetected = this.detections.reduce((total, detection) => {
    return total + detection.parasiteCount;
  }, 0);
  
  this.totalWbcDetected = this.detections.reduce((total, detection) => {
    return total + detection.whiteBloodCellsDetected;
  }, 0);
  
  this.totalImagesAnalyzed = this.detections.length;
  
  // Calculate parasite distribution
  this.parasiteDistribution = { PF: 0, PM: 0, PO: 0, PV: 0 };
  this.detections.forEach(detection => {
    detection.parasitesDetected.forEach(parasite => {
      if (this.parasiteDistribution.hasOwnProperty(parasite.type)) {
        this.parasiteDistribution[parasite.type]++;
      }
    });
  });
  
  // Set flags based on analysis
  this.flags.lowConfidence = this.mostProbableParasite?.confidence < 0.7;
  this.flags.requiresManualReview = this.flags.lowConfidence || this.flags.inconsistentResults;
  
  // Set mostProbableParasite full name
  if (this.mostProbableParasite?.type) {
    this.mostProbableParasite.fullName = this.parasiteTypeNames[this.mostProbableParasite.type];
  }
  
  next();
});

// Static methods
diagnosisResultSchema.statics.getStatistics = function(startDate, endDate) {
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
        totalTests: { $sum: 1 },
        positiveTests: { $sum: { $cond: [{ $eq: ['$status', 'POS'] }, 1, 0] } },
        negativeTests: { $sum: { $cond: [{ $eq: ['$status', 'NEG'] }, 1, 0] } },
        mildCases: { $sum: { $cond: [{ $eq: ['$severity.level', 'mild'] }, 1, 0] } },
        moderateCases: { $sum: { $cond: [{ $eq: ['$severity.level', 'moderate'] }, 1, 0] } },
        severeCases: { $sum: { $cond: [{ $eq: ['$severity.level', 'severe'] }, 1, 0] } },
        avgConfidence: { $avg: '$mostProbableParasite.confidence' },
        reviewedCases: { $sum: { $cond: ['$manualReview.isReviewed', 1, 0] } }
      }
    }
  ]);
};

diagnosisResultSchema.statics.findByStatus = function(status) {
  return this.find({ status }).populate('test');
};

diagnosisResultSchema.statics.findRequiringReview = function() {
  return this.find({ 
    'flags.requiresManualReview': true,
    'manualReview.isReviewed': false 
  }).populate('test');
};

// Instance methods
diagnosisResultSchema.methods.calculateSeverity = function() {
  if (this.status === 'NEG') {
    this.severity = { level: 'negative', confidence: 1.0, basis: 'negative_result' };
    return this.severity;
  }
  
  // Simple severity calculation based on parasite count
  const totalParasites = this.totalParasitesDetected;
  const totalImages = this.totalImagesAnalyzed;
  const parasiteDensity = totalParasites / totalImages;
  
  let level, confidence;
  
  if (parasiteDensity <= 2) {
    level = 'mild';
    confidence = 0.8;
  } else if (parasiteDensity <= 5) {
    level = 'moderate';
    confidence = 0.85;
  } else {
    level = 'severe';
    confidence = 0.9;
  }
  
  this.severity = { level, confidence, basis: 'parasite_density' };
  return this.severity;
};

diagnosisResultSchema.methods.addManualReview = function(reviewData, reviewerId) {
  this.manualReview = {
    isReviewed: true,
    reviewedBy: reviewerId,
    reviewedAt: new Date(),
    ...reviewData
  };
  
  this.flags.requiresManualReview = false;
  return this.save();
};

diagnosisResultSchema.methods.generateReport = function() {
  return {
    testId: this.testId,
    status: this.finalStatus,
    severity: this.finalSeverity,
    parasiteInfo: this.mostProbableParasite,
    totalParasites: this.totalParasitesDetected,
    totalWBC: this.totalWbcDetected,
    imagesAnalyzed: this.totalImagesAnalyzed,
    parasiteDistribution: this.parasiteDistribution,
    confidence: this.analysisQuality.confidenceLevel,
    reviewStatus: this.manualReview.isReviewed ? 'Reviewed' : 'Automated',
    timestamp: this.createdAt
  };
};

module.exports = mongoose.model('DiagnosisResult', diagnosisResultSchema);
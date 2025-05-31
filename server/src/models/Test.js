// 📁 server/src/models/Test.js
const mongoose = require('mongoose');

const testSchema = new mongoose.Schema({
  testId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    uppercase: true
  },
  patientId: {
    type: String,
    required: true,
    trim: true,
    uppercase: true
  },
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient',
    required: true
  },
  // Test metadata
  testType: {
    type: String,
    default: 'malaria_detection',
    enum: ['malaria_detection']
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal'
  },
  
  // Sample information
  sampleType: {
    type: String,
    default: 'blood_smear',
    enum: ['blood_smear', 'thick_smear', 'thin_smear']
  },
  sampleCollectionDate: {
    type: Date,
    default: Date.now
  },
  sampleCollectedBy: {
    type: String,
    trim: true
  },
  
  // Images uploaded
  images: [{
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
    }
  }],
  
  // Test processing
  processedAt: Date,
  processingTime: Number, // in milliseconds
  
  // Staff information
  technician: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  reviewedAt: Date,
  
  // Clinical information
  clinicalNotes: {
    symptoms: [String],
    duration: String,
    severity: String,
    previousTreatment: String,
    additionalNotes: String
  },
  
  // Quality control
  qualityScore: {
    type: Number,
    min: 0,
    max: 100
  },
  qualityNotes: String,
  
  // Integration flags
  sentToHospital: {
    type: Boolean,
    default: false
  },
  hospitalIntegrationId: String,
  sentAt: Date,
  
  // Audit information
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Custom fields for future use
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true
});

// Indexes for performance
testSchema.index({ testId: 1 });
testSchema.index({ patientId: 1 });
testSchema.index({ status: 1 });
testSchema.index({ createdAt: -1 });
testSchema.index({ technician: 1 });
testSchema.index({ sampleCollectionDate: -1 });
testSchema.index({ processedAt: -1 });

// Compound indexes
testSchema.index({ patientId: 1, createdAt: -1 });
testSchema.index({ status: 1, priority: -1 });
testSchema.index({ technician: 1, status: 1 });

// Pre-save middleware to auto-generate test ID
testSchema.pre('save', async function(next) {
  if (!this.testId) {
    // Generate test ID: TEST-YYYYMMDD-XXX
    const today = new Date();
    const dateStr = today.toISOString().slice(0, 10).replace(/-/g, '');
    
    // Find the last test created today
    const lastTest = await this.constructor
      .findOne({ 
        testId: { $regex: `^TEST-${dateStr}` }
      })
      .sort({ testId: -1 });
    
    let sequence = 1;
    if (lastTest) {
      const lastSequence = parseInt(lastTest.testId.split('-')[2]) || 0;
      sequence = lastSequence + 1;
    }
    
    this.testId = `TEST-${dateStr}-${sequence.toString().padStart(3, '0')}`;
  }
  
  // Update processing time if completed
  if (this.status === 'completed' && this.processedAt && this.createdAt) {
    this.processingTime = this.processedAt.getTime() - this.createdAt.getTime();
  }
  
  next();
});

// Virtual for image count
testSchema.virtual('imageCount').get(function() {
  return this.images ? this.images.length : 0;
});

// Virtual for processing duration in minutes
testSchema.virtual('processingDurationMinutes').get(function() {
  if (this.processingTime) {
    return Math.round(this.processingTime / (1000 * 60));
  }
  return null;
});

// Static methods
testSchema.statics.findByStatus = function(status) {
  return this.find({ status, isActive: true }).populate('patient technician');
};

testSchema.statics.findPending = function() {
  return this.find({ 
    status: { $in: ['pending', 'processing'] }, 
    isActive: true 
  }).populate('patient technician');
};

testSchema.statics.findByPatient = function(patientId) {
  return this.find({ 
    patientId: patientId.toUpperCase(), 
    isActive: true 
  }).populate('patient technician reviewedBy').sort({ createdAt: -1 });
};

testSchema.statics.findByTechnician = function(technicianId) {
  return this.find({ 
    technician: technicianId, 
    isActive: true 
  }).populate('patient').sort({ createdAt: -1 });
};

testSchema.statics.getTestStats = function(startDate, endDate) {
  const matchCondition = { isActive: true };
  
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
        pendingTests: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
        processingTests: { $sum: { $cond: [{ $eq: ['$status', 'processing'] }, 1, 0] } },
        completedTests: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
        failedTests: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
        avgProcessingTime: { $avg: '$processingTime' }
      }
    }
  ]);
};

// Instance methods
testSchema.methods.addImage = function(imageData) {
  this.images.push(imageData);
  return this.save();
};

testSchema.methods.updateStatus = function(newStatus, userId = null) {
  this.status = newStatus;
  
  if (newStatus === 'completed') {
    this.processedAt = new Date();
  }
  
  if (newStatus === 'completed' && userId) {
    this.reviewedBy = userId;
    this.reviewedAt = new Date();
  }
  
  return this.save();
};

testSchema.methods.canBeModified = function() {
  return ['pending', 'processing'].includes(this.status);
};

testSchema.methods.canBeDeleted = function(userRole) {
  return userRole === 'admin' || (this.status === 'pending' && userRole === 'supervisor');
};

module.exports = mongoose.model('Test', testSchema);
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
// diagnosisResultSchema.index({ test: 1 });
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
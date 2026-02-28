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
  
  // ✅ FIXED: Main diagnosis result (from Flask API) - Updated to match Python output
  status: {
    type: String,
    enum: ['POSITIVE', 'NEGATIVE'], // ✅ FIXED: Changed from ['POS', 'NEG'] to match Python
    required: true
  },
  
  // ✅ FIXED: Most probable parasite information - Updated conditional validation
  mostProbableParasite: {
    type: {
      type: String,
      enum: ['PF', 'PM', 'PO', 'PV'], // Plasmodium types
      required: function() {
        return this.status === 'POSITIVE'; // ✅ FIXED: Changed from 'POS' to 'POSITIVE'
      }
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      required: function() {
        return this.status === 'POSITIVE'; // ✅ FIXED: Changed from 'POS' to 'POSITIVE'
      }
    },
    fullName: {
      type: String,
      required: function() {
        return this.status === 'POSITIVE'; // ✅ FIXED: Changed from 'POS' to 'POSITIVE'
      }
    }
  },
  
  // Overall parasite to WBC ratio
  parasiteWbcRatio: {
    type: Number,
    min: 0,
    default: 0
  },
  
  // ✅ ENHANCED: Detailed detections per image - Updated to match Python output exactly
  detections: [{
    imageId: {
      type: String,
      required: true
    },
    originalFilename: String,
    annotatedImagePath: String,
    annotatedUrl: String,
    
    // ✅ FIXED: Parasites detected in this image - Updated bbox format
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
      bbox: [Number] 
    }],
    
    
    wbcsDetected: [{
      type: {
        type: String,
        enum: ['WBC'],
        default: 'WBC'
      },
      confidence: {
        type: Number,
        min: 0,
        max: 1
      },
      bbox: [Number] 
    }],
    
    // White blood cells detected count
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
    },
    
    
    metadata: {
      totalDetections: {
        type: Number,
        default: 0
      },
      detectionRate: {
        type: Number,
        default: 1.0
      }
    }
  }],
  
  
  analysisSummary: {
    parasiteTypesDetected: [String], // List of parasite types found
    avgWbcConfidence: {
      type: Number,
      default: 0
    },
    totalWbcDetections: {
      type: Number,
      default: 0
    },
    imagesProcessed: {
      type: Number,
      default: 0
    }
  },
  
  
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
      enum: ['parasite_density', 'wbc_ratio', 'parasite_count', 'clinical_assessment', 'negative_result'],
      default: 'parasite_density'
    }
  },
  
  // ✅ FIXED: Aggregate statistics - Updated field names to match Python output
  totalParasites: { // ✅ FIXED: Changed from totalParasitesDetected
    type: Number,
    min: 0,
    default: 0
  },
  totalWbcs: { // ✅ FIXED: Changed from totalWbcDetected
    type: Number,
    min: 0,
    default: 0
  },
  totalImagesAttempted: { // ✅ FIXED: Changed from totalImagesAnalyzed to match Python
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
  
  // Model type used for inference
  modelType: {
    type: String,
    enum: ['ONNX', 'PyTorch'],
    default: 'ONNX'
  },

  // Timing statistics from inference
  timing: {
    totalPreprocess_ms: { type: Number, default: 0 },
    totalInference_ms: { type: Number, default: 0 },
    totalPostprocess_ms: { type: Number, default: 0 },
    total_ms: { type: Number, default: 0 },
    avgPreprocess_ms: { type: Number, default: 0 },
    avgInference_ms: { type: Number, default: 0 },
    avgPostprocess_ms: { type: Number, default: 0 },
    avg_ms: { type: Number, default: 0 }
  },

  // API call information
  apiResponse: {
    rawResponse: mongoose.Schema.Types.Mixed,
    processingTime: Number,
    modelVersion: String,
    apiVersion: String,
    callTimestamp: {
      type: Date,
      default: Date.now
    }
  },
  
  
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
      enum: ['POSITIVE', 'NEGATIVE'] 
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

// ✅ FIXED: Pre-save middleware - Updated to use correct field names
diagnosisResultSchema.pre('save', function(next) {
  // ✅ FIXED: Calculate total parasites and WBCs using correct field names
  this.totalParasites = this.detections.reduce((total, detection) => {
    return total + detection.parasiteCount;
  }, 0);
  
  this.totalWbcs = this.detections.reduce((total, detection) => {
    return total + detection.whiteBloodCellsDetected;
  }, 0);
  
  this.totalImagesAttempted = this.detections.length;
  
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
        positiveTests: { $sum: { $cond: [{ $eq: ['$status', 'POSITIVE'] }, 1, 0] } }, 
        negativeTests: { $sum: { $cond: [{ $eq: ['$status', 'NEGATIVE'] }, 1, 0] } }, 
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

// ✅ FIXED: Instance methods - Updated severity calculation
diagnosisResultSchema.methods.calculateSeverity = function() {
  if (this.status === 'NEGATIVE') { // ✅ FIXED: Changed from 'NEG'
    this.severity = { level: 'negative', confidence: 1.0, basis: 'negative_result' };
    return this.severity;
  }
  
  // Simple severity calculation based on parasite count
  const totalParasites = this.totalParasites; // ✅ FIXED: Updated field name
  const totalImages = this.totalImagesAttempted; // ✅ FIXED: Updated field name
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
    totalParasites: this.totalParasites, 
    totalWBC: this.totalWbcs, 
    imagesAnalyzed: this.totalImagesAttempted, 
    parasiteDistribution: this.parasiteDistribution,
    confidence: this.analysisQuality.confidenceLevel,
    reviewStatus: this.manualReview.isReviewed ? 'Reviewed' : 'Automated',
    timestamp: this.createdAt
  };
};

module.exports = mongoose.model('DiagnosisResult', diagnosisResultSchema);
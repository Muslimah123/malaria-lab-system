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
      bbox: [Number],
      parasiteId: Number,
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
    // WHO parasitaemia thresholds (thick film, p/µL):
    //   negative  : 0 parasites
    //   mild      : 1 – 999 p/µL
    //   moderate  : 1,000 – 9,999 p/µL  (boundary ≥ 1,000 → moderate)
    //   severe    : ≥ 10,000 p/µL       (boundary ≥ 10,000 → severe)
    //   unknown   : P3 flag — parasitaemia cannot be calculated
    level: {
      type: String,
      enum: ['negative', 'mild', 'moderate', 'severe', 'unknown'],
      required: true
    },
    // Inherits the parasitaemia flag when the underlying density is preliminary.
    // A severity label must never appear clean when its source data is flagged.
    preliminaryFlag: {
      type: String,
      enum: ['P1', 'P2', 'P3', 'P1+P2', null],
      default: null
    },
    // Human-readable display string, e.g.:
    //   "Moderate"
    //   "Moderate (preliminary — P1: high parasitaemia threshold not met)"
    //   "Unknown (P3: zero WBCs — parasitaemia cannot be calculated)"
    note: {
      type: String,
      default: null
    },
    basis: {
      type: String,
      enum: ['who_parasitaemia_threshold', 'negative_result', 'unquantifiable'],
      default: 'who_parasitaemia_threshold'
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
  
  // Parasite density — WHO thick blood film standard only (MM-SOP-09, Section 4.1):
  //   parasites/µL = (parasites counted / WBCs counted) × 8,000
  // Thin film formula (parasitised RBCs × 5,000,000 / total RBCs) is not
  // applicable here as the system does not detect RBCs.
  parasitemia: {
    type: Number,
    min: 0,
    default: 0
  },

  // True when the WHO MM-SOP-09 counting threshold has not been met.
  parasitemiaIsPreliminary: {
    type: Boolean,
    default: false
  },

  // WHO threshold flag code:
  //   P1 — ≥100 parasites but WBCs < 200 (high parasitemia, insufficient WBCs)
  //   P2 — ≤99  parasites but WBCs < 500 (low parasitemia, insufficient WBCs)
  //   P3 — zero WBCs detected (cannot calculate)
  //   null — WHO thresholds met, result is valid
  parasitemiaFlag: {
    type: String,
    enum: ['P1', 'P2', 'P3', 'P1+P2', null],
    default: null
  },

  // Plain-English explanation populated when parasitemiaIsPreliminary is true.
  parasitemiaNote: {
    type: String,
    default: null
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
    },
    // Digital sign-off fields
    signedByName: String,
    verificationCode: String,

    // --- Detection-level review ---
    // Parasites the clinician kept or drew (renumbered 1,2,3… after edits)
    reviewedDetections: [{
      parasiteId:         Number,   // final sequential ID after editing
      type:               { type: String, enum: ['PF', 'PM', 'PO', 'PV'] },
      confidence:         { type: Number, min: 0, max: 1 },
      bbox:               [Number], // [x1, y1, x2, y2]
      source:             { type: String, enum: ['model', 'clinician'], default: 'model' },
      originalParasiteId: Number,   // model's original ID (null for clinician-added)
    }],
    // WBCs the clinician kept or drew
    reviewedWbcs: [{
      wbcId:      Number,
      confidence: { type: Number, min: 0, max: 1 },
      bbox:       [Number],
      source:     { type: String, enum: ['model', 'clinician'], default: 'model' },
    }],
    flaggedParasiteIds: [Number],  // model parasiteIds removed as false positives
    flaggedWbcIds:      [Number],  // model wbcIds removed as false positives

    // Recomputed counts from reviewed detections
    parasiteCountReviewed:              Number,
    wbcCountReviewed:                   Number,
    parasiteWbcRatioReviewed:           Number,
    parasiteDensityPerUlReviewed:       Number,
    parasiteDensityIsPreliminaryReviewed: Boolean,
    parasiteDensityFlagReviewed:        String,
    parasiteDensityNoteReviewed:        String,

    // Per-image reviewed annotated image paths
    reviewedImages: [{
      imageId:           String,
      reviewedImagePath: String,
      reviewedImageUrl:  String,
    }],

    detectionsEdited: { type: Boolean, default: false },
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
  
  // WHO thick blood film parasitaemia (MM-SOP-09, Section 4.1) — thick film only.
  // Thin film formula (parasitised RBCs × 5,000,000 / total RBCs) not applicable:
  // this system does not detect RBCs.
  //
  // WHO counting thresholds applied retrospectively across all slides:
  //   Valid HIGH:  WBCs ≥ 200 AND parasites ≥ 100
  //   Valid LOW:   WBCs ≥ 500 AND parasites ≤  99
  //   P1:  parasites ≥ 100 but WBCs < 200
  //   P2:  parasites ≤  99 but WBCs < 500
  //   P3:  zero WBCs — density cannot be calculated
  const WHO_ASSUMED_WBC_PER_UL = 8000;

  if (this.totalParasites === 0) {
    // NEGATIVE — no parasites detected; parasitaemia is not applicable.
    // Calculating 0 / WBCs × 8,000 = 0 p/µL would be clinically misleading.
    this.parasitemia              = 0;
    this.parasitemiaIsPreliminary = false;
    this.parasitemiaFlag          = null;
    this.parasitemiaNote          = null;

  } else if (this.totalWbcs === 0) {
    // P3 — parasites found but no WBCs; denominator is zero
    this.parasitemia              = 0;
    this.parasitemiaIsPreliminary = true;
    this.parasitemiaFlag          = 'P3';
    this.parasitemiaNote          = `Parasitaemia cannot be calculated: no white blood cells (WBCs) were detected ` +
                                    `in this sample. A valid blood smear should contain WBCs alongside parasites. ` +
                                    `Please check the sample quality and consider repeat testing. ` +
                                    `(${this.totalParasites} parasite(s) detected, 0 WBCs counted.)`;

  } else if (this.totalWbcs >= 200 && this.totalParasites >= 100) {
    // WHO valid — high parasitaemia (early exit at 200 WBCs)
    this.parasitemia              = parseFloat(((this.totalParasites / this.totalWbcs) * WHO_ASSUMED_WBC_PER_UL).toFixed(2));
    this.parasitemiaIsPreliminary = false;
    this.parasitemiaFlag          = null;
    this.parasitemiaNote          = null;

  } else if (this.totalWbcs >= 500) {
    // WHO valid — low parasitaemia (full exit at 500 WBCs)
    this.parasitemia              = parseFloat(((this.totalParasites / this.totalWbcs) * WHO_ASSUMED_WBC_PER_UL).toFixed(2));
    this.parasitemiaIsPreliminary = false;
    this.parasitemiaFlag          = null;
    this.parasitemiaNote          = null;

  } else if (this.totalParasites >= 100) {
    // P1 — ≥100 parasites but batch ended before reaching 200 WBCs
    this.parasitemia              = parseFloat(((this.totalParasites / this.totalWbcs) * WHO_ASSUMED_WBC_PER_UL).toFixed(2));
    this.parasitemiaIsPreliminary = true;
    this.parasitemiaFlag          = 'P1';
    this.parasitemiaNote          = `Preliminary estimate: For high-density infections (100 or more parasites detected), ` +
                                    `WHO guidelines require at least 200 white blood cells (WBCs) to be counted. ` +
                                    `Only ${this.totalWbcs} WBC(s) were detected in this sample. ` +
                                    `The parasitaemia value of ${Math.round(this.parasitemia).toLocaleString('en-US')} p/uL is an estimate and should be interpreted with caution.`;

  } else if (this.totalWbcs >= 200) {
    // P2 — passed 200 WBC checkpoint, parasites < 100,
    // counting should have continued to 500 WBCs but batch ended early
    this.parasitemia              = parseFloat(((this.totalParasites / this.totalWbcs) * WHO_ASSUMED_WBC_PER_UL).toFixed(2));
    this.parasitemiaIsPreliminary = true;
    this.parasitemiaFlag          = 'P2';
    this.parasitemiaNote          = `Preliminary estimate: For low-density infections (fewer than 100 parasites detected), ` +
                                    `WHO guidelines require at least 500 white blood cells (WBCs) to be counted. ` +
                                    `Only ${this.totalWbcs} WBCs were counted in this sample. ` +
                                    `The parasitaemia value of ${Math.round(this.parasitemia).toLocaleString('en-US')} p/uL is an estimate and should be interpreted with caution.`;

  } else {
    // P1+P2 — WBCs < 200 AND parasites ≤ 99: both thresholds unmet simultaneously
    this.parasitemia              = parseFloat(((this.totalParasites / this.totalWbcs) * WHO_ASSUMED_WBC_PER_UL).toFixed(2));
    this.parasitemiaIsPreliminary = true;
    this.parasitemiaFlag          = 'P1+P2';
    this.parasitemiaNote          = `Preliminary estimate: WHO guidelines require at least 200 WBCs for high-density infections ` +
                                    `(100 or more parasites) or 500 WBCs for low-density infections (fewer than 100 parasites). ` +
                                    `Only ${this.totalWbcs} WBC(s) were detected in this sample. ` +
                                    `The parasitaemia value of ${Math.round(this.parasitemia).toLocaleString('en-US')} p/uL is an estimate and should be interpreted with caution.`;
  }

  // ── WHO severity classification ───────────────────────────────────────
  // Direct lookup on parasitaemia (p/µL). Boundaries belong to the higher
  // category (≥ 1,000 → Moderate; ≥ 10,000 → Severe).
  // Severity inherits the parasitaemia flag so a clinician never sees a
  // clean severity label backed by preliminary data.
  if (this.totalParasites === 0) {
    // NEGATIVE — no parasites; severity is not applicable
    this.severity = {
      level:           'negative',
      preliminaryFlag: null,
      note:            'Negative',
      basis:           'negative_result'
    };

  } else if (this.parasitemiaFlag === 'P3') {
    // Unknown — parasitaemia cannot be calculated (zero WBCs)
    this.severity = {
      level:           'unknown',
      preliminaryFlag: 'P3',
      note:            'Unknown (no WBCs detected, parasitaemia cannot be calculated)',
      basis:           'unquantifiable'
    };

  } else {
    // WHO threshold lookup — explicit boundary handling
    let sevLevel;
    if (this.parasitemia >= 10000) {
      sevLevel = 'severe';
    } else if (this.parasitemia >= 1000) {
      sevLevel = 'moderate';
    } else {
      sevLevel = 'mild';
    }

    const displayLevel = sevLevel.charAt(0).toUpperCase() + sevLevel.slice(1);

    this.severity = {
      level:           sevLevel,
      preliminaryFlag: this.parasitemiaFlag || null,
      note:            this.parasitemiaIsPreliminary
                         ? `${displayLevel} (unconfirmed: insufficient WBC count)`
                         : displayLevel,
      basis:           'who_parasitaemia_threshold'
    };
  }

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
  // WHO MM-SOP-09 severity lookup — mirrors the pre-save hook.
  // Call this only when you need to recompute severity on an already-saved
  // document (e.g. after manually patching parasitemia).  For new documents
  // the pre-save hook runs automatically and this method is not needed.

  const SEVERITY_FLAG_LABELS = {
    'P1':    'P1: high parasitaemia threshold not met',
    'P2':    'P2: low parasitaemia threshold not met',
    'P1+P2': 'P1+P2: both WHO thresholds not met',
  };

  if (this.totalParasites === 0) {
    this.severity = {
      level:           'negative',
      preliminaryFlag: null,
      note:            'Negative',
      basis:           'negative_result'
    };

  } else if (this.parasitemiaFlag === 'P3') {
    this.severity = {
      level:           'unknown',
      preliminaryFlag: 'P3',
      note:            'Unknown (no WBCs detected, parasitaemia cannot be calculated)',
      basis:           'unquantifiable'
    };

  } else {
    let sevLevel;
    if (this.parasitemia >= 10000) {
      sevLevel = 'severe';
    } else if (this.parasitemia >= 1000) {
      sevLevel = 'moderate';
    } else {
      sevLevel = 'mild';
    }

    const displayLevel = sevLevel.charAt(0).toUpperCase() + sevLevel.slice(1);
    const flagLabel    = SEVERITY_FLAG_LABELS[this.parasitemiaFlag] || null;

    this.severity = {
      level:           sevLevel,
      preliminaryFlag: this.parasitemiaFlag || null,
      note:            this.parasitemiaIsPreliminary
                         ? `${displayLevel} (preliminary — ${flagLabel})`
                         : displayLevel,
      basis:           'who_parasitaemia_threshold'
    };
  }

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
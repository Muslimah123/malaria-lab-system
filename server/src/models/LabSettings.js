const mongoose = require('mongoose');

const labSettingsSchema = new mongoose.Schema({
  // Laboratory Information
  lab: {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    address: {
      type: String,
      required: true,
      trim: true,
      maxlength: 500
    },
    phone: {
      type: String,
      required: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true
    },
    accreditation: {
      type: String,
      trim: true,
      maxlength: 100
    },
    director: {
      type: String,
      trim: true,
      maxlength: 100
    },
    licenseNumber: {
      type: String,
      trim: true
    }
  },
  // Quality & Workflow Settings
  quality: {
    defaultSampleType: {
      type: String,
      enum: ['blood_smear', 'thick_smear', 'rdt', 'pcr'],
      default: 'blood_smear'
    },
    qualityThreshold: {
      type: Number,
      default: 85,
      min: 50,
      max: 100
    },
    autoReview: {
      type: Boolean,
      default: false
    },
    requireSecondReview: {
      type: Boolean,
      default: true
    },
    retentionPeriod: {
      type: Number,
      default: 365, // days
      min: 30,
      max: 3650
    }
  },
  // System Settings
  system: {
    maintenanceMode: {
      type: Boolean,
      default: false
    },
    allowRegistration: {
      type: Boolean,
      default: false
    },
    defaultUserRole: {
      type: String,
      enum: ['technician', 'supervisor'],
      default: 'technician'
    },
    sessionTimeout: {
      type: Number,
      default: 30, // minutes
      min: 5,
      max: 480
    },
    maxConcurrentSessions: {
      type: Number,
      default: 5,
      min: 1,
      max: 20
    }
  },
  // Integration Settings
  integrations: {
    hospitalEMR: {
      enabled: {
        type: Boolean,
        default: false
      },
      endpoint: {
        type: String,
        trim: true
      },
      apiKey: {
        type: String,
        trim: true
      },
      syncFrequency: {
        type: String,
        enum: ['realtime', 'hourly', 'daily'],
        default: 'daily'
      }
    },
    lims: {
      enabled: {
        type: Boolean,
        default: false
      },
      endpoint: {
        type: String,
        trim: true
      },
      credentials: {
        username: String,
        password: String
      }
    },
    publicHealth: {
      enabled: {
        type: Boolean,
        default: true
      },
      endpoint: {
        type: String,
        trim: true
      },
      reportingFrequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly'],
        default: 'weekly'
      }
    },
    cloudStorage: {
      enabled: {
        type: Boolean,
        default: false
      },
      provider: {
        type: String,
        enum: ['aws', 'azure', 'gcp'],
        default: 'aws'
      },
      credentials: {
        accessKey: String,
        secretKey: String,
        bucket: String
      },
      backupFrequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly'],
        default: 'daily'
      }
    }
  },
  // Notification Templates
  notifications: {
    criticalResultTemplate: {
      type: String,
      default: 'CRITICAL: Severe malaria detected for patient {{patientName}}. Immediate attention required.'
    },
    testCompletionTemplate: {
      type: String,
      default: 'Test {{testId}} for patient {{patientName}} has been completed. Result: {{result}}.'
    },
    systemMaintenanceTemplate: {
      type: String,
      default: 'System maintenance scheduled for {{date}} at {{time}}. Expected duration: {{duration}}.'
    }
  },
  // Audit Settings
  audit: {
    retentionPeriod: {
      type: Number,
      default: 2555, // 7 years in days
      min: 365,
      max: 3650
    },
    logLevel: {
      type: String,
      enum: ['minimal', 'standard', 'detailed'],
      default: 'standard'
    },
    autoArchive: {
      type: Boolean,
      default: true
    }
  },
  // Version and update tracking
  version: {
    type: String,
    default: '1.0.0'
  },
  lastModified: {
    by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    at: {
      type: Date,
      default: Date.now
    },
    reason: {
      type: String,
      trim: true
    }
  }
}, {
  timestamps: true
});

// Ensure only one lab settings document exists
// labSettingsSchema.index({}, { unique: true });

// Static method to get lab settings (create if doesn't exist)
labSettingsSchema.statics.get = async function() {
  let settings = await this.findOne();
  
  if (!settings) {
    settings = new this({
      lab: {
        name: 'Laboratory',
        address: 'Lab Address',
        phone: '+250XXXXXXXXX',
        email: 'info@lab.com'
      }
    });
    await settings.save();
  }
  
  return settings;
};

// Method to update specific section with audit trail
labSettingsSchema.methods.updateSection = async function(section, data, modifiedBy, reason = '') {
  if (this[section]) {
    Object.assign(this[section], data);
    this.lastModified = {
      by: modifiedBy,
      at: new Date(),
      reason
    };
    return this.save();
  }
  throw new Error(`Invalid settings section: ${section}`);
};

module.exports = mongoose.model('LabSettings', labSettingsSchema);
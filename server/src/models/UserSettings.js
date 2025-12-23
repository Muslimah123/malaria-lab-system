// 📁 server/src/models/UserSettings.js
const mongoose = require('mongoose');

const userSettingsSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  // Notification Preferences
  notifications: {
    criticalResults: {
      type: Boolean,
      default: true
    },
    testCompletion: {
      type: Boolean,
      default: true
    },
    systemAlerts: {
      type: Boolean,
      default: true
    },
    dailyReports: {
      type: Boolean,
      default: false
    },
    weeklyReports: {
      type: Boolean,
      default: true
    },
    // Notification Channels
    email: {
      type: Boolean,
      default: true
    },
    sms: {
      type: Boolean,
      default: false
    },
    push: {
      type: Boolean,
      default: true
    },
    sound: {
      type: Boolean,
      default: true
    },
    frequency: {
      type: String,
      enum: ['immediate', 'hourly', 'daily'],
      default: 'immediate'
    }
  },
  // Display Preferences
  display: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'system'],
      default: 'dark'
    },
    language: {
      type: String,
      enum: ['en', 'fr', 'rw', 'sw'],
      default: 'en'
    },
    timezone: {
      type: String,
      default: 'Africa/Kigali'
    },
    dateFormat: {
      type: String,
      enum: ['DD/MM/YYYY', 'MM/DD/YYYY', 'YYYY-MM-DD'],
      default: 'DD/MM/YYYY'
    },
    timeFormat: {
      type: String,
      enum: ['12h', '24h'],
      default: '24h'
    },
    density: {
      type: String,
      enum: ['comfortable', 'compact'],
      default: 'comfortable'
    },
    animations: {
      type: Boolean,
      default: true
    }
  },
  // Security Preferences
  security: {
    twoFactor: {
      type: Boolean,
      default: false
    },
    sessionTimeout: {
      type: Number,
      default: 30, // minutes
      min: 5,
      max: 480
    },
    autoLock: {
      type: Number,
      default: 15, // minutes
      min: 0,
      max: 60
    },
    loginNotifications: {
      type: Boolean,
      default: true
    },
    passwordExpiry: {
      type: Number,
      default: 90, // days
      min: 30,
      max: 365
    }
  },
  // Dashboard Preferences
  dashboard: {
    defaultView: {
      type: String,
      enum: ['overview', 'tests', 'analytics'],
      default: 'overview'
    },
    refreshInterval: {
      type: Number,
      default: 300, // seconds
      min: 30,
      max: 3600
    },
    autoRefresh: {
      type: Boolean,
      default: true
    },
    compactMode: {
      type: Boolean,
      default: false
    }
  }
}, {
  timestamps: true
});

// Indexes
// userSettingsSchema.index({ user: 1 });

// Static method to get settings for a user (create if doesn't exist)
userSettingsSchema.statics.getForUser = async function(userId) {
  let settings = await this.findOne({ user: userId });
  
  if (!settings) {
    settings = new this({ user: userId });
    await settings.save();
  }
  
  return settings;
};

// Method to update specific section
userSettingsSchema.methods.updateSection = async function(section, data) {
  if (this[section]) {
    Object.assign(this[section], data);
    return this.save();
  }
  throw new Error(`Invalid settings section: ${section}`);
};

module.exports = mongoose.model('UserSettings', userSettingsSchema);


// 📁 server/src/models/Patient.js
const mongoose = require('mongoose');

const patientSchema = new mongoose.Schema({
  patientId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    uppercase: true // Convert to uppercase for consistency
  },
  // Basic patient information
  firstName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  dateOfBirth: {
    type: Date
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'unknown'],
    default: 'unknown'
  },
  age: {
    type: Number,
    min: 0,
    max: 150
  },
  // Contact information
  phoneNumber: {
    type: String,
    trim: true
  },
  email: {
    type: String,
    lowercase: true,
    trim: true
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: {
      type: String,
      default: 'Rwanda'
    }
  },
  // Medical information
  bloodType: {
    type: String,
    enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'unknown'],
    default: 'unknown'
  },
  allergies: [{
    type: String,
    trim: true
  }],
  medicalHistory: [{
    condition: String,
    diagnosedDate: Date,
    notes: String
  }],
  // Emergency contact
  emergencyContact: {
    name: String,
    relationship: String,
    phoneNumber: String
  },
  // Hospital/clinic information
  hospitalId: {
    type: String,
    trim: true // For future hospital integration
  },
  referringPhysician: {
    name: String,
    licenseNumber: String,
    department: String
  },
  // Test history summary
  totalTests: {
    type: Number,
    default: 0
  },
  positiveTests: {
    type: Number,
    default: 0
  },
  lastTestDate: {
    type: Date
  },
  lastTestResult: {
    type: String,
    enum: ['POS', 'NEG']
  },
  // Data management
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance
patientSchema.index({ patientId: 1 });
patientSchema.index({ lastName: 1, firstName: 1 });
patientSchema.index({ createdAt: -1 });
patientSchema.index({ lastTestDate: -1 });
patientSchema.index({ isActive: 1 });

// Virtual for full name
patientSchema.virtual('fullName').get(function() {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.patientId; // Fallback to patient ID
});

// Virtual for age calculation if DOB is provided
patientSchema.virtual('calculatedAge').get(function() {
  if (this.dateOfBirth) {
    const today = new Date();
    const birthDate = new Date(this.dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    return age;
  }
  return this.age; // Return manually entered age
});

// Pre-save middleware to auto-generate patient ID if not provided
patientSchema.pre('save', async function(next) {
  if (!this.patientId) {
    // Generate patient ID: PAT-YYYYMMDD-XXX
    const today = new Date();
    const dateStr = today.toISOString().slice(0, 10).replace(/-/g, '');
    
    // Find the last patient created today
    const lastPatient = await this.constructor
      .findOne({ 
        patientId: { $regex: `^PAT-${dateStr}` }
      })
      .sort({ patientId: -1 });
    
    let sequence = 1;
    if (lastPatient) {
      const lastSequence = parseInt(lastPatient.patientId.split('-')[2]) || 0;
      sequence = lastSequence + 1;
    }
    
    this.patientId = `PAT-${dateStr}-${sequence.toString().padStart(3, '0')}`;
  }
  
  // Update calculated age if DOB is provided
  if (this.dateOfBirth && !this.age) {
    this.age = this.calculatedAge;
  }
  
  next();
});

// Static methods
patientSchema.statics.findByPatientId = function(patientId) {
  return this.findOne({ patientId: patientId.toUpperCase(), isActive: true });
};

patientSchema.statics.searchPatients = function(searchTerm) {
  const regex = new RegExp(searchTerm, 'i');
  return this.find({
    isActive: true,
    $or: [
      { patientId: regex },
      { firstName: regex },
      { lastName: regex },
      { phoneNumber: regex }
    ]
  });
};

// Instance method to get test statistics
patientSchema.methods.getTestStats = function() {
  return {
    total: this.totalTests,
    positive: this.positiveTests,
    negative: this.totalTests - this.positiveTests,
    positiveRate: this.totalTests > 0 ? (this.positiveTests / this.totalTests * 100).toFixed(1) : 0
  };
};

module.exports = mongoose.model('Patient', patientSchema);
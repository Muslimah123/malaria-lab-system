// server/src/models/Treatment.js
const mongoose = require('mongoose');

const treatmentSchema = new mongoose.Schema({
  test: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test',
    required: true
  },
  testId: {
    type: String,
    required: true,
    uppercase: true,
    trim: true
  },
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient',
    required: true
  },
  patientId: {
    type: String,
    required: true,
    uppercase: true,
    trim: true
  },
  prescribedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  prescribedAt: {
    type: Date,
    default: Date.now
  },

  // Treatment details
  drug: {
    type: String,
    enum: [
      'Artemether-Lumefantrine',
      'Artesunate',
      'Artesunate-Amodiaquine',
      'Dihydroartemisinin-Piperaquine',
      'Quinine',
      'Chloroquine',
      'Primaquine',
      'Other'
    ],
    required: true
  },
  drugOther: String,       // filled when drug = 'Other'
  dosage: {
    type: String,
    required: true,
    trim: true
  },
  duration: {
    type: String,
    required: true,
    trim: true
  },
  route: {
    type: String,
    enum: ['oral', 'iv', 'im'],
    default: 'oral'
  },

  // Follow-up
  followUpDate: Date,
  followUpNotes: String,

  // Outcome
  outcome: {
    type: String,
    enum: ['pending', 'improving', 'cured', 'treatment_failure', 'referred', 'lost_to_followup'],
    default: 'pending'
  },
  outcomeUpdatedAt: Date,
  outcomeUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  notes: String
}, {
  timestamps: true
});

treatmentSchema.index({ testId: 1 });
treatmentSchema.index({ patientId: 1 });
treatmentSchema.index({ outcome: 1 });
treatmentSchema.index({ followUpDate: 1 });

module.exports = mongoose.model('Treatment', treatmentSchema);

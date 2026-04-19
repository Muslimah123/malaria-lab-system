// server/src/controllers/treatmentController.js
const Treatment = require('../models/Treatment');
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class TreatmentController {

  // POST /api/treatments  — record a new treatment
  async createTreatment(req, res, next) {
    try {
      const { testId, drug, drugOther, dosage, duration, route, followUpDate, notes } = req.body;
      const user = req.user;

      if (!testId || !drug || !dosage || !duration) {
        return res.status(400).json({ success: false, message: 'testId, drug, dosage and duration are required' });
      }

      const test = await Test.findOne({ testId: testId.toUpperCase() }).populate('patient');
      if (!test) return res.status(404).json({ success: false, message: 'Test not found' });

      const diagnosis = await DiagnosisResult.findOne({ test: test._id });
      if (!diagnosis || diagnosis.status !== 'POSITIVE') {
        return res.status(400).json({ success: false, message: 'Treatment can only be recorded for POSITIVE results' });
      }

      const existing = await Treatment.findOne({ testId: testId.toUpperCase() });
      if (existing) {
        return res.status(409).json({ success: false, message: 'Treatment already recorded for this test. Use PATCH to update.' });
      }

      const created = await Treatment.create({
        test: test._id,
        testId: testId.toUpperCase(),
        patient: test.patient._id,
        patientId: test.patientId,
        prescribedBy: user._id,
        drug,
        drugOther: drug === 'Other' ? drugOther : undefined,
        dosage,
        duration,
        route: route || 'oral',
        followUpDate: followUpDate ? new Date(followUpDate) : undefined,
        notes
      });

      const treatment = await Treatment.findById(created._id)
        .populate('prescribedBy', 'firstName lastName username');

      await auditService.log({
        action: 'treatment_recorded',
        userId: user._id,
        userInfo: { username: user.username, role: user.role },
        resourceType: 'treatment',
        resourceId: testId,
        details: { drug, dosage, duration },
        status: 'success',
        riskLevel: 'medium'
      });

      res.status(201).json({ success: true, data: { treatment } });
    } catch (error) {
      logger.error('Create treatment error:', error);
      next(new AppError('Failed to record treatment', 500));
    }
  }

  // GET /api/treatments/test/:testId
  async getByTestId(req, res, next) {
    try {
      const treatment = await Treatment.findOne({ testId: req.params.testId.toUpperCase() })
        .populate('prescribedBy', 'firstName lastName username')
        .populate('outcomeUpdatedBy', 'firstName lastName username');

      if (!treatment) {
        return res.status(404).json({ success: false, message: 'No treatment recorded for this test' });
      }

      res.json({ success: true, data: { treatment } });
    } catch (error) {
      logger.error('Get treatment error:', error);
      next(new AppError('Failed to get treatment', 500));
    }
  }

  // GET /api/treatments/patient/:patientId  — full treatment history for a patient
  async getByPatient(req, res, next) {
    try {
      const treatments = await Treatment.find({ patientId: req.params.patientId.toUpperCase() })
        .populate('prescribedBy', 'firstName lastName')
        .populate('test', 'testId createdAt')
        .sort({ createdAt: -1 });

      res.json({ success: true, data: { treatments } });
    } catch (error) {
      logger.error('Get patient treatments error:', error);
      next(new AppError('Failed to get treatment history', 500));
    }
  }

  // PATCH /api/treatments/:treatmentId/outcome  — update outcome
  async updateOutcome(req, res, next) {
    try {
      const { outcome, followUpNotes } = req.body;
      const user = req.user;

      const validOutcomes = ['pending', 'improving', 'cured', 'treatment_failure', 'referred', 'lost_to_followup'];
      if (!outcome || !validOutcomes.includes(outcome)) {
        return res.status(400).json({ success: false, message: 'Valid outcome is required' });
      }

      const treatment = await Treatment.findById(req.params.treatmentId);
      if (!treatment) return res.status(404).json({ success: false, message: 'Treatment not found' });

      treatment.outcome = outcome;
      treatment.outcomeUpdatedAt = new Date();
      treatment.outcomeUpdatedBy = user._id;
      if (followUpNotes) treatment.followUpNotes = followUpNotes;
      await treatment.save();

      await treatment.populate('prescribedBy', 'firstName lastName username');

      await auditService.log({
        action: 'treatment_outcome_updated',
        userId: user._id,
        userInfo: { username: user.username, role: user.role },
        resourceType: 'treatment',
        resourceId: treatment.testId,
        details: { outcome },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({ success: true, data: { treatment } });
    } catch (error) {
      logger.error('Update outcome error:', error);
      next(new AppError('Failed to update outcome', 500));
    }
  }

  // GET /api/treatments/followups  — upcoming follow-ups (next 7 days)
  async getUpcomingFollowups(req, res, next) {
    try {
      const now = new Date();
      const in7days = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

      const treatments = await Treatment.find({
        followUpDate: { $gte: now, $lte: in7days },
        outcome: { $in: ['pending', 'improving'] }
      })
        .populate('patient', 'firstName lastName patientId')
        .populate('prescribedBy', 'firstName lastName')
        .sort({ followUpDate: 1 });

      res.json({ success: true, data: { treatments, count: treatments.length } });
    } catch (error) {
      logger.error('Get followups error:', error);
      next(new AppError('Failed to get follow-ups', 500));
    }
  }
}

module.exports = new TreatmentController();

// 📁 server/src/controllers/patientController.js
const Patient = require('../models/Patient');
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const auditService = require('../services/auditService');
const reportService = require('../services/reportService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class PatientController {
  /**
   * Get all patients with filtering and pagination
   */
  async getAllPatients(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        gender,
        bloodType,
        hasPositiveTests,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Build filter object
      const filter = { isActive: true };

      if (gender) filter.gender = gender;
      if (bloodType) filter.bloodType = bloodType;
      if (hasPositiveTests === 'true') filter.positiveTests = { $gt: 0 };

      // Search functionality
      if (search) {
        const searchRegex = new RegExp(search, 'i');
        filter.$or = [
          { patientId: searchRegex },
          { firstName: searchRegex },
          { lastName: searchRegex },
          { phoneNumber: searchRegex },
          { email: searchRegex }
        ];
      }

      // Build sort object
      const sort = {};
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

      // Execute query with pagination
      const [patients, total] = await Promise.all([
        Patient.find(filter)
          .populate('createdBy', 'username firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        Patient.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          patients,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: totalPages,
            hasNextPage: page < totalPages,
            hasPrevPage: page > 1
          }
        }
      });

    } catch (error) {
      logger.error('Get all patients error:', error);
      next(new AppError('Failed to retrieve patients', 500));
    }
  }

  /**
   * Create a new patient
   */
  async createPatient(req, res, next) {
    try {
      const patientData = req.body;
      const user = req.user;

      // Check if patient ID already exists (if provided)
      if (patientData.patientId) {
        const existingPatient = await Patient.findByPatientId(patientData.patientId);
        if (existingPatient) {
          return res.status(409).json({
            success: false,
            message: 'Patient ID already exists'
          });
        }
      }

      // Create new patient
      const patient = new Patient({
        ...patientData,
        createdBy: user._id
      });

      await patient.save();

      // Populate created by for response
      await patient.populate('createdBy', 'username firstName lastName');

      // Log patient creation
      await auditService.log({
        action: 'patient_created',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'patient',
        resourceId: patient.patientId,
        resourceName: patient.fullName || patient.patientId,
        details: {
          patientData: {
            patientId: patient.patientId,
            name: patient.fullName,
            age: patient.age,
            gender: patient.gender
          }
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: '/api/patients'
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.status(201).json({
        success: true,
        message: 'Patient created successfully',
        data: {
          patient
        }
      });

    } catch (error) {
      logger.error('Create patient error:', error);
      
      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          message: 'Patient ID already exists'
        });
      }
      
      next(new AppError('Failed to create patient', 500));
    }
  }

  /**
   * Get patient by ID
   */
  async getPatientById(req, res, next) {
    try {
      const { patientId } = req.params;

      const patient = await Patient.findByPatientId(patientId)
        .populate('createdBy', 'username firstName lastName')
        .populate('updatedBy', 'username firstName lastName');

      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Log patient access
      await auditService.log({
        action: 'patient_viewed',
        userId: req.user._id,
        userInfo: { username: req.user.username, email: req.user.email, role: req.user.role },
        resourceType: 'patient',
        resourceId: patient.patientId,
        resourceName: patient.fullName || patient.patientId,
        details: {
          patientId: patient.patientId,
          viewedFields: ['basic_info', 'contact_info', 'medical_info']
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'GET',
          endpoint: `/api/patients/${patientId}`
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        data: {
          patient,
          testStatistics: patient.getTestStats()
        }
      });

    } catch (error) {
      logger.error('Get patient by ID error:', error);
      next(new AppError('Failed to retrieve patient', 500));
    }
  }

  /**
   * Update patient information
   */
  async updatePatient(req, res, next) {
    try {
      const { patientId } = req.params;
      const updateData = req.body;
      const user = req.user;

      const patient = await Patient.findByPatientId(patientId);

      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Track changes for audit log
      const originalData = patient.toObject();
      const changes = [];

      // Update allowed fields
      const allowedFields = [
        'firstName', 'lastName', 'dateOfBirth', 'gender', 'age', 
        'phoneNumber', 'email', 'address', 'bloodType', 'allergies', 
        'medicalHistory', 'emergencyContact', 'referringPhysician'
      ];

      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          if (JSON.stringify(patient[field]) !== JSON.stringify(updateData[field])) {
            changes.push(field);
            patient[field] = updateData[field];
          }
        }
      });

      if (changes.length === 0) {
        return res.json({
          success: true,
          message: 'No changes detected',
          data: { patient }
        });
      }

      // Set updated by
      patient.updatedBy = user._id;
      await patient.save();

      // Populate for response
      await patient.populate([
        { path: 'createdBy', select: 'username firstName lastName' },
        { path: 'updatedBy', select: 'username firstName lastName' }
      ]);

      // Log patient update
      await auditService.log({
        action: 'patient_updated',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'patient',
        resourceId: patient.patientId,
        resourceName: patient.fullName || patient.patientId,
        details: {
          changes,
          previousValue: originalData,
          newValue: patient.toObject()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'PUT',
          endpoint: `/api/patients/${patientId}`
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Patient updated successfully',
        data: {
          patient,
          changes
        }
      });

    } catch (error) {
      logger.error('Update patient error:', error);
      next(new AppError('Failed to update patient', 500));
    }
  }

  /**
   * Delete patient (soft delete)
   */
  async deletePatient(req, res, next) {
    try {
      const { patientId } = req.params;
      const user = req.user;

      const patient = await Patient.findByPatientId(patientId);

      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Check if patient has active tests
      const activeTests = await Test.countDocuments({ 
        patientId: patient.patientId, 
        status: { $in: ['pending', 'processing'] },
        isActive: true 
      });

      if (activeTests > 0) {
        return res.status(400).json({
          success: false,
          message: 'Cannot delete patient with active tests'
        });
      }

      // Soft delete
      patient.isActive = false;
      await patient.save();

      // Log patient deletion
      await auditService.log({
        action: 'patient_deleted',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'patient',
        resourceId: patient.patientId,
        resourceName: patient.fullName || patient.patientId,
        details: {
          deletedPatientData: patient.toObject(),
          reason: 'Administrative deletion',
          totalTests: patient.totalTests
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'DELETE',
          endpoint: `/api/patients/${patientId}`
        },
        status: 'success',
        riskLevel: 'high'
      });

      res.json({
        success: true,
        message: 'Patient deleted successfully'
      });

    } catch (error) {
      logger.error('Delete patient error:', error);
      next(new AppError('Failed to delete patient', 500));
    }
  }

  /**
   * Get all tests for a specific patient
   */
  async getPatientTests(req, res, next) {
    try {
      const { patientId } = req.params;
      const { status, page = 1, limit = 10 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Check if patient exists
      const patient = await Patient.findByPatientId(patientId);
      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Build filter
      const filter = { patientId: patientId.toUpperCase(), isActive: true };
      if (status) filter.status = status;

      const [tests, total] = await Promise.all([
        Test.find(filter)
          .populate('technician', 'username firstName lastName')
          .populate('reviewedBy', 'username firstName lastName')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit)),
        Test.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          patient: {
            patientId: patient.patientId,
            fullName: patient.fullName,
            testStatistics: patient.getTestStats()
          },
          tests,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: totalPages
          }
        }
      });

    } catch (error) {
      logger.error('Get patient tests error:', error);
      next(new AppError('Failed to retrieve patient tests', 500));
    }
  }

  /**
   * Get patient medical history and test results
   */
  async getPatientHistory(req, res, next) {
    try {
      const { patientId } = req.params;
      const { includeNegativeResults = 'true', startDate, endDate } = req.query;

      // Check if patient exists
      const patient = await Patient.findByPatientId(patientId);
      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Build date filter
      const dateFilter = {};
      if (startDate || endDate) {
        dateFilter.createdAt = {};
        if (startDate) dateFilter.createdAt.$gte = new Date(startDate);
        if (endDate) dateFilter.createdAt.$lte = new Date(endDate);
      }

      // Get test history
      const testHistory = await Test.find({
        patientId: patient.patientId,
        isActive: true,
        ...dateFilter
      })
        .populate('technician', 'username firstName lastName')
        .sort({ createdAt: -1 });

      // Get diagnosis history
      const diagnosisFilter = {
        testId: { $in: testHistory.map(t => t.testId) }
      };

      if (includeNegativeResults === 'false') {
        diagnosisFilter.status = 'POS';
      }

      const diagnosisHistory = await DiagnosisResult.find(diagnosisFilter)
        .populate('test', 'testId createdAt')
        .sort({ createdAt: -1 });

      // Calculate statistics
      const statistics = {
        totalTests: testHistory.length,
        completedTests: testHistory.filter(t => t.status === 'completed').length,
        positiveResults: diagnosisHistory.filter(d => d.status === 'POS').length,
        negativeResults: diagnosisHistory.filter(d => d.status === 'NEG').length,
        severityDistribution: {
          mild: diagnosisHistory.filter(d => d.severity?.level === 'mild').length,
          moderate: diagnosisHistory.filter(d => d.severity?.level === 'moderate').length,
          severe: diagnosisHistory.filter(d => d.severity?.level === 'severe').length
        },
        parasiteTypes: this.getParasiteTypeDistribution(diagnosisHistory),
        testTrend: this.getTestTrend(testHistory)
      };

      res.json({
        success: true,
        data: {
          patient,
          testHistory,
          diagnosisHistory,
          statistics
        }
      });

    } catch (error) {
      logger.error('Get patient history error:', error);
      next(new AppError('Failed to retrieve patient history', 500));
    }
  }

  /**
   * Search patients by various criteria
   */
  async searchPatients(req, res, next) {
    try {
      const { q, limit = 10 } = req.query;

      const results = await Patient.searchPatients(q)
        .limit(parseInt(limit))
        .sort({ createdAt: -1 });

      res.json({
        success: true,
        data: {
          patients: results,
          totalResults: results.length,
          searchQuery: q
        }
      });

    } catch (error) {
      logger.error('Search patients error:', error);
      next(new AppError('Failed to search patients', 500));
    }
  }

  /**
   * Get patient statistics
   */
  async getPatientStatistics(req, res, next) {
    try {
      const { startDate, endDate } = req.query;

      // Build date filter
      const dateFilter = { isActive: true };
      if (startDate || endDate) {
        dateFilter.createdAt = {};
        if (startDate) dateFilter.createdAt.$gte = new Date(startDate);
        if (endDate) dateFilter.createdAt.$lte = new Date(endDate);
      }

      // Get overall statistics
      const [
        totalPatients,
        patientsWithTests,
        patientsWithPositiveResults,
        genderDistribution,
        bloodTypeDistribution,
        ageDistribution
      ] = await Promise.all([
        Patient.countDocuments(dateFilter),
        Patient.countDocuments({ ...dateFilter, totalTests: { $gt: 0 } }),
        Patient.countDocuments({ ...dateFilter, positiveTests: { $gt: 0 } }),
        this.getGenderDistribution(dateFilter),
        this.getBloodTypeDistribution(dateFilter),
        this.getAgeDistribution(dateFilter)
      ]);

      // Calculate average age
      const ageStats = await Patient.aggregate([
        { $match: { ...dateFilter, age: { $exists: true, $ne: null } } },
        {
          $group: {
            _id: null,
            averageAge: { $avg: '$age' },
            minAge: { $min: '$age' },
            maxAge: { $max: '$age' }
          }
        }
      ]);

      res.json({
        success: true,
        data: {
          totalPatients,
          patientsWithTests,
          patientsWithPositiveResults,
          testParticipationRate: totalPatients > 0 ? ((patientsWithTests / totalPatients) * 100).toFixed(1) : 0,
          positiveResultRate: patientsWithTests > 0 ? ((patientsWithPositiveResults / patientsWithTests) * 100).toFixed(1) : 0,
          averageAge: ageStats[0]?.averageAge?.toFixed(1) || 0,
          ageRange: ageStats[0] ? `${ageStats[0].minAge}-${ageStats[0].maxAge}` : 'N/A',
          genderDistribution,
          bloodTypeDistribution,
          ageDistribution
        }
      });

    } catch (error) {
      logger.error('Get patient statistics error:', error);
      next(new AppError('Failed to retrieve patient statistics', 500));
    }
  }

  /**
   * Export patient data and test history
   */
  async exportPatientData(req, res, next) {
    try {
      const { patientId } = req.params;
      const { format = 'pdf', includeTestImages = 'false' } = req.query;
      const user = req.user;

      // Get patient with full history
      const patient = await Patient.findByPatientId(patientId);
      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Get test and diagnosis history
      const testHistory = await Test.find({ patientId: patient.patientId, isActive: true })
        .populate('technician', 'username firstName lastName')
        .sort({ createdAt: -1 });

      const diagnosisHistory = await DiagnosisResult.find({
        testId: { $in: testHistory.map(t => t.testId) }
      }).sort({ createdAt: -1 });

      // Generate export based on format
      let exportData;
      let contentType;
      let filename;

      const exportOptions = {
        includeTestImages: includeTestImages === 'true'
      };

      if (format === 'pdf') {
        exportData = await reportService.generatePatientReportPDF(patient, testHistory, diagnosisHistory, exportOptions);
        contentType = 'application/pdf';
        filename = `patient-${patient.patientId}.pdf`;
      } else if (format === 'json') {
        exportData = JSON.stringify({
          patient: patient.toObject(),
          testHistory,
          diagnosisHistory,
          exportedAt: new Date(),
          exportedBy: user.fullName
        }, null, 2);
        contentType = 'application/json';
        filename = `patient-${patient.patientId}.json`;
      } else if (format === 'csv') {
        exportData = await reportService.generatePatientCSV(patient, testHistory, diagnosisHistory);
        contentType = 'text/csv';
        filename = `patient-${patient.patientId}.csv`;
      }

      // Log export
      await auditService.log({
        action: 'patient_data_exported',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'patient',
        resourceId: patient.patientId,
        resourceName: patient.fullName || patient.patientId,
        details: {
          format,
          includeTestImages,
          testsIncluded: testHistory.length,
          diagnosesIncluded: diagnosisHistory.length
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'GET',
          endpoint: `/api/patients/${patientId}/export`
        },
        status: 'success',
        riskLevel: 'medium'
      });

      res.set({
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="${filename}"`
      });

      res.send(exportData);

    } catch (error) {
      logger.error('Export patient data error:', error);
      next(new AppError('Failed to export patient data', 500));
    }
  }

  /**
   * Bulk import patients from CSV
   */
  async bulkImportPatients(req, res, next) {
    try {
      const { validateOnly = 'false' } = req.body;
      const user = req.user;

      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'CSV file is required'
        });
      }

      // Process CSV file
      const importResults = await this.processBulkImport(req.file, validateOnly === 'true', user);

      // Log bulk import
      await auditService.log({
        action: 'bulk_patient_import',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'patient',
        resourceId: 'bulk_import',
        details: {
          fileName: req.file.originalname,
          validateOnly: validateOnly === 'true',
          totalRows: importResults.totalRows,
          imported: importResults.imported,
          failed: importResults.failed,
          errors: importResults.errors.slice(0, 10) // Limit errors in log
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: '/api/patients/bulk-import'
        },
        status: importResults.imported > 0 ? 'success' : 'failure',
        riskLevel: 'medium'
      });

      res.json({
        success: true,
        message: validateOnly === 'true' ? 'Validation completed' : 'Bulk import completed',
        data: importResults
      });

    } catch (error) {
      logger.error('Bulk import patients error:', error);
      next(new AppError('Failed to import patients', 500));
    }
  }

  /**
   * Helper methods
   */
  getParasiteTypeDistribution(diagnosisHistory) {
    const distribution = { PF: 0, PM: 0, PO: 0, PV: 0 };
    
    diagnosisHistory.forEach(diagnosis => {
      if (diagnosis.status === 'POS' && diagnosis.mostProbableParasite?.type) {
        distribution[diagnosis.mostProbableParasite.type]++;
      }
    });

    return distribution;
  }

  getTestTrend(testHistory) {
    const last6Months = testHistory.filter(test => {
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      return test.createdAt >= sixMonthsAgo;
    });

    return {
      totalInLast6Months: last6Months.length,
      averagePerMonth: (last6Months.length / 6).toFixed(1)
    };
  }

  async getGenderDistribution(filter) {
    return await Patient.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$gender',
          count: { $sum: 1 }
        }
      }
    ]);
  }

  async getBloodTypeDistribution(filter) {
    return await Patient.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$bloodType',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);
  }

  async getAgeDistribution(filter) {
    return await Patient.aggregate([
      { $match: { ...filter, age: { $exists: true, $ne: null } } },
      {
        $bucket: {
          groupBy: '$age',
          boundaries: [0, 18, 35, 50, 65, 150],
          default: 'unknown',
          output: {
            count: { $sum: 1 }
          }
        }
      }
    ]);
  }

  async processBulkImport(file, validateOnly, user) {
    // This would implement CSV parsing and validation
    // For now, return a placeholder response
    return {
      totalRows: 0,
      imported: 0,
      failed: 0,
      errors: [],
      validateOnly
    };
  }
}

module.exports = new PatientController();
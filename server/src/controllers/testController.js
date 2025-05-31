// 📁 server/src/controllers/testController.js
const Test = require('../models/Test');
const Patient = require('../models/Patient');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const { socketService } = require('../socket');

class TestController {
  /**
   * Get all tests with filtering and pagination
   */
  async getAllTests(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        status,
        priority,
        patientId,
        technicianId,
        startDate,
        endDate,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      const user = req.user;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Build filter object
      const filter = { isActive: true };

      // Role-based filtering
      if (user.role === 'technician' && !user.permissions.canViewAllTests) {
        filter.technician = user._id;
      }

      if (status) filter.status = status;
      if (priority) filter.priority = priority;
      if (patientId) filter.patientId = patientId.toUpperCase();
      if (technicianId) filter.technician = technicianId;

      // Date range filtering
      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }

      // Build sort object
      const sort = {};
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

      // Execute query with pagination
      const [tests, total] = await Promise.all([
        Test.find(filter)
          .populate('patient', 'patientId firstName lastName age gender')
          .populate('technician', 'username firstName lastName')
          .populate('reviewedBy', 'username firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        Test.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          tests,
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
      logger.error('Get all tests error:', error);
      next(new AppError('Failed to retrieve tests', 500));
    }
  }

  /**
   * Create a new test
   */
  async createTest(req, res, next) {
    try {
      const { patientId, priority = 'normal', sampleType = 'blood_smear', clinicalNotes } = req.body;
      const technician = req.user;

      // Check if patient exists
      const patient = await Patient.findByPatientId(patientId);
      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      // Create new test
      const test = new Test({
        patientId: patientId.toUpperCase(),
        patient: patient._id,
        priority,
        sampleType,
        technician: technician._id,
        clinicalNotes: clinicalNotes || {}
      });

      await test.save();

      // Update patient test count
      patient.totalTests += 1;
      patient.lastTestDate = new Date();
      await patient.save();

      // Populate the test object for response
      await test.populate([
        { path: 'patient', select: 'patientId firstName lastName age gender' },
        { path: 'technician', select: 'username firstName lastName' }
      ]);

      // Log test creation
      await auditService.log({
        action: 'test_created',
        userId: technician._id,
        userInfo: { username: technician.username, email: technician.email, role: technician.role },
        resourceType: 'test',
        resourceId: test.testId,
        resourceName: `Test for ${patient.patientId}`,
        details: {
          testData: { patientId, priority, sampleType },
          patientName: patient.fullName || patient.patientId
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: '/api/tests'
        },
        status: 'success',
        riskLevel: 'low'
      });

      // Emit real-time notification
      socketService.emitToAll('test:created', {
        test: test.toObject(),
        message: `New test ${test.testId} created for patient ${patient.patientId}`
      });

      res.status(201).json({
        success: true,
        message: 'Test created successfully',
        data: {
          test
        }
      });

    } catch (error) {
      logger.error('Create test error:', error);
      next(new AppError('Failed to create test', 500));
    }
  }

  /**
   * Get test by ID
   */
  async getTestById(req, res, next) {
    try {
      const { testId } = req.params;
      const user = req.user;

      const test = await Test.findOne({ testId: testId.toUpperCase(), isActive: true })
        .populate('patient')
        .populate('technician', 'username firstName lastName')
        .populate('reviewedBy', 'username firstName lastName');

      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Check if user has permission to view this test
      if (user.role === 'technician' && 
          !user.permissions.canViewAllTests && 
          test.technician._id.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view this test'
        });
      }

      res.json({
        success: true,
        data: {
          test
        }
      });

    } catch (error) {
      logger.error('Get test by ID error:', error);
      next(new AppError('Failed to retrieve test', 500));
    }
  }

  /**
   * Update test
   */
  async updateTest(req, res, next) {
    try {
      const { testId } = req.params;
      const updateData = req.body;
      const user = req.user;

      const test = await Test.findOne({ testId: testId.toUpperCase(), isActive: true });

      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Check if user can modify this test
      if (!test.canBeModified()) {
        return res.status(400).json({
          success: false,
          message: 'Test cannot be modified in its current status'
        });
      }

      // Check permissions
      const isTestOwner = test.technician.toString() === user._id.toString();
      const hasPermission = user.role === 'admin' || user.role === 'supervisor' || isTestOwner;

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to update this test'
        });
      }

      // Track changes for audit log
      const originalData = test.toObject();
      const changes = [];

      // Update allowed fields
      const allowedFields = ['priority', 'clinicalNotes', 'qualityScore', 'qualityNotes'];
      
      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          if (JSON.stringify(test[field]) !== JSON.stringify(updateData[field])) {
            changes.push(field);
            test[field] = updateData[field];
          }
        }
      });

      // Only supervisors and admins can change status
      if (updateData.status && ['supervisor', 'admin'].includes(user.role)) {
        if (test.status !== updateData.status) {
          changes.push('status');
          await test.updateStatus(updateData.status, user._id);
        }
      }

      if (changes.length === 0) {
        return res.json({
          success: true,
          message: 'No changes detected',
          data: { test }
        });
      }

      test.updatedBy = user._id;
      await test.save();

      // Populate for response
      await test.populate([
        { path: 'patient', select: 'patientId firstName lastName age gender' },
        { path: 'technician', select: 'username firstName lastName' },
        { path: 'reviewedBy', select: 'username firstName lastName' }
      ]);

      // Log test update
      await auditService.log({
        action: 'test_updated',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'test',
        resourceId: test.testId,
        resourceName: `Test ${test.testId}`,
        details: {
          changes,
          previousValue: originalData,
          newValue: test.toObject()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'PUT',
          endpoint: `/api/tests/${testId}`
        },
        status: 'success',
        riskLevel: 'low'
      });

      // Emit real-time update
      socketService.emitToAll('test:updated', {
        test: test.toObject(),
        changes,
        updatedBy: user.fullName
      });

      res.json({
        success: true,
        message: 'Test updated successfully',
        data: {
          test,
          changes
        }
      });

    } catch (error) {
      logger.error('Update test error:', error);
      next(new AppError('Failed to update test', 500));
    }
  }

  /**
   * Delete test
   */
  async deleteTest(req, res, next) {
    try {
      const { testId } = req.params;
      const user = req.user;

      const test = await Test.findOne({ testId: testId.toUpperCase(), isActive: true })
        .populate('patient');

      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Check if user can delete this test
      if (!test.canBeDeleted(user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to delete this test'
        });
      }

      // Soft delete
      test.isActive = false;
      await test.save();

      // Update patient test count
      if (test.patient) {
        test.patient.totalTests = Math.max(0, test.patient.totalTests - 1);
        await test.patient.save();
      }

      // Log test deletion
      await auditService.log({
        action: 'test_deleted',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'test',
        resourceId: test.testId,
        resourceName: `Test ${test.testId}`,
        details: {
          deletedTestData: test.toObject(),
          reason: 'Manual deletion by user'
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'DELETE',
          endpoint: `/api/tests/${testId}`
        },
        status: 'success',
        riskLevel: 'high'
      });

      res.json({
        success: true,
        message: 'Test deleted successfully'
      });

    } catch (error) {
      logger.error('Delete test error:', error);
      next(new AppError('Failed to delete test', 500));
    }
  }

  /**
   * Update test status
   */
  async updateTestStatus(req, res, next) {
    try {
      const { testId } = req.params;
      const { status, notes } = req.body;
      const user = req.user;

      const test = await Test.findOne({ testId: testId.toUpperCase(), isActive: true })
        .populate('patient', 'patientId firstName lastName');

      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Check permissions for status changes
      const isTestOwner = test.technician.toString() === user._id.toString();
      const isSupervisor = ['supervisor', 'admin'].includes(user.role);

      // Only test owner can mark as processing, supervisors can change any status
      if (status === 'processing' && !isTestOwner && !isSupervisor) {
        return res.status(403).json({
          success: false,
          message: 'Only assigned technician can start processing'
        });
      }

      if (['completed', 'failed', 'cancelled'].includes(status) && !isSupervisor && !isTestOwner) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to change test status'
        });
      }

      const oldStatus = test.status;
      await test.updateStatus(status, user._id);

      if (notes) {
        test.qualityNotes = notes;
        await test.save();
      }

      // Log status change
      await auditService.log({
        action: 'test_status_changed',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'test',
        resourceId: test.testId,
        resourceName: `Test ${test.testId}`,
        details: {
          previousStatus: oldStatus,
          newStatus: status,
          notes,
          patientId: test.patientId
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'PATCH',
          endpoint: `/api/tests/${testId}/status`
        },
        status: 'success',
        riskLevel: 'low'
      });

      // Emit real-time status update
      socketService.emitToAll('test:statusChanged', {
        testId: test.testId,
        oldStatus,
        newStatus: status,
        updatedBy: user.fullName,
        patientId: test.patientId
      });

      res.json({
        success: true,
        message: 'Test status updated successfully',
        data: {
          testId: test.testId,
          oldStatus,
          newStatus: status
        }
      });

    } catch (error) {
      logger.error('Update test status error:', error);
      next(new AppError('Failed to update test status', 500));
    }
  }

  /**
   * Get tests by patient
   */
  async getTestsByPatient(req, res, next) {
    try {
      const { patientId } = req.params;
      const { page = 1, limit = 10 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Check if patient exists
      const patient = await Patient.findByPatientId(patientId);
      if (!patient) {
        return res.status(404).json({
          success: false,
          message: 'Patient not found'
        });
      }

      const [tests, total] = await Promise.all([
        Test.findByPatient(patientId)
          .populate('technician', 'username firstName lastName')
          .populate('reviewedBy', 'username firstName lastName')
          .skip(skip)
          .limit(parseInt(limit)),
        Test.countDocuments({ patientId: patientId.toUpperCase(), isActive: true })
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          patient: patient.toJSON(),
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
      logger.error('Get tests by patient error:', error);
      next(new AppError('Failed to retrieve patient tests', 500));
    }
  }

  /**
   * Get tests assigned to current technician
   */
  async getMyTests(req, res, next) {
    try {
      const { status, page = 1, limit = 20 } = req.query;
      const technician = req.user;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      const filter = { technician: technician._id, isActive: true };
      if (status) filter.status = status;

      const [tests, total] = await Promise.all([
        Test.find(filter)
          .populate('patient', 'patientId firstName lastName age gender')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit)),
        Test.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
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
      logger.error('Get my tests error:', error);
      next(new AppError('Failed to retrieve your tests', 500));
    }
  }

  /**
   * Get test statistics
   */
  async getTestStatistics(req, res, next) {
    try {
      const { startDate, endDate, technicianId } = req.query;

      // Get basic test statistics
      const stats = await Test.getTestStats(startDate, endDate);
      
      let technicianStats = null;
      if (technicianId) {
        const technicianFilter = { technician: technicianId, isActive: true };
        if (startDate || endDate) {
          technicianFilter.createdAt = {};
          if (startDate) technicianFilter.createdAt.$gte = new Date(startDate);
          if (endDate) technicianFilter.createdAt.$lte = new Date(endDate);
        }

        technicianStats = await Test.getTestStats(startDate, endDate);
      }

      // Get daily statistics for charts
      const dailyStats = await this.getDailyTestStats(startDate, endDate);

      res.json({
        success: true,
        data: {
          overall: stats[0] || {
            totalTests: 0,
            pendingTests: 0,
            processingTests: 0,
            completedTests: 0,
            failedTests: 0,
            avgProcessingTime: 0
          },
          technician: technicianStats,
          dailyStats
        }
      });

    } catch (error) {
      logger.error('Get test statistics error:', error);
      next(new AppError('Failed to retrieve test statistics', 500));
    }
  }

  /**
   * Assign test to technician
   */
  async assignTest(req, res, next) {
    try {
      const { testId } = req.params;
      const { technicianId } = req.body;
      const supervisor = req.user;

      // Find test
      const test = await Test.findOne({ testId: testId.toUpperCase(), isActive: true })
        .populate('patient', 'patientId firstName lastName');

      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Find technician
      const technician = await User.findById(technicianId);
      if (!technician || !technician.isActive || technician.role !== 'technician') {
        return res.status(404).json({
          success: false,
          message: 'Technician not found or invalid'
        });
      }

      const oldTechnicianId = test.technician;
      test.technician = technicianId;
      await test.save();

      // Log assignment
      await auditService.log({
        action: 'test_assigned',
        userId: supervisor._id,
        userInfo: { username: supervisor.username, email: supervisor.email, role: supervisor.role },
        resourceType: 'test',
        resourceId: test.testId,
        resourceName: `Test ${test.testId}`,
        details: {
          previousTechnician: oldTechnicianId,
          newTechnician: technicianId,
          technicianName: technician.fullName,
          patientId: test.patientId
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'PATCH',
          endpoint: `/api/tests/${testId}/assign`
        },
        status: 'success',
        riskLevel: 'low'
      });

      // Emit real-time notification
      socketService.emitToUser(technicianId, 'test:assigned', {
        test: test.toObject(),
        message: `Test ${test.testId} has been assigned to you`,
        assignedBy: supervisor.fullName
      });

      res.json({
        success: true,
        message: 'Test assigned successfully',
        data: {
          testId: test.testId,
          assignedTo: technician.fullName
        }
      });

    } catch (error) {
      logger.error('Assign test error:', error);
      next(new AppError('Failed to assign test', 500));
    }
  }

  /**
   * Get pending tests
   */
  async getPendingTests(req, res, next) {
    try {
      const { priority, page = 1, limit = 20 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      const filter = { status: { $in: ['pending', 'processing'] }, isActive: true };
      if (priority) filter.priority = priority;

      const [tests, total] = await Promise.all([
        Test.find(filter)
          .populate('patient', 'patientId firstName lastName age gender')
          .populate('technician', 'username firstName lastName')
          .sort({ priority: -1, createdAt: 1 }) // High priority first, then FIFO
          .skip(skip)
          .limit(parseInt(limit)),
        Test.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
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
      logger.error('Get pending tests error:', error);
      next(new AppError('Failed to retrieve pending tests', 500));
    }
  }

  /**
   * Helper method to get daily test statistics
   */
  async getDailyTestStats(startDate, endDate) {
    try {
      const matchCondition = { isActive: true };
      
      if (startDate || endDate) {
        matchCondition.createdAt = {};
        if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
        if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
      }

      return await Test.aggregate([
        { $match: matchCondition },
        {
          $group: {
            _id: {
              year: { $year: '$createdAt' },
              month: { $month: '$createdAt' },
              day: { $dayOfMonth: '$createdAt' }
            },
            totalTests: { $sum: 1 },
            completedTests: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
            pendingTests: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
            processingTests: { $sum: { $cond: [{ $eq: ['$status', 'processing'] }, 1, 0] } },
            failedTests: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } }
          }
        },
        {
          $project: {
            date: {
              $dateFromParts: {
                year: '$_id.year',
                month: '$_id.month',
                day: '$_id.day'
              }
            },
            totalTests: 1,
            completedTests: 1,
            pendingTests: 1,
            processingTests: 1,
            failedTests: 1
          }
        },
        { $sort: { date: 1 } }
      ]);
    } catch (error) {
      logger.error('Get daily test stats error:', error);
      return [];
    }
  }
}

module.exports = new TestController();
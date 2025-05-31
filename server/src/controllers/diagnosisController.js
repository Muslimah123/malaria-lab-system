// 📁 server/src/controllers/diagnosisController.js
const DiagnosisResult = require('../models/DiagnosisResult');
const Test = require('../models/Test');
const Patient = require('../models/Patient');
const AuditLog = require('../models/AuditLog');
const auditService = require('../services/auditService');
const reportService = require('../services/reportService');
const fileService = require('../services/fileService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const { socketService } = require('../socket');

class DiagnosisController {
  /**
   * Get all diagnosis results with filtering
   */
  async getAllDiagnosisResults(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        status,
        severity,
        parasiteType,
        startDate,
        endDate,
        requiresReview,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      const user = req.user;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Build filter object
      const filter = {};

      // Role-based filtering
      if (user.role === 'technician' && !user.permissions.canViewAllTests) {
        // Get tests where user is the technician
        const userTests = await Test.find({ technician: user._id }, '_id');
        filter.test = { $in: userTests.map(t => t._id) };
      }

      if (status) filter.status = status;
      if (severity) filter['severity.level'] = severity;
      if (parasiteType) filter['mostProbableParasite.type'] = parasiteType;
      if (requiresReview === 'true') filter['flags.requiresManualReview'] = true;

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
      const [results, total] = await Promise.all([
        DiagnosisResult.find(filter)
          .populate({
            path: 'test',
            select: 'testId patientId priority status createdAt',
            populate: {
              path: 'patient',
              select: 'patientId firstName lastName age gender'
            }
          })
          .populate('manualReview.reviewedBy', 'username firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit)),
        DiagnosisResult.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          results,
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
      logger.error('Get all diagnosis results error:', error);
      next(new AppError('Failed to retrieve diagnosis results', 500));
    }
  }

  /**
   * Get diagnosis result by test ID
   */
  async getDiagnosisResultByTestId(req, res, next) {
    try {
      const { testId } = req.params;
      const user = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate({
          path: 'test',
          select: 'testId patientId priority status technician createdAt',
          populate: [
            {
              path: 'patient',
              select: 'patientId firstName lastName age gender phoneNumber'
            },
            {
              path: 'technician',
              select: 'username firstName lastName'
            }
          ]
        })
        .populate('manualReview.reviewedBy', 'username firstName lastName');

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Check if user has permission to view this result
      const isTestOwner = result.test.technician._id.toString() === user._id.toString();
      const isSupervisor = ['supervisor', 'admin'].includes(user.role);

      if (!isTestOwner && !isSupervisor && !user.permissions.canViewAllTests) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view this diagnosis result'
        });
      }

      // Log diagnosis result access
      await auditService.log({
        action: 'diagnosis_viewed',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'diagnosis',
        resourceId: result._id.toString(),
        resourceName: `Diagnosis for ${result.testId}`,
        details: {
          testId: result.testId,
          status: result.status,
          severity: result.severity.level
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'GET',
          endpoint: `/api/diagnosis/${testId}`
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        data: {
          result
        }
      });

    } catch (error) {
      logger.error('Get diagnosis result by test ID error:', error);
      next(new AppError('Failed to retrieve diagnosis result', 500));
    }
  }

  /**
   * Add manual review to diagnosis result
   */
  async addManualReview(req, res, next) {
    try {
      const { testId } = req.params;
      const { reviewNotes, overriddenStatus, overriddenSeverity, reviewerConfidence = 'medium' } = req.body;
      const reviewer = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate('test', 'testId patientId');

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Check if already reviewed
      if (result.manualReview.isReviewed) {
        return res.status(400).json({
          success: false,
          message: 'Diagnosis result has already been reviewed'
        });
      }

      // Add manual review
      const reviewData = {
        reviewNotes,
        overriddenStatus,
        overriddenSeverity,
        reviewerConfidence
      };

      await result.addManualReview(reviewData, reviewer._id);

      // Log manual review
      await auditService.log({
        action: 'diagnosis_reviewed',
        userId: reviewer._id,
        userInfo: { username: reviewer.username, email: reviewer.email, role: reviewer.role },
        resourceType: 'diagnosis',
        resourceId: result._id.toString(),
        resourceName: `Diagnosis for ${result.testId}`,
        details: {
          testId: result.testId,
          originalStatus: result.status,
          originalSeverity: result.severity.level,
          overriddenStatus,
          overriddenSeverity,
          reviewNotes: reviewNotes.substring(0, 100) + '...' // Truncate for log
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: `/api/diagnosis/${testId}/review`
        },
        status: 'success',
        riskLevel: 'medium'
      });

      // Emit real-time notification
      socketService.emitToAll('diagnosis:reviewed', {
        testId: result.testId,
        reviewedBy: reviewer.fullName,
        finalStatus: result.finalStatus,
        finalSeverity: result.finalSeverity
      });

      res.json({
        success: true,
        message: 'Manual review added successfully',
        data: {
          result: {
            testId: result.testId,
            finalStatus: result.finalStatus,
            finalSeverity: result.finalSeverity,
            reviewedBy: reviewer.fullName,
            reviewedAt: result.manualReview.reviewedAt
          }
        }
      });

    } catch (error) {
      logger.error('Add manual review error:', error);
      next(new AppError('Failed to add manual review', 500));
    }
  }

  /**
   * Get annotated images for diagnosis result
   */
  async getDiagnosisImages(req, res, next) {
    try {
      const { testId } = req.params;
      const { imageId } = req.query;
      const user = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate('test', 'testId images technician');

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Check permissions
      const isTestOwner = result.test.technician.toString() === user._id.toString();
      const isSupervisor = ['supervisor', 'admin'].includes(user.role);

      if (!isTestOwner && !isSupervisor && !user.permissions.canViewAllTests) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view diagnosis images'
        });
      }

      // Filter detections if specific image requested
      let detections = result.detections;
      if (imageId) {
        detections = detections.filter(d => d.imageId === imageId);
      }

      // Build image data with annotations
      const images = await Promise.all(detections.map(async (detection) => {
        try {
          // Find corresponding uploaded image
          const uploadedImage = result.test.images.find(img => 
            img.filename.includes(detection.imageId) || detection.imageId.includes(img.filename)
          );

          if (!uploadedImage) {
            return null;
          }

          // Generate image URL
          const imageUrl = await fileService.getImageUrl(uploadedImage.path);

          return {
            imageId: detection.imageId,
            originalFilename: detection.originalFilename || uploadedImage.originalName,
            url: imageUrl,
            annotations: {
              parasites: detection.parasitesDetected.map(parasite => ({
                type: parasite.type,
                confidence: parasite.confidence,
                boundingBox: parasite.bbox,
                typeFullName: result.parasiteTypeNames[parasite.type]
              })),
              summary: {
                parasiteCount: detection.parasiteCount,
                wbcCount: detection.whiteBloodCellsDetected,
                parasiteWbcRatio: detection.parasiteWbcRatio
              }
            },
            metadata: {
              size: uploadedImage.size,
              uploadedAt: uploadedImage.uploadedAt
            }
          };
        } catch (imageError) {
          logger.warn(`Failed to process image ${detection.imageId}:`, imageError);
          return null;
        }
      }));

      // Filter out null results
      const validImages = images.filter(img => img !== null);

      res.json({
        success: true,
        data: {
          testId: result.testId,
          status: result.finalStatus,
          severity: result.finalSeverity,
          images: validImages,
          totalImages: validImages.length,
          totalParasites: result.totalParasitesDetected,
          totalWBC: result.totalWbcDetected
        }
      });

    } catch (error) {
      logger.error('Get diagnosis images error:', error);
      next(new AppError('Failed to retrieve diagnosis images', 500));
    }
  }

  /**
   * Get diagnosis statistics
   */
  async getDiagnosisStatistics(req, res, next) {
    try {
      const { startDate, endDate, groupBy = 'day' } = req.query;

      // Get overall statistics
      const overall = await DiagnosisResult.getStatistics(startDate, endDate);

      // Get parasite distribution
      const parasiteDistribution = await this.getParasiteDistribution(startDate, endDate);

      // Get severity distribution
      const severityDistribution = await this.getSeverityDistribution(startDate, endDate);

      // Get trends data
      const trends = await this.getTrendsData(startDate, endDate, groupBy);

      // Get quality metrics
      const qualityMetrics = await this.getQualityMetrics(startDate, endDate);

      res.json({
        success: true,
        data: {
          overall: overall[0] || {
            totalTests: 0,
            positiveTests: 0,
            negativeTests: 0,
            mildCases: 0,
            moderateCases: 0,
            severeCases: 0,
            avgConfidence: 0,
            reviewedCases: 0
          },
          parasiteDistribution,
          severityDistribution,
          trends,
          qualityMetrics
        }
      });

    } catch (error) {
      logger.error('Get diagnosis statistics error:', error);
      next(new AppError('Failed to retrieve diagnosis statistics', 500));
    }
  }

  /**
   * Get diagnosis results requiring manual review
   */
  async getResultsRequiringReview(req, res, next) {
    try {
      const { page = 1, limit = 20 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      const [results, total] = await Promise.all([
        DiagnosisResult.findRequiringReview()
          .populate({
            path: 'test',
            select: 'testId patientId priority createdAt',
            populate: {
              path: 'patient',
              select: 'patientId firstName lastName age'
            }
          })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit)),
        DiagnosisResult.countDocuments({
          'flags.requiresManualReview': true,
          'manualReview.isReviewed': false
        })
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          results,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: totalPages
          }
        }
      });

    } catch (error) {
      logger.error('Get results requiring review error:', error);
      next(new AppError('Failed to retrieve results requiring review', 500));
    }
  }

  /**
   * Get all positive malaria cases
   */
  async getPositiveCases(req, res, next) {
    try {
      const {
        severity,
        parasiteType,
        startDate,
        endDate,
        page = 1,
        limit = 20
      } = req.query;

      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Build filter for positive cases
      const filter = { status: 'POS' };

      if (severity) filter['severity.level'] = severity;
      if (parasiteType) filter['mostProbableParasite.type'] = parasiteType;

      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }

      const [results, total] = await Promise.all([
        DiagnosisResult.find(filter)
          .populate({
            path: 'test',
            select: 'testId patientId priority createdAt',
            populate: {
              path: 'patient',
              select: 'patientId firstName lastName age gender phoneNumber'
            }
          })
          .sort({ 'severity.level': -1, createdAt: -1 }) // Severe cases first
          .skip(skip)
          .limit(parseInt(limit)),
        DiagnosisResult.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          results,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: totalPages
          },
          summary: {
            totalPositiveCases: total,
            criticalCasesCount: results.filter(r => r.severity.level === 'severe').length
          }
        }
      });

    } catch (error) {
      logger.error('Get positive cases error:', error);
      next(new AppError('Failed to retrieve positive cases', 500));
    }
  }

  /**
   * Export diagnosis result as PDF report
   */
  async exportDiagnosisReport(req, res, next) {
    try {
      const { testId } = req.params;
      const { format = 'pdf' } = req.query;
      const user = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate({
          path: 'test',
          populate: [
            { path: 'patient' },
            { path: 'technician', select: 'username firstName lastName' }
          ]
        })
        .populate('manualReview.reviewedBy', 'username firstName lastName');

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Generate report based on format
      let report;
      let contentType;
      let filename;

      if (format === 'pdf') {
        report = await reportService.generateDiagnosisPDF(result);
        contentType = 'application/pdf';
        filename = `diagnosis-${result.testId}.pdf`;
      } else if (format === 'json') {
        report = JSON.stringify(result.generateReport(), null, 2);
        contentType = 'application/json';
        filename = `diagnosis-${result.testId}.json`;
      }

      // Log report export
      await auditService.log({
        action: 'report_exported',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'diagnosis',
        resourceId: result._id.toString(),
        resourceName: `Diagnosis report for ${result.testId}`,
        details: {
          testId: result.testId,
          format,
          fileSize: Buffer.byteLength(report)
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'GET',
          endpoint: `/api/diagnosis/${testId}/export`
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.set({
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="${filename}"`
      });

      res.send(report);

    } catch (error) {
      logger.error('Export diagnosis report error:', error);
      next(new AppError('Failed to export diagnosis report', 500));
    }
  }

  /**
   * Send diagnosis result to hospital EMR system
   */
  async sendToHospitalEMR(req, res, next) {
    try {
      const { testId } = req.params;
      const { hospitalId, departmentId, physicianId, notes } = req.body;
      const user = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate('test')
        .populate('test.patient');

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Check if already exported
      if (result.exportedToHospital) {
        return res.status(400).json({
          success: false,
          message: 'Result has already been sent to hospital system'
        });
      }

      // Prepare integration data
      const integrationData = {
        testId: result.testId,
        patientId: result.test.patient.patientId,
        diagnosis: result.generateReport(),
        hospitalId,
        departmentId,
        physicianId,
        notes,
        sentBy: user.fullName,
        sentAt: new Date()
      };

      // Send to hospital EMR (implement actual integration)
      // const hospitalResponse = await hospitalEMRService.sendDiagnosis(integrationData);

      // Mark as exported
      result.exportedToHospital = true;
      result.exportedAt = new Date();
      result.hospitalReferenceId = `HOSP-${Date.now()}`; // Generate reference ID
      await result.save();

      // Log hospital integration
      await auditService.log({
        action: 'data_exported_to_hospital',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'diagnosis',
        resourceId: result._id.toString(),
        resourceName: `Diagnosis for ${result.testId}`,
        details: {
          testId: result.testId,
          hospitalId,
          departmentId,
          hospitalReferenceId: result.hospitalReferenceId
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: `/api/diagnosis/${testId}/hospital-integration`
        },
        status: 'success',
        riskLevel: 'medium'
      });

      res.json({
        success: true,
        message: 'Diagnosis result sent to hospital successfully',
        data: {
          hospitalReferenceId: result.hospitalReferenceId,
          sentAt: result.exportedAt
        }
      });

    } catch (error) {
      logger.error('Send to hospital EMR error:', error);
      next(new AppError('Failed to send result to hospital system', 500));
    }
  }

  /**
   * Export multiple diagnosis results
   */
  async batchExportResults(req, res, next) {
    try {
      const { testIds, format = 'pdf', includeImages = false } = req.body;
      const user = req.user;

      // Find all results
      const results = await DiagnosisResult.find({ 
        testId: { $in: testIds.map(id => id.toUpperCase()) } 
      })
        .populate({
          path: 'test',
          populate: [
            { path: 'patient' },
            { path: 'technician', select: 'username firstName lastName' }
          ]
        })
        .populate('manualReview.reviewedBy', 'username firstName lastName');

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'No diagnosis results found for provided test IDs'
        });
      }

      // Generate batch export
      const exportData = await reportService.generateBatchExport(results, format, includeImages);

      // Log batch export
      await auditService.log({
        action: 'batch_export',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'diagnosis',
        resourceId: 'batch_export',
        details: {
          testIds: testIds,
          format,
          includeImages,
          resultCount: results.length,
          fileSize: exportData.size
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: '/api/diagnosis/batch-export'
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.set({
        'Content-Type': exportData.contentType,
        'Content-Disposition': `attachment; filename="${exportData.filename}"`
      });

      res.send(exportData.data);

    } catch (error) {
      logger.error('Batch export results error:', error);
      next(new AppError('Failed to export diagnosis results', 500));
    }
  }

  /**
   * Add quality feedback on diagnosis result
   */
  async addQualityFeedback(req, res, next) {
    try {
      const { testId } = req.params;
      const { qualityScore, feedback, imageQualityIssues = [] } = req.body;
      const user = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() });

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Update quality information
      result.analysisQuality.overallScore = qualityScore * 20; // Convert 1-5 to 0-100
      result.analysisQuality.confidenceLevel = qualityScore >= 4 ? 'high' : qualityScore >= 3 ? 'medium' : 'low';
      
      // Add quality issues if provided
      if (imageQualityIssues.length > 0) {
        result.flags.qualityIssues = true;
        result.analysisQuality.imageQualityScores = imageQualityIssues.map(issue => ({
          imageId: issue,
          score: qualityScore * 20,
          issues: [feedback]
        }));
      }

      await result.save();

      // Log quality feedback
      await auditService.log({
        action: 'quality_feedback_added',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'diagnosis',
        resourceId: result._id.toString(),
        resourceName: `Quality feedback for ${result.testId}`,
        details: {
          testId: result.testId,
          qualityScore,
          feedback: feedback.substring(0, 100) + '...',
          imageQualityIssues
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: `/api/diagnosis/${testId}/quality-feedback`
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Quality feedback submitted successfully',
        data: {
          qualityScore: result.analysisQuality.overallScore,
          confidenceLevel: result.analysisQuality.confidenceLevel
        }
      });

    } catch (error) {
      logger.error('Add quality feedback error:', error);
      next(new AppError('Failed to add quality feedback', 500));
    }
  }

  /**
   * Helper methods for statistics
   */
  async getParasiteDistribution(startDate, endDate) {
    const matchCondition = { status: 'POS' };
    
    if (startDate || endDate) {
      matchCondition.createdAt = {};
      if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
      if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
    }

    return await DiagnosisResult.aggregate([
      { $match: matchCondition },
      {
        $group: {
          _id: '$mostProbableParasite.type',
          count: { $sum: 1 },
          avgConfidence: { $avg: '$mostProbableParasite.confidence' }
        }
      },
      { $sort: { count: -1 } }
    ]);
  }

  async getSeverityDistribution(startDate, endDate) {
    const matchCondition = {};
    
    if (startDate || endDate) {
      matchCondition.createdAt = {};
      if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
      if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
    }

    return await DiagnosisResult.aggregate([
      { $match: matchCondition },
      {
        $group: {
          _id: '$severity.level',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);
  }

  async getTrendsData(startDate, endDate, groupBy) {
    const matchCondition = {};
    
    if (startDate || endDate) {
      matchCondition.createdAt = {};
      if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
      if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
    }

    let groupByExpression;
    switch (groupBy) {
      case 'week':
        groupByExpression = {
          year: { $year: '$createdAt' },
          week: { $week: '$createdAt' }
        };
        break;
      case 'month':
        groupByExpression = {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' }
        };
        break;
      default: // day
        groupByExpression = {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' }
        };
    }

    return await DiagnosisResult.aggregate([
      { $match: matchCondition },
      {
        $group: {
          _id: groupByExpression,
          totalTests: { $sum: 1 },
          positiveTests: { $sum: { $cond: [{ $eq: ['$status', 'POS'] }, 1, 0] } },
          negativeTests: { $sum: { $cond: [{ $eq: ['$status', 'NEG'] }, 1, 0] } }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.week': 1 } }
    ]);
  }

  async getQualityMetrics(startDate, endDate) {
    const matchCondition = {};
    
    if (startDate || endDate) {
      matchCondition.createdAt = {};
      if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
      if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
    }

    return await DiagnosisResult.aggregate([
      { $match: matchCondition },
      {
        $group: {
          _id: null,
          avgOverallScore: { $avg: '$analysisQuality.overallScore' },
          highConfidenceCount: { $sum: { $cond: [{ $eq: ['$analysisQuality.confidenceLevel', 'high'] }, 1, 0] } },
          mediumConfidenceCount: { $sum: { $cond: [{ $eq: ['$analysisQuality.confidenceLevel', 'medium'] }, 1, 0] } },
          lowConfidenceCount: { $sum: { $cond: [{ $eq: ['$analysisQuality.confidenceLevel', 'low'] }, 1, 0] } },
          qualityIssuesCount: { $sum: { $cond: ['$flags.qualityIssues', 1, 0] } }
        }
      }
    ]);
  }
}

module.exports = new DiagnosisController();
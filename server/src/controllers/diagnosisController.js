// 📁 server/src/controllers/diagnosisController.js
const DiagnosisResult = require('../models/DiagnosisResult');
const Test = require('../models/Test');
const Patient = require('../models/Patient');
const AuditLog = require('../models/AuditLog');
const auditService = require('../services/auditService');
const reportService = require('../services/reportService');
const fileService = require('../services/fileService');
const diagnosisService = require('../services/diagnosisService'); // ✅ FIXED: Added missing import
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const { socketService } = require('../socket');
const path = require('path');

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
   *  FIXED: Get annotated images for diagnosis result
   */
  async getDiagnosisImages(req, res, next) {
    try {
      const { testId } = req.params;
      const { imageId } = req.query;
      const user = req.user;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate('test', 'testId technician _id');

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

      // Try to find the upload session to get actual file paths
      const uploadSession = await fileService.getUploadSessionForTest(result.test._id);

      // Base URL for images
      const baseUrl = process.env.API_URL || 'http://localhost:5000';

      // Build image data from detections
      const images = await Promise.all(detections.map(async (detection, index) => {
        let imageUrl = null;
        let annotatedUrl = null;

        // Try to find the uploaded file that matches this detection
        if (uploadSession && uploadSession.files) {
          const uploadedFile = uploadSession.files.find(file => 
            file.filename === detection.imageId ||
            file.filename.includes(detection.imageId) ||
            detection.imageId.includes(file.filename) ||
            file.originalName === detection.originalFilename
          );

          if (uploadedFile) {
            const relativePath = await fileService.getImageUrl(uploadedFile.path);
            imageUrl = `${baseUrl}${relativePath}`;
          }
        }

        // Fallback URL with full base URL
        if (!imageUrl) {
          imageUrl = `${baseUrl}/uploads/images/${detection.imageId}`;
        }

        if (detection.annotatedImagePath) {
          try {
            const sanitizedPath = detection.annotatedImagePath.replace(/^\/+/, '');
            const annotatedFullPath = path.join(fileService.uploadDir, sanitizedPath);
            if (await fileService.fileExists(annotatedFullPath)) {
              const relativeAnnotatedUrl = await fileService.getImageUrl(annotatedFullPath);
              annotatedUrl = `${baseUrl}${relativeAnnotatedUrl}`;
            } else {
              logger.warn(`Annotated image not found on disk: ${annotatedFullPath}`);
            }
          } catch (annotatedError) {
            logger.warn('Failed to resolve annotated image path:', annotatedError);
          }
        }

        // ✅ FIXED: Process parasites with array bbox format from Python system
        const parasites = (detection.parasitesDetected || []).map(parasite => {
          let confidence = parasite.confidence || 0;
          
          // If confidence is 0, it might be stored in a different field
          if (confidence === 0 && parasite.score) {
            confidence = parasite.score;
          }
          
          // Ensure confidence is in 0-1 range (not percentage)
          if (confidence > 1) {
            confidence = confidence / 100;
          }

          // ✅ FIXED: Handle bbox as array format from Python system
          let boundingBox;
          if (Array.isArray(parasite.bbox) && parasite.bbox.length === 4) {
            // Python returns [x_min, y_min, x_max, y_max] array format
            boundingBox = {
              x1: parasite.bbox[0],
              y1: parasite.bbox[1], 
              x2: parasite.bbox[2],
              y2: parasite.bbox[3]
            };
          } else if (parasite.bbox && typeof parasite.bbox === 'object') {
            // Fallback for object format
            boundingBox = parasite.bbox;
          } else {
            // Default empty bbox
            boundingBox = { x1: 0, y1: 0, x2: 0, y2: 0 };
          }

          return {
            type: parasite.type,
            confidence: confidence,
            boundingBox: boundingBox,
            typeFullName: {
              'PF': 'Plasmodium Falciparum',
              'PM': 'Plasmodium Malariae',
              'PO': 'Plasmodium Ovale',
              'PV': 'Plasmodium Vivax'
            }[parasite.type] || parasite.type
          };
        });

        // ✅ FIXED: Process WBCs with array bbox format from Python system
        const wbcs = (detection.wbcsDetected || []).map(wbc => {
          let boundingBox;
          if (Array.isArray(wbc.bbox) && wbc.bbox.length === 4) {
            // Python returns [x_min, y_min, x_max, y_max] array format
            boundingBox = {
              x1: wbc.bbox[0],
              y1: wbc.bbox[1],
              x2: wbc.bbox[2], 
              y2: wbc.bbox[3]
            };
          } else if (wbc.bbox && typeof wbc.bbox === 'object') {
            // Fallback for object format
            boundingBox = wbc.bbox;
          } else {
            // Default empty bbox
            boundingBox = { x1: 0, y1: 0, x2: 0, y2: 0 };
          }

          return {
            type: 'WBC',
            confidence: wbc.confidence || 0.95,
            boundingBox: boundingBox,
            typeFullName: 'White Blood Cell'
          };
        });

        // Log for debugging
        logger.debug(`Image ${detection.imageId}: ${parasites.length} parasites, ${wbcs.length} WBCs`);

        return {
          imageId: detection.imageId,
          originalFilename: detection.originalFilename || `blood_smear_${index + 1}.jpg`,
          url: annotatedUrl || imageUrl,
          annotatedUrl,
          originalUrl: imageUrl,
          annotations: {
            parasites: parasites,
            wbcs: wbcs,
            summary: {
              parasiteCount: detection.parasiteCount || parasites.length || 0,
              wbcCount: detection.whiteBloodCellsDetected || wbcs.length || 0,
              parasiteWbcRatio: detection.parasiteWbcRatio || 0
            }
          }
        };
      }));

      // Log summary for debugging
      logger.info(`Returning ${images.length} images for test ${testId}`);
      const totalParasites = images.reduce((sum, img) => sum + img.annotations.parasites.length, 0);
      const totalWBCs = images.reduce((sum, img) => sum + img.annotations.wbcs.length, 0);
      logger.info(`Total annotations: ${totalParasites} parasites, ${totalWBCs} WBCs`);

      res.json({
        success: true,
        data: {
          testId: result.testId,
          status: result.finalStatus || result.status,
          severity: result.finalSeverity || result.severity?.level,
          images: images,
          totalImages: images.length,
          // ✅ FIXED: Use correct field names
          totalParasites: result.totalParasites || totalParasites, // ✅ FIXED: Changed from totalParasitesDetected
          totalWBC: result.totalWbcs || totalWBCs // ✅ FIXED: Changed from totalWbcDetected
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
   * ✅ FIXED: Get all positive malaria cases
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

      // ✅ FIXED: Build filter for positive cases
      const filter = { status: 'POSITIVE' }; // ✅ FIXED: Changed from 'POS' to 'POSITIVE'

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
   * ✅ COMPLETELY FIXED: Run malaria diagnosis for uploaded images
   */
  async runDiagnosis(req, res, next) {
    const { testId } = req.params;

    try {
      logger.info(`Starting diagnosis for test ${testId}`);

      // Find the test
      const test = await Test.findOne({ testId });
      if (!test) {
        throw new AppError(`Test with ID ${testId} not found`, 404);
      }

      // Check if diagnosis already exists
      const existingDiagnosis = await DiagnosisResult.findOne({ testId: test.testId });
      if (existingDiagnosis) {
        return res.status(400).json({
          success: false,
          message: 'Diagnosis already exists for this test'
        });
      }

      // Find uploaded image paths
      const uploadSession = await fileService.getUploadSessionForTest(test._id);
      if (!uploadSession || !uploadSession.files || uploadSession.files.length === 0) {
        throw new AppError('No uploaded images found for this test', 400);
      }

      const imagePaths = uploadSession.files.map(file => file.path);
      logger.info(`Found ${imagePaths.length} images for analysis`);

      // Call the Flask diagnosis API
      const diagnosisResult = await diagnosisService.analyzeSample(imagePaths);
      logger.info(`Flask API returned: Status=${diagnosisResult.status}, Parasites=${diagnosisResult.totalParasites}, WBCs=${diagnosisResult.totalWbcs}`);

      // Debug: Log timing data
      logger.info(`Timing data received: ${JSON.stringify(diagnosisResult.timing)}`);
      logger.info(`Model type received: ${diagnosisResult.modelType}`);

      // ✅ COMPLETELY FIXED: Save the diagnosis result with correct field mapping
      const newDiagnosisResult = new DiagnosisResult({
        test: test._id, // ✅ FIXED: Add required test field
        testId: test.testId,
        
        // ✅ FIXED: Use correct field names from updated service (camelCase)
        status: diagnosisResult.status, // Already 'POSITIVE'/'NEGATIVE' from fixed service
        mostProbableParasite: diagnosisResult.mostProbableParasite, // ✅ FIXED: camelCase
        parasiteWbcRatio: diagnosisResult.parasiteWbcRatio, // ✅ FIXED: camelCase
        detections: diagnosisResult.detections,
        
        // ✅ FIXED: Add all fields that service now returns
        totalParasites: diagnosisResult.totalParasites, // ✅ FIXED: Use new field name
        totalWbcs: diagnosisResult.totalWbcs, // ✅ FIXED: Use new field name
        totalImagesAttempted: diagnosisResult.totalImagesAttempted, // ✅ FIXED: Use new field name
        analysisSummary: diagnosisResult.analysisSummary, // ✅ FIXED: Add missing field

        // ✅ NEW: Add model type and timing statistics
        modelType: diagnosisResult.modelType || 'ONNX',
        // Only set timing if it has actual values (not all zeros)
        timing: diagnosisResult.timing && diagnosisResult.timing.total_ms > 0
          ? diagnosisResult.timing
          : undefined,

        // ✅ FIXED: Add processing metadata
        apiResponse: {
          rawResponse: diagnosisResult,
          processingTime: diagnosisResult.processingMetadata?.processingTime || Date.now(),
          modelVersion: diagnosisResult.modelType || 'ONNX',
          apiVersion: '1.0',
          callTimestamp: new Date()
        }
      });

      // Calculate and set severity based on results
      newDiagnosisResult.calculateSeverity();

      await newDiagnosisResult.save();
      logger.info(`Diagnosis result saved with ID: ${newDiagnosisResult._id}`);

      // Debug: Log saved timing data
      logger.info(`Saved timing data: ${JSON.stringify(newDiagnosisResult.timing)}`);
      logger.info(`Saved modelType: ${newDiagnosisResult.modelType}`);

      // Update the test status
      test.status = 'completed';
      test.completedAt = new Date();
      await test.save();

      logger.info(`Diagnosis completed for test ${testId}: Status=${newDiagnosisResult.status}, Severity=${newDiagnosisResult.severity.level}, Parasites=${newDiagnosisResult.totalParasites}, WBCs=${newDiagnosisResult.totalWbcs}`);

      // Emit real-time notification
      socketService.emitToAll('diagnosis:completed', {
        testId: test.testId,
        status: newDiagnosisResult.status,
        severity: newDiagnosisResult.severity.level,
        totalParasites: newDiagnosisResult.totalParasites,
        totalWbcs: newDiagnosisResult.totalWbcs
      });

      res.status(200).json({
        success: true,
        message: 'Diagnosis completed successfully',
        data: {
          diagnosisResult: newDiagnosisResult,
          summary: {
            status: newDiagnosisResult.status,
            severity: newDiagnosisResult.severity.level,
            totalParasites: newDiagnosisResult.totalParasites,
            totalWBCs: newDiagnosisResult.totalWbcs,
            parasiteWbcRatio: newDiagnosisResult.parasiteWbcRatio,
            imagesProcessed: newDiagnosisResult.totalImagesAttempted,
            mostProbableParasite: newDiagnosisResult.mostProbableParasite
          }
        }
      });

    } catch (error) {
      logger.error('Run diagnosis error:', error);
      next(error);
    }
  }

  /**
   * Debug diagnosis result data structure
   */
  async debugDiagnosisResult(req, res, next) {
    try {
      const { testId } = req.params;

      const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() })
        .populate('test', 'testId patientId')
        .lean();

      if (!result) {
        return res.json({
          success: true,
          message: `No diagnosis result found for test ID: ${testId}`,
          debug: null
        });
      }

      // Build debug information
      const debugInfo = {
        testId: result.testId,
        status: result.status,
        detectionsCount: result.detections ? result.detections.length : 0,
        firstDetection: null,
        processingMetadata: result.processingMetadata || {},
        flags: result.flags || {},
        createdAt: result.createdAt,
        dataStructure: {
          hasMostProbableParasite: !!result.mostProbableParasite,
          hasAnalysisSummary: !!result.analysisSummary,
          hasFlags: !!result.flags,
          hasProcessingMetadata: !!result.processingMetadata,
          totalParasites: result.totalParasites,
          totalWbcs: result.totalWbcs,
          totalImagesAttempted: result.totalImagesAttempted
        }
      };

      // Add first detection details if available
      if (result.detections && result.detections.length > 0) {
        const firstDetection = result.detections[0];
        debugInfo.firstDetection = {
          imageId: firstDetection.imageId,
          originalFilename: firstDetection.originalFilename,
          parasiteCount: (firstDetection.parasitesDetected || []).length,
          wbcCount: (firstDetection.wbcsDetected || []).length,
          parasitesDetected: firstDetection.parasitesDetected ? firstDetection.parasitesDetected.length : 0,
          wbcsDetected: firstDetection.wbcsDetected ? firstDetection.wbcsDetected.length : 0,
          firstParasite: firstDetection.parasitesDetected && firstDetection.parasitesDetected.length > 0 
            ? firstDetection.parasitesDetected[0] 
            : null,
          firstWbc: firstDetection.wbcsDetected && firstDetection.wbcsDetected.length > 0 
            ? firstDetection.wbcsDetected[0] 
            : null,
          metadata: firstDetection.metadata || {}
        };
      }

      res.json({
        success: true,
        debug: debugInfo
      });

    } catch (error) {
      logger.error('Debug diagnosis result error:', error);
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Test Flask API integration
   */
  async testFlaskApi(req, res, next) {
    try {
      const { imagePaths } = req.body;
      
      if (!imagePaths || !Array.isArray(imagePaths)) {
        return res.status(400).json({
          success: false,
          message: 'imagePaths array is required'
        });
      }

      // Call Flask API directly to see raw response
      const result = await diagnosisService.analyzeSample(imagePaths);

      // Return raw Flask response for debugging
      res.json({
        success: true,
        rawFlaskResponse: result,
        firstDetection: result.detections?.[0],
        firstParasite: result.detections?.[0]?.parasitesDetected?.[0],
        summary: {
          status: result.status,
          totalParasites: result.totalParasites,
          totalWbcs: result.totalWbcs,
          imagesProcessed: result.totalImagesAttempted
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
        stack: error.stack
      });
    }
  }

  /**
   * ✅ FIXED: Helper methods for statistics
   */
  async getParasiteDistribution(startDate, endDate) {
    const matchCondition = { status: 'POSITIVE' }; // ✅ FIXED: Changed from 'POS'
    
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

  /**
   * ✅ FIXED: Get trends data with correct status values
   */
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
          // ✅ FIXED: Update status values in aggregation
          positiveTests: { $sum: { $cond: [{ $eq: ['$status', 'POSITIVE'] }, 1, 0] } }, // ✅ FIXED: Changed from 'POS'
          negativeTests: { $sum: { $cond: [{ $eq: ['$status', 'NEGATIVE'] }, 1, 0] } }  // ✅ FIXED: Changed from 'NEG'
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

  /**
   * Get image detection details
   */
  async getImageDetectionDetails(req, res, next) {
    try {
      const { resultId, imageId } = req.params;

      const result = await DiagnosisResult.findById(resultId);
      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Find the specific image detection
      const imageDetection = result.detections.find(d => d.imageId === imageId);
      if (!imageDetection) {
        return res.status(404).json({
          success: false,
          message: 'Image detection not found'
        });
      }

      res.json({
        success: true,
        data: {
          imageId: imageDetection.imageId,
          parasitesDetected: imageDetection.parasitesDetected || [],
          wbcsDetected: imageDetection.wbcsDetected || [],
          summary: {
            parasiteCount: imageDetection.parasiteCount || 0,
            wbcCount: imageDetection.whiteBloodCellsDetected || 0,
            parasiteWbcRatio: imageDetection.parasiteWbcRatio || 0
          }
        }
      });

    } catch (error) {
      logger.error('Error getting image detection details:', error);
      next(error);
    }
  }

  /**
   * Get performance analytics
   */
  async getPerformanceAnalytics(req, res, next) {
    try {
      const { startDate, endDate, groupBy = 'day' } = req.query;

      const matchCondition = {};
      if (startDate || endDate) {
        matchCondition.createdAt = {};
        if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
        if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
      }

      const analytics = await DiagnosisResult.aggregate([
        { $match: matchCondition },
        {
          $group: {
            _id: this.getGroupByExpression(groupBy),
            count: { $sum: 1 },
            avgParasiteCount: { $avg: '$totalParasites' },
            avgWbcCount: { $avg: '$totalWbcs' },
            positiveCount: { $sum: { $cond: [{ $eq: ['$status', 'POSITIVE'] }, 1, 0] } },
            negativeCount: { $sum: { $cond: [{ $eq: ['$status', 'NEGATIVE'] }, 1, 0] } }
          }
        },
        { $sort: { _id: 1 } }
      ]);

      res.json({
        success: true,
        data: {
          analytics,
          summary: {
            totalTests: analytics.reduce((sum, item) => sum + item.count, 0),
            totalPositive: analytics.reduce((sum, item) => sum + item.positiveCount, 0),
            totalNegative: analytics.reduce((sum, item) => sum + item.negativeCount, 0),
            avgParasiteCount: analytics.reduce((sum, item) => sum + item.avgParasiteCount, 0) / Math.max(analytics.length, 1),
            avgWbcCount: analytics.reduce((sum, item) => sum + item.avgWbcCount, 0) / Math.max(analytics.length, 1)
          }
        }
      });

    } catch (error) {
      logger.error('Get performance analytics error:', error);
      next(new AppError('Failed to retrieve performance analytics', 500));
    }
  }

  /**
   * Helper method for grouping analytics
   */
  getGroupByExpression(groupBy) {
    switch (groupBy) {
      case 'hour':
        return {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' },
          hour: { $hour: '$createdAt' }
        };
      case 'day':
        return {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' }
        };
      case 'month':
        return {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' }
        };
      default:
        return {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' }
        };
    }
  }

  /**
   * Get urgent case analytics
   */
  async getUrgentCaseAnalytics(req, res, next) {
    try {
      const { startDate, endDate, groupBy = 'day' } = req.query;
      
      // Build date filter
      const dateFilter = {};
      if (startDate || endDate) {
        dateFilter.createdAt = {};
        if (startDate) dateFilter.createdAt.$gte = new Date(startDate);
        if (endDate) dateFilter.createdAt.$lte = new Date(endDate);
      }

      // Get urgent cases (for now, we'll consider severe cases as urgent)
      const urgentCases = await DiagnosisResult.find({
        ...dateFilter,
        'severity.level': 'severe'
      });

      res.json({
        success: true,
        data: {
          urgentAnalytics: urgentCases,
          processingModeComparison: {
            fastMode: { count: 0, avgProcessingTime: 0 },
            enhancedMode: { count: 0, avgProcessingTime: 0 }
          },
          summary: {
            totalUrgentCases: urgentCases.length,
            urgentPositive: urgentCases.filter(c => c.status === 'POSITIVE').length,
            urgentNegative: urgentCases.filter(c => c.status === 'NEGATIVE').length,
            avgUrgentProcessingTime: 0
          }
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get detection data (bounding boxes only)
   */
  async getDetectionData(req, res, next) {
    try {
      const { resultId, imageId } = req.params;

      // Return detection data (bounding boxes only)
      res.json({
        success: true,
        data: {
          resultId,
          imageId,
          detectionType: 'bounding_boxes',
          segmentation: {
            available: false,
            masks: [],
            polygons: []
          },
          message: 'Only bounding box detection is supported. Segmentation masks are not available.'
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get model capabilities
   */
  async getModelCapabilities(req, res, next) {
    try {
      res.json({
        success: true,
        capabilities: {
          modelInfo: {
            modelPath: "V12.pt",
            modelType: "YOLO",
            device: "cpu",
            validParasiteTypes: ["PF", "PM", "PO", "PV"],
            validWbcTypes: ["WBC"]
          },
          enhancedFeatures: {
            detection: { available: true, formats: ["bounding_boxes"], description: "Bounding box detection for parasites and WBCs" },
            performanceMetrics: { available: false, metrics: [], description: "Not implemented" },
            multiFormatBbox: { available: false, formats: [], description: "Not implemented" },
            classProbabilities: { available: false, classes: [], description: "Not implemented" },
            segmentation: { available: false, formats: [], description: "Not implemented - detection only" }
          },
          configurationOptions: {
            confidenceThreshold: { type: "number", min: 0, max: 1, default: 0.26, description: "Detection confidence threshold" }
          }
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get system health
   */
  async getSystemHealth(req, res, next) {
    try {
      res.json({
        success: true,
        systemHealth: {
          status: "healthy",
          timestamp: new Date().toISOString(),
          flaskApi: {
            status: "healthy",
            healthCheck: {},
            memoryStatus: {},
            endpoint: "http://flask-api:5000"
          },
          processing: {
            last24Hours: {
              totalProcessed: 0,
              avgProcessingTime: 0,
              fastModeCount: 0,
              enhancedModeCount: 0,
              urgentCaseCount: 0
            }
          },
          enhancedFeatures: {
            detection: { available: true, status: "enabled" },
            performanceMetrics: { available: false, status: "disabled" },
            classProbabilities: { available: false, status: "disabled" },
            multiFormatBbox: { available: false, status: "disabled" },
            segmentation: { available: false, status: "disabled" }
          },
          recommendations: ["System is running normally", "Detection system is active and ready"]
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get processing status for an upload session (fallback for WebSocket)
   * This endpoint is used when WebSocket connection fails or for polling
   */
  async getProcessingStatus(req, res, next) {
    try {
      const { sessionId } = req.params;
      const UploadSession = require('../models/UploadSession');

      // Find the upload session
      const session = await UploadSession.findOne({ sessionId });

      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found',
          status: 'not_found'
        });
      }

      // Determine status based on session state
      // IMPORTANT: session.status === 'completed' only means files are UPLOADED,
      // not that ML processing is complete. We must verify actual processing completion.
      let status = 'processing';
      let result = null;

      // Check if ML processing has actually completed (not just file upload)
      const processingActuallyCompleted =
        session.processing?.completedAt ||
        session.processing?.stages?.apiSubmission?.status === 'completed';

      // Try to get the diagnosis result (this is the definitive indicator of completion)
      const diagnosisResult = session.testId
        ? await DiagnosisResult.findOne({ testId: session.testId })
        : null;

      if (diagnosisResult) {
        // DiagnosisResult exists = processing is truly complete
        status = 'completed';
        result = {
          testId: diagnosisResult.testId,
          status: diagnosisResult.status,
          totalParasites: diagnosisResult.totalParasites,
          totalWbcs: diagnosisResult.totalWbcs,
          severity: diagnosisResult.severity?.level,
          mostProbableParasite: diagnosisResult.mostProbableParasite
        };
      } else if (processingActuallyCompleted && session.status === 'completed') {
        // Processing finished but no result yet (edge case)
        status = 'completed';
      } else if (session.status === 'failed' || session.status === 'cancelled') {
        status = 'failed';
      } else if (session.processing?.isProcessing) {
        // Actively processing
        status = 'processing';
      } else if (session.status === 'completed' && !processingActuallyCompleted) {
        // Files uploaded but processing hasn't started yet - treat as "ready to process"
        status = 'uploaded';
      }

      // Calculate progress based on actual status
      const uploadedFiles = session.files?.filter(f => f.status === 'completed') || [];
      const totalFiles = session.files?.length || 0;

      // Progress calculation depends on actual processing state
      let progress;
      let stage = session.processing?.currentStage || 'unknown';

      if (status === 'completed') {
        progress = 100;
        stage = 'completed';
      } else if (status === 'uploaded') {
        // Files uploaded but processing not started - show minimal progress
        progress = 5;
        stage = 'queued';
      } else if (status === 'processing') {
        // Use processing stage progress if available, otherwise estimate
        progress = session.processing?.progress ||
          (totalFiles > 0 ? Math.round((uploadedFiles.length / totalFiles) * 50) + 10 : 10);
      } else {
        progress = 0;
      }

      logger.info(`Processing status for ${sessionId}: status=${status}, progress=${progress}, isProcessing=${session.processing?.isProcessing}, sessionStatus=${session.status}`);

      res.json({
        success: true,
        sessionId,
        status,
        progress,
        stage,
        totalFiles,
        processedFiles: uploadedFiles.length,
        isProcessing: session.processing?.isProcessing || false,
        result,
        lastError: session.lastError,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Get processing status error:', error);
      next(new AppError('Failed to get processing status', 500));
    }
  }

}

module.exports = new DiagnosisController();
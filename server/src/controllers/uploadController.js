// 📁 server/src/controllers/uploadController.js
const path = require('path');
const fs = require('fs').promises;
const UploadSession = require('../models/UploadSession');
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const auditService = require('../services/auditService');
const fileService = require('../services/fileService');
const diagnosisService = require('../services/diagnosisService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const { socketService } = require('../socket');

class UploadController {
  /**
   * Create a new upload session
   */
  async createUploadSession(req, res, next) {
    try {
      const { testId, maxFiles = 50, maxFileSize = 10485760 } = req.body;  // Increased for hospital use 
      const user = req.user;

      // Verify test exists and user has access
      const test = await Test.findOne({ testId: testId.toUpperCase(), isActive: true });
      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Check if user can upload to this test
      const isTestOwner = test.technician.toString() === user._id.toString();
      const isSupervisor = ['supervisor', 'admin'].includes(user.role);

      if (!isTestOwner && !isSupervisor) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to upload files for this test'
        });
      }

      // Check if test is in a state that allows uploads
      if (!['pending', 'processing'].includes(test.status)) {
        return res.status(400).json({
          success: false,
          message: 'Cannot upload files to a test in this status'
        });
      }

      // Create upload session
      const uploadSession = new UploadSession({
        user: user._id,
        test: test._id,
        testId: test.testId,
        patientId: test.patientId,
        config: {
          maxFiles,
          maxFileSize,
          allowedTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/tiff', 'image/tif']
        },
        metadata: {
          clientInfo: {
            userAgent: req.get('User-Agent'),
            ipAddress: req.ip,
            platform: req.get('sec-ch-ua-platform') || 'unknown'
          },
          uploadMethod: 'file_select'
        }
      });

      await uploadSession.save();

      // Log session creation
      await auditService.log({
        action: 'upload_session_created',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'upload',
        resourceId: uploadSession.sessionId,
        resourceName: `Upload session for ${test.testId}`,
        details: {
          testId: test.testId,
          patientId: test.patientId,
          maxFiles,
          maxFileSize
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: '/api/upload/session'
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.status(201).json({
        success: true,
        message: 'Upload session created successfully',
        data: {
          session: uploadSession
        }
      });

    } catch (error) {
      logger.error('Create upload session error:', error);
      next(new AppError('Failed to create upload session', 500));
    }
  }

  /**
   * Get upload session details
   */
  async getUploadSession(req, res, next) {
    try {
      const { sessionId } = req.params;
      const user = req.user;

      const session = await UploadSession.findOne({ sessionId })
        .populate('user', 'username firstName lastName')
        .populate('test', 'testId patientId status');

      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found'
        });
      }

      // Check if user has access to this session
      const isOwner = session.user._id.toString() === user._id.toString();
      const isSupervisor = ['supervisor', 'admin'].includes(user.role);

      if (!isOwner && !isSupervisor) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to access this upload session'
        });
      }

      res.json({
        success: true,
        data: {
          session
        }
      });

    } catch (error) {
      logger.error('Get upload session error:', error);
      next(new AppError('Failed to retrieve upload session', 500));
    }
  }

  /**
   * Upload files to an existing session (with shared volume support)
   */
  async uploadFiles(req, res, next) {
    try {
      const { sessionId } = req.params;
      const files = req.files;
      const user = req.user;

      if (!files || files.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No files provided'
        });
      }

      // Find upload session
      const session = await UploadSession.findOne({ sessionId, isCleanedUp: false });
      
      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found or expired',
          errorCode: 'SESSION_NOT_FOUND',
          sessionId
        });
      }

      // Check session ownership and status
      if (session.user.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to upload to this session'
        });
      }

      if (session.status !== 'active') {
        return res.status(400).json({
          success: false,
          message: `Upload session is in '${session.status}' status and cannot accept new files`
        });
      }

      // Check file limits
      const currentFileCount = session.files.length;
      if (currentFileCount + files.length > session.config.maxFiles) {
        return res.status(400).json({
          success: false,
          message: `Cannot upload more than ${session.config.maxFiles} files per session`
        });
      }

      const uploadResults = [];
      const errors = [];

      // Process each file
      for (const file of files) {
        try {
          // Validate file
          const validation = await fileService.validateImageFile(file, session.config);
          
          if (!validation.isValid) {
            errors.push({
              filename: file.originalname,
              errors: validation.errors
            });
            continue;
          }

          // Save file and get metadata
          const savedFile = await fileService.saveUploadedFile(file, session.sessionId);
          
          // Copy to shared volume for Flask API access
          const sharedPath = await this.copyToSharedVolume(savedFile);
          
          // Add to session with both paths
          session.files.push({
            filename: savedFile.filename,
            originalName: file.originalname,
            path: savedFile.path,        // Local Node.js path
            sharedPath: sharedPath,      // Shared volume path for Flask
            size: file.size,
            mimetype: file.mimetype,
            status: 'completed',
            isValid: true,
            imageMetadata: savedFile.metadata
          });

          uploadResults.push({
            originalName: file.originalname,
            filename: savedFile.filename,
            size: file.size,
            status: 'completed'
          });

          // Emit real-time progress update
          socketService.emitToUser(user._id, 'upload:fileUploaded', {
            sessionId,
            filename: savedFile.filename,
            originalName: file.originalname,
            progress: session.progress.percentComplete
          });

        } catch (fileError) {
          logger.error(`File upload error for ${file.originalname}:`, fileError);
          errors.push({
            filename: file.originalname,
            errors: ['Failed to process file: ' + fileError.message]
          });
        }
      }

      // Save session with updated files
      await session.save();

      // Log file uploads
      await auditService.log({
        action: 'files_uploaded',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'upload',
        resourceId: session.sessionId,
        resourceName: `Upload session ${session.sessionId}`,
        details: {
          uploadedFiles: uploadResults.length,
          failedFiles: errors.length,
          totalFiles: files.length,
          testId: session.testId
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'POST',
          endpoint: `/api/upload/files/${sessionId}`
        },
        status: uploadResults.length > 0 ? 'success' : 'failure',
        riskLevel: 'low'
      });

      // Emit session update
      socketService.emitToUser(user._id, 'upload:sessionUpdated', {
        sessionId,
        session: session.getSummary()
      });

      res.json({
        success: true,
        message: `${uploadResults.length} files uploaded successfully`,
        data: {
          session: session.getSummary(),
          uploadedFiles: uploadResults,
          errors,
          sessionInfo: {
            sessionId: session.sessionId,
            status: session.status,
            expiresAt: session.expiresAt,
            totalFiles: session.files.length,
            maxFiles: session.config.maxFiles
          }
        }
      });

    } catch (error) {
      logger.error('Upload files error:', error);
      next(new AppError('Failed to upload files', 500));
    }
  }

  /**
   * Copy uploaded file to shared volume for Flask API access
   */
  async copyToSharedVolume(savedFile) {
    try {
      const fs = require('fs').promises;
      const path = require('path');
      
      // Define shared volume path
      const sharedDir = process.env.SHARED_UPLOAD_DIR || '/app/uploads'; // Same volume, different mount point
      const sharedFileName = path.basename(savedFile.path);
      const sharedPath = path.join(sharedDir, sharedFileName);
      
      // Copy file to shared location
      await fs.copyFile(savedFile.path, sharedPath);
      
      logger.debug(`Copied file to shared volume: ${sharedPath}`);
      
      return sharedPath;
      
    } catch (error) {
      logger.error('Failed to copy file to shared volume:', error);
      // Return original path as fallback
      return savedFile.path;
    }
  }

  /**
   * Process uploaded files (send to Flask API for diagnosis)
   */
  async processFiles(req, res, next) {
    try {
      const { sessionId } = req.params;
      const user = req.user;

      // Find upload session
      const session = await UploadSession.findOne({ sessionId })
        .populate('test');

      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found'
        });
      }

      // Check ownership
      if (session.user.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to process this session'
        });
      }

      // Check if session has valid files
      const validFiles = session.getValidFiles();
      if (validFiles.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No valid files to process'
        });
      }

      // Check if already processing
      if (session.processing.isProcessing) {
        return res.status(400).json({
          success: false,
          message: 'Session is already being processed'
        });
      }

      // Start processing
      await session.startProcessing();

      // Update test status to processing
      const test = session.test;
      if (test.status === 'pending') {
        await test.updateStatus('processing', user._id);
      }

      // Emit real-time update
      socketService.emitToUser(user._id, 'upload:processingStarted', {
        sessionId,
        testId: test.testId,
        fileCount: validFiles.length
      });

      // Process asynchronously
      this.processFilesAsync(session, user._id);

      res.json({
        success: true,
        message: 'Processing started successfully',
        data: {
          processingId: session.sessionId,
          estimatedTime: `${validFiles.length * 30} seconds`,
          fileCount: validFiles.length
        }
      });

    } catch (error) {
      logger.error('Process files error:', error);
      next(new AppError('Failed to start processing', 500));
    }
  }

/**
 * ✅ COMPLETELY FIXED: Async file processing (calls Flask API)
 */
async processFilesAsync(session, userId) {
  try {
    // Mark file validation stage as in progress
    await session.markProcessingStage('fileValidation', 'in_progress');

    const validFiles = session.getValidFiles();
    
    // Use shared paths for Flask API if available, otherwise use local paths
    const imagePaths = validFiles.map(file => file.sharedPath || file.path);

    logger.info(`Processing ${validFiles.length} files with Flask API`);
    logger.debug('Image paths for Flask:', imagePaths);

    // ✅ IMPROVED: Send detailed progress updates
    const sendProgressUpdate = (stage, progress, details = {}) => {
      const progressData = {
        sessionId: session.sessionId,
        stage,
        progress,
        overall: progress,
        totalFiles: validFiles.length,
        processedFiles: Math.floor((progress / 100) * validFiles.length),
        estimatedTimeRemaining: Math.max(10, Math.round((100 - progress) * 2)),
        ...details
      };
      
      logger.debug(`Sending progress update: ${stage} - ${progress}%`);
      socketService.emitToUploadSession(session.sessionId, userId, 'upload:processingProgress', progressData);
    };

    // Send initial progress
    sendProgressUpdate('fileValidation', 10, { 
      currentFile: validFiles[0]?.originalName || 'Preparing...' 
    });

    // Mark file validation as completed
    await session.markProcessingStage('fileValidation', 'completed');
    sendProgressUpdate('imagePreperation', 25, { 
      currentFile: 'Preparing images for analysis...' 
    });

    // Mark image preparation as in progress
    await session.markProcessingStage('imagePreperation', 'in_progress');

    // Mark image preparation as completed
    await session.markProcessingStage('imagePreperation', 'completed');
    sendProgressUpdate('apiSubmission', 45, { 
      currentFile: 'Sending to AI analysis engine...' 
    });

    // Mark API submission as in progress
    await session.markProcessingStage('apiSubmission', 'in_progress');

    // Send progress update before calling Flask API
    sendProgressUpdate('analysis', 50, {
      currentFile: 'AI analysis starting...',
      analysisMode: 'parallel'
    });

    // ✅ NEW: Per-image progress tracking
    let imagesProcessed = 0;
    const totalImages = validFiles.length;

    const onImageProgress = (progressData) => {
      imagesProcessed = progressData.completed;
      const analysisProgress = 50 + Math.round((progressData.completed / progressData.total) * 35); // 50-85%

      // Send per-image progress update
      socketService.emitToUploadSession(session.sessionId, userId, 'upload:processingProgress', {
        sessionId: session.sessionId,
        stage: 'analysis',
        progress: analysisProgress,
        overall: analysisProgress,
        totalFiles: totalImages,
        processedFiles: progressData.completed,
        currentFile: `Analyzing image ${progressData.completed}/${progressData.total}: ${progressData.currentImage}`,
        imageProgress: {
          completed: progressData.completed,
          total: progressData.total,
          percentage: progressData.percentage,
          currentImage: progressData.currentImage,
          parasitesFound: progressData.imageResult?.parasiteCount || 0,
          wbcsFound: progressData.imageResult?.wbcCount || 0,
          timing: progressData.imageResult?.timing || null
        }
      });

      logger.info(`Image ${progressData.completed}/${progressData.total} completed: ${progressData.currentImage}`);
    };

    // ✅ FIXED: Call Flask diagnosis API with streaming progress
    const diagnosisResult = await diagnosisService.analyzeSampleWithProgress(imagePaths, onImageProgress);

    logger.info(`Flask API returned: Status=${diagnosisResult.status}, Parasites=${diagnosisResult.totalParasites}, WBCs=${diagnosisResult.totalWbcs}`);

    // Mark API submission as completed
    await session.markProcessingStage('apiSubmission', 'completed');
    sendProgressUpdate('reportGeneration', 85, { 
      currentFile: 'Generating diagnostic report...' 
    });

    // Debug: Log timing data received from diagnosis service
    logger.info(`Timing received from diagnosis service: ${JSON.stringify(diagnosisResult.timing)}`);
    logger.info(`ModelType received: ${diagnosisResult.modelType}`);

    // ✅ COMPLETELY FIXED: Create diagnosis result record with correct field mapping
    const result = new DiagnosisResult({
      test: session.test._id, // ✅ FIXED: Add required test field
      testId: session.testId,
      
      // ✅ FIXED: Use correct field names from updated service (camelCase)
      status: diagnosisResult.status, // Already 'POSITIVE'/'NEGATIVE' from fixed service
      mostProbableParasite: diagnosisResult.mostProbableParasite, // ✅ FIXED: camelCase
      parasiteWbcRatio: diagnosisResult.parasiteWbcRatio, // ✅ FIXED: camelCase
      
      // ✅ FIXED: Add all fields that service now returns
      totalParasites: diagnosisResult.totalParasites, // ✅ FIXED: Use new field name
      totalWbcs: diagnosisResult.totalWbcs, // ✅ FIXED: Use new field name
      totalImagesAttempted: diagnosisResult.totalImagesAttempted, // ✅ FIXED: Use new field name
      analysisSummary: diagnosisResult.analysisSummary, // ✅ FIXED: Add missing field

      // ✅ NEW: Add model type and timing statistics
      modelType: diagnosisResult.modelType || 'ONNX',
      timing: diagnosisResult.timing || null,
      
      // ✅ FIXED: Process detections with correct field names
      detections: diagnosisResult.detections.map(detection => ({
        imageId: detection.imageId, // ✅ FIXED: camelCase
        originalFilename: validFiles.find(f => f.filename.includes(detection.imageId))?.originalName,
        
        // ✅ FIXED: Use camelCase field names from service
        parasitesDetected: detection.parasitesDetected || [], // ✅ FIXED: camelCase
        wbcsDetected: detection.wbcsDetected || [], // ✅ FIXED: Add missing field
        whiteBloodCellsDetected: detection.whiteBloodCellsDetected || 0, // ✅ FIXED: camelCase
        parasiteCount: detection.parasiteCount || 0, // ✅ FIXED: camelCase
        parasiteWbcRatio: detection.parasiteWbcRatio || 0, // ✅ FIXED: camelCase
        annotatedImagePath: detection.annotatedImagePath ,
        annotatedUrl: detection.annotatedUrl ,
        
        // ✅ FIXED: Add metadata field
        metadata: detection.metadata || {
          totalDetections: 0,
          detectionRate: 1.0
        }
      })),
      
      // ✅ FIXED: Add processing metadata
      apiResponse: {
        rawResponse: diagnosisResult,
        processingTime: session.processing.processingTime,
        callTimestamp: new Date(),
        apiVersion: diagnosisResult.processingMetadata?.apiVersion || '1.0',
        modelVersion: 'V12.pt'
      }
    });

    // Calculate severity
    result.calculateSeverity();
    await result.save();

    logger.info(`DiagnosisResult saved: Status=${result.status}, Severity=${result.severity.level}, Parasites=${result.totalParasites}, WBCs=${result.totalWbcs}`);
    logger.info(`Timing saved: ${JSON.stringify(result.timing)}, ModelType: ${result.modelType}`);

    // ✅ FIXED: Send final progress update with "completed" stage
    const sendFinalProgress = (stage, progress, details = {}) => {
      const progressData = {
        sessionId: session.sessionId,
        stage,
        progress,
        overall: progress,
        totalFiles: validFiles.length,
        processedFiles: validFiles.length,
        estimatedTimeRemaining: 0,
        ...details
      };
      
      logger.debug(`Sending final progress update: ${stage} - ${progress}%`);
      socketService.emitToUploadSession(session.sessionId, userId, 'upload:processingProgress', progressData);
    };

    // Send final progress update with "completed" stage
    sendFinalProgress('completed', 100, { 
      currentFile: 'Analysis complete!',
      result: diagnosisResult.status,
      confidence: diagnosisResult.mostProbableParasite?.confidence || 0
    });

    // Complete processing
    await session.completeProcessing(true);

    // Update test status
    const test = await Test.findById(session.test);
    await test.updateStatus('completed', userId);

    // ✅ FIXED: Update patient statistics with correct status values
    const patient = await test.populate('patient');
    if (diagnosisResult.status === 'POSITIVE') { // ✅ FIXED: Changed from 'POS' to 'POSITIVE'
      patient.patient.positiveTests += 1;
    }
    patient.patient.lastTestResult = diagnosisResult.status; // ✅ FIXED: Now stores 'POSITIVE'/'NEGATIVE'
    await patient.patient.save();

    // Log successful processing
    await auditService.log({
      action: 'diagnosis_completed',
      userId: userId,
      resourceType: 'diagnosis',
      resourceId: result._id.toString(),
      resourceName: `Diagnosis for ${session.testId}`,
      details: {
        sessionId: session.sessionId,
        result: diagnosisResult.status,
        parasiteType: diagnosisResult.mostProbableParasite?.type,
        confidence: diagnosisResult.mostProbableParasite?.confidence,
        totalParasites: diagnosisResult.totalParasites,
        totalWbcs: diagnosisResult.totalWbcs,
        filesProcessed: validFiles.length
      },
      status: 'success',
      riskLevel: 'low'
    });

    // ✅ IMPROVED: Emit completion notification with completed stage
    logger.info(`[Socket] Emitting completion for session ${session.sessionId} and user ${userId}`);
    const completionSuccess = socketService.emitToUploadSession(session.sessionId, userId, 'upload:processingCompleted', {
      sessionId: session.sessionId,
      testId: session.testId,
      result: result.generateReport(),
      status: diagnosisResult.status,
      confidence: diagnosisResult.mostProbableParasite?.confidence,
      processingTime: session.processing.processingTime,
      stage: 'completed',
      overall: 100
    });

    if (!completionSuccess) {
      logger.error(`Failed to emit completion notification for session ${session.sessionId}`);
    }

    // ✅ FIXED: Emit to all supervisors for positive results
    if (diagnosisResult.status === 'POSITIVE') { // ✅ FIXED: Changed from 'POS' to 'POSITIVE'
      socketService.emitToRole('supervisor', 'diagnosis:positiveResult', {
        testId: session.testId,
        patientId: session.patientId,
        severity: result.severity.level,
        technician: userId
      });
    }

  } catch (error) {
    logger.error('Async file processing error:', error);

    // Mark processing as failed
    await session.completeProcessing(false);
    session.errorMessages.push(error.message);
    session.lastError = {
      message: error.message,
      timestamp: new Date(),
      code: 'PROCESSING_FAILED'
    };
    await session.save();

    // Update test status to failed
    const test = await Test.findById(session.test);
    await test.updateStatus('failed', userId);

    // Log processing failure
    await auditService.log({
      action: 'diagnosis_failed',
      userId: userId,
      resourceType: 'diagnosis',
      resourceId: session.sessionId,
      details: {
        sessionId: session.sessionId,
        error: error.message,
        filesAttempted: session.getValidFiles().length
      },
      status: 'failure',
      riskLevel: 'medium'
    });

    // IMPROVED: Emit failure notification
    socketService.emitToUploadSession(session.sessionId, userId, 'upload:processingFailed', {
      sessionId: session.sessionId,
      testId: session.testId,
      error: error.message,
      stage: 'failed'
    });
  }
}


  /**
   * Cancel upload session
   */
  async cancelUploadSession(req, res, next) {
    try {
      const { sessionId } = req.params;
      const { reason = 'User cancelled' } = req.body;
      const user = req.user;

      const session = await UploadSession.findOne({ sessionId });
      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found'
        });
      }

      // Check ownership
      if (session.user.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to cancel this session'
        });
      }

      await session.cancel(reason);

      // Log cancellation
      await auditService.log({
        action: 'upload_session_cancelled',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'upload',
        resourceId: session.sessionId,
        details: { reason, filesUploaded: session.files.length },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Upload session cancelled successfully'
      });

    } catch (error) {
      logger.error('Cancel upload session error:', error);
      next(new AppError('Failed to cancel upload session', 500));
    }
  }

  /**
   * Delete a specific file from upload session
   */
  async deleteFile(req, res, next) {
    try {
      const { sessionId } = req.params;
      const { filename } = req.body;
      const user = req.user;

      const session = await UploadSession.findOne({ sessionId });
      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found'
        });
      }

      // Check ownership
      if (session.user.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to modify this session'
        });
      }

      // Find file in session
      const fileIndex = session.files.findIndex(f => f.filename === filename);
      if (fileIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'File not found in session'
        });
      }

      const file = session.files[fileIndex];

      // Delete physical file
      try {
        await fileService.deleteFile(file.path);
      } catch (deleteError) {
        logger.warn('Failed to delete physical file:', deleteError);
      }

      // Remove from session
      session.files.splice(fileIndex, 1);
      await session.save();

      res.json({
        success: true,
        message: 'File deleted successfully'
      });

    } catch (error) {
      logger.error('Delete file error:', error);
      next(new AppError('Failed to delete file', 500));
    }
  }

  /**
   * Get user's upload sessions
   */
  async getUserUploadSessions(req, res, next) {
    try {
      const { status, page = 1, limit = 10 } = req.query;
      const user = req.user;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      const filter = { user: user._id };
      if (status) filter.status = status;

      const [sessions, total] = await Promise.all([
        UploadSession.find(filter)
          .populate('test', 'testId patientId status')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit)),
        UploadSession.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          sessions,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: totalPages
          }
        }
      });

    } catch (error) {
      logger.error('Get user upload sessions error:', error);
      next(new AppError('Failed to retrieve upload sessions', 500));
    }
  }

  /**
   * Validate files before upload
   */
  async validateFiles(req, res, next) {
    try {
      const files = req.files;

      if (!files || files.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No files provided'
        });
      }

      const validFiles = [];
      const invalidFiles = [];
      let totalSize = 0;

      const config = {
        maxFileSize: 10485760, // 10MB
        allowedTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/tiff', 'image/tif']
      };

      for (const file of files) {
        const validation = await fileService.validateImageFile(file, config);
        
        if (validation.isValid) {
          validFiles.push({
            originalName: file.originalname,
            size: file.size,
            mimetype: file.mimetype,
            metadata: validation.metadata
          });
          totalSize += file.size;
        } else {
          invalidFiles.push({
            originalName: file.originalname,
            errors: validation.errors
          });
        }
      }

      res.json({
        success: true,
        data: {
          validFiles,
          invalidFiles,
          totalSize,
          summary: {
            totalFiles: files.length,
            validCount: validFiles.length,
            invalidCount: invalidFiles.length
          }
        }
      });

    } catch (error) {
      logger.error('Validate files error:', error);
      next(new AppError('Failed to validate files', 500));
    }
  }

  /**
   * Retry failed file uploads or processing
   */
  async retryUpload(req, res, next) {
    try {
      const { sessionId } = req.params;
      const { retryType = 'processing', filenames } = req.body;
      const user = req.user;

      const session = await UploadSession.findOne({ sessionId });
      if (!session) {
        return res.status(404).json({
          success: false,
          message: 'Upload session not found'
        });
      }

      // Check ownership
      if (session.user.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to retry this session'
        });
      }

      if (retryType === 'processing') {
        // Reset processing status
        session.processing.isProcessing = false;
        session.status = 'active';
        session.errors = [];
        
        // Reset processing stages
        Object.keys(session.processing.stages).forEach(stage => {
          session.processing.stages[stage].status = 'pending';
          session.processing.stages[stage].errors = [];
        });

        await session.save();

        // Start processing again
        this.processFilesAsync(session, user._id);

        res.json({
          success: true,
          message: 'Processing retry initiated'
        });

      } else {
        res.status(400).json({
          success: false,
          message: 'Upload retry not implemented yet'
        });
      }

    } catch (error) {
      logger.error('Retry upload error:', error);
      next(new AppError('Failed to retry upload', 500));
    }
  }

  /**
   * Get upload statistics
   */
  async getUploadStatistics(req, res, next) {
    try {
      const { startDate, endDate } = req.query;

      const stats = await UploadSession.getUploadStatistics(startDate, endDate);

      res.json({
        success: true,
        data: stats[0] || {
          totalSessions: 0,
          completedSessions: 0,
          failedSessions: 0,
          totalFiles: 0,
          avgFilesPerSession: 0,
          totalUploadSize: 0
        }
      });

    } catch (error) {
      logger.error('Get upload statistics error:', error);
      next(new AppError('Failed to retrieve upload statistics', 500));
    }
  }

  /**
   * Cleanup expired upload sessions
   */
  async cleanupExpiredSessions(req, res, next) {
    try {
      const expiredSessions = await UploadSession.findExpiredSessions();
      
      let cleanedSessions = 0;
      let cleanedFiles = 0;
      let freedSpace = 0;

      for (const session of expiredSessions) {
        try {
          // Delete physical files
          for (const file of session.files) {
            try {
              const stats = await fs.stat(file.path);
              freedSpace += stats.size;
              await fileService.deleteFile(file.path);
              cleanedFiles++;
            } catch (deleteError) {
              logger.warn(`Failed to delete file ${file.path}:`, deleteError);
            }
          }

          // Mark session as cleaned up
          await session.cleanup();
          cleanedSessions++;

        } catch (sessionError) {
          logger.error(`Failed to cleanup session ${session.sessionId}:`, sessionError);
        }
      }

      // Log cleanup activity
      await auditService.log({
        action: 'upload_cleanup',
        userId: req.user._id,
        userInfo: { username: req.user.username, email: req.user.email, role: req.user.role },
        resourceType: 'system',
        resourceId: 'upload_cleanup',
        details: {
          cleanedSessions,
          cleanedFiles,
          freedSpace: `${(freedSpace / (1024 * 1024)).toFixed(2)} MB`
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Cleanup completed successfully',
        data: {
          cleanedSessions,
          cleanedFiles,
          freedSpace: `${(freedSpace / (1024 * 1024)).toFixed(2)} MB`
        }
      });

    } catch (error) {
      logger.error('Cleanup expired sessions error:', error);
      next(new AppError('Failed to cleanup expired sessions', 500));
    }
  }
  /**
   * Debug: Get all upload sessions for current user (temporary debug endpoint)
   */
  async debugUploadSessions(req, res, next) {
    try {
      const user = req.user;
      
      // Get all sessions for this user
      const allSessions = await UploadSession.find({ user: user._id })
        .sort({ createdAt: -1 })
        .limit(20);
      
      // Get active sessions
      const activeSessions = await UploadSession.find({
        user: user._id,
        status: 'active',
        expiresAt: { $gt: new Date() },
        isCleanedUp: false
      });
      
      // Check if the specific session exists
      const specificSession = await UploadSession.findOne({
        sessionId: req.query.sessionId
      });
      
      res.json({
        success: true,
        debug: {
          userId: user._id,
          currentTime: new Date(),
          totalSessions: allSessions.length,
          activeSessions: activeSessions.length,
          searchedSessionId: req.query.sessionId,
          specificSessionFound: !!specificSession,
          specificSessionDetails: specificSession,
          allUserSessions: allSessions.map(s => ({
            sessionId: s.sessionId,
            status: s.status,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
            isCleanedUp: s.isCleanedUp,
            fileCount: s.files.length
          })),
          activeSessions: activeSessions.map(s => ({
            sessionId: s.sessionId,
            testId: s.testId,
            status: s.status,
            fileCount: s.files.length,
            expiresAt: s.expiresAt
          }))
        }
      });
      
    } catch (error) {
      logger.error('Debug upload sessions error:', error);
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}
module.exports = new UploadController();
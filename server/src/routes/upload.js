// 📁 server/src/routes/upload.js
const express = require('express');
const { body, param, query } = require('express-validator');
const uploadController = require('../controllers/uploadController');
const { validateRequest } = require('../middleware/validation');
const { auth, requireAdmin, requireSupervisor, requirePermission } = require('../middleware/auth');
const { fileUpload, handleUploadError, trackUploadStart, trackUploadEnd } = require('../middleware/fileUpload');

const router = express.Router();

// All upload routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     UploadSession:
 *       type: object
 *       properties:
 *         sessionId:
 *           type: string
 *           example: "upload_1707123456789_abc123def"
 *         status:
 *           type: string
 *           enum: [active, completed, failed, cancelled, expired]
 *         testId:
 *           type: string
 *           example: "TEST-20250611-001"
 */

/**
 * @swagger
 * /api/upload/session:
 *   post:
 *     summary: Create a new upload session
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - testId
 *             properties:
 *               testId:
 *                 type: string
 *                 example: "TEST-20250611-001"
 *               maxFiles:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 20
 *                 default: 10
 *               maxFileSize:
 *                 type: integer
 *                 minimum: 1024
 *                 maximum: 52428800
 *                 default: 10485760
 *     responses:
 *       201:
 *         description: Upload session created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     session:
 *                       $ref: '#/components/schemas/UploadSession'
 */
router.post('/session',
  requirePermission('canUploadSamples'),
  body('testId').notEmpty().withMessage('Test ID is required'),
  body('maxFiles').optional().isInt({ min: 1, max: 20 }).withMessage('Max files must be between 1 and 20'),
  body('maxFileSize').optional().isInt({ min: 1024, max: 52428800 }).withMessage('Max file size must be between 1KB and 50MB'),
  validateRequest,
  uploadController.createUploadSession
);

/**
 * @swagger
 * /api/upload/session/{sessionId}:
 *   get:
 *     summary: Get upload session details
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Upload session retrieved successfully
 */
router.get('/session/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  validateRequest,
  uploadController.getUploadSession
);

/**
 * @swagger
 * /api/upload/files/{sessionId}:
 *   post:
 *     summary: Upload files to an existing session
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               files:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *                 description: Blood sample images (JPEG, PNG, TIFF)
 *     responses:
 *       200:
 *         description: Files uploaded successfully
 */
router.post('/files/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  validateRequest,
  trackUploadStart,
  ...fileUpload,
  trackUploadEnd,
  handleUploadError,
  uploadController.uploadFiles
);

/**
 * @swagger
 * /api/upload/process/{sessionId}:
 *   post:
 *     summary: Process uploaded files (send to Flask API for diagnosis)
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Processing started successfully
 */
router.post('/process/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  validateRequest,
  uploadController.processFiles
);

/**
 * @swagger
 * /api/upload/validate-files:
 *   post:
 *     summary: Validate files before upload
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               files:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *     responses:
 *       200:
 *         description: File validation results
 */
router.post('/validate-files',
  trackUploadStart,
  ...fileUpload,
  trackUploadEnd,
  handleUploadError,
  uploadController.validateFiles
);

/**
 * @swagger
 * /api/upload/my-sessions:
 *   get:
 *     summary: Get user's upload sessions
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, completed, failed, cancelled, expired]
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *     responses:
 *       200:
 *         description: Upload sessions retrieved successfully
 */
router.get('/my-sessions',
  query('status').optional().isIn(['active', 'completed', 'failed', 'cancelled', 'expired']).withMessage('Status must be a valid upload session status'),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  validateRequest,
  uploadController.getUserUploadSessions
);

/**
 * @swagger
 * /api/upload/cancel/{sessionId}:
 *   patch:
 *     summary: Cancel upload session
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *                 maxLength: 200
 *     responses:
 *       200:
 *         description: Upload session cancelled successfully
 */
router.patch('/cancel/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  body('reason').optional().isString().isLength({ max: 200 }).withMessage('Reason must be a string less than 200 characters'),
  validateRequest,
  uploadController.cancelUploadSession
);

/**
 * @swagger
 * /api/upload/delete-file/{sessionId}:
 *   delete:
 *     summary: Delete a specific file from upload session
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - filename
 *             properties:
 *               filename:
 *                 type: string
 *     responses:
 *       200:
 *         description: File deleted successfully
 */
router.delete('/delete-file/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  body('filename').notEmpty().withMessage('Filename is required'),
  validateRequest,
  uploadController.deleteFile
);

/**
 * @swagger
 * /api/upload/retry/{sessionId}:
 *   post:
 *     summary: Retry failed upload or processing
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               retryType:
 *                 type: string
 *                 enum: [upload, processing]
 *                 default: processing
 *               filenames:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Retry initiated successfully
 */
router.post('/retry/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  body('retryType').optional().isIn(['upload', 'processing']).withMessage('Retry type must be upload or processing'),
  body('filenames').optional().isArray().withMessage('Filenames must be an array'),
  validateRequest,
  uploadController.retryUpload
);

/**
 * @swagger
 * /api/upload/statistics:
 *   get:
 *     summary: Get upload statistics (Supervisor/Admin only)
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Upload statistics retrieved successfully
 */
router.get('/statistics',
  requireSupervisor,
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  validateRequest,
  uploadController.getUploadStatistics
);

/**
 * @swagger
 * /api/upload/cleanup:
 *   post:
 *     summary: Cleanup expired upload sessions (Admin only)
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Cleanup completed successfully
 */
router.post('/cleanup',
  requireAdmin,
  uploadController.cleanupExpiredSessions
);

// Debug endpoint - remove in production
router.get('/debug/sessions',
  query('sessionId').optional().isString(),
  validateRequest,
  uploadController.debugUploadSessions
);

module.exports = router;
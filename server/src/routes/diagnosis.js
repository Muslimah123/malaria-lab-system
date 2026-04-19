// 📁 server/src/routes/diagnosis.js
const express = require('express');
const { body, param, query } = require('express-validator');
const diagnosisController = require('../controllers/diagnosisController');
const { validateRequest } = require('../middleware/validation');
const { auth, requireAdmin, requireSupervisor, requirePermission } = require('../middleware/auth');

const router = express.Router();

// All diagnosis routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     DiagnosisResult:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *         testId:
 *           type: string
 *           example: "TEST-20250531-001"
 *         status:
 *           type: string
 *           enum: [POSITIVE, NEGATIVE]
 *           description: Diagnosis status
 *         mostProbableParasite:
 *           type: object
 *           properties:
 *             type:
 *               type: string
 *               enum: [PF, PM, PO, PV]
 *             confidence:
 *               type: number
 *               minimum: 0
 *               maximum: 1
 *             fullName:
 *               type: string
 *         parasiteWbcRatio:
 *           type: number
 *           description: Ratio of parasites to white blood cells
 *         detections:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               imageId:
 *                 type: string
 *               originalFilename:
 *                 type: string
 *               parasitesDetected:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     type:
 *                       type: string
 *                       enum: [PF, PM, PO, PV]
 *                     confidence:
 *                       type: number
 *                       minimum: 0
 *                       maximum: 1
 *                     bbox:
 *                       type: array
 *                       items:
 *                         type: number
 *                       description: Bounding box coordinates [x_min, y_min, x_max, y_max]
 *               wbcsDetected:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     type:
 *                       type: string
 *                       enum: [WBC]
 *                     confidence:
 *                       type: number
 *                       minimum: 0
 *                       maximum: 1
 *                     bbox:
 *                       type: array
 *                       items:
 *                         type: number
 *                       description: Bounding box coordinates [x_min, y_min, x_max, y_max]
 *               parasiteCount:
 *                 type: integer
 *               whiteBloodCellsDetected:
 *                 type: integer
 *               parasiteWbcRatio:
 *                 type: number
 *               metadata:
 *                 type: object
 *                 properties:
 *                   totalDetections:
 *                     type: number
 *                   detectionRate:
 *                     type: number
 *         analysisSummary:
 *           type: object
 *           properties:
 *             parasiteTypesDetected:
 *               type: array
 *               items:
 *                 type: string
 *             avgWbcConfidence:
 *               type: number
 *             totalWbcDetections:
 *               type: number
 *             imagesProcessed:
 *               type: number
 *         totalParasites:
 *           type: integer
 *           description: Total parasites detected across all images
 *         totalWbcs:
 *           type: integer
 *           description: Total WBCs detected across all images
 *         totalImagesAttempted:
 *           type: integer
 *           description: Total number of images processed
 *         severity:
 *           type: object
 *           properties:
 *             level:
 *               type: string
 *               enum: [negative, mild, moderate, severe]
 *             confidence:
 *               type: number
 *         flags:
 *           type: object
 *           properties:
 *             requiresManualReview:
 *               type: boolean
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 *     ManualReview:
 *       type: object
 *       required:
 *         - reviewNotes
 *       properties:
 *         reviewNotes:
 *           type: string
 *           maxLength: 1000
 *         overriddenStatus:
 *           type: string
 *           enum: [POSITIVE, NEGATIVE]
 *         overriddenSeverity:
 *           type: string
 *           enum: [negative, mild, moderate, severe]
 *         reviewerConfidence:
 *           type: string
 *           enum: [low, medium, high]
 */

// ✅ FIXED: SPECIFIC ROUTES FIRST - These MUST come before parameterized routes

/**
 * @swagger
 * /api/diagnosis:
 *   get:
 *     summary: Get all diagnosis results with filtering
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
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
 *           maximum: 100
 *           default: 20
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [POSITIVE, NEGATIVE]
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [negative, mild, moderate, severe]
 *       - in: query
 *         name: parasiteType
 *         schema:
 *           type: string
 *           enum: [PF, PM, PO, PV]
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
 *       - in: query
 *         name: requiresReview
 *         schema:
 *           type: boolean
 *     responses:
 *       200:
 *         description: Diagnosis results retrieved successfully
 */
router.get('/',
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('status').optional().isIn(['POSITIVE', 'NEGATIVE']), // ✅ FIXED: Updated status values
  query('severity').optional().isIn(['negative', 'mild', 'moderate', 'severe']),
  query('parasiteType').optional().isIn(['PF', 'PM', 'PO', 'PV']),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  query('requiresReview').optional().isBoolean(),
  validateRequest,
  diagnosisController.getAllDiagnosisResults
);

/**
 * @swagger
 * /api/diagnosis/statistics:
 *   get:
 *     summary: Get diagnosis statistics (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.get('/statistics',
  requireSupervisor,
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  query('groupBy').optional().isIn(['day', 'week', 'month']),
  validateRequest,
  diagnosisController.getDiagnosisStatistics
);

/**
 * @swagger
 * /api/diagnosis/requiring-review:
 *   get:
 *     summary: Get diagnosis results requiring manual review (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.get('/requiring-review',
  requireSupervisor,
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  validateRequest,
  diagnosisController.getResultsRequiringReview
);

/**
 * @swagger
 * /api/diagnosis/positive-cases:
 *   get:
 *     summary: Get all positive malaria cases (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.get('/positive-cases',
  requireSupervisor,
  query('severity').optional().isIn(['mild', 'moderate', 'severe']),
  query('parasiteType').optional().isIn(['PF', 'PM', 'PO', 'PV']),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  validateRequest,
  diagnosisController.getPositiveCases
);

/**
 * ✅ NEW: Performance analytics route
 * @swagger
 * /api/diagnosis/performance/analytics:
 *   get:
 *     summary: Get performance analytics for diagnosis results
 *     tags: [Diagnosis, Analytics]
 *     security:
 *       - bearerAuth: []
 */
router.get('/performance/analytics',
  requireSupervisor,
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  query('groupBy').optional().isIn(['hour', 'day', 'month']),
  validateRequest,
  diagnosisController.getPerformanceAnalytics
);

/**
 * ✅ NEW: Urgent case analytics route
 * @swagger
 * /api/diagnosis/urgent-analytics:
 *   get:
 *     summary: Get urgent case statistics and processing mode comparison analytics
 *     tags: [Diagnosis, Analytics]
 *     security:
 *       - bearerAuth: []
 */
router.get('/urgent-analytics',
  requireSupervisor,
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  query('groupBy').optional().isIn(['hour', 'day', 'week', 'month']),
  validateRequest,
  diagnosisController.getUrgentCaseAnalytics
);

/**
 * ✅ NEW: Model capabilities route
 * @swagger
 * /api/diagnosis/model/capabilities:
 *   get:
 *     summary: Get current model capabilities and available features
 *     tags: [Diagnosis, Model]
 *     security:
 *       - bearerAuth: []
 */
router.get('/model/capabilities',
  diagnosisController.getModelCapabilities
);

/**
 * ✅ NEW: System health route
 * @swagger
 * /api/diagnosis/system/health:
 *   get:
 *     summary: Get comprehensive system health status and recommendations
 *     tags: [Diagnosis, System]
 *     security:
 *       - bearerAuth: []
 */
router.get('/system/health',
  diagnosisController.getSystemHealth
);

/**
 * @swagger
 * /api/diagnosis/status/{sessionId}:
 *   get:
 *     summary: Get processing status for an upload session (fallback for WebSocket)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *         description: Upload session ID
 *     responses:
 *       200:
 *         description: Processing status retrieved successfully
 *       404:
 *         description: Session not found
 */
router.get('/status/:sessionId',
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  validateRequest,
  diagnosisController.getProcessingStatus
);

/**
 * @swagger
 * /api/diagnosis/batch-export:
 *   post:
 *     summary: Export multiple diagnosis results (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.post('/batch-export',
  requireSupervisor,
  requirePermission('canExportReports'),
  body('testIds')
    .isArray({ min: 1, max: 100 })
    .withMessage('Test IDs must be an array with 1-100 items'),
  body('format')
    .optional()
    .isIn(['pdf', 'csv', 'json'])
    .withMessage('Format must be pdf, csv, or json'),
  body('includeImages')
    .optional()
    .isBoolean()
    .withMessage('Include images must be a boolean'),
  validateRequest,
  diagnosisController.batchExportResults
);

// ✅ FIXED: PARAMETERIZED ROUTES COME AFTER SPECIFIC ROUTES

/**
 * @swagger
 * /api/diagnosis/{testId}:
 *   get:
 *     summary: Get diagnosis result by test ID
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.get('/:testId',
  param('testId').notEmpty().withMessage('Test ID is required'),
  validateRequest,
  diagnosisController.getDiagnosisResultByTestId
);

/**
 * ✅ NEW: Run diagnosis route
 * @swagger
 * /api/diagnosis/{testId}/run:
 *   post:
 *     summary: Run malaria diagnosis for uploaded images
 *     description: Execute malaria detection analysis on uploaded images for a specific test
 *     tags: [Diagnosis, AI]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *         description: Test ID to run diagnosis on
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               confidenceThreshold:
 *                 type: number
 *                 minimum: 0
 *                 maximum: 1
 *                 default: 0.26
 *                 description: Confidence threshold for detection
 *               fastMode:
 *                 type: boolean
 *                 default: false
 *                 description: Enable fast mode for urgent cases
 *               urgentCase:
 *                 type: boolean
 *                 default: false
 *                 description: Mark as urgent case
 *     responses:
 *       200:
 *         description: Diagnosis completed successfully
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
 *                     diagnosisResult:
 *                       $ref: '#/components/schemas/DiagnosisResult'
 *                     summary:
 *                       type: object
 *                       properties:
 *                         status:
 *                           type: string
 *                         totalParasites:
 *                           type: number
 *                         totalWBCs:
 *                           type: number
 *                         severity:
 *                           type: string
 *       400:
 *         description: Bad request - missing images or invalid parameters
 *       404:
 *         description: Test not found
 *       500:
 *         description: Internal server error
 */
router.post('/:testId/run',
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('confidenceThreshold').optional().isFloat({ min: 0, max: 1 }),
  body('fastMode').optional().isBoolean(),
  body('urgentCase').optional().isBoolean(),
  validateRequest,
  diagnosisController.runDiagnosis
);

/**
 * @swagger
 * /api/diagnosis/{testId}/review:
 *   post:
 *     summary: Add manual review to diagnosis result (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.post('/:testId/review',
  requireSupervisor,
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('reviewNotes')
    .notEmpty()
    .isLength({ max: 1000 })
    .withMessage('Review notes are required and must be less than 1000 characters'),
  body('overriddenStatus')
    .optional()
    .isIn(['POSITIVE', 'NEGATIVE']) // ✅ FIXED: Updated status values
    .withMessage('Overridden status must be POSITIVE or NEGATIVE'),
  body('overriddenSeverity')
    .optional()
    .isIn(['negative', 'mild', 'moderate', 'severe'])
    .withMessage('Overridden severity must be negative, mild, moderate, or severe'),
  body('reviewerConfidence')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Reviewer confidence must be low, medium, or high'),
  body('reviewedDetections').optional().isArray(),
  body('reviewedWbcs').optional().isArray(),
  body('flaggedParasiteIds').optional().isArray(),
  body('flaggedWbcIds').optional().isArray(),
  body('imagePaths').optional().isArray(),
  validateRequest,
  diagnosisController.addManualReview
);

/**
 * @swagger
 * /api/diagnosis/{testId}/images:
 *   get:
 *     summary: Get annotated images for diagnosis result
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.get('/:testId/images',
  param('testId').notEmpty().withMessage('Test ID is required'),
  query('imageId').optional().isString(),
  validateRequest,
  diagnosisController.getDiagnosisImages
);

/**
 * @swagger
 * /api/diagnosis/{testId}/export:
 *   get:
 *     summary: Export diagnosis result as PDF report
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.get('/:testId/export',
  requirePermission('canExportReports'),
  param('testId').notEmpty().withMessage('Test ID is required'),
  query('format').optional().isIn(['pdf', 'json']),
  validateRequest,
  diagnosisController.exportDiagnosisReport
);

/**
 * @swagger
 * /api/diagnosis/{testId}/hospital-integration:
 *   post:
 *     summary: Send diagnosis result to hospital EMR system (Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.post('/:testId/hospital-integration',
  requireAdmin,
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('hospitalId').optional().isString(),
  body('departmentId').optional().isString(),
  body('physicianId').optional().isString(),
  body('notes').optional().isString().isLength({ max: 500 }),
  validateRequest,
  diagnosisController.sendToHospitalEMR
);

/**
 * @swagger
 * /api/diagnosis/{testId}/quality-feedback:
 *   post:
 *     summary: Provide quality feedback on diagnosis result
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 */
router.post('/:testId/quality-feedback',
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('qualityScore')
    .isInt({ min: 1, max: 5 })
    .withMessage('Quality score must be between 1 and 5'),
  body('feedback')
    .notEmpty()
    .isLength({ max: 500 })
    .withMessage('Feedback is required and must be less than 500 characters'),
  body('imageQualityIssues')
    .optional()
    .isArray()
    .withMessage('Image quality issues must be an array'),
  validateRequest,
  diagnosisController.addQualityFeedback
);

/**
 * ✅ FIXED: Debug route now delegates to controller
 * @swagger
 * /api/diagnosis/{testId}/debug:
 *   get:
 *     summary: Debug route to check diagnosis data structure
 *     tags: [Diagnosis, Debug]
 *     security:
 *       - bearerAuth: []
 */
router.get('/:testId/debug',
  param('testId').notEmpty().withMessage('Test ID is required'),
  validateRequest,
  diagnosisController.debugDiagnosisResult
);

/**
 * ✅ FIXED: Test Flask API route now delegates to controller  
 * @swagger
 * /api/diagnosis/{testId}/test-flask-api:
 *   post:
 *     summary: Test Flask API integration and inspect raw response
 *     tags: [Diagnosis, Debug]
 *     security:
 *       - bearerAuth: []
 */
router.post('/:testId/test-flask-api',
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('imagePaths').isArray({ min: 1 }).withMessage('At least one image path is required'),
  body('imagePaths.*').isString().withMessage('Image paths must be strings'),
  validateRequest,
  diagnosisController.testFlaskApi
);

/**
 * ✅ NEW: Get detection details for specific image
 * @swagger
 * /api/diagnosis/{resultId}/detection/{imageId}:
 *   get:
 *     summary: Get enhanced detection details for a specific image
 *     tags: [Diagnosis, Detection]
 *     security:
 *       - bearerAuth: []
 */
router.get('/:resultId/detection/:imageId',
  param('resultId').notEmpty().withMessage('Result ID is required'),
  param('imageId').notEmpty().withMessage('Image ID is required'),
  query('coordinateFormat').optional().isIn(['xyxy', 'xyxyn', 'xywh', 'xywhn']),
  validateRequest,
  diagnosisController.getImageDetectionDetails
);

module.exports = router;
// 📁 server/src/routes/diagnosis.js
const express = require('express');
const { body, param, query } = require('express-validator');
const diagnosisController = require('../controllers/diagnosisController');
const { validateRequest } = require('../middleware/validation');
const { auth,requireAdmin, requireSupervisor, requirePermission } = require('../middleware/auth');


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
 *           enum: [POS, NEG]
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
 *         severity:
 *           type: object
 *           properties:
 *             level:
 *               type: string
 *               enum: [negative, mild, moderate, severe]
 *             confidence:
 *               type: number
 *         detections:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               imageId:
 *                 type: string
 *               parasitesDetected:
 *                 type: array
 *                 items:
 *                   type: object
 *               parasiteCount:
 *                 type: integer
 *               whiteBloodCellsDetected:
 *                 type: integer
 *         totalParasitesDetected:
 *           type: integer
 *         totalWbcDetected:
 *           type: integer
 *         createdAt:
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
 *           enum: [POS, NEG]
 *         overriddenSeverity:
 *           type: string
 *           enum: [negative, mild, moderate, severe]
 *         reviewerConfidence:
 *           type: string
 *           enum: [low, medium, high]
 */

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
 *           enum: [POS, NEG]
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
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     results:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/DiagnosisResult'
 *                     pagination:
 *                       type: object
 */
router.get('/',
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('status').optional().isIn(['POS', 'NEG']),
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
 * /api/diagnosis/{testId}:
 *   get:
 *     summary: Get diagnosis result by test ID
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Diagnosis result retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     result:
 *                       $ref: '#/components/schemas/DiagnosisResult'
 *       404:
 *         description: Diagnosis result not found
 */
router.get('/:testId',
  param('testId').notEmpty().withMessage('Test ID is required'),
  validateRequest,
  diagnosisController.getDiagnosisResultByTestId
);

/**
 * @swagger
 * /api/diagnosis/{testId}/review:
 *   post:
 *     summary: Add manual review to diagnosis result (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ManualReview'
 *     responses:
 *       200:
 *         description: Manual review added successfully
 *       400:
 *         description: Invalid review data
 *       403:
 *         description: Not authorized to review diagnoses
 *       404:
 *         description: Diagnosis result not found
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
    .isIn(['POS', 'NEG'])
    .withMessage('Overridden status must be POS or NEG'),
  body('overriddenSeverity')
    .optional()
    .isIn(['negative', 'mild', 'moderate', 'severe'])
    .withMessage('Overridden severity must be negative, mild, moderate, or severe'),
  body('reviewerConfidence')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Reviewer confidence must be low, medium, or high'),
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
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: imageId
 *         schema:
 *           type: string
 *         description: Specific image ID to retrieve
 *     responses:
 *       200:
 *         description: Images retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     images:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           imageId:
 *                             type: string
 *                           url:
 *                             type: string
 *                           annotations:
 *                             type: array
 *                             items:
 *                               type: object
 *       404:
 *         description: Diagnosis result or images not found
 */
router.get('/:testId/images',
  param('testId').notEmpty().withMessage('Test ID is required'),
  query('imageId').optional().isString(),
  validateRequest,
  diagnosisController.getDiagnosisImages
);

/**
 * @swagger
 * /api/diagnosis/statistics:
 *   get:
 *     summary: Get diagnosis statistics (Supervisor/Admin only)
 *     tags: [Diagnosis]
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
 *       - in: query
 *         name: groupBy
 *         schema:
 *           type: string
 *           enum: [day, week, month]
 *           default: day
 *     responses:
 *       200:
 *         description: Diagnosis statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     overall:
 *                       type: object
 *                       properties:
 *                         totalTests:
 *                           type: integer
 *                         positiveTests:
 *                           type: integer
 *                         negativeTests:
 *                           type: integer
 *                         positiveRate:
 *                           type: number
 *                     parasiteDistribution:
 *                       type: object
 *                     severityDistribution:
 *                       type: object
 *                     trends:
 *                       type: array
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
 *           maximum: 50
 *           default: 20
 *     responses:
 *       200:
 *         description: Results requiring review retrieved successfully
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
 *     parameters:
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [mild, moderate, severe]
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
 *     responses:
 *       200:
 *         description: Positive cases retrieved successfully
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
 * @swagger
 * /api/diagnosis/{testId}/export:
 *   get:
 *     summary: Export diagnosis result as PDF report
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [pdf, json]
 *           default: pdf
 *     responses:
 *       200:
 *         description: Report exported successfully
 *         content:
 *           application/pdf:
 *             schema:
 *               type: string
 *               format: binary
 *           application/json:
 *             schema:
 *               type: object
 *       404:
 *         description: Diagnosis result not found
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
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               hospitalId:
 *                 type: string
 *               departmentId:
 *                 type: string
 *               physicianId:
 *                 type: string
 *               notes:
 *                 type: string
 *     responses:
 *       200:
 *         description: Result sent to hospital successfully
 *       400:
 *         description: Integration error
 *       404:
 *         description: Diagnosis result not found
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
 * /api/diagnosis/batch-export:
 *   post:
 *     summary: Export multiple diagnosis results (Supervisor/Admin only)
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - testIds
 *             properties:
 *               testIds:
 *                 type: array
 *                 items:
 *                   type: string
 *                 maxItems: 100
 *               format:
 *                 type: string
 *                 enum: [pdf, csv, json]
 *                 default: pdf
 *               includeImages:
 *                 type: boolean
 *                 default: false
 *     responses:
 *       200:
 *         description: Batch export initiated successfully
 *         content:
 *           application/zip:
 *             schema:
 *               type: string
 *               format: binary
 *       400:
 *         description: Invalid export parameters
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

/**
 * @swagger
 * /api/diagnosis/{testId}/quality-feedback:
 *   post:
 *     summary: Provide quality feedback on diagnosis result
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
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
 *               - qualityScore
 *               - feedback
 *             properties:
 *               qualityScore:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 5
 *               feedback:
 *                 type: string
 *                 maxLength: 500
 *               imageQualityIssues:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Quality feedback submitted successfully
 *       404:
 *         description: Diagnosis result not found
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
 * @swagger
 * /api/diagnosis/{testId}/debug:
 *   get:
 *     summary: Debug route to check diagnosis data structure
 *     tags: [Diagnosis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *         description: The test ID for the diagnosis to debug
 *     responses:
 *       200:
 *         description: Debug information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 debug:
 *                   type: object
 *                   properties:
 *                     testId:
 *                       type: string
 *                       description: The test ID
 *                     status:
 *                       type: string
 *                       description: Current status of the diagnosis
 *                     detectionsCount:
 *                       type: integer
 *                       description: Number of detections found
 *                     firstDetection:
 *                       type: object
 *                       nullable: true
 *                       properties:
 *                         imageId:
 *                           type: string
 *                           description: ID of the first detected image
 *                         originalFilename:
 *                           type: string
 *                           description: Original filename of the image
 *                         parasiteCount:
 *                           type: integer
 *                           description: Total parasite count in the image
 *                         parasitesDetected:
 *                           type: integer
 *                           description: Number of parasites detected
 *                         firstParasite:
 *                           type: object
 *                           nullable: true
 *                           description: Information about the first parasite detected
 *                 message:
 *                   type: string
 *                   description: Message when no diagnosis result is found
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 error:
 *                   type: string
 */

// Debug endpoint to check data structure
router.get('/:testId/debug', auth, async (req, res) => {
  try {
    const { testId } = req.params;
    
    const DiagnosisResult = require('../models/DiagnosisResult');
    const result = await DiagnosisResult.findOne({ testId: testId.toUpperCase() });
    
    if (!result) {
      return res.json({ success: false, message: 'No diagnosis result found' });
    }
    
    res.json({
      success: true,
      debug: {
        testId: result.testId,
        status: result.status,
        detectionsCount: result.detections?.length || 0,
        firstDetection: result.detections?.[0] ? {
          imageId: result.detections[0].imageId,
          originalFilename: result.detections[0].originalFilename,
          parasiteCount: result.detections[0].parasiteCount,
          parasitesDetected: result.detections[0].parasitesDetected?.length || 0,
          firstParasite: result.detections[0].parasitesDetected?.[0]
        } : null
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
/**
 * @swagger
 * /api/diagnosis/{testId}/test-flask-api:
 *   post:
 *     summary: Test Flask API integration and inspect raw response
 *     description: Debug route to test direct communication with Flask API and examine the raw response structure
 *     tags: [Diagnosis, Debug]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *         description: The test ID for the diagnosis
 *         example: "TEST123"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - imagePaths
 *             properties:
 *               imagePaths:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: Array of image file paths to analyze
 *                 example: ["/uploads/image1.jpg", "/uploads/image2.jpg"]
 *                 minItems: 1
 *           example:
 *             imagePaths: ["/uploads/sample1.jpg", "/uploads/sample2.jpg"]
 *     responses:
 *       200:
 *         description: Flask API test completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 rawFlaskResponse:
 *                   type: object
 *                   description: Complete raw response from Flask API
 *                   properties:
 *                     detections:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           image_id:
 *                             type: string
 *                           original_filename:
 *                             type: string
 *                           parasite_count:
 *                             type: integer
 *                           parasites_detected:
 *                             type: array
 *                             items:
 *                               type: object
 *                   additionalProperties: true
 *                 firstDetection:
 *                   type: object
 *                   nullable: true
 *                   description: First detection object from Flask response for inspection
 *                   properties:
 *                     image_id:
 *                       type: string
 *                       description: ID of the analyzed image
 *                     original_filename:
 *                       type: string
 *                       description: Original filename of the image
 *                     parasite_count:
 *                       type: integer
 *                       description: Total number of parasites detected
 *                     parasites_detected:
 *                       type: array
 *                       description: Array of detected parasites
 *                       items:
 *                         type: object
 *                   additionalProperties: true
 *                 firstParasite:
 *                   type: object
 *                   nullable: true
 *                   description: First parasite detection for detailed inspection
 *                   properties:
 *                     type:
 *                       type: string
 *                       description: Type of parasite detected
 *                     confidence:
 *                       type: number
 *                       description: Confidence score of detection
 *                     coordinates:
 *                       type: object
 *                       description: Bounding box coordinates
 *                   additionalProperties: true
 *       400:
 *         description: Bad request - missing or invalid imagePaths
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "imagePaths array is required"
 *       401:
 *         description: Unauthorized - authentication required
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Authentication required"
 *       500:
 *         description: Internal server error - Flask API communication failed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: "Flask API connection failed"
 *                 stack:
 *                   type: string
 *                   description: Error stack trace for debugging
 *                   example: "Error: connect ECONNREFUSED 127.0.0.1:5001..."
 */

// Also add this route to check what Flask actually returns
router.post('/:testId/test-flask-api', auth, async (req, res) => {
  try {
    const { imagePaths } = req.body;
    
    if (!imagePaths || !Array.isArray(imagePaths)) {
      return res.status(400).json({
        success: false,
        message: 'imagePaths array is required'
      });
    }

    // Call Flask API directly to see raw response
    const diagnosisService = require('../services/diagnosisService');
    const result = await diagnosisService.analyzeSample(imagePaths);

    // Return raw Flask response
    res.json({
      success: true,
      rawFlaskResponse: result,
      // Inspect first detection
      firstDetection: result.detections?.[0],
      firstParasite: result.detections?.[0]?.parasites_detected?.[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

module.exports = router;
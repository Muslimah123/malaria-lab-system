// 📁 server/src/routes/tests.js
const express = require('express');
const { body, param, query } = require('express-validator');
const testController = require('../controllers/testController');
const { validateRequest } = require('../middleware/validation');
const { auth } = require('../middleware/auth');
const authController = require('../controllers/authController');

const router = express.Router();

// All test routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     Test:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *         testId:
 *           type: string
 *           example: "TEST-20250531-001"
 *         patientId:
 *           type: string
 *           example: "PAT-20250531-001"
 *         status:
 *           type: string
 *           enum: [pending, processing, completed, failed, cancelled]
 *         priority:
 *           type: string
 *           enum: [low, normal, high, urgent]
 *         sampleType:
 *           type: string
 *           enum: [blood_smear, thick_smear, thin_smear]
 *         images:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               filename:
 *                 type: string
 *               originalName:
 *                 type: string
 *               size:
 *                 type: number
 *               uploadedAt:
 *                 type: string
 *                 format: date-time
 *         technician:
 *           $ref: '#/components/schemas/User'
 *         createdAt:
 *           type: string
 *           format: date-time
 *     CreateTestRequest:
 *       type: object
 *       required:
 *         - patientId
 *       properties:
 *         patientId:
 *           type: string
 *           example: "PAT-20250531-001"
 *         priority:
 *           type: string
 *           enum: [low, normal, high, urgent]
 *           default: normal
 *         sampleType:
 *           type: string
 *           enum: [blood_smear, thick_smear, thin_smear]
 *           default: blood_smear
 *         clinicalNotes:
 *           type: object
 *           properties:
 *             symptoms:
 *               type: array
 *               items:
 *                 type: string
 *             duration:
 *               type: string
 *             severity:
 *               type: string
 *             previousTreatment:
 *               type: string
 *             additionalNotes:
 *               type: string
 */

// Validation schemas
const createTestValidation = [
  body('patientId')
    .notEmpty()
    .isLength({ min: 3, max: 50 })
    .withMessage('Patient ID is required and must be 3-50 characters'),
  body('priority')
    .optional()
    .isIn(['low', 'normal', 'high', 'urgent'])
    .withMessage('Priority must be low, normal, high, or urgent'),
  body('sampleType')
    .optional()
    .isIn(['blood_smear', 'thick_smear', 'thin_smear'])
    .withMessage('Sample type must be blood_smear, thick_smear, or thin_smear'),
  body('clinicalNotes.symptoms')
    .optional()
    .isArray()
    .withMessage('Symptoms must be an array'),
  body('clinicalNotes.duration')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('Duration must be a string less than 200 characters'),
  body('clinicalNotes.severity')
    .optional()
    .isString()
    .isLength({ max: 50 })
    .withMessage('Severity must be a string less than 50 characters')
];

const updateTestValidation = [
  param('testId')
    .notEmpty()
    .withMessage('Test ID is required'),
  body('priority')
    .optional()
    .isIn(['low', 'normal', 'high', 'urgent'])
    .withMessage('Priority must be low, normal, high, or urgent'),
  body('status')
    .optional()
    .isIn(['pending', 'processing', 'completed', 'failed', 'cancelled'])
    .withMessage('Status must be pending, processing, completed, failed, or cancelled'),
  body('clinicalNotes')
    .optional()
    .isObject()
    .withMessage('Clinical notes must be an object')
];

const testQueryValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('status')
    .optional()
    .isIn(['pending', 'processing', 'completed', 'failed', 'cancelled'])
    .withMessage('Status must be a valid test status'),
  query('priority')
    .optional()
    .isIn(['low', 'normal', 'high', 'urgent'])
    .withMessage('Priority must be a valid priority level'),
  query('patientId')
    .optional()
    .isString()
    .withMessage('Patient ID must be a string'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO date')
];

/**
 * @swagger
 * /api/tests:
 *   get:
 *     summary: Get all tests with filtering and pagination
 *     tags: [Tests]
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
 *           enum: [pending, processing, completed, failed, cancelled]
 *       - in: query
 *         name: priority
 *         schema:
 *           type: string
 *           enum: [low, normal, high, urgent]
 *       - in: query
 *         name: patientId
 *         schema:
 *           type: string
 *       - in: query
 *         name: technicianId
 *         schema:
 *           type: string
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
 *         description: Tests retrieved successfully
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
 *                     tests:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Test'
 *                     pagination:
 *                       type: object
 *                       properties:
 *                         page:
 *                           type: integer
 *                         limit:
 *                           type: integer
 *                         total:
 *                           type: integer
 *                         pages:
 *                           type: integer
 */
router.get('/',
  testQueryValidation,
  validateRequest,
  testController.getAllTests
);

/**
 * @swagger
 * /api/tests:
 *   post:
 *     summary: Create a new test
 *     tags: [Tests]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateTestRequest'
 *     responses:
 *       201:
 *         description: Test created successfully
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
 *                     test:
 *                       $ref: '#/components/schemas/Test'
 *       400:
 *         description: Invalid input data
 *       404:
 *         description: Patient not found
 */
router.post('/',
  authController.requirePermission('canUploadSamples'),
  createTestValidation,
  validateRequest,
  testController.createTest
);

/**
 * @swagger
 * /api/tests/{testId}:
 *   get:
 *     summary: Get test by ID
 *     tags: [Tests]
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
 *         description: Test retrieved successfully
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
 *                     test:
 *                       $ref: '#/components/schemas/Test'
 *       404:
 *         description: Test not found
 */
router.get('/:testId',
  param('testId').notEmpty().withMessage('Test ID is required'),
  validateRequest,
  testController.getTestById
);

/**
 * @swagger
 * /api/tests/{testId}:
 *   put:
 *     summary: Update test
 *     tags: [Tests]
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
 *             properties:
 *               priority:
 *                 type: string
 *                 enum: [low, normal, high, urgent]
 *               status:
 *                 type: string
 *                 enum: [pending, processing, completed, failed, cancelled]
 *               clinicalNotes:
 *                 type: object
 *     responses:
 *       200:
 *         description: Test updated successfully
 *       400:
 *         description: Invalid input data
 *       403:
 *         description: Not authorized to update this test
 *       404:
 *         description: Test not found
 */
router.put('/:testId',
  updateTestValidation,
  validateRequest,
  testController.updateTest
);

/**
 * @swagger
 * /api/tests/{testId}:
 *   delete:
 *     summary: Delete test (Admin/Supervisor only)
 *     tags: [Tests]
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
 *         description: Test deleted successfully
 *       403:
 *         description: Not authorized to delete this test
 *       404:
 *         description: Test not found
 */
router.delete('/:testId',
  param('testId').notEmpty().withMessage('Test ID is required'),
  validateRequest,
  testController.deleteTest
);

/**
 * @swagger
 * /api/tests/{testId}/status:
 *   patch:
 *     summary: Update test status
 *     tags: [Tests]
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
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [pending, processing, completed, failed, cancelled]
 *               notes:
 *                 type: string
 *     responses:
 *       200:
 *         description: Test status updated successfully
 *       400:
 *         description: Invalid status
 *       404:
 *         description: Test not found
 */
router.patch('/:testId/status',
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('status')
    .isIn(['pending', 'processing', 'completed', 'failed', 'cancelled'])
    .withMessage('Status must be a valid test status'),
  body('notes')
    .optional()
    .isString()
    .isLength({ max: 500 })
    .withMessage('Notes must be a string less than 500 characters'),
  validateRequest,
  testController.updateTestStatus
);

/**
 * @swagger
 * /api/tests/patient/{patientId}:
 *   get:
 *     summary: Get all tests for a specific patient
 *     tags: [Tests]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
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
 *         description: Patient tests retrieved successfully
 *       404:
 *         description: Patient not found
 */
router.get('/patient/:patientId',
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  validateRequest,
  testController.getTestsByPatient
);

/**
 * @swagger
 * /api/tests/technician/my-tests:
 *   get:
 *     summary: Get tests assigned to current technician
 *     tags: [Tests]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, processing, completed, failed, cancelled]
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
 *         description: Technician tests retrieved successfully
 */
router.get('/technician/my-tests',
  query('status').optional().isIn(['pending', 'processing', 'completed', 'failed', 'cancelled']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  validateRequest,
  testController.getMyTests
);

/**
 * @swagger
 * /api/tests/statistics:
 *   get:
 *     summary: Get test statistics
 *     tags: [Tests]
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
 *         name: technicianId
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Test statistics retrieved successfully
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
 *                     totalTests:
 *                       type: integer
 *                     pendingTests:
 *                       type: integer
 *                     processingTests:
 *                       type: integer
 *                     completedTests:
 *                       type: integer
 *                     failedTests:
 *                       type: integer
 *                     avgProcessingTime:
 *                       type: number
 */
router.get('/statistics',
  authController.requireSupervisor,
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  query('technicianId').optional().isString(),
  validateRequest,
  testController.getTestStatistics
);

/**
 * @swagger
 * /api/tests/{testId}/assign:
 *   patch:
 *     summary: Assign test to technician (Supervisor/Admin only)
 *     tags: [Tests]
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
 *               - technicianId
 *             properties:
 *               technicianId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Test assigned successfully
 *       403:
 *         description: Not authorized to assign tests
 *       404:
 *         description: Test or technician not found
 */
router.patch('/:testId/assign',
  authController.requireSupervisor,
  param('testId').notEmpty().withMessage('Test ID is required'),
  body('technicianId').notEmpty().withMessage('Technician ID is required'),
  validateRequest,
  testController.assignTest
);

/**
 * @swagger
 * /api/tests/pending:
 *   get:
 *     summary: Get all pending tests (Supervisor/Admin only)
 *     tags: [Tests]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: priority
 *         schema:
 *           type: string
 *           enum: [low, normal, high, urgent]
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
 *         description: Pending tests retrieved successfully
 */
router.get('/pending',
  authController.requireSupervisor,
  query('priority').optional().isIn(['low', 'normal', 'high', 'urgent']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  validateRequest,
  testController.getPendingTests
);

module.exports = router;
// 📁 server/src/routes/patients.js
const express = require('express');
const { body, param, query } = require('express-validator');
const patientController = require('../controllers/patientController');
const { validateRequest } = require('../middleware/validation');
const { auth } = require('../middleware/auth');
const authController = require('../controllers/authController');

const router = express.Router();

// All patient routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     Patient:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *         patientId:
 *           type: string
 *           example: "PAT-20250531-001"
 *         firstName:
 *           type: string
 *           example: "John"
 *         lastName:
 *           type: string
 *           example: "Doe"
 *         dateOfBirth:
 *           type: string
 *           format: date
 *         gender:
 *           type: string
 *           enum: [male, female, other, unknown]
 *         age:
 *           type: integer
 *           minimum: 0
 *           maximum: 150
 *         phoneNumber:
 *           type: string
 *         email:
 *           type: string
 *           format: email
 *         address:
 *           type: object
 *           properties:
 *             street:
 *               type: string
 *             city:
 *               type: string
 *             state:
 *               type: string
 *             zipCode:
 *               type: string
 *             country:
 *               type: string
 *         bloodType:
 *           type: string
 *           enum: [A+, A-, B+, B-, AB+, AB-, O+, O-, unknown]
 *         totalTests:
 *           type: integer
 *         positiveTests:
 *           type: integer
 *         lastTestDate:
 *           type: string
 *           format: date-time
 *         lastTestResult:
 *           type: string
 *           enum: [POS, NEG]
 *         createdAt:
 *           type: string
 *           format: date-time
 *     CreatePatientRequest:
 *       type: object
 *       properties:
 *         patientId:
 *           type: string
 *           description: "Optional - will be auto-generated if not provided"
 *         firstName:
 *           type: string
 *           maxLength: 50
 *         lastName:
 *           type: string
 *           maxLength: 50
 *         dateOfBirth:
 *           type: string
 *           format: date
 *         gender:
 *           type: string
 *           enum: [male, female, other, unknown]
 *         age:
 *           type: integer
 *           minimum: 0
 *           maximum: 150
 *         phoneNumber:
 *           type: string
 *         email:
 *           type: string
 *           format: email
 *         address:
 *           type: object
 *         bloodType:
 *           type: string
 *           enum: [A+, A-, B+, B-, AB+, AB-, O+, O-, unknown]
 *         allergies:
 *           type: array
 *           items:
 *             type: string
 *         emergencyContact:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *             relationship:
 *               type: string
 *             phoneNumber:
 *               type: string
 */

// Validation schemas
const createPatientValidation = [
  body('patientId')
    .optional()
    .isLength({ min: 3, max: 50 })
    .matches(/^[A-Z0-9-_]+$/)
    .withMessage('Patient ID must be 3-50 characters and contain only uppercase letters, numbers, hyphens, and underscores'),
  body('firstName')
    .optional()
    .isLength({ max: 50 })
    .trim()
    .withMessage('First name must be less than 50 characters'),
  body('lastName')
    .optional()
    .isLength({ max: 50 })
    .trim()
    .withMessage('Last name must be less than 50 characters'),
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Date of birth must be a valid date'),
  body('gender')
    .optional()
    .isIn(['male', 'female', 'other', 'unknown'])
    .withMessage('Gender must be male, female, other, or unknown'),
  body('age')
    .optional()
    .isInt({ min: 0, max: 150 })
    .withMessage('Age must be between 0 and 150'),
  body('phoneNumber')
    .optional()
    .isMobilePhone()
    .withMessage('Phone number must be a valid mobile number'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Email must be valid'),
  body('bloodType')
    .optional()
    .isIn(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'unknown'])
    .withMessage('Blood type must be valid'),
  body('allergies')
    .optional()
    .isArray()
    .withMessage('Allergies must be an array'),
  body('emergencyContact.phoneNumber')
    .optional()
    .isMobilePhone()
    .withMessage('Emergency contact phone must be valid')
];

const updatePatientValidation = [
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  ...createPatientValidation
];

const patientQueryValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('search')
    .optional()
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Search term must be 1-100 characters'),
  query('gender')
    .optional()
    .isIn(['male', 'female', 'other', 'unknown'])
    .withMessage('Gender filter must be valid'),
  query('bloodType')
    .optional()
    .isIn(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'unknown'])
    .withMessage('Blood type filter must be valid'),
  query('hasPositiveTests')
    .optional()
    .isBoolean()
    .withMessage('Has positive tests must be boolean'),
  query('sortBy')
    .optional()
    .isIn(['patientId', 'firstName', 'lastName', 'lastTestDate', 'totalTests', 'createdAt'])
    .withMessage('Sort by field must be valid'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc')
];

/**
 * @swagger
 * /api/patients:
 *   get:
 *     summary: Get all patients with filtering and pagination
 *     tags: [Patients]
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
 *         name: search
 *         schema:
 *           type: string
 *         description: Search by patient ID, name, or phone number
 *       - in: query
 *         name: gender
 *         schema:
 *           type: string
 *           enum: [male, female, other, unknown]
 *       - in: query
 *         name: bloodType
 *         schema:
 *           type: string
 *           enum: [A+, A-, B+, B-, AB+, AB-, O+, O-, unknown]
 *       - in: query
 *         name: hasPositiveTests
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [patientId, firstName, lastName, lastTestDate, totalTests, createdAt]
 *           default: createdAt
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *     responses:
 *       200:
 *         description: Patients retrieved successfully
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
 *                     patients:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Patient'
 *                     pagination:
 *                       type: object
 */
router.get('/',
  patientQueryValidation,
  validateRequest,
  patientController.getAllPatients
);

/**
 * @swagger
 * /api/patients:
 *   post:
 *     summary: Create a new patient
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreatePatientRequest'
 *     responses:
 *       201:
 *         description: Patient created successfully
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
 *                     patient:
 *                       $ref: '#/components/schemas/Patient'
 *       400:
 *         description: Invalid input data
 *       409:
 *         description: Patient ID already exists
 */
router.post('/',
  createPatientValidation,
  validateRequest,
  patientController.createPatient
);

/**
 * @swagger
 * /api/patients/{patientId}:
 *   get:
 *     summary: Get patient by ID
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Patient retrieved successfully
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
 *                     patient:
 *                       $ref: '#/components/schemas/Patient'
 *       404:
 *         description: Patient not found
 */
router.get('/:patientId',
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  validateRequest,
  patientController.getPatientById
);

/**
 * @swagger
 * /api/patients/{patientId}:
 *   put:
 *     summary: Update patient information
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreatePatientRequest'
 *     responses:
 *       200:
 *         description: Patient updated successfully
 *       400:
 *         description: Invalid input data
 *       404:
 *         description: Patient not found
 */
router.put('/:patientId',
  updatePatientValidation,
  validateRequest,
  patientController.updatePatient
);

/**
 * @swagger
 * /api/patients/{patientId}:
 *   delete:
 *     summary: Delete patient (Admin only)
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Patient deleted successfully
 *       403:
 *         description: Not authorized to delete patients
 *       404:
 *         description: Patient not found
 */
router.delete('/:patientId',
  authController.requireAdmin,
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  validateRequest,
  patientController.deletePatient
);

/**
 * @swagger
 * /api/patients/{patientId}/tests:
 *   get:
 *     summary: Get all tests for a specific patient
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
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
 *           default: 10
 *     responses:
 *       200:
 *         description: Patient tests retrieved successfully
 *       404:
 *         description: Patient not found
 */
router.get('/:patientId/tests',
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  query('status').optional().isIn(['pending', 'processing', 'completed', 'failed', 'cancelled']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  validateRequest,
  patientController.getPatientTests
);

/**
 * @swagger
 * /api/patients/{patientId}/history:
 *   get:
 *     summary: Get patient medical history and test results
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: includeNegativeResults
 *         schema:
 *           type: boolean
 *           default: true
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
 *         description: Patient history retrieved successfully
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
 *                     patient:
 *                       $ref: '#/components/schemas/Patient'
 *                     testHistory:
 *                       type: array
 *                     diagnosisHistory:
 *                       type: array
 *                     statistics:
 *                       type: object
 *       404:
 *         description: Patient not found
 */
router.get('/:patientId/history',
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  query('includeNegativeResults').optional().isBoolean(),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  validateRequest,
  patientController.getPatientHistory
);

/**
 * @swagger
 * /api/patients/search:
 *   get:
 *     summary: Search patients by various criteria
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *           minLength: 2
 *         description: Search query (patient ID, name, phone, email)
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *     responses:
 *       200:
 *         description: Search results retrieved successfully
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
 *                     patients:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Patient'
 *                     totalResults:
 *                       type: integer
 *       400:
 *         description: Invalid search query
 */
router.get('/search',
  query('q')
    .notEmpty()
    .isLength({ min: 2, max: 100 })
    .withMessage('Search query must be 2-100 characters'),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  validateRequest,
  patientController.searchPatients
);

/**
 * @swagger
 * /api/patients/statistics:
 *   get:
 *     summary: Get patient statistics (Supervisor/Admin only)
 *     tags: [Patients]
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
 *         description: Patient statistics retrieved successfully
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
 *                     totalPatients:
 *                       type: integer
 *                     patientsWithTests:
 *                       type: integer
 *                     patientsWithPositiveResults:
 *                       type: integer
 *                     averageAge:
 *                       type: number
 *                     genderDistribution:
 *                       type: object
 *                     bloodTypeDistribution:
 *                       type: object
 */
router.get('/statistics',
  authController.requireSupervisor,
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  validateRequest,
  patientController.getPatientStatistics
);

/**
 * @swagger
 * /api/patients/{patientId}/export:
 *   get:
 *     summary: Export patient data and test history
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: patientId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [pdf, json, csv]
 *           default: pdf
 *       - in: query
 *         name: includeTestImages
 *         schema:
 *           type: boolean
 *           default: false
 *     responses:
 *       200:
 *         description: Patient data exported successfully
 *         content:
 *           application/pdf:
 *             schema:
 *               type: string
 *               format: binary
 *           application/json:
 *             schema:
 *               type: object
 *           text/csv:
 *             schema:
 *               type: string
 *       404:
 *         description: Patient not found
 */
router.get('/:patientId/export',
  authController.requirePermission('canExportReports'),
  param('patientId').notEmpty().withMessage('Patient ID is required'),
  query('format').optional().isIn(['pdf', 'json', 'csv']),
  query('includeTestImages').optional().isBoolean(),
  validateRequest,
  patientController.exportPatientData
);

/**
 * @swagger
 * /api/patients/bulk-import:
 *   post:
 *     summary: Bulk import patients from CSV (Admin only)
 *     tags: [Patients]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *                 description: CSV file with patient data
 *               validateOnly:
 *                 type: boolean
 *                 default: false
 *                 description: Only validate data without importing
 *     responses:
 *       200:
 *         description: Bulk import completed successfully
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
 *                     imported:
 *                       type: integer
 *                     failed:
 *                       type: integer
 *                     errors:
 *                       type: array
 *       400:
 *         description: Invalid CSV file
 */
router.post('/bulk-import',
  authController.requireAdmin,
  patientController.bulkImportPatients
);

module.exports = router;
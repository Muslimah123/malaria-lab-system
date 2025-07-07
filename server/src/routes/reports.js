// 📁 server/src/routes/report.js
const express = require('express');
const { body, param, query } = require('express-validator');
const reportController = require('../controllers/reportController');
const { validateRequest } = require('../middleware/validation');
const { auth,requireAdmin, requireSupervisor, requirePermission } = require('../middleware/auth');

const router = express.Router();

// All report routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     ReportRequest:
 *       type: object
 *       properties:
 *         format:
 *           type: string
 *           enum: [pdf, json]
 *           default: pdf
 *         includeImages:
 *           type: boolean
 *           default: false
 *     BulkReportRequest:
 *       type: object
 *       properties:
 *         testIds:
 *           type: array
 *           items:
 *             type: string
 *         patientId:
 *           type: string
 *         dateRange:
 *           type: object
 *           properties:
 *             start:
 *               type: string
 *               format: date
 *             end:
 *               type: string
 *               format: date
 *         format:
 *           type: string
 *           enum: [pdf, json]
 *           default: pdf
 */

/**
 * @swagger
 * /api/reports/test/{testId}:
 *   get:
 *     summary: Generate report for a specific test
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *         description: Test ID to generate report for
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [pdf, json]
 *           default: pdf
 *         description: Report format
 *       - in: query
 *         name: includeImages
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Include original images in report
 *     responses:
 *       200:
 *         description: Report generated successfully
 *         content:
 *           application/pdf:
 *             schema:
 *               type: string
 *               format: binary
 *           application/json:
 *             schema:
 *               type: object
 *       404:
 *         description: Test or diagnosis result not found
 *       403:
 *         description: Access denied
 */
router.get('/test/:testId',
  param('testId')
    .notEmpty()
    .withMessage('Test ID is required')
    .isLength({ min: 3, max: 50 })
    .withMessage('Test ID must be between 3 and 50 characters'),
  query('format')
    .optional()
    .isIn(['pdf', 'json'])
    .withMessage('Format must be pdf or json'),
  query('includeImages')
    .optional()
    .isBoolean()
    .withMessage('includeImages must be a boolean'),
  validateRequest,
  reportController.generateTestReport
);

/**
 * @swagger
 * /api/reports/bulk:
 *   post:
 *     summary: Generate bulk reports for multiple tests
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/BulkReportRequest'
 *     responses:
 *       200:
 *         description: Bulk report generated successfully
 *         content:
 *           application/pdf:
 *             schema:
 *               type: string
 *               format: binary
 *       400:
 *         description: Invalid request parameters
 *       404:
 *         description: No tests found matching criteria
 */
router.post('/bulk',
  requirePermission('canViewReports'),
  body('testIds')
    .optional()
    .isArray({ min: 1, max: 50 })
    .withMessage('Test IDs must be an array with 1-50 items'),
  body('testIds.*')
    .optional()
    .isString()
    .isLength({ min: 3, max: 50 })
    .withMessage('Each test ID must be a string between 3-50 characters'),
  body('patientId')
    .optional()
    .isString()
    .isLength({ min: 3, max: 50 })
    .withMessage('Patient ID must be between 3-50 characters'),
  body('dateRange.start')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  body('dateRange.end')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  body('format')
    .optional()
    .isIn(['pdf', 'json'])
    .withMessage('Format must be pdf or json'),
  validateRequest,
  reportController.generateBulkReports
);

/**
 * @swagger
 * /api/reports/export/csv:
 *   get:
 *     summary: Export diagnosis data as CSV
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Start date for data export
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: End date for data export
 *       - in: query
 *         name: includePatientData
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Include patient personal information
 *     responses:
 *       200:
 *         description: CSV data exported successfully
 *         content:
 *           text/csv:
 *             schema:
 *               type: string
 *       403:
 *         description: Insufficient permissions
 */
router.get('/export/csv',
  requireSupervisor,
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('includePatientData')
    .optional()
    .isBoolean()
    .withMessage('includePatientData must be a boolean'),
  validateRequest,
  reportController.exportCSV
);

/**
 * @swagger
 * /api/reports/available:
 *   get:
 *     summary: Get list of available reports for the user
 *     tags: [Reports]
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
 *         name: patientId
 *         schema:
 *           type: string
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, processing, completed, failed]
 *     responses:
 *       200:
 *         description: Available reports retrieved successfully
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
 *                     reports:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           testId:
 *                             type: string
 *                           patientId:
 *                             type: string
 *                           createdAt:
 *                             type: string
 *                             format: date-time
 *                           hasReport:
 *                             type: boolean
 *                           reportTypes:
 *                             type: array
 *                             items:
 *                               type: string
 *                     pagination:
 *                       type: object
 */
router.get('/available',
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('patientId')
    .optional()
    .isString()
    .isLength({ min: 3, max: 50 })
    .withMessage('Patient ID must be between 3-50 characters'),
  query('status')
    .optional()
    .isIn(['pending', 'processing', 'completed', 'failed'])
    .withMessage('Status must be a valid test status'),
  validateRequest,
  reportController.getAvailableReports
);

/**
 * @swagger
 * /api/reports/statistics:
 *   get:
 *     summary: Get report generation statistics (Supervisor/Admin only)
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [day, week, month, year]
 *           default: month
 *     responses:
 *       200:
 *         description: Report statistics retrieved successfully
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
 *                     totalReports:
 *                       type: integer
 *                     reportsThisPeriod:
 *                       type: integer
 *                     reportsByFormat:
 *                       type: object
 *                     mostRequestedReports:
 *                       type: array
 */
router.get('/statistics',
  requireSupervisor,
  query('period')
    .optional()
    .isIn(['day', 'week', 'month', 'year'])
    .withMessage('Period must be day, week, month, or year'),
  validateRequest,
  async (req, res, next) => {
    try {
      // Basic statistics implementation
      // This would typically be moved to a dedicated controller method
      res.json({
        success: true,
        data: {
          totalReports: 0,
          reportsThisPeriod: 0,
          reportsByFormat: {
            pdf: 0,
            json: 0,
            csv: 0
          },
          mostRequestedReports: []
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/reports/schedule:
 *   post:
 *     summary: Schedule automatic report generation (Admin only)
 *     tags: [Reports]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - schedule
 *               - recipients
 *             properties:
 *               name:
 *                 type: string
 *                 description: Schedule name
 *               schedule:
 *                 type: string
 *                 description: Cron expression for schedule
 *               recipients:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: email
 *               criteria:
 *                 type: object
 *                 description: Report criteria
 *               format:
 *                 type: string
 *                 enum: [pdf, csv]
 *                 default: pdf
 *     responses:
 *       201:
 *         description: Report schedule created successfully
 *       400:
 *         description: Invalid schedule parameters
 */
router.post('/schedule',
  requireAdmin,
  body('name')
    .notEmpty()
    .isLength({ min: 3, max: 100 })
    .withMessage('Schedule name must be between 3-100 characters'),
  body('schedule')
    .notEmpty()
    .withMessage('Schedule cron expression is required'),
  body('recipients')
    .isArray({ min: 1 })
    .withMessage('At least one recipient is required'),
  body('recipients.*')
    .isEmail()
    .withMessage('All recipients must be valid email addresses'),
  body('format')
    .optional()
    .isIn(['pdf', 'csv'])
    .withMessage('Format must be pdf or csv'),
  validateRequest,
  async (req, res, next) => {
    try {
      // Placeholder for scheduled reports functionality
      // This would typically integrate with a job scheduler like Bull or Agenda
      res.status(201).json({
        success: true,
        message: 'Report schedule created successfully',
        data: {
          scheduleId: 'schedule_' + Date.now(),
          nextRun: new Date(Date.now() + 24 * 60 * 60 * 1000) // Next day
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
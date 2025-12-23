// 📁 server/src/routes/integration.js
const express = require('express');
const { body, param, query } = require('express-validator');
const integrationController = require('../controllers/integrationController');
const { validateRequest } = require('../middleware/validation');
const { auth, requireAdmin, requireSupervisor, requirePermission } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// All integration routes require authentication
router.use(auth);

/**
 * @swagger
 * /api/integration/sync/{testId}:
 *   post:
 *     summary: Sync single test result with hospital system
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: testId
 *         required: true
 *         schema:
 *           type: string
 *         description: Test ID to sync
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               system:
 *                 type: string
 *                 enum: [api, hl7, fhir]
 *                 default: api
 *               priority:
 *                 type: string
 *                 enum: [low, normal, high, urgent]
 *                 default: normal
 *     responses:
 *       200:
 *         description: Test result synced successfully
 *       404:
 *         description: Test not found or not completed
 *       403:
 *         description: Insufficient permissions
 */
router.post('/sync/:testId',
  requirePermission('canSyncResults'),
  param('testId')
    .notEmpty()
    .withMessage('Test ID is required')
    .isLength({ min: 3, max: 50 })
    .withMessage('Test ID must be between 3 and 50 characters'),
  body('system')
    .optional()
    .isIn(['api', 'hl7', 'fhir'])
    .withMessage('System must be api, hl7, or fhir'),
  body('priority')
    .optional()
    .isIn(['low', 'normal', 'high', 'urgent'])
    .withMessage('Priority must be low, normal, high, or urgent'),
  validateRequest,
  integrationController.syncTestResult
);

/**
 * @swagger
 * /api/integration/bulk-sync:
 *   post:
 *     summary: Bulk sync multiple test results (Supervisor/Admin only)
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               testIds:
 *                 type: array
 *                 items:
 *                   type: string
 *               dateRange:
 *                 type: object
 *                 properties:
 *                   start:
 *                     type: string
 *                     format: date
 *                   end:
 *                     type: string
 *                     format: date
 *               system:
 *                 type: string
 *                 enum: [api, hl7, fhir]
 *                 default: api
 *               priority:
 *                 type: string
 *                 enum: [low, normal, high, urgent]
 *                 default: normal
 *     responses:
 *       200:
 *         description: Bulk sync completed
 *       404:
 *         description: No tests found matching criteria
 */
router.post('/bulk-sync',
  requireSupervisor,
  body('testIds')
    .optional()
    .isArray({ min: 1, max: 50 })
    .withMessage('Test IDs must be an array with 1-50 items'),
  body('testIds.*')
    .optional()
    .isString()
    .isLength({ min: 3, max: 50 })
    .withMessage('Each test ID must be a string between 3-50 characters'),
  body('dateRange.start')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  body('dateRange.end')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  body('system')
    .optional()
    .isIn(['api', 'hl7', 'fhir'])
    .withMessage('System must be api, hl7, or fhir'),
  body('priority')
    .optional()
    .isIn(['low', 'normal', 'high', 'urgent'])
    .withMessage('Priority must be low, normal, high, or urgent'),
  validateRequest,
  integrationController.bulkSyncResults
);

/**
 * @swagger
 * /api/integration/status:
 *   get:
 *     summary: Get sync status for tests
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: testIds
 *         schema:
 *           type: string
 *         description: Comma-separated list of test IDs
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
 *         name: status
 *         schema:
 *           type: string
 *           enum: [synced, pending, failed, not_synced]
 *     responses:
 *       200:
 *         description: Sync status retrieved successfully
 */
router.get('/status',
  query('testIds')
    .optional()
    .isString()
    .withMessage('Test IDs must be a comma-separated string'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('status')
    .optional()
    .isIn(['synced', 'pending', 'failed', 'not_synced'])
    .withMessage('Status must be synced, pending, failed, or not_synced'),
  validateRequest,
  integrationController.getSyncStatus
);

/**
 * @swagger
 * /api/integration/configure:
 *   post:
 *     summary: Configure integration settings (Admin only)
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - hospitalEndpoint
 *               - authMethod
 *             properties:
 *               hospitalEndpoint:
 *                 type: string
 *                 format: uri
 *               authMethod:
 *                 type: string
 *                 enum: [bearer, basic, apikey, oauth2]
 *               credentials:
 *                 type: object
 *               syncSchedule:
 *                 type: string
 *               autoSync:
 *                 type: boolean
 *                 default: false
 *               retrySettings:
 *                 type: object
 *                 properties:
 *                   maxAttempts:
 *                     type: integer
 *                     minimum: 1
 *                     maximum: 10
 *                   backoffMultiplier:
 *                     type: number
 *                     minimum: 1
 *     responses:
 *       200:
 *         description: Integration settings configured successfully
 *       400:
 *         description: Invalid configuration or connection test failed
 */
router.post('/configure',
  requireAdmin,
  body('hospitalEndpoint')
    .notEmpty()
    .withMessage('Hospital endpoint is required')
    .isURL()
    .withMessage('Hospital endpoint must be a valid URL'),
  body('authMethod')
    .notEmpty()
    .withMessage('Authentication method is required')
    .isIn(['bearer', 'basic', 'apikey', 'oauth2'])
    .withMessage('Auth method must be bearer, basic, apikey, or oauth2'),
  body('credentials')
    .optional()
    .isObject()
    .withMessage('Credentials must be an object'),
  body('syncSchedule')
    .optional()
    .isString()
    .withMessage('Sync schedule must be a valid cron expression'),
  body('autoSync')
    .optional()
    .isBoolean()
    .withMessage('Auto sync must be a boolean'),
  body('retrySettings.maxAttempts')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Max attempts must be between 1 and 10'),
  body('retrySettings.backoffMultiplier')
    .optional()
    .isFloat({ min: 1 })
    .withMessage('Backoff multiplier must be at least 1'),
  validateRequest,
  integrationController.configureIntegration
);

/**
 * @swagger
 * /api/integration/health:
 *   get:
 *     summary: Get integration status and health
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Integration status retrieved successfully
 */
router.get('/health',
  requirePermission('canViewIntegration'),
  integrationController.getIntegrationStatus
);

/**
 * @swagger
 * /api/integration/retry-failed:
 *   post:
 *     summary: Retry failed sync operations (Supervisor/Admin only)
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               testIds:
 *                 type: array
 *                 items:
 *                   type: string
 *               maxRetries:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 10
 *                 default: 3
 *     responses:
 *       200:
 *         description: Retry operation completed
 *       404:
 *         description: No failed tests found that can be retried
 */
router.post('/retry-failed',
  requireSupervisor,
  body('testIds')
    .optional()
    .isArray()
    .withMessage('Test IDs must be an array'),
  body('testIds.*')
    .optional()
    .isString()
    .isLength({ min: 3, max: 50 })
    .withMessage('Each test ID must be a string between 3-50 characters'),
  body('maxRetries')
    .optional()
    .isInt({ min: 1, max: 10 })
    .withMessage('Max retries must be between 1 and 10'),
  validateRequest,
  integrationController.retryFailedSyncs
);

/**
 * @swagger
 * /api/integration/test-connection:
 *   post:
 *     summary: Test connection to hospital system (Admin only)
 *     tags: [Integration]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               endpoint:
 *                 type: string
 *                 format: uri
 *               authMethod:
 *                 type: string
 *                 enum: [bearer, basic, apikey, oauth2]
 *               credentials:
 *                 type: object
 *     responses:
 *       200:
 *         description: Connection test results
 */
router.post('/test-connection',
  requireAdmin,
  body('endpoint')
    .optional()
    .isURL()
    .withMessage('Endpoint must be a valid URL'),
  body('authMethod')
    .optional()
    .isIn(['bearer', 'basic', 'apikey', 'oauth2'])
    .withMessage('Auth method must be bearer, basic, apikey, or oauth2'),
  body('credentials')
    .optional()
    .isObject()
    .withMessage('Credentials must be an object'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { endpoint, authMethod, credentials } = req.body;
      
      const testResult = await integrationController.testHospitalConnection(
        endpoint,
        authMethod,
        credentials
      );
      
      res.json({
        success: true,
        data: {
          connectionStatus: testResult.success ? 'connected' : 'failed',
          responseTime: testResult.responseTime,
          details: testResult.results || { error: testResult.error },
          timestamp: new Date()
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/integration/webhook:
 *   post:
 *     summary: Receive webhook notifications from hospital system
 *     tags: [Integration]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *               data:
 *                 type: object
 *               timestamp:
 *                 type: string
 *                 format: date-time
 *               signature:
 *                 type: string
 *     responses:
 *       200:
 *         description: Webhook processed successfully
 *       400:
 *         description: Invalid webhook payload
 *       401:
 *         description: Invalid webhook signature
 */
router.post('/webhook',
  body('type')
    .notEmpty()
    .withMessage('Webhook type is required'),
  body('data')
    .notEmpty()
    .withMessage('Webhook data is required'),
  body('timestamp')
    .optional()
    .isISO8601()
    .withMessage('Timestamp must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { type, data, timestamp, signature } = req.body;
      
      // Verify webhook signature if configured
      if (process.env.WEBHOOK_SECRET && signature) {
        const crypto = require('crypto');
        const expectedSignature = crypto
          .createHmac('sha256', process.env.WEBHOOK_SECRET)
          .update(JSON.stringify(req.body))
          .digest('hex');
          
        if (signature !== expectedSignature) {
          return res.status(401).json({
            success: false,
            message: 'Invalid webhook signature'
          });
        }
      }
      
      // Process webhook based on type
      switch (type) {
        case 'sync_confirmation':
          // Handle sync confirmation from hospital system
          logger.info('Received sync confirmation webhook:', data);
          break;
          
        case 'data_request':
          // Handle data request from hospital system
          logger.info('Received data request webhook:', data);
          break;
          
        default:
          logger.warn('Unknown webhook type:', type);
      }
      
      res.json({
        success: true,
        message: 'Webhook processed successfully',
        timestamp: new Date()
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/integration/logs:
 *   get:
 *     summary: Get integration activity logs (Admin only)
 *     tags: [Integration]
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
 *         name: action
 *         schema:
 *           type: string
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [success, failure]
 *     responses:
 *       200:
 *         description: Integration logs retrieved successfully
 */
router.get('/logs',
  requireAdmin,
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('action')
    .optional()
    .isString()
    .withMessage('Action must be a string'),
  query('status')
    .optional()
    .isIn(['success', 'failure'])
    .withMessage('Status must be success or failure'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { page = 1, limit = 20, action, status } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);
      
      // Build query for audit logs
      let queryObj = {
        resourceType: 'integration'
      };
      
      if (action) {
        queryObj.action = action;
      }
      
      if (status) {
        queryObj.status = status;
      }
      
      // This would typically query the audit log collection
      // For now, return a placeholder response
      res.json({
        success: true,
        data: {
          logs: [],
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: 0,
            pages: 0
          }
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
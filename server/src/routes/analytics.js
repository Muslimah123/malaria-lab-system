// 📁 server/src/routes/analytics.js
const express = require('express');
const { query } = require('express-validator');
const analyticsController = require('../controllers/analyticsController');
const { validateRequest } = require('../middleware/validation');
const { auth, requireSupervisor, requirePermission } = require('../middleware/auth'); // FIXED: Import from auth middleware


const router = express.Router();

// All analytics routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     DashboardStats:
 *       type: object
 *       properties:
 *         todayStats:
 *           type: object
 *           properties:
 *             totalTests:
 *               type: integer
 *             completedTests:
 *               type: integer
 *             pendingTests:
 *               type: integer
 *             failedTests:
 *               type: integer
 *             positiveResults:
 *               type: integer
 *             negativeResults:
 *               type: integer
 *             positivesRate:
 *               type: string
 *         severityBreakdown:
 *           type: object
 *           properties:
 *             mild:
 *               type: integer
 *             moderate:
 *               type: integer
 *             severe:
 *               type: integer
 *         quickActions:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *               url:
 *                 type: string
 *               icon:
 *                 type: string
 *         recentActivities:
 *           type: array
 *           items:
 *             type: object
 *         alerts:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [info, warning, error]
 *               title:
 *                 type: string
 *               message:
 *                 type: string
 *     AnalyticsData:
 *       type: object
 *       properties:
 *         period:
 *           type: object
 *           properties:
 *             type:
 *               type: string
 *             start:
 *               type: string
 *               format: date-time
 *             end:
 *               type: string
 *               format: date-time
 *         testTrends:
 *           type: array
 *           items:
 *             type: object
 *         diagnosisDistribution:
 *           type: object
 *         parasiteTypeDistribution:
 *           type: array
 *           items:
 *             type: object
 *         severityTrends:
 *           type: array
 *           items:
 *             type: object
 *         qualityMetrics:
 *           type: object
 */

/**
 * @swagger
 * /api/analytics/dashboard:
 *   get:
 *     summary: Get dashboard statistics for today
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/DashboardStats'
 *       403:
 *         description: Access denied
 */
router.get('/dashboard',
  analyticsController.getDashboardStats.bind(analyticsController));

/**
 * @swagger
 * /api/analytics/comprehensive:
 *   get:
 *     summary: Get comprehensive analytics data
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [day, week, month, year, custom]
 *           default: month
 *         description: Time period for analytics
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Start date for custom period
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: End date for custom period
 *     responses:
 *       200:
 *         description: Comprehensive analytics data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/AnalyticsData'
 *       400:
 *         description: Invalid date parameters
 */
router.get('/comprehensive',
  requirePermission('canViewAllTests'),
  query('period')
    .optional()
    .isIn(['day', 'week', 'month', 'year', 'custom'])
    .withMessage('Period must be day, week, month, year, or custom'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  analyticsController.getAnalytics.bind(analyticsController)
);

/**
 * @swagger
 * /api/analytics/test-trends:
 *   get:
 *     summary: Get test volume trends over time
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 365
 *           default: 30
 *         description: Number of days to analyze
 *       - in: query
 *         name: groupBy
 *         schema:
 *           type: string
 *           enum: [day, week, month]
 *           default: day
 *         description: How to group the data
 *     responses:
 *       200:
 *         description: Test trends data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       date:
 *                         type: string
 *                         format: date
 *                       totalTests:
 *                         type: integer
 *                       completedTests:
 *                         type: integer
 *                       pendingTests:
 *                         type: integer
 *                       failedTests:
 *                         type: integer
 *                       completionRate:
 *                         type: string
 */
router.get('/test-trends',
  query('days')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Days must be between 1 and 365'),
  query('groupBy')
    .optional()
    .isIn(['day', 'week', 'month'])
    .withMessage('Group by must be day, week, or month'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { days = 30, groupBy = 'day' } = req.query;
      const user = req.user;
      
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      
      const dateRange = { start: startDate, end: endDate };
      
      // Base query with date range
      let baseQuery = {
        createdAt: { $gte: dateRange.start, $lte: dateRange.end },
        isActive: true
      };
      
      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      const trends = await analyticsController.getTestTrends(dateRange, baseQuery);
      
      res.json({
        success: true,
        data: trends,
        metadata: {
          period: `${days} days`,
          groupBy,
          startDate,
          endDate
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/diagnosis-distribution:
 *   get:
 *     summary: Get distribution of positive vs negative diagnoses
 *     tags: [Analytics]
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
 *         description: Filter by specific technician (supervisor/admin only)
 *     responses:
 *       200:
 *         description: Diagnosis distribution data retrieved successfully
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
 *                     positive:
 *                       type: integer
 *                     negative:
 *                       type: integer
 *                     total:
 *                       type: integer
 *                     positiveRate:
 *                       type: string
 *                     avgConfidencePositive:
 *                       type: string
 */
router.get('/diagnosis-distribution',
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('technicianId')
    .optional()
    .isMongoId()
    .withMessage('Technician ID must be a valid MongoDB ObjectId'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate, technicianId } = req.query;
      const user = req.user;
      
      // Build base query
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      // Handle technician filtering
      if (technicianId) {
        // Only supervisors/admins can filter by other technicians
        if (!['supervisor', 'admin'].includes(user.role)) {
          return res.status(403).json({
            success: false,
            message: 'Insufficient permissions to filter by technician'
          });
        }
        baseQuery.technician = technicianId;
      } else if (user.role === 'technician') {
        // Technicians see only their own data
        baseQuery.technician = user._id;
      }
      
      const distribution = await analyticsController.getDiagnosisDistribution(baseQuery);
      
      res.json({
        success: true,
        data: distribution
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/parasite-types:
 *   get:
 *     summary: Get distribution of detected parasite types
 *     tags: [Analytics]
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
 *         description: Parasite type distribution retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       type:
 *                         type: string
 *                       name:
 *                         type: string
 *                       count:
 *                         type: integer
 *                       avgConfidence:
 *                         type: string
 */
router.get('/parasite-types',
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate } = req.query;
      const user = req.user;
      
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      const distribution = await analyticsController.getParasiteTypeDistribution(baseQuery);
      
      res.json({
        success: true,
        data: distribution
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/technician-performance:
 *   get:
 *     summary: Get technician performance metrics (Supervisor/Admin only)
 *     tags: [Analytics]
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
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [totalTests, completionRate, failureRate]
 *           default: totalTests
 *     responses:
 *       200:
 *         description: Technician performance data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       technicianId:
 *                         type: string
 *                       technicianName:
 *                         type: string
 *                       totalTests:
 *                         type: integer
 *                       completedTests:
 *                         type: integer
 *                       pendingTests:
 *                         type: integer
 *                       failedTests:
 *                         type: integer
 *                       completionRate:
 *                         type: string
 *                       failureRate:
 *                         type: string
 */
router.get('/technician-performance',
  requireSupervisor,
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('sortBy')
    .optional()
    .isIn(['totalTests', 'completionRate', 'failureRate'])
    .withMessage('Sort by must be totalTests, completionRate, or failureRate'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate, sortBy = 'totalTests' } = req.query;
      
      const dateRange = {
        start: startDate ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        end: endDate ? new Date(endDate) : new Date()
      };
      
      const performance = await analyticsController.getTechnicianPerformance(dateRange);
      
      // Sort results
      const sortedPerformance = performance.sort((a, b) => {
        switch (sortBy) {
          case 'completionRate':
            return parseFloat(b.completionRate) - parseFloat(a.completionRate);
          case 'failureRate':
            return parseFloat(a.failureRate) - parseFloat(b.failureRate);
          case 'totalTests':
          default:
            return b.totalTests - a.totalTests;
        }
      });
      
      res.json({
        success: true,
        data: sortedPerformance,
        metadata: {
          period: {
            start: dateRange.start,
            end: dateRange.end
          },
          sortBy
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/quality-metrics:
 *   get:
 *     summary: Get quality metrics for diagnoses
 *     tags: [Analytics]
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
 *         description: Quality metrics retrieved successfully
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
 *                     avgConfidence:
 *                       type: string
 *                     highConfidenceRate:
 *                       type: string
 *                     lowConfidenceRate:
 *                       type: string
 *                     avgParasiteCount:
 *                       type: string
 *                     avgWbcCount:
 *                       type: string
 *                     qualityScore:
 *                       type: string
 */
router.get('/quality-metrics',
  requirePermission('canViewAnalytics'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate } = req.query;
      const user = req.user;
      
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      const qualityMetrics = await analyticsController.getQualityMetrics(baseQuery);
      
      res.json({
        success: true,
        data: qualityMetrics
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/export:
 *   get:
 *     summary: Export analytics data as CSV
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [trends, distribution, performance, quality]
 *           default: trends
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
 *         description: Analytics data exported successfully
 *         content:
 *           text/csv:
 *             schema:
 *               type: string
 */
router.get('/export',
  requireSupervisor,
  query('type')
    .optional()
    .isIn(['trends', 'distribution', 'performance', 'quality'])
    .withMessage('Type must be trends, distribution, performance, or quality'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { type = 'trends', startDate, endDate } = req.query;
      
      // Calculate date range
      const dateRange = {
        start: startDate ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        end: endDate ? new Date(endDate) : new Date()
      };
      
      let csvContent = '';
      let filename = '';
      
      switch (type) {
        case 'trends':
          const trends = await analyticsController.getTestTrends(dateRange, { isActive: true });
          csvContent = 'Date,Total Tests,Completed Tests,Pending Tests,Failed Tests,Completion Rate\n';
          trends.forEach(trend => {
            csvContent += `${trend.date.toISOString().split('T')[0]},${trend.totalTests},${trend.completedTests},${trend.pendingTests},${trend.failedTests},${trend.completionRate}%\n`;
          });
          filename = `test_trends_${Date.now()}.csv`;
          break;
          
        case 'performance':
          const performance = await analyticsController.getTechnicianPerformance(dateRange);
          csvContent = 'Technician,Total Tests,Completed Tests,Failed Tests,Completion Rate,Failure Rate\n';
          performance.forEach(perf => {
            csvContent += `"${perf.technicianName}",${perf.totalTests},${perf.completedTests},${perf.failedTests},${perf.completionRate}%,${perf.failureRate}%\n`;
          });
          filename = `technician_performance_${Date.now()}.csv`;
          break;
          
        default:
          return res.status(400).json({
            success: false,
            message: 'Export type not implemented yet'
          });
      }
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);
      
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
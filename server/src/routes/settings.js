// 📁 server/src/routes/settings.js
const express = require('express');
const { body, query, param } = require('express-validator');
const settingsController = require('../controllers/settingsController');
const { validateRequest } = require('../middleware/validation');
const { 
  auth, 
  requireAdmin, 
  requireSupervisor,
  requireRole 
} = require('../middleware/auth');

const router = express.Router();

// All settings routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     UserProfile:
 *       type: object
 *       properties:
 *         firstName:
 *           type: string
 *           minLength: 1
 *           maxLength: 50
 *         lastName:
 *           type: string
 *           minLength: 1
 *           maxLength: 50
 *         phoneNumber:
 *           type: string
 *         department:
 *           type: string
 *         licenseNumber:
 *           type: string
 *     UserSettings:
 *       type: object
 *       properties:
 *         notifications:
 *           type: object
 *         display:
 *           type: object
 *         security:
 *           type: object
 *         dashboard:
 *           type: object
 *     LabSettings:
 *       type: object
 *       properties:
 *         lab:
 *           type: object
 *         quality:
 *           type: object
 *         system:
 *           type: object
 *         integrations:
 *           type: object
 */

// ==================== PROFILE ROUTES ====================

/**
 * @swagger
 * /api/settings/profile:
 *   get:
 *     summary: Get current user's profile
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Profile retrieved successfully
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
 *                     profile:
 *                       $ref: '#/components/schemas/UserProfile'
 */
router.get('/profile', settingsController.getProfile);

/**
 * @swagger
 * /api/settings/profile:
 *   put:
 *     summary: Update current user's profile
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserProfile'
 *     responses:
 *       200:
 *         description: Profile updated successfully
 */
router.put('/profile',
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  body('phoneNumber')
    .optional()
    .trim()
    .isMobilePhone()
    .withMessage('Invalid phone number format'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Department name too long'),
  body('licenseNumber')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('License number too long'),
  validateRequest,
  settingsController.updateProfile
);

/**
 * @swagger
 * /api/settings/profile/password:
 *   put:
 *     summary: Change user password
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 minLength: 6
 *               newPassword:
 *                 type: string
 *                 minLength: 6
 *     responses:
 *       200:
 *         description: Password changed successfully
 */
router.put('/profile/password',
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long')
    .matches(/^(?=.*[a-zA-Z])(?=.*\d)/)
    .withMessage('New password must contain at least one letter and one number'),
  validateRequest,
  settingsController.changePassword
);

// ==================== USER SETTINGS ROUTES ====================

/**
 * @swagger
 * /api/settings/user:
 *   get:
 *     summary: Get user settings
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User settings retrieved successfully
 */
router.get('/user', settingsController.getUserSettings);

/**
 * @swagger
 * /api/settings/user:
 *   put:
 *     summary: Update user settings section
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - section
 *               - data
 *             properties:
 *               section:
 *                 type: string
 *                 enum: [notifications, display, security, dashboard]
 *               data:
 *                 type: object
 *     responses:
 *       200:
 *         description: Settings updated successfully
 */
router.put('/user',
  body('section')
    .isIn(['notifications', 'display', 'security', 'dashboard'])
    .withMessage('Invalid section. Must be notifications, display, security, or dashboard'),
  body('data')
    .isObject()
    .withMessage('Data must be an object'),
  // Validate specific sections
  body('data.theme')
    .optional()
    .isIn(['light', 'dark', 'system'])
    .withMessage('Invalid theme'),
  body('data.language')
    .optional()
    .isIn(['en', 'fr', 'rw', 'sw'])
    .withMessage('Invalid language'),
  body('data.sessionTimeout')
    .optional()
    .isInt({ min: 5, max: 480 })
    .withMessage('Session timeout must be between 5 and 480 minutes'),
  body('data.autoLock')
    .optional()
    .isInt({ min: 0, max: 60 })
    .withMessage('Auto lock must be between 0 and 60 minutes'),
  validateRequest,
  settingsController.updateUserSettings
);

/**
 * @swagger
 * /api/settings/user/reset:
 *   post:
 *     summary: Reset user settings to defaults
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               section:
 *                 type: string
 *                 enum: [notifications, display, security, dashboard]
 *                 description: Optional - reset specific section only
 *     responses:
 *       200:
 *         description: Settings reset successfully
 */
router.post('/user/reset',
  body('section')
    .optional()
    .isIn(['notifications', 'display', 'security', 'dashboard'])
    .withMessage('Invalid section'),
  validateRequest,
  settingsController.resetUserSettings
);

// ==================== LAB SETTINGS ROUTES ====================

/**
 * @swagger
 * /api/settings/lab:
 *   get:
 *     summary: Get lab settings (Supervisor+ only)
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lab settings retrieved successfully
 *       403:
 *         description: Access denied - insufficient permissions
 */
router.get('/lab', 
  requireSupervisor,
  settingsController.getLabSettings
);

/**
 * @swagger
 * /api/settings/lab:
 *   put:
 *     summary: Update lab settings (Admin only)
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - section
 *               - data
 *             properties:
 *               section:
 *                 type: string
 *                 enum: [lab, quality, system, integrations, notifications, audit]
 *               data:
 *                 type: object
 *               reason:
 *                 type: string
 *                 description: Reason for the change (for audit trail)
 *     responses:
 *       200:
 *         description: Lab settings updated successfully
 *       403:
 *         description: Access denied - admin role required
 */
router.put('/lab',
  requireAdmin,
  body('section')
    .isIn(['lab', 'quality', 'system', 'integrations', 'notifications', 'audit'])
    .withMessage('Invalid section'),
  body('data')
    .isObject()
    .withMessage('Data must be an object'),
  body('reason')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason too long'),
  // Validate specific lab setting fields
  body('data.name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Lab name must be between 1 and 100 characters'),
  body('data.email')
    .optional()
    .isEmail()
    .withMessage('Invalid email format'),
  body('data.qualityThreshold')
    .optional()
    .isInt({ min: 50, max: 100 })
    .withMessage('Quality threshold must be between 50 and 100'),
  body('data.retentionPeriod')
    .optional()
    .isInt({ min: 30, max: 3650 })
    .withMessage('Retention period must be between 30 and 3650 days'),
  body('data.sessionTimeout')
    .optional()
    .isInt({ min: 5, max: 480 })
    .withMessage('Session timeout must be between 5 and 480 minutes'),
  validateRequest,
  settingsController.updateLabSettings
);

/**
 * @swagger
 * /api/settings/lab/history:
 *   get:
 *     summary: Get lab settings change history (Admin only)
 *     tags: [Settings]
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
 *     responses:
 *       200:
 *         description: Lab settings history retrieved successfully
 *       403:
 *         description: Access denied - admin role required
 */
router.get('/lab/history',
  requireAdmin,
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  validateRequest,
  settingsController.getLabSettingsHistory
);

// ==================== SYSTEM & UTILITY ROUTES ====================

/**
 * @swagger
 * /api/settings/export:
 *   get:
 *     summary: Export settings (Admin only)
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         required: true
 *         schema:
 *           type: string
 *           enum: [lab, user]
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [json]
 *           default: json
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *         description: Required when type=user
 *     responses:
 *       200:
 *         description: Settings exported successfully
 *       403:
 *         description: Access denied - admin role required
 */
router.get('/export',
  requireAdmin,
  query('type')
    .isIn(['lab', 'user'])
    .withMessage('Type must be lab or user'),
  query('format')
    .optional()
    .isIn(['json'])
    .withMessage('Format must be json'),
  query('userId')
    .optional()
    .isMongoId()
    .withMessage('Invalid user ID'),
  validateRequest,
  settingsController.exportSettings
);

/**
 * @swagger
 * /api/settings/system/status:
 *   get:
 *     summary: Get system status and health (Supervisor+ only)
 *     tags: [Settings]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System status retrieved successfully
 *       403:
 *         description: Access denied - supervisor or admin role required
 */
router.get('/system/status',
  requireSupervisor,
  settingsController.getSystemStatus
);

module.exports = router;
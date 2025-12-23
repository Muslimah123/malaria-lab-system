// // 📁 server/src/routes/users.js
// const express = require('express');
// const router = express.Router();
// const userController = require('../controllers/userController');
// const { auth, requireAdmin } = require('../middleware/auth');
// const { validateRequest } = require('../middleware/validation');
// const { body, param, query } = require('express-validator');

// // All routes require authentication
// router.use(auth);

// // All routes in this file require admin role
// router.use(requireAdmin);

// /**
//  * @swagger
//  * components:
//  *   schemas:
//  *     User:
//  *       type: object
//  *       required:
//  *         - username
//  *         - email
//  *         - firstName
//  *         - lastName
//  *         - role
//  *       properties:
//  *         _id:
//  *           type: string
//  *           description: The auto-generated id of the user
//  *           example: 507f1f77bcf86cd799439011
//  *         username:
//  *           type: string
//  *           description: Unique username
//  *           example: johndoe
//  *         email:
//  *           type: string
//  *           format: email
//  *           description: User's email address
//  *           example: john.doe@example.com
//  *         firstName:
//  *           type: string
//  *           description: User's first name
//  *           example: John
//  *         lastName:
//  *           type: string
//  *           description: User's last name
//  *           example: Doe
//  *         role:
//  *           type: string
//  *           enum: [technician, supervisor, admin]
//  *           description: User's role in the system
//  *           example: technician
//  *         isActive:
//  *           type: boolean
//  *           description: Whether the user account is active
//  *           example: true
//  *         department:
//  *           type: string
//  *           description: User's department
//  *           example: Laboratory
//  *         phoneNumber:
//  *           type: string
//  *           description: User's phone number
//  *           example: +1234567890
//  *         licenseNumber:
//  *           type: string
//  *           description: Medical technician license number
//  *           example: MED123456
//  *         permissions:
//  *           type: object
//  *           properties:
//  *             canUploadSamples:
//  *               type: boolean
//  *               example: true
//  *             canViewAllTests:
//  *               type: boolean
//  *               example: false
//  *             canDeleteTests:
//  *               type: boolean
//  *               example: false
//  *             canManageUsers:
//  *               type: boolean
//  *               example: false
//  *             canExportReports:
//  *               type: boolean
//  *               example: true
//  *         createdAt:
//  *           type: string
//  *           format: date-time
//  *           description: User creation timestamp
//  *         updatedAt:
//  *           type: string
//  *           format: date-time
//  *           description: Last update timestamp
//  *         lastLogin:
//  *           type: string
//  *           format: date-time
//  *           description: Last login timestamp
//  *     
//  *     UserListResponse:
//  *       type: object
//  *       properties:
//  *         success:
//  *           type: boolean
//  *           example: true
//  *         data:
//  *           type: array
//  *           items:
//  *             $ref: '#/components/schemas/User'
//  *         pagination:
//  *           type: object
//  *           properties:
//  *             page:
//  *               type: integer
//  *               example: 1
//  *             limit:
//  *               type: integer
//  *               example: 20
//  *             total:
//  *               type: integer
//  *               example: 100
//  *             pages:
//  *               type: integer
//  *               example: 5
//  *     
//  *     UpdateRoleRequest:
//  *       type: object
//  *       required:
//  *         - role
//  *       properties:
//  *         role:
//  *           type: string
//  *           enum: [technician, supervisor, admin]
//  *           description: New role for the user
//  *           example: supervisor
//  *     
//  *     ResetPasswordRequest:
//  *       type: object
//  *       required:
//  *         - newPassword
//  *       properties:
//  *         newPassword:
//  *           type: string
//  *           minLength: 6
//  *           description: New password for the user
//  *           example: newSecurePassword123
//  *     
//  *     ErrorResponse:
//  *       type: object
//  *       properties:
//  *         success:
//  *           type: boolean
//  *           example: false
//  *         message:
//  *           type: string
//  *           example: Error message description
//  *         error:
//  *           type: object
//  *           description: Additional error details
//  * 
//  * tags:
//  *   - name: User Management
//  *     description: User management operations (Admin only)
//  */

// /**
//  * @swagger
//  * /api/users:
//  *   get:
//  *     summary: Get all users with pagination
//  *     description: Retrieve a paginated list of all users in the system. Only accessible by administrators.
//  *     tags: [User Management]
//  *     security:
//  *       - bearerAuth: []
//  *     parameters:
//  *       - in: query
//  *         name: page
//  *         schema:
//  *           type: integer
//  *           minimum: 1
//  *           default: 1
//  *         description: Page number for pagination
//  *       - in: query
//  *         name: limit
//  *         schema:
//  *           type: integer
//  *           minimum: 1
//  *           maximum: 100
//  *           default: 20
//  *         description: Number of items per page
//  *     responses:
//  *       200:
//  *         description: List of users retrieved successfully
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/UserListResponse'
//  *       401:
//  *         description: Unauthorized - Invalid or missing token
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       403:
//  *         description: Forbidden - Requires admin role
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       500:
//  *         description: Internal server error
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  */
// router.get('/', 
//   [
//     query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
//     query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
//   ],
//   validateRequest,
//   userController.getAllUsers
// );

// /**
//  * @swagger
//  * /api/users/search:
//  *   get:
//  *     summary: Search users by username or email
//  *     description: Search for users by matching username or email. Only accessible by administrators.
//  *     tags: [User Management]
//  *     security:
//  *       - bearerAuth: []
//  *     parameters:
//  *       - in: query
//  *         name: query
//  *         required: true
//  *         schema:
//  *           type: string
//  *         description: Search query to match against username or email
//  *         example: john
//  *       - in: query
//  *         name: page
//  *         schema:
//  *           type: integer
//  *           minimum: 1
//  *           default: 1
//  *         description: Page number for pagination
//  *       - in: query
//  *         name: limit
//  *         schema:
//  *           type: integer
//  *           minimum: 1
//  *           maximum: 100
//  *           default: 20
//  *         description: Number of items per page
//  *     responses:
//  *       200:
//  *         description: Search results retrieved successfully
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/UserListResponse'
//  *       400:
//  *         description: Bad request - Missing or invalid query parameter
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       401:
//  *         description: Unauthorized - Invalid or missing token
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       403:
//  *         description: Forbidden - Requires admin role
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       500:
//  *         description: Internal server error
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  */
// router.get('/search',
//   [
//     query('query').notEmpty().withMessage('Search query is required'),
//     query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
//     query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
//   ],
//   validateRequest,
//   userController.searchUsers
// );

// /**
//  * @swagger
//  * /api/users/{userId}/role:
//  *   put:
//  *     summary: Update user role
//  *     description: Update the role of a specific user. Only accessible by administrators.
//  *     tags: [User Management]
//  *     security:
//  *       - bearerAuth: []
//  *     parameters:
//  *       - in: path
//  *         name: userId
//  *         required: true
//  *         schema:
//  *           type: string
//  *         description: MongoDB ObjectId of the user
//  *         example: 507f1f77bcf86cd799439011
//  *     requestBody:
//  *       required: true
//  *       content:
//  *         application/json:
//  *           schema:
//  *             $ref: '#/components/schemas/UpdateRoleRequest'
//  *     responses:
//  *       200:
//  *         description: User role updated successfully
//  *         content:
//  *           application/json:
//  *             schema:
//  *               type: object
//  *               properties:
//  *                 success:
//  *                   type: boolean
//  *                   example: true
//  *                 message:
//  *                   type: string
//  *                   example: User role updated
//  *                 data:
//  *                   $ref: '#/components/schemas/User'
//  *       400:
//  *         description: Bad request - Invalid role or user ID
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       401:
//  *         description: Unauthorized - Invalid or missing token
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       403:
//  *         description: Forbidden - Requires admin role
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       404:
//  *         description: User not found
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       500:
//  *         description: Internal server error
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  */
// router.put('/:userId/role',
//   [
//     param('userId').isMongoId().withMessage('Invalid user ID'),
//     body('role').isIn(['admin', 'technician', 'supervisor']).withMessage('Invalid role')
//   ],
//   validateRequest,
//   userController.updateUserRole
// );

// /**
//  * @swagger
//  * /api/users/{userId}/reset-password:
//  *   post:
//  *     summary: Reset user password
//  *     description: Reset the password for a specific user and send notification email. Only accessible by administrators.
//  *     tags: [User Management]
//  *     security:
//  *       - bearerAuth: []
//  *     parameters:
//  *       - in: path
//  *         name: userId
//  *         required: true
//  *         schema:
//  *           type: string
//  *         description: MongoDB ObjectId of the user
//  *         example: 507f1f77bcf86cd799439011
//  *     requestBody:
//  *       required: true
//  *       content:
//  *         application/json:
//  *           schema:
//  *             $ref: '#/components/schemas/ResetPasswordRequest'
//  *     responses:
//  *       200:
//  *         description: Password reset successfully
//  *         content:
//  *           application/json:
//  *             schema:
//  *               type: object
//  *               properties:
//  *                 success:
//  *                   type: boolean
//  *                   example: true
//  *                 message:
//  *                   type: string
//  *                   example: User password reset and email notification sent
//  *       400:
//  *         description: Bad request - Invalid password or user ID
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       401:
//  *         description: Unauthorized - Invalid or missing token
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       403:
//  *         description: Forbidden - Requires admin role
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       404:
//  *         description: User not found
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       500:
//  *         description: Internal server error
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  */
// router.post('/:userId/reset-password',
//   [
//     param('userId').isMongoId().withMessage('Invalid user ID'),
//     body('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
//   ],
//   validateRequest,
//   userController.resetUserPassword
// );

// /**
//  * @swagger
//  * /api/users/{userId}:
//  *   delete:
//  *     summary: Delete a user
//  *     description: Permanently delete a user from the system. Only accessible by administrators.
//  *     tags: [User Management]
//  *     security:
//  *       - bearerAuth: []
//  *     parameters:
//  *       - in: path
//  *         name: userId
//  *         required: true
//  *         schema:
//  *           type: string
//  *         description: MongoDB ObjectId of the user to delete
//  *         example: 507f1f77bcf86cd799439011
//  *     responses:
//  *       200:
//  *         description: User deleted successfully
//  *         content:
//  *           application/json:
//  *             schema:
//  *               type: object
//  *               properties:
//  *                 success:
//  *                   type: boolean
//  *                   example: true
//  *                 message:
//  *                   type: string
//  *                   example: User deleted
//  *       400:
//  *         description: Bad request - Invalid user ID
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       401:
//  *         description: Unauthorized - Invalid or missing token
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       403:
//  *         description: Forbidden - Requires admin role
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       404:
//  *         description: User not found
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  *       500:
//  *         description: Internal server error
//  *         content:
//  *           application/json:
//  *             schema:
//  *               $ref: '#/components/schemas/ErrorResponse'
//  */
// router.delete('/:userId',
//   [
//     param('userId').isMongoId().withMessage('Invalid user ID')
//   ],
//   validateRequest,
//   userController.deleteUser
// );

// module.exports = router;
// 📁 server/src/routes/users.js - COMPLETE ENHANCED VERSION
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { auth, requireAdmin } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { body, param, query } = require('express-validator');

// All routes require authentication
router.use(auth);

// All routes in this file require admin role
router.use(requireAdmin);

/**
 * @swagger
 * components:
 *   schemas:
 *     UserWithStats:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           description: User ID
 *           example: 507f1f77bcf86cd799439011
 *         username:
 *           type: string
 *           example: johndoe
 *         email:
 *           type: string
 *           format: email
 *           example: john.doe@example.com
 *         firstName:
 *           type: string
 *           example: John
 *         lastName:
 *           type: string
 *           example: Doe
 *         role:
 *           type: string
 *           enum: [technician, supervisor, admin]
 *           example: technician
 *         isActive:
 *           type: boolean
 *           example: true
 *         department:
 *           type: string
 *           example: Laboratory
 *         phoneNumber:
 *           type: string
 *           example: +1234567890
 *         licenseNumber:
 *           type: string
 *           example: MED123456
 *         testsProcessed:
 *           type: integer
 *           description: Total tests processed by this user
 *           example: 45
 *         completedTests:
 *           type: integer
 *           description: Number of completed tests
 *           example: 42
 *         pendingTests:
 *           type: integer
 *           description: Number of pending/processing tests
 *           example: 2
 *         failedTests:
 *           type: integer
 *           description: Number of failed tests
 *           example: 1
 *         successRate:
 *           type: number
 *           description: Success rate percentage (0-100)
 *           example: 93.33
 *         lastTestDate:
 *           type: string
 *           format: date-time
 *           description: Date of last test processed
 *         avgProcessingTime:
 *           type: number
 *           description: Average processing time in minutes
 *           example: 15.5
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 *         lastLogin:
 *           type: string
 *           format: date-time
 *     
 *     UserListResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         data:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/UserWithStats'
 *         pagination:
 *           type: object
 *           properties:
 *             page:
 *               type: integer
 *               example: 1
 *             limit:
 *               type: integer
 *               example: 20
 *             total:
 *               type: integer
 *               example: 100
 *             pages:
 *               type: integer
 *               example: 5
 *         statistics:
 *           type: object
 *           properties:
 *             totalUsers:
 *               type: integer
 *               example: 100
 *             totalTestsProcessed:
 *               type: integer
 *               example: 1250
 *             averageTestsPerUser:
 *               type: integer
 *               example: 12
 *             averageSuccessRate:
 *               type: number
 *               example: 85.5
 *     
 *     UserStatistics:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         data:
 *           type: object
 *           properties:
 *             totalUsers:
 *               type: integer
 *               example: 100
 *             activeUsers:
 *               type: integer
 *               example: 85
 *             inactiveUsers:
 *               type: integer
 *               example: 15
 *             totalTestsProcessed:
 *               type: integer
 *               example: 1250
 *             totalCompletedTests:
 *               type: integer
 *               example: 1100
 *             totalPendingTests:
 *               type: integer
 *               example: 120
 *             totalFailedTests:
 *               type: integer
 *               example: 30
 *             avgTestsPerUser:
 *               type: number
 *               example: 12.5
 *             overallSuccessRate:
 *               type: number
 *               example: 88.0
 *             activeUserPercentage:
 *               type: number
 *               example: 85.0
 *             adminCount:
 *               type: integer
 *               example: 5
 *             supervisorCount:
 *               type: integer
 *               example: 15
 *             technicianCount:
 *               type: integer
 *               example: 80
 *             usersWithNoTests:
 *               type: integer
 *               example: 10
 *     
 *     TopPerformer:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *         firstName:
 *           type: string
 *           example: John
 *         lastName:
 *           type: string
 *           example: Doe
 *         fullName:
 *           type: string
 *           example: John Doe
 *         email:
 *           type: string
 *           example: john.doe@example.com
 *         role:
 *           type: string
 *           example: technician
 *         department:
 *           type: string
 *           example: Laboratory
 *         testsProcessed:
 *           type: integer
 *           example: 75
 *         completedTests:
 *           type: integer
 *           example: 72
 *         failedTests:
 *           type: integer
 *           example: 3
 *         successRate:
 *           type: number
 *           example: 96.0
 *         performanceScore:
 *           type: number
 *           description: Weighted performance score
 *           example: 89.5
 *         avgProcessingTime:
 *           type: number
 *           description: Average processing time in minutes
 *           example: 12.5
 *         lastLogin:
 *           type: string
 *           format: date-time
 *     
 *     UpdateRoleRequest:
 *       type: object
 *       required:
 *         - role
 *       properties:
 *         role:
 *           type: string
 *           enum: [technician, supervisor, admin]
 *           example: supervisor
 *     
 *     ResetPasswordRequest:
 *       type: object
 *       required:
 *         - newPassword
 *       properties:
 *         newPassword:
 *           type: string
 *           minLength: 6
 *           example: newSecurePassword123
 *     
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: false
 *         message:
 *           type: string
 *           example: Error message description
 *         error:
 *           type: object
 *           description: Additional error details
 * 
 * tags:
 *   - name: User Management
 *     description: Enhanced user management operations with test statistics (Admin only)
 */

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users with enhanced statistics and filtering
 *     description: Retrieve a paginated list of all users with their test performance metrics, filtering options, and comprehensive statistics
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *         description: Number of items per page
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *           enum: [all, admin, supervisor, technician]
 *         description: Filter by user role
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, active, inactive]
 *         description: Filter by user status (active/inactive)
 *     responses:
 *       200:
 *         description: Users with comprehensive statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserListResponse'
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Requires admin role
 *       500:
 *         description: Internal server error
 */
router.get('/', 
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('role').optional().isIn(['all', 'admin', 'supervisor', 'technician']).withMessage('Invalid role filter'),
    query('status').optional().isIn(['all', 'active', 'inactive']).withMessage('Invalid status filter')
  ],
  validateRequest,
  userController.getAllUsers
);

/**
 * @swagger
 * /api/users/search:
 *   get:
 *     summary: Enhanced user search with filters and statistics
 *     description: Search for users by name, username, or email with additional filtering options and test statistics
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: query
 *         required: true
 *         schema:
 *           type: string
 *           minLength: 1
 *         description: Search query to match against username, email, firstName, or lastName
 *         example: john
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *           enum: [all, admin, supervisor, technician]
 *         description: Filter by user role
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [all, active, inactive]
 *         description: Filter by user status
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *         description: Number of items per page
 *     responses:
 *       200:
 *         description: Search results with statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/UserListResponse'
 *                 - type: object
 *                   properties:
 *                     searchQuery:
 *                       type: string
 *                       example: john
 *       400:
 *         description: Bad request - Missing or invalid query parameter
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       500:
 *         description: Internal server error
 */
router.get('/search',
  [
    query('query').notEmpty().trim().withMessage('Search query is required'),
    query('role').optional().isIn(['all', 'admin', 'supervisor', 'technician']).withMessage('Invalid role filter'),
    query('status').optional().isIn(['all', 'active', 'inactive']).withMessage('Invalid status filter'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
  ],
  validateRequest,
  userController.searchUsers
);

/**
 * @swagger
 * /api/users/statistics:
 *   get:
 *     summary: Get comprehensive user and test statistics
 *     description: Retrieve detailed statistics about users, their roles, activity status, and test performance metrics
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserStatistics'
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       500:
 *         description: Internal server error
 */
router.get('/statistics',
  userController.getUserStatistics
);

/**
 * @swagger
 * /api/users/top-performers:
 *   get:
 *     summary: Get top performing users by test metrics
 *     description: Retrieve users ranked by their test processing performance, success rates, and performance scores
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *         description: Number of top performers to return (max 50)
 *     responses:
 *       200:
 *         description: Top performers retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/TopPerformer'
 *                 metadata:
 *                   type: object
 *                   properties:
 *                     requestedLimit:
 *                       type: integer
 *                       example: 10
 *                     actualLimit:
 *                       type: integer
 *                       example: 10
 *                     resultCount:
 *                       type: integer
 *                       example: 8
 *                     generatedAt:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       500:
 *         description: Internal server error
 */
router.get('/top-performers',
  [
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
  ],
  validateRequest,
  userController.getTopPerformers
);

/**
 * @swagger
 * /api/users/{userId}/role:
 *   put:
 *     summary: Update user role
 *     description: Update the role of a specific user. Only accessible by administrators.
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: MongoDB ObjectId of the user
 *         example: 507f1f77bcf86cd799439011
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateRoleRequest'
 *     responses:
 *       200:
 *         description: User role updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User role updated
 *                 data:
 *                   $ref: '#/components/schemas/UserWithStats'
 *       400:
 *         description: Bad request - Invalid role or user ID
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */
router.put('/:userId/role',
  [
    param('userId').isMongoId().withMessage('Invalid user ID'),
    body('role').isIn(['admin', 'technician', 'supervisor']).withMessage('Invalid role')
  ],
  validateRequest,
  userController.updateUserRole
);

/**
 * @swagger
 * /api/users/{userId}/toggle-status:
 *   patch:
 *     summary: Toggle user active status
 *     description: Toggle the active/inactive status of a user. Safer alternative to deletion.
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: MongoDB ObjectId of the user
 *         example: 507f1f77bcf86cd799439011
 *     responses:
 *       200:
 *         description: User status toggled successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User activated
 *                 data:
 *                   $ref: '#/components/schemas/UserWithStats'
 *       400:
 *         description: Bad request - Invalid user ID
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */
router.patch('/:userId/toggle-status',
  [
    param('userId').isMongoId().withMessage('Invalid user ID')
  ],
  validateRequest,
  userController.toggleUserStatus
);

/**
 * @swagger
 * /api/users/{userId}/reset-password:
 *   post:
 *     summary: Reset user password
 *     description: Reset the password for a specific user and send notification email. Only accessible by administrators.
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: MongoDB ObjectId of the user
 *         example: 507f1f77bcf86cd799439011
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ResetPasswordRequest'
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User password reset and email notification sent
 *       400:
 *         description: Bad request - Invalid password or user ID
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */
router.post('/:userId/reset-password',
  [
    param('userId').isMongoId().withMessage('Invalid user ID'),
    body('newPassword')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters')
      .matches(/^(?=.*[a-zA-Z])(?=.*\d)/)
      .withMessage('Password must contain at least one letter and one number')
  ],
  validateRequest,
  userController.resetUserPassword
);

/**
 * @swagger
 * /api/users/{userId}:
 *   delete:
 *     summary: Delete a user (with safety checks)
 *     description: Permanently delete a user from the system. Prevents deletion if user has associated tests. Only accessible by administrators.
 *     tags: [User Management]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: MongoDB ObjectId of the user to delete
 *         example: 507f1f77bcf86cd799439011
 *     responses:
 *       200:
 *         description: User deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User deleted
 *       400:
 *         description: Bad request - Cannot delete user with tests or invalid user ID
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
 *                   example: Cannot delete user. User has 15 associated tests. Consider deactivating instead.
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - Requires admin role
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 */
router.delete('/:userId',
  [
    param('userId').isMongoId().withMessage('Invalid user ID')
  ],
  validateRequest,
  userController.deleteUser
);

module.exports = router;
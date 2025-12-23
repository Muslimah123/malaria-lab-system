// // server/src/controllers/userController.js
// const User = require('../models/User');
// const logger = require('../utils/logger');
// const { AppError } = require('../utils/errorTypes');
// const emailService = require('../services/emailService');

// class UserController {
//   /**
//    * Get all users with pagination (admin only)
//    */
//   async getAllUsers(req, res, next) {
//     try {
//       if (req.user.role !== 'admin') {
//         return res.status(403).json({ success: false, message: 'Only admins can access user list' });
//       }

//       const { page = 1, limit = 20 } = req.query;
//       const skip = (parseInt(page) - 1) * parseInt(limit);
//       const total = await User.countDocuments();
//       const users = await User.find()
//         .select('-password')
//         .skip(skip)
//         .limit(parseInt(limit))
//         .lean();

//       res.json({
//         success: true,
//         data: users,
//         pagination: {
//           page: parseInt(page),
//           limit: parseInt(limit),
//           total,
//           pages: Math.ceil(total / parseInt(limit))
//         }
//       });
//     } catch (error) {
//       logger.error('Get all users error:', error);
//       next(new AppError('Failed to retrieve users', 500));
//     }
//   }

//   /**
//    * Update user role (admin only)
//    */
//   async updateUserRole(req, res, next) {
//     try {
//       if (req.user.role !== 'admin') {
//         return res.status(403).json({ success: false, message: 'Only admins can update user roles' });
//       }
//       const { userId } = req.params;
//       const { role } = req.body;
//       const validRoles = ['admin', 'technician', 'supervisor'];
//       if (!validRoles.includes(role)) {
//         return res.status(400).json({ success: false, message: 'Invalid role specified' });
//       }
//       const user = await User.findByIdAndUpdate(userId, { role }, { new: true, runValidators: true }).select('-password').lean();
//       if (!user) {
//         return res.status(404).json({ success: false, message: 'User not found' });
//       }
//       res.json({ success: true, message: 'User role updated', data: user });
//     } catch (error) {
//       logger.error('Update user role error:', error);
//       next(new AppError('Failed to update user role', 500));
//     }
//   }

//   /**
//    * Delete a user (admin only)
//    */
//   async deleteUser(req, res, next) {
//     try {
//       if (req.user.role !== 'admin') {
//         return res.status(403).json({ success: false, message: 'Only admins can delete users' });
//       }
//       const { userId } = req.params;
//       const user = await User.findByIdAndDelete(userId);
//       if (!user) {
//         return res.status(404).json({ success: false, message: 'User not found' });
//       }
//       res.json({ success: true, message: 'User deleted' });
//     } catch (error) {
//       logger.error('Delete user error:', error);
//       next(new AppError('Failed to delete user', 500));
//     }
//   }

//   /**
//    * Reset user password (admin only)
//    */
//   async resetUserPassword(req, res, next) {
//     try {
//       if (req.user.role !== 'admin') {
//         return res.status(403).json({ success: false, message: 'Only admins can reset passwords' });
//       }
//       const { userId } = req.params;
//       const { newPassword } = req.body;
//       if (!newPassword || newPassword.length < 6) {
//         return res.status(400).json({ success: false, message: 'Invalid new password (min 6 characters)' });
//       }
//       const user = await User.findById(userId);
//       if (!user) {
//         return res.status(404).json({ success: false, message: 'User not found' });
//       }
//       user.password = newPassword; // Assumes pre-save hook hashes password
//       await user.save();
//       await emailService.sendPasswordResetNotification(user.email, newPassword);
//       res.json({ success: true, message: 'User password reset and email notification sent' });
//     } catch (error) {
//       logger.error('Reset password error:', error);
//       next(new AppError('Failed to reset password', 500));
//     }
//   }

//   /**
//    * Search users by username or email (admin only)
//    */
//   async searchUsers(req, res, next) {
//     try {
//       if (req.user.role !== 'admin') {
//         return res.status(403).json({ success: false, message: 'Only admins can search users' });
//       }
//       const { query } = req.query;
//       const { page = 1, limit = 20 } = req.query;
//       if (!query || query.trim() === '') {
//         return res.status(400).json({ success: false, message: 'Search query is required' });
//       }
//       const regex = new RegExp(query, 'i');
//       const skip = (parseInt(page) - 1) * parseInt(limit);
//       const total = await User.countDocuments({
//         $or: [
//           { username: { $regex: regex } },
//           { email: { $regex: regex } }
//         ]
//       });
//       const users = await User.find({
//         $or: [
//           { username: { $regex: regex } },
//           { email: { $regex: regex } }
//         ]
//       }).select('-password').skip(skip).limit(parseInt(limit)).lean();
//       res.json({
//         success: true,
//         data: users,
//         pagination: {
//           page: parseInt(page),
//           limit: parseInt(limit),
//           total,
//           pages: Math.ceil(total / parseInt(limit))
//         }
//       });
//     } catch (error) {
//       logger.error('Search users error:', error);
//       next(new AppError('Failed to search users', 500));
//     }
//   }
// }

// module.exports = new UserController();
// 📁 server/src/controllers/userController.js - COMPLETE ENHANCED VERSION
const User = require('../models/User');
const Test = require('../models/Test');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const emailService = require('../services/emailService');

class UserController {
  /**
   * Get all users with pagination, filtering, and test statistics (admin only)
   */
  async getAllUsers(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can access user list' 
        });
      }

      const { page = 1, limit = 20, role, status } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // ✅ BUILD FILTER CONDITIONS - Fixed for your User model
      const matchCondition = {};
      if (role && role !== 'all') {
        matchCondition.role = role;
      }
      if (status && status !== 'all') {
        // Map status to isActive boolean field (your User model uses isActive, not status)
        matchCondition.isActive = status === 'active';
      }

      // ✅ AGGREGATION PIPELINE WITH TEST STATISTICS
      const pipeline = [
        // Match users based on filters
        { $match: matchCondition },
        
        // ✅ JOIN WITH TESTS COLLECTION
        {
          $lookup: {
            from: 'tests', // Collection name (lowercase, plural)
            localField: '_id',
            foreignField: 'technician',
            as: 'userTests'
          }
        },
        
        // ✅ ADD COMPUTED FIELDS
        {
          $addFields: {
            // Count total tests processed by this user
            testsProcessed: { $size: '$userTests' },
            
            // Count tests by status
            completedTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $eq: ['$$this.status', 'completed'] }
                }
              }
            },
            
            pendingTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $in: ['$$this.status', ['pending', 'processing']] }
                }
              }
            },
            
            failedTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $eq: ['$$this.status', 'failed'] }
                }
              }
            },
            
            // Calculate success rate
            successRate: {
              $cond: [
                { $gt: ['$testsProcessed', 0] },
                {
                  $multiply: [
                    {
                      $divide: [
                        {
                          $size: {
                            $filter: {
                              input: '$userTests',
                              cond: { $eq: ['$$this.status', 'completed'] }
                            }
                          }
                        },
                        { $size: '$userTests' }
                      ]
                    },
                    100
                  ]
                },
                0
              ]
            },
            
            // Calculate last activity from tests
            lastTestDate: {
              $max: '$userTests.createdAt'
            },
            
            // Average processing time for completed tests
            avgProcessingTime: {
              $avg: {
                $map: {
                  input: {
                    $filter: {
                      input: '$userTests',
                      cond: { 
                        $and: [
                          { $eq: ['$$this.status', 'completed'] },
                          { $ne: ['$$this.processingTime', null] }
                        ]
                      }
                    }
                  },
                  as: 'test',
                  in: '$$test.processingTime'
                }
              }
            }
          }
        },
        
        // ✅ REMOVE SENSITIVE FIELDS AND UNNECESSARY DATA
        {
          $project: {
            password: 0,
            userTests: 0, // Remove the full tests array, keep only computed stats
            __v: 0
          }
        },
        
        // ✅ SORT BY CREATION DATE (newest first)
        { $sort: { createdAt: -1 } },
        
        // ✅ PAGINATION
        { $skip: skip },
        { $limit: parseInt(limit) }
      ];

      // ✅ EXECUTE AGGREGATION WITH PERFORMANCE HINT
      const [users, totalCount] = await Promise.all([
        User.aggregate(pipeline),
        User.countDocuments(matchCondition)
      ]);

      // ✅ ROUND SUCCESS RATES AND PROCESSING TIMES
      const processedUsers = users.map(user => ({
        ...user,
        successRate: user.successRate ? Math.round(user.successRate * 100) / 100 : 0,
        avgProcessingTime: user.avgProcessingTime ? Math.round(user.avgProcessingTime / 1000 / 60) : null // Convert to minutes
      }));

      // ✅ ENHANCED RESPONSE WITH COMPREHENSIVE STATISTICS
      res.json({
        success: true,
        data: processedUsers,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalCount,
          pages: Math.ceil(totalCount / parseInt(limit))
        },
        // ✅ OVERALL STATISTICS
        statistics: {
          totalUsers: totalCount,
          totalTestsProcessed: users.reduce((sum, user) => sum + (user.testsProcessed || 0), 0),
          averageTestsPerUser: users.length > 0 ? Math.round(users.reduce((sum, user) => sum + (user.testsProcessed || 0), 0) / users.length) : 0,
          averageSuccessRate: users.length > 0 ? Math.round(users.reduce((sum, user) => sum + (user.successRate || 0), 0) / users.length * 100) / 100 : 0
        }
      });

    } catch (error) {
      logger.error('Get all users error:', error);
      next(new AppError('Failed to retrieve users', 500));
    }
  }

  /**
   * Enhanced search users with test statistics and filters (admin only)
   */
  async searchUsers(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can search users' 
        });
      }

      const { query, role, status } = req.query;
      const { page = 1, limit = 20 } = req.query;
      
      if (!query || query.trim() === '') {
        return res.status(400).json({ 
          success: false, 
          message: 'Search query is required' 
        });
      }

      const regex = new RegExp(query.trim(), 'i');
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // ✅ BUILD SEARCH CONDITIONS
      const searchCondition = {
        $or: [
          { username: { $regex: regex } },
          { email: { $regex: regex } },
          { firstName: { $regex: regex } },
          { lastName: { $regex: regex } }
        ]
      };

      // ✅ ADD FILTERS - Fixed for your User model
      if (role && role !== 'all') {
        searchCondition.role = role;
      }
      if (status && status !== 'all') {
        searchCondition.isActive = status === 'active';
      }

      // ✅ AGGREGATION PIPELINE FOR SEARCH WITH TEST STATISTICS
      const pipeline = [
        { $match: searchCondition },
        
        // Join with tests
        {
          $lookup: {
            from: 'tests',
            localField: '_id',
            foreignField: 'technician',
            as: 'userTests'
          }
        },
        
        // Add computed fields
        {
          $addFields: {
            testsProcessed: { $size: '$userTests' },
            completedTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $eq: ['$$this.status', 'completed'] }
                }
              }
            },
            pendingTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $in: ['$$this.status', ['pending', 'processing']] }
                }
              }
            },
            successRate: {
              $cond: [
                { $gt: [{ $size: '$userTests' }, 0] },
                {
                  $multiply: [
                    {
                      $divide: [
                        {
                          $size: {
                            $filter: {
                              input: '$userTests',
                              cond: { $eq: ['$$this.status', 'completed'] }
                            }
                          }
                        },
                        { $size: '$userTests' }
                      ]
                    },
                    100
                  ]
                },
                0
              ]
            },
            lastTestDate: { $max: '$userTests.createdAt' }
          }
        },
        
        // Remove unnecessary fields
        {
          $project: {
            password: 0,
            userTests: 0,
            __v: 0
          }
        },
        
        // Sort by relevance (tests processed, then creation date)
        { $sort: { testsProcessed: -1, createdAt: -1 } },
        { $skip: skip },
        { $limit: parseInt(limit) }
      ];

      const [users, totalCount] = await Promise.all([
        User.aggregate(pipeline),
        User.countDocuments(searchCondition)
      ]);

      // Process results
      const processedUsers = users.map(user => ({
        ...user,
        successRate: user.successRate ? Math.round(user.successRate * 100) / 100 : 0
      }));

      res.json({
        success: true,
        data: processedUsers,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalCount,
          pages: Math.ceil(totalCount / parseInt(limit))
        },
        searchQuery: query
      });

    } catch (error) {
      logger.error('Search users error:', error);
      next(new AppError('Failed to search users', 500));
    }
  }

  /**
   * Get comprehensive user statistics (admin only)
   */
  async getUserStatistics(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can access user statistics' 
        });
      }

      const userStats = await User.aggregate([
        {
          $lookup: {
            from: 'tests',
            localField: '_id',
            foreignField: 'technician',
            as: 'userTests'
          }
        },
        {
          $group: {
            _id: null,
            totalUsers: { $sum: 1 },
            activeUsers: {
              $sum: {
                $cond: [{ $eq: ['$isActive', true] }, 1, 0] // Fixed: use isActive
              }
            },
            inactiveUsers: {
              $sum: {
                $cond: [{ $eq: ['$isActive', false] }, 1, 0]
              }
            },
            totalTestsProcessed: {
              $sum: { $size: '$userTests' }
            },
            totalCompletedTests: {
              $sum: {
                $size: {
                  $filter: {
                    input: '$userTests',
                    cond: { $eq: ['$$this.status', 'completed'] }
                  }
                }
              }
            },
            totalPendingTests: {
              $sum: {
                $size: {
                  $filter: {
                    input: '$userTests',
                    cond: { $in: ['$$this.status', ['pending', 'processing']] }
                  }
                }
              }
            },
            totalFailedTests: {
              $sum: {
                $size: {
                  $filter: {
                    input: '$userTests',
                    cond: { $eq: ['$$this.status', 'failed'] }
                  }
                }
              }
            },
            avgTestsPerUser: {
              $avg: { $size: '$userTests' }
            },
            // Role distribution
            adminCount: {
              $sum: {
                $cond: [{ $eq: ['$role', 'admin'] }, 1, 0]
              }
            },
            supervisorCount: {
              $sum: {
                $cond: [{ $eq: ['$role', 'supervisor'] }, 1, 0]
              }
            },
            technicianCount: {
              $sum: {
                $cond: [{ $eq: ['$role', 'technician'] }, 1, 0]
              }
            },
            // Users with no tests
            usersWithNoTests: {
              $sum: {
                $cond: [{ $eq: [{ $size: '$userTests' }, 0] }, 1, 0]
              }
            }
          }
        }
      ]);

      // ✅ Handle empty result and format data
      const result = userStats[0] || {
        totalUsers: 0,
        activeUsers: 0,
        inactiveUsers: 0,
        totalTestsProcessed: 0,
        totalCompletedTests: 0,
        totalPendingTests: 0,
        totalFailedTests: 0,
        avgTestsPerUser: 0,
        adminCount: 0,
        supervisorCount: 0,
        technicianCount: 0,
        usersWithNoTests: 0
      };

      // Round averages and calculate additional metrics
      result.avgTestsPerUser = result.avgTestsPerUser ? Math.round(result.avgTestsPerUser * 100) / 100 : 0;
      result.overallSuccessRate = result.totalTestsProcessed > 0 ? 
        Math.round((result.totalCompletedTests / result.totalTestsProcessed) * 10000) / 100 : 0;
      result.activeUserPercentage = result.totalUsers > 0 ? 
        Math.round((result.activeUsers / result.totalUsers) * 10000) / 100 : 0;

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      logger.error('Get user statistics error:', error);
      next(new AppError('Failed to retrieve user statistics', 500));
    }
  }

  /**
   * Get top performing users by test metrics (admin only)
   */
  async getTopPerformers(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can access performance data' 
        });
      }

      const { limit = 10 } = req.query;
      const limitNum = Math.min(parseInt(limit), 50); // Max 50 users

      const topPerformers = await User.aggregate([
        {
          $lookup: {
            from: 'tests',
            localField: '_id',
            foreignField: 'technician',
            as: 'userTests'
          }
        },
        {
          $addFields: {
            testsProcessed: { $size: '$userTests' },
            completedTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $eq: ['$$this.status', 'completed'] }
                }
              }
            },
            failedTests: {
              $size: {
                $filter: {
                  input: '$userTests',
                  cond: { $eq: ['$$this.status', 'failed'] }
                }
              }
            },
            avgProcessingTime: {
              $avg: {
                $map: {
                  input: {
                    $filter: {
                      input: '$userTests',
                      cond: { 
                        $and: [
                          { $eq: ['$$this.status', 'completed'] },
                          { $ne: ['$$this.processingTime', null] }
                        ]
                      }
                    }
                  },
                  as: 'test',
                  in: '$$test.processingTime'
                }
              }
            }
          }
        },
        {
          $match: {
            testsProcessed: { $gt: 0 }, // Only users with tests
            isActive: true // Only active users
          }
        },
        {
          $addFields: {
            successRate: {
              $cond: [
                { $gt: ['$testsProcessed', 0] },
                {
                  $multiply: [
                    { $divide: ['$completedTests', '$testsProcessed'] },
                    100
                  ]
                },
                0
              ]
            },
            // Performance score: weighted average of success rate and volume
            performanceScore: {
              $add: [
                { $multiply: [
                  {
                    $cond: [
                      { $gt: ['$testsProcessed', 0] },
                      { $multiply: [{ $divide: ['$completedTests', '$testsProcessed'] }, 100] },
                      0
                    ]
                  },
                  0.7 // 70% weight on success rate
                ]},
                { $multiply: [
                  {
                    $cond: [
                      { $gte: ['$testsProcessed', 10] },
                      { $min: [{ $divide: ['$testsProcessed', 10] }, 10] }, // Cap at 10 points for volume
                      { $divide: ['$testsProcessed', 10] }
                    ]
                  },
                  3 // 30% weight on volume (max 30 points)
                ]}
              ]
            }
          }
        },
        {
          $project: {
            firstName: 1,
            lastName: 1,
            email: 1,
            role: 1,
            department: 1,
            testsProcessed: 1,
            completedTests: 1,
            failedTests: 1,
            successRate: 1,
            performanceScore: 1,
            avgProcessingTime: {
              $cond: [
                { $ne: ['$avgProcessingTime', null] },
                { $divide: ['$avgProcessingTime', 60000] }, // Convert to minutes
                null
              ]
            },
            lastLogin: 1
          }
        },
        { $sort: { performanceScore: -1, testsProcessed: -1 } },
        { $limit: limitNum }
      ]);

      // Format the results
      const formattedPerformers = topPerformers.map(user => ({
        ...user,
        successRate: Math.round(user.successRate * 100) / 100,
        performanceScore: Math.round(user.performanceScore * 100) / 100,
        avgProcessingTime: user.avgProcessingTime ? Math.round(user.avgProcessingTime * 100) / 100 : null,
        fullName: `${user.firstName} ${user.lastName}`
      }));

      res.json({
        success: true,
        data: formattedPerformers,
        metadata: {
          requestedLimit: parseInt(limit),
          actualLimit: limitNum,
          resultCount: formattedPerformers.length,
          generatedAt: new Date().toISOString()
        }
      });

    } catch (error) {
      logger.error('Get top performers error:', error);
      next(new AppError('Failed to retrieve top performers', 500));
    }
  }

  /**
   * Update user role (admin only)
   */
  async updateUserRole(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can update user roles' 
        });
      }

      const { userId } = req.params;
      const { role } = req.body;
      
      const validRoles = ['admin', 'technician', 'supervisor'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid role specified' 
        });
      }

      const user = await User.findByIdAndUpdate(
        userId, 
        { role }, 
        { new: true, runValidators: true }
      ).select('-password').lean();

      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }

      logger.info(`User role updated: ${user.email} -> ${role} by ${req.user.email}`);

      res.json({ 
        success: true, 
        message: 'User role updated', 
        data: user 
      });
    } catch (error) {
      logger.error('Update user role error:', error);
      next(new AppError('Failed to update user role', 500));
    }
  }

  /**
   * Delete a user (admin only)
   */
  async deleteUser(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can delete users' 
        });
      }

      const { userId } = req.params;
      
      // Check if user has tests before deletion
      const testCount = await Test.countDocuments({ technician: userId });
      if (testCount > 0) {
        return res.status(400).json({
          success: false,
          message: `Cannot delete user. User has ${testCount} associated tests. Consider deactivating instead.`
        });
      }

      const user = await User.findByIdAndDelete(userId);
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }

      logger.warn(`User deleted: ${user.email} by ${req.user.email}`);

      res.json({ 
        success: true, 
        message: 'User deleted' 
      });
    } catch (error) {
      logger.error('Delete user error:', error);
      next(new AppError('Failed to delete user', 500));
    }
  }

  /**
   * Reset user password (admin only)
   */
  async resetUserPassword(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can reset passwords' 
        });
      }

      const { userId } = req.params;
      const { newPassword } = req.body;
      
      if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid new password (min 6 characters)' 
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }

      user.password = newPassword; // Pre-save hook will hash it
      await user.save();

      // Send notification email
      try {
        await emailService.sendPasswordResetNotification(user.email, newPassword);
      } catch (emailError) {
        logger.error('Failed to send password reset email:', emailError);
        // Don't fail the request if email fails
      }

      logger.info(`Password reset for user: ${user.email} by ${req.user.email}`);

      res.json({ 
        success: true, 
        message: 'User password reset and email notification sent' 
      });
    } catch (error) {
      logger.error('Reset password error:', error);
      next(new AppError('Failed to reset password', 500));
    }
  }

  /**
   * Toggle user active status (admin only)
   */
  async toggleUserStatus(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only admins can toggle user status' 
        });
      }

      const { userId } = req.params;
      
      const user = await User.findById(userId).select('-password');
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'User not found' 
        });
      }

      user.isActive = !user.isActive;
      await user.save();

      logger.info(`User status toggled: ${user.email} -> ${user.isActive ? 'active' : 'inactive'} by ${req.user.email}`);

      res.json({ 
        success: true, 
        message: `User ${user.isActive ? 'activated' : 'deactivated'}`, 
        data: user 
      });
    } catch (error) {
      logger.error('Toggle user status error:', error);
      next(new AppError('Failed to toggle user status', 500));
    }
  }
}

module.exports = new UserController();

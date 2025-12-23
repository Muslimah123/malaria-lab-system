// 📁 server/src/controllers/settingsController.js
const User = require('../models/User');
const UserSettings = require('../models/UserSettings');
const LabSettings = require('../models/LabSettings');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const bcrypt = require('bcryptjs');

class SettingsController {
  /**
   * Get current user's profile information
   */
  async getProfile(req, res, next) {
    try {
      const user = req.user;
      
      res.json({
        success: true,
        data: {
          profile: user.toJSON()
        }
      });

    } catch (error) {
      logger.error('Get profile error:', error);
      next(new AppError('Failed to retrieve profile', 500));
    }
  }

  /**
   * Update current user's profile information
   */
  async updateProfile(req, res, next) {
    try {
      const userId = req.user._id;
      const { 
        firstName, 
        lastName, 
        phoneNumber, 
        department, 
        licenseNumber 
      } = req.body;

      // Build update object with only provided fields
      const updateData = {};
      if (firstName !== undefined) updateData.firstName = firstName;
      if (lastName !== undefined) updateData.lastName = lastName;
      if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;
      if (department !== undefined) updateData.department = department;
      if (licenseNumber !== undefined) updateData.licenseNumber = licenseNumber;

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        updateData,
        { new: true, runValidators: true }
      ).select('-password');

      if (!updatedUser) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Log profile update
      await auditService.log({
        action: 'profile_updated',
        userId: userId,
        userInfo: { 
          username: req.user.username, 
          email: req.user.email, 
          role: req.user.role 
        },
        resourceType: 'user',
        resourceId: userId.toString(),
        details: { 
          updatedFields: Object.keys(updateData),
          changes: updateData
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: req.method,
          endpoint: req.originalUrl
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: {
          profile: updatedUser.toJSON()
        }
      });

    } catch (error) {
      logger.error('Update profile error:', error);
      
      if (error.name === 'ValidationError') {
        return res.status(400).json({
          success: false,
          message: 'Validation error',
          errors: Object.values(error.errors).map(err => err.message)
        });
      }
      
      next(new AppError('Failed to update profile', 500));
    }
  }

  /**
   * Change user password
   */
  async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user._id;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          message: 'Current password and new password are required'
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'New password must be at least 6 characters long'
        });
      }

      // Get user with password
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Verify current password
      const isCurrentPasswordValid = await user.comparePassword(currentPassword);
      if (!isCurrentPasswordValid) {
        // Log failed password change attempt
        await auditService.log({
          action: 'password_change_failed',
          userId: userId,
          userInfo: { 
            username: req.user.username, 
            email: req.user.email, 
            role: req.user.role 
          },
          resourceType: 'user',
          resourceId: userId.toString(),
          details: { 
            reason: 'Invalid current password',
            timestamp: new Date()
          },
          requestInfo: {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            method: req.method,
            endpoint: req.originalUrl
          },
          status: 'failure',
          riskLevel: 'medium'
        });

        return res.status(400).json({
          success: false,
          message: 'Current password is incorrect'
        });
      }

      // Update password
      user.password = newPassword;
      await user.save();

      // Log successful password change
      await auditService.log({
        action: 'password_changed',
        userId: userId,
        userInfo: { 
          username: req.user.username, 
          email: req.user.email, 
          role: req.user.role 
        },
        resourceType: 'user',
        resourceId: userId.toString(),
        details: { 
          timestamp: new Date()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: req.method,
          endpoint: req.originalUrl
        },
        status: 'success',
        riskLevel: 'medium'
      });

      res.json({
        success: true,
        message: 'Password changed successfully'
      });

    } catch (error) {
      logger.error('Change password error:', error);
      next(new AppError('Failed to change password', 500));
    }
  }

  /**
   * Get user settings
   */
  async getUserSettings(req, res, next) {
    try {
      const userId = req.user._id;
      
      const settings = await UserSettings.getForUser(userId);
      
      res.json({
        success: true,
        data: {
          settings: settings.toObject()
        }
      });

    } catch (error) {
      logger.error('Get user settings error:', error);
      next(new AppError('Failed to retrieve user settings', 500));
    }
  }

  /**
   * Update user settings section
   */
  async updateUserSettings(req, res, next) {
    try {
      const userId = req.user._id;
      const { section, data } = req.body;

      if (!section || !data) {
        return res.status(400).json({
          success: false,
          message: 'Section and data are required'
        });
      }

      const validSections = ['notifications', 'display', 'security', 'dashboard'];
      if (!validSections.includes(section)) {
        return res.status(400).json({
          success: false,
          message: `Invalid section. Must be one of: ${validSections.join(', ')}`
        });
      }

      const settings = await UserSettings.getForUser(userId);
      await settings.updateSection(section, data);

      // Log settings update
      await auditService.log({
        action: 'user_settings_updated',
        userId: userId,
        userInfo: { 
          username: req.user.username, 
          email: req.user.email, 
          role: req.user.role 
        },
        resourceType: 'user_settings',
        resourceId: settings._id.toString(),
        details: { 
          section,
          changes: data,
          timestamp: new Date()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: req.method,
          endpoint: req.originalUrl
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: `${section} settings updated successfully`,
        data: {
          settings: settings.toObject()
        }
      });

    } catch (error) {
      logger.error('Update user settings error:', error);
      
      if (error.message.includes('Invalid settings section')) {
        return res.status(400).json({
          success: false,
          message: error.message
        });
      }
      
      next(new AppError('Failed to update user settings', 500));
    }
  }

  /**
   * Reset user settings to defaults
   */
  async resetUserSettings(req, res, next) {
    try {
      const userId = req.user._id;
      const { section } = req.body;

      const settings = await UserSettings.getForUser(userId);

      if (section) {
        // Reset specific section
        const validSections = ['notifications', 'display', 'security', 'dashboard'];
        if (!validSections.includes(section)) {
          return res.status(400).json({
            success: false,
            message: `Invalid section. Must be one of: ${validSections.join(', ')}`
          });
        }

        // Get default values for section
        const defaultSettings = new UserSettings();
        settings[section] = defaultSettings[section];
        await settings.save();

        res.json({
          success: true,
          message: `${section} settings reset to defaults`,
          data: {
            settings: settings.toObject()
          }
        });
      } else {
        // Reset all settings
        await UserSettings.findOneAndDelete({ user: userId });
        const newSettings = await UserSettings.getForUser(userId);

        res.json({
          success: true,
          message: 'All settings reset to defaults',
          data: {
            settings: newSettings.toObject()
          }
        });
      }

      // Log settings reset
      await auditService.log({
        action: 'user_settings_reset',
        userId: userId,
        userInfo: { 
          username: req.user.username, 
          email: req.user.email, 
          role: req.user.role 
        },
        resourceType: 'user_settings',
        resourceId: settings._id.toString(),
        details: { 
          section: section || 'all',
          timestamp: new Date()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: req.method,
          endpoint: req.originalUrl
        },
        status: 'success',
        riskLevel: 'low'
      });

    } catch (error) {
      logger.error('Reset user settings error:', error);
      next(new AppError('Failed to reset user settings', 500));
    }
  }

  /**
   * Get lab settings (Supervisor+ only)
   */
  async getLabSettings(req, res, next) {
    try {
      if (!['supervisor', 'admin'].includes(req.user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Supervisor or admin role required.'
        });
      }

      const settings = await LabSettings.get();
      
      res.json({
        success: true,
        data: {
          settings: settings.toObject()
        }
      });

    } catch (error) {
      logger.error('Get lab settings error:', error);
      next(new AppError('Failed to retrieve lab settings', 500));
    }
  }

  /**
   * Update lab settings (Admin only)
   */
  async updateLabSettings(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Admin role required.'
        });
      }

      const { section, data, reason = '' } = req.body;

      if (!section || !data) {
        return res.status(400).json({
          success: false,
          message: 'Section and data are required'
        });
      }

      const validSections = ['lab', 'quality', 'system', 'integrations', 'notifications', 'audit'];
      if (!validSections.includes(section)) {
        return res.status(400).json({
          success: false,
          message: `Invalid section. Must be one of: ${validSections.join(', ')}`
        });
      }

      const settings = await LabSettings.get();
      await settings.updateSection(section, data, req.user._id, reason);

      // Log lab settings update
      await auditService.log({
        action: 'lab_settings_updated',
        userId: req.user._id,
        userInfo: { 
          username: req.user.username, 
          email: req.user.email, 
          role: req.user.role 
        },
        resourceType: 'lab_settings',
        resourceId: settings._id.toString(),
        details: { 
          section,
          changes: data,
          reason,
          timestamp: new Date()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: req.method,
          endpoint: req.originalUrl
        },
        status: 'success',
        riskLevel: 'high'
      });

      res.json({
        success: true,
        message: `Lab ${section} settings updated successfully`,
        data: {
          settings: settings.toObject()
        }
      });

    } catch (error) {
      logger.error('Update lab settings error:', error);
      
      if (error.message.includes('Invalid settings section')) {
        return res.status(400).json({
          success: false,
          message: error.message
        });
      }
      
      next(new AppError('Failed to update lab settings', 500));
    }
  }

  /**
   * Get lab settings history (Admin only)
   */
  async getLabSettingsHistory(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Admin role required.'
        });
      }

      const { page = 1, limit = 20 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Get audit logs for lab settings changes
      const auditLogs = await require('../models/AuditLog').find({
        resourceType: 'lab_settings',
        action: { $in: ['lab_settings_updated', 'lab_settings_reset'] }
      })
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

      const total = await require('../models/AuditLog').countDocuments({
        resourceType: 'lab_settings',
        action: { $in: ['lab_settings_updated', 'lab_settings_reset'] }
      });

      res.json({
        success: true,
        data: auditLogs,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit))
        }
      });

    } catch (error) {
      logger.error('Get lab settings history error:', error);
      next(new AppError('Failed to retrieve lab settings history', 500));
    }
  }

  /**
   * Export settings (Admin only)
   */
  async exportSettings(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Admin role required.'
        });
      }

      const { type = 'lab', format = 'json' } = req.query;

      let settings;
      if (type === 'lab') {
        settings = await LabSettings.get();
      } else if (type === 'user') {
        const { userId } = req.query;
        if (!userId) {
          return res.status(400).json({
            success: false,
            message: 'User ID required for user settings export'
          });
        }
        settings = await UserSettings.getForUser(userId);
      } else {
        return res.status(400).json({
          success: false,
          message: 'Invalid type. Must be "lab" or "user"'
        });
      }

      if (format === 'json') {
        res.json({
          success: true,
          data: {
            type,
            settings: settings.toObject(),
            exportedAt: new Date(),
            exportedBy: req.user.email
          }
        });
      } else {
        return res.status(400).json({
          success: false,
          message: 'Invalid format. Only JSON supported currently'
        });
      }

      // Log settings export
      await auditService.log({
        action: 'settings_exported',
        userId: req.user._id,
        userInfo: { 
          username: req.user.username, 
          email: req.user.email, 
          role: req.user.role 
        },
        resourceType: `${type}_settings`,
        resourceId: settings._id.toString(),
        details: { 
          type,
          format,
          timestamp: new Date()
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: req.method,
          endpoint: req.originalUrl
        },
        status: 'success',
        riskLevel: 'medium'
      });

    } catch (error) {
      logger.error('Export settings error:', error);
      next(new AppError('Failed to export settings', 500));
    }
  }

  /**
   * Get system status and health
   */
  async getSystemStatus(req, res, next) {
    try {
      if (!['supervisor', 'admin'].includes(req.user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Supervisor or admin role required.'
        });
      }

      // Get basic system metrics
      const [
        totalUsers,
        activeUsers,
        totalTests,
        recentTests,
        labSettings
      ] = await Promise.all([
        User.countDocuments(),
        User.countDocuments({ isActive: true }),
        require('../models/Test').countDocuments(),
        require('../models/Test').countDocuments({
          createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        }),
        LabSettings.get()
      ]);

      const systemStatus = {
        server: {
          status: 'healthy',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          nodeVersion: process.version
        },
        database: {
          status: 'connected',
          // Add more DB metrics if needed
        },
        application: {
          users: {
            total: totalUsers,
            active: activeUsers
          },
          tests: {
            total: totalTests,
            last24h: recentTests
          },
          maintenanceMode: labSettings.system.maintenanceMode
        },
        lastCheck: new Date()
      };

      res.json({
        success: true,
        data: systemStatus
      });

    } catch (error) {
      logger.error('Get system status error:', error);
      next(new AppError('Failed to retrieve system status', 500));
    }
  }
}

module.exports = new SettingsController();
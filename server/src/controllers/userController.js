// 📁 server/src/controllers/userController.js
const User = require('../models/User');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const emailService = require('../services/emailService');

class UserController {
  /**
   * Get all users with pagination (admin only)
   */
  async getAllUsers(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Only admins can access user list' });
      }

      const { page = 1, limit = 20 } = req.query;
      const skip = (parseInt(page) - 1) * parseInt(limit);
      const total = await User.countDocuments();
      const users = await User.find()
        .select('-password')
        .skip(skip)
        .limit(parseInt(limit))
        .lean();

      res.json({
        success: true,
        data: users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit))
        }
      });
    } catch (error) {
      logger.error('Get all users error:', error);
      next(new AppError('Failed to retrieve users', 500));
    }
  }

  /**
   * Update user role (admin only)
   */
  async updateUserRole(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Only admins can update user roles' });
      }
      const { userId } = req.params;
      const { role } = req.body;
      const validRoles = ['admin', 'technician', 'supervisor'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ success: false, message: 'Invalid role specified' });
      }
      const user = await User.findByIdAndUpdate(userId, { role }, { new: true, runValidators: true }).select('-password').lean();
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      res.json({ success: true, message: 'User role updated', data: user });
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
        return res.status(403).json({ success: false, message: 'Only admins can delete users' });
      }
      const { userId } = req.params;
      const user = await User.findByIdAndDelete(userId);
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      res.json({ success: true, message: 'User deleted' });
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
        return res.status(403).json({ success: false, message: 'Only admins can reset passwords' });
      }
      const { userId } = req.params;
      const { newPassword } = req.body;
      if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'Invalid new password (min 6 characters)' });
      }
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      user.password = newPassword; // Assumes pre-save hook hashes password
      await user.save();
      await emailService.sendPasswordResetNotification(user.email, newPassword);
      res.json({ success: true, message: 'User password reset and email notification sent' });
    } catch (error) {
      logger.error('Reset password error:', error);
      next(new AppError('Failed to reset password', 500));
    }
  }

  /**
   * Search users by username or email (admin only)
   */
  async searchUsers(req, res, next) {
    try {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Only admins can search users' });
      }
      const { query } = req.query;
      const { page = 1, limit = 20 } = req.query;
      if (!query || query.trim() === '') {
        return res.status(400).json({ success: false, message: 'Search query is required' });
      }
      const regex = new RegExp(query, 'i');
      const skip = (parseInt(page) - 1) * parseInt(limit);
      const total = await User.countDocuments({
        $or: [
          { username: { $regex: regex } },
          { email: { $regex: regex } }
        ]
      });
      const users = await User.find({
        $or: [
          { username: { $regex: regex } },
          { email: { $regex: regex } }
        ]
      }).select('-password').skip(skip).limit(parseInt(limit)).lean();
      res.json({
        success: true,
        data: users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit))
        }
      });
    } catch (error) {
      logger.error('Search users error:', error);
      next(new AppError('Failed to search users', 500));
    }
  }
}

module.exports = new UserController();

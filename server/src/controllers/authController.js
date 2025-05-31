// 📁 server/src/controllers/authController.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const authService = require('../services/authService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class AuthController {
  /**
   * Login user
   */
  async login(req, res, next) {
    try {
      const { email, password } = req.body;
      const clientIP = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Find user by email
      const user = await User.findOne({ email, isActive: true });
      
      if (!user) {
        // Log failed login attempt
        await auditService.log({
          action: 'failed_login',
          userId: null,
          userInfo: { email },
          resourceType: 'user',
          resourceId: email,
          details: { reason: 'User not found' },
          requestInfo: { ipAddress: clientIP, userAgent, method: 'POST', endpoint: '/api/auth/login' },
          status: 'failure',
          riskLevel: 'medium'
        });

        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      // Check password
      const isPasswordValid = await user.comparePassword(password);
      
      if (!isPasswordValid) {
        // Log failed login attempt
        await auditService.log({
          action: 'failed_login',
          userId: user._id,
          userInfo: { username: user.username, email: user.email, role: user.role },
          resourceType: 'user',
          resourceId: user._id.toString(),
          details: { reason: 'Invalid password' },
          requestInfo: { ipAddress: clientIP, userAgent, method: 'POST', endpoint: '/api/auth/login' },
          status: 'failure',
          riskLevel: 'medium'
        });

        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      // Generate tokens
      const tokens = await authService.generateTokens(user);
      
      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Log successful login
      await auditService.log({
        action: 'login',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role, fullName: user.fullName },
        resourceType: 'user',
        resourceId: user._id.toString(),
        details: { loginTime: new Date() },
        requestInfo: { ipAddress: clientIP, userAgent, method: 'POST', endpoint: '/api/auth/login' },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: user.toJSON(),
          token: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: process.env.JWT_EXPIRES_IN || '1h'
        }
      });

    } catch (error) {
      logger.error('Login error:', error);
      next(new AppError('Login failed', 500));
    }
  }

  /**
   * Register new user (Admin only)
   */
  async register(req, res, next) {
    try {
      const { username, email, password, firstName, lastName, role = 'technician' } = req.body;
      const adminUser = req.user;

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User with this email or username already exists'
        });
      }

      // Create new user
      const newUser = new User({
        username,
        email,
        password,
        firstName,
        lastName,
        role
      });

      await newUser.save();

      // Log user creation
      await auditService.log({
        action: 'user_created',
        userId: adminUser._id,
        userInfo: { username: adminUser.username, email: adminUser.email, role: adminUser.role },
        resourceType: 'user',
        resourceId: newUser._id.toString(),
        resourceName: newUser.fullName,
        details: { 
          newUserData: { username, email, firstName, lastName, role },
          createdBy: adminUser.fullName
        },
        requestInfo: { 
          ipAddress: req.ip, 
          userAgent: req.get('User-Agent'), 
          method: 'POST', 
          endpoint: '/api/auth/register' 
        },
        status: 'success',
        riskLevel: 'medium'
      });

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: {
          user: newUser.toJSON()
        }
      });

    } catch (error) {
      logger.error('Registration error:', error);
      
      if (error.code === 11000) {
        return res.status(400).json({
          success: false,
          message: 'User with this email or username already exists'
        });
      }
      
      next(new AppError('Registration failed', 500));
    }
  }

  /**
   * Logout user
   */
  async logout(req, res, next) {
    try {
      const user = req.user;
      const token = req.token;

      // Add token to blacklist
      await authService.blacklistToken(token);

      // Log logout
      await auditService.log({
        action: 'logout',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'user',
        resourceId: user._id.toString(),
        details: { logoutTime: new Date() },
        requestInfo: { 
          ipAddress: req.ip, 
          userAgent: req.get('User-Agent'), 
          method: 'POST', 
          endpoint: '/api/auth/logout' 
        },
        status: 'success',
        riskLevel: 'low'
      });

      res.json({
        success: true,
        message: 'Logout successful'
      });

    } catch (error) {
      logger.error('Logout error:', error);
      next(new AppError('Logout failed', 500));
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(req, res, next) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: 'Refresh token is required'
        });
      }

      // Verify refresh token
      const decoded = await authService.verifyRefreshToken(refreshToken);
      
      // Find user
      const user = await User.findById(decoded.userId);
      
      if (!user || !user.isActive) {
        return res.status(401).json({
          success: false,
          message: 'User not found or inactive'
        });
      }

      // Generate new tokens
      const tokens = await authService.generateTokens(user);

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          token: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: process.env.JWT_EXPIRES_IN || '1h'
        }
      });

    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(req, res, next) {
    try {
      const user = req.user;
      
      res.json({
        success: true,
        data: {
          user: user.toJSON()
        }
      });

    } catch (error) {
      logger.error('Get current user error:', error);
      next(new AppError('Failed to get user profile', 500));
    }
  }

  /**
   * Change password
   */
  async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = req.user;

      // Verify current password
      const isCurrentPasswordValid = await user.comparePassword(currentPassword);
      
      if (!isCurrentPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'Current password is incorrect'
        });
      }

      // Update password
      user.password = newPassword;
      await user.save();

      // Log password change
      await auditService.log({
        action: 'password_change',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'user',
        resourceId: user._id.toString(),
        details: { changeTime: new Date() },
        requestInfo: { 
          ipAddress: req.ip, 
          userAgent: req.get('User-Agent'), 
          method: 'PUT', 
          endpoint: '/api/auth/change-password' 
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
   * Forgot password
   */
  async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email, isActive: true });
      
      if (!user) {
        // Don't reveal if user exists or not
        return res.json({
          success: true,
          message: 'If the email exists, a password reset link has been sent'
        });
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      // Store reset token (you'd typically store this in the user document or a separate collection)
      // For now, we'll use a simple approach
      await authService.storePasswordResetToken(user._id, resetToken, resetTokenExpiry);

      // Send email (implement email service)
      // await emailService.sendPasswordResetEmail(user.email, resetToken);

      // Log password reset request
      await auditService.log({
        action: 'password_reset_requested',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'user',
        resourceId: user._id.toString(),
        details: { requestTime: new Date(), tokenExpiry: resetTokenExpiry },
        requestInfo: { 
          ipAddress: req.ip, 
          userAgent: req.get('User-Agent'), 
          method: 'POST', 
          endpoint: '/api/auth/forgot-password' 
        },
        status: 'success',
        riskLevel: 'medium'
      });

      res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent'
      });

    } catch (error) {
      logger.error('Forgot password error:', error);
      next(new AppError('Failed to process password reset request', 500));
    }
  }

  /**
   * Reset password with token
   */
  async resetPassword(req, res, next) {
    try {
      const { token, newPassword } = req.body;

      // Verify reset token
      const userId = await authService.verifyPasswordResetToken(token);
      
      if (!userId) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token'
        });
      }

      // Find user and update password
      const user = await User.findById(userId);
      
      if (!user || !user.isActive) {
        return res.status(400).json({
          success: false,
          message: 'User not found or inactive'
        });
      }

      user.password = newPassword;
      await user.save();

      // Clear reset token
      await authService.clearPasswordResetToken(userId);

      // Log password reset
      await auditService.log({
        action: 'password_reset_completed',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'user',
        resourceId: user._id.toString(),
        details: { resetTime: new Date() },
        requestInfo: { 
          ipAddress: req.ip, 
          userAgent: req.get('User-Agent'), 
          method: 'POST', 
          endpoint: '/api/auth/reset-password' 
        },
        status: 'success',
        riskLevel: 'high'
      });

      res.json({
        success: true,
        message: 'Password reset successful'
      });

    } catch (error) {
      logger.error('Reset password error:', error);
      next(new AppError('Failed to reset password', 500));
    }
  }

  /**
   * Verify session
   */
  async verifySession(req, res, next) {
    try {
      const user = req.user;
      
      res.json({
        success: true,
        message: 'Session is valid',
        data: {
          user: user.toJSON(),
          sessionExpiry: req.tokenExpiry
        }
      });

    } catch (error) {
      logger.error('Verify session error:', error);
      next(new AppError('Session verification failed', 500));
    }
  }

  /**
   * Middleware to require admin role
   */
  requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    next();
  }

  /**
   * Middleware to require supervisor or admin role
   */
  requireSupervisor(req, res, next) {
    if (!['supervisor', 'admin'].includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Supervisor or admin access required'
      });
    }
    next();
  }

  /**
   * Middleware to require specific permission
   */
  requirePermission(permission) {
    return (req, res, next) => {
      if (!req.user.permissions[permission]) {
        return res.status(403).json({
          success: false,
          message: `Permission required: ${permission}`
        });
      }
      next();
    };
  }
}

module.exports = new AuthController();
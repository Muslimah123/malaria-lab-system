// 📁 server/src/services/authService.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const redis = require('redis');
const User = require('../models/User');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
    this.refreshTokenExpiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
    
    // Initialize Redis client for token blacklisting and session management
    this.initializeRedis();
  }

  /**
   * Initialize Redis connection
   */
  async initializeRedis() {
    try {
      this.redisClient = redis.createClient({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD,
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3
      });

      this.redisClient.on('error', (err) => {
        logger.error('Redis connection error:', err);
      });

      this.redisClient.on('connect', () => {
        logger.info('Connected to Redis');
      });

      await this.redisClient.connect();
    } catch (error) {
      logger.warn('Redis not available, using memory fallback:', error.message);
      this.useMemoryFallback = true;
      this.memoryStore = new Map();
    }
  }

  /**
   * Generate JWT access token and refresh token
   */
  async generateTokens(user) {
    try {
      const payload = {
        userId: user._id.toString(),
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      };

      // Generate access token
      const accessToken = jwt.sign(payload, this.jwtSecret, {
        expiresIn: this.jwtExpiresIn,
        issuer: 'malaria-lab-system',
        audience: 'malaria-lab-users'
      });

      // Generate refresh token
      const refreshPayload = {
        userId: user._id.toString(),
        tokenType: 'refresh'
      };

      const refreshToken = jwt.sign(refreshPayload, this.jwtSecret, {
        expiresIn: this.refreshTokenExpiresIn,
        issuer: 'malaria-lab-system',
        audience: 'malaria-lab-users'
      });

      // Store refresh token
      await this.storeRefreshToken(user._id.toString(), refreshToken);

      return {
        accessToken,
        refreshToken,
        expiresIn: this.jwtExpiresIn
      };

    } catch (error) {
      logger.error('Token generation failed:', error);
      throw new AppError('Failed to generate authentication tokens', 500);
    }
  }

  /**
   * Verify JWT token
   */
  async verifyToken(token) {
    try {
      // Check if token is blacklisted
      const isBlacklisted = await this.isTokenBlacklisted(token);
      if (isBlacklisted) {
        throw new AppError('Token has been revoked', 401);
      }

      // Verify token
      const decoded = jwt.verify(token, this.jwtSecret, {
        issuer: 'malaria-lab-system',
        audience: 'malaria-lab-users'
      });

      return decoded;

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new AppError('Invalid token', 401);
      }
      if (error instanceof jwt.TokenExpiredError) {
        throw new AppError('Token has expired', 401);
      }
      throw error;
    }
  }

  /**
   * Verify refresh token
   */
  async verifyRefreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, this.jwtSecret, {
        issuer: 'malaria-lab-system',
        audience: 'malaria-lab-users'
      });

      if (decoded.tokenType !== 'refresh') {
        throw new AppError('Invalid refresh token', 401);
      }

      // Check if refresh token exists in store
      const storedToken = await this.getStoredRefreshToken(decoded.userId);
      if (storedToken !== refreshToken) {
        throw new AppError('Refresh token not found or invalid', 401);
      }

      return decoded;

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
        throw new AppError('Invalid or expired refresh token', 401);
      }
      throw error;
    }
  }

  /**
   * Blacklist a token
   */
  async blacklistToken(token) {
    try {
      const decoded = jwt.decode(token);
      if (!decoded || !decoded.exp) {
        return;
      }

      const expiresAt = decoded.exp * 1000; // Convert to milliseconds
      const ttl = Math.max(0, expiresAt - Date.now());

      if (ttl > 0) {
        const key = `blacklist:${token}`;
        
        if (this.useMemoryFallback) {
          this.memoryStore.set(key, true);
          // Set cleanup timeout
          setTimeout(() => {
            this.memoryStore.delete(key);
          }, ttl);
        } else {
          await this.redisClient.setEx(key, Math.ceil(ttl / 1000), 'true');
        }
      }

    } catch (error) {
      logger.error('Token blacklisting failed:', error);
      // Don't throw error for blacklisting failure
    }
  }

  /**
   * Check if token is blacklisted
   */
  async isTokenBlacklisted(token) {
    try {
      const key = `blacklist:${token}`;
      
      if (this.useMemoryFallback) {
        return this.memoryStore.has(key);
      } else {
        const result = await this.redisClient.get(key);
        return result === 'true';
      }
    } catch (error) {
      logger.error('Blacklist check failed:', error);
      return false; // Fail open
    }
  }

  /**
   * Store refresh token
   */
  async storeRefreshToken(userId, refreshToken) {
    try {
      const key = `refresh:${userId}`;
      const decoded = jwt.decode(refreshToken);
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);

      if (this.useMemoryFallback) {
        this.memoryStore.set(key, refreshToken);
        // Set cleanup timeout
        setTimeout(() => {
          this.memoryStore.delete(key);
        }, ttl * 1000);
      } else {
        await this.redisClient.setEx(key, ttl, refreshToken);
      }

    } catch (error) {
      logger.error('Refresh token storage failed:', error);
      throw new AppError('Failed to store refresh token', 500);
    }
  }

  /**
   * Get stored refresh token
   */
  async getStoredRefreshToken(userId) {
    try {
      const key = `refresh:${userId}`;
      
      if (this.useMemoryFallback) {
        return this.memoryStore.get(key) || null;
      } else {
        return await this.redisClient.get(key);
      }
    } catch (error) {
      logger.error('Refresh token retrieval failed:', error);
      return null;
    }
  }

  /**
   * Clear refresh token
   */
  async clearRefreshToken(userId) {
    try {
      const key = `refresh:${userId}`;
      
      if (this.useMemoryFallback) {
        this.memoryStore.delete(key);
      } else {
        await this.redisClient.del(key);
      }
    } catch (error) {
      logger.error('Refresh token clearing failed:', error);
    }
  }

  /**
   * Store password reset token
   */
  async storePasswordResetToken(userId, token, expiresAt) {
    try {
      const key = `password_reset:${userId}`;
      const data = {
        token: await this.hashToken(token),
        expiresAt: expiresAt.toISOString(),
        createdAt: new Date().toISOString()
      };

      const ttl = Math.ceil((expiresAt.getTime() - Date.now()) / 1000);

      if (this.useMemoryFallback) {
        this.memoryStore.set(key, data);
        // Set cleanup timeout
        setTimeout(() => {
          this.memoryStore.delete(key);
        }, ttl * 1000);
      } else {
        await this.redisClient.setEx(key, ttl, JSON.stringify(data));
      }

      return token; // Return original token for email

    } catch (error) {
      logger.error('Password reset token storage failed:', error);
      throw new AppError('Failed to generate password reset token', 500);
    }
  }

  /**
   * Verify password reset token
   */
  async verifyPasswordResetToken(token) {
    try {
      const hashedToken = await this.hashToken(token);

      // Find user with this token (in a real implementation, you'd store userId with token)
      const users = await User.find({ isActive: true });
      
      for (const user of users) {
        const key = `password_reset:${user._id}`;
        let storedData;

        if (this.useMemoryFallback) {
          storedData = this.memoryStore.get(key);
        } else {
          const result = await this.redisClient.get(key);
          storedData = result ? JSON.parse(result) : null;
        }

        if (storedData && storedData.token === hashedToken) {
          const expiresAt = new Date(storedData.expiresAt);
          if (new Date() <= expiresAt) {
            return user._id.toString();
          } else {
            // Token expired, clean up
            await this.clearPasswordResetToken(user._id.toString());
          }
        }
      }

      return null; // Token not found or expired

    } catch (error) {
      logger.error('Password reset token verification failed:', error);
      return null;
    }
  }

  /**
   * Clear password reset token
   */
  async clearPasswordResetToken(userId) {
    try {
      const key = `password_reset:${userId}`;
      
      if (this.useMemoryFallback) {
        this.memoryStore.delete(key);
      } else {
        await this.redisClient.del(key);
      }
    } catch (error) {
      logger.error('Password reset token clearing failed:', error);
    }
  }

  /**
   * Hash token for secure storage
   */
  async hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Generate secure random token
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Create session
   */
  async createSession(userId, sessionData = {}) {
    try {
      const sessionId = this.generateSecureToken();
      const key = `session:${sessionId}`;
      
      const session = {
        userId,
        createdAt: new Date().toISOString(),
        lastAccessedAt: new Date().toISOString(),
        ...sessionData
      };

      const ttl = 24 * 60 * 60; // 24 hours

      if (this.useMemoryFallback) {
        this.memoryStore.set(key, session);
        setTimeout(() => {
          this.memoryStore.delete(key);
        }, ttl * 1000);
      } else {
        await this.redisClient.setEx(key, ttl, JSON.stringify(session));
      }

      return sessionId;

    } catch (error) {
      logger.error('Session creation failed:', error);
      throw new AppError('Failed to create session', 500);
    }
  }

  /**
   * Get session
   */
  async getSession(sessionId) {
    try {
      const key = `session:${sessionId}`;
      
      if (this.useMemoryFallback) {
        return this.memoryStore.get(key) || null;
      } else {
        const result = await this.redisClient.get(key);
        return result ? JSON.parse(result) : null;
      }
    } catch (error) {
      logger.error('Session retrieval failed:', error);
      return null;
    }
  }

  /**
   * Update session last accessed time
   */
  async updateSessionAccess(sessionId) {
    try {
      const session = await this.getSession(sessionId);
      if (session) {
        session.lastAccessedAt = new Date().toISOString();
        
        const key = `session:${sessionId}`;
        const ttl = 24 * 60 * 60; // Reset TTL

        if (this.useMemoryFallback) {
          this.memoryStore.set(key, session);
        } else {
          await this.redisClient.setEx(key, ttl, JSON.stringify(session));
        }
      }
    } catch (error) {
      logger.error('Session update failed:', error);
    }
  }

  /**
   * Destroy session
   */
  async destroySession(sessionId) {
    try {
      const key = `session:${sessionId}`;
      
      if (this.useMemoryFallback) {
        this.memoryStore.delete(key);
      } else {
        await this.redisClient.del(key);
      }
    } catch (error) {
      logger.error('Session destruction failed:', error);
    }
  }

  /**
   * Cleanup expired sessions and tokens
   */
  async cleanupExpiredSessions() {
    try {
      if (!this.useMemoryFallback) {
        // Redis handles TTL automatically, but we can run additional cleanup
        const pattern = 'session:*';
        const keys = await this.redisClient.keys(pattern);
        
        for (const key of keys) {
          const ttl = await this.redisClient.ttl(key);
          if (ttl <= 0) {
            await this.redisClient.del(key);
          }
        }
      }
      
      logger.info('Session cleanup completed');
    } catch (error) {
      logger.error('Session cleanup failed:', error);
    }
  }

  /**
   * Get user's active sessions
   */
  async getUserSessions(userId) {
    try {
      const sessions = [];
      
      if (this.useMemoryFallback) {
        for (const [key, session] of this.memoryStore.entries()) {
          if (key.startsWith('session:') && session.userId === userId) {
            sessions.push({
              sessionId: key.replace('session:', ''),
              ...session
            });
          }
        }
      } else {
        const pattern = 'session:*';
        const keys = await this.redisClient.keys(pattern);
        
        for (const key of keys) {
          const sessionData = await this.redisClient.get(key);
          if (sessionData) {
            const session = JSON.parse(sessionData);
            if (session.userId === userId) {
              sessions.push({
                sessionId: key.replace('session:', ''),
                ...session
              });
            }
          }
        }
      }

      return sessions;
    } catch (error) {
      logger.error('Get user sessions failed:', error);
      return [];
    }
  }

  /**
   * Revoke all user sessions
   */
  async revokeAllUserSessions(userId) {
    try {
      const sessions = await this.getUserSessions(userId);
      
      for (const session of sessions) {
        await this.destroySession(session.sessionId);
      }
      
      // Also clear refresh token
      await this.clearRefreshToken(userId);

      logger.info(`Revoked ${sessions.length} sessions for user ${userId}`);
      return sessions.length;

    } catch (error) {
      logger.error('Revoke user sessions failed:', error);
      return 0;
    }
  }

  /**
   * Validate password strength
   */
  validatePasswordStrength(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const errors = [];

    if (password.length < minLength) {
      errors.push(`Password must be at least ${minLength} characters long`);
    }
    if (!hasUpperCase) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!hasLowerCase) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!hasNumbers) {
      errors.push('Password must contain at least one number');
    }
    if (!hasSpecialChar) {
      errors.push('Password must contain at least one special character');
    }

    return {
      isValid: errors.length === 0,
      errors,
      strength: this.calculatePasswordStrength(password)
    };
  }

  /**
   * Calculate password strength score
   */
  calculatePasswordStrength(password) {
    let score = 0;
    
    // Length
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    
    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    
    // Patterns
    if (!/(.)\1{2,}/.test(password)) score += 1; // No repeated characters
    if (!/123|abc|qwe/i.test(password)) score += 1; // No common sequences

    if (score <= 3) return 'weak';
    if (score <= 5) return 'medium';
    if (score <= 7) return 'strong';
    return 'very_strong';
  }
}

module.exports = new AuthService();
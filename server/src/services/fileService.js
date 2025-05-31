// 📁 server/src/services/fileService.js
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class FileService {
  constructor() {
    this.uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, '../../uploads');
    this.maxFileSize = parseInt(process.env.MAX_FILE_SIZE) || 10485760; // 10MB
    this.allowedMimeTypes = [
      'image/jpeg',
      'image/jpg', 
      'image/png',
      'image/tiff',
      'image/tif'
    ];
    
    this.initializeDirectories();
  }

  /**
   * Initialize upload directories
   */
  async initializeDirectories() {
    try {
      // Create main upload directory
      await fs.mkdir(this.uploadDir, { recursive: true });
      
      // Create subdirectories for organization
      const subdirs = ['images', 'thumbnails', 'temp', 'exports'];
      for (const subdir of subdirs) {
        await fs.mkdir(path.join(this.uploadDir, subdir), { recursive: true });
      }
      
      logger.info(`File upload directories initialized at: ${this.uploadDir}`);
    } catch (error) {
      logger.error('Failed to initialize upload directories:', error);
      throw new AppError('Failed to initialize file storage', 500);
    }
  }

  /**
   * Validate uploaded image file
   */
  async validateImageFile(file, config = {}) {
    const validation = {
      isValid: true,
      errors: [],
      warnings: [],
      metadata: {}
    };

    try {
      // Use provided config or defaults
      const maxSize = config.maxFileSize || this.maxFileSize;
      const allowedTypes = config.allowedTypes || this.allowedMimeTypes;

      // Check file existence
      if (!file) {
        validation.isValid = false;
        validation.errors.push('No file provided');
        return validation;
      }

      // Check file size
      if (file.size > maxSize) {
        validation.isValid = false;
        validation.errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed size (${this.formatFileSize(maxSize)})`);
      }

      // Check MIME type
      if (!allowedTypes.includes(file.mimetype)) {
        validation.isValid = false;
        validation.errors.push(`File type ${file.mimetype} is not supported. Allowed types: ${allowedTypes.join(', ')}`);
      }

      // Check file extension
      const ext = path.extname(file.originalname).toLowerCase();
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.tiff', '.tif'];
      if (!allowedExtensions.includes(ext)) {
        validation.isValid = false;
        validation.errors.push(`File extension ${ext} is not supported`);
      }

      // If file is valid, get image metadata
      if (validation.isValid && file.buffer) {
        try {
          const metadata = await sharp(file.buffer).metadata();
          validation.metadata = {
            width: metadata.width,
            height: metadata.height,
            format: metadata.format,
            space: metadata.space,
            channels: metadata.channels,
            depth: metadata.depth,
            density: metadata.density,
            hasProfile: metadata.hasProfile,
            hasAlpha: metadata.hasAlpha
          };

          // Validate image dimensions
          if (metadata.width < 100 || metadata.height < 100) {
            validation.warnings.push('Image resolution is very low, this may affect diagnosis accuracy');
          }

          if (metadata.width > 4000 || metadata.height > 4000) {
            validation.warnings.push('Image resolution is very high, consider resizing for faster processing');
          }

          // Check aspect ratio
          const aspectRatio = metadata.width / metadata.height;
          if (aspectRatio < 0.5 || aspectRatio > 2) {
            validation.warnings.push('Unusual aspect ratio detected');
          }

        } catch (metadataError) {
          validation.warnings.push('Could not read image metadata');
          logger.warn('Image metadata extraction failed:', metadataError);
        }
      }

      // Additional file content validation
      if (file.buffer) {
        // Check for common file corruption indicators
        if (file.buffer.length === 0) {
          validation.isValid = false;
          validation.errors.push('File appears to be empty');
        }

        // Basic magic number check for JPEG/PNG
        if (file.mimetype === 'image/jpeg' && !this.isValidJPEG(file.buffer)) {
          validation.warnings.push('File may be corrupted or not a valid JPEG');
        }
        
        if (file.mimetype === 'image/png' && !this.isValidPNG(file.buffer)) {
          validation.warnings.push('File may be corrupted or not a valid PNG');
        }
      }

    } catch (error) {
      validation.isValid = false;
      validation.errors.push(`File validation error: ${error.message}`);
      logger.error('File validation error:', error);
    }

    return validation;
  }

  /**
   * Save uploaded file to disk
   */
  async saveUploadedFile(file, sessionId) {
    try {
      // Generate unique filename
      const timestamp = Date.now();
      const randomString = crypto.randomBytes(8).toString('hex');
      const extension = path.extname(file.originalname).toLowerCase();
      const filename = `${sessionId}_${timestamp}_${randomString}${extension}`;
      
      // Create file path
      const relativePath = path.join('images', filename);
      const fullPath = path.join(this.uploadDir, relativePath);

      // Save file
      await fs.writeFile(fullPath, file.buffer);

      // Generate thumbnail
      const thumbnailPath = await this.generateThumbnail(fullPath, filename);

      // Get file stats
      const stats = await fs.stat(fullPath);

      logger.info(`File saved successfully: ${filename}`);

      return {
        filename,
        originalName: file.originalname,
        path: fullPath,
        relativePath,
        size: stats.size,
        mimetype: file.mimetype,
        thumbnailPath,
        savedAt: new Date(),
        metadata: await this.getImageMetadata(fullPath)
      };

    } catch (error) {
      logger.error('File save error:', error);
      throw new AppError(`Failed to save file: ${error.message}`, 500);
    }
  }

  /**
   * Generate thumbnail for image
   */
  async generateThumbnail(imagePath, filename) {
    try {
      const thumbnailFilename = `thumb_${filename}`;
      const thumbnailPath = path.join(this.uploadDir, 'thumbnails', thumbnailFilename);

      await sharp(imagePath)
        .resize(200, 200, {
          fit: 'inside',
          withoutEnlargement: true
        })
        .jpeg({ quality: 80 })
        .toFile(thumbnailPath);

      return thumbnailPath;

    } catch (error) {
      logger.warn('Thumbnail generation failed:', error);
      return null;
    }
  }

  /**
   * Get image metadata using Sharp
   */
  async getImageMetadata(imagePath) {
    try {
      const metadata = await sharp(imagePath).metadata();
      return {
        width: metadata.width,
        height: metadata.height,
        format: metadata.format,
        space: metadata.space,
        channels: metadata.channels,
        depth: metadata.depth,
        density: metadata.density,
        hasProfile: metadata.hasProfile,
        hasAlpha: metadata.hasAlpha,
        orientation: metadata.orientation
      };
    } catch (error) {
      logger.warn('Metadata extraction failed:', error);
      return {};
    }
  }

  /**
   * Delete file from disk
   */
  async deleteFile(filePath) {
    try {
      // Delete main file
      await fs.unlink(filePath);

      // Delete thumbnail if exists
      const filename = path.basename(filePath);
      const thumbnailPath = path.join(this.uploadDir, 'thumbnails', `thumb_${filename}`);
      
      try {
        await fs.unlink(thumbnailPath);
      } catch (thumbError) {
        // Thumbnail deletion failure is not critical
        logger.debug('Thumbnail deletion failed (may not exist):', thumbError);
      }

      logger.info(`File deleted successfully: ${filePath}`);

    } catch (error) {
      logger.error('File deletion error:', error);
      throw new AppError(`Failed to delete file: ${error.message}`, 500);
    }
  }

  /**
   * Get image URL for serving
   */
  async getImageUrl(filePath) {
    try {
      // In development, return local file path
      // In production, this would return a signed URL or CDN URL
      const relativePath = path.relative(this.uploadDir, filePath);
      return `/uploads/${relativePath.replace(/\\/g, '/')}`;
    } catch (error) {
      logger.error('Get image URL error:', error);
      return null;
    }
  }

  /**
   * Get thumbnail URL
   */
  async getThumbnailUrl(filename) {
    try {
      const thumbnailFilename = `thumb_${filename}`;
      return `/uploads/thumbnails/${thumbnailFilename}`;
    } catch (error) {
      logger.error('Get thumbnail URL error:', error);
      return null;
    }
  }

  /**
   * Resize image for analysis
   */
  async resizeImageForAnalysis(imagePath, maxWidth = 2000, maxHeight = 2000) {
    try {
      const outputPath = imagePath.replace(/(\.[^.]+)$/, '_resized$1');
      
      await sharp(imagePath)
        .resize(maxWidth, maxHeight, {
          fit: 'inside',
          withoutEnlargement: true
        })
        .jpeg({ quality: 95 }) // High quality for analysis
        .toFile(outputPath);

      return outputPath;

    } catch (error) {
      logger.error('Image resize error:', error);
      throw new AppError(`Failed to resize image: ${error.message}`, 500);
    }
  }

  /**
   * Optimize image for storage
   */
  async optimizeImage(imagePath, quality = 85) {
    try {
      const optimizedPath = imagePath.replace(/(\.[^.]+)$/, '_optimized$1');
      
      const image = sharp(imagePath);
      const metadata = await image.metadata();

      // Apply optimization based on format
      if (metadata.format === 'jpeg') {
        await image
          .jpeg({ quality, progressive: true })
          .toFile(optimizedPath);
      } else if (metadata.format === 'png') {
        await image
          .png({ compressionLevel: 8, progressive: true })
          .toFile(optimizedPath);
      } else {
        // Convert to JPEG for other formats
        await image
          .jpeg({ quality, progressive: true })
          .toFile(optimizedPath);
      }

      return optimizedPath;

    } catch (error) {
      logger.error('Image optimization error:', error);
      throw new AppError(`Failed to optimize image: ${error.message}`, 500);
    }
  }

  /**
   * Validate JPEG file signature
   */
  isValidJPEG(buffer) {
    // JPEG files start with FF D8 and end with FF D9
    if (buffer.length < 4) return false;
    return buffer[0] === 0xFF && buffer[1] === 0xD8 && 
           buffer[buffer.length - 2] === 0xFF && buffer[buffer.length - 1] === 0xD9;
  }

  /**
   * Validate PNG file signature
   */
  isValidPNG(buffer) {
    // PNG files start with specific signature
    if (buffer.length < 8) return false;
    const pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    return pngSignature.every((byte, index) => buffer[index] === byte);
  }

  /**
   * Format file size for display
   */
  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Clean up temporary files
   */
  async cleanupTempFiles(olderThanHours = 24) {
    try {
      const tempDir = path.join(this.uploadDir, 'temp');
      const files = await fs.readdir(tempDir);
      const cutoffTime = Date.now() - (olderThanHours * 60 * 60 * 1000);
      
      let deletedCount = 0;
      
      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = await fs.stat(filePath);
        
        if (stats.mtime.getTime() < cutoffTime) {
          await fs.unlink(filePath);
          deletedCount++;
        }
      }
      
      logger.info(`Cleaned up ${deletedCount} temporary files`);
      return deletedCount;

    } catch (error) {
      logger.error('Temp file cleanup error:', error);
      return 0;
    }
  }

  /**
   * Get storage statistics
   */
  async getStorageStats() {
    try {
      const stats = {
        directories: {},
        totalSize: 0,
        totalFiles: 0
      };

      const subdirs = ['images', 'thumbnails', 'temp', 'exports'];
      
      for (const subdir of subdirs) {
        const dirPath = path.join(this.uploadDir, subdir);
        const dirStats = await this.getDirectoryStats(dirPath);
        stats.directories[subdir] = dirStats;
        stats.totalSize += dirStats.size;
        stats.totalFiles += dirStats.files;
      }

      return stats;

    } catch (error) {
      logger.error('Storage stats error:', error);
      return {
        directories: {},
        totalSize: 0,
        totalFiles: 0,
        error: error.message
      };
    }
  }

  /**
   * Get directory statistics
   */
  async getDirectoryStats(dirPath) {
    try {
      const files = await fs.readdir(dirPath);
      let totalSize = 0;
      let fileCount = 0;

      for (const file of files) {
        const filePath = path.join(dirPath, file);
        const stats = await fs.stat(filePath);
        
        if (stats.isFile()) {
          totalSize += stats.size;
          fileCount++;
        }
      }

      return {
        size: totalSize,
        files: fileCount,
        sizeFormatted: this.formatFileSize(totalSize)
      };

    } catch (error) {
      return {
        size: 0,
        files: 0,
        sizeFormatted: '0 Bytes',
        error: error.message
      };
    }
  }

  /**
   * Create backup of files
   */
  async createBackup(filePaths, backupName) {
    try {
      const backupDir = path.join(this.uploadDir, 'backups', backupName);
      await fs.mkdir(backupDir, { recursive: true });

      const copiedFiles = [];
      
      for (const filePath of filePaths) {
        const filename = path.basename(filePath);
        const backupPath = path.join(backupDir, filename);
        
        await fs.copyFile(filePath, backupPath);
        copiedFiles.push(filename);
      }

      logger.info(`Created backup with ${copiedFiles.length} files: ${backupName}`);
      return {
        backupPath: backupDir,
        files: copiedFiles,
        createdAt: new Date()
      };

    } catch (error) {
      logger.error('Backup creation error:', error);
      throw new AppError(`Failed to create backup: ${error.message}`, 500);
    }
  }

  /**
   * Check file exists
   */
  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Move file to different location
   */
  async moveFile(sourcePath, destinationPath) {
    try {
      // Ensure destination directory exists
      const destDir = path.dirname(destinationPath);
      await fs.mkdir(destDir, { recursive: true });

      // Move file
      await fs.rename(sourcePath, destinationPath);
      
      logger.info(`File moved from ${sourcePath} to ${destinationPath}`);
      return destinationPath;

    } catch (error) {
      logger.error('File move error:', error);
      throw new AppError(`Failed to move file: ${error.message}`, 500);
    }
  }

  /**
   * Copy file to different location
   */
  async copyFile(sourcePath, destinationPath) {
    try {
      // Ensure destination directory exists
      const destDir = path.dirname(destinationPath);
      await fs.mkdir(destDir, { recursive: true });

      // Copy file
      await fs.copyFile(sourcePath, destinationPath);
      
      logger.info(`File copied from ${sourcePath} to ${destinationPath}`);
      return destinationPath;

    } catch (error) {
      logger.error('File copy error:', error);
      throw new AppError(`Failed to copy file: ${error.message}`, 500);
    }
  }
}

module.exports = new FileService();
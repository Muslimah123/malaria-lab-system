// 📁 server/src/middleware/fileUpload.js
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

// Configure storage
const storage = multer.memoryStorage(); // Store in memory for processing

// File filter function
const fileFilter = (req, file, cb) => {
  try {
    // Allowed MIME types for medical images
    const allowedMimeTypes = [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/tiff',
      'image/tif'
    ];

    // Allowed file extensions
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.tiff', '.tif'];
    const fileExtension = path.extname(file.originalname).toLowerCase();

    // Check MIME type
    if (!allowedMimeTypes.includes(file.mimetype)) {
      logger.warn(`File upload rejected - invalid MIME type: ${file.mimetype}`);
      return cb(new AppError(`File type ${file.mimetype} is not supported. Allowed types: ${allowedMimeTypes.join(', ')}`, 400), false);
    }

    // Check file extension
    if (!allowedExtensions.includes(fileExtension)) {
      logger.warn(`File upload rejected - invalid extension: ${fileExtension}`);
      return cb(new AppError(`File extension ${fileExtension} is not supported. Allowed extensions: ${allowedExtensions.join(', ')}`, 400), false);
    }

    // Check filename for dangerous characters
    const dangerousChars = /[<>:"|?*\x00-\x1f]/;
    if (dangerousChars.test(file.originalname)) {
      logger.warn(`File upload rejected - dangerous filename: ${file.originalname}`);
      return cb(new AppError('Filename contains invalid characters', 400), false);
    }

    // Check filename length
    if (file.originalname.length > 255) {
      logger.warn(`File upload rejected - filename too long: ${file.originalname.length} characters`);
      return cb(new AppError('Filename is too long (maximum 255 characters)', 400), false);
    }

    // Log successful file validation
    logger.debug(`File upload validated: ${file.originalname} (${file.mimetype})`);
    cb(null, true);

  } catch (error) {
    logger.error('File filter error:', error);
    cb(new AppError('File validation failed', 500), false);
  }
};

// Configure multer
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB default
    files: parseInt(process.env.MAX_FILES_PER_REQUEST) || 20, // 20 files max
    fields: 10,
    fieldNameSize: 100,
    fieldSize: 1024 * 1024, // 1MB for form fields
    headerPairs: 2000
  }
});

/**
 * Enhanced file upload middleware with additional validation
 */
const enhancedFileUpload = (fieldName, maxCount = 20) => {
  return [
    // Rate limiting for file uploads
    (req, res, next) => {
      // Check if user has too many concurrent uploads
      const userUploads = global.activeUploads?.get?.(req.user?._id) || 0;
      const maxConcurrentUploads = 5;

      if (userUploads >= maxConcurrentUploads) {
        return res.status(429).json({
          success: false,
          message: 'Too many concurrent uploads. Please wait and try again.',
          retryAfter: 30
        });
      }

      next();
    },

    // Main multer middleware
    upload.array(fieldName, maxCount),

    // Post-upload validation
    async (req, res, next) => {
      try {
        if (!req.files || req.files.length === 0) {
          return next(); // No files to validate
        }

        const validationErrors = [];
        const validatedFiles = [];

        for (let i = 0; i < req.files.length; i++) {
          const file = req.files[i];
          const fileValidation = await validateIndividualFile(file, i);

          if (fileValidation.isValid) {
            validatedFiles.push(file);
          } else {
            validationErrors.push(...fileValidation.errors);
          }
        }

        // If any files failed validation, reject the entire upload
        if (validationErrors.length > 0) {
          logger.warn('File upload validation failed:', validationErrors);
          return res.status(400).json({
            success: false,
            message: 'File validation failed',
            errors: validationErrors
          });
        }

        // Replace req.files with only validated files
        req.files = validatedFiles;

        // Add upload metadata
        req.uploadMetadata = {
          totalFiles: validatedFiles.length,
          totalSize: validatedFiles.reduce((sum, file) => sum + file.size, 0),
          uploadedAt: new Date(),
          uploadedBy: req.user?._id
        };

        logger.info(`File upload successful: ${validatedFiles.length} files, total size: ${formatFileSize(req.uploadMetadata.totalSize)}`);
        next();

      } catch (error) {
        logger.error('Post-upload validation error:', error);
        next(new AppError('File upload validation failed', 500));
      }
    }
  ];
};

/**
 * Validate individual uploaded file
 */
async function validateIndividualFile(file, index) {
  const validation = {
    isValid: true,
    errors: []
  };

  try {
    // Check if file buffer exists
    if (!file.buffer || file.buffer.length === 0) {
      validation.isValid = false;
      validation.errors.push(`File ${index + 1}: Empty file buffer`);
      return validation;
    }

    // Validate file size
    if (file.size === 0) {
      validation.isValid = false;
      validation.errors.push(`File ${index + 1}: File is empty`);
    }

    // Check for minimum file size (avoid tiny corrupt files)
    if (file.size < 1024) { // 1KB minimum
      validation.isValid = false;
      validation.errors.push(`File ${index + 1}: File too small (minimum 1KB)`);
    }

    // Validate file signature (magic numbers)
    const fileSignature = await validateFileSignature(file.buffer, file.mimetype);
    if (!fileSignature.isValid) {
      validation.isValid = false;
      validation.errors.push(`File ${index + 1}: ${fileSignature.error}`);
    }

    // Check for image dimensions if it's an image
    if (file.mimetype.startsWith('image/')) {
      const imageValidation = await validateImageDimensions(file.buffer);
      if (!imageValidation.isValid) {
        validation.isValid = false;
        validation.errors.push(`File ${index + 1}: ${imageValidation.error}`);
      }
    }

    // Scan for potential malware (basic checks)
    const malwareCheck = await basicMalwareCheck(file.buffer, file.originalname);
    if (!malwareCheck.isValid) {
      validation.isValid = false;
      validation.errors.push(`File ${index + 1}: ${malwareCheck.error}`);
    }

  } catch (error) {
    validation.isValid = false;
    validation.errors.push(`File ${index + 1}: Validation error - ${error.message}`);
  }

  return validation;
}

/**
 * Validate file signature (magic numbers)
 */
async function validateFileSignature(buffer, mimeType) {
  const signatures = {
    'image/jpeg': [
      [0xFF, 0xD8, 0xFF], // JPEG
      [0xFF, 0xD8, 0xFF, 0xE0], // JPEG/JFIF
      [0xFF, 0xD8, 0xFF, 0xE1] // JPEG/EXIF
    ],
    'image/png': [
      [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] // PNG
    ],
    'image/tiff': [
      [0x49, 0x49, 0x2A, 0x00], // TIFF (little endian)
      [0x4D, 0x4D, 0x00, 0x2A]  // TIFF (big endian)
    ]
  };

  const expectedSignatures = signatures[mimeType];
  if (!expectedSignatures) {
    return { isValid: true }; // No signature check for this type
  }

  const isValid = expectedSignatures.some(signature => {
    return signature.every((byte, index) => buffer[index] === byte);
  });

  return {
    isValid,
    error: isValid ? null : 'File signature does not match the declared file type'
  };
}

/**
 * Validate image dimensions
 */
async function validateImageDimensions(buffer) {
  try {
    const sharp = require('sharp');
    const metadata = await sharp(buffer).metadata();

    const minWidth = 50;
    const minHeight = 50;
    const maxWidth = 10000;
    const maxHeight = 10000;

    if (metadata.width < minWidth || metadata.height < minHeight) {
      return {
        isValid: false,
        error: `Image dimensions too small (minimum ${minWidth}x${minHeight})`
      };
    }

    if (metadata.width > maxWidth || metadata.height > maxHeight) {
      return {
        isValid: false,
        error: `Image dimensions too large (maximum ${maxWidth}x${maxHeight})`
      };
    }

    return { isValid: true };

  } catch (error) {
    return {
      isValid: false,
      error: 'Unable to read image metadata - file may be corrupted'
    };
  }
}

/**
 * Basic malware check (simple patterns)
 */
async function basicMalwareCheck(buffer, filename) {
  try {
    const bufferString = buffer.toString('utf8', 0, Math.min(buffer.length, 10000));
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /vbscript:/gi,
      /onload\s*=/gi,
      /onerror\s*=/gi,
      /document\.write/gi,
      /eval\s*\(/gi
    ];

    const foundPattern = suspiciousPatterns.find(pattern => pattern.test(bufferString));
    if (foundPattern) {
      return {
        isValid: false,
        error: 'File contains suspicious content'
      };
    }

    // Check filename for suspicious extensions
    const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.php'];
    const hasMultipleExtensions = (filename.match(/\./g) || []).length > 1;
    const hasSuspiciousExtension = suspiciousExtensions.some(ext => 
      filename.toLowerCase().includes(ext)
    );

    if (hasMultipleExtensions && hasSuspiciousExtension) {
      return {
        isValid: false,
        error: 'Suspicious filename detected'
      };
    }

    return { isValid: true };

  } catch (error) {
    // If check fails, allow file (fail open for availability)
    logger.warn('Malware check failed:', error);
    return { isValid: true };
  }
}

/**
 * Middleware to handle upload errors
 */
const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    let message = 'File upload error';
    let statusCode = 400;

    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        message = `File too large. Maximum size is ${formatFileSize(error.limit)}`;
        break;
      case 'LIMIT_FILE_COUNT':
        message = `Too many files. Maximum is ${error.limit} files`;
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        message = `Unexpected file field: ${error.field}`;
        break;
      case 'LIMIT_PART_COUNT':
        message = 'Too many form parts';
        break;
      case 'LIMIT_FIELD_KEY':
        message = 'Field name too long';
        break;
      case 'LIMIT_FIELD_VALUE':
        message = 'Field value too long';
        break;
      case 'LIMIT_FIELD_COUNT':
        message = 'Too many fields';
        break;
      default:
        message = `Upload error: ${error.message}`;
    }

    logger.warn('Multer upload error:', { code: error.code, message: error.message });

    return res.status(statusCode).json({
      success: false,
      message,
      code: error.code
    });
  }

  if (error instanceof AppError) {
    return res.status(error.statusCode).json({
      success: false,
      message: error.message
    });
  }

  logger.error('Unexpected upload error:', error);
  return res.status(500).json({
    success: false,
    message: 'File upload failed'
  });
};

/**
 * Middleware to clean up uploaded files on error
 */
const cleanupOnError = (req, res, next) => {
  const originalSend = res.send;

  res.send = function(data) {
    // If response is an error and we have files, clean them up
    if (res.statusCode >= 400 && req.files) {
      setImmediate(() => {
        req.files.forEach(file => {
          if (file.path) {
            fs.unlink(file.path, (err) => {
              if (err) logger.warn('Failed to cleanup uploaded file:', err);
            });
          }
        });
      });
    }

    return originalSend.call(this, data);
  };

  next();
};

/**
 * Format file size for display
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Track concurrent uploads globally
 */
if (!global.activeUploads) {
  global.activeUploads = new Map();
}

/**
 * Middleware to track upload start
 */
const trackUploadStart = (req, res, next) => {
  if (req.user) {
    const currentCount = global.activeUploads.get(req.user._id) || 0;
    global.activeUploads.set(req.user._id, currentCount + 1);
  }
  next();
};

/**
 * Middleware to track upload end
 */
const trackUploadEnd = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    if (req.user) {
      const currentCount = global.activeUploads.get(req.user._id) || 0;
      if (currentCount > 0) {
        global.activeUploads.set(req.user._id, currentCount - 1);
      }
    }
    return originalSend.call(this, data);
  };
  
  next();
};

module.exports = {
  fileUpload: enhancedFileUpload('files'),
  singleFileUpload: upload.single('file'),
  handleUploadError,
  cleanupOnError,
  trackUploadStart,
  trackUploadEnd,
  validateIndividualFile,
  formatFileSize
};

//  server/src/services/diagnosisService.js
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class DiagnosisService {
  constructor() {
    this.flaskApiUrl = process.env.FLASK_API_URL || 'http://flask-api:5000';
    this.apiTimeout = parseInt(process.env.FLASK_API_TIMEOUT) || 300000; // 5 minutes
    this.retryAttempts = parseInt(process.env.FLASK_API_RETRY_ATTEMPTS) || 3;
    this.retryDelay = parseInt(process.env.FLASK_API_RETRY_DELAY) || 5000; // 5 seconds
    this.useSharedVolume = process.env.USE_SHARED_VOLUME === 'true' || true;
  }

  /**
   * Analyze blood sample images using Flask API
   * @param {string[]} imagePaths - Array of image file paths
   * @returns {Object} - Diagnosis result from Flask API
   */
  async analyzeSample(imagePaths) {
    try {
      logger.info(`Starting diagnosis analysis for ${imagePaths.length} images`);

      // Validate input
      if (!imagePaths || imagePaths.length === 0) {
        throw new AppError('No images provided for analysis', 400);
      }

      // Validate image files exist
      await this.validateImageFiles(imagePaths);

      // Check Flask API health first
      await this.checkFlaskApiHealth();

      let response;
      
      if (this.useSharedVolume) {
        // Use shared volume approach - send file paths
        response = await this.analyzeWithPaths(imagePaths);
      } else {
        // Use file upload approach - send file data
        response = await this.analyzeWithFileUpload(imagePaths);
      }

      // Validate and process response
      const processedResult = await this.processFlaskResponse(response.data);

      logger.info(`Diagnosis analysis completed successfully - Status: ${processedResult.status}`);

      return processedResult;

    } catch (error) {
      logger.error('Diagnosis analysis failed:', error);
      
      if (error instanceof AppError) {
        throw error;
      }
      
      // Wrap unexpected errors
      throw new AppError(`Diagnosis analysis failed: ${error.message}`, 500);
    }
  }

  /**
   * ✅ FIXED: Analyze using shared volume (send paths to Flask)
   */
  async analyzeWithPaths(imagePaths) {
    try {
      // ✅ FIXED: No path conversion needed - both containers use /app/uploads
      logger.info('Using shared volume approach - sending paths to Flask');
      logger.info('Image paths being sent to Flask:', imagePaths);

      const requestData = {
        image_paths: imagePaths,  // ✅ Send paths as-is
        metadata: {
          timestamp: new Date().toISOString(),
          source: 'malaria-lab-system',
          analysis_type: 'malaria_detection'
        }
      };

      const response = await this.callFlaskApiWithRetry(`${this.flaskApiUrl}/diagnose`, requestData, 'json');
      return response;

    } catch (error) {
      logger.error('Shared volume analysis failed:', error);
      
      // If shared volume fails, try file upload as fallback
      if (error.response?.status === 400) {
        logger.info('Falling back to file upload approach');
        return await this.analyzeWithFileUpload(imagePaths);
      }
      
      throw error;
    }
  }

  /**
   * Analyze using file upload (send file data to Flask)
   */
  async analyzeWithFileUpload(imagePaths) {
    try {
      logger.info('Using file upload approach - sending files to Flask');

      const formData = await this.prepareFormData(imagePaths);

      const response = await this.callFlaskApiWithRetry(`${this.flaskApiUrl}/analyze`, formData, 'form');
      return response;

    } catch (error) {
      logger.error('File upload analysis failed:', error);
      throw error;
    }
  }

  /**
   * Validate that all image files exist and are readable
   */
  async validateImageFiles(imagePaths) {
    const validationPromises = imagePaths.map(async (imagePath) => {
      try {
        const stats = await fs.promises.stat(imagePath);
        
        if (!stats.isFile()) {
          throw new Error(`Path is not a file: ${imagePath}`);
        }

        // Check file size (should be reasonable for image)
        if (stats.size === 0) {
          throw new Error(`File is empty: ${imagePath}`);
        }

        if (stats.size > 50 * 1024 * 1024) { // 50MB limit
          throw new Error(`File too large: ${imagePath}`);
        }

        // Check file extension
        const ext = path.extname(imagePath).toLowerCase();
        const allowedExtensions = ['.jpg', '.jpeg', '.png', '.tiff', '.tif'];
        
        if (!allowedExtensions.includes(ext)) {
          throw new Error(`Unsupported file format: ${imagePath}`);
        }

        return true;
      } catch (error) {
        throw new AppError(`Image validation failed for ${imagePath}: ${error.message}`, 400);
      }
    });

    await Promise.all(validationPromises);
  }

  /**
   * Prepare FormData for Flask API request
   */
  async prepareFormData(imagePaths) {
    const formData = new FormData();

    // Add each image file to form data
    for (let i = 0; i < imagePaths.length; i++) {
      const imagePath = imagePaths[i];
      const fileName = path.basename(imagePath);
      
      try {
        const fileStream = fs.createReadStream(imagePath);
        formData.append('files', fileStream, {
          filename: fileName,
          contentType: this.getContentType(path.extname(fileName))
        });
        
        logger.debug(`Added file to form data: ${fileName}`);
      } catch (error) {
        throw new AppError(`Failed to read image file: ${imagePath}`, 500);
      }
    }

    // Add any additional parameters
    formData.append('analysis_type', 'malaria_detection');
    formData.append('timestamp', new Date().toISOString());

    return formData;
  }

  /**
   * Get content type for image file
   */
  getContentType(extension) {
    const contentTypes = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.tiff': 'image/tiff',
      '.tif': 'image/tiff'
    };

    return contentTypes[extension.toLowerCase()] || 'image/jpeg';
  }

  /**
   * Call Flask API with retry logic
   */
  async callFlaskApiWithRetry(url, data, type = 'json') {
    let lastError;

    for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
      try {
        logger.info(`Flask API call attempt ${attempt}/${this.retryAttempts}`);

        let config = {
          timeout: this.apiTimeout,
          headers: {
            'X-API-Version': '1.0',
            'X-Request-Source': 'malaria-lab-system'
          }
        };

        if (type === 'form') {
          config.headers = {
            ...config.headers,
            ...data.getHeaders()
          };
          config.maxContentLength = 100 * 1024 * 1024; // 100MB
          config.maxBodyLength = 100 * 1024 * 1024;
        } else {
          config.headers['Content-Type'] = 'application/json';
        }

        const response = await axios.post(url, data, config);

        logger.info(`Flask API call successful on attempt ${attempt}`);
        return response;

      } catch (error) {
        lastError = error;
        
        // Log detailed error information
        const errorDetails = {
          attempt,
          message: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText,
          data: error.response?.data
        };
        
        logger.warn(`Flask API call attempt ${attempt} failed:`, errorDetails);

        // Check if error is retryable
        const isRetryable = this.isRetryableError(error);
        
        if (!isRetryable || attempt === this.retryAttempts) {
          // Don't retry for non-retryable errors or if we've exhausted attempts
          break;
        }

        // Wait before retrying
        if (attempt < this.retryAttempts) {
          const delay = this.retryDelay * attempt; // Exponential backoff
          logger.info(`Waiting ${delay}ms before retry...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    // All attempts failed
    const errorMessage = lastError.response?.data?.message || lastError.message || 'Unknown error';
    throw new AppError(`Flask API call failed after ${this.retryAttempts} attempts: ${errorMessage}`, 503);
  }

  /**
   * Check if Flask API is healthy and reachable
   */
  async checkFlaskApiHealth() {
    try {
      const response = await axios.get(`${this.flaskApiUrl}/health`, {
        timeout: 10000 // 10 seconds timeout for health check
      });
      
      if (response.status === 200 && response.data.status === 'healthy') {
        logger.info('Flask API health check passed');
        return true;
      } else {
        throw new Error(`Flask API unhealthy: ${JSON.stringify(response.data)}`);
      }
    } catch (error) {
      logger.error('Flask API health check failed:', error.message);
      throw new Error('Flask API is not available or not responding to health checks');
    }
  }

  /**
   * ✅ FIXED: Process and validate Flask API response - Now correctly handles Python output
   */
  async processFlaskResponse(responseData) {
    try {
      logger.info('Processing Flask API response...');
      logger.debug('Raw Flask response keys:', Object.keys(responseData));

      // ✅ FIXED: Validate response structure for Python output format
      this.validateFlaskResponse(responseData);

      // ✅ FIXED: Python already returns the correct format - just pass it through with minimal processing
      const processedResult = {
        // ✅ FIXED: No status mapping - Python returns 'POSITIVE'/'NEGATIVE' which schema expects
        status: responseData.status, // 'POSITIVE' or 'NEGATIVE'
        
        // ✅ FIXED: Use camelCase field names that Python returns
        mostProbableParasite: responseData.mostProbableParasite || null,
        parasiteWbcRatio: responseData.parasiteWbcRatio || 0,
        
        // ✅ FIXED: Pass through detections array as-is (Python already returns correct format)
        detections: this.processDetections(responseData.detections || []),
        
        // ✅ FIXED: Include fields that Python returns but original service missed
        totalParasites: responseData.totalParasites || 0,
        totalWbcs: responseData.totalWbcs || 0,
        totalImagesAttempted: responseData.totalImagesAttempted || 0,
        
        // ✅ FIXED: Include analysis summary that Python returns
        analysisSummary: responseData.analysisSummary || {
          parasiteTypesDetected: [],
          avgWbcConfidence: 0,
          totalWbcDetections: 0,
          imagesProcessed: 0
        },
        
        // ✅ ENHANCED: Add processing metadata
        processingMetadata: {
          timestamp: new Date().toISOString(),
          apiVersion: '1.0',
          modelVersion: 'V12.pt',
          processingTime: Date.now() // Could be enhanced to measure actual time
        }
      };

      logger.info(`Processed Flask response - Status: ${processedResult.status}, Parasites: ${processedResult.totalParasites}, WBCs: ${processedResult.totalWbcs}`);
      
      return processedResult;

    } catch (error) {
      logger.error('Flask response processing failed:', error);
      throw new AppError(`Invalid response from Flask API: ${error.message}`, 502);
    }
  }

  /**
   * ✅ FIXED: Validate Flask API response structure - Updated for Python output format
   */
  validateFlaskResponse(responseData) {
    // Check required fields
    if (!responseData.status) {
      throw new Error('Missing required field: status');
    }

    // ✅ FIXED: Validate status values that Python actually returns
    const validStatusValues = ['POSITIVE', 'NEGATIVE'];
    if (!validStatusValues.includes(responseData.status)) {
      throw new Error(`Invalid status value: ${responseData.status}. Expected: ${validStatusValues.join(', ')}`);
    }

    // ✅ FIXED: Updated validation for positive results
    if (responseData.status === 'POSITIVE') {
      if (!responseData.mostProbableParasite) {
        logger.warning('Missing mostProbableParasite for positive result');
      } else {
        // Validate mostProbableParasite structure
        const mpp = responseData.mostProbableParasite;
        if (!mpp.type || mpp.confidence === undefined) {
          throw new Error('Invalid mostProbableParasite structure - missing type or confidence');
        }

        // Validate parasite type
        const validTypes = ['PF', 'PM', 'PO', 'PV'];
        if (!validTypes.includes(mpp.type)) {
          throw new Error(`Invalid parasite type: ${mpp.type}. Expected: ${validTypes.join(', ')}`);
        }

        // Validate confidence
        if (typeof mpp.confidence !== 'number' || mpp.confidence < 0 || mpp.confidence > 1) {
          throw new Error(`Invalid confidence value: ${mpp.confidence}. Must be number between 0 and 1`);
        }
      }
    }

    // Validate detections array
    if (!Array.isArray(responseData.detections)) {
      throw new Error('Detections must be an array');
    }

    logger.info('Flask response validation passed');
  }

  /**
   * ✅ FIXED: Process detections array - Minimal processing since Python returns correct format
   */
  processDetections(detections) {
    return detections.map((detection, index) => {
      try {
        const annotatedUrl = this.getAnnotatedImageUrl(detection.annotatedImagePath);
        // ✅ FIXED: Python already returns camelCase fields - just validate and pass through
        const processedDetection = {
          imageId: detection.imageId || `image_${index}`,
          originalFilename: detection.originalFilename || `image_${index}`,
          
          // ✅ FIXED: Pass through parasite detections as-is (Python returns correct array format)
          parasitesDetected: this.validateAndCleanDetectionArray(detection.parasitesDetected || [], 'parasite'),
          
          // ✅ FIXED: Pass through WBC detections as-is (Python returns correct array format) 
          wbcsDetected: this.validateAndCleanDetectionArray(detection.wbcsDetected || [], 'wbc'),
          
          // ✅ FIXED: Use camelCase field names from Python
          whiteBloodCellsDetected: detection.whiteBloodCellsDetected || 0,
          parasiteCount: detection.parasiteCount || 0,
          parasiteWbcRatio: detection.parasiteWbcRatio || 0,
          annotatedImagePath: detection.annotatedImagePath || null,
          annotatedUrl:annotatedUrl,
          
          // ✅ FIXED: Include metadata that Python returns
          metadata: detection.metadata || {
            totalDetections: 0,
            detectionRate: 1.0
          }
        };

        logger.debug(`Processed detection for ${processedDetection.imageId}: ${processedDetection.parasiteCount} parasites, ${processedDetection.whiteBloodCellsDetected} WBCs`);
        
        return processedDetection;
        
      } catch (error) {
        logger.warn(`Error processing detection ${index}:`, error);
        return {
          imageId: `image_${index}`,
          originalFilename: `image_${index}`,
          parasitesDetected: [],
          wbcsDetected: [],
          whiteBloodCellsDetected: 0,
          parasiteCount: 0,
          parasiteWbcRatio: 0,
          annotatedImagePath: null,
          annotatedUrl: null,
          metadata: { totalDetections: 0, detectionRate: 1.0 },
          error: error.message
        };
      }
    });
  }

  /**
   * ✅ NEW: Validate and clean detection arrays (parasites or WBCs)
   */
  validateAndCleanDetectionArray(detections, type) {
    if (!Array.isArray(detections)) {
      logger.warn(`Invalid ${type} detections - not an array:`, detections);
      return [];
    }

    return detections.map((detection, index) => {
      try {
        // Validate detection structure
        if (!detection.type || detection.confidence === undefined || !detection.bbox) {
          logger.warn(`Invalid ${type} detection structure at index ${index}:`, detection);
          return null;
        }

        // ✅ FIXED: Don't convert bbox - Python returns [x,y,x,y] array which schema expects
        if (!Array.isArray(detection.bbox) || detection.bbox.length !== 4) {
          logger.warn(`Invalid bbox format for ${type} at index ${index}:`, detection.bbox);
          return null;
        }

        // Validate confidence range
        const confidence = Math.max(0, Math.min(1, detection.confidence));
        if (confidence !== detection.confidence) {
          logger.warn(`Clamped confidence for ${type} at index ${index}: ${detection.confidence} → ${confidence}`);
        }

        // ✅ FIXED: Return detection exactly as Python provides it (correct format)
        return {
          type: detection.type,
          confidence: confidence,
          bbox: detection.bbox // Keep as array [x_min, y_min, x_max, y_max]
        };
        
      } catch (error) {
        logger.warn(`Error processing ${type} detection at index ${index}:`, error);
        return null;
      }
    }).filter(detection => detection !== null);
  }

  /**
   * ✅ NEW: Convert annotated image path to full URL
   */
  getAnnotatedImageUrl(annotatedImagePath) {
    if (!annotatedImagePath) return null;
    
    const cleanPath = annotatedImagePath.replace(/^\/+/, '');
    const baseUrl = process.env.API_BASE_URL || 'http://localhost:5000';
    const fullUrl = `${baseUrl}/uploads/${cleanPath}`;
    
    logger.debug(`Converted annotated image path: ${annotatedImagePath} -> ${fullUrl}`);
    
    return fullUrl;
  }

  /**
   * Check if an error is retryable
   */
  isRetryableError(error) {
    // Retry on network errors
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      return true;
    }

    // Retry on 5xx errors (server errors)
    if (error.response?.status >= 500) {
      return true;
    }

    // Don't retry on 4xx errors (client errors) except 429 (rate limit)
    if (error.response?.status >= 400 && error.response?.status < 500) {
      return error.response?.status === 429; // Only retry rate limits
    }

    return false;
  }

  /**
   * Health check for Flask API
   */
  async healthCheck() {
    try {
      const response = await axios.get(`${this.flaskApiUrl}/health`, {
        timeout: 10000 // 10 seconds
      });

      return {
        status: 'healthy',
        version: response.data.version || 'unknown',
        timestamp: new Date().toISOString(),
        response_time: response.headers['x-response-time'] || 'unknown'
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Get Flask API status and capabilities
   */
  async getApiInfo() {
    try {
      const response = await axios.get(`${this.flaskApiUrl}/model_info`, {
        timeout: 10000
      });

      return {
        available: true,
        model: response.data.model || 'V12.pt',
        type: response.data.type || 'YOLO',
        capabilities: response.data.capabilities || {},
        supported_classes: response.data.supported_classes || {},
        confidence_threshold: response.data.confidence_threshold || 0.26
      };
    } catch (error) {
      return {
        available: false,
        error: error.message
      };
    }
  }

  /**
   * Test Flask API with sample data
   */
  async testApiConnection() {
    try {
      logger.info('Testing Flask API connection...');
      
      const healthStatus = await this.healthCheck();
      const apiInfo = await this.getApiInfo();

      return {
        connection: 'successful',
        health: healthStatus,
        info: apiInfo,
        tested_at: new Date().toISOString()
      };
    } catch (error) {
      return {
        connection: 'failed',
        error: error.message,
        tested_at: new Date().toISOString()
      };
    }
  }
}

module.exports = new DiagnosisService();
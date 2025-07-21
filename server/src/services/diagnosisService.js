// 📁 server/src/services/diagnosisService.js
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
   * Analyze using shared volume (send paths to Flask)
   */
  async analyzeWithPaths(imagePaths) {
    try {
      // Convert local paths to shared volume paths that Flask can access
      const sharedPaths = imagePaths.map(localPath => {
        const relativePath = path.relative('/app/uploads', localPath);
        return path.join('/app/shared_uploads', relativePath);
      });

      logger.info('Using shared volume approach - sending paths to Flask');

      const requestData = {
        image_paths: sharedPaths,
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
        
        logger.warn(`Flask API call attempt ${attempt} failed:`, {
          error: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText
        });

        // Don't retry for certain errors
        if (error.response?.status === 400 || error.response?.status === 422) {
          throw new AppError(`Invalid request to Flask API: ${error.response.data?.message || error.message}`, 400);
        }

        // If this isn't the last attempt, wait before retrying
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
   * Process and validate Flask API response
   */
  async processFlaskResponse(responseData) {
    try {
      // Validate response structure
      this.validateFlaskResponse(responseData);

      const mapApiStatus = (status) => {
        const upperStatus = status.toUpperCase();
        if (upperStatus === 'POSITIVE') return 'POS';
        if (upperStatus === 'NEGATIVE') return 'NEG';
        return upperStatus;
      };

      // Process the response according to Flask API format
      const processedResult = {
        status: mapApiStatus(responseData.status), // 'POS' or 'NEG'
        most_probable_parasite: responseData.most_probable_parasite || null,
        parasite_wbc_ratio: responseData.parasite_wbc_ratio || 0,
        detections: this.processDetections(responseData.detections || []),
        overall_confidence: responseData.overall_confidence || 0,
        processing_info: {
          timestamp: new Date().toISOString(),
          api_version: responseData.api_version || '1.0',
          model_version: responseData.model_version || 'unknown',
          processing_time_ms: responseData.processing_time_ms || 0
        },
        raw_response: responseData // Store complete response for debugging
      };

      return processedResult;

    } catch (error) {
      logger.error('Flask response processing failed:', error);
      throw new AppError(`Invalid response from Flask API: ${error.message}`, 502);
    }
  }

  /**
   * Validate Flask API response structure
   */
  validateFlaskResponse(responseData) {
    // Check required fields
    if (!responseData.status) {
      throw new Error('Missing required field: status');
    }

    const validStatusValues = ['POS', 'NEG', 'POSITIVE', 'NEGATIVE'];
    if (!validStatusValues.includes(responseData.status.toUpperCase())) {
      throw new Error(`Invalid status value: ${responseData.status}`);
    }

    if (responseData.status.toUpperCase().startsWith('POS')) {
      if (!responseData.most_probable_parasite) {
        throw new Error('Missing most_probable_parasite for positive result');
      }

      if (!responseData.most_probable_parasite.type || !responseData.most_probable_parasite.confidence) {
        throw new Error('Invalid most_probable_parasite structure');
      }

      // Validate parasite type
      const validTypes = ['PF', 'PM', 'PO', 'PV'];
      if (!validTypes.includes(responseData.most_probable_parasite.type)) {
        throw new Error(`Invalid parasite type: ${responseData.most_probable_parasite.type}`);
      }

      // Validate confidence
      const confidence = responseData.most_probable_parasite.confidence;
      if (typeof confidence !== 'number' || confidence < 0 || confidence > 1) {
        throw new Error(`Invalid confidence value: ${confidence}`);
      }
    }

    // Validate detections array
    if (!Array.isArray(responseData.detections)) {
      throw new Error('Detections must be an array');
    }
  }

  /**
   * Process detections array from Flask response
   */
  processDetections(detections) {
    return detections.map((detection, index) => {
      try {
        return {
          image_id: detection.image_id || `image_${index}`,
          parasites_detected: this.processParasitesDetected(detection.parasites_detected || []),
          white_blood_cells_detected: detection.white_blood_cells_detected || 0,
          parasite_count: detection.parasite_count || 0,
          parasite_wbc_ratio: detection.parasite_wbc_ratio || 0,
          quality_score: detection.quality_score || null,
          processing_notes: detection.processing_notes || null
        };
      } catch (error) {
        logger.warn(`Error processing detection ${index}:`, error);
        return {
          image_id: `image_${index}`,
          parasites_detected: [],
          white_blood_cells_detected: 0,
          parasite_count: 0,
          parasite_wbc_ratio: 0,
          error: error.message
        };
      }
    });
  }

  /**
   * Process parasites detected in an image
   */
  processParasitesDetected(parasites) {
    return parasites.map(parasite => {
      // Validate parasite structure
      if (!parasite.type || !parasite.confidence || !parasite.bbox) {
        logger.warn('Invalid parasite detection structure:', parasite);
        return null;
      }

      return {
        type: parasite.type,
        confidence: Math.max(0, Math.min(1, parasite.confidence)), // Clamp to [0,1]
        bbox: this.processBoundingBox(parasite.bbox),
        additional_info: parasite.additional_info || {}
      };
    }).filter(parasite => parasite !== null);
  }

  /**
   * Process bounding box coordinates
   */
  processBoundingBox(bbox) {
    // Handle different bbox formats
    if (Array.isArray(bbox) && bbox.length === 4) {
      // [x1, y1, x2, y2] format
      return {
        x1: bbox[0],
        y1: bbox[1],
        x2: bbox[2],
        y2: bbox[3]
      };
    } else if (typeof bbox === 'object' && bbox.x1 !== undefined) {
      // Object format
      return {
        x1: bbox.x1,
        y1: bbox.y1,
        x2: bbox.x2,
        y2: bbox.y2
      };
    } else {
      logger.warn('Invalid bounding box format:', bbox);
      return { x1: 0, y1: 0, x2: 0, y2: 0 };
    }
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
      const response = await axios.get(`${this.flaskApiUrl}/info`, {
        timeout: 10000
      });

      return {
        available: true,
        version: response.data.version,
        capabilities: response.data.capabilities || [],
        supported_formats: response.data.supported_formats || [],
        max_file_size: response.data.max_file_size || 'unknown',
        max_files_per_request: response.data.max_files_per_request || 'unknown'
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
      // This would use a test image or mock data
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
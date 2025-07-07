// 📁 server/src/config/swagger.js
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Malaria Lab System API',
      version: '1.0.0',
      description: 'API documentation for the Malaria Lab System backend',
      contact: {
        name: 'API Support',
        email: 'support@malarialabsystem.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: 'http://localhost:5000',  // Changed from 3000 to 5000
        description: 'Local development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter JWT token'
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ]
  },
  apis: ['./src/routes/*.js', './src/models/*.js'] // Scan route files for Swagger annotations
};

const swaggerSpec = swaggerJsdoc(options);

// Export the spec directly, not as a function
module.exports = swaggerSpec;
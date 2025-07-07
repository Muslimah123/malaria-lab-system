#!/bin/bash

echo "🧪 Testing Malaria Lab System Services..."

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Test MongoDB
echo "📊 Testing MongoDB connection..."
docker exec malaria-backend sh -c "curl -s mongodb:27017 || echo 'MongoDB connection failed'"

# Test Redis
echo "🔄 Testing Redis connection..."
docker exec malaria-backend sh -c "redis-cli -h redis ping || echo 'Redis connection failed'"

# Test Flask API Health
echo "🧬 Testing Flask API health..."
curl -s http://localhost:5001/health || echo "Flask API health check failed"

# Test Backend API
echo "🖥️  Testing Backend API..."
curl -s http://localhost:5000/api/health || echo "Backend API health check failed"

# Test Frontend
echo "🌐 Testing Frontend..."
curl -s http://localhost:3000 | grep -q "html" && echo "Frontend is serving HTML" || echo "Frontend test failed"

# Test Internal Service Communication
echo "🔗 Testing internal service communication..."
docker exec malaria-backend sh -c "curl -s http://flask-api:5001/health" || echo "Backend to Flask API communication failed"

echo "✅ Service testing completed!"
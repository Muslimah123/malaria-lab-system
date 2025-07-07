#!/bin/bash

echo "🔧 Quick Fix: Restarting with corrected configuration..."

# Stop current containers
echo "🛑 Stopping current containers..."
docker-compose -f docker-compose.dev.yml down

# Remove problematic volumes (optional)
read -p "🗑️  Remove old MongoDB data? (y/N): " remove_data
if [[ $remove_data =~ ^[Yy]$ ]]; then
    docker volume rm malaria-lab-system_mongodb_data 2>/dev/null || echo "Volume already removed or doesn't exist"
    echo "✅ MongoDB data cleared"
fi

# Clean up containers
echo "🧹 Cleaning up containers..."
docker container prune -f

# Restart with fixes
echo "🚀 Starting with fixes..."
docker-compose -f docker-compose.dev.yml up --build -d

echo "⏳ Waiting for services to stabilize..."
sleep 15

echo "🧪 Testing services..."

# Test each service
echo "📊 Testing MongoDB..."
docker exec malaria-mongo-dev mongosh --eval "db.runCommand('ping')" 2>/dev/null && echo " ✅ MongoDB is responding" || echo " ❌ MongoDB still failing"

echo "🔄 Testing Redis..."
docker exec malaria-redis-dev redis-cli ping 2>/dev/null && echo " ✅ Redis is responding" || echo " ❌ Redis still failing"

echo "🖥️  Testing Backend..."
sleep 5
curl -s http://localhost:5000/api/health 2>/dev/null && echo " ✅ Backend is responding" || echo " ❌ Backend still starting..."

echo "🌐 Testing Frontend..."
curl -s http://localhost:3000 | grep -q "html" && echo " ✅ Frontend is serving" || echo " ❌ Frontend not ready"

echo ""
echo "📋 Service Status:"
docker-compose -f docker-compose.dev.yml ps

echo ""
echo "📝 To view logs:"
echo "   All services: docker-compose -f docker-compose.dev.yml logs -f"
echo "   Backend only: docker-compose -f docker-compose.dev.yml logs -f backend"
echo "   MongoDB only: docker-compose -f docker-compose.dev.yml logs -f mongodb"
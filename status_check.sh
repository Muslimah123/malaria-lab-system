#!/bin/bash

echo "🔍 Current System Status Check..."

# Check container status
echo "📦 Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "🧪 Service Tests:"

# Test Frontend (should work)
echo "🌐 Frontend:"
curl -s http://localhost:3000 >/dev/null && echo "  ✅ Frontend accessible at http://localhost:3000" || echo "  ❌ Frontend not accessible"

# Test individual containers
echo ""
echo "📊 MongoDB:"
if docker ps | grep -q malaria-mongo-dev; then
    echo "  ✅ Container running"
    docker exec malaria-mongo-dev mongosh --eval "db.runCommand('ping')" 2>/dev/null && echo "  ✅ MongoDB responding" || echo "  ❌ MongoDB not responding"
else
    echo "  ❌ Container not running"
fi

echo ""
echo "🔄 Redis:"
if docker ps | grep -q malaria-redis-dev; then
    echo "  ✅ Container running"
    docker exec malaria-redis-dev redis-cli ping 2>/dev/null && echo "  ✅ Redis responding" || echo "  ❌ Redis not responding"
else
    echo "  ❌ Container not running"
fi

echo ""
echo "🖥️  Backend:"
if docker ps | grep -q malaria-backend-dev; then
    echo "  ❌ Container crashed - needs restart"
else
    echo "  ❌ Container not running"
fi

echo ""
echo "🎯 What's Working:"
curl -s http://localhost:3000 >/dev/null && echo "  ✅ Frontend: http://localhost:3000"
docker exec malaria-redis-dev redis-cli ping >/dev/null 2>&1 && echo "  ✅ Redis: localhost:6379"

echo ""
echo "⚠️  What Needs Fixing:"
echo "  🔧 MongoDB: Restart needed (init script issue)"
echo "  🔧 Backend: Restart needed (Redis config + MongoDB connection)"

echo ""
echo "🚀 To fix, run: ./quick-fix-restart.sh"
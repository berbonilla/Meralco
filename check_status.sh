#!/bin/bash

# Malwize Server Status Checker

echo "🔍 Checking Malwize Server Status..."
echo "=================================="

# Check API server
echo -n "📡 API Server (port 8000): "
if curl -s http://localhost:8000/docs > /dev/null 2>&1; then
    echo "✅ RUNNING"
else
    echo "❌ NOT RUNNING"
fi

# Check Frontend server
echo -n "🌐 Frontend Server (port 8080): "
if curl -s http://localhost:8080 > /dev/null 2>&1; then
    echo "✅ RUNNING"
else
    echo "❌ NOT RUNNING"
fi

echo "=================================="

# Show process info
echo ""
echo "📊 Process Information:"
ps aux | grep -E "(uvicorn.*scanner_api|python.*robust_server|python.*http.server)" | grep -v grep || echo "No server processes found"

echo ""
echo "🌐 URLs:"
echo "  Frontend: http://localhost:8080"
echo "  API Docs: http://localhost:8000/docs" 
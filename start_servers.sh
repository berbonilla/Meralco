#!/bin/bash

# Malwize Server Startup Script
# Starts both API and Frontend servers

echo "🚀 Starting Malwize Servers..."
echo "================================"

# Function to cleanup on exit
cleanup() {
    echo "🛑 Stopping servers..."
    pkill -f "uvicorn.*scanner_api" 2>/dev/null
    pkill -f "python.*robust_server" 2>/dev/null
    pkill -f "python.*http.server" 2>/dev/null
    echo "✅ Servers stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start API server
echo "📡 Starting API server on port 8000..."
uvicorn scanner_api:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!

# Wait a moment for API to start
sleep 3

# Check if API started successfully
if ! curl -s http://localhost:8000/docs > /dev/null; then
    echo "❌ API server failed to start"
    cleanup
fi

echo "✅ API server started (PID: $API_PID)"

# Start Frontend server
echo "🌐 Starting Frontend server on port 8080..."
cd pages && python robust_server.py &
FRONTEND_PID=$!

# Wait a moment for frontend to start
sleep 3

# Check if frontend started successfully
if ! curl -s http://localhost:8080 > /dev/null; then
    echo "❌ Frontend server failed to start"
    cleanup
fi

echo "✅ Frontend server started (PID: $FRONTEND_PID)"
echo ""
echo "🎉 Malwize is now running!"
echo "📍 Frontend: http://localhost:8080"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all servers"
echo "================================"

# Wait for user to stop
wait 
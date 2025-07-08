#!/usr/bin/env python3
"""
Robust HTTP Server for Malwize Frontend
Handles BrokenPipeError and other connection issues gracefully
"""

import http.server
import socketserver
import os
import sys
import signal
from pathlib import Path

class RobustHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler that handles connection errors gracefully"""
    
    def log_message(self, format, *args):
        """Custom logging to avoid BrokenPipeError in logs"""
        try:
            super().log_message(format, *args)
        except BrokenPipeError:
            # Silently ignore broken pipe errors in logging
            pass
    
    def copyfile(self, source, outputfile):
        """Override copyfile to handle BrokenPipeError gracefully"""
        try:
            super().copyfile(source, outputfile)
        except BrokenPipeError:
            # Client disconnected, this is normal behavior
            self.log_error("Client disconnected during file transfer")
        except ConnectionResetError:
            # Connection was reset by client
            self.log_error("Connection reset by client")
        except Exception as e:
            # Log other errors but don't crash
            self.log_error(f"File transfer error: {e}")
    
    def handle_one_request(self):
        """Override to handle request errors gracefully"""
        try:
            super().handle_one_request()
        except BrokenPipeError:
            # Client disconnected before request completed
            self.log_error("Client disconnected before request completion")
        except ConnectionResetError:
            # Connection was reset
            self.log_error("Connection reset by client")
        except Exception as e:
            # Log other errors but continue serving
            self.log_error(f"Request handling error: {e}")
    
    def finish(self):
        """Override finish to handle cleanup errors"""
        try:
            super().finish()
        except (BrokenPipeError, ConnectionResetError):
            # Client already disconnected, this is normal
            pass
        except Exception as e:
            # Log other cleanup errors
            self.log_error(f"Cleanup error: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\nReceived signal {signum}, shutting down gracefully...")
    sys.exit(0)

def main():
    """Main server function"""
    port = 8080
    host = "0.0.0.0"
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Change to the pages directory
    pages_dir = Path(__file__).parent
    os.chdir(pages_dir)
    
    # Create server with custom handler
    with socketserver.TCPServer((host, port), RobustHTTPRequestHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"🚀 Malwize Frontend Server")
        print(f"📍 Serving on http://{host}:{port}")
        print(f"📁 Directory: {pages_dir}")
        print(f"⚡ Press Ctrl+C to stop")
        print("-" * 50)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped by user")
        except Exception as e:
            print(f"\n❌ Server error: {e}")
        finally:
            httpd.shutdown()
            print("✅ Server shutdown complete")

if __name__ == "__main__":
    main() 
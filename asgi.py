#!/usr/bin/env python3
"""
ASGI wrapper with non-blocking initialization
"""
import os
import asyncio
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

print("🚀 Starting ASGI application...")

async def initialize_app():
    """Initialize app in background without blocking"""
    try:
        print("🔄 Starting background initialization...")
        
        # Import and initialize in background
        from master import app, init_enhanced_db, cleanup_expired_task
        
        # Initialize database (this might be async)
        await init_enhanced_db()
        print("✅ Database initialized")
        
        # Start background tasks
        asyncio.create_task(cleanup_expired_task())
        print("✅ Background tasks started")
        
        return app
        
    except Exception as e:
        print(f"❌ Background initialization failed: {e}")
        # Create emergency app
        from quart import Quart
        emergency_app = Quart("emergency")
        emergency_app.config["PROVIDE_AUTOMATIC_OPTIONS"] = True
        
        @emergency_app.route('/')
        async def home():
            return "🟢 Emergency Mode - Main app initializing"
        
        @emergency_app.route('/health')
        async def health():
            return {"status": "initializing", "message": str(e)}
        
        return emergency_app

# Start initialization in background but don't wait for it
initialization_task = asyncio.create_task(initialize_app())

# Create a temporary app that immediately binds to the port
from quart import Quart

# Create immediate response app
application = Quart("immediate")

# Set critical config
application.config["PROVIDE_AUTOMATIC_OPTIONS"] = True

@application.route('/')
async def home():
    # Check if main app is ready
    if initialization_task.done():
        try:
            main_app = initialization_task.result()
            return "🟢 Main Application Running"
        except:
            return "🔴 Main Application Failed - Running in Emergency Mode"
    else:
        return "🟡 Application Initializing... Please wait"

@application.route('/health')
async def health():
    return {
        "status": "healthy", 
        "message": "Application binding to port",
        "initializing": not initialization_task.done()
    }

@application.before_serving
async def switch_to_main_app():
    """Switch to main app once it's ready"""
    try:
        print("🔄 Checking if main app is ready...")
        if initialization_task.done():
            main_app = initialization_task.result()
            if main_app != application:
                print("✅ Switching to main application")
                # Replace routes with main app
                application.dispatch_request = main_app.dispatch_request
                application.handle_user_exception = main_app.handle_user_exception
                application.process_response = main_app.process_response
    except Exception as e:
        print(f"❌ Failed to switch to main app: {e}")

print("✅ ASGI application created - should bind to port immediately")
print(f"📍 Will bind to port {os.environ.get('PORT', 5000)}")

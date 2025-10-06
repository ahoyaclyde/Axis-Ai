#!/usr/bin/env python3
"""
ASGI entry point for Quart
"""
import os
import asyncio
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

print("🚀 Starting Quart application...")

try:
    # Import your application
    from master import app, init_enhanced_db, cleanup_expired_task
    
    async def setup():
        """Setup the application"""
        print("✅ Application imported successfully")
        
        # Initialize database
        await init_enhanced_db()
        print("✅ Database initialized")
        
        # Start background tasks
        asyncio.create_task(cleanup_expired_task())
        print("✅ Background tasks started")
        
        port = os.environ.get('PORT', 5000)
        print(f"✅ Quart application ready on port {port}")
        return app
    
    # Create application
    application = asyncio.run(setup())
    
except Exception as e:
    print(f"❌ Failed to setup application: {e}")
    import traceback
    traceback.print_exc()
    raise

#!/usr/bin/env python3
"""
ASGI entry point for Render deployment
"""
import os
import asyncio
import logging
import importlib.util
import sys

# Add current directory to Python path
sys.path.append(os.path.dirname(__file__))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_app():
    """Create and initialize application"""
    try:
        # Direct import from the specific file
        spec = importlib.util.spec_from_file_location("app", "Master-Rust-Connect.py")
        app_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app_module)
        
        # Get the app and functions
        app = app_module.app
        init_enhanced_db = app_module.init_enhanced_db
        cleanup_expired_task = app_module.cleanup_expired_task
        
        logger.info("🚀 Initializing Forensic Video Analysis Platform...")
        
        # Initialize database
        await init_enhanced_db()
        logger.info("✅ Database initialized successfully")
        
        # Start background tasks
        asyncio.create_task(cleanup_expired_task())
        logger.info("✅ Background tasks started")
        
        logger.info(f"✅ Application ready on port {os.environ.get('PORT', 5000)}")
        return app
        
    except Exception as e:
        logger.error(f"❌ Application initialization failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise

# Create application instance
application = asyncio.run(create_app())

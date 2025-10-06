#!/usr/bin/env python3
"""
ASGI entry point for Docker deployment
"""
import os
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_app():
    """Create and initialize application"""
    try:
        from app import app, init_enhanced_db, cleanup_expired_task
        
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
        raise

# Create application instance
application = asyncio.run(create_app())

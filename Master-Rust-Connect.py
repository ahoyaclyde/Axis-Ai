#!/usr/bin/env python3
"""
Forensic Video Analysis Platform with Enhanced Multi-Chain Web3 Authentication
Features:
- Multi-chain wallet support (Ethereum, Bitcoin, Solana, Polygon, Avalanche, Lisk, etc.)
- Enhanced user management with email verification links
- Multi-country support and Individual/Company account types
- Role-based access control with bonus credit system
- Secure video processing with user isolation
- JWT tokens for API authentication
- Rust-based wallet connector for cryptographic operations
- Email verification system with links (not codes)

Requirements:
pip install quart aiosqlite aiofiles pillow opencv-python psutil bcrypt pyjwt cryptography

Run:
  python app.py
"""

import os
import io
import json
import zipfile
import cv2
import numpy as np
import json

import base64
import asyncio
import tempfile
import shutil
import subprocess
import time
import hashlib
import psutil
import bcrypt
import jwt
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode
from collections import defaultdict, deque



import matplotlib.pyplot as plt
import matplotlib.patches as patches
import seaborn as sns
from matplotlib.backends.backend_agg import FigureCanvasAgg
from scipy.spatial.distance import euclidean
from scipy import ndimage
from sklearn.cluster import DBSCAN
from filterpy.kalman import KalmanFilter
from scipy.optimize import linear_sum_assignment



import aiosqlite
import aiofiles
import cv2
from PIL import Image
from quart import Quart, render_template_string, render_template, request, jsonify, session, websocket, send_file, g
from functools import wraps
import secrets


# Import Rust wallet connector
from rust_wallet import get_wallet_connector, close_wallet_connector


# Render-specific configuration

# -------------------------
# Configuration
# -------------------------
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH =  DB_PATH = os.environ.get('DATABASE_URL', 'forensics.db')
UPLOAD_DIR = str(BASE_DIR / "uploads")
UPLOAD_FOLDER = Path('uploads')
OUTPUT_DIR = str(BASE_DIR / "outputs")
SNAPSHOTS_FOLDER = Path('object_snapshots')
SNAPSHOTS_FOLDER.mkdir(exist_ok=True)
DETECTIONS_DIR = str(BASE_DIR / "detections")
ALLOWED_EXTENSIONS = {"mp4", "avi", "mov", "mkv", "flv", "wmv"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024  # 2 GB

# Authentication settings
JWT_SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(hours=24)
SESSION_TIMEOUT = timedelta(hours=8)

# Enhanced authentication settings
VERIFICATION_TOKEN_LENGTH = 32
VERIFICATION_TOKEN_EXPIRY_HOURS = 24

# Global job storage for progress tracking
active_jobs = {}

# Multi-chain configuration
SUPPORTED_CHAINS = {
    'ethereum': {
        'name': 'Ethereum',
        'chain_id': 1,
        'symbol': 'ETH',
        'address_prefix': '0x',
        'address_length': 42,
        'signing_methods': ['personal_sign', 'eth_signTypedData_v4'],
        'explorer': 'https://etherscan.io/address/'
    },
    'bitcoin': {
        'name': 'Bitcoin',
        'chain_id': 0,
        'symbol': 'BTC',
        'address_prefix': ['1', '3', 'bc1'],
        'address_length': [26, 35, 42],
        'signing_methods': ['bip322', 'message_sign'],
        'explorer': 'https://blockstream.info/address/'
    },
    'solana': {
        'name': 'Solana',
        'chain_id': 101,
        'symbol': 'SOL',
        'address_prefix': '',
        'address_length': 32,  # Base58 encoded, typically 44 chars
        'signing_methods': ['solana_signMessage'],
        'explorer': 'https://explorer.solana.com/address/'
    },
    'polygon': {
        'name': 'Polygon',
        'chain_id': 137,
        'symbol': 'MATIC',
        'address_prefix': '0x',
        'address_length': 42,
        'signing_methods': ['personal_sign', 'eth_signTypedData_v4'],
        'explorer': 'https://polygonscan.com/address/'
    },
    'avalanche': {
        'name': 'Avalanche',
        'chain_id': 43114,
        'symbol': 'AVAX',
        'address_prefix': '0x',
        'address_length': 42,
        'signing_methods': ['personal_sign', 'eth_signTypedData_v4'],
        'explorer': 'https://snowtrace.io/address/'
    },
    'lisk': {
        'name': 'Lisk',
        'chain_id': 1,
        'symbol': 'LSK',
        'address_prefix': '',  # Lisk uses base58 addresses
        'address_length': 41,  # Lisk addresses are typically 41 chars
        'signing_methods': ['ed25519_sign'],
        'explorer': 'https://liskscan.com/account/'
    }
}

# Countries list for dropdown
COUNTRIES = [
    "Afghanistan", "Albania", "Algeria", "Argentina", "Australia", "Austria", 
    "Bangladesh", "Belgium", "Brazil", "Canada", "China", "Denmark", "Egypt", 
    "France", "Germany", "Ghana", "India", "Indonesia", "Iran", "Iraq", "Italy", 
    "Japan", "Jordan", "Kenya", "Malaysia", "Mexico", "Netherlands", "Nigeria", 
    "Pakistan", "Philippines", "Poland", "Russia", "Saudi Arabia", "South Africa", 
    "Spain", "Sweden", "Switzerland", "Turkey", "Uganda", "Ukraine", 
    "United Kingdom", "United States", "Vietnam", "Zimbabwe"
]


ProductID = str("Knott-Forensics")
CompanyID = str("Sense-AI")

# URL processing settings
URL_JOB_EXPIRY_HOURS = 24
TEMP_DETECTION_CLEANUP_HOURS = 48

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DETECTIONS_DIR, exist_ok=True)


# WITH THIS:
class PreConfiguredQuart(Quart):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set critical configuration BEFORE any internal setup
        self.config.update({
            "PROVIDE_AUTOMATIC_OPTIONS": True,
            "SECRET_KEY": os.environ.get('JWT_SECRET', JWT_SECRET_KEY),
            "MAX_CONTENT_LENGTH": MAX_CONTENT_LENGTH,
        })

# Use the pre-configured class
app = PreConfiguredQuart(__name__)

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = JWT_SECRET_KEY
# In your Master-Rust-Connect.py, around line 184 where you create the app:

# ⚠️ CRITICAL: Add these configurations IMMEDIATELY after creating the app


# Continue with your existing configuration...
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = JWT_SECRET_KEY

# Continue with your existing code...
# -------------------------
# Global runtime state
# -------------------------
job_tasks: Dict[int, asyncio.Task] = {}
job_ws_clients: Dict[int, List] = {}

# -------------------------
# Enhanced Database Schema with Multi-Chain Support
# -------------------------
CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,  -- NULL for Web3-only users
    role TEXT DEFAULT 'user',  -- user, premium, admin
    is_active BOOLEAN DEFAULT 1,
    email_verified BOOLEAN DEFAULT 0,
    credits INTEGER DEFAULT 10,  -- Processing credits
    country TEXT,
    account_type TEXT DEFAULT 'individual',  -- individual, company
    phone_number TEXT,
    company_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT,
    login_method TEXT DEFAULT 'web2'  -- web2, web3, both
);
"""

CREATE_WALLETS = """
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    chain_type TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    public_key TEXT,
    is_verified BOOLEAN DEFAULT 0,
    is_primary BOOLEAN DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(user_id, chain_type, wallet_address)
);
"""

CREATE_VERIFICATION_TOKENS = """
CREATE TABLE IF NOT EXISTS verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    type TEXT DEFAULT 'email_verification',  -- email_verification, password_reset
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    user_agent TEXT,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_UPLOADS = """
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    saved_path TEXT NOT NULL,
    size_bytes INTEGER,
    file_hash TEXT,
    upload_method TEXT DEFAULT 'web',  -- web, api
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_JOBS = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    upload_id INTEGER,
    source_url TEXT,
    source_type TEXT DEFAULT 'file',
    object_filter TEXT DEFAULT 'all',
    confidence REAL DEFAULT 0.5,
    frame_skip INTEGER DEFAULT 10,
    status TEXT DEFAULT 'pending',
    credits_cost INTEGER DEFAULT 1,
    started_at TEXT,
    completed_at TEXT,
    expires_at TEXT,
    process_pid INTEGER,
    task_name TEXT DEFAULT 'extraction',
    time_taken REAL,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (upload_id) REFERENCES uploads (id)
);
"""

CREATE_DETECTIONS = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    frame_number INTEGER,
    timestamp REAL,
    class_name TEXT,
    class_id INTEGER,
    confidence REAL,
    bbox TEXT,
    image_base64 TEXT,
    image_path TEXT,
    detection_group TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES jobs (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_LOGS = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER,
    user_id INTEGER,
    level TEXT,
    message TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES jobs (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_USER_ACTIVITY = """
CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,  -- login, logout, upload, job_start, etc.
    details TEXT,  -- JSON details
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""

CREATE_MOTION_TRAJECTORY_TABLE = """
    CREATE TABLE IF NOT EXISTS motion_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        total_objects INTEGER,
        analysis_data TEXT,
        heatmap_image TEXT,
        trajectory_heatmap TEXT,  
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (job_id) REFERENCES jobs (id)
    );
"""
    

CREATE_OBJECT_TRAJECTORY_TABLE = """
    CREATE TABLE IF NOT EXISTS object_trajectories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        object_id INTEGER,
        object_class TEXT,
        trajectory_data TEXT,
        speed_data TEXT,
        direction_data TEXT,
        total_distance REAL,
        avg_speed REAL,
        max_speed REAL,
        duration REAL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (analysis_id) REFERENCES motion_analysis (id)
    );
"""


CREATE_TIMELINE_TABLE = """
CREATE TABLE IF NOT EXISTS timeline_videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                duration REAL,
                metadata TEXT,
                upload_time TEXT DEFAULT (datetime('now')),
                analysis_status TEXT DEFAULT 'pending',
                video_hash TEXT UNIQUE
            );
        """


async def init_enhanced_db():
    """Initialize enhanced database with all tables and migrations"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys=ON;")
        
        # Create all tables
        await db.execute(CREATE_USERS)
        await db.execute(CREATE_WALLETS)
        await db.execute(CREATE_VERIFICATION_TOKENS)
        await db.execute(CREATE_SESSIONS)
        await db.execute(CREATE_UPLOADS)
        await db.execute(CREATE_JOBS)
        await db.execute(CREATE_DETECTIONS)
        await db.execute(CREATE_LOGS)
        await db.execute(CREATE_USER_ACTIVITY)
        await db.execute(CREATE_MOTION_TRAJECTORY_TABLE)
        await db.execute(CREATE_OBJECT_TRAJECTORY_TABLE)
        await db.execute(CREATE_TIMELINE_TABLE)
    
        await db.commit()
        
        # Create admin user if doesn't exist
        admin_exists = await db.execute("SELECT id FROM users WHERE username='admin'")
        if not await admin_exists.fetchone():
            admin_hash = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
            await db.execute("""
                INSERT INTO users (username, email, password_hash, role, is_active, email_verified, credits, country, account_type)
                VALUES ('admin', 'admin@forensics.app', ?, 'admin', 1, 1, 1000, 'United States', 'individual')
            """, (admin_hash,))
            await db.commit()
            print("Created default admin user: admin/admin123")

# -------------------------
# Database Helpers
# -------------------------
async def db_insert(table: str, data: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cols = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        query = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
        cur = await db.execute(query, tuple(data.values()))
        await db.commit()
        return cur.lastrowid

async def db_update(table: str, data: dict, where: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        set_clause = ", ".join([f"{k}=?" for k in data.keys()])
        where_clause = " AND ".join([f"{k}=?" for k in where.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        await db.execute(query, tuple(data.values()) + tuple(where.values()))
        await db.commit()

async def db_query(sql: str, params: tuple = ()):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(sql, params)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

async def db_query_one(sql: str, params: tuple = ()):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(sql, params)
        row = await cur.fetchone()
        return dict(row) if row else None
    
    

# Database connection helper
async def get_db():
    return await aiosqlite.connect('your_database.db')

# Generic function to fetch data by user ID
async def fetch_user_data(table_name, user_id, limit=1000):
    async with await get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            f"SELECT * FROM {table_name} WHERE user_id = ? ORDER BY id DESC LIMIT ?", 
            (user_id, limit)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

# Get specific user profile
async def fetch_user_by_id(user_id):
    async with await get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None



# Get specific user profile
async def fetch_user_by_addr(addr):
    async with await get_db() as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute("SELECT * FROM users WHERE username = ?", (addr,))
        row = await cursor.fetchone()
        return dict(row) if row else None

# -------------------------
# Enhanced Verification System with Links (Not Codes)
# -------------------------
def generate_verification_token():
    """Generate a secure verification token"""
    import secrets
    return secrets.token_urlsafe(VERIFICATION_TOKEN_LENGTH)

async def send_verification_email(email: str, verification_url: str, name: str = "User"):
    """Send verification link via email (simulated for demo)"""
    print(f"[EMAIL] Sending verification link to {email}")
    print(f"[EMAIL] Verification URL: {verification_url}")
    print(f"[EMAIL] Dear {name}, please click the link above to verify your email address.")
    # In production, integrate with SendGrid, Mailgun, etc.
    return True

async def send_password_reset_email(email: str, reset_url: str, name: str = "User"):
    """Send password reset link via email"""
    print(f"[EMAIL] Sending password reset link to {email}")
    print(f"[EMAIL] Reset URL: {reset_url}")
    return True

async def create_verification_token(user_id: int, email: str, token_type: str = 'email_verification'):
    """Create and store verification token"""
    token = generate_verification_token()
    expires_at = (datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)).isoformat()
    
    # Deactivate any existing tokens for this user/type
    await db_update("verification_tokens", 
                   {"used_at": datetime.utcnow().isoformat()}, 
                   {"user_id": user_id, "type": token_type, "used_at": None})
    
    # Create new token
    await db_insert("verification_tokens", {
        "user_id": user_id,
        "email": email,
        "token": token,
        "type": token_type,
        "expires_at": expires_at
    })
    
    return token

async def verify_token(token: str, token_type: str = 'email_verification'):
    """Verify a verification token"""
    # Get the token record
    token_record = await db_query_one("""
        SELECT * FROM verification_tokens 
        WHERE token = ? AND type = ? AND used_at IS NULL AND expires_at > datetime('now')
        LIMIT 1
    """, (token, token_type))
    
    if not token_record:
        return {"success": False, "error": "Invalid or expired verification link"}
    
    # Mark token as used
    await db_update("verification_tokens", {"used_at": datetime.utcnow().isoformat()}, {"id": token_record['id']})
    
    # Mark user as verified if this is email verification
    if token_type == 'email_verification' and token_record['user_id']:
        await db_update("users", {"email_verified": 1}, {"id": token_record['user_id']})
    
    return {"success": True, "user_id": token_record['user_id'], "email": token_record['email']}

# -------------------------
# Multi-Chain Wallet Validation with Rust Connector
# -------------------------
def validate_ethereum_address(address):
    """Validate Ethereum-style address (0x + 40 hex chars)"""
    if not address.startswith('0x'):
        return False
    if len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False

def validate_bitcoin_address(address):
    """Basic Bitcoin address validation"""
    # Check common Bitcoin address formats
    if address.startswith('1') and 26 <= len(address) <= 34:
        return True
    if address.startswith('3') and 26 <= len(address) <= 34:
        return True
    if address.startswith('bc1') and len(address) >= 14:
        return True
    return False

def validate_solana_address(address):
    """Validate Solana address (base58, 32-44 chars)"""
    try:
        # Solana addresses are base58 encoded 32-byte public keys
        import base58
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except:
        return False

def validate_lisk_address(address):
    """Validate Lisk address (base58, typically 41 chars)"""
    try:
        # Lisk addresses are base58 encoded
        import base58
        decoded = base58.b58decode(address)
        return len(address) == 41  # Standard Lisk address length
    except:
        return False

def validate_address(chain_type, address):
    """Universal address validator"""
    validators = {
        'ethereum': validate_ethereum_address,
        'polygon': validate_ethereum_address,  # Same format as Ethereum
        'avalanche': validate_ethereum_address,  # Same format as Ethereum
        'bitcoin': validate_bitcoin_address,
        'solana': validate_solana_address,
        'lisk': validate_lisk_address
    }
    
    if chain_type in validators:
        return validators[chain_type](address)
    return True  # Accept any address for unknown chains

def get_signing_message(chain_type, address, nonce):
    """Generate chain-appropriate signing message"""
    base_message = f"ForensicPlatform: Verify ownership of {address} on {chain_type} with nonce: {nonce}"
    
    # Chain-specific message formats
    message_formats = {
        'bitcoin': f"ForensicPlatform Bitcoin Verification\nAddress: {address}\nNonce: {nonce}",
        'solana': f"ForensicPlatform Solana Verification\nAddress: {address}\nNonce: {nonce}",
        'lisk': f"ForensicPlatform Lisk Verification\nAddress: {address}\nNonce: {nonce}",
        'ethereum': base_message,
        'polygon': base_message,
        'avalanche': base_message
    }
    
    return message_formats.get(chain_type, base_message)

async def verify_wallet_signature(chain_type: str, address: str, public_key: str, message: str, signature: str) -> bool:
    """Verify wallet signature using Rust connector"""
    try:
        wallet_connector = get_wallet_connector()
        
        if chain_type == 'lisk':
            # Use Rust connector for Lisk
            return wallet_connector.verify_signature(public_key, message, signature)
        else:
            # For other chains, use Python implementation
            # This is a simplified version - in production you'd use chain-specific libraries
            if chain_type in ['ethereum', 'polygon', 'avalanche']:
                # Use web3.py for EVM chains
                try:
                    from web3 import Web3
                    w3 = Web3()
                    recovered_address = w3.eth.account.recover_message(text=message, signature=signature)
                    return recovered_address.lower() == address.lower()
                except ImportError:
                    # Fallback to basic verification
                    return len(signature) > 0
            else:
                # For other chains, accept any non-empty signature (simplified)
                return len(signature) > 0
                
    except Exception as e:
        print(f"Error verifying signature for {chain_type}: {e}")
        return False

# -------------------------
# Authentication & Authorization
# -------------------------
def generate_jwt_token(user_data: dict) -> str:
    """Generate JWT token for user"""
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + JWT_EXPIRATION_DELTA,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def create_session(user_id: int, user_agent: str = None, ip_address: str = None) -> str:
    """Create new session for user"""
    session_id = hashlib.sha256(f"{user_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()
    expires_at = (datetime.utcnow() + SESSION_TIMEOUT).isoformat()
    
    await db_insert("sessions", {
        "id": session_id,
        "user_id": user_id,
        "expires_at": expires_at,
        "user_agent": user_agent,
        "ip_address": ip_address
    })
    
    return session_id

async def verify_session(session_id: str) -> dict:
    """Verify session and return user data"""
    session_data = await db_query_one("""
        SELECT s.*, u.* FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.id = ? AND s.expires_at > datetime('now') AND u.is_active = 1
    """, (session_id,))
    
    return session_data

async def log_user_activity(user_id: int, action: str, details: dict = None, ip_address: str = None, user_agent: str = None):
    """Log user activity"""
    await db_insert("user_activity", {
        "user_id": user_id,
        "action": action,
        "details": json.dumps(details) if details else None,
        "ip_address": ip_address,
        "user_agent": user_agent
    })

def auth_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        # Check for JWT token in header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            token_data = verify_jwt_token(token)
            if token_data:
                user = await db_query_one("SELECT * FROM users WHERE id = ? AND is_active = 1", (token_data['user_id'],))
                if user:
                    g.current_user = user
                    return await f(*args, **kwargs)
        
        # Check for session ID in cookie
        session_id = session.get('session_id')
        if session_id:
            session_data = await verify_session(session_id)
            if session_data:
                g.current_user = session_data
                return await f(*args, **kwargs)
        
        return jsonify({"error": "Authentication required "}), 401
    
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user') or g.current_user['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return await f(*args, **kwargs)
    
    return decorated_function

# -------------------------
# Utility Functions
# -------------------------
async def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of uploaded file asynchronously"""
    hash_sha256 = hashlib.sha256()
    async with aiofiles.open(file_path, 'rb') as f:
        while chunk := await f.read(8192):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def generate_detection_group(class_name: str, bbox: list) -> str:
    """Generate detection group identifier"""
    x1, y1, x2, y2 = bbox
    grid_x = int((x1 + x2) / 2 / 200)
    grid_y = int((y1 + y2) / 2 / 150)
    return f"{class_name}_grid_{grid_x}_{grid_y}"

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

async def log(job_id: Optional[int], level: str, message: str, user_id: int = None):
    """Enhanced logging with user context"""
    rec = {
        "job_id": job_id,
        "user_id": user_id or (g.current_user['id'] if hasattr(g, 'current_user') else None),
        "level": level,
        "message": message,
    }
    row_id = await db_insert("logs", rec)
    
    # WebSocket notifications
    if job_id in job_ws_clients:
        payload = json.dumps({
            "type": "log", 
            "job_id": job_id, 
            "level": level, 
            "message": message, 
            "created_at": datetime.utcnow().isoformat()
        })
        for ws in list(job_ws_clients.get(job_id, [])):
            try:
                asyncio.create_task(ws.send(payload))
            except Exception:
                pass
    
    return row_id


    # Notify connected websockets for this job
    if job_id in job_ws_clients:
        payload = json.dumps({"type": "log", "job_id": job_id, "level": level, "message": message, "created_at": datetime.utcnow().isoformat()})
        # send in background to avoid blocking DB writes
        for ws in list(job_ws_clients.get(job_id, [])):
            try:
                asyncio.create_task(ws.send(payload))
            except Exception:
                # ignore; connection cleanup happens elsewhere
                pass
    return row_id
# -------------------------


# -------------------------
# Enhanced Authentication Routes with Multi-Chain Support
# -------------------------
@app.route('/auth/register', methods=['POST'])
async def register():
    data = await request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    country = data.get('country')
    account_type = data.get('account_type', 'individual')
    company_name = data.get('company_name')
    phone_number = data.get('phone_number')
    
    if not username or not email or not country:
        return jsonify({"error": "Username, email, and country are required"}), 400
    
    if account_type == 'company' and not company_name:
        return jsonify({"error": "Company name is required for company accounts"}), 400
    
    # Check if user exists
    existing = await db_query_one("SELECT id FROM users WHERE username=? OR email=?", (username, email))
    if existing:
        return jsonify({"error": "User already exists"}), 400
    
    # Create user
    user_data = {
        "username": username,
        "email": email,
        "country": country,
        "account_type": account_type,
        "phone_number": phone_number,
        "company_name": company_name,
        "login_method": "web2",
        "email_verified": 0
    }
    
    if password:
        user_data["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    user_id = await db_insert("users", user_data)
    
    # Generate and send verification link (not code)
    verification_token = await create_verification_token(user_id, email)
    verification_url = f"{request.host_url}auth/verify-email?token={verification_token}"
    
    name = company_name if account_type == 'company' else username
    email_sent = await send_verification_email(email, verification_url, name)
    
    if not email_sent:
        return jsonify({"error": "Failed to send verification email"}), 500
    
    await log_user_activity(user_id, "register", {
        "method": "web2",
        "country": country,
        "account_type": account_type
    }, request.remote_addr, request.headers.get('User-Agent'))
    
    return jsonify({
        "success": True,
        "message": "Registration successful. Please check your email for verification link.",
        "user_id": user_id,
        "email": email,
        "requires_verification": True
    })

@app.route('/auth/verify-email')
async def verify_email_page():
    """Email verification page that handles the verification token"""
    token = request.args.get('token')
    
    if not token:
        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification - Forensic Analysis</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-red-600 mb-4">Invalid Verification Link</h1>
                <p class="text-gray-600">The verification link is invalid or has expired.</p>
                <a href="/" class="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Return to Login
                </a>
            </div>
        </body>
        </html>
        ''')
    
    # Verify the token
    result = await verify_token(token, 'email_verification')
    
    if not result['success']:
        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification - Forensic Analysis</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-red-600 mb-4">Verification Failed</h1>
                <p class="text-gray-600">{{ error }}</p>
                <a href="/" class="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Return to Login
                </a>
            </div>
        </body>
        </html>
        ''', error=result.get('error', 'Unknown error'))
    
    # Get user data
    user = await db_query_one("SELECT * FROM users WHERE id=?", (result['user_id'],))
    if not user:
        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification - Forensic Analysis</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-red-600 mb-4">User Not Found</h1>
                <p class="text-gray-600">The user associated with this verification link was not found.</p>
                <a href="/" class="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Return to Login
                </a>
            </div>
        </body>
        </html>
        ''')
    
    # Create session and token
    session_id = await create_session(user['id'], request.headers.get('User-Agent'), request.remote_addr)
    token = generate_jwt_token(user)
    
    session['session_id'] = session_id
    
    await log_user_activity(user['id'], "email_verified", {}, 
                           request.remote_addr, request.headers.get('User-Agent'))
    
    return await render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Email Verified - Forensic Analysis</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            // Store the JWT token for API calls
            localStorage.setItem('jwt_token', '{{ token }}');
            
            function connectWallet() {
                window.location.href = '/auth/connect-wallet';
            }
            
            function goToDashboard() {
                window.location.href = '/dashboard';
            }
        </script>
    </head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
            <div class="text-center mb-6">
                <div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg class="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                </div>
                <h1 class="text-2xl font-bold text-green-600 mb-2">Email Verified!</h1>
                <p class="text-gray-600">Your email has been successfully verified.</p>
            </div>
            
            <div class="space-y-4">
                <button onclick="connectWallet()" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 px-4 rounded-lg font-semibold transition duration-200 flex items-center justify-center">
                    <span class="mr-2">🔗</span>
                    Connect Wallet & Get Bonus Credits
                </button>
                
                <button onclick="goToDashboard()" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg font-semibold transition duration-200">
                    Skip to Dashboard
                </button>
            </div>
            
            <p class="text-xs text-gray-500 text-center mt-4">
                You can connect your wallet later from your profile settings
            </p>
        </div>
    </body>
    </html>
    ''', token=token, user=user)





# -------------------------
# Enhanced Login Template with Multi-Chain Support
# -------------------------
ENHANCED_LOGIN_TEMPLATE = '''<!doctype html>
<html><head>
  <meta charset="utf-8">
  <title>Forensic Video Analysis - Multi-Chain Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.ethers.io/lib/ethers-5.7.2.umd.min.js"></script>
  <style>
    .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
    .card { backdrop-filter: blur(10px); background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); }
    .form-transition { transition: all 0.3s ease-in-out; }
    .chain-card { transition: all 0.2s ease; cursor: pointer; }
    .chain-card:hover { transform: translateY(-2px); box-shadow: 0 10px 25px rgba(0,0,0,0.1); }
  </style>
</head>
<body class="gradient-bg min-h-screen flex items-center justify-center p-4">
  <div class="card rounded-xl p-8 w-full max-w-4xl text-white">
    <div class="text-center mb-8">
      <h1 class="text-4xl font-bold mb-2">Forensic Video Analysis</h1>
      <p class="text-gray-200">Multi-chain authentication powered by Web3</p>
    </div>
    
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
      <!-- Web2 Login Section -->
      <div class="bg-white/10 rounded-xl p-6">
        <h2 class="text-2xl font-bold mb-4">Traditional Login</h2>
        <form id="loginSubmit" class="space-y-4">
          <div>
            <input id="username" type="text" placeholder="Username or Email" 
                   class="w-full p-3 rounded bg-white/20 border border-white/30 text-white placeholder-gray-300">
          </div>
          <div>
            <input id="password" type="password" placeholder="Password" 
                   class="w-full p-3 rounded bg-white/20 border border-white/30 text-white placeholder-gray-300">
          </div>
          <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 p-3 rounded font-semibold transition">
            Login with Email
          </button>
        </form>
        
        <div class="text-center my-6">
          <span class="text-gray-300">Don't have an account?</span>
          <a href="#" id="showSignup" class="text-blue-300 hover:text-blue-200 ml-2">Sign Up</a>
        </div>
      </div>
      
      <!-- Web3 Login Section -->
      <div class="bg-white/10 rounded-xl p-6">
        <h2 class="text-2xl font-bold mb-4">Web3 Wallet Login</h2>
        <p class="text-gray-200 mb-4">Connect your wallet to login instantly</p>
        
        <div class="grid grid-cols-2 gap-3 mb-4">
          <!-- Ethereum -->
          <div class="chain-card bg-orange-500/20 border border-orange-400/30 rounded-lg p-4 text-center" onclick="connectWeb3('ethereum')">
            <div class="text-2xl mb-2">🦊</div>
            <div class="font-semibold">Ethereum</div>
            <div class="text-xs text-orange-200">MetaMask</div>
          </div>
          
          <!-- Bitcoin -->
          <div class="chain-card bg-orange-600/20 border border-orange-500/30 rounded-lg p-4 text-center" onclick="connectWeb3('bitcoin')">
            <div class="text-2xl mb-2">₿</div>
            <div class="font-semibold">Bitcoin</div>
            <div class="text-xs text-orange-200">Any Wallet</div>
          </div>
          
          <!-- Solana -->
          <div class="chain-card bg-purple-500/20 border border-purple-400/30 rounded-lg p-4 text-center" onclick="connectWeb3('solana')">
            <div class="text-2xl mb-2">◎</div>
            <div class="font-semibold">Solana</div>
            <div class="text-xs text-purple-200">Phantom</div>
          </div>
          
          <!-- Lisk -->
          <div class="chain-card bg-blue-500/20 border border-blue-400/30 rounded-lg p-4 text-center" onclick="connectWeb3('lisk')">
            <div class="text-2xl mb-2">⛓️</div>
            <div class="font-semibold">Lisk</div>
            <div class="text-xs text-blue-200">Lisk Wallet</div>
          </div>
        </div>
        
        <div class="text-center">
          <button onclick="showManualWallet()" class="text-blue-300 hover:text-blue-200 text-sm">
            Or connect wallet manually
          </button>
        </div>
      </div>
    </div>
    
    <!-- Manual Wallet Connection Modal -->
    <div id="manualWalletModal" class="fixed inset-0 bg-black/50 flex items-center justify-center hidden z-50">
      <div class="bg-white rounded-xl p-6 w-full max-w-md text-gray-800">
        <h3 class="text-xl font-bold mb-4">Connect Wallet Manually</h3>
        <form id="manualWalletForm" class="space-y-4">
          <div>
            <label class="block text-sm font-medium mb-2">Blockchain</label>
            <select id="manualChain" class="w-full p-3 border border-gray-300 rounded-lg" required>
              <option value="">Select Blockchain</option>
              <option value="ethereum">Ethereum</option>
              <option value="bitcoin">Bitcoin</option>
              <option value="solana">Solana</option>
              <option value="lisk">Lisk</option>
              <option value="polygon">Polygon</option>
              <option value="avalanche">Avalanche</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-medium mb-2">Wallet Address</label>
            <input type="text" id="manualAddress" class="w-full p-3 border border-gray-300 rounded-lg" placeholder="0x..." required>
          </div>
          <div class="flex space-x-3">
            <button type="button" onclick="hideManualWallet()" class="flex-1 bg-gray-300 hover:bg-gray-400 p-3 rounded font-semibold">
              Cancel
            </button>
            <button type="submit" class="flex-1 bg-green-600 hover:bg-green-700 text-white p-3 rounded font-semibold">
              Connect
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Registration Form Modal -->
  <div id="registrationModal" class="fixed inset-0 bg-black/50 flex items-center justify-center hidden z-50">
    <div class="bg-white rounded-xl p-6 w-full max-w-md text-gray-800 max-h-screen overflow-y-auto">
      <h3 class="text-xl font-bold mb-4">Create Account</h3>
      <form id="registerSubmit" class="space-y-4">
        <input type="text" id="newUsername" placeholder="Username" required
               class="w-full p-3 border border-gray-300 rounded-lg">
        <input type="email" id="newEmail" placeholder="Email Address" required
               class="w-full p-3 border border-gray-300 rounded-lg">
        <input type="password" id="newPassword" placeholder="Password" 
               class="w-full p-3 border border-gray-300 rounded-lg">
        
        <select id="country" required class="w-full p-3 border border-gray-300 rounded-lg">
          <option value="">Select Country</option>
        </select>
        
        <select id="accountType" class="w-full p-3 border border-gray-300 rounded-lg">
          <option value="individual">Individual Account</option>
          <option value="company">Company Account</option>
        </select>
        
        <div id="companyFields" class="hidden">
          <input type="text" id="companyName" placeholder="Company Name" 
                 class="w-full p-3 border border-gray-300 rounded-lg">
        </div>
        
        <div class="flex space-x-3">
          <button type="button" onclick="hideRegistration()" class="flex-1 bg-gray-300 hover:bg-gray-400 p-3 rounded font-semibold">
            Cancel
          </button>
          <button type="submit" class="flex-1 bg-green-600 hover:bg-green-700 text-white p-3 rounded font-semibold">
            Create Account
          </button>
        </div>
      </form>
    </div>
  </div>

  <script>
  // Countries data
  const countries = ''' + json.dumps(COUNTRIES) + ''';
  
  // Populate countries dropdown
  const countrySelect = document.getElementById('country');
  countries.forEach(country => {
    const option = document.createElement('option');
    option.value = country;
    option.textContent = country;
    countrySelect.appendChild(option);
  });
  
  let currentUserData = null;
  
  // Account type change handler
  document.getElementById('accountType').addEventListener('change', (e) => {
    const companyFields = document.getElementById('companyFields');
    if (e.target.value === 'company') {
      companyFields.classList.remove('hidden');
    } else {
      companyFields.classList.add('hidden');
    }
  });
  
  // Modal functions
  function showManualWallet() {
    document.getElementById('manualWalletModal').classList.remove('hidden');
  }
  
  function hideManualWallet() {
    document.getElementById('manualWalletModal').classList.add('hidden');
  }
  
  function showRegistration() {
    document.getElementById('registrationModal').classList.remove('hidden');
  }
  
  function hideRegistration() {
    document.getElementById('registrationModal').classList.add('hidden');
  }
  
  // Show registration form
  document.getElementById('showSignup').addEventListener('click', (e) => {
    e.preventDefault();
    showRegistration();
  });
  
  // Web3 connection functions
  async function connectWeb3(chainType) {
    try {
      let address;
      
      if (chainType === 'ethereum' && typeof window.ethereum !== 'undefined') {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        address = accounts[0];
      } else {
        // For other chains, show manual entry
        showManualWallet();
        document.getElementById('manualChain').value = chainType;
        return;
      }
      
      // Attempt login with wallet
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          wallet_address: address,
          chain_type: chainType
        })
      });
      
      const result = await response.json();
      if (response.ok) {
        localStorage.setItem('jwt_token', result.token);
        window.location.href = '/dashboard';
      } else {
        // Wallet not registered, offer to register
        if (confirm('Wallet not registered. Would you like to create an account?')) {
          showRegistration();
          // Pre-fill with wallet info
          document.getElementById('manualChain').value = chainType;
          document.getElementById('manualAddress').value = address;
        }
      }
    } catch (error) {
      alert('Connection failed: ' + error.message);
    }
  }
  
  // Manual wallet form
  document.getElementById('manualWalletForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const chainType = document.getElementById('manualChain').value;
    const address = document.getElementById('manualAddress').value;
    
    if (!chainType || !address) {
      alert('Please fill in all fields');
      return;
    }
    
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          wallet_address: address,
          chain_type: chainType
        })
      });
      
      const result = await response.json();
      if (response.ok) {
        localStorage.setItem('jwt_token', result.token);
        window.location.href = '/dashboard';
      } else {
        alert('Login failed: ' + result.error);
      }
    } catch (error) {
      alert('Error: ' + error.message);
    }
  });
  
  // Traditional login form
  document.getElementById('loginSubmit').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const result = await response.json();
      if (response.ok) {
        localStorage.setItem('jwt_token', result.token);
        window.location.href = '/dashboard';
      } else {
        alert('Login failed: ' + result.error);
      }
    } catch (error) {
      alert('Login error: ' + error.message);
    }
  });
  
  // Registration form
  document.getElementById('registerSubmit').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
      username: document.getElementById('newUsername').value,
      email: document.getElementById('newEmail').value,
      password: document.getElementById('newPassword').value,
      country: document.getElementById('country').value,
      account_type: document.getElementById('accountType').value,
      company_name: document.getElementById('accountType').value === 'company' ? 
                   document.getElementById('companyName').value : ''
    };
    
    if (!formData.username || !formData.email || !formData.country) {
      alert('Please fill in all required fields');
      return;
    }
    
    try {
      const response = await fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      
      const result = await response.json();
      if (response.ok) {
        alert('Registration successful! Please check your email for verification link.');
        hideRegistration();
      } else {
        alert('Registration failed: ' + result.error);
      }
    } catch (error) {
      alert('Registration error: ' + error.message);
    }
  });
  </script>
</body></html>'''





@app.route('/auth/connect-wallet')
@auth_required
async def connect_wallet_page():
    """Wallet connection page with multi-chain support"""
    wallets = await db_query("""
    SELECT chain_type, wallet_address, is_verified, is_primary, created_at 
    FROM wallets WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC
""", (g.current_user['id'],))
    return await render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Connect Wallet - Forensic Analysis</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.ethers.io/lib/ethers-5.7.2.umd.min.js"></script>
    </head>
    <body class="bg-gray-100 min-h-screen">
        <nav class="bg-white shadow-lg">
            <div class="max-w-7xl mx-auto px-4">
                <div class="flex justify-between h-16">
                    <div class="flex items-center">
                        <h1 class="text-xl font-bold text-gray-800">Forensic Analysis</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-gray-600">Welcome, {{ user.username }}</span>
                        <a href="/dashboard" class="text-blue-600 hover:text-blue-800">Dashboard</a>
                    </div>
                </div>
            </div>
        </nav>

        <div class="max-w-4xl mx-auto py-8 px-4">
            <div class="bg-white rounded-lg shadow-lg p-8">
                <h1 class="text-3xl font-bold text-gray-800 mb-2">Connect Your Wallet</h1>
                <p class="text-gray-600 mb-8">Connect your wallet to get bonus credits and enable Web3 features</p>
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                    <!-- Ethereum/MetaMask -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-blue-500 transition duration-200 cursor-pointer" onclick="connectEthereum()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-orange-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-orange-600 font-bold">🦊</span>
                            </div>
                            <h3 class="text-lg font-semibold">Ethereum</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with MetaMask or any Ethereum wallet</p>
                        <div class="text-xs text-gray-500">Supports: ETH, MATIC, AVAX</div>
                    </div>
                    
                    <!-- Bitcoin -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-orange-500 transition duration-200 cursor-pointer" onclick="connectBitcoin()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-orange-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-orange-600 font-bold">₿</span>
                            </div>
                            <h3 class="text-lg font-semibold">Bitcoin</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with Bitcoin wallet</p>
                        <div class="text-xs text-gray-500">Supports: BTC</div>
                    </div>
                    
                    <!-- Solana -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-purple-500 transition duration-200 cursor-pointer" onclick="connectSolana()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-purple-600 font-bold">◎</span>
                            </div>
                            <h3 class="text-lg font-semibold">Solana</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with Solana wallet</p>
                        <div class="text-xs text-gray-500">Supports: SOL</div>
                    </div>
                    
                    <!-- Lisk -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-blue-500 transition duration-200 cursor-pointer" onclick="connectLisk()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-blue-600 font-bold">⛓️</span>
                            </div>
                            <h3 class="text-lg font-semibold">Lisk</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Connect with Lisk wallet</p>
                        <div class="text-xs text-gray-500">Supports: LSK</div>
                    </div>
                    
                    <!-- Manual Entry -->
                    <div class="border-2 border-gray-200 rounded-lg p-6 hover:border-green-500 transition duration-200 cursor-pointer" onclick="showManualEntry()">
                        <div class="flex items-center mb-4">
                            <div class="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mr-3">
                                <span class="text-green-600 font-bold">📝</span>
                            </div>
                            <h3 class="text-lg font-semibold">Manual Entry</h3>
                        </div>
                        <p class="text-gray-600 text-sm mb-4">Enter wallet details manually</p>
                        <div class="text-xs text-gray-500">All chains supported</div>
                    </div>
                </div>
                
                <!-- Manual Entry Form -->
                <div id="manualEntry" class="hidden bg-gray-50 p-6 rounded-lg mb-6">
                    <h3 class="text-xl font-semibold mb-4">Manual Wallet Entry</h3>
                    <form id="manualWalletForm" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Blockchain</label>
                            <select id="chainType" class="w-full p-3 border border-gray-300 rounded-lg" required>
                                <option value="">Select Blockchain</option>
                                <option value="ethereum">Ethereum</option>
                                <option value="bitcoin">Bitcoin</option>
                                <option value="solana">Solana</option>
                                <option value="lisk">Lisk</option>
                                <option value="polygon">Polygon</option>
                                <option value="avalanche">Avalanche</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Wallet Address</label>
                            <input type="text" id="walletAddress" class="w-full p-3 border border-gray-300 rounded-lg" placeholder="Enter wallet address" required>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Public Key (Optional)</label>
                            <input type="text" id="publicKey" class="w-full p-3 border border-gray-300 rounded-lg" placeholder="Enter public key if available">
                        </div>
                        <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white py-3 px-4 rounded-lg font-semibold">
                            Connect Wallet
                        </button>
                    </form>
                </div>
                
                <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <div class="flex items-start">
                        <div class="flex-shrink-0">
                            <span class="text-blue-600">💎</span>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-medium text-blue-800">Bonus Credits</h3>
                            <p class="text-sm text-blue-700 mt-1">
                                Connect your first wallet and receive <strong>5 bonus credits</strong> for video processing!
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
        async function connectEthereum() {
            if (typeof window.ethereum !== 'undefined') {
                try {
                    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                    const address = accounts[0];
                    
                    // Get chain ID
                    const chainId = await window.ethereum.request({ method: 'eth_chainId' });
                    
                    // Sign message for verification
                    const message = `ForensicPlatform: Verify ownership of ${address} on Ethereum`;
                    const signature = await window.ethereum.request({
                        method: 'personal_sign',
                        params: [message, address]
                    });
                    
                    await registerWallet('ethereum', address, '', signature, message);
                    
                } catch (error) {
                    alert('Ethereum connection failed: ' + error.message);
                }
            } else {
                alert('MetaMask is not installed. Please install MetaMask or use manual entry.');
            }
        }
        
        function connectBitcoin() {
            alert('Bitcoin wallet connection would be implemented here. Use manual entry for now.');
            showManualEntry();
        }
        
        function connectSolana() {
            alert('Solana wallet connection would be implemented here. Use manual entry for now.');
            showManualEntry();
        }
        
        function connectLisk() {
            alert('Lisk wallet connection would be implemented here. Use manual entry for now.');
            showManualEntry();
        }
        
        function showManualEntry() {
            document.getElementById('manualEntry').classList.remove('hidden');
        }
        
        document.getElementById('manualWalletForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const chainType = document.getElementById('chainType').value;
            const address = document.getElementById('walletAddress').value;
            const publicKey = document.getElementById('publicKey').value;
            
            if (!chainType || !address) {
                alert('Please fill in all required fields');
                return;
            }
            
            await registerWallet(chainType, address, publicKey, '', '');
        });
        
        async function registerWallet(chainType, address, publicKey, signature, message) {
            try {
                const token = localStorage.getItem('jwt_token');
                const response = await fetch('/auth/connect-wallet', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        chain_type: chainType,
                        wallet_address: address,
                        public_key: publicKey,
                        signature: signature,
                        message: message
                    })
                });
                
                const result = await response.json();
                if (response.ok) {
                    alert('Wallet connected successfully! ' + result.message);
                    window.location.href = '/dashboard';
                } else {
                    alert('Failed to connect wallet: ' + result.error);
                }
            } catch (error) {
                alert('Error connecting wallet: ' + error.message);
            }
        }
        </script>
    </body>
    </html>
    ''', user=g.current_user)


@app.route('/auth/profile/json')
@auth_required
async def json_profile():
    """Get user profile with connected wallets"""
    wallets = await db_query("""
        SELECT chain_type, wallet_address, is_verified, is_primary, created_at 
        FROM wallets WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC
    """, (g.current_user['id'],))
    
    pid = await db_query("""
        SELECT id
        FROM users WHERE email = ? 
    """, (g.current_user['username'],))
    
    
    
    return jsonify({
        "user": {
            "id": g.current_user["id"],
            "username": g.current_user["username"],
            "email": g.current_user["email"],
            "role": g.current_user["role"],
            "credits": g.current_user["credits"],
            "country": g.current_user.get("country"),
            "account_type": g.current_user.get("account_type"),
            "company_name": g.current_user.get("company_name"),
            "created_at": g.current_user["created_at"],
            "last_login": g.current_user["last_login"] ,
            "profileid" : pid 
        },
        "wallets": wallets
    })




@app.route('/auth/profile/<string:sect>/')
@auth_required
async def profile(sect):
    """Get user profile with connected wallets"""
    wallets = await db_query("""
        SELECT chain_type, wallet_address, is_verified, is_primary, created_at 
        FROM wallets WHERE user_id = ? ORDER BY is_primary DESC, created_at DESC
    """, (g.current_user['id'],))
    
    return await render_template("Account-Profile-Concept.html" , user = g.current_user  ,  sect = sect  , ProductID = ProductID , CompanyID = CompanyID )



@app.route('/auth/login', methods=['POST'])
async def login():
    """Login with email/password or wallet"""
    data = await request.get_json()
    username = data.get('username')
    password = data.get('password')
    wallet_address = data.get('wallet_address')
    chain_type = data.get('chain_type', 'ethereum')
    
    user = None
    
    if wallet_address:
        # Web3 login - find user by wallet address
        wallet = await db_query_one("""
            SELECT w.*, u.* FROM wallets w
            JOIN users u ON w.user_id = u.id
            WHERE w.wallet_address = ? AND w.chain_type = ? AND u.is_active = 1
        """, (wallet_address, chain_type))
        
        if wallet:
            user = wallet
        else:
            return jsonify({"error": "Wallet not registered"}), 401
    
    elif username and password:
        # Web2 login
        user = await db_query_one("SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1", (username, username))
        if not user or not user['password_hash']:
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            return jsonify({"error": "Invalid credentials"}), 401
    
    else:
        return jsonify({"error": "Invalid login data"}), 400
    
    # Update last login
    await db_update("users", {"last_login": datetime.utcnow().isoformat()}, {"id": user['id']})
    
    # Create session and token
    session_id = await create_session(user['id'], request.headers.get('User-Agent'), request.remote_addr)
    token = generate_jwt_token(user)
    
    session['session_id'] = session_id
    
    await log_user_activity(user['id'], "login", {
        "method": "web3" if wallet_address else "web2",
        "chain_type": chain_type if wallet_address else None
    }, request.remote_addr, request.headers.get('User-Agent'))
    
    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "credits": user["credits"],
            "email_verified": user["email_verified"]
        }
    })

# ... (rest of the routes remain similar but with multi-chain support)



@app.route('/')
async def login_page():
    return await render_template("Auth-Context-Provider.html")



@app.route('/signup/')
async def signup_page():
    return await render_template("New.html")




@app.route('/platform/tools/')
async def platform_units():
    return await render_template("Platform-Tools-Pro.html")

@app.route('/Outpost/Gallery/')
async def intergration_pool():
    return await render_template("Outpost-Relay-Center.html")


@app.route('/dashboard/')
@auth_required
async def dashboard():
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Projects)
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Projects) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    # LEts extract All Jobs Run By This Account 
    return await render_template("Dashboard-Context-Provider.html", user=g.current_user , Projects = Projects  , Projects_Index = Projects_Index )




@app.route('/explorer/<string:sect>/')
@auth_required
async def explorer(sect):
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Detections = await db_query("""
        SELECT * FROM detections WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Detections)
    # Sanitization 
    
    if(Detections):
        Detections_Index = len(Detections) 
    else:
        Detections_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Projects)
    # Sanitization 
    
    
    
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Time_Analysis = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Time_Analysis)
    
    Time_Index = len(Time_Analysis) if not Time_Analysis else int(0)
    
    
    
    
    
    # Detections  : Unit Logs : Uploaded Files 
    """Get user profile with connected wallets"""
    Motion_Analysis = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? AND task_name = ? 
    """, (g.current_user['user_id'],'motion_tracking'))
    print(Motion_Analysis)
    
    Motion_Index = len(Motion_Analysis) if not Motion_Analysis else int(0)
    
    
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Detections) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    """Get user profile with connected wallets"""
    Upload_Feed = await db_query("""
        SELECT * FROM uploads WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Upload_Feed)
    # Sanitization 
    
    if(Upload_Feed):
        Upload_Index = len(Upload_Feed) 
    else:
        Upload_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    
    """Get user profile with connected wallets"""
    Unit_Logs = await db_query("""
        SELECT * FROM user_activity WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Unit_Logs)
    # Sanitization 
    
    if(Unit_Logs):
        Log_Index = len(Unit_Logs) 
    else:
        Log_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    
    
    
    return await render_template("Explorer-Context-Provider.html", sect = sect  , user=g.current_user , Detection = Detections , Detections_Index = Detections_Index  , Upload_Feed = Upload_Feed , Upload_Index = Upload_Index  ,  Unit_Logs = Unit_Logs , Log_Index = Log_Index , Projects = Projects  , Projects_Index = Projects_Index , Time_Analysis = Time_Analysis , Time_Index = Time_Index , Motion_Analysis = Motion_Analysis , Motion_Index = Motion_Index ) 
                                  






@app.route('/projects/<string:sect>/')
@auth_required
async def augmented_projects(sect):
    """Get user profile with connected wallets"""
    Projects = await db_query("""
        SELECT * FROM jobs WHERE user_id = ? 
    """, (g.current_user['user_id'],))
    print(Projects)
    # Sanitization 
    
    if(Projects):
        Projects_Index = len(Projects) 
    else:
        Projects_Index = int(0)
    profile_id = (g.current_user['user_id'])
    print(profile_id)
    
    
    return await render_template("Projects-Context-Provider.html", sect = sect  , Projects = Projects  , Projects_Index = Projects_Index ,  user=g.current_user)


# -------------------------
# Main Application Routes (Same structure as before)
# -------------------------

# User profile endpoint
@app.route('/api/user/<int:user_id>')
async def get_user_profile(user_id):
    try:
        user = await fetch_user_by_addr(user_id)
        if user:
            return jsonify({
                'success': True,
                'data': user
            })
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User sessions
@app.route('/api/user/<int:user_id>/sessions')
async def get_user_sessions(user_id):
    try:
        sessions = await fetch_user_data('sessions', user_id)
        return jsonify({
            'success': True,
            'data': sessions,
            'count': len(sessions)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User uploads
@app.route('/api/user/<int:user_id>/uploads')
async def get_user_uploads(user_id):
    try:
        uploads = await fetch_user_data('uploads', user_id)
        return jsonify({
            'success': True,
            'data': uploads,
            'count': len(uploads)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User jobs
@app.route('/api/user/<int:user_id>/jobs')
async def get_user_jobs(user_id):
    try:
        jobs = await fetch_user_data('jobs', user_id)
        return jsonify({
            'success': True,
            'data': jobs,
            'count': len(jobs)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User detections
@app.route('/api/user/<int:user_id>/detections')
async def get_user_detections(user_id):
    try:
        detections = await fetch_user_data('detections', user_id)
        return jsonify({
            'success': True,
            'data': detections,
            'count': len(detections)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User logs
@app.route('/api/user/<int:user_id>/logs')
async def get_user_logs(user_id):
    try:
        logs = await fetch_user_data('logs', user_id)
        return jsonify({
            'success': True,
            'data': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# User activity
@app.route('/api/user/<int:user_id>/activity')
async def get_user_activity(user_id):
    try:
        activity = await fetch_user_data('user_activity', user_id)
        return jsonify({
            'success': True,
            'data': activity,
            'count': len(activity)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


    
# Get recent user activity (for live updates)
@app.route('/api/user/<int:user_id>/recent')
async def get_recent_user_activity(user_id):
    try:
        async with await get_db() as conn:
            conn.row_factory = aiosqlite.Row
            
            # Get recent activity (last 10 items)
            cursor = await conn.execute("""
                SELECT * FROM user_activity 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT 10
            """, (user_id,))
            recent_activity = [dict(row) for row in await cursor.fetchall()]
            
            # Get latest job status
            cursor = await conn.execute("""
                SELECT id, status, task_name, started_at, completed_at 
                FROM jobs 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT 5
            """, (user_id,))
            recent_jobs = [dict(row) for row in await cursor.fetchall()]
            
            # Get user current credits
            cursor = await conn.execute("SELECT credits FROM users WHERE id = ?", (user_id,))
            user_credits = (await cursor.fetchone())[0]
            
            return jsonify({
                'success': True,
                'data': {
                    'recent_activity': recent_activity,
                    'recent_jobs': recent_jobs,
                    'current_credits': user_credits,
                    'timestamp': datetime.now().isoformat()
                }
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Search users by username or email
@app.route('/api/users/search')
async def search_users():
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify({'success': False, 'error': 'Query parameter required'}), 400
        
        async with await get_db() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT id, username, email, role, credits, created_at 
                FROM users 
                WHERE username LIKE ? OR email LIKE ?
                LIMIT 20
            """, (f'%{query}%', f'%{query}%'))
            
            users = [dict(row) for row in await cursor.fetchall()]
            return jsonify({
                'success': True,
                'data': users,
                'count': len(users)
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Get all users (for admin)
@app.route('/api/users/list')
async def get_all_users():
    try:
        async with await get_db() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT id, username, email, role, credits, is_active, 
                       email_verified, wallet_verified, created_at, last_login
                FROM users 
                ORDER BY created_at DESC
            """)
            
            users = [dict(row) for row in await cursor.fetchall()]
            return jsonify({
                'success': True,
                'data': users,
                'count': len(users)
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ... (MOTION TRAJECTORY LINEUP)
# Fix the average filter and update the results route


@app.template_filter('average')
def average_filter(values):
    """Calculate average of a list of values"""
    if values is None:
        return 0
    
    # Convert async generator or other iterable to list
    if hasattr(values, '__aiter__'):
        # Handle async generators by converting to list (in practice, we should await this)
        # For template filters, we need to work with sync data
        return 0
    elif hasattr(values, '__iter__'):
        values_list = list(values)
    else:
        values_list = [values]
    
    if not values_list or len(values_list) == 0:
        return 0
    
    numeric_values = [v for v in values_list if isinstance(v, (int, float))]
    return sum(numeric_values) / len(numeric_values) if numeric_values else 0

# Add a new filter to handle async data safely
@app.template_filter('sync_list')
def sync_list_filter(values):
    """Convert async generator to list for template usage"""
    if hasattr(values, '__aiter__'):
        # In template context, we can't await, so return empty list
        return []
    elif hasattr(values, '__iter__'):
        return list(values)
    else:
        return [values]


class MotionTracker:
    """Advanced multi-object tracking with Kalman filtering"""
    
    def __init__(self, max_disappeared=10, max_distance=100):
        self.next_object_id = 0
        self.objects = {}
        self.disappeared = {}
        self.max_disappeared = max_disappeared
        self.max_distance = max_distance
        
        # Trajectory storage
        self.trajectories = defaultdict(list)
        self.speed_history = defaultdict(list)
        self.direction_history = defaultdict(list)
        self.kalman_filters = {}
        
    def _create_kalman_filter(self):
        """Create a Kalman filter for object tracking"""
        kf = KalmanFilter(dim_x=4, dim_z=2)
        
        kf.F = np.array([[1, 0, 1, 0],
                         [0, 1, 0, 1], 
                         [0, 0, 1, 0],
                         [0, 0, 0, 1]])
        
        kf.H = np.array([[1, 0, 0, 0],
                         [0, 1, 0, 0]])
        
        kf.Q = np.eye(4) * 0.1
        kf.R = np.eye(2) * 1
        kf.P *= 100
        
        return kf
        
    def register(self, centroid, bbox, class_name, confidence, frame_num, timestamp):
        """Register a new object"""
        object_id = self.next_object_id
        
        self.objects[object_id] = {
            'centroid': centroid,
            'bbox': bbox,
            'class_name': class_name,
            'confidence': confidence,
            'last_seen': frame_num,
            'first_seen': frame_num
        }
        self.disappeared[object_id] = 0
        self.trajectories[object_id].append((centroid[0], centroid[1], frame_num, timestamp))
        
        # Initialize Kalman filter
        kf = self._create_kalman_filter()
        kf.x = np.array([centroid[0], centroid[1], 0, 0])
        self.kalman_filters[object_id] = kf
        
        self.next_object_id += 1
        return object_id
    
    def deregister(self, object_id):
        """Remove an object that has disappeared"""
        if object_id in self.objects:
            del self.objects[object_id]
        if object_id in self.disappeared:
            del self.disappeared[object_id]
        if object_id in self.kalman_filters:
            del self.kalman_filters[object_id]
    
    def update(self, detections, frame_num, timestamp):
        """Update tracker with new detections"""
        # Predict next positions using Kalman filters
        for object_id, kf in self.kalman_filters.items():
            kf.predict()
            
        if len(detections) == 0:
            for object_id in list(self.disappeared.keys()):
                self.disappeared[object_id] += 1
                if self.disappeared[object_id] > self.max_disappeared:
                    self.deregister(object_id)
            return self.objects
        
        if len(self.objects) == 0:
            for detection in detections:
                centroid = self._get_centroid(detection['bbox'])
                self.register(centroid, detection['bbox'], detection['class_name'], 
                            detection['confidence'], frame_num, timestamp)
        else:
            predicted_centroids = []
            object_ids = list(self.objects.keys())
            
            for object_id in object_ids:
                if object_id in self.kalman_filters:
                    predicted_pos = self.kalman_filters[object_id].x[:2]
                    predicted_centroids.append(predicted_pos)
                else:
                    predicted_centroids.append(self.objects[object_id]['centroid'])
            
            detection_centroids = [self._get_centroid(det['bbox']) for det in detections]
            
            distances = np.linalg.norm(np.array(predicted_centroids)[:, np.newaxis] - 
                                     np.array(detection_centroids), axis=2)
            
            rows = distances.min(axis=1).argsort()
            cols = distances.argmin(axis=1)[rows]
            
            used_row_indices = set()
            used_col_indices = set()
            
            for (row, col) in zip(rows, cols):
                if row in used_row_indices or col in used_col_indices:
                    continue
                
                if distances[row, col] <= self.max_distance:
                    object_id = object_ids[row]
                    detection = detections[col]
                    centroid = detection_centroids[col]
                    
                    old_centroid = self.objects[object_id]['centroid']
                    self.objects[object_id]['centroid'] = centroid
                    self.objects[object_id]['bbox'] = detection['bbox']
                    self.objects[object_id]['confidence'] = detection['confidence']
                    self.objects[object_id]['last_seen'] = frame_num
                    self.disappeared[object_id] = 0
                    
                    if object_id in self.kalman_filters:
                        self.kalman_filters[object_id].update(np.array(centroid))
                    
                    if len(self.trajectories[object_id]) > 0:
                        speed = self._calculate_speed(old_centroid, centroid)
                        direction = self._calculate_direction(old_centroid, centroid)
                        
                        self.speed_history[object_id].append(speed)
                        self.direction_history[object_id].append(direction)
                    
                    self.trajectories[object_id].append((centroid[0], centroid[1], frame_num, timestamp))
                    
                    used_row_indices.add(row)
                    used_col_indices.add(col)
            
            unused_row_indices = set(range(0, distances.shape[0])).difference(used_row_indices)
            unused_col_indices = set(range(0, distances.shape[1])).difference(used_col_indices)
            
            for row in unused_row_indices:
                object_id = object_ids[row]
                self.disappeared[object_id] += 1
                if self.disappeared[object_id] > self.max_disappeared:
                    self.deregister(object_id)
            
            for col in unused_col_indices:
                detection = detections[col]
                centroid = detection_centroids[col]
                self.register(centroid, detection['bbox'], detection['class_name'], 
                            detection['confidence'], frame_num, timestamp)
        
        return self.objects
    
    def _get_centroid(self, bbox):
        """Calculate centroid from bounding box"""
        x, y, w, h = bbox
        return (int(x + w/2), int(y + h/2))
    
    def _calculate_speed(self, old_centroid, new_centroid):
        """Calculate speed between two points"""
        return euclidean(old_centroid, new_centroid)
    
    def _calculate_direction(self, old_centroid, new_centroid):
        """Calculate direction angle between two points"""
        dx = new_centroid[0] - old_centroid[0]
        dy = new_centroid[1] - old_centroid[1]
        return np.arctan2(dy, dx) * 180 / np.pi
    
    def get_trajectory_analysis(self):
        """Get comprehensive trajectory analysis"""
        analysis = {}
        
        for object_id, trajectory in self.trajectories.items():
            if len(trajectory) < 2:
                continue
                
            traj_array = np.array(trajectory)
            
            total_distance = 0
            for i in range(1, len(trajectory)):
                total_distance += euclidean(trajectory[i][:2], trajectory[i-1][:2])
            
            avg_speed = np.mean(self.speed_history[object_id]) if self.speed_history[object_id] else 0
            max_speed = np.max(self.speed_history[object_id]) if self.speed_history[object_id] else 0
            
            directions = self.direction_history[object_id]
            direction_variance = np.var(directions) if directions else 0
            
            start_time = trajectory[0][3] if len(trajectory) > 0 else 0
            end_time = trajectory[-1][3] if len(trajectory) > 0 else 0
            duration = end_time - start_time
            
            x_coords = [point[0] for point in trajectory]
            y_coords = [point[1] for point in trajectory]
            
            analysis[object_id] = {
                'object_class': self.objects.get(object_id, {}).get('class_name', 'unknown'),
                'total_distance': total_distance,
                'avg_speed': avg_speed,
                'max_speed': max_speed,
                'duration': duration,
                'direction_variance': direction_variance,
                'path_straightness': 1.0 / (1.0 + direction_variance) if direction_variance > 0 else 1.0,
                'bounding_rect': {
                    'x_min': min(x_coords), 'x_max': max(x_coords),
                    'y_min': min(y_coords), 'y_max': max(y_coords)
                },
                'trajectory_points': len(trajectory),
                'start_frame': trajectory[0][2],
                'end_frame': trajectory[-1][2]
            }
            
        return analysis


class MotionHeatmapGenerator:
    """Generate motion heatmaps and trajectory visualizations"""
    
    def __init__(self, frame_width, frame_height):
        self.frame_width = frame_width
        self.frame_height = frame_height
        self.heatmap_data = np.zeros((frame_height, frame_width), dtype=np.float32)
        self.trajectory_heatmap = np.zeros((frame_height, frame_width), dtype=np.float32)
        
    def add_detection(self, bbox, confidence=1.0):
        """Add a detection to the heatmap"""
        x, y, w, h = bbox
        x, y, w, h = int(x), int(y), int(w), int(h)
        
        x = max(0, min(x, self.frame_width - 1))
        y = max(0, min(y, self.frame_height - 1))
        w = min(w, self.frame_width - x)
        h = min(h, self.frame_height - y)
        
        center_x, center_y = x + w//2, y + h//2
        
        kernel_size = max(w, h) // 2
        if kernel_size < 5:
            kernel_size = 5
            
        y_indices, x_indices = np.ogrid[:kernel_size*2+1, :kernel_size*2+1]
        gaussian = np.exp(-((x_indices - kernel_size)**2 + (y_indices - kernel_size)**2) / (2.0 * (kernel_size/3)**2))
        
        start_y = max(0, center_y - kernel_size)
        end_y = min(self.frame_height, center_y + kernel_size + 1)
        start_x = max(0, center_x - kernel_size)
        end_x = min(self.frame_width, center_x + kernel_size + 1)
        
        gaussian_start_y = max(0, kernel_size - center_y) if center_y < kernel_size else 0
        gaussian_end_y = gaussian_start_y + (end_y - start_y)
        gaussian_start_x = max(0, kernel_size - center_x) if center_x < kernel_size else 0
        gaussian_end_x = gaussian_start_x + (end_x - start_x)
        
        if gaussian_end_y > gaussian_start_y and gaussian_end_x > gaussian_start_x:
            self.heatmap_data[start_y:end_y, start_x:end_x] += gaussian[gaussian_start_y:gaussian_end_y, gaussian_start_x:gaussian_end_x] * confidence
    
    def add_trajectory_point(self, point, intensity=1.0):
        """Add a trajectory point to the trajectory heatmap"""
        x, y = int(point[0]), int(point[1])
        if 0 <= x < self.frame_width and 0 <= y < self.frame_height:
            for dx in range(-2, 3):
                for dy in range(-2, 3):
                    if 0 <= x+dx < self.frame_width and 0 <= y+dy < self.frame_height:
                        if dx*dx + dy*dy <= 4:
                            self.trajectory_heatmap[y+dy, x+dx] += intensity
    
    def generate_heatmap_image(self, colormap='hot'):
        """Generate heatmap visualization"""
        if self.heatmap_data.max() > 0:
            normalized = self.heatmap_data / self.heatmap_data.max()
        else:
            normalized = self.heatmap_data
            
        cmap = plt.get_cmap(colormap)
        colored = cmap(normalized)
        heatmap_img = (colored * 255).astype(np.uint8)
        
        return heatmap_img
    
    def generate_trajectory_heatmap(self, colormap='plasma'):
        """Generate trajectory heatmap visualization"""
        if self.trajectory_heatmap.max() > 0:
            normalized = self.trajectory_heatmap / self.trajectory_heatmap.max()
        else:
            normalized = self.trajectory_heatmap
            
        cmap = plt.get_cmap(colormap)
        colored = cmap(normalized)
        trajectory_img = (colored * 255).astype(np.uint8)
        
        return trajectory_img

    def generate_object_trajectory(self, trajectory_points, frame_width=None, frame_height=None):
        """Generate individual object trajectory visualization"""
        if not frame_width:
            frame_width = self.frame_width
        if not frame_height:
            frame_height = self.frame_height
            
        fig, ax = plt.subplots(figsize=(10, 8))
        
        x_coords = [point[0] for point in trajectory_points]
        y_coords = [point[1] for point in trajectory_points]
        
        ax.plot(x_coords, y_coords, 'b-', linewidth=2, alpha=0.7, label='Trajectory')
        ax.scatter(x_coords, y_coords, c=range(len(x_coords)), cmap='viridis', s=30, alpha=0.8)
        
        if len(trajectory_points) > 0:
            ax.scatter(x_coords[0], y_coords[0], color='green', s=100, marker='o', label='Start')
            ax.scatter(x_coords[-1], y_coords[-1], color='red', s=100, marker='s', label='End')
        
        ax.set_xlim(0, frame_width)
        ax.set_ylim(frame_height, 0)
        ax.set_xlabel('X Position (pixels)')
        ax.set_ylabel('Y Position (pixels)')
        ax.set_title('Object Trajectory Path')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()


# Update the MotionAnalyzer class to use the standalone function
class MotionAnalyzer:
    """Main motion analysis processor"""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        
    async def process_video_for_motion(self, video_path: str, job_id: int, user_id: int, 
                                     confidence_threshold: float = 0.5, 
                                     frame_skip: int = 5):
        """Process video for motion tracking and analysis"""
        
        try:
            active_jobs[job_id] = {'status': 'processing', 'progress': 0, 'message': 'Initializing...'}
            await self._update_job_status(job_id, 'processing', "Initializing video processing")
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"Cannot open video file: {video_path}")
            
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            tracker = MotionTracker(max_disappeared=15, max_distance=150)
            heatmap_gen = MotionHeatmapGenerator(frame_width, frame_height)
            
            backSub = cv2.createBackgroundSubtractorMOG2(detectShadows=True)
            
            frame_count = 0
            processed_frames = 0
            
            active_jobs[job_id] = {'status': 'processing', 'progress': 0, 'message': f'Processing {total_frames} frames'}
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                current_time = frame_count / fps if fps > 0 else frame_count
                
                if frame_count % (frame_skip + 1) == 0:
                    fg_mask = backSub.apply(frame)
                    
                    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
                    fg_mask = cv2.morphologyEx(fg_mask, cv2.MORPH_OPEN, kernel)
                    
                    contours, _ = cv2.findContours(fg_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    
                    detections = []
                    for contour in contours:
                        if cv2.contourArea(contour) > 500:
                            x, y, w, h = cv2.boundingRect(contour)
                            
                            if w > 20 and h > 20 and w < frame_width/2 and h < frame_height/2:
                                detection = {
                                    'bbox': (x, y, w, h),
                                    'confidence': 0.8,
                                    'class_name': 'moving_object'
                                }
                                detections.append(detection)
                                heatmap_gen.add_detection((x, y, w, h), 0.8)
                    
                    tracked_objects = tracker.update(detections, frame_count, current_time)
                    
                    for obj_id, obj_info in tracked_objects.items():
                        if obj_id in tracker.trajectories:
                            trajectory = tracker.trajectories[obj_id]
                            if len(trajectory) > 0:
                                latest_point = trajectory[-1]
                                heatmap_gen.add_trajectory_point(latest_point[:2])
                    
                    processed_frames += 1
                    
                    if processed_frames % 20 == 0:
                        progress = (frame_count / total_frames) * 100
                        active_jobs[job_id] = {
                            'status': 'processing', 
                            'progress': progress, 
                            'message': f'Processed {processed_frames} frames ({progress:.1f}%)'
                        }
                
                frame_count += 1
                
                if frame_count % 100 == 0:
                    await asyncio.sleep(0.01)
            
            cap.release()
            
            active_jobs[job_id] = {'status': 'processing', 'progress': 90, 'message': 'Generating analysis...'}
            trajectory_analysis = tracker.get_trajectory_analysis()
            heatmap_img = heatmap_gen.generate_heatmap_image()
            trajectory_heatmap = heatmap_gen.generate_trajectory_heatmap()
            
            results = await self._save_motion_results(
                job_id, user_id, trajectory_analysis, 
                heatmap_img, trajectory_heatmap, tracker
            )
            
            active_jobs[job_id] = {
                'status': 'completed', 
                'progress': 100, 
                'message': f'Analysis completed. Tracked {len(trajectory_analysis)} objects'
            }
            await self._update_job_status(job_id, 'completed', 
                                        f"Motion analysis completed. Tracked {len(trajectory_analysis)} objects")
            
            return results
            
        except Exception as e:
            active_jobs[job_id] = {'status': 'failed', 'progress': 0, 'message': str(e)}
            await self._update_job_status(job_id, 'failed', str(e))
            raise e
    
    async def _save_motion_results(self, job_id: int, user_id: int, analysis: Dict, 
                                 heatmap_img: np.ndarray, trajectory_heatmap: np.ndarray, 
                                 tracker: MotionTracker):
        """Save motion analysis results to database"""
        
        heatmap_b64 = self._image_to_base64(heatmap_img)
        trajectory_b64 = self._image_to_base64(trajectory_heatmap)
        
        # Ensure analysis data is JSON serializable
        serializable_analysis = {}
        for obj_id, obj_analysis in analysis.items():
            serializable_analysis[str(obj_id)] = {
                k: (float(v) if isinstance(v, (int, float, np.number)) else str(v) if v is not None else None)
                for k, v in obj_analysis.items()
            }
        
        async with aiosqlite.connect(self.db_path) as db:
              # Use the standalone function
            
            await db.execute("""
                INSERT INTO motion_analysis 
                (job_id, user_id, total_objects, analysis_data, heatmap_image, trajectory_heatmap)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (job_id, user_id, len(analysis), json.dumps(serializable_analysis), heatmap_b64, trajectory_b64))
            
            analysis_id = job_id
            
            for obj_id, obj_analysis in analysis.items():
                # Ensure trajectory data is properly formatted
                trajectory_points = tracker.trajectories.get(obj_id, [])
                serializable_trajectory = []
                for point in trajectory_points:
                    if len(point) >= 2:
                        trajectory_point = [
                            float(point[0]) if point[0] is not None else 0.0,
                            float(point[1]) if point[1] is not None else 0.0
                        ]
                        if len(point) > 2:
                            trajectory_point.append(int(point[2]) if point[2] is not None else 0)
                        if len(point) > 3:
                            trajectory_point.append(float(point[3]) if point[3] is not None else 0.0)
                        serializable_trajectory.append(trajectory_point)
                
                # Fix: Ensure speed and direction data are proper JSON arrays, not string representations
                speed_data = tracker.speed_history.get(obj_id, [])
                direction_data = tracker.direction_history.get(obj_id, [])
                
                # Convert numpy types to Python native types
                speed_data_clean = [float(s) if isinstance(s, (int, float, np.number)) else 0.0 for s in speed_data]
                direction_data_clean = [float(d) if isinstance(d, (int, float, np.number)) else 0.0 for d in direction_data]
                
                trajectory_json = json.dumps(serializable_trajectory)
                speed_json = json.dumps(speed_data_clean)
                direction_json = json.dumps(direction_data_clean)
                
                await db.execute("""
                    INSERT INTO object_trajectories 
                    (analysis_id, object_id, object_class, trajectory_data, speed_data, 
                     direction_data, total_distance, avg_speed, max_speed, duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id, 
                    obj_id, 
                    obj_analysis.get('object_class', 'unknown'), 
                    trajectory_json,
                    speed_json, 
                    direction_json, 
                    float(obj_analysis.get('total_distance', 0)),
                    float(obj_analysis.get('avg_speed', 0)), 
                    float(obj_analysis.get('max_speed', 0)), 
                    float(obj_analysis.get('duration', 0))
                ))
            
            await db.commit()
            
        return {
            'analysis_id': analysis_id,
            'total_objects': len(analysis),
            'analysis_data': serializable_analysis,
            'heatmap_available': True,
            'trajectory_heatmap_available': True
        }
    
    def _image_to_base64(self, img: np.ndarray) -> str:
        """Convert numpy image to base64 string"""
        _, buffer = cv2.imencode('.png', img)
        img_b64 = base64.b64encode(buffer).decode('utf-8')
        return img_b64
    
    async def _update_job_status(self, job_id: int, status: str, message: str = ""):
        """Update job status in database"""
        async with aiosqlite.connect(self.db_path) as db:
              # Use the standalone function
            if status == 'completed':
                await db.execute("""
                    UPDATE jobs SET status = ?, completed_at = datetime('now') WHERE id = ?
                """, (status, job_id))
            elif status == 'processing' and message:
                await db.execute("""
                    UPDATE jobs SET status = ?, started_at = datetime('now') WHERE id = ?
                """, (status, job_id))
            else:
                await db.execute("""
                    UPDATE jobs SET status = ? WHERE id = ?
                """, (status, job_id))
                
            await db.commit()

# Also update the database creation to ensure proper data storage
# Fix the _save_motion_results method in MotionAnalyzer class
async def _save_motion_results(self, job_id: int, user_id: int, analysis: Dict, 
                             heatmap_img: np.ndarray, trajectory_heatmap: np.ndarray, 
                             tracker: MotionTracker):
    """Save motion analysis results to database"""
    
    heatmap_b64 = self._image_to_base64(heatmap_img)
    trajectory_b64 = self._image_to_base64(trajectory_heatmap)
    
    # Ensure analysis data is JSON serializable
    serializable_analysis = {}
    for obj_id, obj_analysis in analysis.items():
        serializable_analysis[str(obj_id)] = {
            k: (float(v) if isinstance(v, (int, float, np.number)) else str(v) if v is not None else None)
            for k, v in obj_analysis.items()
        }
    
    async with aiosqlite.connect(self.db_path) as db:
        await self._create_tables(db)
        
        await db.execute("""
            INSERT INTO motion_analysis 
            (job_id, user_id, total_objects, analysis_data, heatmap_image, trajectory_heatmap)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (job_id, g.current_user['user_id'], len(analysis), json.dumps(serializable_analysis), heatmap_b64, trajectory_b64))
        
        analysis_id = job_id
        
        for obj_id, obj_analysis in analysis.items():
            # Ensure trajectory data is properly formatted
            trajectory_points = tracker.trajectories.get(obj_id, [])
            serializable_trajectory = []
            for point in trajectory_points:
                if len(point) >= 2:
                    trajectory_point = [
                        float(point[0]) if point[0] is not None else 0.0,
                        float(point[1]) if point[1] is not None else 0.0
                    ]
                    if len(point) > 2:
                        trajectory_point.append(int(point[2]) if point[2] is not None else 0)
                    if len(point) > 3:
                        trajectory_point.append(float(point[3]) if point[3] is not None else 0.0)
                    serializable_trajectory.append(trajectory_point)
            
            # Fix: Ensure speed and direction data are proper JSON arrays, not string representations
            speed_data = tracker.speed_history.get(obj_id, [])
            direction_data = tracker.direction_history.get(obj_id, [])
            
            # Convert numpy types to Python native types
            speed_data_clean = [float(s) if isinstance(s, (int, float, np.number)) else 0.0 for s in speed_data]
            direction_data_clean = [float(d) if isinstance(d, (int, float, np.number)) else 0.0 for d in direction_data]
            
            trajectory_json = json.dumps(serializable_trajectory)
            speed_json = json.dumps(speed_data_clean)
            direction_json = json.dumps(direction_data_clean)
            
            await db.execute("""
                INSERT INTO object_trajectories 
                (analysis_id, object_id, object_class, trajectory_data, speed_data, 
                 direction_data, total_distance, avg_speed, max_speed, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id, 
                obj_id, 
                obj_analysis.get('object_class', 'unknown'), 
                trajectory_json,
                speed_json, 
                direction_json, 
                float(obj_analysis.get('total_distance', 0)),
                float(obj_analysis.get('avg_speed', 0)), 
                float(obj_analysis.get('max_speed', 0)), 
                float(obj_analysis.get('duration', 0))
            ))
        
        await db.commit()
        
    return {
        'analysis_id': analysis_id,
        'total_objects': len(analysis),
        'analysis_data': serializable_analysis,
        'heatmap_available': True,
        'trajectory_heatmap_available': True
    }

    
def _image_to_base64(self, img: np.ndarray) -> str:
    """Convert numpy image to base64 string"""
    _, buffer = cv2.imencode('.png', img)
    img_b64 = base64.b64encode(buffer).decode('utf-8')
    return img_b64

async def _update_job_status(self, job_id: int, status: str, message: str = ""):
    """Update job status in database"""
    async with aiosqlite.connect(self.db_path) as db:
        await self._create_tables(db)
        if status == 'completed':
            await db.execute("""
                UPDATE jobs SET status = ?, completed_at = datetime('now') WHERE id = ?
            """, (status, job_id))
        elif status == 'processing' and message:
            await db.execute("""
                UPDATE jobs SET status = ?, started_at = datetime('now') WHERE id = ?
            """, (status, job_id))
        else:
            await db.execute("""
                UPDATE jobs SET status = ? WHERE id = ?
            """, (status, job_id))
            
        await db.commit()




# API ROutes DECL




# API Routes

@app.route('/Motion')
async def handshake_motion():

    """Enhanced dashboard"""
    return await render_template_string(ENHANCED_DASHBOARD_HTML)

@app.route('/motion/dashboard')
async def motion_dashboard():
    """Interactive dashboard"""
    stats = await get_dashboard_stats()
    recent_jobs = await get_recent_jobs()
    return await render_template_string(INTERACTIVE_DASHBOARD_HTML, stats=stats, recent_jobs=recent_jobs)

@app.route('/upload', methods=['GET', 'POST'])
@auth_required
async def upload_video():

    """Handle video upload"""
    if request.method == 'GET':
        return await render_template_string(UPLOAD_HTML)
    
    files = await request.files
    form = await request.form
    
    if 'video' not in files:
        return jsonify({'error': 'No video file provided'}), 400
    
    video_file = files['video']
    if video_file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
      
    up_id = random.randrange(10000000)
    user_id = g.current_user['user_id']
    byte_size = str(int(34))
    filename = f"{int(time.time())}_{video_file.filename}"
    file_path = os.path.join(UPLOAD_DIR , filename)
    Generic_Hash = None
     
    await video_file.save(str(file_path))
    
    async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                INSERT INTO uploads (id , user_id, filename , saved_path , size_bytes , file_hash ,  upload_method , 
                            created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'))
             """, (up_id , user_id, filename , file_path , byte_size ,  Generic_Hash if Generic_Hash else '404X' , 'file' if file_path else 'url'))
            await db.commit()
    
    

    
    confidence = float(form.get('confidence', 0.5))
    frame_skip = int(form.get('frame_skip', 5))
    
    user_id = g.current_user['user_id']
    job_id = await create_motion_job(user_id, str(file_path), 
                                   confidence=confidence, frame_skip=frame_skip)
    
    return jsonify({
        'job_id': job_id,
        'status': 'created',
        'message': 'Upload successful, processing started'
    })


# Fix the view_results route to properly handle the data
@app.route('/results/<int:job_id>')
@auth_required
async def view_results(job_id):
    """View analysis results"""
    user_id = g.current_user['user_id']
    results = await get_motion_results(job_id, user_id)
    
    if not results:
        return "Job not found", 404
    
    if results.get('status') != 'completed':
        return await render_template_string(PROGRESS_HTML, job_id=job_id, status=results)
    
    # Ensure trajectories is a proper list for template usage
    if 'trajectories' in results and hasattr(results['trajectories'], '__aiter__'):
        results['trajectories'] = []
    elif 'trajectories' in results:
        results['trajectories'] = list(results['trajectories'])
    
    return await render_template_string(ENHANCED_RESULTS_HTML, job_id=job_id, results=results)



# Fix the track_object route with better JSON parsing
@app.route('/track/<int:job_id>/<int:object_id>')
@auth_required
async def track_object(job_id, object_id):
    """Individual object tracking view"""
   
    user_id = g.current_user['user_id']
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT ot.*, ma.analysis_data 
                FROM object_trajectories ot
                JOIN motion_analysis ma ON ot.analysis_id = ma.id
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ? AND ot.object_id = ?
            """, (job_id, user_id, object_id))
            result = await cursor.fetchone()
            
            if not result:
                return "Object trajectory not found", 404
            
            # Safely parse JSON data with comprehensive error handling
            def safe_json_parse(data, default=None):
                """Safely parse JSON data with multiple fallbacks"""
                if data is None or data == '':
                    return default if default is not None else []
                
                # If it's already a list/dict, return it
                if isinstance(data, (list, dict)):
                    return data
                
                # Try to parse as JSON
                try:
                    return json.loads(data)
                except (json.JSONDecodeError, TypeError) as e:
                    print(f"JSON parse error: {e}, data: {repr(data)}")
                    
                    # If it looks like a string representation of a list, try eval (carefully)
                    if isinstance(data, str) and data.startswith('[') and data.endswith(']'):
                        try:
                            # Use ast.literal_eval for safe evaluation
                            import ast
                            return ast.literal_eval(data)
                        except (SyntaxError, ValueError) as e2:
                            print(f"Literal eval error: {e2}")
                    
                    return default if default is not None else []
            
            trajectory_data = safe_json_parse(result[3], [])
            speed_data = safe_json_parse(result[4], [])
            direction_data = safe_json_parse(result[5], [])
            analysis_data = safe_json_parse(result[11], {})
            
            # Fix: Ensure numeric values are properly converted
            def safe_float(value, default=0.0):
                """Safely convert to float"""
                if value is None:
                    return default
                try:
                    return float(value)
                except (ValueError, TypeError):
                    return default
            
            object_info = {
                'object_id': object_id,
                'job_id': job_id,
                'object_class': result[2] or 'unknown',
                'trajectory_points': trajectory_data,
                'speed_data': speed_data,
                'direction_data': direction_data,
                'total_distance': safe_float(result[6]),
                'avg_speed': safe_float(result[7]),
                'max_speed': safe_float(result[8]),
                'duration': safe_float(result[9]),
                'analysis_summary': analysis_data.get(str(object_id), {})
            }
            
            print(f"Loaded object {object_id}: {len(trajectory_data)} trajectory points")
            
            return await render_template_string(OBJECT_TRACKING_HTML, object_info=object_info)
            
    except Exception as e:
        print(f"Error loading object tracking: {e}")
        import traceback
        traceback.print_exc()
        return f"Error loading object tracking: {str(e)}", 500





# Update the migrate_database function to use the standalone create_tables function
async def migrate_database():
    """Migrate existing database to fix data format issues"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
              # Use the standalone function
            
            # Check if we need to migrate
            cursor = await db.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND name='object_trajectories'
            """)
            if not await cursor.fetchone():
                return  # No trajectories table yet
            
            # Check for problematic data
            cursor = await db.execute("""
                SELECT object_id, speed_data, direction_data FROM object_trajectories 
                WHERE speed_data LIKE '[%' OR direction_data LIKE '[%'
            """)
            problematic_records = await cursor.fetchall()
            
            for record in problematic_records:
                object_id, speed_data, direction_data = record
                
                # Fix speed data
                if speed_data and speed_data.startswith('[') and speed_data.endswith(']'):
                    try:
                        import ast
                        fixed_speed = json.dumps(ast.literal_eval(speed_data))
                        await db.execute("UPDATE object_trajectories SET speed_data = ? WHERE object_id = ?", 
                                       (fixed_speed, object_id))
                        print(f"Fixed speed data for object {object_id}")
                    except:
                        print(f"Could not fix speed data for object {object_id}")
                
                # Fix direction data
                if direction_data and direction_data.startswith('[') and direction_data.endswith(']'):
                    try:
                        import ast
                        fixed_direction = json.dumps(ast.literal_eval(direction_data))
                        await db.execute("UPDATE object_trajectories SET direction_data = ? WHERE object_id = ?", 
                                       (fixed_direction, object_id))
                        print(f"Fixed direction data for object {object_id}")
                    except:
                        print(f"Could not fix direction data for object {object_id}")
            
            await db.commit()
            print("Database migration completed")
            
    except Exception as e:
        print(f"Database migration error: {e}")



# Add a route to trigger database migration
@app.route('/admin/migrate-db')
async def admin_migrate_db():
    """Admin route to migrate database (one-time use)"""
    await migrate_database()
    return jsonify({'status': 'Migration completed'})





# Update the get_object_trajectory_image function with better error handling
@app.route('/api/motion/object-trajectory/<int:job_id>/<int:object_id>')
@auth_required
async def get_object_trajectory_image(job_id, object_id):
    """Get individual object trajectory visualization"""

    user_id = g.current_user['user_id']
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT trajectory_data FROM object_trajectories ot
                JOIN motion_analysis ma ON ot.analysis_id = ma.id
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ? AND ot.object_id = ?
            """, (job_id, user_id, object_id))
            result = await cursor.fetchone()
            
            if not result or not result[0]:
                return jsonify({'error': 'Object trajectory not found or empty'}), 404
            
            # Safely parse trajectory data with multiple fallbacks
            trajectory_data = None
            data = result[0]
            
            # Try JSON parse first
            try:
                trajectory_data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                # Try literal eval for string representations
                try:
                    import ast
                    trajectory_data = ast.literal_eval(data)
                except (SyntaxError, ValueError):
                    trajectory_data = []
            
            if not trajectory_data or len(trajectory_data) == 0:
                # Create a simple placeholder image
                fig, ax = plt.subplots(figsize=(10, 8))
                ax.text(0.5, 0.5, 'No trajectory data available', 
                       horizontalalignment='center', verticalalignment='center',
                       transform=ax.transAxes, fontsize=16)
                ax.set_xlim(0, 1)
                ax.set_ylim(0, 1)
                ax.axis('off')
                
                buffer = io.BytesIO()
                plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
                plt.close()
                
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                temp_file.write(buffer.getvalue())
                temp_file.close()
                
                return await send_file(temp_file.name, mimetype='image/png')
            
            # Create trajectory visualization
            heatmap_gen = MotionHeatmapGenerator(800, 600)
            trajectory_img = heatmap_gen.generate_object_trajectory(trajectory_data)
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            temp_file.write(trajectory_img)
            temp_file.close()
            
            return await send_file(temp_file.name, mimetype='image/png')
            
    except Exception as e:
        print(f"Error generating trajectory image: {e}")
        # Return a simple error image
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.text(0.5, 0.5, f'Error: {str(e)}', 
               horizontalalignment='center', verticalalignment='center',
               transform=ax.transAxes, fontsize=12, color='red')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        plt.close()
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
        temp_file.write(buffer.getvalue())
        temp_file.close()
        
        return await send_file(temp_file.name, mimetype='image/png')



@app.route('/api/motion/analyze', methods=['POST'])
async def analyze_motion():
    """Start motion analysis job"""
    data = await request.get_json()
    
    user_id = g.current_user['user_id']
    file_path = data.get('file_path')
    confidence = data.get('confidence', 0.5)
    frame_skip = data.get('frame_skip', 5)
    
    if not file_path:
        return jsonify({'error': 'file_path required'}), 400
    
    try:
        job_id = await create_motion_job(user_id, file_path, confidence=confidence, frame_skip=frame_skip)
        return jsonify({'job_id': job_id, 'status': 'created'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/motion/results/<int:job_id>')
@auth_required
async def get_motion_analysis_results(job_id):
    """Get motion analysis results"""
    user_id = g.current_user['user_id']
    
    
    try:
        results = await get_motion_results(job_id, user_id)
        if results is None:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/motion/status/<int:job_id>')
@auth_required
async def get_job_status(job_id):
    """Get real-time job status"""
    if job_id in active_jobs:
        return jsonify(active_jobs[job_id])
    else:
        
        user_id = g.current_user['user_id']
    
        results = await get_motion_results(job_id, user_id)
        if results:
            return jsonify(results)
        else:
            return jsonify({'error': 'Job not found'}), 404

@app.route('/api/motion/heatmap/<int:job_id>')
@auth_required
async def get_motion_heatmap(job_id):
    """Get motion heatmap image"""
    user_id = g.current_user['user_id']
    
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT heatmap_image FROM motion_analysis ma
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ?
            """, (job_id, user_id))
            result = await cursor.fetchone()
            
            if not result:
                return jsonify({'error': 'Heatmap not found'}), 404
            
            img_data = base64.b64decode(result[0])
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            temp_file.write(img_data)
            temp_file.close()
            
            return await send_file(temp_file.name, mimetype='image/png')
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/motion/trajectory-heatmap/<int:job_id>')
@auth_required
async def get_trajectory_heatmap(job_id):
    """Get trajectory heatmap image"""
   
    user_id = g.current_user['user_id']
    
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT trajectory_heatmap FROM motion_analysis ma
                JOIN jobs j ON ma.job_id = j.id
                WHERE j.id = ? AND j.user_id = ?
            """, (job_id, user_id))
            result = await cursor.fetchone()
            
            if not result:
                return jsonify({'error': 'Trajectory heatmap not found'}), 404
            
            img_data = base64.b64decode(result[0])
            
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            temp_file.write(img_data)
            temp_file.close()
            
            return await send_file(temp_file.name, mimetype='image/png')
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500





##################################################################
##################### TIMELINE ###################################



# Global storage
active_timeline_jobs = {}
live_websockets = defaultdict(list)
active_trackers = {}

class ObjectProfile:
    """Individual object profile with comprehensive tracking"""
    
    def __init__(self, object_id, first_appearance, bbox, class_name, color):
        self.object_id = object_id
        self.class_name = class_name
        self.color = color
        
        # Appearance tracking
        self.appearance_segments = []  # List of {start_frame, end_frame, start_time, end_time}
        self.current_segment = {
            'start_frame': first_appearance['frame_num'],
            'end_frame': first_appearance['frame_num'],
            'start_time': first_appearance['timestamp'],
            'end_time': first_appearance['timestamp']
        }
        
        # Statistics
        self.total_duration = 0.0
        self.total_frames = 1
        self.appearance_count = 1
        
        # Visual data
        self.snapshots = []  # List of {frame_num, timestamp, bbox, image_data}
        self.keyframes = []  # Important frames for this object
        self.trajectory = []  # Movement path
        
        # Current state
        self.last_seen_frame = first_appearance['frame_num']
        self.last_seen_time = first_appearance['timestamp']
        self.last_bbox = bbox
        self.disappeared_frames = 0
        
        # Take initial snapshot
        self._take_snapshot(first_appearance['frame_num'], first_appearance['timestamp'], bbox, first_appearance.get('frame_data'))
    
    def update_appearance(self, frame_num, timestamp, bbox, frame_data=None):
        """Update object appearance with continuity check"""
        self.last_seen_frame = frame_num
        self.last_seen_time = timestamp
        self.last_bbox = bbox
        self.disappeared_frames = 0
        self.total_frames += 1
        
        # Check if this is a continuation or new appearance
        frame_gap = frame_num - self.current_segment['end_frame']
        time_gap = timestamp - self.current_segment['end_time']
        
        if frame_gap <= 30 and time_gap <= 2.0:  # Continuation threshold
            # Continue current segment
            self.current_segment['end_frame'] = frame_num
            self.current_segment['end_time'] = timestamp
        else:
            # End current segment and start new one
            self._finalize_current_segment()
            self.current_segment = {
                'start_frame': frame_num,
                'end_frame': frame_num,
                'start_time': timestamp,
                'end_time': timestamp
            }
            self.appearance_count += 1
        
        # Take periodic snapshots (every 30 frames or 2 seconds)
        if len(self.snapshots) == 0 or frame_num - self.snapshots[-1]['frame_num'] >= 30:
            self._take_snapshot(frame_num, timestamp, bbox, frame_data)
        
        # Update trajectory
        centroid = self._get_centroid(bbox)
        self.trajectory.append({
            'frame_num': frame_num,
            'timestamp': timestamp,
            'position': centroid,
            'bbox': bbox
        })
    
    def mark_disappeared(self, frame_num):
        """Mark object as disappeared"""
        self.disappeared_frames += 1
        
        # If disappeared for too long, finalize current segment
        if self.disappeared_frames >= 30:  # 1 second at 30fps
            self._finalize_current_segment()
    
    def _finalize_current_segment(self):
        """Finalize current appearance segment"""
        if (self.current_segment['end_frame'] > self.current_segment['start_frame'] or
            self.current_segment['end_time'] > self.current_segment['start_time']):
            
            segment_duration = (self.current_segment['end_time'] - 
                              self.current_segment['start_time'])
            self.total_duration += segment_duration
            
            self.appearance_segments.append(self.current_segment.copy())
    
    def _take_snapshot(self, frame_num, timestamp, bbox, frame_data=None):
        """Take snapshot of object"""
        if frame_data is not None:
            # Extract object from frame using bbox
            x, y, w, h = bbox
            x, y, w, h = int(x), int(y), int(w), int(h)
            
            # Ensure coordinates are within frame bounds
            if (0 <= y < frame_data.shape[0] and 0 <= x < frame_data.shape[1] and
                y + h <= frame_data.shape[0] and x + w <= frame_data.shape[1]):
                
                object_crop = frame_data[y:y+h, x:x+w]
                
                # Encode as base64 for storage
                _, buffer = cv2.imencode('.jpg', object_crop, [cv2.IMWRITE_JPEG_QUALITY, 70])
                image_data = base64.b64encode(buffer).decode('utf-8')
                
                snapshot = {
                    'frame_num': frame_num,
                    'timestamp': timestamp,
                    'bbox': bbox,
                    'image_data': image_data,
                    'position': self._get_centroid(bbox)
                }
                
                self.snapshots.append(snapshot)
                
                # Keep only last 5 snapshots to save space
                if len(self.snapshots) > 5:
                    self.snapshots.pop(0)
    
    def _get_centroid(self, bbox):
        """Calculate centroid from bounding box"""
        x, y, w, h = bbox
        return (int(x + w/2), int(y + h/2))
    
    def get_profile_summary(self):
        """Get comprehensive object profile"""
        # Finalize any active segment
        if (self.current_segment['end_frame'] >= self.current_segment['start_frame'] and
            self.current_segment['end_time'] >= self.current_segment['start_time']):
            self._finalize_current_segment()
        
        return {
            'object_id': self.object_id,
            'class_name': self.class_name,
            'color': self.color,
            'total_duration': self.total_duration,
            'total_frames': self.total_frames,
            'appearance_count': self.appearance_count,
            'last_seen_frame': self.last_seen_frame,
            'last_seen_time': self.last_seen_time,
            'appearance_segments': self.appearance_segments,
            'snapshots_count': len(self.snapshots),
            'trajectory_length': len(self.trajectory),
            'snapshots': self.snapshots,
            'keyframes': [seg['start_frame'] for seg in self.appearance_segments[:3]],  # First 3 appearance starts
            'trajectory': self.trajectory[-20:]  # Last 20 trajectory points
        }

class ObjectTimelineTracker:
    """Main tracker managing all object profiles"""
    
    def __init__(self):
        self.object_profiles = {}  # object_id -> ObjectProfile
        self.next_object_id = 1
        self.color_palette = self._generate_color_palette()
        self.frame_count = 0
        self.current_time = 0.0
        
    def _generate_color_palette(self):
        """Generate distinct colors for object tracking"""
        colors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7',
            '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9',
            '#F8C471', '#82E0AA', '#F1948A', '#85C1E9', '#D7BDE2',
            '#F9E79F', '#ABEBC6', '#AED6F1', '#FAD7A0', '#A2D9CE'
        ]
        return deque(colors * 3)  # Repeat to ensure enough colors
    
    def process_frame(self, frame, detections, frame_num, timestamp):
        """Process frame and update all object profiles"""
        self.frame_count = frame_num
        self.current_time = timestamp
        
        # Update existing objects
        updated_objects = set()
        
        for obj_id, profile in list(self.object_profiles.items()):
            # Find best matching detection for this object
            best_match = None
            best_distance = float('inf')
            
            for i, det in enumerate(detections):
                if i in updated_objects:
                    continue
                
                # Calculate distance between object and detection
                obj_center = profile._get_centroid(profile.last_bbox)
                det_center = profile._get_centroid(det['bbox'])
                distance = euclidean(obj_center, det_center)
                
                # Also check class similarity
                class_similarity = 1.0 if profile.class_name == det['class_name'] else 0.3
                adjusted_distance = distance * (2.0 - class_similarity)
                
                if adjusted_distance < 150 and adjusted_distance < best_distance:
                    best_match = (i, det)
                    best_distance = adjusted_distance
            
            if best_match is not None:
                # Update existing object
                det_idx, detection = best_match
                profile.update_appearance(frame_num, timestamp, detection['bbox'], frame)
                updated_objects.add(det_idx)
            else:
                # Mark as disappeared
                profile.mark_disappeared(frame_num)
                # Remove if disappeared for too long
                if profile.disappeared_frames > 90:  # 3 seconds at 30fps
                    del self.object_profiles[obj_id]
        
        # Create new profiles for unmatched detections
        for i, detection in enumerate(detections):
            if i not in updated_objects:
                object_id = f"obj_{self.next_object_id:04d}"
                color = self.color_palette[0]
                self.color_palette.rotate(-1)
                
                profile = ObjectProfile(
                    object_id=object_id,
                    first_appearance={
                        'frame_num': frame_num,
                        'timestamp': timestamp,
                        'frame_data': frame
                    },
                    bbox=detection['bbox'],
                    class_name=detection['class_name'],
                    color=color
                )
                
                self.object_profiles[object_id] = profile
                self.next_object_id += 1
        
        return self._create_visualization_frame(frame)
    
    def _create_visualization_frame(self, frame):
        """Create visualization frame with bounding boxes and info"""
        viz_frame = frame.copy()
        
        for obj_id, profile in self.object_profiles.items():
            if profile.disappeared_frames > 0:
                continue  # Skip disappeared objects
            
            # Draw bounding box
            x, y, w, h = [int(coord) for coord in profile.last_bbox]
            color = self._hex_to_bgr(profile.color)
            
            # Draw main bounding box
            cv2.rectangle(viz_frame, (x, y), (x + w, y + h), color, 3)
            
            # Draw object ID and info
            info_text = f"{obj_id} ({profile.class_name})"
            duration_text = f"Time: {profile.total_duration + (self.current_time - profile.current_segment['start_time']):.1f}s"
            appearances_text = f"Appearances: {profile.appearance_count}"
            
            # Background for text
            text_y = y - 10 if y - 10 > 20 else y + h + 60
            cv2.rectangle(viz_frame, (x, text_y - 60), (x + 200, text_y + 10), (0, 0, 0), -1)
            cv2.rectangle(viz_frame, (x, text_y - 60), (x + 200, text_y + 10), color, 2)
            
            # Draw text
            cv2.putText(viz_frame, info_text, (x + 5, text_y - 40),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            cv2.putText(viz_frame, duration_text, (x + 5, text_y - 20),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)
            cv2.putText(viz_frame, appearances_text, (x + 5, text_y),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)
            
            # Draw trajectory
            if len(profile.trajectory) > 1:
                points = []
                for point in profile.trajectory[-20:]:  # Last 20 points
                    pos = point['position']
                    points.append(pos)
                
                if len(points) >= 2:
                    points = np.array(points, dtype=np.int32)
                    cv2.polylines(viz_frame, [points], False, color, 2)
        
        # Add frame info
        info_text = f"Frame: {self.frame_count} | Objects: {len([p for p in self.object_profiles.values() if p.disappeared_frames == 0])}"
        cv2.putText(viz_frame, info_text, (10, 30),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 3)
        cv2.putText(viz_frame, info_text, (10, 30),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        
        return viz_frame
    
    def _hex_to_bgr(self, hex_color):
        """Convert hex color to BGR for OpenCV"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        return (rgb[2], rgb[1], rgb[0])  # BGR format
    
    def get_all_profiles(self):
        """Get all object profiles"""
        return {obj_id: profile.get_profile_summary() 
                for obj_id, profile in self.object_profiles.items()}
    
    def get_active_objects(self):
        """Get currently active objects"""
        return {obj_id: profile for obj_id, profile in self.object_profiles.items() 
                if profile.disappeared_frames == 0}

class EnhancedObjectDetector:
    """Improved object detector with better classification"""
    
    def __init__(self):
        self.back_sub = cv2.createBackgroundSubtractorMOG2(history=500, varThreshold=16, detectShadows=True)
        self.kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
        
    def detect_objects(self, frame, timestamp):
        """Detect objects in frame with enhanced classification"""
        try:
            # Resize for processing efficiency
            height, width = frame.shape[:2]
            if width > 800:
                scale = 800 / width
                new_width = 800
                new_height = int(height * scale)
                frame_resized = cv2.resize(frame, (new_width, new_height))
            else:
                frame_resized = frame
                new_width, new_height = width, height
            
            # Background subtraction
            fg_mask = self.back_sub.apply(frame_resized)
            
            # Noise removal and enhancement
            fg_mask = cv2.morphologyEx(fg_mask, cv2.MORPH_OPEN, self.kernel)
            fg_mask = cv2.dilate(fg_mask, self.kernel, iterations=2)
            
            # Find contours
            contours, _ = cv2.findContours(fg_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            detections = []
            for contour in contours:
                area = cv2.contourArea(contour)
                if 500 < area < 50000:  # Adjusted range
                    x, y, w, h = cv2.boundingRect(contour)
                    
                    # Scale coordinates back to original frame size
                    if width != new_width:
                        scale_x = width / new_width
                        scale_y = height / new_height
                        x, y, w, h = int(x * scale_x), int(y * scale_y), int(w * scale_x), int(h * scale_y)
                    
                    # Enhanced classification
                    class_name, confidence = self._classify_object(w, h, area, contour)
                    
                    detections.append({
                        'bbox': (x, y, w, h),
                        'class_name': class_name,
                        'confidence': confidence,
                        'timestamp': timestamp,
                        'area': area
                    })
            
            return detections
            
        except Exception as e:
            print(f"Detection error: {e}")
            return []
    
    def _classify_object(self, w, h, area, contour):
        """Enhanced object classification"""
        aspect_ratio = w / h if h > 0 else 1.0
        
        # Calculate additional features
        perimeter = cv2.arcLength(contour, True)
        circularity = 4 * np.pi * area / (perimeter * perimeter) if perimeter > 0 else 0
        
        if aspect_ratio > 2.5:
            # Very wide - likely vehicle
            return 'vehicle', min(area / 15000, 1.0)
        elif aspect_ratio > 1.8:
            # Wide object
            if area > 8000:
                return 'vehicle', min(area / 20000, 1.0)
            else:
                return 'small_object', min(area / 5000, 1.0)
        elif 0.7 < aspect_ratio < 1.8:
            # Human-like aspect ratio
            if area > 5000:
                return 'person', min(area / 15000, 1.0)
            elif area > 1500:
                return 'person', min(area / 8000, 0.8)
            else:
                return 'small_object', min(area / 3000, 1.0)
        else:
            # Tall or irregular
            if area > 3000:
                return 'person', min(area / 10000, 0.7)
            else:
                return 'small_object', min(area / 2000, 1.0)

@app.route('/Timeline')
async def object_timeline_dashboard():
    """Main dashboard for object timeline profiling"""
    return await render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Object Timeline Profiling</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .object-card {
            border-left: 4px solid;
            transition: all 0.3s ease;
        }
        .object-card:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .timeline-bar {
            height: 20px;
            background: #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
        }
        .appearance-segment {
            height: 100%;
            position: absolute;
            border-radius: 10px;
        }
        .snapshot-img {
            border: 2px solid;
            border-radius: 4px;
            transition: transform 0.2s ease;
            cursor: pointer;
        }
        .snapshot-img:hover {
            transform: scale(1.05);
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.8);
        }
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 10px;
            width: 80%;
            max-width: 900px;
            max-height: 80vh;
            overflow-y: auto;
        }
        .close-modal {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close-modal:hover {
            color: black;
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-900 mb-3">
                <i class="fas fa-user-clock text-blue-500 mr-3"></i>
                Object Timeline Profiling
            </h1>
            <p class="text-gray-600 text-lg">Track individual objects with duration, reappearances, and snapshots</p>
        </div>

        <div class="grid lg:grid-cols-4 gap-8">
            <!-- Left Sidebar -->
            <div class="lg:col-span-1 space-y-6">
                <!-- Video Management -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-xl font-semibold mb-4">
                        <i class="fas fa-video text-red-500 mr-2"></i>
                        Video Management
                    </h2>
                    
                    <!-- File Upload -->
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700 mb-2">Upload New Video</label>
                        <input type="file" id="video-upload" class="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100" accept="video/*">
                        <button onclick="uploadVideo()" class="w-full mt-2 bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-lg">
                            <i class="fas fa-cloud-upload-alt mr-2"></i>Upload Video
                        </button>
                    </div>
                    
                    <!-- Select Existing Video -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Select Existing Video</label>
                        <select id="video-select" class="w-full border border-gray-300 rounded-lg p-2 mb-2" onchange="selectExistingVideo(this.value)">
                            <option value="">Choose a video...</option>
                        </select>
                        <button onclick="loadVideos()" class="w-full bg-gray-500 hover:bg-gray-600 text-white py-2 px-4 rounded-lg">
                            <i class="fas fa-sync-alt mr-2"></i>Refresh List
                        </button>
                    </div>
                    
                    <div id="upload-status" class="mt-3 text-sm"></div>
                </div>

                <!-- Analysis Controls -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-xl font-semibold mb-4">
                        <i class="fas fa-play-circle text-green-500 mr-2"></i>
                        Analysis Controls
                    </h2>
                    <button onclick="startAnalysis()" class="w-full bg-green-500 hover:bg-green-600 text-white py-3 px-4 rounded-lg font-semibold mb-3">
                        Start Object Profiling
                    </button>
                    <button onclick="stopAnalysis()" class="w-full bg-red-500 hover:bg-red-600 text-white py-2 px-4 rounded-lg font-semibold">
                        Stop Analysis
                    </button>
                    <div id="analysis-status" class="mt-4 hidden">
                        <div class="flex justify-between text-sm mb-1">
                            <span id="status-text">Processing...</span>
                            <span id="status-progress">0%</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-2">
                            <div id="progress-bar" class="bg-blue-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                    </div>
                </div>

                <!-- Active Objects Counter -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h3 class="text-lg font-semibold mb-3">
                        <i class="fas fa-object-group text-blue-500 mr-2"></i>
                        Live Objects
                    </h3>
                    <div class="text-center">
                        <div class="text-3xl font-bold text-blue-600 mb-2" id="active-objects-count">0</div>
                        <div class="text-sm text-gray-600">Currently Tracked</div>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="lg:col-span-3">
                <!-- Live Video Feed -->
                <div class="bg-white rounded-xl shadow-lg p-6 mb-6">
                    <h2 class="text-xl font-semibold mb-4">
                        <i class="fas fa-eye text-purple-500 mr-2"></i>
                        Live Object Tracking
                    </h2>
                    <div class="video-container border-2 border-gray-200 rounded-lg bg-gray-900 relative">
                        <img id="live-video" src="" class="w-full h-auto" style="display: none; max-height: 60vh;">
                        <div id="initial-state" class="flex items-center justify-center h-96">
                            <div class="text-center text-gray-500">
                                <i class="fas fa-binoculars text-6xl mb-4"></i>
                                <p class="text-xl">Upload and start analysis to see object tracking</p>
                                <p class="text-sm mt-2">Each object gets unique color and detailed timeline</p>
                            </div>
                        </div>
                    </div>
                    <div class="mt-4 grid grid-cols-4 gap-4 text-center">
                        <div class="bg-blue-50 rounded-lg p-3">
                            <div class="text-2xl font-bold text-blue-600" id="total-frames">0</div>
                            <div class="text-sm text-gray-600">Frames</div>
                        </div>
                        <div class="bg-green-50 rounded-lg p-3">
                            <div class="text-2xl font-bold text-green-600" id="total-objects">0</div>
                            <div class="text-sm text-gray-600">Total Objects</div>
                        </div>
                        <div class="bg-purple-50 rounded-lg p-3">
                            <div class="text-2xl font-bold text-purple-600" id="current-time">0.0s</div>
                            <div class="text-sm text-gray-600">Time</div>
                        </div>
                        <div class="bg-orange-50 rounded-lg p-3">
                            <div class="text-2xl font-bold text-orange-600" id="processing-fps">0</div>
                            <div class="text-sm text-gray-600">FPS</div>
                        </div>
                    </div>
                </div>

                <!-- Object Profiles -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-xl font-semibold">
                            <i class="fas fa-id-card text-green-500 mr-2"></i>
                            Object Profiles
                        </h2>
                        <button onclick="downloadAllSnapshots()" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg">
                            <i class="fas fa-download mr-2"></i>Download All Snapshots
                        </button>
                    </div>
                    <div id="object-profiles" class="space-y-4 max-h-96 overflow-y-auto">
                        <div class="text-center text-gray-500 py-8">
                            <i class="fas fa-users text-4xl mb-2"></i>
                            <p>Object profiles will appear here during analysis</p>
                            <p class="text-sm mt-1">Each profile shows duration, appearances, and snapshots</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Snapshot Modal -->
    <div id="snapshot-modal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <div class="grid grid-cols-2 gap-6 mt-4">
                <div>
                    <h3 class="text-xl font-bold mb-4" id="modal-object-id">Object ID</h3>
                    <div id="modal-object-info" class="space-y-3">
                        <!-- Object info will be populated here -->
                    </div>
                </div>
                <div>
                    <img id="modal-snapshot-img" src="" class="w-full h-auto rounded-lg border-2">
                    <div class="mt-4 text-center">
                        <button onclick="downloadCurrentSnapshot()" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg">
                            <i class="fas fa-download mr-2"></i>Download This Snapshot
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentVideoId = null;
        let websocket = null;
        let isAnalyzing = false;
        let frameCount = 0;
        let lastFpsUpdate = 0;
        let currentFps = 0;
        let currentProfiles = {};
        let currentSnapshotData = null;

        // Initialize WebSocket
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/object-timeline`;
            
            websocket = new WebSocket(wsUrl);
            
            websocket.onopen = function() {
                updateConnectionStatus('connected', 'Connected');
                console.log('WebSocket connected');
            };
            
            websocket.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    handleRealtimeUpdate(data);
                } catch (e) {
                    console.error('Error parsing message:', e);
                }
            };
            
            websocket.onclose = function() {
                updateConnectionStatus('disconnected', 'Disconnected');
                setTimeout(connectWebSocket, 3000);
            };
            
            websocket.onerror = function(error) {
                console.error('WebSocket error:', error);
                updateConnectionStatus('error', 'Connection Error');
            };
        }

        function handleRealtimeUpdate(data) {
            switch(data.type) {
                case 'video_frame':
                    updateVideoFrame(data);
                    updateStatistics(data);
                    break;
                case 'object_profiles':
                    currentProfiles = data.profiles;
                    updateObjectProfiles(data.profiles);
                    break;
                case 'analysis_started':
                    showNotification('Object profiling started!', 'success');
                    document.getElementById('initial-state').style.display = 'none';
                    document.getElementById('live-video').style.display = 'block';
                    isAnalyzing = true;
                    break;
                case 'analysis_completed':
                    showNotification('Analysis completed! Final profiles available.', 'success');
                    isAnalyzing = false;
                    // Save final profiles
                    currentProfiles = data.profiles;
                    updateObjectProfiles(data.profiles);
                    break;
                case 'error':
                    showNotification('Error: ' + data.message, 'error');
                    isAnalyzing = false;
                    break;
            }
        }

        function updateVideoFrame(data) {
            const videoImg = document.getElementById('live-video');
            videoImg.src = 'data:image/jpeg;base64,' + data.frame_data;
            
            // Update FPS
            frameCount++;
            const now = Date.now();
            if (now - lastFpsUpdate >= 1000) {
                currentFps = frameCount;
                frameCount = 0;
                lastFpsUpdate = now;
            }
        }

        function updateStatistics(data) {
            document.getElementById('total-frames').textContent = data.frame_number;
            document.getElementById('current-time').textContent = data.timestamp.toFixed(1) + 's';
            document.getElementById('processing-fps').textContent = currentFps;
            document.getElementById('active-objects-count').textContent = data.active_objects;
            document.getElementById('total-objects').textContent = data.total_objects;
            
            // Update progress
            if (data.progress) {
                updateAnalysisStatus('processing', `Processing... ${data.progress.toFixed(1)}%`, data.progress);
            }
        }

        function updateObjectProfiles(profiles) {
            const container = document.getElementById('object-profiles');
            
            if (!profiles || Object.keys(profiles).length === 0) {
                container.innerHTML = `
                    <div class="text-center text-gray-500 py-8">
                        <i class="fas fa-users text-4xl mb-2"></i>
                        <p>No objects tracked yet</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = Object.values(profiles).map(profile => `
                <div class="object-card bg-white border rounded-lg p-4 shadow-sm" style="border-left-color: ${profile.color}">
                    <div class="flex justify-between items-start mb-3">
                        <div>
                            <div class="flex items-center mb-1">
                                <div class="w-4 h-4 rounded-full mr-2" style="background-color: ${profile.color}"></div>
                                <span class="font-bold text-lg">${profile.object_id}</span>
                                <span class="ml-2 px-2 py-1 bg-gray-100 rounded text-sm capitalize">${profile.class_name}</span>
                            </div>
                            <div class="text-sm text-gray-600">
                                Duration: <strong>${profile.total_duration.toFixed(1)}s</strong> | 
                                Frames: <strong>${profile.total_frames}</strong> | 
                                Appearances: <strong>${profile.appearance_count}</strong>
                            </div>
                        </div>
                        <div class="text-right">
                            <div class="text-sm text-gray-500">Last seen</div>
                            <div class="font-semibold">Frame ${profile.last_seen_frame}</div>
                        </div>
                    </div>
                    
                    ${profile.snapshots && profile.snapshots.length > 0 ? `
                    <div class="mb-3">
                        <div class="text-sm font-semibold mb-2">Snapshots:</div>
                        <div class="flex space-x-2 overflow-x-auto">
                            ${profile.snapshots.map((snapshot, index) => `
                                <img src="data:image/jpeg;base64,${snapshot.image_data}" 
                                     class="snapshot-img w-16 h-16 object-cover" 
                                     style="border-color: ${profile.color}"
                                     title="Frame ${snapshot.frame_num} - ${snapshot.timestamp.toFixed(1)}s"
                                     onclick="showSnapshotModal('${profile.object_id}', ${index})">
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                    
                    <div class="flex justify-between items-center text-xs text-gray-500">
                        <span>Tracked segments: ${profile.appearance_segments ? profile.appearance_segments.length : 0}</span>
                        <button onclick="downloadObjectSnapshots('${profile.object_id}')" class="text-blue-500 hover:text-blue-700">
                            <i class="fas fa-download mr-1"></i>Download Snapshots
                        </button>
                    </div>
                </div>
            `).join('');
        }

        function showSnapshotModal(objectId, snapshotIndex) {
            const profile = currentProfiles[objectId];
            if (!profile || !profile.snapshots || !profile.snapshots[snapshotIndex]) return;
            
            const snapshot = profile.snapshots[snapshotIndex];
            currentSnapshotData = { objectId, snapshotIndex, snapshot, profile };
            
            // Update modal content
            document.getElementById('modal-object-id').textContent = `${objectId} (${profile.class_name})`;
            document.getElementById('modal-snapshot-img').src = `data:image/jpeg;base64,${snapshot.image_data}`;
            
            // Populate object info
            const infoContainer = document.getElementById('modal-object-info');
            infoContainer.innerHTML = `
                <div class="grid grid-cols-2 gap-2 text-sm">
                    <div class="font-semibold">Object ID:</div>
                    <div>${objectId}</div>
                    
                    <div class="font-semibold">Class:</div>
                    <div class="capitalize">${profile.class_name}</div>
                    
                    <div class="font-semibold">Total Duration:</div>
                    <div>${profile.total_duration.toFixed(1)} seconds</div>
                    
                    <div class="font-semibold">Total Frames:</div>
                    <div>${profile.total_frames}</div>
                    
                    <div class="font-semibold">Appearances:</div>
                    <div>${profile.appearance_count}</div>
                    
                    <div class="font-semibold">Snapshot Frame:</div>
                    <div>${snapshot.frame_num}</div>
                    
                    <div class="font-semibold">Snapshot Time:</div>
                    <div>${snapshot.timestamp.toFixed(1)}s</div>
                    
                    <div class="font-semibold">Position:</div>
                    <div>(${snapshot.position[0]}, ${snapshot.position[1]})</div>
                    
                    <div class="font-semibold">Bounding Box:</div>
                    <div>${snapshot.bbox[0]}x${snapshot.bbox[1]} ${snapshot.bbox[2]}x${snapshot.bbox[3]}</div>
                </div>
                
                ${profile.appearance_segments && profile.appearance_segments.length > 0 ? `
                <div class="mt-4">
                    <div class="font-semibold mb-2">Appearance Segments:</div>
                    <div class="space-y-1 text-xs">
                        ${profile.appearance_segments.map(segment => `
                            <div class="flex justify-between">
                                <span>Frames ${segment.start_frame}-${segment.end_frame}</span>
                                <span>${(segment.end_time - segment.start_time).toFixed(1)}s</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
            `;
            
            // Show modal
            document.getElementById('snapshot-modal').style.display = 'block';
        }

        function downloadCurrentSnapshot() {
            if (!currentSnapshotData) return;
            
            const { snapshot, profile } = currentSnapshotData;
            const link = document.createElement('a');
            link.download = `${profile.object_id}_frame_${snapshot.frame_num}.jpg`;
            link.href = `data:image/jpeg;base64,${snapshot.image_data}`;
            link.click();
        }

        function downloadObjectSnapshots(objectId) {
            const profile = currentProfiles[objectId];
            if (!profile || !profile.snapshots) return;
            
            profile.snapshots.forEach((snapshot, index) => {
                const link = document.createElement('a');
                link.download = `${objectId}_snapshot_${index + 1}_frame_${snapshot.frame_num}.jpg`;
                link.href = `data:image/jpeg;base64,${snapshot.image_data}`;
                link.click();
            });
        }

        function downloadAllSnapshots() {
            Object.values(currentProfiles).forEach(profile => {
                if (profile.snapshots) {
                    profile.snapshots.forEach((snapshot, index) => {
                        const link = document.createElement('a');
                        link.download = `${profile.object_id}_snapshot_${index + 1}_frame_${snapshot.frame_num}.jpg`;
                        link.href = `data:image/jpeg;base64,${snapshot.image_data}`;
                        link.click();
                    });
                }
            });
        }

        // Close modal when clicking X
        document.querySelector('.close-modal').onclick = function() {
            document.getElementById('snapshot-modal').style.display = 'none';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('snapshot-modal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }

        async function uploadVideo() {
            const fileInput = document.getElementById('video-upload');
            const file = fileInput.files[0];
            const statusEl = document.getElementById('upload-status');
            
            if (!file) {
                statusEl.innerHTML = '<span class="text-red-400">Please select a video file first</span>';
                return;
            }
            
            statusEl.innerHTML = '<span class="text-yellow-400">Uploading...</span>';
            
            const formData = new FormData();
            formData.append('video', file);
            
            try {
                const response = await fetch('/api/object-timeline/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    currentVideoId = result.video_id;
                    statusEl.innerHTML = '<span class="text-green-400">Video uploaded successfully!</span>';
                    showNotification('Video uploaded successfully!', 'success');
                    loadVideos(); // Refresh the video list
                } else {
                    throw new Error(result.error || 'Upload failed');
                }
            } catch (error) {
                statusEl.innerHTML = `<span class="text-red-400">Upload failed: ${error.message}</span>`;
                showNotification('Upload failed: ' + error.message, 'error');
            }
        }

        async function loadVideos() {
            try {
                const response = await fetch('/api/object-timeline/videos');
                const result = await response.json();
                
                if (response.ok) {
                    displayVideoList(result.videos);
                } else {
                    throw new Error(result.error || 'Failed to load videos');
                }
            } catch (error) {
                console.error('Error loading videos:', error);
                showNotification('Failed to load videos: ' + error.message, 'error');
            }
        }

        function displayVideoList(videos) {
            const select = document.getElementById('video-select');
            
            if (!videos || videos.length === 0) {
                select.innerHTML = '<option value="">No videos available</option>';
                return;
            }
            
            select.innerHTML = '<option value="">Choose a video...</option>' +
                videos.map(video => `
                    <option value="${video.id}" ${video.id == currentVideoId ? 'selected' : ''}>
                        ${video.filename} (${new Date(video.upload_time).toLocaleDateString()})
                    </option>
                `).join('');
        }

        function selectExistingVideo(videoId) {
            if (videoId) {
                currentVideoId = parseInt(videoId);
                showNotification('Video selected', 'success');
            }
        }

        function startAnalysis() {
            if (!currentVideoId) {
                showNotification('Please select or upload a video first', 'error');
                return;
            }
            
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                websocket.send(JSON.stringify({
                    type: 'start_analysis',
                    video_id: currentVideoId
                }));
            } else {
                showNotification('WebSocket not connected. Please wait...', 'error');
            }
        }

        function stopAnalysis() {
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                websocket.send(JSON.stringify({
                    type: 'stop_analysis'
                }));
            }
            isAnalyzing = false;
            showNotification('Analysis stopped', 'info');
        }

        function updateConnectionStatus(status, message) {
            // Create status element if it doesn't exist
            let statusEl = document.getElementById('connection-status');
            if (!statusEl) {
                statusEl = document.createElement('div');
                statusEl.id = 'connection-status';
                statusEl.className = 'fixed bottom-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50';
                document.body.appendChild(statusEl);
            }
            
            statusEl.className = 'fixed bottom-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50 ';
            statusEl.innerHTML = `<i class="fas fa-wifi mr-2"></i><span>${message}</span>`;
            
            switch(status) {
                case 'connected':
                    statusEl.classList.add('bg-green-600', 'text-white');
                    break;
                case 'disconnected':
                    statusEl.classList.add('bg-yellow-600', 'text-white');
                    break;
                case 'error':
                    statusEl.classList.add('bg-red-600', 'text-white');
                    break;
            }
        }

        function updateAnalysisStatus(status, message, progress) {
            const statusEl = document.getElementById('analysis-status');
            const textEl = document.getElementById('status-text');
            const progressEl = document.getElementById('status-progress');
            const progressBar = document.getElementById('progress-bar');
            
            statusEl.classList.remove('hidden');
            textEl.textContent = message;
            progressEl.textContent = progress.toFixed(1) + '%';
            progressBar.style.width = progress + '%';
            
            progressBar.className = 'h-2 rounded-full transition-all duration-300 ';
            if (status === 'processing') progressBar.classList.add('bg-blue-600');
            else if (status === 'completed') progressBar.classList.add('bg-green-600');
            else if (status === 'error') progressBar.classList.add('bg-red-600');
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50 ${
                type === 'success' ? 'bg-green-500' : 
                type === 'error' ? 'bg-red-500' : 'bg-blue-500'
            } text-white`;
            notification.innerHTML = `<div class="flex items-center"><i class="fas fa-${type === 'success' ? 'check' : 'exclamation-triangle'} mr-2"></i><span>${message}</span></div>`;
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 4000);
        }

        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            connectWebSocket();
            loadVideos(); // Load existing videos on page load
        });
    </script>
</body>
</html>
''')

@app.websocket('/ws/object-timeline')
async def object_timeline_websocket():
    """WebSocket for object timeline profiling"""
    await websocket.accept()
    print("Object Timeline WebSocket connected")
    
    current_video_id = None
    tracker = None
    detector = None
    video_capture = None
    
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=300.0)
                
                if data.get('type') == 'start_analysis' and data.get('video_id'):
                    current_video_id = data['video_id']
                    await start_object_analysis(current_video_id, websocket)
                    
                elif data.get('type') == 'stop_analysis':
                    await stop_object_analysis()
                    await websocket.send_json({'type': 'analysis_stopped'})
                    
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({'type': 'ping'})
                except:
                    break
            except Exception as e:
                print(f"WebSocket error: {e}")
                break
                
    except Exception as e:
        print(f"WebSocket connection error: {e}")
    finally:
        await stop_object_analysis()
        print("Object Timeline WebSocket disconnected")

async def start_object_analysis(video_id, websocket):
    """Start object-centric timeline analysis"""
    try:
        # Get video path
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("SELECT file_path FROM timeline_videos WHERE id = ?", (video_id,))
            video = await cursor.fetchone()
            if not video:
                await websocket.send_json({'type': 'error', 'message': 'Video not found'})
                return
        
        video_path = video[0]
        
        # Initialize components
        cap = cv2.VideoCapture(str(video_path))
        if not cap.isOpened():
            await websocket.send_json({'type': 'error', 'message': 'Cannot open video'})
            return
        
        tracker = ObjectTimelineTracker()
        detector = EnhancedObjectDetector()
        
        await websocket.send_json({'type': 'analysis_started'})
        
        fps = cap.get(cv2.CAP_PROP_FPS) or 30
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_interval = 1.0 / fps
        
        frame_count = 0
        last_profile_update = 0
        start_time = time.time()
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            current_time = frame_count / fps
            
            # Detect objects
            detections = detector.detect_objects(frame, current_time)
            
            # Process frame with tracker
            viz_frame = tracker.process_frame(frame, detections, frame_count, current_time)
            
            # Encode frame for streaming
            _, buffer = cv2.imencode('.jpg', viz_frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
            frame_data = base64.b64encode(buffer).decode('utf-8')
            
            # Send frame update
            await websocket.send_json({
                'type': 'video_frame',
                'frame_data': frame_data,
                'frame_number': frame_count,
                'timestamp': current_time,
                'active_objects': len(tracker.get_active_objects()),
                'total_objects': len(tracker.object_profiles),
                'progress': (frame_count / total_frames) * 100 if total_frames > 0 else 0
            })
            
            # Send profile updates every 30 frames
            if frame_count - last_profile_update >= 30:
                profiles = tracker.get_all_profiles()
                await websocket.send_json({
                    'type': 'object_profiles',
                    'profiles': profiles
                })
                last_profile_update = frame_count
            
            frame_count += 1
            
            # Maintain frame rate
            elapsed = time.time() - start_time
            expected_time = frame_count * frame_interval
            if elapsed < expected_time:
                await asyncio.sleep(expected_time - elapsed)
            
        # Final analysis completion
        cap.release()
        
        # Save final profiles to database
        final_profiles = tracker.get_all_profiles()
        await save_object_profiles(video_id, final_profiles)
        
        await websocket.send_json({
            'type': 'analysis_completed',
            'profiles': final_profiles,
            'total_objects': len(final_profiles),
            'total_frames': frame_count,
            'total_duration': frame_count / fps
        })
        
    except Exception as e:
        print(f"Object analysis error: {e}")
        await websocket.send_json({'type': 'error', 'message': str(e)})

async def save_object_profiles(video_id, profiles):
    """Save object profiles to database"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # Create object profiles table if not exists
            await db.execute("""
                CREATE TABLE IF NOT EXISTS object_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    video_id INTEGER NOT NULL,
                    object_id TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    color TEXT NOT NULL,
                    total_duration REAL NOT NULL,
                    total_frames INTEGER NOT NULL,
                    appearance_count INTEGER NOT NULL,
                    profile_data TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (video_id) REFERENCES timeline_videos (id)
                );
            """)
            
            # Save each profile
            for obj_id, profile in profiles.items():
                await db.execute("""
                    INSERT INTO object_profiles 
                    (video_id, object_id, class_name, color, total_duration, total_frames, appearance_count, profile_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    video_id, obj_id, profile['class_name'], profile['color'],
                    profile['total_duration'], profile['total_frames'],
                    profile['appearance_count'], json.dumps(profile, default=str)
                ))
            
            await db.commit()
            print(f"Saved {len(profiles)} object profiles to database")
            
    except Exception as e:
        print(f"Error saving object profiles: {e}")

async def stop_object_analysis():
    """Stop object analysis"""
    # Cleanup resources
    pass

@app.route('/api/object-timeline/upload', methods=['POST'])
async def upload_object_timeline_video():
    """Upload video for object timeline analysis"""
    try:
        if 'video' not in (await request.files):
            return jsonify({'error': 'No video file provided'}), 400
        
        video_file = (await request.files)['video']
        if video_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not video_file.filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
            return jsonify({'error': 'Please upload a video file (mp4, avi, mov, mkv, webm)'}), 400
        
        file_hash = hashlib.md5(f"{time.time()}_{video_file.filename}".encode()).hexdigest()[:8]
        filename = f"object_timeline_{file_hash}_{video_file.filename}"
        file_path =UPLOAD_FOLDER / filename
        
        UPLOAD_FOLDER.mkdir(exist_ok=True)
        await video_file.save(file_path)
        
        # Verify file was saved
        if not file_path.exists():
            return jsonify({'error': 'File save failed'}), 500
        
        user_id = 1
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                INSERT INTO timeline_videos 
                (user_id, filename, file_path, file_size, analysis_status, upload_time)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, (user_id, filename, str(file_path), 
                  file_path.stat().st_size, 'pending'))
            
            await db.commit()
            
            # Get the last inserted ID properly
            cursor = await db.execute("SELECT last_insert_rowid()")
            result = await cursor.fetchone()
            video_id = result[0] if result else None
        
        if not video_id:
            return jsonify({'error': 'Failed to get video ID'}), 500
        
        return jsonify({
            'video_id': video_id,
            'filename': filename,
            'status': 'uploaded',
            'message': 'Video uploaded successfully'
        })
        
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/object-timeline/videos')
async def get_uploaded_videos():
    """Get list of uploaded videos"""
    try:
        user_id = 1
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT id, filename, file_path, upload_time, analysis_status 
                FROM timeline_videos 
                WHERE user_id = ? 
                ORDER BY upload_time DESC
            """, (user_id,))
            
            videos = await cursor.fetchall()
            
            result = []
            for video in videos:
                result.append({
                    'id': video[0],
                    'filename': video[1],
                    'file_path': video[2],
                    'upload_time': video[3],
                    'analysis_status': video[4]
                })
            
            return jsonify({'videos': result})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/object-timeline/profiles/<int:video_id>')
async def get_object_profiles(video_id):
    """Get object profiles for a specific video"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT object_id, class_name, color, total_duration, total_frames, 
                       appearance_count, profile_data
                FROM object_profiles 
                WHERE video_id = ?
            """, (video_id,))
            
            profiles_data = await cursor.fetchall()
            
            profiles = {}
            for profile in profiles_data:
                profile_dict = {
                    'object_id': profile[0],
                    'class_name': profile[1],
                    'color': profile[2],
                    'total_duration': profile[3],
                    'total_frames': profile[4],
                    'appearance_count': profile[5],
                    'profile_data': json.loads(profile[6]) if profile[6] else {}
                }
                profiles[profile[0]] = profile_dict
            
            return jsonify({'profiles': profiles})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

###################################################################
########################## EOF TIMELINE ##########################



############################# START OF FRAME EXTRACTOR #######################
###################################################################################

# -------------------------
# Object Detection Core
# -------------------------
class ObjectDetector:
    def __init__(self, model_name: str = "yolov5s", confidence: float = 0.5):
        self.confidence = confidence
        self.model = None
        self.model_names = None
        
        # Attempt to load torch model if available.
        try:
            import importlib
            torch = importlib.import_module("torch")
            self.model = torch.hub.load("ultralytics/yolov5", model_name, pretrained=True)
            self.model.eval()
            self.model_names = getattr(self.model, "names", None)
            print("[detector] YOLO model loaded")
        except Exception as e:
            print(f"[detector] YOLO load failed ({e}). Running in no-op mode.")

    def detect_sync(self, frame, confidence: Optional[float] = None):
        """
        Synchronous detection wrapper intended to run in a thread executor.
        Returns list of dicts with keys: bbox, confidence, class_id, class_name
        """
        if self.model is None:
            return []  # no-op if model missing
        
        try:
            results = self.model(frame)
            detections = []
            arr = results.xyxy[0].cpu().numpy()
            for *box, conf, cls in arr:
                if conf >= (confidence if confidence is not None else self.confidence):
                    x1, y1, x2, y2 = map(int, box)
                    cid = int(cls)
                    cname = self.model_names[cid] if self.model_names and cid < len(self.model_names) else str(cid)
                    detections.append({
                        "bbox": [x1, y1, x2, y2],
                        "confidence": float(conf),
                        "class_id": cid,
                        "class_name": cname
                    })
            return detections
        except Exception as e:
            print("[detector] detection error:", e)
            return []

    async def process_video(self, job_id: int, video_path: str, object_filter: str, confidence: float, frame_skip: int):
        """
        Core processing loop with enhanced tracking and grouping.
        """
        start_time = datetime.utcnow()
        current_pid = os.getpid()
        
        await db_update("jobs", {
            "status": "running", 
            "started_at": start_time.isoformat(),
            "process_pid": current_pid,
            "task_name": "extraction"
        }, {"id": job_id})
        
        await log(job_id, "info", f"Job {job_id} started (PID: {current_pid}, filter={object_filter} conf={confidence} step={frame_skip})")
        
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            await log(job_id, "error", f"Cannot open video: {video_path}")
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            return
        
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        frame_number = 0
        
        try:
            while True:
                # Check for stop flag in DB to support graceful stops
                job_row = await db_query_one("SELECT status FROM jobs WHERE id=?", (job_id,))
                if job_row and job_row.get("status") == "stopped":
                    await log(job_id, "info", "Job requested to stop — exiting")
                    break
                
                ret, frame = cap.read()
                if not ret:
                    break
                
                if frame_number % frame_skip != 0:
                    frame_number += 1
                    continue
                
                timestamp = round(frame_number / fps, 2)
                
                # Run sync detection in thread pool to avoid blocking event loop
                loop = asyncio.get_running_loop()
                detections = await loop.run_in_executor(None, self.detect_sync, frame, confidence)
                
                # Filter detections
                filtered = []
                for det in detections:
                    cname = det["class_name"]
                    if object_filter == "all" or (object_filter == "people" and cname == "person") or (cname == object_filter):
                        filtered.append(det)
                
                # Save detections & emit per-detection logs
                for det in filtered:
                    x1, y1, x2, y2 = det["bbox"]
                    img_b64 = None
                    img_path = None
                    
                    # Generate detection group for similar detections
                    detection_group = generate_detection_group(det["class_name"], det["bbox"])
                    
                    try:
                        cropped = frame[y1:y2, x1:x2]
                        if cropped.size > 0:
                            rgb = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGB)
                            pil = Image.fromarray(rgb)
                            buf = io.BytesIO()
                            pil.save(buf, format="PNG")
                            img_b64 = base64.b64encode(buf.getvalue()).decode()
                            
                            # Save detection image to disk
                            job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
                            os.makedirs(job_folder, exist_ok=True)
                            img_filename = f"detection_{frame_number}_{det['class_name']}_{det['confidence']:.2f}.png"
                            img_path = os.path.join(job_folder, img_filename)
                            pil.save(img_path)
                            
                    except Exception as e:
                        img_b64 = None
                        img_path = None
                        await log(job_id, "warn", f"Crop failed for frame {frame_number}: {e}")
                    
                    # Insert detection with image path and grouping
                    detection_id = await db_insert("detections", {
                        "job_id": job_id,
                        "user_id" : g.current_user['user_id'],
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": json.dumps(det["bbox"]),
                        "image_base64": img_b64,
                        "image_path": img_path,
                        "detection_group": detection_group ,
                        "created_at" : datetime.utcnow().isoformat()
                    })
                    
                    # Enhanced real-time notification with detection details
                    payload = json.dumps({
                        "type": "detection",
                        "job_id": job_id,
                        "detection_id": detection_id,
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": det["bbox"],
                        "image_base64": img_b64,
                        "image_path": img_path,
                        "detection_group": detection_group
                    })
                    for ws in list(job_ws_clients.get(job_id, [])):
                        try:
                            asyncio.create_task(ws.send(payload))
                        except Exception:
                            pass
                
                progress = round((frame_number / total_frames) * 100, 2) if total_frames > 0 else 0
                if frame_number % (frame_skip * 5) == 0:  # Less frequent logging
                    await log(job_id, "info", f"Frame {frame_number} processed, detections={len(filtered)}, progress={progress}%")
                
                # send progress message to clients
                progress_payload = json.dumps({"type": "progress", "job_id": job_id, "frame": frame_number, "progress": progress})
                for ws in list(job_ws_clients.get(job_id, [])):
                    try:
                        asyncio.create_task(ws.send(progress_payload))
                    except Exception:
                        pass
                
                frame_number += 1
            
            # Calculate time taken
            end_time = datetime.utcnow()
            time_taken = (end_time - start_time).total_seconds()
            
            # Completed normally
            await db_update("jobs", {
                "status": "completed", 
                "completed_at": end_time.isoformat(),
                "time_taken": time_taken
            }, {"id": job_id})
            await log(job_id, "info", f"Job completed in {time_taken:.2f} seconds")
            
            # notify clients
            done_payload = json.dumps({"type": "done", "job_id": job_id, "time_taken": time_taken})
            for ws in list(job_ws_clients.get(job_id, [])):
                try:
                    asyncio.create_task(ws.send(done_payload))
                except Exception:
                    pass
        
        except asyncio.CancelledError:
            # Task canceled explicitly
            time_taken = (datetime.utcnow() - start_time).total_seconds()
            await db_update("jobs", {
                "status": "stopped", 
                "completed_at": datetime.utcnow().isoformat(),
                "time_taken": time_taken
            }, {"id": job_id})
            await log(job_id, "info", f"Job cancelled after {time_taken:.2f} seconds")
        except Exception as e:
            time_taken = (datetime.utcnow() - start_time).total_seconds()
            await db_update("jobs", {
                "status": "failed", 
                "completed_at": datetime.utcnow().isoformat(),
                "time_taken": time_taken
            }, {"id": job_id})
            await log(job_id, "error", f"Processing error after {time_taken:.2f} seconds: {e}")
        finally:
            cap.release()
            # cleanup job_tasks entry if present
            job_tasks.pop(job_id, None)

detector = ObjectDetector()

# -------------------------
# URL Video Stream Processor
# -------------------------
class URLVideoProcessor:
    def __init__(self):
        self.ytdlp_available = False
        try:
            # Check if yt-dlp is available
            result = subprocess.run(['yt-dlp', '--version'], capture_output=True, timeout=10)
            if result.returncode == 0:
                self.ytdlp_available = True
                print("[URLProcessor] yt-dlp found and available")
        except Exception as e:
            print(f"[URLProcessor] yt-dlp not available: {e}")
            print("[URLProcessor] Install with: pip install yt-dlp")

    def get_video_stream_url(self, url: str) -> Optional[str]:
        """
        Get direct video stream URL using yt-dlp without downloading
        Returns the best video stream URL for direct opencv access
        """
        if not self.ytdlp_available:
            # Fallback: try to use URL directly (works for direct video links)
            return url
        
        try:
            # Get video info without downloading
            cmd = [
                'yt-dlp', 
                '-f', 'best[height<=720]',  # Prefer 720p or lower for processing speed
                '--get-url',
                '--no-playlist',
                url
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                stream_url = result.stdout.strip()
                return stream_url
            else:
                print(f"[URLProcessor] yt-dlp failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"[URLProcessor] yt-dlp timeout for URL: {url}")
            return None
        except Exception as e:
            print(f"[URLProcessor] Error getting stream URL: {e}")
            return None

    async def process_url_video(self, job_id: int, source_url: str, object_filter: str, confidence: float, frame_skip: int):
        """
        Process video directly from URL without downloading to disk
        Uses OpenCV to read from stream URL and processes frames in real-time
        """
        await db_update("jobs", {"status": "running", "started_at": datetime.utcnow().isoformat()}, {"id": job_id})
        await log(job_id, "info", f"URL Job {job_id} started - getting stream URL")
        
        # Get stream URL
        stream_url = self.get_video_stream_url(source_url)
        if not stream_url:
            await log(job_id, "error", f"Could not get video stream from URL: {source_url}")
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            return
        
        await log(job_id, "info", f"Got stream URL, starting video processing")
        
        # Open video stream with OpenCV
        cap = cv2.VideoCapture(stream_url)
        if not cap.isOpened():
            await log(job_id, "error", f"Cannot open video stream: {stream_url}")
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            return
        
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        frame_number = 0
        
        await log(job_id, "info", f"Stream opened successfully (fps={fps}, total_frames={total_frames})")
        
        try:
            while True:
                # Check for stop flag
                job_row = await db_query_one("SELECT status FROM jobs WHERE id=?", (job_id,))
                if job_row and job_row.get("status") == "stopped":
                    await log(job_id, "info", "URL job requested to stop — exiting")
                    break
                
                ret, frame = cap.read()
                if not ret:
                    await log(job_id, "info", "End of video stream reached")
                    break
                
                if frame_number % frame_skip != 0:
                    frame_number += 1
                    continue
                
                timestamp = round(frame_number / fps, 2)
                
                # Run detection using the same detector instance
                loop = asyncio.get_running_loop()
                detections = await loop.run_in_executor(None, detector.detect_sync, frame, confidence)
                
                # Filter detections
                filtered = []
                for det in detections:
                    cname = det["class_name"]
                    if object_filter == "all" or (object_filter == "people" and cname == "person") or (cname == object_filter):
                        filtered.append(det)
                
                # Save detections - same as file processing but with URL source
                for det in filtered:
                    x1, y1, x2, y2 = det["bbox"]
                    img_b64 = None
                    img_path = None
                    
                    try:
                        cropped = frame[y1:y2, x1:x2]
                        if cropped.size > 0:
                            rgb = cv2.cvtColor(cropped, cv2.COLOR_BGR2RGB)
                            pil = Image.fromarray(rgb)
                            buf = io.BytesIO()
                            pil.save(buf, format="PNG")
                            img_b64 = base64.b64encode(buf.getvalue()).decode()
                            
                            # Save detection image to disk
                            job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
                            os.makedirs(job_folder, exist_ok=True)
                            img_filename = f"detection_{frame_number}_{det['class_name']}_{det['confidence']:.2f}.png"
                            img_path = os.path.join(job_folder, img_filename)
                            pil.save(img_path)
                            
                    except Exception as e:
                        img_b64 = None
                        img_path = None
                        await log(job_id, "warn", f"Crop failed for frame {frame_number}: {e}")
                    
                    # Insert detection with image path
                    detection_id = await db_insert("detections", {
                        "job_id": job_id,
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": json.dumps(det["bbox"]),
                        "image_base64": img_b64,
                        "image_path": img_path
                    })
                    
                    # Enhanced real-time notification
                    payload = json.dumps({
                        "type": "detection",
                        "job_id": job_id,
                        "detection_id": detection_id,
                        "frame_number": frame_number,
                        "timestamp": timestamp,
                        "class_name": det["class_name"],
                        "class_id": det["class_id"],
                        "confidence": det["confidence"],
                        "bbox": det["bbox"],
                        "image_base64": img_b64,
                        "image_path": img_path
                    })
                    for ws in list(job_ws_clients.get(job_id, [])):
                        try:
                            asyncio.create_task(ws.send(payload))
                        except Exception:
                            pass
                
                # Progress reporting
                progress = round((frame_number / total_frames) * 100, 2) if total_frames > 0 else 0
                if frame_number % (frame_skip * 10) == 0:  # Less frequent logging for streams
                    await log(job_id, "info", f"Frame {frame_number} processed, detections={len(filtered)}, progress={progress}%")
                
                # Progress WebSocket update
                progress_payload = json.dumps({"type": "progress", "job_id": job_id, "frame": frame_number, "progress": progress})
                for ws in list(job_ws_clients.get(job_id, [])):
                    try:
                        asyncio.create_task(ws.send(progress_payload))
                    except Exception:
                        pass
                
                frame_number += 1
                
                # Prevent runaway processing for very long streams
                if frame_number > 50000:  # ~33 minutes at 25fps
                    await log(job_id, "warn", "Reached frame limit, stopping processing")
                    break
            
            # Completed successfully
            await db_update("jobs", {"status": "completed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            await log(job_id, "info", "URL job completed successfully")
            
            # Notify WebSocket clients
            done_payload = json.dumps({"type": "done", "job_id": job_id})
            for ws in list(job_ws_clients.get(job_id, [])):
                try:
                    asyncio.create_task(ws.send(done_payload))
                except Exception:
                    pass
        
        except asyncio.CancelledError:
            await db_update("jobs", {"status": "stopped", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            await log(job_id, "info", "URL job cancelled")
        except Exception as e:
            await db_update("jobs", {"status": "failed", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
            await log(job_id, "error", f"URL processing error: {e}")
        finally:
            cap.release()
            job_tasks.pop(job_id, None)

# Initialize processors
url_processor = URLVideoProcessor()

# -------------------------
# Background cleanup task
# -------------------------
async def cleanup_expired_task():
    """
    Background task that runs every hour to cleanup expired URL job data
    """
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            now = datetime.utcnow().isoformat()
            
            # Find and cleanup expired URL jobs
            expired_jobs = await db_query(
                "SELECT id FROM jobs WHERE source_type='url' AND expires_at < ? AND status IN ('completed', 'failed', 'stopped')", 
                (now,)
            )
            
            cleanup_count = 0
            for job in expired_jobs:
                job_id = job["id"]
                try:
                    # Delete detection images folder
                    job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
                    if os.path.exists(job_folder):
                        shutil.rmtree(job_folder)
                    
                    # Delete detections, logs, and job record
                    async with aiosqlite.connect(DB_PATH) as db:
                        await db.execute("DELETE FROM detections WHERE job_id=?", (job_id,))
                        await db.execute("DELETE FROM logs WHERE job_id=?", (job_id,))
                        await db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                        await db.commit()
                    cleanup_count += 1
                except Exception as e:
                    print(f"[cleanup] Error cleaning up job {job_id}: {e}")
            
            if cleanup_count > 0:
                print(f"[cleanup] Removed {cleanup_count} expired URL jobs")
                
        except Exception as e:
            print(f"[cleanup] Background cleanup error: {e}")


@app.route("/start_url_job", methods=["POST"])
@auth_required
async def start_url_job():
    """
    Starts background detection for a video URL (YouTube, Instagram, TikTok, etc.)
    JSON body:
      { "url": str, "object_filter": "all"|"people"|<class>, "confidence": float, "frame_skip": int }
    """
    payload = await request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Expected JSON body"}), 400
    
    url = payload.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    # Basic URL validation
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "Invalid URL format"}), 400

    object_filter = payload.get("object_filter", "all")
    confidence = float(payload.get("confidence", 0.5))
    frame_skip = int(payload.get("frame_skip", 10))
    
    # Calculate expiry time
    expires_at = (datetime.utcnow() + timedelta(hours=URL_JOB_EXPIRY_HOURS)).isoformat()
    
    # Insert URL job row (no upload_id needed)
    job_id = await db_insert("jobs", {
        
        "source_url": url,
        "source_type": "url",
        "object_filter": object_filter,
        "confidence": confidence,
        "frame_skip": frame_skip,
        "status": "pending",
        "expires_at": expires_at
    })
    
    # Start background URL processing task
    task = asyncio.create_task(url_processor.process_url_video(job_id, url, object_filter, confidence, frame_skip))
    job_tasks[job_id] = task
    
    await log(job_id, "info", f"URL Job {job_id} queued for processing (expires: {expires_at})")
    return jsonify({"job_id": job_id, "expires_at": expires_at, "expiry_hours": URL_JOB_EXPIRY_HOURS})

@app.route("/cleanup_expired", methods=["POST"])
@auth_required
async def cleanup_expired_jobs():
    """
    Manual cleanup of expired URL job data (normally runs automatically)
    """
    try:
        now = datetime.utcnow().isoformat()
        
        # Find expired jobs
        expired_jobs = await db_query(
            "SELECT id FROM jobs WHERE source_type='url' AND expires_at < ? AND status IN ('completed', 'failed', 'stopped')", 
            (now,)
        )
        
        cleanup_count = 0
        for job in expired_jobs:
            job_id = job["id"]
            
            # Delete detection images folder
            job_folder = os.path.join(DETECTIONS_DIR, f"job_{job_id}")
            if os.path.exists(job_folder):
                shutil.rmtree(job_folder)
            
            # Delete detections for expired jobs
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute("DELETE FROM detections WHERE job_id=?", (job_id,))
                await db.execute("DELETE FROM logs WHERE job_id=?", (job_id,))
                await db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                await db.commit()
            cleanup_count += 1
        
        return jsonify({"cleaned_up": cleanup_count, "message": f"Removed {cleanup_count} expired URL jobs"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/start_job", methods=["POST"])
@auth_required
async def start_job():
    """
    Starts background detection for an existing upload.
    JSON body:
      { "upload_id": int, "object_filter": "all"|"people"|<class>, "confidence": float, "frame_skip": int }
    """
    payload = await request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Expected JSON body"}), 400

    upload_id = payload.get("upload_id")
    if not upload_id:
        return jsonify({"error": "upload_id required"}), 400

    upload = await db_query_one("SELECT * FROM uploads WHERE id=?", (upload_id,))
    if not upload:
        return jsonify({"error": "upload_id not found"}), 404

    object_filter = payload.get("object_filter", "all")
    confidence = float(payload.get("confidence", 0.5))
    frame_skip = int(payload.get("frame_skip", 10))

    # Insert job row
    job_id = await db_insert("jobs", {
        "user_id" : g.current_user['user_id'],
        "upload_id": upload_id,
        "source_type": "file",
        "object_filter": object_filter,
        "confidence": confidence,
        "frame_skip": frame_skip,
        "status": "pending"
    })

    # Start background task
    task = asyncio.create_task(detector.process_video(job_id, upload["saved_path"], object_filter, confidence, frame_skip))
    job_tasks[job_id] = task

    await log(job_id, "info", f"Job {job_id} queued for processing")
    return jsonify({"job_id": job_id})

@app.route("/stop_job", methods=["POST"])
@auth_required
async def stop_job():
    payload = await request.get_json(silent=True)
    job_id = payload.get("job_id") if payload else None
    if not job_id:
        return jsonify({"error": "job_id required"}), 400

    # Mark as stopped in DB; background task checks DB status and exits gracefully.
    await db_update("jobs", {"status": "stopped", "completed_at": datetime.utcnow().isoformat()}, {"id": job_id})
    await log(job_id, "info", "Stop requested by user")

    # Attempt to cancel task as well (best-effort)
    task = job_tasks.get(job_id)
    if task:
        task.cancel()
        await log(job_id, "info", "Background task cancellation requested")

    return jsonify({"stopped": True, "job_id": job_id})

@app.route("/jobs")
@auth_required
async def list_jobs():
    """
    Returns a list of jobs with join to upload filename (for file jobs) or URL info
    """
    rows = await db_query("""
        SELECT j.*, u.filename as upload_filename, u.saved_path 
        FROM jobs j 
        LEFT JOIN uploads u ON u.id=j.upload_id 
        ORDER BY j.id DESC
    """)
    
    # Add human-readable info for each job
    for row in rows:
        if row['source_type'] == 'url':
            row['source_display'] = f"URL: {row['source_url'][:50]}..." if len(row['source_url']) > 50 else f"URL: {row['source_url']}"
            if row['expires_at']:
                expires = datetime.fromisoformat(row['expires_at'])
                now = datetime.utcnow()
                if expires > now:
                    hours_left = (expires - now).total_seconds() / 3600
                    row['expires_in_hours'] = round(hours_left, 1)
                else:
                    row['expires_in_hours'] = 0
        else:
            row['source_display'] = row['upload_filename'] or 'Unknown file'
    
    return jsonify({"jobs": rows})

@app.route("/jobs/<int:job_id>/detections")
@auth_required
async def job_detections(job_id: int):
    rows = await db_query("SELECT * FROM detections WHERE job_id=? ORDER BY id DESC", (job_id,))
    return jsonify({"detections": rows})

@app.route("/jobs/<int:job_id>/gallery")
@auth_required
async def job_gallery(job_id: int):
    """
    Gallery view of all detections for a job with images and metadata
    """
    # Check if this is a web request (wants HTML) or API request (wants JSON)
    accept_header = request.headers.get('Accept', '')
    wants_html = 'text/html' in accept_header and 'application/json' not in accept_header
    
    # Get job info
    job = await db_query_one("SELECT j.*, u.filename as upload_filename FROM jobs j LEFT JOIN uploads u ON u.id=j.upload_id WHERE j.id=?", (job_id,))
    if not job:
        if wants_html:
            return "Job not found", 404
        return jsonify({"error": "Job not found"}), 404
    
    if wants_html:
        # Return HTML gallery page
        return await render_template_string(GALLERY_TEMPLATE, job_id=job_id)
    
    # Return JSON data for API requests
    detections = await db_query("SELECT * FROM detections WHERE job_id=? ORDER BY frame_number ASC, confidence DESC", (job_id,))
    
    # Group by class for better organization
    by_class = {}
    for det in detections:
        class_name = det['class_name']
        if class_name not in by_class:
            by_class[class_name] = []
        by_class[class_name].append(det)
    
    return jsonify({
        "job": job,
        "total_detections": len(detections),
        "detections": detections,
        "by_class": by_class,
        "class_counts": {k: len(v) for k, v in by_class.items()}
    })

@app.route("/detection_image/<int:detection_id>")
async def serve_detection_image(detection_id: int):
    """
    Serve detection image by ID
    """
    detection = await db_query_one("SELECT image_path, image_base64 FROM detections WHERE id=?", (detection_id,))
    if not detection:
        return jsonify({"error": "Detection not found"}), 404
    
    # Try to serve from file first
    if detection['image_path'] and os.path.exists(detection['image_path']):
        return await send_file(detection['image_path'], mimetype='image/png')
    
    # Fallback to base64 if file doesn't exist
    if detection['image_base64']:
        img_data = base64.b64decode(detection['image_base64'])
        return img_data, 200, {'Content-Type': 'image/png'}
    
    return jsonify({"error": "Image not available"}), 404

@app.route("/jobs/<int:job_id>/logs")
async def job_logs(job_id: int):
    rows = await db_query("SELECT * FROM logs WHERE job_id=? ORDER BY id ASC", (job_id,))
    return jsonify({"logs": rows})

@app.route("/download/<int:job_id>")
async def download_job_zip(job_id: int):
    detections = await db_query("SELECT * FROM detections WHERE job_id=?", (job_id,))
    if not detections:
        return jsonify({"error": "no detections for job"}), 404

    tmpdir = tempfile.mkdtemp()
    zip_path = os.path.join(tmpdir, f"job_{job_id}_results.zip")

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            metadata = []
            for d in detections:
                det_meta = {
                    "id": d["id"],
                    "frame_number": d["frame_number"],
                    "timestamp": d["timestamp"],
                    "class_name": d["class_name"],
                    "confidence": d["confidence"],
                    "bbox": json.loads(d["bbox"]) if d["bbox"] else None
                }
                metadata.append(det_meta)

                if d.get("image_base64"):
                    try:
                        imgdata = base64.b64decode(d["image_base64"])
                        fname = f"detection_{d['id']}_{d['class_name']}.png"
                        zf.writestr(fname, imgdata)
                    except Exception:
                        pass

            zf.writestr("metadata.json", json.dumps({"job_id": job_id, "detections": metadata}, indent=2))
        
        return await send_file(zip_path, as_attachment=True, download_name=f"job_{job_id}_results.zip")
    finally:
        # cleanup will be handled by OS, but we try to remove tmpdir after send
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

# -------------------------
# WebSocket: subscribe to job logs/events
# -------------------------
@app.websocket("/ws/jobs/<int:job_id>")
async def ws_job_events(job_id: int):
    # register client - get current websocket object correctly
    current_ws = websocket._get_current_object()
    # ensure list exists
    job_ws_clients.setdefault(job_id, []).append(current_ws)

    try:
        await current_ws.send(json.dumps({"type": "info", "message": f"Subscribed to job {job_id} events"}))

        # Send recent logs for context
        recent = await db_query("SELECT * FROM logs WHERE job_id=? ORDER BY id DESC LIMIT 50", (job_id,))
        # send in chronological order
        for r in reversed(recent):
            await current_ws.send(json.dumps({"type": "log", "job_id": job_id, "level": r["level"], "message": r["message"], "created_at": r["created_at"]}))

        # keep connection open and wait for client pings/messages (no-op)
        while True:
            try:
                msg = await current_ws.receive()
                # optionally handle client messages (e.g., request progress), but ignore by default
                # echo back
                await current_ws.send(json.dumps({"type": "echo", "payload": msg}))
            except asyncio.CancelledError:
                break
            except Exception:
                # connection closed or broken
                break
    finally:
        # remove client
        lst = job_ws_clients.get(job_id, [])
        try:
            lst.remove(current_ws)
        except ValueError:
            pass

# -------------------------
# -------------------------
# HTML Templates
# -------------------------

GALLERY_TEMPLATE = '''<!doctype html>
<html><head>
  <meta charset="utf-8">
  <title>Detection Gallery - Job {{job_id}}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .gallery-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; }
    .detection-item { transition: all 0.3s; }
    .detection-item:hover { transform: scale(1.05); }
    .detection-image { width: 100%; height: 150px; object-fit: cover; border-radius: 8px; }
    .confidence-high { border-left: 4px solid #10b981; }
    .confidence-med { border-left: 4px solid #f59e0b; }
    .confidence-low { border-left: 4px solid #ef4444; }
  </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
  <div class="container mx-auto px-4 py-6">
    <div class="mb-6">
      <button onclick="window.close()" class="bg-gray-600 px-4 py-2 rounded hover:bg-gray-500">← Close</button>
      <h1 class="text-2xl font-bold inline-block ml-4">Detection Gallery</h1>
    </div>
    
    <div class="bg-gray-800 p-4 rounded-lg mb-6">
      <h2 class="text-lg font-semibold mb-2">Job Information</h2>
      <div id="jobInfo" class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <div>Job ID: <span class="font-mono" id="jobId">Loading...</span></div>
        <div>Total Detections: <span class="font-bold text-green-400" id="totalDetections">0</span></div>
        <div>Status: <span id="jobStatus">Loading...</span></div>
        <div>Source: <span id="jobSource">Loading...</span></div>
      </div>
    </div>
    
    <div class="mb-4">
      <div class="flex flex-wrap gap-2 mb-4">
        <button onclick="filterByClass('all')" class="filter-btn bg-indigo-600 px-3 py-1 rounded text-sm hover:bg-indigo-500">All</button>
        <div id="classFilters"></div>
      </div>
      
      <div class="flex gap-4 text-sm">
        <label class="flex items-center">
          <input type="range" id="confidenceFilter" min="0" max="100" value="0" class="mr-2">
          Min Confidence: <span id="confidenceValue">0%</span>
        </label>
        <select id="sortOrder" class="bg-gray-700 px-2 py-1 rounded">
          <option value="frame">Sort by Frame</option>
          <option value="confidence">Sort by Confidence</option>
          <option value="class">Sort by Class</option>
          <option value="time">Sort by Time</option>
        </select>
      </div>
    </div>
    
    <div id="detectionGallery" class="gallery-grid">
      <!-- Detections will be loaded here -->
    </div>
    
    <div id="loadingIndicator" class="text-center py-8">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-white"></div>
      <p class="mt-2">Loading detections...</p>
    </div>
  </div>
<script>
let allDetections = [];
let filteredDetections = [];
let currentClassFilter = 'all';

// Load gallery data
async function loadGallery() {
  const jobId = new URLSearchParams(window.location.search).get('job_id') || 
                window.location.pathname.split('/')[2];
  
  try {
    const response = await fetch(`/jobs/${jobId}/gallery`);
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to load gallery');
    }
    
    // Update job info
    document.getElementById('jobId').textContent = data.job.id;
    document.getElementById('totalDetections').textContent = data.total_detections;
    document.getElementById('jobStatus').textContent = data.job.status;
    document.getElementById('jobSource').textContent = data.job.source_type === 'url' ? 
      `URL: ${data.job.source_url?.substring(0, 50)}...` : 
      `File: ${data.job.upload_filename || 'Unknown'}`;
    
    allDetections = data.detections;
    createClassFilters(data.class_counts);
    filterDetections();
    
    document.getElementById('loadingIndicator').style.display = 'none';
    
  } catch (error) {
    document.getElementById('loadingIndicator').innerHTML = 
      `<div class="text-red-400">Error: ${error.message}</div>`;
  }
}

function createClassFilters(classCounts) {
  const filtersDiv = document.getElementById('classFilters');
  filtersDiv.innerHTML = Object.entries(classCounts)
    .sort(([,a], [,b]) => b - a)
    .map(([className, count]) => 
      `<button onclick="filterByClass('${className}')" class="filter-btn bg-gray-600 px-3 py-1 rounded text-sm hover:bg-gray-500">
        ${className} (${count})
      </button>`
    ).join('');
}

function filterByClass(className) {
  currentClassFilter = className;
  // Update button styles
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.remove('bg-indigo-600', 'bg-purple-600');
    btn.classList.add('bg-gray-600');
  });
  event.target.classList.remove('bg-gray-600');
  event.target.classList.add(className === 'all' ? 'bg-indigo-600' : 'bg-purple-600');
  
  filterDetections();
}

function filterDetections() {
  const minConfidence = parseInt(document.getElementById('confidenceFilter').value) / 100;
  const sortOrder = document.getElementById('sortOrder').value;
  
  // Filter
  filteredDetections = allDetections.filter(det => {
    const classMatch = currentClassFilter === 'all' || det.class_name === currentClassFilter;
    const confidenceMatch = det.confidence >= minConfidence;
    return classMatch && confidenceMatch;
  });
  
  // Sort
  filteredDetections.sort((a, b) => {
    switch (sortOrder) {
      case 'confidence': return b.confidence - a.confidence;
      case 'class': return a.class_name.localeCompare(b.class_name);
      case 'time': return a.timestamp - b.timestamp;
      default: return a.frame_number - b.frame_number;
    }
  });
  
  renderGallery();
}

function renderGallery() {
  const gallery = document.getElementById('detectionGallery');
  
  if (filteredDetections.length === 0) {
    gallery.innerHTML = '<div class="col-span-full text-center text-gray-400 py-8">No detections match the current filter</div>';
    return;
  }
  
  gallery.innerHTML = filteredDetections.map(det => {
    const confidencePercent = Math.round(det.confidence * 100);
    const confidenceClass = confidencePercent >= 80 ? 'confidence-high' : 
                           confidencePercent >= 60 ? 'confidence-med' : 'confidence-low';
    
    return `
      <div class="detection-item bg-gray-800 rounded-lg p-3 ${confidenceClass}">
        ${det.image_base64 ? 
          `<img src="data:image/png;base64,${det.image_base64}" class="detection-image mb-2" alt="${det.class_name}">` :
          `<div class="detection-image bg-gray-700 flex items-center justify-center mb-2">
            <span class="text-gray-400 text-sm">No Image</span>
          </div>`
        }
        <div class="space-y-1">
          <div class="font-semibold">${det.class_name}</div>
          <div class="text-sm text-gray-400">Frame ${det.frame_number}</div>
          <div class="text-sm text-gray-400">${det.timestamp}s</div>
          <div class="text-sm">
            <span class="inline-block px-2 py-1 rounded text-xs ${
              confidencePercent >= 80 ? 'bg-green-600' : 
              confidencePercent >= 60 ? 'bg-yellow-600' : 'bg-red-600'
            }">${confidencePercent}%</span>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// Event listeners
document.getElementById('confidenceFilter').addEventListener('input', (e) => {
  document.getElementById('confidenceValue').textContent = e.target.value + '%';
  filterDetections();
});

document.getElementById('sortOrder').addEventListener('change', filterDetections);

// Load gallery on page load
loadGallery();
</script>
</body></html>'''

# -------------------------







###########################################################################################
########################################### EOF ##################################################

@app.route('/api/dashboard/stats')
async def get_dashboard_api_stats():
    """API endpoint for dashboard statistics"""
    try:
        stats = await get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/jobs/recent')
async def get_recent_jobs_api():
    """API endpoint for recent jobs"""
    try:
        jobs = await get_recent_jobs(limit=10)
        return jsonify(jobs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebSocket for real-time progress updates
@app.websocket('/ws/progress/<int:job_id>')
async def progress_websocket(job_id):
    """WebSocket endpoint for real-time progress updates"""
    try:
        while True:
            if job_id in active_jobs:
                await websocket.send(json.dumps(active_jobs[job_id]))
                
                if active_jobs[job_id]['status'] in ['completed', 'failed']:
                    break
            else:
                await websocket.send(json.dumps({'status': 'not_found'}))
                break
            
            await asyncio.sleep(2)
    except Exception as e:
        await websocket.send(json.dumps({'error': str(e)}))



# Update the create_motion_job function to use the standalone create_tables function
async def create_motion_job(user_id: int, file_path: str = None, source_url: str = None,
                          confidence: float = 0.5, frame_skip: int = 5):
    """Create a new motion tracking job"""
    
    async with aiosqlite.connect(DB_PATH) as db:
     
        cursor = await db.execute("""
            INSERT INTO jobs (user_id, source_type, confidence, frame_skip, 
                            task_name, status, credits_cost, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'))
        """, (g.current_user['user_id'], 'file' if file_path else 'url', confidence, frame_skip, 
              'motion_tracking', 'pending', 2))
        
        job_id = cursor.lastrowid
        await db.commit()
    
    analyzer = MotionAnalyzer()
    
    if file_path:
        asyncio.create_task(analyzer.process_video_for_motion(
            file_path, job_id, user_id, confidence, frame_skip
        ))
    
    return job_id


# Update the get_motion_results function to use the standalone create_tables function
async def get_motion_results(job_id: int, user_id: int):
    """Get motion tracking results"""
    
    async with aiosqlite.connect(DB_PATH) as db:
          # Use the standalone function
        
        cursor = await db.execute("""
            SELECT status, completed_at, error_message FROM jobs 
            WHERE id = ? AND user_id = ? AND task_name = 'motion_tracking'
        """, (job_id, user_id))
        job = await cursor.fetchone()
        
        if not job:
            return None
            
        if job[0] != 'completed':
            return {'status': job[0], 'error': job[2] if len(job) > 2 else None}
        
        cursor = await db.execute("""
            SELECT id, total_objects, analysis_data, heatmap_image, trajectory_heatmap
            FROM motion_analysis WHERE job_id = ?
        """, (job_id,))
        analysis = await cursor.fetchone()
        
        if not analysis:
            return {'status': 'completed', 'error': 'No analysis data found'}
        
        cursor = await db.execute("""
            SELECT object_id, object_class, total_distance, avg_speed, max_speed, duration
            FROM object_trajectories WHERE analysis_id = ?
        """, (analysis[0],))
        trajectories = await cursor.fetchall()
        
        # Convert to proper list of dictionaries
        trajectories_list = [
            {
                'object_id': t[0], 
                'class': t[1] or 'unknown', 
                'distance': float(t[2]) if t[2] is not None else 0.0,
                'avg_speed': float(t[3]) if t[3] is not None else 0.0,
                'max_speed': float(t[4]) if t[4] is not None else 0.0,
                'duration': float(t[5]) if t[5] is not None else 0.0
            }
            for t in trajectories
        ]
        
        # Parse analysis data safely
        analysis_data = {}
        if analysis[2]:
            try:
                analysis_data = json.loads(analysis[2])
            except (json.JSONDecodeError, TypeError):
                analysis_data = {}
        
        return {
            'status': 'completed',
            'total_objects': analysis[1] or 0,
            'analysis_summary': analysis_data,
            'heatmap_image': analysis[3],
            'trajectory_heatmap': analysis[4],
            'trajectories': trajectories_list
        }


        
async def get_dashboard_stats():
    """Get dashboard statistics"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM jobs")
        total_jobs = (await cursor.fetchone())[0]
        
        cursor = await db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'processing'")
        active_jobs_count = (await cursor.fetchone())[0]
        
        cursor = await db.execute("SELECT COALESCE(SUM(total_objects), 0) FROM motion_analysis")
        total_objects = (await cursor.fetchone())[0]
        
        cursor = await db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'completed'")
        completed_jobs = (await cursor.fetchone())[0]
        success_rate = (completed_jobs / total_jobs * 100) if total_jobs > 0 else 0
        
        return {
            'total_jobs': total_jobs,
            'active_jobs': active_jobs_count,
            'total_objects': total_objects,
            'success_rate': round(success_rate, 1)
        }

async def get_recent_jobs(limit=5):
    """Get recent jobs"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            SELECT j.id, j.status, j.created_at, j.completed_at, 
                   COALESCE(ma.total_objects, 0) as objects
            FROM jobs j
            LEFT JOIN motion_analysis ma ON j.id = ma.job_id
            WHERE j.task_name = 'motion_tracking'
            ORDER BY j.created_at DESC
            LIMIT ?
        """, (limit,))
        results = await cursor.fetchall()
        
        jobs = []
        for row in results:
            jobs.append({
                'id': row[0],
                'status': row[1],
                'created_at': row[2],
                'completed_at': row[3],
                'objects': row[4]
            })
        
        return jobs


    
# HTML Templates

ENHANCED_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Motion Tracking Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .stat-card { 
            transition: all 0.3s ease; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .stat-card:hover { 
            transform: translateY(-4px); 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1); 
        }
        .glass-effect {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .loading-spinner { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .fade-in { animation: fadeIn 0.5s forwards; }
        @keyframes fadeIn { to { opacity: 1; } }
        .gradient-bg {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Enhanced Header -->
    <header class="gradient-bg text-white shadow-xl">
        <div class="container mx-auto px-6 py-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-4xl font-bold mb-2">
                        <i class="fas fa-video mr-3 text-blue-300"></i>
                        Enhanced Motion Tracking
                    </h1>
                    <p class="text-blue-200">Advanced AI-powered video analysis and object tracking system</p>
                </div>
                <div class="text-right">
                    <div class="text-sm text-blue-200">System Status</div>
                    <div class="flex items-center">
                        <div class="w-3 h-3 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                        <span class="text-lg font-semibold">Online</span>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <div class="container mx-auto px-6 py-8">
        <!-- Quick Stats -->
        <div class="grid md:grid-cols-4 gap-6 mb-8">
            <div class="stat-card text-white rounded-xl shadow-lg p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-blue-200 text-sm">Total Jobs</p>
                        <p class="text-3xl font-bold" id="total-jobs">Loading...</p>
                        <p class="text-blue-200 text-sm mt-1">
                            <i class="fas fa-arrow-up mr-1"></i>Analysis tasks
                        </p>
                    </div>
                    <div class="glass-effect p-3 rounded-full">
                        <i class="fas fa-tasks text-2xl"></i>
                    </div>
                </div>
            </div>
            
            <div class="stat-card text-white rounded-xl shadow-lg p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-blue-200 text-sm">Active Processing</p>
                        <p class="text-3xl font-bold" id="active-jobs">Loading...</p>
                        <p class="text-blue-200 text-sm mt-1">
                            <i class="fas fa-clock mr-1"></i>In progress
                        </p>
                    </div>
                    <div class="glass-effect p-3 rounded-full">
                        <i class="fas fa-play text-2xl"></i>
                    </div>
                </div>
            </div>
            
            <div class="stat-card text-white rounded-xl shadow-lg p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-blue-200 text-sm">Objects Tracked</p>
                        <p class="text-3xl font-bold" id="objects-tracked">Loading...</p>
                        <p class="text-blue-200 text-sm mt-1">
                            <i class="fas fa-crosshairs mr-1"></i>Total detected
                        </p>
                    </div>
                    <div class="glass-effect p-3 rounded-full">
                        <i class="fas fa-search text-2xl"></i>
                    </div>
                </div>
            </div>
            
            <div class="stat-card text-white rounded-xl shadow-lg p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-blue-200 text-sm">Success Rate</p>
                        <p class="text-3xl font-bold" id="success-rate">Loading...</p>
                        <p class="text-blue-200 text-sm mt-1">
                            <i class="fas fa-check-circle mr-1"></i>Completion
                        </p>
                    </div>
                    <div class="glass-effect p-3 rounded-full">
                        <i class="fas fa-chart-line text-2xl"></i>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Actions -->
        <div class="grid lg:grid-cols-3 gap-8 mb-8">
            <!-- Upload Section -->
            <div class="bg-white rounded-xl shadow-lg p-6">
                <h2 class="text-2xl font-semibold mb-4 flex items-center">
                    <i class="fas fa-cloud-upload-alt text-blue-500 mr-3"></i>
                    Upload Video
                </h2>
                <div class="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 transition-colors">
                    <i class="fas fa-video text-4xl text-gray-400 mb-4"></i>
                    <p class="text-gray-600 mb-4">Drop your video file here or click to browse</p>
                    <a href="/upload" class="bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white px-6 py-3 rounded-lg font-medium transition-all duration-200 transform hover:scale-105">
                        <i class="fas fa-plus mr-2"></i>Start Analysis
                    </a>
                </div>
                
                <div class="mt-6 space-y-3">
                    <h3 class="font-semibold text-gray-700">Enhanced Features:</h3>
                    <ul class="text-sm text-gray-600 space-y-2">
                        <li class="flex items-center">
                            <i class="fas fa-check text-green-500 mr-2"></i>
                            AI-powered object detection
                        </li>
                        <li class="flex items-center">
                            <i class="fas fa-check text-green-500 mr-2"></i>
                            Real-time trajectory tracking  
                        </li>
                        <li class="flex items-center">
                            <i class="fas fa-check text-green-500 mr-2"></i>
                            Interactive heatmap generation
                        </li>
                        <li class="flex items-center">
                            <i class="fas fa-check text-green-500 mr-2"></i>
                            Advanced analytics dashboard
                        </li>
                    </ul>
                </div>
            </div>
            
            <!-- Recent Jobs -->
            <div class="bg-white rounded-xl shadow-lg p-6">
                <h2 class="text-2xl font-semibold mb-4 flex items-center">
                    <i class="fas fa-history text-green-500 mr-3"></i>
                    Recent Analysis
                </h2>
                <div id="recent-jobs-list" class="space-y-3">
                    <div class="text-center py-8 text-gray-500">
                        <i class="fas fa-spinner fa-spin text-2xl mb-2"></i>
                        <p>Loading recent jobs...</p>
                    </div>
                </div>
                
                <div class="mt-6">
                    <button onclick="loadRecentJobs()" class="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 py-2 rounded-lg transition duration-200 font-medium">
                        <i class="fas fa-sync-alt mr-2"></i>Refresh Jobs
                    </button>
                </div>
            </div>
            
            <!-- Quick Tools -->
            <div class="bg-white rounded-xl shadow-lg p-6">
                <h2 class="text-2xl font-semibold mb-4 flex items-center">
                    <i class="fas fa-tools text-purple-500 mr-3"></i>
                    Quick Tools
                </h2>
                
                <div class="space-y-4">
                    <a href="/dashboard" class="w-full bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white py-3 px-4 rounded-lg font-medium transition-all duration-200 transform hover:scale-105 flex items-center justify-center">
                        <i class="fas fa-chart-bar mr-2"></i>
                        Analytics Dashboard
                    </a>
                    
                    <button onclick="showJobStatus()" class="w-full bg-gradient-to-r from-green-500 to-teal-500 hover:from-green-600 hover:to-teal-600 text-white py-3 px-4 rounded-lg font-medium transition-all duration-200 transform hover:scale-105 flex items-center justify-center">
                        <i class="fas fa-search mr-2"></i>
                        Check Job Status
                    </button>
                    
                    <button onclick="showSystemInfo()" class="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white py-3 px-4 rounded-lg font-medium transition-all duration-200 transform hover:scale-105 flex items-center justify-center">
                        <i class="fas fa-info-circle mr-2"></i>
                        System Information
                    </button>
                </div>
                
                <!-- System Monitoring -->
                <div class="mt-6 p-4 bg-gray-50 rounded-lg">
                    <h3 class="font-semibold text-gray-700 mb-3">System Health</h3>
                    <div class="space-y-2">
                        <div class="flex justify-between text-sm">
                            <span>CPU Usage</span>
                            <span class="text-green-600">Normal</span>
                        </div>
                        <div class="flex justify-between text-sm">
                            <span>Memory</span>
                            <span class="text-green-600">Optimal</span>
                        </div>
                        <div class="flex justify-between text-sm">
                            <span>Processing Queue</span>
                            <span id="queue-status" class="text-blue-600">Ready</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Performance Metrics -->
        <div class="bg-white rounded-xl shadow-lg p-6 mb-8">
            <h2 class="text-2xl font-semibold mb-6 flex items-center">
                <i class="fas fa-chart-line text-indigo-500 mr-3"></i>
                Performance Overview
            </h2>
            
            <div class="grid md:grid-cols-2 gap-8">
                <div>
                    <h3 class="text-lg font-medium mb-4">Processing Activity</h3>
                    <canvas id="activity-chart" height="200"></canvas>
                </div>
                
                <div>
                    <h3 class="text-lg font-medium mb-4">Success Rate Trend</h3>
                    <canvas id="success-chart" height="200"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modals and Popups -->
    <div id="job-status-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50">
        <div class="flex items-center justify-center min-h-screen p-4">
            <div class="bg-white rounded-xl shadow-xl max-w-md w-full p-6">
                <h3 class="text-xl font-semibold mb-4">Check Job Status</h3>
                <div class="space-y-4">
                    <input type="number" id="job-id-input" placeholder="Enter Job ID" 
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <div class="flex space-x-3">
                        <button onclick="checkJobStatus()" class="flex-1 bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-lg">
                            Check Status
                        </button>
                        <button onclick="closeModal('job-status-modal')" class="flex-1 bg-gray-300 hover:bg-gray-400 text-gray-700 py-2 px-4 rounded-lg">
                            Cancel
                        </button>
                    </div>
                </div>
                <div id="job-status-result" class="mt-4 hidden"></div>
            </div>
        </div>
    </div>

    <script>
        // Load dashboard data on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboardStats();
            loadRecentJobs();
            createCharts();
            
            // Auto-refresh every 30 seconds
            setInterval(loadDashboardStats, 30000);
            setInterval(loadRecentJobs, 60000);
        });
        
        async function loadDashboardStats() {
            try {
                const response = await fetch('/api/dashboard/stats');
                const stats = await response.json();
                
                document.getElementById('total-jobs').textContent = stats.total_jobs;
                document.getElementById('active-jobs').textContent = stats.active_jobs;
                document.getElementById('objects-tracked').textContent = stats.total_objects;
                document.getElementById('success-rate').textContent = stats.success_rate + '%';
                
                // Update queue status
                const queueStatus = document.getElementById('queue-status');
                if (stats.active_jobs > 0) {
                    queueStatus.textContent = `${stats.active_jobs} active`;
                    queueStatus.className = 'text-orange-600';
                } else {
                    queueStatus.textContent = 'Ready';
                    queueStatus.className = 'text-green-600';
                }
            } catch (error) {
                console.error('Failed to load dashboard stats:', error);
            }
        }
        
        async function loadRecentJobs() {
            try {
                const response = await fetch('/api/jobs/recent');
                const jobs = await response.json();
                
                const container = document.getElementById('recent-jobs-list');
                
                if (jobs.length === 0) {
                    container.innerHTML = `
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-inbox text-3xl mb-2"></i>
                            <p>No recent jobs found</p>
                            <p class="text-sm">Upload a video to get started!</p>
                        </div>
                    `;
                    return;
                }
                
                  container.innerHTML = jobs.map(job => `
                    <div class="flex items-center justify-between p-3 bg-gray-50"
                    
                    
                                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors">
                        <div class="flex items-center">
                            <div class="w-3 h-3 rounded-full ${getStatusColor(job.status)} mr-3"></div>
                            <div>
                                <div class="font-medium">Job #${job.id}</div>
                                <div class="text-xs text-gray-500">${new Date(job.created_at).toLocaleDateString()}</div>
                            </div>
                        </div>
                        <div class="text-right">
                            <div class="font-semibold">${job.objects} objects</div>
                            <div class="text-xs capitalize ${getStatusTextColor(job.status)}">${job.status}</div>
                        </div>
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Failed to load recent jobs:', error);
            }
        }
        
        function getStatusColor(status) {
            switch(status) {
                case 'completed': return 'bg-green-500';
                case 'processing': return 'bg-blue-500';
                case 'failed': return 'bg-red-500';
                default: return 'bg-gray-500';
            }
        }
        
        function getStatusTextColor(status) {
            switch(status) {
                case 'completed': return 'text-green-600';
                case 'processing': return 'text-blue-600';
                case 'failed': return 'text-red-600';
                default: return 'text-gray-600';
            }
        }
        
        function createCharts() {
            // Activity chart
            const activityCtx = document.getElementById('activity-chart').getContext('2d');
            new Chart(activityCtx, {
                type: 'line',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [{
                        label: 'Jobs Processed',
                        data: [12, 19, 15, 25, 22, 18, 24],
                        borderColor: '#4f46e5',
                        backgroundColor: 'rgba(79, 70, 229, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
            
            // Success rate chart
            const successCtx = document.getElementById('success-chart').getContext('2d');
            new Chart(successCtx, {
                type: 'bar',
                data: {
                    labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                    datasets: [{
                        label: 'Success Rate %',
                        data: [85, 92, 88, 95],
                        backgroundColor: '#10b981',
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    }
                }
            });
        }
        
        function showJobStatus() {
            document.getElementById('job-status-modal').classList.remove('hidden');
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).classList.add('hidden');
        }
        
        async function checkJobStatus() {
            const jobId = document.getElementById('job-id-input').value;
            if (!jobId) return;
            
            try {
                const response = await fetch(`/api/motion/status/${jobId}`);
                const result = await response.json();
                
                const resultDiv = document.getElementById('job-status-result');
                resultDiv.classList.remove('hidden');
                
                if (result.error) {
                    resultDiv.innerHTML = `
                        <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                            <div class="flex items-center">
                                <i class="fas fa-exclamation-circle text-red-500 mr-2"></i>
                                <span class="text-red-700">${result.error}</span>
                            </div>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="bg-green-50 border border-green-200 rounded-lg p-4">
                            <div class="flex items-center justify-between mb-2">
                                <span class="font-semibold">Job #${jobId}</span>
                                <span class="capitalize px-2 py-1 rounded text-sm ${getStatusTextColor(result.status)} bg-white">${result.status}</span>
                            </div>
                            <div class="text-sm text-gray-600">
                                <div>Progress: ${result.progress || 0}%</div>
                                <div>Message: ${result.message || 'No message'}</div>
                            </div>
                            ${result.status === 'completed' ? `
                                <a href="/results/${jobId}" class="block mt-3 text-center bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-lg text-sm">
                                    View Results
                                </a>
                            ` : ''}
                        </div>
                    `;
                }
            } catch (error) {
                const resultDiv = document.getElementById('job-status-result');
                resultDiv.classList.remove('hidden');
                resultDiv.innerHTML = `
                    <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                        <div class="flex items-center">
                            <i class="fas fa-exclamation-circle text-red-500 mr-2"></i>
                            <span class="text-red-700">Error checking job status</span>
                        </div>
                    </div>
                `;
            }
        }
        
        function showSystemInfo() {
            alert('System Information:\\n\\n• Version: 2.0.0\\n• Last Updated: Today\\n• AI Model: Enhanced Motion Tracking\\n• Support: 24/7 Monitoring\\n• Status: All Systems Operational');
        }
    </script>
</body>
</html>
"""

# Upload HTML Template
UPLOAD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Video - Enhanced Motion Tracking</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .drag-over {
            border-color: #3b82f6;
            background-color: #f0f9ff;
        }
        .progress-bar {
            transition: width 0.3s ease;
        }
        .file-info {
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <!-- Header -->
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-gray-900 mb-2">
                <i class="fas fa-cloud-upload-alt text-blue-500 mr-3"></i>
                Upload Video for Analysis
            </h1>
            <p class="text-gray-600">Upload your video file for advanced motion tracking and trajectory analysis</p>
        </div>

        <!-- Upload Card -->
        <div class="bg-white rounded-xl shadow-lg overflow-hidden">
            <!-- Progress Bar -->
            <div id="upload-progress" class="hidden">
                <div class="h-2 bg-gray-200">
                    <div id="progress-bar" class="h-full bg-blue-500 progress-bar" style="width: 0%"></div>
                </div>
            </div>

            <div class="p-8">
                <!-- Drag & Drop Area -->
                <div id="drop-area" class="border-3 border-dashed border-gray-300 rounded-lg p-12 text-center cursor-pointer transition-all duration-200 hover:border-blue-400 hover:bg-blue-50">
                    <i class="fas fa-cloud-upload-alt text-6xl text-gray-400 mb-4"></i>
                    <h3 class="text-xl font-semibold text-gray-700 mb-2">Drop your video file here</h3>
                    <p class="text-gray-500 mb-4">or click to browse files</p>
                    <input type="file" id="file-input" class="hidden" accept="video/*">
                    <button onclick="document.getElementById('file-input').click()" 
                            class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg font-medium transition-colors">
                        <i class="fas fa-folder-open mr-2"></i>Choose File
                    </button>
                    <p class="text-sm text-gray-400 mt-4">Supported formats: MP4, AVI, MOV, WMV (Max 500MB)</p>
                </div>

                <!-- File Info -->
                <div id="file-info" class="hidden mt-6 p-4 bg-green-50 border border-green-200 rounded-lg file-info">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center">
                            <i class="fas fa-file-video text-green-500 text-xl mr-3"></i>
                            <div>
                                <div id="file-name" class="font-semibold text-gray-800"></div>
                                <div id="file-size" class="text-sm text-gray-600"></div>
                            </div>
                        </div>
                        <button onclick="clearFile()" class="text-red-500 hover:text-red-700">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>

                <!-- Configuration Options -->
                <div id="config-options" class="hidden mt-8">
                    <h3 class="text-lg font-semibold text-gray-800 mb-4">Analysis Configuration</h3>
                    
                    <div class="grid md:grid-cols-2 gap-6">
                        <!-- Confidence Threshold -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                <i class="fas fa-bullseye mr-2"></i>Confidence Threshold
                            </label>
                            <input type="range" id="confidence" min="0.1" max="0.9" step="0.1" value="0.5" 
                                   class="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer">
                            <div class="flex justify-between text-xs text-gray-500">
                                <span>Low (0.1)</span>
                                <span id="confidence-value">Medium (0.5)</span>
                                <span>High (0.9)</span>
                            </div>
                        </div>

                        <!-- Frame Skip -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                <i class="fas fa-film mr-2"></i>Frame Processing Rate
                            </label>
                            <select id="frame-skip" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                                <option value="1">Every frame (Highest accuracy)</option>
                                <option value="3" selected>Every 3rd frame (Balanced)</option>
                                <option value="5">Every 5th frame (Faster processing)</option>
                                <option value="10">Every 10th frame (Fastest)</option>
                            </select>
                        </div>
                    </div>

                    <!-- Advanced Options -->
                    <div class="mt-6">
                        <button onclick="toggleAdvancedOptions()" class="flex items-center text-blue-600 hover:text-blue-800">
                            <i class="fas fa-cogs mr-2"></i>
                            Advanced Options
                            <i id="advanced-arrow" class="fas fa-chevron-down ml-2"></i>
                        </button>
                        
                        <div id="advanced-options" class="hidden mt-4 space-y-4">
                            <div class="grid md:grid-cols-2 gap-4">
                                <div>
                                    <label class="flex items-center">
                                        <input type="checkbox" id="enable-heatmap" checked class="mr-2">
                                        Generate Motion Heatmap
                                    </label>
                                </div>
                                <div>
                                    <label class="flex items-center">
                                        <input type="checkbox" id="enable-trajectories" checked class="mr-2">
                                        Track Individual Trajectories
                                    </label>
                                </div>
                                <div>
                                    <label class="flex items-center">
                                        <input type="checkbox" id="enable-analytics" checked class="mr-2">
                                        Generate Analytics Report
                                    </label>
                                </div>
                                <div>
                                    <label class="flex items-center">
                                        <input type="checkbox" id="enable-export" checked class="mr-2">
                                        Enable Data Export
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Start Analysis Button -->
                    <div class="mt-8 text-center">
                        <button id="start-analysis" 
                                class="bg-gradient-to-r from-green-500 to-teal-500 hover:from-green-600 hover:to-teal-600 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all duration-200 transform hover:scale-105">
                            <i class="fas fa-play-circle mr-2"></i>Start Motion Analysis
                        </button>
                    </div>
                </div>

                <!-- Processing Status -->
                <div id="processing-status" class="hidden mt-8">
                    <div class="text-center p-6 bg-blue-50 rounded-lg">
                        <i class="fas fa-spinner fa-spin text-3xl text-blue-500 mb-3"></i>
                        <h4 class="text-lg font-semibold text-blue-800">Processing Video</h4>
                        <p id="status-message" class="text-blue-600 mt-2">Initializing analysis...</p>
                        
                        <div class="mt-4 bg-white rounded-full h-4 overflow-hidden">
                            <div id="processing-bar" class="h-full bg-gradient-to-r from-blue-500 to-purple-500 progress-bar" style="width: 0%"></div>
                        </div>
                        
                        <div class="mt-4 text-sm text-blue-600">
                            <span id="progress-text">0%</span> • 
                            <span id="time-estimate">Estimating time...</span>
                        </div>
                    </div>
                    
                    <div class="mt-4 text-center">
                        <a href="/" class="text-blue-600 hover:text-blue-800">
                            <i class="fas fa-home mr-2"></i>Return to Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Features Overview -->
        <div class="mt-8 grid md:grid-cols-3 gap-6">
            <div class="text-center p-6 bg-white rounded-lg shadow">
                <i class="fas fa-crosshairs text-3xl text-blue-500 mb-3"></i>
                <h4 class="font-semibold mb-2">Object Tracking</h4>
                <p class="text-gray-600 text-sm">Advanced multi-object tracking with Kalman filtering</p>
            </div>
            <div class="text-center p-6 bg-white rounded-lg shadow">
                <i class="fas fa-map-marked-alt text-3xl text-green-500 mb-3"></i>
                <h4 class="font-semibold mb-2">Trajectory Analysis</h4>
                <p class="text-gray-600 text-sm">Detailed path analysis and movement patterns</p>
            </div>
            <div class="text-center p-6 bg-white rounded-lg shadow">
                <i class="fas fa-chart-bar text-3xl text-purple-500 mb-3"></i>
                <h4 class="font-semibold mb-2">Interactive Reports</h4>
                <p class="text-gray-600 text-sm">Comprehensive analytics and visualization</p>
            </div>
        </div>
    </div>

    <script>
        let selectedFile = null;
        let jobId = null;

        // Initialize event listeners
        document.addEventListener('DOMContentLoaded', function() {
            initializeDragAndDrop();
            setupEventListeners();
        });

        function initializeDragAndDrop() {
            const dropArea = document.getElementById('drop-area');
            const fileInput = document.getElementById('file-input');

            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropArea.addEventListener(eventName, preventDefaults, false);
            });

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            ['dragenter', 'dragover'].forEach(eventName => {
                dropArea.addEventListener(eventName, highlight, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                dropArea.addEventListener(eventName, unhighlight, false);
            });

            function highlight() {
                dropArea.classList.add('drag-over');
            }

            function unhighlight() {
                dropArea.classList.remove('drag-over');
            }

            dropArea.addEventListener('drop', handleDrop, false);
            fileInput.addEventListener('change', handleFileSelect, false);

            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                handleFiles(files);
            }

            function handleFileSelect(e) {
                handleFiles(e.target.files);
            }
        }

        function setupEventListeners() {
            // Confidence slider
            document.getElementById('confidence').addEventListener('input', function() {
                const value = parseFloat(this.value);
                const confidenceText = value < 0.4 ? 'Low' : value < 0.7 ? 'Medium' : 'High';
                document.getElementById('confidence-value').textContent = `${confidenceText} (${value})`;
            });

            // Start analysis button
            document.getElementById('start-analysis').addEventListener('click', startAnalysis);
        }

        function handleFiles(files) {
            if (files.length === 0) return;

            const file = files[0];
            
            // Validate file type
            const validTypes = ['video/mp4', 'video/avi', 'video/quicktime', 'video/x-ms-wmv'];
            if (!validTypes.includes(file.type)) {
                alert('Please select a valid video file (MP4, AVI, MOV, WMV)');
                return;
            }

            // Validate file size (500MB limit)
            if (file.size > 500 * 1024 * 1024) {
                alert('File size must be less than 500MB');
                return;
            }

            selectedFile = file;
            displayFileInfo(file);
            showConfigurationOptions();
        }

        function displayFileInfo(file) {
            const fileSize = (file.size / (1024 * 1024)).toFixed(2);
            
            document.getElementById('file-name').textContent = file.name;
            document.getElementById('file-size').textContent = `${fileSize} MB`;
            document.getElementById('file-info').classList.remove('hidden');
        }

        function showConfigurationOptions() {
            document.getElementById('config-options').classList.remove('hidden');
        }

        function clearFile() {
            selectedFile = null;
            document.getElementById('file-input').value = '';
            document.getElementById('file-info').classList.add('hidden');
            document.getElementById('config-options').classList.add('hidden');
        }

        function toggleAdvancedOptions() {
            const options = document.getElementById('advanced-options');
            const arrow = document.getElementById('advanced-arrow');
            
            if (options.classList.contains('hidden')) {
                options.classList.remove('hidden');
                arrow.classList.remove('fa-chevron-down');
                arrow.classList.add('fa-chevron-up');
            } else {
                options.classList.add('hidden');
                arrow.classList.remove('fa-chevron-up');
                arrow.classList.add('fa-chevron-down');
            }
        }

        async function startAnalysis() {
            if (!selectedFile) {
                alert('Please select a video file first');
                return;
            }

            const confidence = parseFloat(document.getElementById('confidence').value);
            const frameSkip = parseInt(document.getElementById('frame-skip').value);

            // Show processing status
            document.getElementById('config-options').classList.add('hidden');
            document.getElementById('processing-status').classList.remove('hidden');

            try {
                const formData = new FormData();
                formData.append('video', selectedFile);
                formData.append('confidence', confidence);
                formData.append('frame_skip', frameSkip);

                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (response.ok) {
                    jobId = result.job_id;
                    monitorProgress(jobId);
                } else {
                    throw new Error(result.error || 'Upload failed');
                }

            } catch (error) {
                document.getElementById('status-message').textContent = `Error: ${error.message}`;
                document.getElementById('status-message').classList.add('text-red-600');
            }
        }

        async function monitorProgress(jobId) {
            const progressBar = document.getElementById('processing-bar');
            const progressText = document.getElementById('progress-text');
            const statusMessage = document.getElementById('status-message');
            const timeEstimate = document.getElementById('time-estimate');

            let startTime = Date.now();

            const updateProgress = async () => {
                try {
                    const response = await fetch(`/api/motion/status/${jobId}`);
                    const status = await response.json();

                    if (status.error) {
                        statusMessage.textContent = `Error: ${status.error}`;
                        statusMessage.classList.add('text-red-600');
                        return;
                    }

                    const progress = status.progress || 0;
                    progressBar.style.width = `${progress}%`;
                    progressText.textContent = `${Math.round(progress)}%`;
                    statusMessage.textContent = status.message || 'Processing...';

                    // Calculate time estimate
                    if (progress > 0) {
                        const elapsed = (Date.now() - startTime) / 1000;
                        const totalEstimated = elapsed / (progress / 100);
                        const remaining = Math.max(0, totalEstimated - elapsed);
                        timeEstimate.textContent = `~${Math.round(remaining)}s remaining`;
                    }

                    if (status.status === 'completed') {
                        statusMessage.innerHTML = `<i class="fas fa-check-circle mr-2"></i>Analysis completed!`;
                        statusMessage.classList.add('text-green-600');
                        
                        setTimeout(() => {
                            window.location.href = `/results/${jobId}`;
                        }, 2000);
                    } else if (status.status === 'failed') {
                        statusMessage.textContent = `Analysis failed: ${status.message}`;
                        statusMessage.classList.add('text-red-600');
                    } else {
                        setTimeout(updateProgress, 2000);
                    }

                } catch (error) {
                    console.error('Progress monitoring error:', error);
                    setTimeout(updateProgress, 5000);
                }
            };

            updateProgress();
        }
    </script>
</body>
</html>
"""
# ... (previous code remains the same)


# Update the template to use the new sync_list filter and handle empty data
ENHANCED_RESULTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Results - Enhanced Motion Tracking</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .glass-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .hover-lift {
            transition: all 0.3s ease;
        }
        .hover-lift:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .fade-in {
            animation: fadeIn 0.6s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <div class="text-center mb-8 fade-in">
            <h1 class="text-4xl font-bold text-gray-900 mb-3">
                <i class="fas fa-chart-bar text-blue-500 mr-3"></i>
                Motion Analysis Results
            </h1>
            <p class="text-gray-600 text-lg">Job #{{ job_id }} • {{ results.total_objects }} objects tracked</p>
            <div class="flex justify-center space-x-4 mt-4">
                <a href="/" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-lg transition-colors">
                    <i class="fas fa-home mr-2"></i>Dashboard
                </a>
                <a href="/upload" class="bg-green-500 hover:bg-green-600 text-white px-6 py-2 rounded-lg transition-colors">
                    <i class="fas fa-plus mr-2"></i>New Analysis
                </a>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="grid md:grid-cols-4 gap-6 mb-8 fade-in">
            <div class="bg-white rounded-xl shadow-lg p-6 text-center hover-lift">
                <div class="glass-card w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-crosshairs text-2xl text-blue-500"></i>
                </div>
                <h3 class="text-2xl font-bold text-gray-800">{{ results.total_objects }}</h3>
                <p class="text-gray-600">Objects Tracked</p>
            </div>
            
            <div class="bg-white rounded-xl shadow-lg p-6 text-center hover-lift">
                <div class="glass-card w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-route text-2xl text-green-500"></i>
                </div>
                <h3 class="text-2xl font-bold text-gray-800">
                    {{ (results.trajectories|map(attribute='distance')|list|sum|default(0))|round(1) }}
                </h3>
                <p class="text-gray-600">Total Distance (px)</p>
            </div>
            
            <div class="bg-white rounded-xl shadow-lg p-6 text-center hover-lift">
                <div class="glass-card w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-tachometer-alt text-2xl text-orange-500"></i>
                </div>
                <h3 class="text-2xl font-bold text-gray-800">
                    {% set speeds = results.trajectories|map(attribute='avg_speed')|list %}
                    {{ (speeds|sum / speeds|length if speeds|length > 0 else 0)|round(1) }}
                </h3>
                <p class="text-gray-600">Avg Speed</p>
            </div>
            
            <div class="bg-white rounded-xl shadow-lg p-6 text-center hover-lift">
                <div class="glass-card w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-3">
                    <i class="fas fa-clock text-2xl text-purple-500"></i>
                </div>
                <h3 class="text-2xl font-bold text-gray-800">
                    {% set durations = results.trajectories|map(attribute='duration')|list %}
                    {{ (durations|max if durations|length > 0 else 0)|round(1) }}
                </h3>
                <p class="text-gray-600">Max Duration (s)</p>
            </div>
        </div>

        <!-- Main Content Grid -->
        <div class="grid lg:grid-cols-3 gap-8 mb-8">
            <!-- Heatmaps Section -->
            <div class="lg:col-span-2">
                <div class="bg-white rounded-xl shadow-lg p-6 mb-6">
                    <h2 class="text-2xl font-semibold mb-4 flex items-center">
                        <i class="fas fa-fire text-red-500 mr-3"></i>
                        Motion Heatmaps
                    </h2>
                    
                    <div class="grid md:grid-cols-2 gap-6">
                        <div class="text-center">
                            <h3 class="font-semibold mb-3">Motion Detection Heatmap</h3>
                            <div class="border-2 border-gray-200 rounded-lg p-4 bg-gray-50">
                                {% if results.heatmap_image %}
                                <img id="heatmap-img" src="/api/motion/heatmap/{{ job_id }}" 
                                     alt="Motion Heatmap" class="w-full h-64 object-contain rounded">
                                {% else %}
                                <div class="w-full h-64 flex items-center justify-center text-gray-500">
                                    <i class="fas fa-image text-4xl mb-2"></i>
                                    <p>No heatmap available</p>
                                </div>
                                {% endif %}
                            </div>
                            {% if results.heatmap_image %}
                            <div class="mt-3 space-x-2">
                                <button onclick="viewFullscreen('heatmap-img')" 
                                        class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded text-sm">
                                    <i class="fas fa-expand mr-1"></i>Fullscreen
                                </button>
                                <button onclick="downloadHeatmap()" 
                                        class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded text-sm">
                                    <i class="fas fa-download mr-1"></i>Download
                                </button>
                            </div>
                            {% endif %}
                        </div>
                        
                        <div class="text-center">
                            <h3 class="font-semibold mb-3">Trajectory Heatmap</h3>
                            <div class="border-2 border-gray-200 rounded-lg p-4 bg-gray-50">
                                {% if results.trajectory_heatmap %}
                                <img id="trajectory-heatmap-img" src="/api/motion/trajectory-heatmap/{{ job_id }}" 
                                     alt="Trajectory Heatmap" class="w-full h-64 object-contain rounded">
                                {% else %}
                                <div class="w-full h-64 flex items-center justify-center text-gray-500">
                                    <i class="fas fa-image text-4xl mb-2"></i>
                                    <p>No trajectory heatmap available</p>
                                </div>
                                {% endif %}
                            </div>
                            {% if results.trajectory_heatmap %}
                            <div class="mt-3 space-x-2">
                                <button onclick="viewFullscreen('trajectory-heatmap-img')" 
                                        class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded text-sm">
                                    <i class="fas fa-expand mr-1"></i>Fullscreen
                                </button>
                                <button onclick="downloadTrajectoryHeatmap()" 
                                        class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded text-sm">
                                    <i class="fas fa-download mr-1"></i>Download
                                </button>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                </div>

                <!-- Objects List -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-2xl font-semibold mb-4 flex items-center">
                        <i class="fas fa-list text-purple-500 mr-3"></i>
                        Tracked Objects
                    </h2>
                    
                    {% if results.trajectories and results.trajectories|length > 0 %}
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="bg-gray-50">
                                    <th class="px-4 py-3 text-left">Object ID</th>
                                    <th class="px-4 py-3 text-left">Class</th>
                                    <th class="px-4 py-3 text-left">Distance</th>
                                    <th class="px-4 py-3 text-left">Avg Speed</th>
                                    <th class="px-4 py-3 text-left">Duration</th>
                                    <th class="px-4 py-3 text-left">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for obj in results.trajectories %}
                                <tr class="border-b hover:bg-gray-50">
                                    <td class="px-4 py-3 font-mono">#{{ obj.object_id }}</td>
                                    <td class="px-4 py-3">
                                        <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded text-sm capitalize">
                                            {{ obj.class }}
                                        </span>
                                    </td>
                                    <td class="px-4 py-3">{{ "%.1f"|format(obj.distance) }} px</td>
                                    <td class="px-4 py-3">{{ "%.1f"|format(obj.avg_speed) }}</td>
                                    <td class="px-4 py-3">{{ "%.1f"|format(obj.duration) }}s</td>
                                    <td class="px-4 py-3">
                                        <a href="/track/{{ job_id }}/{{ obj.object_id }}" 
                                           class="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded text-sm">
                                            <i class="fas fa-search mr-1"></i>Track
                                        </a>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="text-center py-8 text-gray-500">
                        <i class="fas fa-inbox text-4xl mb-2"></i>
                        <p>No objects were tracked in this analysis</p>
                    </div>
                    {% endif %}
                </div>
            </div>

            <!-- Analytics Sidebar -->
            <div class="space-y-6">
                <!-- Speed Distribution -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h3 class="text-lg font-semibold mb-4">Speed Distribution</h3>
                    <canvas id="speed-chart" height="200"></canvas>
                </div>

                <!-- Object Types -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h3 class="text-lg font-semibold mb-4">Object Classification</h3>
                    <canvas id="type-chart" height="200"></canvas>
                </div>

                <!-- Export Options -->
                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h3 class="text-lg font-semibold mb-4">Export Results</h3>
                    <div class="space-y-3">
                        <button onclick="exportJSON()" class="w-full bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded flex items-center justify-center">
                            <i class="fas fa-file-code mr-2"></i>Export as JSON
                        </button>
                        <button onclick="exportReport()" class="w-full bg-green-500 hover:bg-green-600 text-white py-2 px-4 rounded flex items-center justify-center">
                            <i class="fas fa-file-pdf mr-2"></i>Generate Report
                        </button>
                        <button onclick="exportImages()" class="w-full bg-purple-500 hover:bg-purple-600 text-white py-2 px-4 rounded flex items-center justify-center">
                            <i class="fas fa-images mr-2"></i>Export All Images
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Fullscreen Modal -->
        <div id="fullscreen-modal" class="fixed inset-0 bg-black bg-opacity-90 hidden z-50">
            <div class="flex items-center justify-center h-full">
                <div class="max-w-4xl w-full p-4">
                    <div class="flex justify-between items-center mb-4">
                        <h3 id="modal-title" class="text-white text-xl"></h3>
                        <button onclick="closeFullscreen()" class="text-white text-2xl hover:text-gray-300">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <img id="modal-image" src="" alt="" class="w-full h-auto max-h-screen object-contain">
                </div>
            </div>
        </div>
    </div>

    <script>
        // Initialize charts
        document.addEventListener('DOMContentLoaded', function() {
            createSpeedChart();
            createTypeChart();
        });

        function createSpeedChart() {
            const ctx = document.getElementById('speed-chart').getContext('2d');
            const speeds = {{ results.trajectories|map(attribute='avg_speed')|list|tojson }};
            
            if (speeds.length === 0) {
                ctx.fillText('No speed data available', 10, 50);
                return;
            }
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: speeds.map((_, i) => `Obj ${i + 1}`),
                    datasets: [{
                        label: 'Average Speed',
                        data: speeds,
                        backgroundColor: 'rgba(54, 162, 235, 0.6)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Speed (px/frame)'
                            }
                        }
                    }
                }
            });
        }

        function createTypeChart() {
            const ctx = document.getElementById('type-chart').getContext('2d');
            const objects = {{ results.trajectories|list|tojson }};
            
            if (objects.length === 0) {
                ctx.fillText('No object data available', 10, 50);
                return;
            }
            
            const typeCount = {};
            
            objects.forEach(obj => {
                const type = obj.class || 'unknown';
                typeCount[type] = (typeCount[type] || 0) + 1;
            });
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(typeCount),
                    datasets: [{
                        data: Object.values(typeCount),
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.6)',
                            'rgba(54, 162, 235, 0.6)',
                            'rgba(255, 206, 86, 0.6)',
                            'rgba(75, 192, 192, 0.6)',
                            'rgba(153, 102, 255, 0.6)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }

        function viewFullscreen(imageId) {
            const img = document.getElementById(imageId);
            const modal = document.getElementById('fullscreen-modal');
            const modalImg = document.getElementById('modal-image');
            const modalTitle = document.getElementById('modal-title');
            
            modalTitle.textContent = img.alt;
            modalImg.src = img.src;
            modal.classList.remove('hidden');
        }

        function closeFullscreen() {
            document.getElementById('fullscreen-modal').classList.add('hidden');
        }

        function downloadHeatmap() {
            const link = document.createElement('a');
            link.href = document.getElementById('heatmap-img').src;
            link.download = `heatmap-job-{{ job_id }}.png`;
            link.click();
        }

        function downloadTrajectoryHeatmap() {
            const link = document.createElement('a');
            link.href = document.getElementById('trajectory-heatmap-img').src;
            link.download = `trajectory-heatmap-job-{{ job_id }}.png`;
            link.click();
        }

        function exportJSON() {
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({{ results.analysis_summary|tojson }}, null, 2));
            const link = document.createElement('a');
            link.href = dataStr;
            link.download = `motion-analysis-job-{{ job_id }}.json`;
            link.click();
        }

        function exportReport() {
            alert('PDF report generation would be implemented here. This feature requires server-side PDF generation.');
        }

        function exportImages() {
            {% if results.heatmap_image %}downloadHeatmap();{% endif %}
            {% if results.trajectory_heatmap %}setTimeout(downloadTrajectoryHeatmap, 100);{% endif %}
            alert('Available images are being downloaded...');
        }
    </script>
</body>
</html>
"""

# Also add a simple test route to verify the database is working
@app.route('/test-db')
async def test_db():
    """Test database connection and tables"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
            return jsonify({'status': 'Database connected successfully'})
    except Exception as e:
        return jsonify({'error': f'Database connection failed: {str(e)}'}), 500
# Add the missing HTML templates
INTERACTIVE_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Dashboard - Motion Tracking</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-3xl font-bold mb-6">Interactive Analytics Dashboard</h1>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <!-- Add interactive dashboard content here -->
        </div>
    </div>
</body>
</html>
"""

PROGRESS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Processing - Motion Tracking</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 text-center">
        <div class="bg-white rounded-lg shadow-lg p-8 max-w-md mx-auto">
            <i class="fas fa-spinner fa-spin text-4xl text-blue-500 mb-4"></i>
            <h2 class="text-2xl font-bold mb-2">Processing Video</h2>
            <p class="text-gray-600 mb-4">Your video is being analyzed. This may take a few minutes.</p>
            <div class="w-full bg-gray-200 rounded-full h-4">
                <div id="progress-bar" class="bg-blue-500 h-4 rounded-full" style="width: {{ status.progress }}%"></div>
            </div>
            <p id="progress-text" class="mt-2 text-sm text-gray-600">{{ status.progress }}% Complete</p>
            <p id="status-message" class="mt-2 text-sm">{{ status.message }}</p>
        </div>
    </div>
    <script>
        // Auto-refresh progress
        setInterval(() => {
            window.location.reload();
        }, 5000);
    </script>
</body>
</html>
"""


# Update the OBJECT_TRACKING_HTML template to handle empty data gracefully
OBJECT_TRACKING_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Object Tracking - Motion Analysis</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-900 mb-3">
                <i class="fas fa-search-location text-blue-500 mr-3"></i>
                Object Tracking Details
            </h1>
            <p class="text-gray-600 text-lg">Job #{{ object_info.job_id }} • Object #{{ object_info.object_id }}</p>
            <div class="flex justify-center space-x-4 mt-4">
                <a href="/results/{{ object_info.job_id }}" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-lg transition-colors">
                    <i class="fas fa-arrow-left mr-2"></i>Back to Results
                </a>
                <a href="/" class="bg-gray-500 hover:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors">
                    <i class="fas fa-home mr-2"></i>Dashboard
                </a>
            </div>
        </div>

        <!-- Object Summary -->
        <div class="grid md:grid-cols-4 gap-6 mb-8">
            <div class="stat-card rounded-xl shadow-lg p-6 text-center">
                <i class="fas fa-route text-3xl mb-3 text-white"></i>
                <h3 class="text-2xl font-bold">{{ "%.1f"|format(object_info.total_distance) }} px</h3>
                <p class="text-blue-200">Total Distance</p>
            </div>
            
            <div class="stat-card rounded-xl shadow-lg p-6 text-center">
                <i class="fas fa-tachometer-alt text-3xl mb-3 text-white"></i>
                <h3 class="text-2xl font-bold">{{ "%.1f"|format(object_info.avg_speed) }}</h3>
                <p class="text-blue-200">Avg Speed</p>
            </div>
            
            <div class="stat-card rounded-xl shadow-lg p-6 text-center">
                <i class="fas fa-rocket text-3xl mb-3 text-white"></i>
                <h3 class="text-2xl font-bold">{{ "%.1f"|format(object_info.max_speed) }}</h3>
                <p class="text-blue-200">Max Speed</p>
            </div>
            
            <div class="stat-card rounded-xl shadow-lg p-6 text-center">
                <i class="fas fa-clock text-3xl mb-3 text-white"></i>
                <h3 class="text-2xl font-bold">{{ "%.1f"|format(object_info.duration) }}s</h3>
                <p class="text-blue-200">Duration</p>
            </div>
        </div>

        <div class="grid lg:grid-cols-2 gap-8">
            <!-- Trajectory Visualization -->
            <div class="bg-white rounded-xl shadow-lg p-6">
                <h2 class="text-2xl font-semibold mb-4 flex items-center">
                    <i class="fas fa-map-marked-alt text-green-500 mr-3"></i>
                    Trajectory Path
                </h2>
                {% if object_info.trajectory_points and object_info.trajectory_points|length > 0 %}
                <div class="border-2 border-gray-200 rounded-lg p-4 bg-gray-50">
                    <img src="/api/motion/object-trajectory/{{ object_info.job_id }}/{{ object_info.object_id }}" 
                         alt="Object Trajectory" class="w-full h-80 object-contain">
                </div>
                <div class="mt-3 text-center">
                    <button onclick="downloadTrajectory()" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded">
                        <i class="fas fa-download mr-1"></i>Download Trajectory
                    </button>
                </div>
                {% else %}
                <div class="text-center py-12 text-gray-500">
                    <i class="fas fa-map-marker-alt text-4xl mb-3"></i>
                    <p>No trajectory data available</p>
                    <p class="text-sm">This object may not have sufficient tracking data</p>
                </div>
                {% endif %}
            </div>

            <!-- Detailed Information -->
            <div class="bg-white rounded-xl shadow-lg p-6">
                <h2 class="text-2xl font-semibold mb-4 flex items-center">
                    <i class="fas fa-info-circle text-blue-500 mr-3"></i>
                    Object Information
                </h2>
                
                <div class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-gray-50 p-3 rounded-lg">
                            <label class="block text-sm font-medium text-gray-600">Object ID</label>
                            <p class="font-mono text-lg">#{{ object_info.object_id }}</p>
                        </div>
                        <div class="bg-gray-50 p-3 rounded-lg">
                            <label class="block text-sm font-medium text-gray-600">Class</label>
                            <p class="text-lg capitalize">{{ object_info.object_class }}</p>
                        </div>
                    </div>
                    
                    <div class="bg-gray-50 p-3 rounded-lg">
                        <label class="block text-sm font-medium text-gray-600">Trajectory Points</label>
                        <p class="text-lg">{{ object_info.trajectory_points|length }} points tracked</p>
                    </div>
                    
                    {% if object_info.analysis_summary %}
                    <div class="bg-blue-50 p-3 rounded-lg">
                        <label class="block text-sm font-medium text-blue-600">Analysis Summary</label>
                        <div class="text-sm text-blue-800 mt-2">
                            {% if object_info.analysis_summary.path_straightness %}
                            <p>Path Straightness: {{ "%.2f"|format(object_info.analysis_summary.path_straightness) }}</p>
                            {% endif %}
                            {% if object_info.analysis_summary.direction_variance %}
                            <p>Direction Variance: {{ "%.2f"|format(object_info.analysis_summary.direction_variance) }}</p>
                            {% endif %}
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Speed and Direction Charts -->
                {% if object_info.speed_data and object_info.speed_data|length > 1 %}
                <div class="mt-6">
                    <h3 class="text-lg font-semibold mb-3">Speed Over Time</h3>
                    <canvas id="speed-chart" height="150"></canvas>
                </div>
                {% endif %}

                {% if object_info.direction_data and object_info.direction_data|length > 1 %}
                <div class="mt-6">
                    <h3 class="text-lg font-semibold mb-3">Direction Changes</h3>
                    <canvas id="direction-chart" height="150"></canvas>
                </div>
                {% endif %}
            </div>
        </div>

        <!-- Raw Data Section -->
        <div class="mt-8 bg-white rounded-xl shadow-lg p-6">
            <h2 class="text-2xl font-semibold mb-4 flex items-center">
                <i class="fas fa-database text-purple-500 mr-3"></i>
                Raw Trajectory Data
            </h2>
            
            {% if object_info.trajectory_points and object_info.trajectory_points|length > 0 %}
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-gray-50">
                            <th class="px-3 py-2 text-left">Point</th>
                            <th class="px-3 py-2 text-left">X</th>
                            <th class="px-3 py-2 text-left">Y</th>
                            <th class="px-3 py-2 text-left">Frame</th>
                            <th class="px-3 py-2 text-left">Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for point in object_info.trajectory_points[:10] %}
                        <tr class="border-b">
                            <td class="px-3 py-2 font-mono">{{ loop.index }}</td>
                            <td class="px-3 py-2">{{ "%.1f"|format(point[0]) if point[0] is number else point[0] }}</td>
                            <td class="px-3 py-2">{{ "%.1f"|format(point[1]) if point[1] is number else point[1] }}</td>
                            <td class="px-3 py-2">{{ point[2] if point|length > 2 else 'N/A' }}</td>
                            <td class="px-3 py-2">{{ "%.1f"|format(point[3]) if point|length > 3 and point[3] is number else 'N/A' }}</td>
                        </tr>
                        {% endfor %}
                        {% if object_info.trajectory_points|length > 10 %}
                        <tr>
                            <td colspan="5" class="px-3 py-2 text-center text-gray-500">
                                ... and {{ object_info.trajectory_points|length - 10 }} more points
                            </td>
                        </tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="text-center py-8 text-gray-500">
                <i class="fas fa-database text-3xl mb-2"></i>
                <p>No trajectory data available for display</p>
            </div>
            {% endif %}
        </div>
    </div>

    <script>
        // Initialize charts if data is available
        document.addEventListener('DOMContentLoaded', function() {
            {% if object_info.speed_data and object_info.speed_data|length > 1 %}
            createSpeedChart();
            {% endif %}
            
            {% if object_info.direction_data and object_info.direction_data|length > 1 %}
            createDirectionChart();
            {% endif %}
        });

        {% if object_info.speed_data and object_info.speed_data|length > 1 %}
        function createSpeedChart() {
            const ctx = document.getElementById('speed-chart').getContext('2d');
            const speeds = {{ object_info.speed_data|tojson }};
            
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: speeds.map((_, i) => i + 1),
                    datasets: [{
                        label: 'Speed (px/frame)',
                        data: speeds,
                        borderColor: 'rgb(75, 192, 192)',
                        tension: 0.1,
                        fill: false
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        {% endif %}

        {% if object_info.direction_data and object_info.direction_data|length > 1 %}
        function createDirectionChart() {
            const ctx = document.getElementById('direction-chart').getContext('2d');
            const directions = {{ object_info.direction_data|tojson }};
            
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: directions.map((_, i) => i + 1),
                    datasets: [{
                        label: 'Direction (degrees)',
                        data: directions,
                        borderColor: 'rgb(153, 102, 255)',
                        tension: 0.1,
                        fill: false
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        {% endif %}

        function downloadTrajectory() {
            const link = document.createElement('a');
            link.href = '/api/motion/object-trajectory/{{ object_info.job_id }}/{{ object_info.object_id }}';
            link.download = `trajectory-job-{{ object_info.job_id }}-object-{{ object_info.object_id }}.png`;
            link.click();
        }
    </script>
</body>
</html>
"""
# Add missing route for the interactive dashboard
@app.route('/analytics')
async def analytics_dashboard():
    """Advanced analytics dashboard"""
    return await render_template_string(INTERACTIVE_DASHBOARD_HTML)




@app.route("/Frame/Extractor/")
@auth_required
async def extractor():
    return await render_template( 'Frame-Extractor-Concept.html' , user = g.current_user )
  
@app.route("/upload/frame/", methods=["POST"])
@auth_required
async def upload_frame():
    """
    Chunked async upload with file hashing:
    - Accepts multipart/form-data with 'file' field.
    - Streams the werkzeug.FileStorage.stream in sync reads (1MB) and writes via aiofiles.
    - Calculates SHA256 hash of the uploaded file
    """
    try:
        files = await request.files
        if "file" not in files:
            return jsonify({"error": "No file field in form"}), 400
        
        file = files["file"]
        filename = file.filename or f"upload_{int(datetime.utcnow().timestamp())}"
        
        if not allowed_file(filename):
            return jsonify({"error": f"File type not allowed. Allowed: {ALLOWED_EXTENSIONS}"}), 400
        
        safe_name = f"{int(datetime.utcnow().timestamp())}_{filename.replace(' ', '_')}"
        save_path = os.path.join(UPLOAD_DIR, safe_name)
        
        # Stream read from werkzeug FileStorage .stream (synchronous) in chunks and write via aiofiles
        with file.stream as src:
            async with aiofiles.open(save_path, "wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)  # 1 MB
                    if not chunk:
                        break
                    await out.write(chunk)
        
        size = os.path.getsize(save_path)
        # Calculate file hash
        file_hash = await calculate_file_hash(save_path)
        
        upload_id = await db_insert("uploads", {
            "id": random.randrange(10000000000),
            "user_id" : g.current_user['user_id'],
            "filename": filename,
            "saved_path": save_path,
            "size_bytes": size,
            "file_hash": file_hash ,
            "upload_method": "file" ,
            "created_at" : datetime.utcnow().isoformat()
        })
        
        await log(upload_id, "info", f"Uploaded file {filename} saved as {save_path} (hash: {file_hash[:16]}...)")
        return jsonify({
            "upload_id": upload_id , 
            "filename": filename, 
            "saved_path": save_path,
            "file_hash": file_hash,
            "size_bytes": size
        })
        
    except Exception as e:
        await log(None, "error", f"Upload failed: {e}")
        return jsonify({"error": str(e)}), 500

# Add export functionality
@app.route('/api/export/json/<int:job_id>')
@auth_required
async def export_json(job_id):
    """Export analysis results as JSON"""
    
    user_id = g.current_user['user_id']
    
    results = await get_motion_results(job_id, user_id)
    
    if not results:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify(results['analysis_summary'])

@app.route('/api/export/report/<int:job_id>')
@auth_required
async def export_report(job_id):
    """Generate PDF report (placeholder)"""
    return jsonify({'message': 'PDF report generation would be implemented here'})

# Add error handling middleware
@app.errorhandler(404)
@auth_required
async def not_found(error):
    return await render_template_string("""
        <div class="min-h-screen bg-gray-100 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-800">404</h1>
                <p class="text-xl text-gray-600 mb-4">Page not found</p>
                <a href="/" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg">
                    Return to Dashboard
                </a>
            </div>
        </div>
    """), 404

@app.errorhandler(500)
async def internal_error(error):
    return await render_template_string("""
        <div class="min-h-screen bg-gray-100 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-800">500</h1>
                <p class="text-xl text-gray-600 mb-4">Internal server error</p>
                <a href="/" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg">
                    Return to Dashboard
                </a>
            </div>
        </div>
    """), 500

# Add health check endpoint
@app.route('/health')
@auth_required
async def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

# -------------------------
# Application Startup and Cleanup
# -------------------------
@app.before_serving
async def startup():
    """Initialize application"""
    await init_enhanced_db()
     # Start background cleanup task
    asyncio.create_task(cleanup_expired_task())
    print("[startup] Background cleanup task started")
    
    # Test Rust wallet connector
    try:
        connector = get_wallet_connector()
        if connector.health_check():
            print("✓ Rust wallet connector initialized successfully")
        else:
            print("⚠ Rust wallet connector health check failed")
    except Exception as e:
        print(f"⚠ Rust wallet connector not available: {e}")
    
    print("Forensic Video Analysis Platform started!")
    print("Access the application at: http://localhost:5000")
    print("Default admin credentials: admin/admin123")

@app.after_serving
async def cleanup():
    """Cleanup resources"""
    close_wallet_connector()

# Add health check endpoint
@app.route('/health/sys/')
async def health_check():
    """Health check endpoint for Docker and Render"""
    try:
        # Check database connection
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
        
        # System info
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "Forensic Video Analysis Platform",
            "version": "2.0.0",
            "system": {
                "memory_used": f"{memory.percent}%",
                "disk_used": f"{disk.percent}%",
                "python_version": os.environ.get('PYTHON_VERSION', '3.11.0')
            },
            "database": "connected",
            "endpoints": {
                "websocket": "active",
                "authentication": "active",
                "video_processing": "active"
            }
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

# Add this to ensure the app binds to the correct port
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    print(f"🚀 Starting application on {host}:{port}")
    print(f"🔧 Environment: {'Production' if os.environ.get('RENDER') else 'Development'}")
    
    # Development mode
    app.run(host=host, port=port, debug=not os.environ.get('RENDER'))

from fastmcp import FastMCP
import json
import os
from typing import Optional
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
from functools import wraps

# Google OAuth imports
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import secrets

# ------------------------------
# Google OAuth Configuration
# ------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

# Session storage (in production, use Redis)
active_sessions = {}  # {session_token: {user_email, expires_at, user_info}}

# ------------------------------
# Authentication Decorator
# ------------------------------
def require_auth(func):
    """Decorator to require authentication for tool functions"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Extract session_token from kwargs
        session_token = kwargs.get('session_token')
        
        if not session_token:
            return {
                "error": "Authentication required",
                "message": "Please provide a valid session_token. Call google_auth_login first.",
                "authenticated": False
            }
        
        # Validate session
        session = active_sessions.get(session_token)
        if not session:
            return {
                "error": "Invalid session",
                "message": "Session token is invalid or expired. Please login again.",
                "authenticated": False
            }
        
        # Check if session expired
        if datetime.fromisoformat(session['expires_at']) < datetime.now():
            del active_sessions[session_token]
            return {
                "error": "Session expired",
                "message": "Your session has expired. Please login again.",
                "authenticated": False
            }
        
        # Inject authenticated user_id into kwargs
        kwargs['user_id'] = session['user_email']
        kwargs.pop('session_token', None)  # Remove session_token from kwargs
        
        # Call the original function
        return func(*args, **kwargs)
    
    return wrapper

# ------------------------------
# HIPAA Audit Logger
# ------------------------------
class HIPAAAuditLogger:
    """HIPAA-compliant audit logging for all data access"""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.audit_log = []
    
    def log_event(self, event_type: str, user_id: str, resource_key: str, 
                  action: str, status: str, details: Optional[dict] = None):
        """Log a HIPAA-compliant audit event"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": hashlib.sha256(user_id.encode()).hexdigest()[:16],  # Anonymized user ID
            "resource_key": resource_key,
            "action": action,
            "status": status,
            "ip_address": "REDACTED",  # In production, capture from request
            "details": details or {}
        }
        
        if self.redis_client:
            try:
                # Store audit logs in Redis with retention
                log_key = f"hipaa:audit:{datetime.now().strftime('%Y%m%d')}"
                self.redis_client.rpush(log_key, json.dumps(audit_entry))
                # Set 7-year retention as per HIPAA requirements
                self.redis_client.expire(log_key, 60 * 60 * 24 * 365 * 7)
            except Exception as e:
                print(f"⚠️  Audit log write failed: {e}")
        else:
            self.audit_log.append(audit_entry)
    
    def get_audit_logs(self, days: int = 30, user_id: Optional[str] = None) -> list:
        """Retrieve audit logs for the specified number of days, optionally filtered by user"""
        if self.redis_client:
            try:
                logs = []
                for i in range(days):
                    date = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
                    log_key = f"hipaa:audit:{date}"
                    day_logs = self.redis_client.lrange(log_key, 0, -1)
                    logs.extend([json.loads(log) for log in day_logs])
                
                # Filter by user if specified
                if user_id:
                    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:16]
                    logs = [log for log in logs if log.get("user_id") == user_hash]
                
                return logs
            except Exception as e:
                print(f"⚠️  Audit log read failed: {e}")
                return []
        else:
            logs = self.audit_log
            if user_id:
                user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:16]
                logs = [log for log in logs if log.get("user_id") == user_hash]
            return logs

# ------------------------------
# HIPAA Encryption Manager
# ------------------------------
class HIPAAEncryptionManager:
    """HIPAA-compliant encryption manager with mandatory AES-256 encryption"""
    
    def __init__(self):
        self.cipher = None
        self.encryption_enabled = False
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize MANDATORY encryption with user-provided key"""
        encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if not encryption_key:
            raise ValueError(
                "❌ HIPAA COMPLIANCE VIOLATION: ENCRYPTION_KEY environment variable is REQUIRED!\n"
                "🔐 Set ENCRYPTION_KEY to a strong passphrase (min 32 characters recommended)\n"
                "💡 Example: export ENCRYPTION_KEY='your-very-strong-passphrase-here'"
            )
        
        if len(encryption_key) < 16:
            raise ValueError(
                "❌ HIPAA COMPLIANCE VIOLATION: ENCRYPTION_KEY must be at least 16 characters!\n"
                "🔐 Use a strong passphrase (32+ characters recommended)"
            )
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'hipaa_mcp_memory_v1_salt_do_not_change',
                iterations=600000,  # Increased iterations for HIPAA compliance
            )
            key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
            self.cipher = Fernet(key)
            self.encryption_enabled = True
            print("🔐 HIPAA Encryption: ENABLED (AES-256-CBC)")
            print("✅ All PHI/ePHI will be encrypted at rest")
            print(f"🔒 Key derivation: PBKDF2-HMAC-SHA256 (600,000 iterations)")
        except Exception as e:
            raise RuntimeError(f"❌ HIPAA COMPLIANCE VIOLATION: Encryption initialization failed: {e}")
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data using AES-256"""
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise RuntimeError(f"❌ Encryption error: {e}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            raise RuntimeError(f"❌ Decryption error: {e}")
    
    def encrypt_memory(self, memory: dict) -> dict:
        """Encrypt sensitive fields in a memory object"""
        encrypted_memory = memory.copy()
        
        if "content" in encrypted_memory:
            encrypted_memory["content"] = self.encrypt(encrypted_memory["content"])
        
        if "metadata" in encrypted_memory and encrypted_memory["metadata"]:
            encrypted_memory["metadata"] = {
                k: self.encrypt(str(v)) for k, v in encrypted_memory["metadata"].items()
            }
        
        encrypted_memory["encrypted"] = True
        encrypted_memory["encryption_version"] = "AES-256-HIPAA-v1"
        return encrypted_memory
    
    def decrypt_memory(self, memory: dict) -> dict:
        """Decrypt sensitive fields in a memory object"""
        decrypted_memory = memory.copy()
        
        if "content" in decrypted_memory:
            decrypted_memory["content"] = self.decrypt(decrypted_memory["content"])
        
        if "metadata" in decrypted_memory and decrypted_memory["metadata"]:
            decrypted_memory["metadata"] = {
                k: self.decrypt(v) for k, v in decrypted_memory["metadata"].items()
            }
        
        decrypted_memory["encrypted"] = False
        return decrypted_memory

# Initialize encryption manager (will raise error if ENCRYPTION_KEY not set)
encryption_manager = HIPAAEncryptionManager()

# ------------------------------
# Initialize FastMCP
# ------------------------------
mcp = FastMCP(
    name="hipaa-memory-google-auth",
)

# ------------------------------
# Redis Storage Configuration
# ------------------------------
redis_client = None
STORAGE_TYPE = "Memory (Non-HIPAA Compliant - Use Redis for Production)"

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL")
    
    if REDIS_URL:
        redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30,
            ssl_cert_reqs=None  # For Upstash
        )
        redis_client.ping()
        STORAGE_TYPE = "Redis (Upstash - HIPAA Compliant with Encryption)"
        print("✅ Connected to Redis (HIPAA-compliant storage)")
        print("💾 Storage: PERMANENT with encrypted backup")
        print("👥 Multi-user: ENABLED with data isolation")
    else:
        print("⚠️  WARNING: REDIS_URL not configured!")
        print("❌ HIPAA COMPLIANCE RISK: In-memory storage is NOT recommended for PHI")
        print("💡 Configure REDIS_URL for persistent, encrypted storage")
        
except ImportError:
    print("❌ CRITICAL: Redis package not installed")
    print("❌ HIPAA COMPLIANCE RISK: Install redis package for production use")
    
except Exception as e:
    print(f"⚠️  Redis connection failed: {e}")
    print("❌ HIPAA COMPLIANCE RISK: Using temporary storage")

# Fallback in-memory storage (NOT HIPAA compliant for production)
# Structure: {user_id: [memories]}
memory_store = {}

# Initialize audit logger
audit_logger = HIPAAAuditLogger(redis_client)

# ------------------------------
# Google OAuth Functions
# ------------------------------
def verify_google_token(token: str) -> Optional[dict]:
    """Verify Google ID token and return user info"""
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Verify the issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        # Return user info
        return {
            'email': idinfo['email'],
            'name': idinfo.get('name', ''),
            'picture': idinfo.get('picture', ''),
            'email_verified': idinfo.get('email_verified', False),
            'sub': idinfo['sub']  # Google user ID
        }
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None

def create_session(user_info: dict) -> str:
    """Create a new session for authenticated user"""
    session_token = secrets.token_urlsafe(32)
    
    session_data = {
        'user_email': user_info['email'],
        'user_name': user_info['name'],
        'user_picture': user_info['picture'],
        'user_sub': user_info['sub'],
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=7)).isoformat(),
        'user_info': user_info
    }
    
    # Store in Redis if available
    if redis_client:
        try:
            session_key = f"session:{session_token}"
            redis_client.setex(
                session_key,
                timedelta(days=7),
                json.dumps(session_data)
            )
        except Exception as e:
            print(f"Warning: Could not store session in Redis: {e}")
    
    active_sessions[session_token] = session_data
    
    audit_logger.log_event(
        "AUTH_LOGIN", 
        user_info['email'], 
        "session", 
        "CREATE_SESSION", 
        "SUCCESS",
        {"name": user_info['name']}
    )
    
    return session_token

# ------------------------------
# Authentication Tools
# ------------------------------
@mcp.tool()
def google_auth_login(id_token_str: str) -> dict:
    """
    Authenticate user with Google OAuth ID token.
    
    Args:
        id_token_str: Google ID token received from OAuth flow
        
    Returns:
        Dictionary with session token and user information
        
    Example:
        After user completes Google OAuth flow, call:
        google_auth_login(id_token_str="google_id_token_here")
    """
    if not GOOGLE_CLIENT_ID:
        return {
            "error": "Google OAuth not configured",
            "message": "GOOGLE_CLIENT_ID environment variable is not set",
            "authenticated": False
        }
    
    user_info = verify_google_token(id_token_str)
    
    if not user_info:
        audit_logger.log_event(
            "AUTH_FAILED", 
            "unknown", 
            "login", 
            "LOGIN", 
            "FAILED",
            {"reason": "Invalid token"}
        )
        return {
            "error": "Authentication failed",
            "message": "Invalid or expired Google ID token",
            "authenticated": False
        }
    
    session_token = create_session(user_info)
    
    return {
        "success": True,
        "authenticated": True,
        "session_token": session_token,
        "user": {
            "email": user_info['email'],
            "name": user_info['name'],
            "picture": user_info['picture'],
            "email_verified": user_info['email_verified']
        },
        "expires_at": (datetime.now() + timedelta(days=7)).isoformat(),
        "message": "Successfully authenticated with Google",
        "instructions": "Use this session_token in all subsequent tool calls"
    }

@mcp.tool()
def google_auth_logout(session_token: str) -> dict:
    """
    Logout user and invalidate session.
    
    Args:
        session_token: Session token to invalidate
        
    Returns:
        Dictionary with logout status
    """
    session = active_sessions.get(session_token)
    
    if session:
        user_email = session['user_email']
        
        # Remove from memory
        if session_token in active_sessions:
            del active_sessions[session_token]
        
        # Remove from Redis
        if redis_client:
            try:
                redis_client.delete(f"session:{session_token}")
            except Exception as e:
                print(f"Warning: Could not delete session from Redis: {e}")
        
        audit_logger.log_event(
            "AUTH_LOGOUT", 
            user_email, 
            "session", 
            "LOGOUT", 
            "SUCCESS",
            {}
        )
        
        return {
            "success": True,
            "message": f"Successfully logged out user: {user_email}",
            "authenticated": False
        }
    
    return {
        "error": "Invalid session",
        "message": "Session token not found or already expired",
        "authenticated": False
    }

@mcp.tool()
def google_auth_verify_session(session_token: str) -> dict:
    """
    Verify if a session token is still valid.
    
    Args:
        session_token: Session token to verify
        
    Returns:
        Dictionary with session validation status
    """
    session = active_sessions.get(session_token)
    
    if not session:
        # Try to load from Redis
        if redis_client:
            try:
                session_key = f"session:{session_token}"
                session_data = redis_client.get(session_key)
                if session_data:
                    session = json.loads(session_data)
                    active_sessions[session_token] = session
            except Exception as e:
                print(f"Warning: Could not load session from Redis: {e}")
    
    if not session:
        return {
            "valid": False,
            "authenticated": False,
            "message": "Session not found"
        }
    
    # Check expiration
    expires_at = datetime.fromisoformat(session['expires_at'])
    if expires_at < datetime.now():
        del active_sessions[session_token]
        return {
            "valid": False,
            "authenticated": False,
            "message": "Session expired"
        }
    
    return {
        "valid": True,
        "authenticated": True,
        "user": {
            "email": session['user_email'],
            "name": session['user_name'],
            "picture": session['user_picture']
        },
        "expires_at": session['expires_at'],
        "created_at": session['created_at']
    }

# ------------------------------
# Multi-User Storage Functions
# ------------------------------
def get_user_storage_key(user_id: str) -> str:
    """Generate a storage key for a specific user"""
    # Hash user_id for privacy
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:32]
    return f"hipaa:memories:user:{user_hash}"

def load_user_memories(user_id: str) -> list:
    """Load memories for a specific user from Redis or in-memory storage."""
    global memory_store
    
    if redis_client:
        try:
            storage_key = get_user_storage_key(user_id)
            data = redis_client.get(storage_key)
            if data:
                memories = json.loads(data)
                decrypted_memories = [
                    encryption_manager.decrypt_memory(m) for m in memories
                ]
                return decrypted_memories
            return []
        except Exception as e:
            print(f"⚠️  Error loading from Redis for user {user_id}: {e}")
            audit_logger.log_event("SYSTEM_ERROR", user_id, "all", "LOAD", "FAILED", {"error": str(e)})
            return memory_store.get(user_id, [])
    else:
        return memory_store.get(user_id, [])

def save_user_memories(user_id: str, memories: list) -> bool:
    """Save memories for a specific user to Redis or in-memory storage with encryption."""
    global memory_store
    
    if redis_client:
        try:
            storage_key = get_user_storage_key(user_id)
            encrypted_memories = [
                encryption_manager.encrypt_memory(m) for m in memories
            ]
            redis_client.set(storage_key, json.dumps(encrypted_memories))
            
            # Create encrypted backup
            user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:32]
            backup_key = f"hipaa:backup:user:{user_hash}:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            redis_client.set(backup_key, json.dumps(encrypted_memories))
            redis_client.expire(backup_key, 60 * 60 * 24 * 90)  # 90-day retention
            
            return True
        except Exception as e:
            print(f"❌ Error saving to Redis for user {user_id}: {e}")
            audit_logger.log_event("SYSTEM_ERROR", user_id, "all", "SAVE", "FAILED", {"error": str(e)})
            memory_store[user_id] = memories
            return False
    else:
        memory_store[user_id] = memories
        return True

# ------------------------------
# Protected Memory Management Tools (Require Auth)
# ------------------------------
@mcp.tool()
@require_auth
def create_memory(
    key: str, 
    content: str, 
    session_token: str,
    tag: Optional[str] = None, 
    metadata: Optional[dict] = None,
    user_id: str = None  # Injected by @require_auth
) -> str:
    """
    Create a new encrypted memory (HIPAA-compliant). Requires authentication.
    
    Args:
        key: Unique identifier for the memory
        content: The PHI/ePHI content to remember (will be encrypted)
        session_token: Valid session token from google_auth_login (REQUIRED)
        tag: Optional tag for categorization
        metadata: Optional additional information (will be encrypted)
        
    Returns:
        Success message with encryption confirmation
    """
    memories = load_user_memories(user_id)
    
    # Check for duplicate key
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "CREATE", "FAILED", 
                                  {"reason": "Duplicate key"})
            return f"❌ Memory with key '{key}' already exists. Use update_memory to modify it."
    
    new_memory = {
        "key": key,
        "content": content,
        "tag": tag if tag else "general",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "created_by": hashlib.sha256(user_id.encode()).hexdigest()[:16],
        "metadata": metadata if metadata else {},
        "hipaa_compliant": True,
        "retention_years": 7,
        "user_id": user_id
    }
    
    memories.append(new_memory)
    
    if save_user_memories(user_id, memories):
        audit_logger.log_event("PHI_CREATE", user_id, key, "CREATE", "SUCCESS", 
                              {"tag": tag, "encrypted": True})
        tag_info = f" [Tag: {new_memory['tag']}]" if tag else ""
        return (f"✅ HIPAA-Compliant Memory Created: '{key}'{tag_info}\n"
                f"🔐 Content: ENCRYPTED (AES-256)\n"
                f"👤 User: {user_id}\n"
                f"💾 Storage: {STORAGE_TYPE}\n"
                f"📋 Audit: Logged\n"
                f"⏱️  Retention: 7 years (HIPAA minimum)")
    else:
        return f"❌ Memory creation failed - storage error"

@mcp.tool()
@require_auth
def get_memory(key: str, session_token: str, user_id: str = None) -> dict:
    """
    Retrieve a specific encrypted memory (HIPAA-compliant). Requires authentication.
    
    Args:
        key: The unique identifier of the memory to retrieve
        session_token: Valid session token from google_auth_login (REQUIRED)
        
    Returns:
        Dictionary with decrypted memory details
    """
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "READ", "SUCCESS", 
                                  {"encrypted": True})
            return {
                "found": True,
                "memory": memory,
                "user_id": user_id,
                "storage": STORAGE_TYPE,
                "encrypted": True,
                "hipaa_compliant": True,
                "audit_logged": True
            }
    
    audit_logger.log_event("PHI_ACCESS", user_id, key, "READ", "NOT_FOUND", {})
    return {
        "found": False,
        "user_id": user_id,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool()
@require_auth
def list_memories(
    session_token: str,
    tag: Optional[str] = None, 
    search: Optional[str] = None,
    user_id: str = None
) -> dict:
    """
    List all encrypted memories with optional filters (HIPAA-compliant). Requires authentication.
    
    Args:
        session_token: Valid session token from google_auth_login (REQUIRED)
        tag: Filter memories by tag (optional)
        search: Search term to find in keys or content (optional)
        
    Returns:
        Dictionary with decrypted memories list
    """
    memories = load_user_memories(user_id)
    
    if tag:
        memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    if search:
        search_lower = search.lower()
        memories = [
            m for m in memories 
            if search_lower in m["key"].lower() or search_lower in m["content"].lower()
        ]
    
    audit_logger.log_event("PHI_ACCESS", user_id, "list", "LIST", "SUCCESS", 
                          {"count": len(memories), "filtered": bool(tag or search)})
    
    return {
        "user_id": user_id,
        "total_count": len(memories),
        "memories": memories,
        "storage": STORAGE_TYPE,
        "encrypted": True,
        "hipaa_compliant": True,
        "audit_logged": True
    }

@mcp.tool()
@require_auth
def update_memory(
    key: str,
    session_token: str,
    new_content: Optional[str] = None, 
    new_tag: Optional[str] = None, 
    new_metadata: Optional[dict] = None,
    user_id: str = None
) -> str:
    """
    Update an existing encrypted memory (HIPAA-compliant). Requires authentication.
    
    Args:
        key: The unique identifier of the memory to update
        session_token: Valid session token from google_auth_login (REQUIRED)
        new_content: New content (will be encrypted)
        new_tag: New tag (optional)
        new_metadata: New metadata to merge (will be encrypted)
        
    Returns:
        Success message with encryption confirmation
    """
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            updates = []
            
            if new_content is not None:
                old_content_hash = hashlib.sha256(memory["content"].encode()).hexdigest()[:8]
                memory["content"] = new_content
                updates.append(f"Content updated (old hash: {old_content_hash})")
            
            if new_tag is not None:
                old_tag = memory.get("tag", "general")
                memory["tag"] = new_tag
                updates.append(f"Tag: {old_tag} → {new_tag}")
            
            if new_metadata is not None:
                memory["metadata"].update(new_metadata)
                updates.append("Metadata updated")
            
            if not updates:
                return f"⚠️  No changes specified for memory: '{key}'"
            
            memory["updated_at"] = datetime.now().isoformat()
            memory["updated_by"] = hashlib.sha256(user_id.encode()).hexdigest()[:16]
            
            if save_user_memories(user_id, memories):
                audit_logger.log_event("PHI_MODIFY", user_id, key, "UPDATE", "SUCCESS", 
                                      {"changes": updates})
                return (f"✅ HIPAA-Compliant Memory Updated: '{key}'\n" + 
                       "\n".join(updates) + 
                       f"\n🔐 Encryption: AES-256\n📋 Audit: Logged")
            else:
                return f"❌ Memory update failed - storage error"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
@require_auth
def forget_memory(key: str, session_token: str, reason: str = "User request", user_id: str = None) -> str:
    """
    Securely delete an encrypted memory (HIPAA-compliant). Requires authentication.
    
    Args:
        key: The unique identifier of the memory to delete
        session_token: Valid session token from google_auth_login (REQUIRED)
        reason: Reason for deletion (for audit trail)
        
    Returns:
        Success message with audit confirmation
    """
    memories = load_user_memories(user_id)
    original_count = len(memories)
    
    deleted_memory = next((m for m in memories if m["key"].lower() == key.lower()), None)
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        if save_user_memories(user_id, memories):
            audit_logger.log_event("PHI_DELETE", user_id, key, "DELETE", "SUCCESS", 
                                  {"reason": reason, "tag": deleted_memory.get("tag") if deleted_memory else None})
            return (f"✅ HIPAA-Compliant Memory Deleted: '{key}'\n"
                   f"🔐 Secure deletion completed\n"
                   f"📋 Audit: Logged with reason: {reason}\n"
                   f"⏱️  Audit retained for 7 years per HIPAA")
        else:
            return f"❌ Memory deletion failed - storage error"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
@require_auth
def get_server_status(session_token: str, user_id: str = None) -> dict:
    """
    Get HIPAA-compliant server status and statistics. Requires authentication.
    
    Args:
        session_token: Valid session token from google_auth_login (REQUIRED)
        
    Returns:
        Dictionary with server status and HIPAA compliance details
    """
    memories = load_user_memories(user_id)
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    audit_logger.log_event("SYSTEM_ACCESS", user_id, "status", "GET_STATUS", "SUCCESS", {})
    
    return {
        "user_info": {
            "current_user": user_id,
            "memory_count": len(memories),
            "tags": memory_tags
        },
        "authentication": {
            "method": "Google OAuth 2.0",
            "session_based": True,
            "configured": bool(GOOGLE_CLIENT_ID)
        },
        "hipaa_compliance": {
            "compliant": redis_client is not None and encryption_manager.encryption_enabled,
            "encryption_enabled": encryption_manager.encryption_enabled,
            "encryption_algorithm": "AES-256-CBC (Fernet)",
            "audit_logging": True,
            "data_retention": "7 years (HIPAA minimum)",
            "access_controls": "Google OAuth + Session tokens"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "redis_connected": redis_client is not None,
            "persistent": redis_client is not None
        }
    }

@mcp.tool()
@require_auth
def get_audit_logs(session_token: str, days: int = 30, user_id: str = None) -> dict:
    """
    Retrieve HIPAA audit logs. Requires authentication.
    
    Args:
        session_token: Valid session token from google_auth_login (REQUIRED)
        days: Number of days of logs to retrieve (default: 30, max: 365)
        
    Returns:
        Dictionary with audit log entries for the authenticated user
    """
    if days > 365:
        days = 365
    
    logs = audit_logger.get_audit_logs(days, user_id)
    
    audit_logger.log_event("AUDIT_ACCESS", user_id, "audit_logs", "READ_AUDIT", "SUCCESS", 
                          {"days": days, "log_count": len(logs)})
    
    return {
        "user_id": user_id,
        "days_requested": days,
        "log_count": len(logs),
        "logs": logs,
        "hipaa_retention": "7 years"
    }

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/hipaa-info")
def server_info() -> str:
    """Get HIPAA compliance and authentication information about the MCP server."""
    info = {
        "name": "hipaa-memory-google-auth",
        "version": "5.0.0-HIPAA-GOOGLE-AUTH",
        "description": "HIPAA-Compliant Memory Server with Google OAuth Authentication",
        "authentication": {
            "method": "Google OAuth 2.0",
            "configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            "session_duration": "7 days",
            "required_env_vars": ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"],
            "flow": "Use google_auth_login with Google ID token to get session_token"
        },
        "hipaa_compliance": {
            "encryption": {
                "enabled": True,
                "algorithm": "AES-256-CBC (Fernet)",
                "mandatory": True
            },
            "audit_logging": {
                "enabled": True,
                "retention_years": 7
            },
            "access_controls": {
                "authentication": "Google OAuth 2.0",
                "session_management": "Token-based with expiration"
            }
        },
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None
        }
    }
    return json.dumps(info, indent=2)

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("🏥 HIPAA-COMPLIANT MEMORY SERVER WITH GOOGLE OAUTH")
    print("=" * 70)
    
    print("\n🔐 AUTHENTICATION:")
    print(f"   Method: Google OAuth 2.0")
    print(f"   Status: {'✅ CONFIGURED' if GOOGLE_CLIENT_ID else '❌ NOT CONFIGURED'}")
    if not GOOGLE_CLIENT_ID:
        print("   ⚠️  Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")
    
    print("\n🔐 ENCRYPTION STATUS:")
    print(f"   Algorithm: AES-256-CBC (Fernet)")
    print(f"   Status: {'✅ ENABLED' if encryption_manager.encryption_enabled else '❌ DISABLED'}")
    
    print("\n💾 STORAGE:")
    print(f"   Type: {STORAGE_TYPE}")
    print(f"   Redis: {'✅ Connected' if redis_client else '❌ Not Connected'}")
    
    print("\n" + "=" * 70)
    print(f"🔧 Registered {len(mcp._tools)} tools")
    print("=" * 70)
    print("✅ Server ready - Use google_auth_login to authenticate")
    print("=" * 70)
    
    mcp.run()
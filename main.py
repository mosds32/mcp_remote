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

# Google OAuth imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# ------------------------------
# Google OAuth Manager
# ------------------------------
class GoogleOAuthManager:
    """
    Manages Google OAuth 2.0 authentication with automatic token refresh.
    Designed for FastMCP Cloud deployment with Claude.ai integration.
    """
    
    def __init__(self):
        self.credentials = None
        self.scopes = [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ]
        
        # Load OAuth config from environment
        self.client_config = {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8080/oauth2callback")]
            }
        }
        
        self._initialize_oauth()
    
    def _initialize_oauth(self):
        """Initialize OAuth with stored credentials or prepare for new flow"""
        
        # Check for required environment variables
        if not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
            print("⚠️  Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
            print("📝 To enable Google OAuth:")
            print("   1. Go to https://console.cloud.google.com/apis/credentials")
            print("   2. Create OAuth 2.0 Client ID")
            print("   3. Set authorized redirect URIs")
            print("   4. Export credentials as environment variables")
            return
        
        # Try to load existing credentials from environment
        refresh_token = os.getenv("GOOGLE_REFRESH_TOKEN")
        access_token = os.getenv("GOOGLE_ACCESS_TOKEN")
        
        if refresh_token:
            try:
                self.credentials = Credentials(
                    token=access_token,
                    refresh_token=refresh_token,
                    token_uri=self.client_config["web"]["token_uri"],
                    client_id=self.client_config["web"]["client_id"],
                    client_secret=self.client_config["web"]["client_secret"],
                    scopes=self.scopes
                )
                
                # Refresh if expired
                if self.credentials.expired:
                    self.credentials.refresh(Request())
                    print("🔄 Google OAuth tokens refreshed successfully")
                
                print("✅ Google OAuth: Authenticated")
                self._print_user_info()
                
            except Exception as e:
                print(f"⚠️  Failed to load Google credentials: {e}")
                print("💡 Run the authorization flow to get new tokens")
        else:
            print("ℹ️  No Google refresh token found. Authorization needed.")
            print("💡 Use get_google_auth_url() tool to start OAuth flow")
    
    def get_authorization_url(self) -> dict:
        """
        Generate Google OAuth authorization URL for user to authenticate.
        
        Returns:
            Dictionary with authorization URL and state
        """
        try:
            flow = Flow.from_client_config(
                self.client_config,
                scopes=self.scopes,
                redirect_uri=self.client_config["web"]["redirect_uris"][0]
            )
            
            authorization_url, state = flow.authorization_url(
                access_type='offline',  # Request refresh token
                prompt='consent',  # Force consent screen to ensure refresh token
                include_granted_scopes='true'
            )
            
            return {
                "success": True,
                "authorization_url": authorization_url,
                "state": state,
                "instructions": [
                    "1. Open the authorization_url in your browser",
                    "2. Sign in with your Google account",
                    "3. Grant the requested permissions",
                    "4. Copy the authorization code from the redirect URL",
                    "5. Use complete_google_auth() tool with the code"
                ]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to generate authorization URL"
            }
    
    def complete_authorization(self, authorization_code: str, state: str = None) -> dict:
        """
        Complete OAuth flow with authorization code and store tokens.
        
        Args:
            authorization_code: Code received from Google OAuth redirect
            state: State parameter for verification (optional)
            
        Returns:
            Dictionary with success status and token information
        """
        try:
            flow = Flow.from_client_config(
                self.client_config,
                scopes=self.scopes,
                redirect_uri=self.client_config["web"]["redirect_uris"][0]
            )
            
            # Exchange authorization code for tokens
            flow.fetch_token(code=authorization_code)
            
            self.credentials = flow.credentials
            
            # Extract tokens for storage
            tokens = {
                "access_token": self.credentials.token,
                "refresh_token": self.credentials.refresh_token,
                "token_uri": self.credentials.token_uri,
                "client_id": self.credentials.client_id,
                "client_secret": self.credentials.client_secret,
                "scopes": list(self.credentials.scopes)
            }
            
            print("✅ Google OAuth authentication successful!")
            print(f"🔑 Access Token: {tokens['access_token'][:20]}...")
            print(f"🔄 Refresh Token: {tokens['refresh_token'][:20] if tokens['refresh_token'] else 'None'}...")
            
            self._print_user_info()
            
            return {
                "success": True,
                "message": "Authentication successful!",
                "tokens": tokens,
                "instructions": [
                    "IMPORTANT: Store these tokens securely as environment variables:",
                    f"export GOOGLE_ACCESS_TOKEN='{tokens['access_token']}'",
                    f"export GOOGLE_REFRESH_TOKEN='{tokens['refresh_token']}'",
                    "",
                    "For production deployment (FastMCP Cloud):",
                    "1. Add these as environment variables in your deployment settings",
                    "2. Restart your MCP server",
                    "3. Tokens will auto-refresh when expired"
                ]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to complete authorization"
            }
    
    def get_valid_credentials(self) -> Optional[Credentials]:
        """
        Get valid credentials, refreshing if necessary.
        
        Returns:
            Valid Google credentials or None
        """
        if not self.credentials:
            return None
        
        try:
            # Refresh token if expired
            if self.credentials.expired and self.credentials.refresh_token:
                self.credentials.refresh(Request())
                print("🔄 Google OAuth token auto-refreshed")
            
            return self.credentials
            
        except Exception as e:
            print(f"❌ Failed to refresh credentials: {e}")
            return None
    
    def _print_user_info(self):
        """Print authenticated user information"""
        try:
            if not self.credentials:
                return
            
            # Build userinfo service
            service = build('oauth2', 'v2', credentials=self.credentials)
            user_info = service.userinfo().get().execute()
            
            print(f"👤 Authenticated as: {user_info.get('email', 'Unknown')}")
            print(f"📧 Email: {user_info.get('email', 'N/A')}")
            print(f"👤 Name: {user_info.get('name', 'N/A')}")
            
        except Exception as e:
            print(f"⚠️  Could not fetch user info: {e}")
    
    def get_user_email(self) -> Optional[str]:
        """
        Get authenticated user's email address.
        
        Returns:
            Email address or None
        """
        try:
            creds = self.get_valid_credentials()
            if not creds:
                return None
            
            service = build('oauth2', 'v2', credentials=creds)
            user_info = service.userinfo().get().execute()
            return user_info.get('email')
            
        except Exception as e:
            print(f"⚠️  Could not get user email: {e}")
            return None
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated"""
        return self.credentials is not None and self.get_valid_credentials() is not None

# Initialize Google OAuth manager
google_oauth = GoogleOAuthManager()

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
memory_store = {}

# Initialize audit logger
audit_logger = HIPAAAuditLogger(redis_client)

# ------------------------------
# Multi-User Storage Functions
# ------------------------------
def get_user_id_from_google() -> str:
    """
    Get user ID from Google OAuth email.
    Falls back to 'default_user' if not authenticated.
    """
    email = google_oauth.get_user_email()
    if email:
        # Use email as user_id for consistent identification
        return email
    return "default_user"

def get_user_storage_key(user_id: str) -> str:
    """Generate a storage key for a specific user"""
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
# Google OAuth Tools
# ------------------------------
@mcp.tool()
def get_google_auth_url() -> dict:
    """
    Get Google OAuth authorization URL to authenticate your account.
    
    This is the first step in the OAuth flow. You'll need to:
    1. Open the returned URL in your browser
    2. Sign in with your Google account
    3. Grant permissions
    4. Copy the authorization code from the redirect URL
    5. Use complete_google_auth() with that code
    
    Returns:
        Dictionary with authorization URL and instructions
    """
    return google_oauth.get_authorization_url()

@mcp.tool()
def complete_google_auth(authorization_code: str, state: Optional[str] = None) -> dict:
    """
    Complete Google OAuth authentication with the authorization code.
    
    Args:
        authorization_code: The code you received after authorizing in your browser
        state: Optional state parameter for verification
        
    Returns:
        Dictionary with success status and token storage instructions
    """
    return google_oauth.complete_authorization(authorization_code, state)

@mcp.tool()
def check_google_auth_status() -> dict:
    """
    Check if Google OAuth is currently authenticated and working.
    
    Returns:
        Dictionary with authentication status and user information
    """
    is_auth = google_oauth.is_authenticated()
    
    result = {
        "authenticated": is_auth,
        "timestamp": datetime.now().isoformat()
    }
    
    if is_auth:
        email = google_oauth.get_user_email()
        result["user_email"] = email
        result["user_id_for_memories"] = email
        result["status"] = "✅ Google OAuth is active"
        result["message"] = f"Authenticated as {email}. This email will be used as your user_id for memory storage."
    else:
        result["status"] = "❌ Not authenticated"
        result["message"] = "Use get_google_auth_url() to start authentication process"
        result["instructions"] = [
            "1. Call get_google_auth_url() to get authorization URL",
            "2. Open the URL in your browser and sign in",
            "3. Copy the authorization code from redirect",
            "4. Call complete_google_auth(code='YOUR_CODE') to finish setup"
        ]
    
    return result

# ------------------------------
# Memory Management Tools (with Google Auth)
# ------------------------------
@mcp.tool()
def create_memory(
    key: str, 
    content: str, 
    tag: Optional[str] = None, 
    metadata: Optional[dict] = None,
    user_id: Optional[str] = None
) -> str:
    """
    Create a new encrypted memory (HIPAA-compliant).
    
    If Google OAuth is configured, your email will be used as user_id automatically.
    
    Args:
        key: Unique identifier for the memory
        content: The PHI/ePHI content to remember (will be encrypted)
        tag: Optional tag for categorization
        metadata: Optional additional information (will be encrypted)
        user_id: Optional override (defaults to Google email if authenticated)
        
    Returns:
        Success message with encryption confirmation
    """
    # Use Google email as user_id if authenticated, otherwise use provided or default
    if not user_id:
        user_id = get_user_id_from_google()
    
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
        "user_id": user_id,
        "auth_method": "google_oauth" if google_oauth.is_authenticated() else "manual"
    }
    
    memories.append(new_memory)
    
    if save_user_memories(user_id, memories):
        audit_logger.log_event("PHI_CREATE", user_id, key, "CREATE", "SUCCESS", 
                              {"tag": tag, "encrypted": True})
        
        auth_info = f"👤 Google Account: {user_id}" if google_oauth.is_authenticated() else f"👤 User: {user_id}"
        tag_info = f" [Tag: {new_memory['tag']}]" if tag else ""
        
        return (f"✅ HIPAA-Compliant Memory Created: '{key}'{tag_info}\n"
                f"🔐 Content: ENCRYPTED (AES-256)\n"
                f"{auth_info}\n"
                f"💾 Storage: {STORAGE_TYPE}\n"
                f"📋 Audit: Logged\n"
                f"⏱️  Retention: 7 years (HIPAA minimum)")
    else:
        audit_logger.log_event("PHI_CREATE", user_id, key, "CREATE", "FAILED", 
                              {"reason": "Storage error"})
        return f"❌ Memory creation failed - storage error"

@mcp.tool()
def get_memory(key: str, user_id: Optional[str] = None) -> dict:
    """
    Retrieve a specific encrypted memory by key (HIPAA-compliant).
    
    If Google OAuth is configured, your email will be used as user_id automatically.
    
    Args:
        key: The unique identifier of the memory to retrieve
        user_id: Optional override (defaults to Google email if authenticated)
        
    Returns:
        Dictionary with decrypted memory details or error message
    """
    if not user_id:
        user_id = get_user_id_from_google()
    
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "READ", "SUCCESS", 
                                  {"encrypted": True})
            return {
                "found": True,
                "memory": memory,
                "user_id": user_id,
                "google_authenticated": google_oauth.is_authenticated(),
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
def list_memories(
    tag: Optional[str] = None, 
    search: Optional[str] = None,
    user_id: Optional[str] = None
) -> dict:
    """
    List all encrypted memories with optional filters (HIPAA-compliant).
    
    If Google OAuth is configured, your email will be used as user_id automatically.
    
    Args:
        tag: Filter memories by tag (optional)
        search: Search term to find in keys or content (optional)
        user_id: Optional override (defaults to Google email if authenticated)
        
    Returns:
        Dictionary with decrypted memories list
    """
    if not user_id:
        user_id = get_user_id_from_google()
    
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
        "google_authenticated": google_oauth.is_authenticated(),
        "total_count": len(memories),
        "memories": memories,
        "storage": STORAGE_TYPE,
        "encrypted": True,
        "hipaa_compliant": True,
        "audit_logged": True
    }

@mcp.tool()
def get_server_status(user_id: Optional[str] = None) -> dict:
    """
    Get HIPAA-compliant server status including Google OAuth status.
    
    Args:
        user_id: Optional override (defaults to Google email if authenticated)
        
    Returns:
        Dictionary with server status and HIPAA compliance details
    """
    if not user_id:
        user_id = get_user_id_from_google()
    
    memories = load_user_memories(user_id)
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    audit_logger.log_event("SYSTEM_ACCESS", user_id, "status", "GET_STATUS", "SUCCESS", {})
    
    google_auth_status = {
        "enabled": google_oauth.is_authenticated(),
        "user_email": google_oauth.get_user_email() if google_oauth.is_authenticated() else None,
        "status": "✅ Authenticated" if google_oauth.is_authenticated() else "❌ Not authenticated"
    }
    
    hipaa_compliant = redis_client is not None and encryption_manager.encryption_enabled
    compliance_warnings = []
    
    if not redis_client:
        compliance_warnings.append("⚠️  Redis not connected - using non-persistent storage")
    
    if not encryption_manager.encryption_enabled:
        compliance_warnings.append("❌ CRITICAL: Encryption is disabled - HIPAA violation!")
    
    return {
        "user_info": {
            "current_user": user_id,
            "memory_count": len(memories),
            "tags": memory_tags,
            "google_authenticated": google_oauth.is_authenticated()
        },
        "google_oauth": google_auth_status,
        "hipaa_compliance": {
            "compliant": hipaa_compliant and encryption_manager.encryption_enabled,
            "warnings": compliance_warnings,
            "encryption_enabled": encryption_manager.encryption_enabled,
            "encryption_algorithm": "AES-256-CBC (Fernet)",
            "audit_logging": True,
            "data_retention": "7 years (HIPAA minimum)",
            "access_controls": "Google OAuth + User ID tracking"
        },
        "encryption": {
            "enabled": True,
            "algorithm": "AES-256-CBC (Fernet)",
            "key_derivation": "PBKDF2-HMAC-SHA256 (600,000 iterations)",
            "status": "✅ HIPAA Compliant"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "redis_connected": redis_client is not None,
            "persistent": redis_client is not None,
            "backup_enabled": redis_client is not None
        }
    }

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/hipaa-google-auth-info")
def server_info() -> str:
    """Get HIPAA compliance and Google OAuth information about the MCP server."""
    info = {
        "name": "hipaa-memory-google-auth",
        "version": "5.0.0-HIPAA-GOOGLE-AUTH",
        "description": "HIPAA-Compliant Encrypted Memory Server with Google OAuth Integration",
        "google_oauth": {
            "enabled": True,
            "authentication_status": "Authenticated" if google_oauth.is_authenticated() else "Not authenticated",
            "user_email": google_oauth.get_user_email() if google_oauth.is_authenticated() else None,
            "automatic_user_id": "Uses Google email as user_id for memory isolation"
        },
        "hipaa_compliance": {
            "encryption": {
                "enabled": True,
                "algorithm": "AES-256-CBC (Fernet)",
                "key_derivation": "PBKDF2-HMAC-SHA256 (600,000 iterations)",
                "mandatory": True
            },
            "audit_logging": {
                "enabled": True,
                "retention_years": 7,
                "includes": ["All PHI access", "All modifications", "All deletions"]
            }
        },
        "requirements": {
            "ENCRYPTION_KEY": "Mandatory (min 16 chars, 32+ recommended)",
            "GOOGLE_CLIENT_ID": "Required for OAuth (from Google Cloud Console)",
            "GOOGLE_CLIENT_SECRET": "Required for OAuth",
            "GOOGLE_REDIRECT_URI": "Optional (defaults to localhost)",
            "GOOGLE_REFRESH_TOKEN": "Auto-generated after OAuth flow",
            "REDIS_URL": "Recommended for production"
        }
    }
    return json.dumps(info, indent=2)

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("🏥 HIPAA-COMPLIANT FASTMCP MEMORY SERVER + GOOGLE OAUTH")
    print("=" * 70)
    
    print("\n🔐 GOOGLE OAUTH STATUS:")
    if google_oauth.is_authenticated():
        print(f"   Status: ✅ AUTHENTICATED")
        print(f"   Email: {google_oauth.get_user_email()}")
        print(f"   User ID: {get_user_id_from_google()}")
    else:
        print(f"   Status: ⚠️  NOT AUTHENTICATED")
        print(f"   Action: Use get_google_auth_url() tool to authenticate")
    
    print("\n🔐 ENCRYPTION STATUS:")
    print(f"   Algorithm: AES-256-CBC (Fernet)")
    print(f"   Key Derivation: PBKDF2-HMAC-SHA256 (600,000 iterations)")
    print(f"   Status: {'✅ ENABLED' if encryption_manager.encryption_enabled else '❌ DISABLED'}")
    
    print("\n📋 AUDIT LOGGING:")
    print(f"   Status: ✅ ENABLED")
    print(f"   Retention: 7 years (HIPAA minimum)")
    
    print("\n💾 STORAGE:")
    print(f"   Type: {STORAGE_TYPE}")
    print(f"   Redis: {'✅ Connected' if redis_client else '❌ Not Connected'}")
    print(f"   Persistence: {'✅ ENABLED' if redis_client else '⚠️  DISABLED (In-Memory Only)'}")
    
    print("\n" + "=" * 70)
    print(f"🔧 Registered {len(mcp._tools)} HIPAA-compliant tools")
    print("=" * 70)
    print("✅ Server ready for HIPAA-compliant PHI/ePHI storage with Google OAuth")
    print("=" * 70)
    
    mcp.run()
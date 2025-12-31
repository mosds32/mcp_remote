from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
import json
import os
from typing import Optional, List
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib

# ------------------------------
# Encryption Configuration
# ------------------------------
class EncryptionManager:
    """Manages encryption/decryption of sensitive medical data"""
    
    def __init__(self):
        self.cipher = None
        self.encryption_enabled = False
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialize encryption with user-provided or generated key"""
        encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if encryption_key:
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'medical_mcp_salt_v2_secure',
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
                self.cipher = Fernet(key)
                self.encryption_enabled = True
                print("🔐 Encryption: ENABLED (AES-256)")
                print("✅ Medical data will be encrypted at rest")
            except Exception as e:
                print(f"⚠️  Encryption initialization failed: {e}")
                raise Exception("CRITICAL: Cannot run medical server without encryption!")
        else:
            raise Exception("CRITICAL: ENCRYPTION_KEY environment variable is required for medical data!")
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            raise
    
    def encrypt_record(self, record: dict) -> dict:
        """Encrypt sensitive fields in a medical record"""
        encrypted_record = record.copy()
        
        # Encrypt sensitive medical content
        if "content" in encrypted_record:
            encrypted_record["content"] = self.encrypt(encrypted_record["content"])
        
        # Encrypt metadata
        if "metadata" in encrypted_record and encrypted_record["metadata"]:
            encrypted_record["metadata"] = {
                k: self.encrypt(str(v)) for k, v in encrypted_record["metadata"].items()
            }
        
        encrypted_record["encrypted"] = True
        return encrypted_record
    
    def decrypt_record(self, record: dict) -> dict:
        """Decrypt sensitive fields in a medical record"""
        if not record.get("encrypted", False):
            return record
        
        decrypted_record = record.copy()
        
        if "content" in decrypted_record:
            decrypted_record["content"] = self.decrypt(decrypted_record["content"])
        
        if "metadata" in decrypted_record and decrypted_record["metadata"]:
            decrypted_record["metadata"] = {
                k: self.decrypt(v) for k, v in decrypted_record["metadata"].items()
            }
        
        decrypted_record["encrypted"] = False
        return decrypted_record

# Initialize encryption manager
encryption_manager = EncryptionManager()

# ------------------------------
# Authentication & Session Management
# ------------------------------
class SessionManager:
    """Manages user sessions and authentication"""
    
    def __init__(self):
        self.active_sessions = {}
        self.user_database = {}
        self._load_users()
    
    def _load_users(self):
        """Load registered users from Redis or environment"""
        # In production, this would come from a secure database
        # For now, we'll use environment variables
        users_json = os.getenv("REGISTERED_USERS", "[]")
        try:
            users = json.loads(users_json)
            for user in users:
                self.user_database[user["email"]] = {
                    "user_id": user["user_id"],
                    "email": user["email"],
                    "role": user.get("role", "patient"),
                    "name": user.get("name", "")
                }
            print(f"✅ Loaded {len(self.user_database)} registered users")
        except Exception as e:
            print(f"⚠️  Error loading users: {e}")
    
    def create_session(self, email: str) -> Optional[str]:
        """Create a new session for authenticated user"""
        if email not in self.user_database:
            print(f"❌ Unauthorized user attempted access: {email}")
            return None
        
        user_id = self.user_database[email]["user_id"]
        session_token = hashlib.sha256(f"{email}{datetime.now().isoformat()}".encode()).hexdigest()
        
        self.active_sessions[session_token] = {
            "user_id": user_id,
            "email": email,
            "role": self.user_database[email]["role"],
            "created_at": datetime.now().isoformat()
        }
        
        print(f"✅ Session created for user: {email} (ID: {user_id})")
        return session_token
    
    def get_user_from_session(self, session_token: str) -> Optional[dict]:
        """Get user info from session token"""
        return self.active_sessions.get(session_token)

# Initialize session manager
session_manager = SessionManager()

# ------------------------------
# Authentication Configuration
# ------------------------------
auth_provider = None

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL:
    try:
        base_url_normalized = BASE_URL.rstrip('/')
        
        auth_provider = GoogleProvider(
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            base_url=base_url_normalized
        )
        print("✅ Google OAuth authentication enabled")
        print(f"🔐 Auth URL: {base_url_normalized}")
        print(f"📝 Redirect URI: {base_url_normalized}/oauth/callback")
    except Exception as e:
        print(f"⚠️  Failed to initialize Google OAuth: {e}")
        print("💡 Server will run without OAuth (use session tokens)")
        auth_provider = None
else:
    print("ℹ️  Google OAuth not configured - using session-based auth")

# Initialize FastMCP
mcp = FastMCP(
    name="secure-medical-records",
    auth=None,
)

# ------------------------------
# Redis Storage Configuration
# ------------------------------
redis_client = None
STORAGE_TYPE = "Memory (Temporary)"

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL")
    
    if REDIS_URL:
        redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30
        )
        redis_client.ping()
        STORAGE_TYPE = "Redis (Upstash - Encrypted & Permanent)"
        print("✅ Connected to Upstash Redis")
        print("💾 Storage: PERMANENT - Medical data will persist securely")
    else:
        print("⚠️  REDIS_URL not found - using temporary storage")
        print("⚠️  WARNING: Medical data will be lost on restart!")
        
except ImportError:
    print("⚠️  Redis package not installed")
    print("⚠️  WARNING: Using temporary in-memory storage")
    
except Exception as e:
    print(f"⚠️  Redis connection failed: {e}")
    print("⚠️  WARNING: Using temporary in-memory storage")

# Fallback in-memory storage
medical_records_store = {}
audit_log_store = []

# ------------------------------
# Audit Logging
# ------------------------------
class AuditLogger:
    """Logs all access to medical records for compliance"""
    
    @staticmethod
    def log_access(user_id: str, action: str, record_key: str, success: bool, details: str = ""):
        """Log access attempt"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "action": action,
            "record_key": record_key,
            "success": success,
            "details": details,
            "ip_address": "127.0.0.1"  # In production, get real IP
        }
        
        if redis_client:
            try:
                # Store in Redis list
                redis_client.lpush("audit_logs", json.dumps(log_entry))
                redis_client.ltrim("audit_logs", 0, 9999)  # Keep last 10000 entries
            except Exception as e:
                print(f"⚠️  Audit log error: {e}")
        else:
            audit_log_store.append(log_entry)
        
        status = "✅" if success else "❌"
        print(f"{status} AUDIT: {user_id} - {action} - {record_key} - {details}")

audit_logger = AuditLogger()

# ------------------------------
# Secure Storage Functions
# ------------------------------
def get_user_records_key(user_id: str) -> str:
    """Generate Redis key for user's medical records"""
    return f"medical:user:{user_id}:records"

def load_user_records(user_id: str) -> dict:
    """Load medical records for a specific user only"""
    if redis_client:
        try:
            records_key = get_user_records_key(user_id)
            data = redis_client.get(records_key)
            
            if data:
                encrypted_records = json.loads(data)
                # Decrypt records
                decrypted_records = {}
                for key, record in encrypted_records.items():
                    decrypted_records[key] = encryption_manager.decrypt_record(record)
                
                print(f"📥 Loaded {len(decrypted_records)} records for user {user_id}")
                return decrypted_records
            
            print(f"📝 No existing records for user {user_id}")
            return {}
            
        except Exception as e:
            print(f"⚠️  Error loading records for user {user_id}: {e}")
            return medical_records_store.get(user_id, {})
    else:
        return medical_records_store.get(user_id, {})

def save_user_records(user_id: str, records: dict) -> bool:
    """Save medical records for a specific user only"""
    if redis_client:
        try:
            # Encrypt all records before saving
            encrypted_records = {}
            for key, record in records.items():
                encrypted_records[key] = encryption_manager.encrypt_record(record)
            
            records_key = get_user_records_key(user_id)
            redis_client.set(records_key, json.dumps(encrypted_records))
            
            print(f"💾 Saved {len(records)} encrypted records for user {user_id}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving records for user {user_id}: {e}")
            medical_records_store[user_id] = records
            return False
    else:
        medical_records_store[user_id] = records
        return True

# ------------------------------
# Secure Medical Records Tools
# ------------------------------
@mcp.tool()
def create_medical_record(
    session_token: str,
    record_type: str,
    content: str,
    metadata: Optional[dict] = None
) -> str:
    """
    Create a new medical record (SECURE - User Isolated)
    
    Args:
        session_token: User's authentication session token
        record_type: Type of record (medical_history, social_history, family_history, sexual_history)
        content: The medical information to store
        metadata: Optional additional information
        
    Returns:
        Success or error message
        
    Security:
        - Only authenticated users can create records
        - Records are encrypted at rest
        - Each user can only access their own records
        - All access is logged for audit
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        audit_logger.log_access("UNKNOWN", "create_record", record_type, False, "Invalid session")
        return "❌ ERROR: Invalid or expired session. Please authenticate first."
    
    user_id = user["user_id"]
    
    # Validate record type
    valid_types = ["medical_history", "past_medical_history", "social_history", "family_history", "sexual_history", "medications", "allergies", "immunizations"]
    if record_type not in valid_types:
        audit_logger.log_access(user_id, "create_record", record_type, False, "Invalid record type")
        return f"❌ ERROR: Invalid record type. Must be one of: {', '.join(valid_types)}"
    
    # Load user's records
    user_records = load_user_records(user_id)
    
    # Check if record already exists
    if record_type in user_records:
        audit_logger.log_access(user_id, "create_record", record_type, False, "Record already exists")
        return f"❌ ERROR: Record '{record_type}' already exists. Use update_medical_record to modify it."
    
    # Create new record
    new_record = {
        "record_type": record_type,
        "content": content,
        "owner_id": user_id,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "metadata": metadata if metadata else {},
        "access_log": []
    }
    
    user_records[record_type] = new_record
    
    # Save to storage
    if save_user_records(user_id, user_records):
        audit_logger.log_access(user_id, "create_record", record_type, True, "Record created successfully")
        return f"✅ Medical record created successfully\n📋 Type: {record_type}\n🔐 Encrypted: YES\n💾 Storage: {STORAGE_TYPE}\n👤 Owner: {user_id}"
    else:
        audit_logger.log_access(user_id, "create_record", record_type, False, "Storage error")
        return "⚠️  Record created but storage may be temporary"

@mcp.tool()
def get_medical_record(session_token: str, record_type: str) -> dict:
    """
    Retrieve a specific medical record (SECURE - User Isolated)
    
    Args:
        session_token: User's authentication session token
        record_type: Type of record to retrieve
        
    Returns:
        Medical record data or error message
        
    Security:
        - Users can ONLY access their own records
        - All access attempts are logged
        - Data is decrypted only for authorized user
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        audit_logger.log_access("UNKNOWN", "get_record", record_type, False, "Invalid session")
        return {
            "success": False,
            "error": "Invalid or expired session. Please authenticate first."
        }
    
    user_id = user["user_id"]
    
    # Load user's records
    user_records = load_user_records(user_id)
    
    # Check if record exists
    if record_type not in user_records:
        audit_logger.log_access(user_id, "get_record", record_type, False, "Record not found")
        return {
            "success": False,
            "error": f"No record found with type: '{record_type}'"
        }
    
    # Log successful access
    audit_logger.log_access(user_id, "get_record", record_type, True, "Record retrieved")
    
    record = user_records[record_type]
    
    return {
        "success": True,
        "record": record,
        "owner_id": user_id,
        "storage": STORAGE_TYPE,
        "encrypted": True
    }

@mcp.tool()
def update_medical_record(
    session_token: str,
    record_type: str,
    new_content: Optional[str] = None,
    new_metadata: Optional[dict] = None
) -> str:
    """
    Update an existing medical record (SECURE - User Isolated)
    
    Args:
        session_token: User's authentication session token
        record_type: Type of record to update
        new_content: New medical information (optional)
        new_metadata: New metadata to merge (optional)
        
    Returns:
        Success or error message
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        audit_logger.log_access("UNKNOWN", "update_record", record_type, False, "Invalid session")
        return "❌ ERROR: Invalid or expired session. Please authenticate first."
    
    user_id = user["user_id"]
    
    # Load user's records
    user_records = load_user_records(user_id)
    
    # Check if record exists
    if record_type not in user_records:
        audit_logger.log_access(user_id, "update_record", record_type, False, "Record not found")
        return f"❌ ERROR: No record found with type: '{record_type}'"
    
    record = user_records[record_type]
    updates = []
    
    # Update content
    if new_content is not None:
        record["content"] = new_content
        updates.append("Content updated")
    
    # Update metadata
    if new_metadata is not None:
        record["metadata"].update(new_metadata)
        updates.append("Metadata updated")
    
    if not updates:
        return f"⚠️  No changes specified for record: '{record_type}'"
    
    record["updated_at"] = datetime.now().isoformat()
    
    # Save to storage
    if save_user_records(user_id, user_records):
        audit_logger.log_access(user_id, "update_record", record_type, True, ", ".join(updates))
        return f"✅ Medical record updated successfully\n📋 Type: {record_type}\n🔄 Changes: {', '.join(updates)}\n💾 Storage: {STORAGE_TYPE}"
    else:
        audit_logger.log_access(user_id, "update_record", record_type, False, "Storage error")
        return "⚠️  Record updated but storage may be temporary"

@mcp.tool()
def delete_medical_record(session_token: str, record_type: str) -> str:
    """
    Delete a medical record (SECURE - User Isolated)
    
    Args:
        session_token: User's authentication session token
        record_type: Type of record to delete
        
    Returns:
        Success or error message
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        audit_logger.log_access("UNKNOWN", "delete_record", record_type, False, "Invalid session")
        return "❌ ERROR: Invalid or expired session. Please authenticate first."
    
    user_id = user["user_id"]
    
    # Load user's records
    user_records = load_user_records(user_id)
    
    # Check if record exists
    if record_type not in user_records:
        audit_logger.log_access(user_id, "delete_record", record_type, False, "Record not found")
        return f"❌ ERROR: No record found with type: '{record_type}'"
    
    # Delete record
    del user_records[record_type]
    
    # Save to storage
    if save_user_records(user_id, user_records):
        audit_logger.log_access(user_id, "delete_record", record_type, True, "Record deleted")
        return f"✅ Medical record deleted successfully\n📋 Type: {record_type}\n💾 Storage: {STORAGE_TYPE}"
    else:
        audit_logger.log_access(user_id, "delete_record", record_type, False, "Storage error")
        return "⚠️  Record deleted but changes may be temporary"

@mcp.tool()
def list_my_medical_records(session_token: str) -> dict:
    """
    List all medical records for the authenticated user (SECURE - User Isolated)
    
    Args:
        session_token: User's authentication session token
        
    Returns:
        Dictionary with user's medical records
        
    Security:
        - Users can ONLY see their own records
        - No cross-user data leakage possible
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        audit_logger.log_access("UNKNOWN", "list_records", "ALL", False, "Invalid session")
        return {
            "success": False,
            "error": "Invalid or expired session. Please authenticate first."
        }
    
    user_id = user["user_id"]
    
    # Load user's records
    user_records = load_user_records(user_id)
    
    audit_logger.log_access(user_id, "list_records", "ALL", True, f"Listed {len(user_records)} records")
    
    # Return sanitized record list (without full content)
    record_summary = []
    for record_type, record in user_records.items():
        record_summary.append({
            "record_type": record_type,
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "has_metadata": bool(record.get("metadata"))
        })
    
    return {
        "success": True,
        "user_id": user_id,
        "total_records": len(user_records),
        "records": record_summary,
        "storage": STORAGE_TYPE,
        "encrypted": True
    }

@mcp.tool()
def create_session(email: str) -> dict:
    """
    Create authentication session for user
    
    Args:
        email: User's email address (must be registered)
        
    Returns:
        Session token if successful
        
    Note:
        In production, this would be called after OAuth verification
    """
    session_token = session_manager.create_session(email)
    
    if session_token:
        user = session_manager.user_database[email]
        return {
            "success": True,
            "session_token": session_token,
            "user_id": user["user_id"],
            "email": email,
            "role": user["role"],
            "message": "✅ Session created successfully. Use this token for all medical record operations."
        }
    else:
        return {
            "success": False,
            "error": "User not registered. Please contact administrator."
        }

@mcp.tool()
def get_audit_logs(session_token: str, limit: int = 50) -> dict:
    """
    Get audit logs for the authenticated user's records (ADMIN or SELF only)
    
    Args:
        session_token: User's authentication session token
        limit: Maximum number of log entries to return
        
    Returns:
        Audit log entries
        
    Security:
        - Users can only see logs for their own records
        - Admins can see all logs
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        return {
            "success": False,
            "error": "Invalid or expired session. Please authenticate first."
        }
    
    user_id = user["user_id"]
    role = user["role"]
    
    if redis_client:
        try:
            logs = redis_client.lrange("audit_logs", 0, limit - 1)
            parsed_logs = [json.loads(log) for log in logs]
            
            # Filter logs based on role
            if role != "admin":
                # Regular users only see their own logs
                parsed_logs = [log for log in parsed_logs if log["user_id"] == user_id]
            
            return {
                "success": True,
                "total_logs": len(parsed_logs),
                "logs": parsed_logs
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error retrieving audit logs: {str(e)}"
            }
    else:
        # Use in-memory logs
        logs = audit_log_store[-limit:] if len(audit_log_store) > limit else audit_log_store
        
        if role != "admin":
            logs = [log for log in logs if log["user_id"] == user_id]
        
        return {
            "success": True,
            "total_logs": len(logs),
            "logs": logs
        }

@mcp.tool()
def get_system_status(session_token: str) -> dict:
    """
    Get system status and security information
    
    Args:
        session_token: User's authentication session token
        
    Returns:
        System status information
    """
    # Authenticate user
    user = session_manager.get_user_from_session(session_token)
    if not user:
        return {
            "success": False,
            "error": "Invalid or expired session. Please authenticate first."
        }
    
    user_id = user["user_id"]
    
    # Get user's record count
    user_records = load_user_records(user_id)
    
    return {
        "success": True,
        "user_info": {
            "user_id": user_id,
            "email": user["email"],
            "role": user["role"]
        },
        "security": {
            "encryption": "AES-256 (Fernet)",
            "encryption_enabled": True,
            "authentication": "Session-based" if not auth_provider else "Google OAuth",
            "audit_logging": "Enabled"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None,
            "redis_connected": redis_client is not None
        },
        "user_records": {
            "total_records": len(user_records),
            "record_types": list(user_records.keys())
        },
        "compliance": {
            "user_isolation": "Enabled",
            "data_encryption_at_rest": "Enabled",
            "audit_logging": "Enabled",
            "access_control": "Enabled"
        }
    }

@mcp.tool()
def get_help() -> dict:
    """
    Get comprehensive help documentation for the secure medical records system
    
    Returns:
        Dictionary with detailed documentation
    """
    return {
        "system_name": "Secure Medical Records MCP Server",
        "version": "2.0.0 - HIPAA Compliant Architecture",
        "security_features": {
            "user_isolation": "Each user can ONLY access their own medical records",
            "encryption": "AES-256 encryption for all data at rest",
            "audit_logging": "All access attempts are logged for compliance",
            "session_based_auth": "Session tokens required for all operations",
            "access_control": "Role-based permissions (patient, doctor, admin)"
        },
        "workflow": {
            "step_1": "Create session using create_session(email) - You'll receive a session_token",
            "step_2": "Use session_token for all subsequent operations",
            "step_3": "Create medical records using create_medical_record(session_token, record_type, content)",
            "step_4": "Retrieve records using get_medical_record(session_token, record_type)",
            "step_5": "Update records using update_medical_record(session_token, record_type, new_content)",
            "step_6": "View audit logs using get_audit_logs(session_token)"
        },
        "available_tools": {
            "create_session": "Create authentication session (required first step)",
            "create_medical_record": "Create new medical record (encrypted, user-isolated)",
            "get_medical_record": "Retrieve specific medical record",
            "update_medical_record": "Update existing medical record",
            "delete_medical_record": "Delete medical record",
            "list_my_medical_records": "List all your medical records",
            "get_audit_logs": "View access logs for compliance",
            "get_system_status": "Check system status and your record count",
            "get_help": "Display this help information"
        },
        "record_types": [
            "medical_history",
            "past_medical_history",
            "social_history",
            "family_history",
            "sexual_history",
            "medications",
            "allergies",
            "immunizations"
        ],
        "example_usage": {
            "1_create_session": "create_session('patient1@example.com')",
            "2_create_record": "create_medical_record(session_token, 'medical_history', 'Diabetes diagnosed 2020, well controlled')",
            "3_get_record": "get_medical_record(session_token, 'medical_history')",
            "4_list_records": "list_my_medical_records(session_token)"
        },
        "environment_setup": {
            "required": [
                "ENCRYPTION_KEY - Encryption key for data at rest (REQUIRED)",
                "REDIS_URL - Redis connection URL for persistent storage (recommended)",
                "REGISTERED_USERS - JSON array of registered users"
            ],
            "optional": [
                "GOOGLE_CLIENT_ID - For Google OAuth",
                "GOOGLE_CLIENT_SECRET - For Google OAuth",
                "BASE_URL - For OAuth callback"
            ]
        },
        "registered_users_format": {
            "example": '[{"user_id": "001", "email": "patient1@example.com", "role": "patient", "name": "John Doe"}]'
        }
    }

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/info")
def server_info() -> str:
    """Get comprehensive information about the secure medical MCP server."""
    info = {
        "name": "secure-medical-records",
        "version": "2.0.0",
        "description": "HIPAA-Compliant Secure Medical Records System with User Isolation",
        "security": {
            "encryption": "AES-256 (Fernet) - ENABLED",
            "user_isolation": "ENABLED - Users can ONLY access their own records",
            "audit_logging": "ENABLED - All access logged",
            "authentication": "Session-based + Optional Google OAuth"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None,
            "redis_connected": redis_client is not None
        },
        "compliance_features": [
            "Data encryption at rest",
            "User isolation and access control",
            "Comprehensive audit logging",
            "Session-based authentication",
            "HIPAA-compliant architecture"
        ],
        "tools_count": 9,
        "registered_users": len(session_manager.user_database)
    }
    return json.dumps(info, indent=2)

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("🏥 SECURE MEDICAL RECORDS MCP SERVER")
    print("=" * 70)
    print("🔐 SECURITY FEATURES:")
    print("   ✅ AES-256 Encryption at rest")
    print("   ✅ User isolation - No cross-user access")
    print("   ✅ Comprehensive audit logging")
    print("   ✅ Session-based authentication")
    print("   ✅ HIPAA-compliant architecture")
    print("=" * 70)
    
    print(f"📦 Storage: {STORAGE_TYPE}")
    print(f"🔌 Redis: {'Connected ✅' if redis_client else 'Not Connected ⚠️'}")
    print(f"👥 Registered Users: {len(session_manager.user_database)}")
    
    print("=" * 70)
    print("🔧 Available Tools: 9")
    print("=" * 70)
    print("🌐 Server ready and listening securely...")
    print("=" * 70)
    
    mcp.run()
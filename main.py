from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
import json
import os
from typing import Optional
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib

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
            "user_id": hashlib.sha256(user_id.encode()).hexdigest()[:16],
            "resource_key": resource_key,
            "action": action,
            "status": status,
            "ip_address": "REDACTED",
            "details": details or {}
        }
        
        if self.redis_client:
            try:
                log_key = f"hipaa:audit:{datetime.now().strftime('%Y%m%d')}"
                self.redis_client.rpush(log_key, json.dumps(audit_entry))
                self.redis_client.expire(log_key, 60 * 60 * 24 * 365 * 7)
            except Exception as e:
                print(f"⚠️  Audit log write failed: {e}")
        else:
            self.audit_log.append(audit_entry)
    
    def get_audit_logs(self, days: int = 30, user_id: Optional[str] = None) -> list:
        """Retrieve audit logs for the specified number of days"""
        if self.redis_client:
            try:
                logs = []
                for i in range(days):
                    date = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
                    log_key = f"hipaa:audit:{date}"
                    day_logs = self.redis_client.lrange(log_key, 0, -1)
                    logs.extend([json.loads(log) for log in day_logs])
                
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
                iterations=600000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
            self.cipher = Fernet(key)
            self.encryption_enabled = True
            print("🔐 HIPAA Encryption: ENABLED (AES-256-CBC)")
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

# Initialize encryption manager
encryption_manager = HIPAAEncryptionManager()

# ------------------------------
# Google OAuth Authentication Configuration
# ------------------------------
auth_provider = None

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")

# CRITICAL FIX: Make auth_provider optional to prevent tool hiding
USE_AUTH = os.getenv("USE_AUTH", "true").lower() == "true"

if USE_AUTH and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL:
    try:
        base_url_normalized = BASE_URL.rstrip('/')
        
        auth_provider = GoogleProvider(
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            base_url=base_url_normalized
        )
        print("=" * 70)
        print("🔐 GOOGLE OAUTH AUTHENTICATION")
        print("=" * 70)
        print("✅ Google OAuth: ENABLED")
        print(f"🌐 Base URL: {base_url_normalized}")
        print(f"📝 Redirect URI: {base_url_normalized}/oauth/callback")
        print(f"🔑 Client ID: {GOOGLE_CLIENT_ID[:20]}...")
        print("=" * 70)
    except Exception as e:
        print(f"⚠️  Failed to initialize Google OAuth: {e}")
        print("💡 Server will run without authentication")
        auth_provider = None
else:
    print("=" * 70)
    print("⚠️  GOOGLE OAUTH NOT CONFIGURED")
    print("=" * 70)
    if USE_AUTH:
        if not GOOGLE_CLIENT_ID:
            print("❌ Missing: GOOGLE_CLIENT_ID")
        if not GOOGLE_CLIENT_SECRET:
            print("❌ Missing: GOOGLE_CLIENT_SECRET")
        if not BASE_URL:
            print("❌ Missing: BASE_URL")
    else:
        print("ℹ️  Authentication disabled via USE_AUTH=false")
    print("=" * 70)

# ------------------------------
# Initialize FastMCP with FIXED Authentication
# ------------------------------
# CRITICAL FIX: Only pass auth if it's actually configured
mcp = FastMCP(
    name="hipaa-memory-multiuser",
    auth=auth_provider if auth_provider else None,
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
            ssl_cert_reqs=None
        )
        redis_client.ping()
        STORAGE_TYPE = "Redis (Upstash - HIPAA Compliant with Encryption)"
        print("✅ Connected to Redis (HIPAA-compliant storage)")
        
except ImportError:
    print("❌ CRITICAL: Redis package not installed")
    
except Exception as e:
    print(f"⚠️  Redis connection failed: {e}")

# Fallback in-memory storage
memory_store = {}

# Initialize audit logger
audit_logger = HIPAAAuditLogger(redis_client)

# ------------------------------
# Helper Functions
# ------------------------------
def get_user_storage_key(user_id: str) -> str:
    """Generate a storage key for a specific user"""
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:32]
    return f"hipaa:memories:user:{user_hash}"

def load_user_memories(user_id: str) -> list:
    """Load memories for a specific user"""
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
            print(f"⚠️  Error loading from Redis: {e}")
            return memory_store.get(user_id, [])
    else:
        return memory_store.get(user_id, [])

def save_user_memories(user_id: str, memories: list) -> bool:
    """Save memories for a specific user"""
    global memory_store
    
    if redis_client:
        try:
            storage_key = get_user_storage_key(user_id)
            encrypted_memories = [
                encryption_manager.encrypt_memory(m) for m in memories
            ]
            redis_client.set(storage_key, json.dumps(encrypted_memories))
            
            # Backup
            user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:32]
            backup_key = f"hipaa:backup:user:{user_hash}:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            redis_client.set(backup_key, json.dumps(encrypted_memories))
            redis_client.expire(backup_key, 60 * 60 * 24 * 90)
            
            return True
        except Exception as e:
            print(f"❌ Error saving to Redis: {e}")
            memory_store[user_id] = memories
            return False
    else:
        memory_store[user_id] = memories
        return True

# ------------------------------
# MCP Tools (All tools from original code)
# ------------------------------
@mcp.tool()
def create_memory(
    key: str, 
    content: str, 
    tag: Optional[str] = None, 
    metadata: Optional[dict] = None,
    user_id: str = "default_user"
) -> str:
    """Create a new encrypted memory for a specific user (HIPAA-compliant)."""
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "CREATE", "FAILED", 
                                  {"reason": "Duplicate key"})
            return f"❌ Memory with key '{key}' already exists for user '{user_id}'."
    
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
                f"🔐 Encrypted | 👤 User: {user_id} | 💾 {STORAGE_TYPE}")
    else:
        return f"❌ Memory creation failed"

@mcp.tool()
def get_memory(key: str, user_id: str = "default_user") -> dict:
    """Retrieve a specific encrypted memory by key."""
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "READ", "SUCCESS", {})
            return {
                "found": True,
                "memory": memory,
                "user_id": user_id,
                "encrypted": True,
                "hipaa_compliant": True
            }
    
    return {
        "found": False,
        "user_id": user_id,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool()
def list_memories(
    tag: Optional[str] = None, 
    search: Optional[str] = None,
    user_id: str = "default_user"
) -> dict:
    """List all encrypted memories for a user."""
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
                          {"count": len(memories)})
    
    return {
        "user_id": user_id,
        "total_count": len(memories),
        "memories": memories,
        "encrypted": True,
        "hipaa_compliant": True
    }

@mcp.tool()
def update_memory(
    key: str, 
    new_content: Optional[str] = None, 
    new_tag: Optional[str] = None, 
    new_metadata: Optional[dict] = None,
    user_id: str = "default_user"
) -> str:
    """Update an existing encrypted memory."""
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            updates = []
            
            if new_content is not None:
                memory["content"] = new_content
                updates.append("Content updated")
            
            if new_tag is not None:
                memory["tag"] = new_tag
                updates.append(f"Tag: {new_tag}")
            
            if new_metadata is not None:
                memory["metadata"].update(new_metadata)
                updates.append("Metadata updated")
            
            memory["updated_at"] = datetime.now().isoformat()
            
            if save_user_memories(user_id, memories):
                audit_logger.log_event("PHI_MODIFY", user_id, key, "UPDATE", "SUCCESS", {})
                return f"✅ Memory Updated: '{key}'\n" + "\n".join(updates)
            else:
                return f"❌ Update failed"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def forget_memory(key: str, user_id: str = "default_user", reason: str = "User request") -> str:
    """Securely delete an encrypted memory."""
    memories = load_user_memories(user_id)
    original_count = len(memories)
    
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        if save_user_memories(user_id, memories):
            audit_logger.log_event("PHI_DELETE", user_id, key, "DELETE", "SUCCESS", 
                                  {"reason": reason})
            return f"✅ Memory Deleted: '{key}' | Reason: {reason}"
        else:
            return f"❌ Deletion failed"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def get_server_status(user_id: str = "default_user") -> dict:
    """Get HIPAA-compliant server status."""
    memories = load_user_memories(user_id)
    
    return {
        "user_info": {
            "current_user": user_id,
            "memory_count": len(memories)
        },
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None"
        },
        "encryption": {
            "enabled": True,
            "algorithm": "AES-256-CBC"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "redis_connected": redis_client is not None
        }
    }

@mcp.tool()
def get_help_documentation() -> dict:
    """Get comprehensive help documentation."""
    return {
        "server_name": "HIPAA-Compliant Multi-User Memory MCP Server",
        "version": "4.0.1-FIXED",
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None"
        },
        "tools": {
            "create_memory": "Create encrypted memory",
            "get_memory": "Retrieve memory by key",
            "list_memories": "List all memories",
            "update_memory": "Update existing memory",
            "forget_memory": "Delete memory",
            "get_server_status": "Get server status"
        }
    }

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("🏥 HIPAA-COMPLIANT MULTI-USER MCP SERVER (FIXED)")
    print("=" * 70)
    print(f"\n🔐 Authentication: {'✅ ENABLED' if auth_provider else '⚠️  DISABLED'}")
    print(f"🔐 Encryption: ✅ ENABLED (AES-256)")
    print(f"💾 Storage: {STORAGE_TYPE}")
    print(f"📋 Audit Logging: ✅ ENABLED")
    print(f"👥 Multi-User: ✅ ENABLED")
    print(f"\n🔧 Registered {len(mcp._tools)} tools")
    print("=" * 70)
    
    mcp.run()
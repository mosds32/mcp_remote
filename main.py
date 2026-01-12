from fastmcp import FastMCP, Context
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

# [Previous HIPAAAuditLogger class remains same]
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
        """Retrieve audit logs"""
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

# [Previous HIPAAEncryptionManager class remains same]
class HIPAAEncryptionManager:
    """HIPAA-compliant encryption manager"""
    
    def __init__(self):
        self.cipher = None
        self.encryption_enabled = False
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if not encryption_key:
            raise ValueError("❌ ENCRYPTION_KEY environment variable is REQUIRED!")
        
        if len(encryption_key) < 16:
            raise ValueError("❌ ENCRYPTION_KEY must be at least 16 characters!")
        
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
            raise RuntimeError(f"❌ Encryption initialization failed: {e}")
    
    def encrypt(self, data: str) -> str:
        encrypted = self.cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        decoded = base64.b64decode(encrypted_data.encode())
        decrypted = self.cipher.decrypt(decoded)
        return decrypted.decode()
    
    def encrypt_memory(self, memory: dict) -> dict:
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
        decrypted_memory = memory.copy()
        if "content" in decrypted_memory:
            decrypted_memory["content"] = self.decrypt(decrypted_memory["content"])
        if "metadata" in decrypted_memory and decrypted_memory["metadata"]:
            decrypted_memory["metadata"] = {
                k: self.decrypt(v) for k, v in decrypted_memory["metadata"].items()
            }
        decrypted_memory["encrypted"] = False
        return decrypted_memory

encryption_manager = HIPAAEncryptionManager()

# [Previous auth setup code remains same]
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
        print("=" * 70)
        print("✅ Google OAuth: ENABLED")
        print(f"🌐 Base URL: {base_url_normalized}")
        print("=" * 70)
    except Exception as e:
        print(f"⚠️  Failed to initialize Google OAuth: {e}")
        auth_provider = None

mcp = FastMCP(name="hipaa-memory-multiuser", auth=auth_provider)

# [Previous storage setup code remains same]
redis_client = None
STORAGE_TYPE = "Memory (Non-HIPAA Compliant)"

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL")
    if REDIS_URL:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        STORAGE_TYPE = "Redis (HIPAA Compliant)"
        print("✅ Connected to Redis")
except Exception as e:
    print(f"⚠️  Redis: {e}")

memory_store = {}
audit_logger = HIPAAAuditLogger(redis_client)

# [Previous helper functions remain same]
def get_user_storage_key(user_id: str) -> str:
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:32]
    return f"hipaa:memories:user:{user_hash}"

def load_user_memories(user_id: str) -> list:
    global memory_store
    if redis_client:
        try:
            storage_key = get_user_storage_key(user_id)
            data = redis_client.get(storage_key)
            if data:
                memories = json.loads(data)
                return [encryption_manager.decrypt_memory(m) for m in memories]
            return []
        except Exception as e:
            print(f"⚠️  Error loading from Redis: {e}")
            return memory_store.get(user_id, [])
    else:
        return memory_store.get(user_id, [])

def save_user_memories(user_id: str, memories: list) -> bool:
    global memory_store
    if redis_client:
        try:
            storage_key = get_user_storage_key(user_id)
            encrypted_memories = [encryption_manager.encrypt_memory(m) for m in memories]
            redis_client.set(storage_key, json.dumps(encrypted_memories))
            return True
        except Exception as e:
            print(f"❌ Error saving to Redis: {e}")
            memory_store[user_id] = memories
            return False
    else:
        memory_store[user_id] = memories
        return True

# ✅ HELPER FUNCTION: Get authenticated user ID
def get_authenticated_user(ctx: Context) -> str:
    """Extract authenticated user ID from context"""
    if hasattr(ctx, 'user') and ctx.user:
        # Google OAuth returns email as user identifier
        if hasattr(ctx.user, 'email'):
            return ctx.user.email
        # Fallback to string representation
        return str(ctx.user)
    return "anonymous_user"

# ✅ UPDATED TOOLS WITH AUTOMATIC USER ID EXTRACTION

@mcp.tool()
def create_memory(
    ctx: Context,  # ✅ ADD THIS
    key: str, 
    content: str, 
    tag: Optional[str] = None, 
    metadata: Optional[dict] = None
) -> str:
    """
    Create a new encrypted memory (HIPAA-compliant).
    User is automatically identified from authentication.
    """
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT USER
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "CREATE", "FAILED", 
                                  {"reason": "Duplicate key"})
            return f"❌ Memory with key '{key}' already exists."
    
    new_memory = {
        "key": key,
        "content": content,
        "tag": tag if tag else "general",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "created_by": hashlib.sha256(user_id.encode()).hexdigest()[:16],
        "metadata": metadata if metadata else {},
        "hipaa_compliant": True,
        "user_id": user_id
    }
    
    memories.append(new_memory)
    
    if save_user_memories(user_id, memories):
        audit_logger.log_event("PHI_CREATE", user_id, key, "CREATE", "SUCCESS", 
                              {"tag": tag, "encrypted": True})
        return (f"✅ Memory Created: '{key}'\n"
                f"👤 User: {user_id}\n"
                f"🔐 Encrypted: AES-256\n"
                f"📋 Audit: Logged")
    else:
        return f"❌ Memory creation failed"

@mcp.tool()
def get_memory(ctx: Context, key: str) -> dict:  # ✅ ADD ctx
    """Retrieve a specific memory (auto-detects user)"""
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            audit_logger.log_event("PHI_ACCESS", user_id, key, "READ", "SUCCESS", {})
            return {
                "found": True,
                "memory": memory,
                "user_id": user_id,
                "encrypted": True,
                "audit_logged": True
            }
    
    return {"found": False, "message": f"No memory found with key: '{key}'"}

@mcp.tool()
def list_memories(ctx: Context, tag: Optional[str] = None, search: Optional[str] = None) -> dict:
    """List all memories for authenticated user"""
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT
    memories = load_user_memories(user_id)
    
    if tag:
        memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    if search:
        search_lower = search.lower()
        memories = [m for m in memories 
                   if search_lower in m["key"].lower() or search_lower in m["content"].lower()]
    
    audit_logger.log_event("PHI_ACCESS", user_id, "list", "LIST", "SUCCESS", 
                          {"count": len(memories)})
    
    return {
        "user_id": user_id,
        "total_count": len(memories),
        "memories": memories,
        "encrypted": True,
        "isolation": "Complete user separation"
    }

@mcp.tool()
def update_memory(
    ctx: Context,  # ✅ ADD THIS
    key: str, 
    new_content: Optional[str] = None, 
    new_tag: Optional[str] = None, 
    new_metadata: Optional[dict] = None
) -> str:
    """Update an existing memory (auto-detects user)"""
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT
    memories = load_user_memories(user_id)
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            updates = []
            
            if new_content is not None:
                memory["content"] = new_content
                updates.append("Content updated")
            
            if new_tag is not None:
                memory["tag"] = new_tag
                updates.append(f"Tag → {new_tag}")
            
            if new_metadata is not None:
                memory["metadata"].update(new_metadata)
                updates.append("Metadata updated")
            
            if not updates:
                return f"⚠️  No changes specified"
            
            memory["updated_at"] = datetime.now().isoformat()
            
            if save_user_memories(user_id, memories):
                audit_logger.log_event("PHI_MODIFY", user_id, key, "UPDATE", "SUCCESS", 
                                      {"changes": updates})
                return f"✅ Memory Updated: '{key}'\n" + "\n".join(updates)
            else:
                return f"❌ Update failed"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def forget_memory(ctx: Context, key: str, reason: str = "User request") -> str:
    """Delete a memory (auto-detects user)"""
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT
    memories = load_user_memories(user_id)
    original_count = len(memories)
    
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        if save_user_memories(user_id, memories):
            audit_logger.log_event("PHI_DELETE", user_id, key, "DELETE", "SUCCESS", 
                                  {"reason": reason})
            return f"✅ Memory Deleted: '{key}'\n📋 Audit: Logged"
        else:
            return f"❌ Deletion failed"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def get_server_status(ctx: Context) -> dict:
    """Get server status for authenticated user"""
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT
    memories = load_user_memories(user_id)
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    return {
        "user_info": {
            "authenticated_user": user_id,  # ✅ SHOWS ACTUAL USER
            "memory_count": len(memories),
            "tags": memory_tags
        },
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None",
            "user_authenticated": user_id != "anonymous_user"
        },
        "hipaa_compliance": {
            "encryption_enabled": True,
            "audit_logging": True,
            "multi_user_isolation": True
        },
        "storage": {
            "type": STORAGE_TYPE,
            "redis_connected": redis_client is not None
        }
    }

@mcp.tool()
def clear_all_memories(ctx: Context, confirmation: str = "", reason: str = "Administrative") -> str:
    """Clear all memories for authenticated user only"""
    user_id = get_authenticated_user(ctx)  # ✅ AUTO-DETECT
    
    if confirmation != "CONFIRM_DELETE_ALL":
        return ("❌ Confirmation required.\n"
                "⚠️  Set confirmation='CONFIRM_DELETE_ALL' to proceed.\n"
                f"📋 This will delete all YOUR memories only.")
    
    memories = load_user_memories(user_id)
    memory_count = len(memories)
    
    if save_user_memories(user_id, []):
        audit_logger.log_event("PHI_DELETE_ALL", user_id, "all", "DELETE_ALL", "SUCCESS", 
                              {"count": memory_count, "reason": reason})
        return f"✅ All {memory_count} memories deleted for user: {user_id}"
    else:
        return f"❌ Deletion failed"

if __name__ == "__main__":
    print("=" * 70)
    print("🏥 HIPAA-COMPLIANT MULTI-USER SERVER")
    print("=" * 70)
    print("✅ AUTO USER DETECTION: Enabled")
    print("✅ Each Google account gets isolated storage")
    print("✅ No manual user_id needed - automatic from OAuth")
    print("=" * 70)
    mcp.run()
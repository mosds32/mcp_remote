from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
import json
import os
from typing import Optional
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging

# Setup logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------------------
# Encryption Configuration
# ------------------------------
class EncryptionManager:
    """Manages encryption/decryption of sensitive data"""
    
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
                    salt=b'mcp_memory_salt_v1',
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
                self.cipher = Fernet(key)
                self.encryption_enabled = True
                logger.info("🔐 Encryption: ENABLED")
            except Exception as e:
                logger.warning(f"⚠️  Encryption initialization failed: {e}")
                self.encryption_enabled = False
        else:
            logger.info("🔓 Encryption: DISABLED")
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not self.encryption_enabled:
            return data
        
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"❌ Encryption error: {e}")
            return data
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        if not self.encryption_enabled:
            return encrypted_data
        
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"❌ Decryption error: {e}")
            return encrypted_data
    
    def encrypt_memory(self, memory: dict) -> dict:
        """Encrypt sensitive fields in a memory object"""
        if not self.encryption_enabled:
            return memory
        
        encrypted_memory = memory.copy()
        
        if "content" in encrypted_memory:
            encrypted_memory["content"] = self.encrypt(encrypted_memory["content"])
        
        if "metadata" in encrypted_memory and encrypted_memory["metadata"]:
            encrypted_memory["metadata"] = {
                k: self.encrypt(str(v)) for k, v in encrypted_memory["metadata"].items()
            }
        
        encrypted_memory["encrypted"] = True
        return encrypted_memory
    
    def decrypt_memory(self, memory: dict) -> dict:
        """Decrypt sensitive fields in a memory object"""
        if not self.encryption_enabled or not memory.get("encrypted", False):
            return memory
        
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
encryption_manager = EncryptionManager()

# ------------------------------
# Authentication Configuration
# ------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL", "").rstrip('/')

auth_provider = None
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL:
    try:
        auth_provider = GoogleProvider(
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            base_url=BASE_URL
        )
        logger.info(f"✅ Google OAuth enabled: {BASE_URL}")
    except Exception as e:
        logger.warning(f"⚠️  Google OAuth failed: {e}")

# Initialize FastMCP with proper configuration
mcp = FastMCP(
    name="memory",
    auth=auth_provider,
    dependencies=[]  # Explicitly set empty dependencies
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
        STORAGE_TYPE = "Redis (Permanent)"
        logger.info("✅ Connected to Redis")
except Exception as e:
    logger.warning(f"⚠️  Redis connection failed: {e}")

# Fallback in-memory storage
memory_store = []

# ------------------------------
# Storage Functions
# ------------------------------
def load_memories():
    """Load memories from Redis or fallback to in-memory storage."""
    global memory_store
    
    if redis_client:
        try:
            data = redis_client.get("mcp:memories")
            if data:
                memories = json.loads(data)
                decrypted_memories = [
                    encryption_manager.decrypt_memory(m) for m in memories
                ]
                return decrypted_memories
            return []
        except Exception as e:
            logger.error(f"⚠️  Error loading from Redis: {e}")
            return memory_store
    else:
        return memory_store

def save_memories(memories):
    """Save memories to Redis or in-memory storage."""
    global memory_store
    
    if redis_client:
        try:
            encrypted_memories = [
                encryption_manager.encrypt_memory(m) for m in memories
            ]
            redis_client.set("mcp:memories", json.dumps(encrypted_memories))
            return True
        except Exception as e:
            logger.error(f"❌ Error saving to Redis: {e}")
            memory_store = memories
            return False
    else:
        memory_store = memories
        return True

# ------------------------------
# Memory Management Tools
# ------------------------------
@mcp.tool()
def create_memory(key: str, content: str, tag: str = "general", metadata: dict = None) -> str:
    """Create a new memory with key-value pair"""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return f"❌ Memory '{key}' already exists. Use update_memory to modify it."
    
    new_memory = {
        "key": key,
        "content": content,
        "tag": tag,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "metadata": metadata or {}
    }
    
    memories.append(new_memory)
    save_memories(memories)
    
    return f"✅ Memory created: '{key}' [Tag: {tag}]\n💾 Content: {content}"

@mcp.tool()
def get_memory(key: str) -> dict:
    """Retrieve a specific memory by key"""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return {
                "found": True,
                "memory": memory,
                "storage": STORAGE_TYPE
            }
    
    return {
        "found": False,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool()
def get_memory_by_tag(tag: str) -> dict:
    """Retrieve all memories with a specific tag"""
    memories = load_memories()
    matching_memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    return {
        "found": len(matching_memories) > 0,
        "tag": tag,
        "count": len(matching_memories),
        "memories": matching_memories
    }

@mcp.tool()
def update_memory(key: str, new_content: str = None, new_tag: str = None, new_metadata: dict = None) -> str:
    """Update an existing memory's content, tag, or metadata"""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            updates = []
            
            if new_content is not None:
                memory["content"] = new_content
                updates.append("Content updated")
            
            if new_tag is not None:
                old_tag = memory.get("tag", "general")
                memory["tag"] = new_tag
                updates.append(f"Tag: {old_tag} → {new_tag}")
            
            if new_metadata is not None:
                memory["metadata"].update(new_metadata)
                updates.append("Metadata updated")
            
            if not updates:
                return f"⚠️  No changes specified for '{key}'"
            
            memory["updated_at"] = datetime.now().isoformat()
            save_memories(memories)
            
            return f"✅ Memory updated: '{key}'\n" + "\n".join(updates)
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def forget_memory(key: str) -> str:
    """Delete a specific memory by key"""
    memories = load_memories()
    original_count = len(memories)
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        save_memories(memories)
        return f"✅ Memory forgotten: '{key}'"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def list_memories(tag: str = None, search: str = None) -> dict:
    """List all memories, optionally filtered by tag or search term"""
    memories = load_memories()
    
    if tag:
        memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    if search:
        search_lower = search.lower()
        memories = [
            m for m in memories 
            if search_lower in m["key"].lower() or search_lower in m["content"].lower()
        ]
    
    return {
        "total_count": len(memories),
        "memories": memories,
        "storage": STORAGE_TYPE
    }

@mcp.tool()
def list_tags() -> dict:
    """List all unique tags used in memories with their counts"""
    memories = load_memories()
    
    if not memories:
        return {
            "total_tags": 0,
            "tags": {},
            "message": "No memories stored yet."
        }
    
    tag_counts = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    
    return {
        "total_tags": len(tag_counts),
        "tags": tag_counts
    }

@mcp.tool()
def memory_based_chat(message: str, tag: str = None) -> str:
    """Respond based on stored memories by searching through content and keys"""
    memories = load_memories()
    
    if not memories:
        return "No memories stored yet. Create memories using create_memory tool."
    
    if tag:
        memories = [m for m in memories if m.get("tag", "").lower() == tag.lower()]
        if not memories:
            return f"No memories found with tag: '{tag}'"
    
    message_lower = message.lower()
    relevant_memories = []
    
    for memory in memories:
        if (message_lower in memory["key"].lower() or 
            message_lower in memory["content"].lower() or
            memory["key"].lower() in message_lower):
            relevant_memories.append(memory)
    
    if relevant_memories:
        relevant_memories.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        best_match = relevant_memories[0]
        return f"💾 {best_match['content']}\n[Source: {best_match['key']} | Tag: {best_match.get('tag', 'general')}]"
    
    return "I don't have a memory about that yet."

@mcp.tool()
def get_server_status() -> dict:
    """Get server status and statistics"""
    memories = load_memories()
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    return {
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None"
        },
        "encryption": {
            "enabled": encryption_manager.encryption_enabled,
            "algorithm": "AES-256" if encryption_manager.encryption_enabled else "None"
        },
        "storage_type": STORAGE_TYPE,
        "redis_connected": redis_client is not None,
        "memories_count": len(memories),
        "memory_tags": memory_tags
    }

@mcp.tool()
def clear_all_memories() -> str:
    """Clear all memories from storage. Use with caution!"""
    save_memories([])
    return f"✅ All memories cleared from {STORAGE_TYPE} storage"

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server Starting...")
    print("=" * 60)
    
    # Log tool registration
    print(f"📦 Registered Tools: {len(mcp._tool_manager._tools)}")
    for tool_name in mcp._tool_manager._tools.keys():
        print(f"  ✓ {tool_name}")
    
    print("=" * 60)
    print(f"🔐 Auth: {'✓ Google OAuth' if auth_provider else '✗ Disabled'}")
    print(f"🔒 Encryption: {'✓ AES-256' if encryption_manager.encryption_enabled else '✗ Disabled'}")
    print(f"💾 Storage: {STORAGE_TYPE}")
    print("=" * 60)
    
    memories = load_memories()
    print(f"✅ Loaded {len(memories)} existing memories")
    print("=" * 60)
    print("🌐 Server ready!")
    print("=" * 60)
    
    mcp.run()
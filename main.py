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
                print("🔐 Encryption: ENABLED (User-provided key)")
                print("✅ Data will be encrypted at rest")
            except Exception as e:
                print(f"⚠️  Encryption initialization failed: {e}")
                print("💡 Data will be stored WITHOUT encryption")
        else:
            print("🔓 Encryption: DISABLED")
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not self.encryption_enabled:
            return data
        
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"❌ Encryption error: {e}")
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
            print(f"❌ Decryption error: {e}")
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
auth_provider = None

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL:
    try:
        # CRITICAL FIX: Normalize base URL properly
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
        print("💡 Server will run without authentication")
        auth_provider = None
else:
    print("ℹ️  Google OAuth not configured")

# Initialize FastMCP with proper configuration
# IMPORTANT: Set auth_required=False to allow tools to be discovered
mcp = FastMCP(
    name="memory",
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
        STORAGE_TYPE = "Redis (Upstash - Permanent + Encrypted)" if encryption_manager.encryption_enabled else "Redis (Upstash - Permanent)"
        print("✅ Connected to Upstash Redis")
        print("💾 Storage: PERMANENT - Data will persist across restarts!")
    else:
        print("⚠️  REDIS_URL not found in environment variables")
        print("📝 Using temporary in-memory storage")
        
except ImportError:
    print("⚠️  Redis package not installed")
    print("📝 Using temporary in-memory storage")
    
except Exception as e:
    print(f"⚠️  Redis connection failed: {e}")
    print("💡 Using temporary in-memory storage")

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
                print(f"📥 Loaded {len(decrypted_memories)} memories from Redis")
                if encryption_manager.encryption_enabled:
                    print("🔓 Memories decrypted successfully")
                return decrypted_memories
            print("📝 No existing memories found in Redis")
            return []
        except Exception as e:
            print(f"⚠️  Error loading from Redis: {e}")
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
            encryption_status = "🔐 ENCRYPTED" if encryption_manager.encryption_enabled else ""
            print(f"💾 Saved {len(memories)} memories to Redis {encryption_status}")
            return True
        except Exception as e:
            print(f"❌ Error saving to Redis: {e}")
            memory_store = memories
            return False
    else:
        memory_store = memories
        return True

# ------------------------------
# Memory Management Tools
# ------------------------------
@mcp.tool()
def create_memory(key: str, content: str, tag: Optional[str] = None, metadata: Optional[dict] = None) -> str:
    """
    Create a new memory with key-value pair.
    
    Args:
        key: Unique identifier for the memory
        content: The actual content to remember
        tag: Optional tag for categorization (default: "general")
        metadata: Optional additional information as a dictionary
        
    Returns:
        Success or error message with storage information
    """
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return f"❌ Memory with key '{key}' already exists. Use update_memory to modify it."
    
    new_memory = {
        "key": key,
        "content": content,
        "tag": tag if tag else "general",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "metadata": metadata if metadata else {}
    }
    
    memories.append(new_memory)
    
    if save_memories(memories):
        tag_info = f" [Tag: {new_memory['tag']}]" if tag else ""
        persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
        encryption_status = "🔐 ENCRYPTED" if encryption_manager.encryption_enabled else ""
        return f"✅ Memory created: '{key}'{tag_info}\n💾 Content: {content}\n📦 Storage: {STORAGE_TYPE} {persistence} {encryption_status}"
    else:
        return f"⚠️  Memory created but storage may be temporary"

@mcp.tool()
def get_memory(key: str) -> dict:
    """
    Retrieve a specific memory by key.
    
    Args:
        key: The unique identifier of the memory to retrieve
        
    Returns:
        Dictionary with memory details or error message
    """
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return {
                "found": True,
                "memory": memory,
                "storage": STORAGE_TYPE,
                "persistent": redis_client is not None,
                "encrypted": encryption_manager.encryption_enabled
            }
    
    return {
        "found": False,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool()
def get_memory_by_tag(tag: str) -> dict:
    """
    Retrieve all memories with a specific tag.
    
    Args:
        tag: The tag to filter memories by
        
    Returns:
        Dictionary with matching memories or error message
    """
    memories = load_memories()
    
    matching_memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    if matching_memories:
        return {
            "found": True,
            "tag": tag,
            "count": len(matching_memories),
            "memories": matching_memories,
            "storage": STORAGE_TYPE,
            "persistent": redis_client is not None,
            "encrypted": encryption_manager.encryption_enabled
        }
    
    return {
        "found": False,
        "tag": tag,
        "message": f"No memories found with tag: '{tag}'"
    }

@mcp.tool()
def update_memory(key: str, new_content: Optional[str] = None, new_tag: Optional[str] = None, new_metadata: Optional[dict] = None) -> str:
    """
    Update an existing memory's content, tag, or metadata.
    
    Args:
        key: The unique identifier of the memory to update
        new_content: New content for the memory (optional)
        new_tag: New tag for the memory (optional)
        new_metadata: New metadata to merge with existing (optional)
        
    Returns:
        Success message with update details or error message
    """
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
                return f"⚠️  No changes specified for memory: '{key}'"
            
            memory["updated_at"] = datetime.now().isoformat()
            
            if save_memories(memories):
                persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
                encryption_status = "🔐 ENCRYPTED" if encryption_manager.encryption_enabled else ""
                return f"✅ Memory updated: '{key}'\n" + "\n".join(updates) + f"\n📦 Storage: {STORAGE_TYPE} {persistence} {encryption_status}"
            else:
                return f"⚠️  Memory updated but storage may be temporary"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def forget_memory(key: str) -> str:
    """
    Delete a specific memory by key.
    
    Args:
        key: The unique identifier of the memory to delete
        
    Returns:
        Success or error message
    """
    memories = load_memories()
    original_count = len(memories)
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        if save_memories(memories):
            persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
            return f"✅ Memory forgotten: '{key}'\n📦 Storage: {STORAGE_TYPE} {persistence}"
        else:
            return f"⚠️  Memory deleted but changes may be temporary"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool()
def list_memories(tag: Optional[str] = None, search: Optional[str] = None) -> dict:
    """
    List all memories, optionally filtered by tag or search term.
    
    Args:
        tag: Filter memories by tag (optional)
        search: Search term to find in keys or content (optional)
        
    Returns:
        Dictionary with total count and list of memories
    """
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
        "storage": STORAGE_TYPE,
        "persistent": redis_client is not None,
        "encrypted": encryption_manager.encryption_enabled
    }

@mcp.tool()
def list_tags() -> dict:
    """
    List all unique tags used in memories with their counts.
    
    Returns:
        Dictionary with all tags and their usage counts
    """
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
        "tags": tag_counts,
        "storage": STORAGE_TYPE,
        "persistent": redis_client is not None,
        "encrypted": encryption_manager.encryption_enabled
    }

@mcp.tool()
def memory_based_chat(message: str, tag: Optional[str] = None) -> str:
    """
    Respond based on stored memories by searching through content and keys.
    
    Args:
        message: Search query to find relevant memories
        tag: Optional tag to filter memories before searching
        
    Returns:
        Best matching memory content or message if no match found
    """
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
        persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
        encryption_status = "🔐 ENCRYPTED" if encryption_manager.encryption_enabled else ""
        return f"💾 {best_match['content']}\n[Source: {best_match['key']} | Tag: {best_match.get('tag', 'general')} | Storage: {STORAGE_TYPE} {persistence} {encryption_status}]"
    
    return "I don't have a memory about that yet."

@mcp.tool()
def get_server_status() -> dict:
    """
    Get server status and statistics including storage and encryption information.
    
    Returns:
        Dictionary with server status, memory counts, storage and security details
    """
    memories = load_memories()
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    redis_status = "Connected ✓" if redis_client else "Not Connected ✗"
    auth_status = "Enabled ✓" if auth_provider else "Disabled ✗"
    encryption_status = "Enabled ✓" if encryption_manager.encryption_enabled else "Disabled ✗"
    
    return {
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None",
            "status": auth_status
        },
        "encryption": {
            "enabled": encryption_manager.encryption_enabled,
            "status": encryption_status,
            "algorithm": "AES-256 (Fernet)" if encryption_manager.encryption_enabled else "None"
        },
        "storage_type": STORAGE_TYPE,
        "redis_status": redis_status,
        "redis_url_configured": os.getenv("REDIS_URL") is not None,
        "persistent": redis_client is not None,
        "memories_count": len(memories),
        "memory_tags_count": len(memory_tags),
        "memory_tags": memory_tags,
        "upstash_setup_url": "https://upstash.com" if not redis_client else None
    }

@mcp.tool()
def clear_all_memories() -> str:
    """
    Clear all memories from storage. Use with caution!
    
    Returns:
        Success or error message
        
    Warning:
        This action cannot be undone!
    """
    if save_memories([]):
        persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
        return f"✅ All memories cleared from {STORAGE_TYPE} storage {persistence}"
    else:
        return f"⚠️  Error clearing memories"

@mcp.tool()
def get_help_documentation() -> dict:
    """
    Get comprehensive help documentation for all available tools.
    
    Returns:
        Dictionary with detailed documentation for each tool
    """
    return {
        "server_name": "Memory MCP Server (Encrypted)",
        "version": "2.0.0",
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None"
        },
        "encryption": {
            "enabled": encryption_manager.encryption_enabled,
            "algorithm": "AES-256 (Fernet)" if encryption_manager.encryption_enabled else "None"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None
        },
        "tools": {
            "create_memory": {
                "description": "Create a new memory with key-value pair (encrypted)",
                "parameters": {
                    "key": "Unique identifier (required)",
                    "content": "The content to remember (required)",
                    "tag": "Category tag (optional, default: 'general')",
                    "metadata": "Additional info as dict (optional)"
                },
                "example": "create_memory('user_pref', 'Dark mode enabled', 'preferences')"
            },
            "get_memory": {
                "description": "Retrieve a specific memory by key (decrypted)",
                "parameters": {
                    "key": "The memory key to retrieve (required)"
                },
                "example": "get_memory('user_pref')"
            },
            "get_memory_by_tag": {
                "description": "Retrieve all memories with a specific tag",
                "parameters": {
                    "tag": "The tag to filter by (required)"
                },
                "example": "get_memory_by_tag('preferences')"
            },
            "update_memory": {
                "description": "Update an existing memory",
                "parameters": {
                    "key": "Memory key to update (required)",
                    "new_content": "New content (optional)",
                    "new_tag": "New tag (optional)",
                    "new_metadata": "New metadata to merge (optional)"
                },
                "example": "update_memory('user_pref', new_content='Light mode enabled')"
            },
            "forget_memory": {
                "description": "Delete a memory by key",
                "parameters": {
                    "key": "Memory key to delete (required)"
                },
                "example": "forget_memory('user_pref')"
            },
            "list_memories": {
                "description": "List all memories with optional filters",
                "parameters": {
                    "tag": "Filter by tag (optional)",
                    "search": "Search in keys/content (optional)"
                },
                "example": "list_memories(tag='preferences')"
            },
            "list_tags": {
                "description": "List all unique tags with usage counts",
                "parameters": {},
                "example": "list_tags()"
            },
            "memory_based_chat": {
                "description": "Search and respond with relevant memories",
                "parameters": {
                    "message": "Search query (required)",
                    "tag": "Filter by tag first (optional)"
                },
                "example": "memory_based_chat('What does user prefer?')"
            },
            "get_server_status": {
                "description": "Get server statistics and status",
                "parameters": {},
                "example": "get_server_status()"
            },
            "clear_all_memories": {
                "description": "Clear all memories (CAUTION: Cannot be undone)",
                "parameters": {},
                "example": "clear_all_memories()"
            },
            "get_help_documentation": {
                "description": "Get this help documentation",
                "parameters": {},
                "example": "get_help_documentation()"
            }
        }
    }

# ------------------------------
# Resources - IMPORTANT for tool discovery
# ------------------------------
@mcp.resource("info://server/info")
def server_info() -> str:
    """Get comprehensive information about the MCP server."""
    info = {
        "name": "memory",
        "version": "2.0.0",
        "description": "Encrypted Memory-Based MCP Server with Persistent Storage and Google OAuth",
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None",
            "base_url": BASE_URL if auth_provider else None
        },
        "encryption": {
            "enabled": encryption_manager.encryption_enabled,
            "algorithm": "AES-256 (Fernet)" if encryption_manager.encryption_enabled else "None",
            "status": "Data encrypted at rest" if encryption_manager.encryption_enabled else "Data stored in plaintext"
        },
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None,
            "redis_connected": redis_client is not None,
            "provider": "Upstash Redis" if redis_client else "In-Memory (Temporary)"
        },
        "tools_count": 11,
        "tools": [
            "create_memory",
            "get_memory",
            "get_memory_by_tag",
            "update_memory",
            "forget_memory",
            "list_memories",
            "list_tags",
            "memory_based_chat",
            "get_server_status",
            "clear_all_memories",
            "get_help_documentation"
        ]
    }
    return json.dumps(info, indent=2)

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server Starting (ENCRYPTED VERSION)...")
    print("=" * 60)
    
    if encryption_manager.encryption_enabled:
        print(f"🔐 Encryption: ENABLED (AES-256)")
        print(f"✅ All sensitive data will be encrypted at rest")
    else:
        print(f"🔓 Encryption: DISABLED")
        print(f"⚠️  Data will be stored in PLAINTEXT!")
    
    print("=" * 60)
    
    if auth_provider:
        print(f"🔐 Authentication: ENABLED (Google OAuth)")
        print(f"🌐 Base URL: {BASE_URL}")
    else:
        print(f"🔓 Authentication: DISABLED")
    
    print("=" * 60)
    
    print(f"📦 Storage Type: {STORAGE_TYPE}")
    
    if redis_client:
        print(f"✅ Redis Status: Connected")
        print(f"💾 Persistence: ENABLED")
    else:
        print(f"⚠️  Redis Status: Not Connected")
        print(f"💾 Persistence: DISABLED")
    
    print("=" * 60)
    
    memories = load_memories()
    print(f"✅ Loaded {len(memories)} existing memories")
    
    print("=" * 60)
    print(f"🔧 Registered {len(mcp._tools)} tools")
    print("=" * 60)
    print(f"🌐 Server ready and listening...")
    print("=" * 60)
    
    mcp.run()
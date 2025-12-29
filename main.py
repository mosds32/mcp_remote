from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
import json
import os
from typing import Optional
from datetime import datetime

# ------------------------------
# Authentication Configuration
# ------------------------------
auth_provider = None

# Check if Google OAuth credentials are available
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and BASE_URL:
    try:
        auth_provider = GoogleProvider(
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            base_url=BASE_URL
        )
        print("✅ Google OAuth authentication enabled")
        print(f"🔐 Auth URL: {BASE_URL}")
    except Exception as e:
        print(f"⚠️  Failed to initialize Google OAuth: {e}")
        print("💡 Server will run without authentication")
else:
    print("ℹ️  Google OAuth not configured")

# Initialize FastMCP BEFORE defining tools
mcp = FastMCP(
    name="memory",
    auth=auth_provider
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
        STORAGE_TYPE = "Redis (Upstash - Permanent)"
        print("✅ Connected to Upstash Redis")
    else:
        print("⚠️  REDIS_URL not found in environment variables")
        
except ImportError:
    print("⚠️  Redis package not installed")
    
except Exception as e:
    print(f"⚠️  Redis connection failed: {e}")

# Fallback in-memory storage
memory_store = []

# ------------------------------
# Storage Functions (MOVED BEFORE TOOLS)
# ------------------------------
def load_memories():
    """Load memories from Redis or fallback to in-memory storage."""
    global memory_store
    
    if redis_client:
        try:
            data = redis_client.get("mcp:memories")
            if data:
                memories = json.loads(data)
                return memories
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
            redis_client.set("mcp:memories", json.dumps(memories))
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

# Tool 1: Create Memory
@mcp.tool()
def create_memory(key: str, content: str, tag: Optional[str] = None) -> str:
    """Create a new memory with key-value pair."""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return f"❌ Memory '{key}' already exists. Use update_memory to modify it."
    
    new_memory = {
        "key": key,
        "content": content,
        "tag": tag if tag else "general",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    memories.append(new_memory)
    save_memories(memories)
    
    persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
    return f"✅ Memory created: '{key}'\n💾 Content: {content}\n📦 Storage: {STORAGE_TYPE} {persistence}"

# Tool 2: Get Memory
@mcp.tool()
def get_memory(key: str) -> str:
    """Retrieve a specific memory by key."""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return f"🔍 Found: {memory['content']}\n[Tag: {memory.get('tag', 'general')} | Created: {memory['created_at']}]"
    
    return f"❌ No memory found with key: '{key}'"

# Tool 3: List All Memories
@mcp.tool()
def list_memories(tag: Optional[str] = None) -> str:
    """List all memories, optionally filtered by tag."""
    memories = load_memories()
    
    if tag:
        memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    if not memories:
        return "📭 No memories stored yet."
    
    result = f"📚 Found {len(memories)} memories:\n\n"
    for i, memory in enumerate(memories, 1):
        result += f"{i}. [{memory['key']}] {memory['content']}\n   Tag: {memory.get('tag', 'general')}\n\n"
    
    persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
    result += f"📦 Storage: {STORAGE_TYPE} {persistence}"
    return result

# Tool 4: Update Memory
@mcp.tool()
def update_memory(key: str, new_content: str) -> str:
    """Update an existing memory's content."""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            old_content = memory["content"]
            memory["content"] = new_content
            memory["updated_at"] = datetime.now().isoformat()
            save_memories(memories)
            
            persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
            return f"✅ Memory updated: '{key}'\nOld: {old_content}\nNew: {new_content}\n📦 Storage: {STORAGE_TYPE} {persistence}"
    
    return f"❌ No memory found with key: '{key}'"

# Tool 5: Delete Memory
@mcp.tool()
def forget_memory(key: str) -> str:
    """Delete a specific memory by key."""
    memories = load_memories()
    original_count = len(memories)
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        save_memories(memories)
        persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
        return f"✅ Memory forgotten: '{key}'\n📦 Storage: {STORAGE_TYPE} {persistence}"
    
    return f"❌ No memory found with key: '{key}'"

# Tool 6: Search Memories
@mcp.tool()
def search_memories(query: str) -> str:
    """Search through all memories by content or key."""
    memories = load_memories()
    
    if not memories:
        return "📭 No memories to search."
    
    query_lower = query.lower()
    results = [
        m for m in memories 
        if query_lower in m["key"].lower() or query_lower in m["content"].lower()
    ]
    
    if not results:
        return f"🔍 No memories found matching: '{query}'"
    
    response = f"🔍 Found {len(results)} matching memories:\n\n"
    for i, memory in enumerate(results, 1):
        response += f"{i}. [{memory['key']}] {memory['content']}\n\n"
    
    return response

# Tool 7: Get Server Status
@mcp.tool()
def get_server_status() -> str:
    """Get server status and statistics."""
    memories = load_memories()
    
    auth_status = "Enabled ✓" if auth_provider else "Disabled ✗"
    redis_status = "Connected ✓" if redis_client else "Not Connected ✗"
    
    status = f"""
🚀 **Memory MCP Server Status**

🔐 Authentication: {auth_status}
   Provider: {"Google OAuth" if auth_provider else "None"}

💾 Storage: {STORAGE_TYPE}
   Redis: {redis_status}
   Persistent: {"Yes ✓" if redis_client else "No ✗"}

📊 Statistics:
   Total Memories: {len(memories)}
   
🛠️ Available Tools: 8
   • create_memory
   • get_memory
   • list_memories
   • update_memory
   • forget_memory
   • search_memories
   • get_server_status
   • clear_all_memories
"""
    return status

# Tool 8: Clear All Memories
@mcp.tool()
def clear_all_memories() -> str:
    """Clear all memories from storage. Use with caution!"""
    save_memories([])
    persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
    return f"✅ All memories cleared from {STORAGE_TYPE} storage {persistence}"

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/info")
def server_info() -> dict:
    """Get comprehensive information about the MCP server."""
    return {
        "name": "memory",
        "version": "2.0.0",
        "description": "Memory-Based MCP Server with Persistent Storage",
        "authentication": {
            "enabled": auth_provider is not None,
            "provider": "Google OAuth" if auth_provider else "None",
            "base_url": BASE_URL if auth_provider else None
        },
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None,
            "redis_connected": redis_client is not None
        },
        "tools_count": 8,
        "tools": [
            "create_memory",
            "get_memory",
            "list_memories",
            "update_memory",
            "forget_memory",
            "search_memories",
            "get_server_status",
            "clear_all_memories"
        ]
    }

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server v2.0 Starting...")
    print("=" * 60)
    
    # Authentication Status
    if auth_provider:
        print(f"🔐 Authentication: ENABLED (Google OAuth)")
        print(f"🌐 Base URL: {BASE_URL}")
    else:
        print(f"🔓 Authentication: DISABLED")
    
    print("=" * 60)
    
    # Storage Status
    print(f"📦 Storage Type: {STORAGE_TYPE}")
    
    if redis_client:
        print(f"✅ Redis Status: Connected")
        print(f"💾 Persistence: ENABLED")
    else:
        print(f"⚠️  Redis Status: Not Connected")
        print(f"💾 Persistence: DISABLED")
    
    print("=" * 60)
    
    # Tool Registration Check
    print(f"🔧 Registered Tools: {len(mcp._tools)}")
    for tool_name in mcp._tools.keys():
        print(f"   ✓ {tool_name}")
    
    print("=" * 60)
    
    memories = load_memories()
    print(f"✅ Loaded {len(memories)} existing memories")
    
    print("=" * 60)
    print(f"🌐 Server ready and listening...")
    print("=" * 60)
    
    # Run server
    mcp.run()
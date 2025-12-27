from fastmcp import FastMCP
import json
import os
from typing import Optional
from datetime import datetime

mcp = FastMCP("MCP-Server")

# ------------------------------
# Redis Storage Configuration
# ------------------------------
try:
    from key_value.aio.stores.redis import RedisStore
    
    # Redis configuration from environment variables
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
    
    # Initialize Redis store
    redis_store = RedisStore(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD
    )
    
    STORAGE_TYPE = "Redis"
    print(f"✅ Using Redis storage: {REDIS_HOST}:{REDIS_PORT}")
    
except ImportError:
    print("⚠️  Redis not available, falling back to in-memory storage")
    from key_value.aio.stores.memory import MemoryStore
    redis_store = MemoryStore()
    STORAGE_TYPE = "Memory (Development Only)"

# ------------------------------
# Storage Helper Functions
# ------------------------------
async def get_all_memories():
    """Get all memory keys from Redis."""
    try:
        result = await redis_store.list(prefix="memory:")
        if result and 'keys' in result:
            return result['keys']
        return []
    except Exception as e:
        print(f"Error listing memories: {e}")
        return []

async def load_memory(key: str):
    """Load a single memory from Redis."""
    try:
        result = await redis_store.get(f"memory:{key}")
        if result and 'value' in result:
            return json.loads(result['value'])
        return None
    except Exception as e:
        print(f"Error loading memory {key}: {e}")
        return None

async def save_memory(key: str, memory_data: dict):
    """Save a single memory to Redis."""
    try:
        await redis_store.set(
            f"memory:{key}",
            json.dumps(memory_data)
        )
        return True
    except Exception as e:
        print(f"Error saving memory {key}: {e}")
        return False

async def delete_memory(key: str):
    """Delete a memory from Redis."""
    try:
        await redis_store.delete(f"memory:{key}")
        return True
    except Exception as e:
        print(f"Error deleting memory {key}: {e}")
        return False

# ------------------------------
# Memory Management Tools
# ------------------------------
@mcp.tool
async def create_memory(key: str, content: str, tag: Optional[str] = None, metadata: Optional[dict] = None) -> str:
    """
    Create a new memory with key-value pair.
    
    Args:
        key: Unique identifier for the memory
        content: The actual content to remember
        tag: Optional tag for categorization
        metadata: Optional additional information
    """
    # Check if memory exists
    existing = await load_memory(key)
    if existing:
        return f"❌ Memory with key '{key}' already exists. Use update_memory to modify it."
    
    new_memory = {
        "key": key,
        "content": content,
        "tag": tag if tag else "general",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "metadata": metadata if metadata else {}
    }
    
    if await save_memory(key, new_memory):
        tag_info = f" [Tag: {new_memory['tag']}]" if tag else ""
        return f"✅ Memory created: '{key}'{tag_info}\n💾 Content: {content}\n🗄️  Storage: {STORAGE_TYPE}"
    else:
        return f"❌ Failed to save memory to storage."

@mcp.tool
async def get_memory(key: str) -> dict:
    """Retrieve a specific memory by key."""
    memory = await load_memory(key)
    
    if memory:
        return {
            "found": True,
            "memory": memory,
            "storage": STORAGE_TYPE
        }
    
    return {
        "found": False,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool
async def update_memory(key: str, new_content: Optional[str] = None, new_tag: Optional[str] = None, new_metadata: Optional[dict] = None) -> str:
    """Update an existing memory's content, tag, or metadata."""
    memory = await load_memory(key)
    
    if not memory:
        return f"❌ No memory found with key: '{key}'"
    
    old_tag = memory.get("tag", "general")
    updates = []
    
    if new_content:
        memory["content"] = new_content
        updates.append(f"Content updated")
    
    if new_tag:
        memory["tag"] = new_tag
        updates.append(f"Tag: {old_tag} → {new_tag}")
    
    if new_metadata:
        memory["metadata"].update(new_metadata)
        updates.append(f"Metadata updated")
    
    memory["updated_at"] = datetime.now().isoformat()
    
    if await save_memory(key, memory):
        return f"✅ Memory updated: '{key}'\n" + "\n".join(updates) + f"\n🗄️  Storage: {STORAGE_TYPE}"
    else:
        return f"❌ Failed to update memory."

@mcp.tool
async def forget_memory(key: str) -> str:
    """Delete a specific memory by key."""
    memory = await load_memory(key)
    
    if not memory:
        return f"❌ No memory found with key: '{key}'"
    
    if await delete_memory(key):
        return f"✅ Memory forgotten: '{key}'"
    else:
        return f"❌ Failed to delete memory."

@mcp.tool
async def list_memories(tag: Optional[str] = None, search: Optional[str] = None) -> dict:
    """List all memories, optionally filtered by tag or search term."""
    memory_keys = await get_all_memories()
    memories = []
    
    for full_key in memory_keys:
        # Extract the actual key (remove "memory:" prefix)
        key = full_key.replace("memory:", "")
        memory = await load_memory(key)
        if memory:
            memories.append(memory)
    
    # Apply filters
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

@mcp.tool
async def memory_based_chat(message: str, tag: Optional[str] = None) -> str:
    """
    Respond based on stored memories.
    Searches through memory content and keys for relevant information.
    """
    memory_keys = await get_all_memories()
    
    if not memory_keys:
        return "No memories stored yet. Create memories using create_memory tool."
    
    memories = []
    for full_key in memory_keys:
        key = full_key.replace("memory:", "")
        memory = await load_memory(key)
        if memory:
            memories.append(memory)
    
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
        return f"💾 {best_match['content']}\n[Source: {best_match['key']} | Storage: {STORAGE_TYPE}]"
    
    return "I don't have a memory about that yet."

@mcp.tool
async def get_server_status() -> dict:
    """Get server status and statistics."""
    memory_keys = await get_all_memories()
    memories = []
    
    for full_key in memory_keys:
        key = full_key.replace("memory:", "")
        memory = await load_memory(key)
        if memory:
            memories.append(memory)
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    return {
        "storage_type": STORAGE_TYPE,
        "redis_host": REDIS_HOST if STORAGE_TYPE == "Redis" else "N/A",
        "memories_count": len(memories),
        "memory_tags_count": len(memory_tags),
        "memory_tags": memory_tags
    }

@mcp.tool
async def clear_all_memories() -> str:
    """Clear all memories. Use with caution!"""
    memory_keys = await get_all_memories()
    deleted_count = 0
    
    for full_key in memory_keys:
        key = full_key.replace("memory:", "")
        if await delete_memory(key):
            deleted_count += 1
    
    return f"✅ Cleared {deleted_count} memories from {STORAGE_TYPE}"

# ------------------------------
# Health Check (Important for Deployment!)
# ------------------------------
@mcp.tool
async def health_check() -> dict:
    """Health check endpoint for deployment monitoring."""
    try:
        # Test storage connection
        test_key = "_health_check_test"
        await redis_store.set(test_key, "ok")
        result = await redis_store.get(test_key)
        await redis_store.delete(test_key)
        
        storage_healthy = result is not None
        
        return {
            "status": "healthy" if storage_healthy else "degraded",
            "storage": STORAGE_TYPE,
            "storage_connected": storage_healthy,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/info")
async def server_info() -> dict:
    """Get information about the server."""
    return {
        "name": "MCP-Server",
        "version": "0.6.0",
        "description": "Memory-Based MCP Server with Redis Storage",
        "storage": {
            "type": STORAGE_TYPE,
            "host": REDIS_HOST if STORAGE_TYPE == "Redis" else "N/A"
        },
        "tools": [
            "health_check",
            "memory_based_chat",
            "create_memory",
            "get_memory",
            "list_memories",
            "update_memory",
            "forget_memory",
            "clear_all_memories",
            "get_server_status"
        ]
    }

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server Starting...")
    print("=" * 60)
    print(f"🗄️  Storage: {STORAGE_TYPE}")
    if STORAGE_TYPE == "Redis":
        print(f"🔗 Redis: {REDIS_HOST}:{REDIS_PORT}")
    print("=" * 60)
    print(f"🌐 Starting server on http://0.0.0.0:8000")
    print("=" * 60)
    
    mcp.run(transport='http', host='0.0.0.0', port=8000)
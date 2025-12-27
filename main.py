from fastmcp import FastMCP
import json
import os
from typing import Optional
from datetime import datetime

mcp = FastMCP("MCP-Server")

# ------------------------------
# Redis Storage Configuration
# ------------------------------
redis_client = None
STORAGE_TYPE = "Memory (Temporary)"

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL")
    
    if REDIS_URL:
        # Connect to Upstash Redis
        redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30
        )
        # Test connection
        redis_client.ping()
        STORAGE_TYPE = "Redis (Upstash - Permanent)"
        print("✅ Connected to Upstash Redis")
        print("💾 Storage: PERMANENT - Data will persist across restarts!")
    else:
        print("⚠️  REDIS_URL not found in environment variables")
        print("📝 Using temporary in-memory storage")
        print("💡 To enable permanent storage:")
        print("   1. Sign up at https://upstash.com (FREE)")
        print("   2. Create a Redis database")
        print("   3. Add REDIS_URL environment variable")
        
except ImportError:
    print("⚠️  Redis package not installed")
    print("📝 Install with: pip install redis")
    print("💡 Using temporary in-memory storage")
    
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
                print(f"📥 Loaded {len(memories)} memories from Redis")
                return memories
            print("📝 No existing memories found in Redis")
            return []
        except Exception as e:
            print(f"⚠️  Error loading from Redis: {e}")
            print("💡 Falling back to in-memory storage")
            return memory_store
    else:
        return memory_store

def save_memories(memories):
    """Save memories to Redis or in-memory storage."""
    global memory_store
    
    if redis_client:
        try:
            redis_client.set("mcp:memories", json.dumps(memories))
            print(f"💾 Saved {len(memories)} memories to Redis (PERMANENT)")
            return True
        except Exception as e:
            print(f"❌ Error saving to Redis: {e}")
            print("💡 Falling back to in-memory storage (TEMPORARY)")
            memory_store = memories
            return False
    else:
        memory_store = memories
        print(f"💾 Saved {len(memories)} memories to memory (TEMPORARY)")
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
        
    Example:
        create_memory("user_pref", "User prefers dark mode", "preferences")
    """
    memories = load_memories()
    
    # Check if memory exists
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
        return f"✅ Memory created: '{key}'{tag_info}\n💾 Content: {content}\n📦 Storage: {STORAGE_TYPE} {persistence}"
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
        
    Example:
        get_memory("user_pref")
    """
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return {
                "found": True,
                "memory": memory,
                "storage": STORAGE_TYPE,
                "persistent": redis_client is not None
            }
    
    return {
        "found": False,
        "message": f"No memory found with key: '{key}'"
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
        
    Example:
        update_memory("user_pref", new_content="User prefers light mode")
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
                return f"✅ Memory updated: '{key}'\n" + "\n".join(updates) + f"\n📦 Storage: {STORAGE_TYPE} {persistence}"
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
        
    Example:
        forget_memory("user_pref")
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
        
    Example:
        list_memories(tag="preferences")
        list_memories(search="dark mode")
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
        "persistent": redis_client is not None
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
        
    Example:
        memory_based_chat("What does user prefer?")
        memory_based_chat("preferences", tag="user")
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
        return f"💾 {best_match['content']}\n[Source: {best_match['key']} | Tag: {best_match.get('tag', 'general')} | Storage: {STORAGE_TYPE} {persistence}]"
    
    return "I don't have a memory about that yet."

@mcp.tool()
def get_server_status() -> dict:
    """
    Get server status and statistics including storage information.
    
    Returns:
        Dictionary with server status, memory counts, and storage details
        
    Example:
        get_server_status()
    """
    memories = load_memories()
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    redis_status = "Connected ✓" if redis_client else "Not Connected ✗"
    
    return {
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
        
    Example:
        clear_all_memories()
    """
    if save_memories([]):
        persistence = "✓ PERMANENT" if redis_client else "⚠ TEMPORARY"
        return f"✅ All memories cleared from {STORAGE_TYPE} storage {persistence}"
    else:
        return f"⚠️  Error clearing memories"

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/info")
def server_info() -> dict:
    """Get comprehensive information about the MCP server."""
    return {
        "name": "MCP-Server",
        "version": "1.0.0",
        "description": "Memory-Based MCP Server with Persistent Storage",
        "storage": {
            "type": STORAGE_TYPE,
            "persistent": redis_client is not None,
            "redis_connected": redis_client is not None,
            "provider": "Upstash Redis" if redis_client else "In-Memory (Temporary)"
        },
        "tools": [
            "create_memory",
            "get_memory",
            "update_memory",
            "forget_memory",
            "list_memories",
            "memory_based_chat",
            "get_server_status",
            "clear_all_memories"
        ],
        "setup_instructions": {
            "step_1": "Sign up at https://upstash.com (FREE tier available)",
            "step_2": "Create a new Redis database",
            "step_3": "Copy the REDIS_URL from database details",
            "step_4": "Add REDIS_URL to environment variables",
            "step_5": "Redeploy your server",
            "note": "Free tier includes 10,000 commands/day with permanent storage"
        } if not redis_client else {
            "status": "✅ Redis configured - using permanent storage"
        }
    }

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server Starting...")
    print("=" * 60)
    print(f"📦 Storage Type: {STORAGE_TYPE}")
    
    if redis_client:
        print(f"✅ Redis Status: Connected")
        print(f"💾 Persistence: ENABLED - Data survives restarts!")
    else:
        print(f"⚠️  Redis Status: Not Connected")
        print(f"💾 Persistence: DISABLED - Data is temporary!")
        print(f"")
        print(f"📝 To enable permanent storage:")
        print(f"   1. Visit: https://upstash.com")
        print(f"   2. Create free Redis database")
        print(f"   3. Set REDIS_URL environment variable")
        print(f"   4. Restart server")
    
    print("=" * 60)
    
    memories = load_memories()
    print(f"✅ Loaded {len(memories)} existing memories")
    
    print("=" * 60)
    print(f"🌐 Server ready and listening...")
    print("=" * 60)
    
    # Run with default settings (FastMCP handles transport automatically)
    mcp.run()
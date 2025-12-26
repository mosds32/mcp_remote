from fastmcp import FastMCP
import json
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

mcp = FastMCP("MCP-Server")

# ------------------------------
# Cloud-Friendly Configuration
# ------------------------------
MEMORY_DIR = os.getenv("MEMORY_DIR", "/data")
MEMORY_FILE = Path(MEMORY_DIR) / "memories.json"

def load_memories():
    """Load memories from file, handling empty or missing files."""
    try:
        if MEMORY_FILE.exists():
            with open(MEMORY_FILE, "r") as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        else:
            save_memories([])
            return []
    except Exception as e:
        print(f"⚠️ Error loading memories: {e}")
        return []

def save_memories(memories):
    """Save memories with error handling."""
    try:
        MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        with open(MEMORY_FILE, "w") as f:
            json.dump(memories, f, indent=4)
        print(f"✅ Memories saved to {MEMORY_FILE}")
        return True
    except PermissionError:
        print(f"❌ Permission denied: Cannot write to {MEMORY_FILE}")
        print(f"💡 Tip: Set MEMORY_DIR environment variable to a writable directory")
        return False
    except Exception as e:
        print(f"❌ Error saving memories: {e}")
        return False

# ------------------------------
# Memory-Based Chat Tool
# ------------------------------
@mcp.tool
def memory_based_chat(message: str, tag: Optional[str] = None) -> str:
    """
    Respond based on stored memories.
    Searches through memory content and keys for relevant information.
    Optionally filter by tag.
    """
    memories = load_memories()
    if not memories:
        return "No memories stored yet. Create memories using create_memory tool."
    
    # Filter by tag if specified
    if tag:
        memories = [m for m in memories if m.get("tag", "").lower() == tag.lower()]
        if not memories:
            return f"No memories found with tag: '{tag}'"
    
    message_lower = message.lower()
    
    # Search for relevant memories
    relevant_memories = []
    for memory in memories:
        # Check if message contains the key or content contains message keywords
        if (message_lower in memory["key"].lower() or 
            message_lower in memory["content"].lower() or
            memory["key"].lower() in message_lower):
            relevant_memories.append(memory)
    
    if relevant_memories:
        # Return the most recently updated memory
        relevant_memories.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        best_match = relevant_memories[0]
        return f"📝 {best_match['content']}\n[Source: {best_match['key']}]"
    
    return "I don't have a memory about that yet."

# ------------------------------
# Memory Management Tools
# ------------------------------
@mcp.tool
def create_memory(key: str, content: str, tag: Optional[str] = None, metadata: Optional[dict] = None) -> str:
    """
    Create a new memory with key-value pair.
    
    Args:
        key: Unique identifier for the memory
        content: The actual content to remember
        tag: Optional tag for categorization (e.g., 'preferences', 'facts', 'context')
        metadata: Optional additional information as a dictionary
    """
    memories = load_memories()
    
    # Check if memory with same key exists
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
        return f"✅ Memory created: '{key}'{tag_info}\n📝 Content: {content}"
    else:
        return f"⚠️ Memory created in-memory but could not be saved to disk."

@mcp.tool
def get_memory(key: str) -> dict:
    """
    Retrieve a specific memory by key.
    """
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return {
                "found": True,
                "memory": memory
            }
    
    return {
        "found": False,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool
def get_memory_by_tag(tag: str) -> dict:
    """
    Get all memories with a specific tag.
    """
    memories = load_memories()
    tagged_memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    return {
        "tag": tag,
        "count": len(tagged_memories),
        "memories": tagged_memories
    }

@mcp.tool
def list_memories(tag: Optional[str] = None, search: Optional[str] = None) -> dict:
    """
    List all memories, optionally filtered by tag or search term.
    
    Args:
        tag: Filter by specific tag
        search: Search in keys and content
    """
    memories = load_memories()
    
    # Filter by tag if specified
    if tag:
        memories = [m for m in memories if m.get("tag", "general").lower() == tag.lower()]
    
    # Search in keys and content if specified
    if search:
        search_lower = search.lower()
        memories = [
            m for m in memories 
            if search_lower in m["key"].lower() or search_lower in m["content"].lower()
        ]
    
    return {
        "total_count": len(memories),
        "memories": memories
    }

@mcp.tool
def update_memory(key: str, new_content: Optional[str] = None, new_tag: Optional[str] = None, new_metadata: Optional[dict] = None) -> str:
    """
    Update an existing memory's content, tag, or metadata.
    """
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            old_content = memory["content"]
            old_tag = memory.get("tag", "general")
            
            updates = []
            if new_content:
                memory["content"] = new_content
                updates.append(f"Content: {old_content[:50]}... → {new_content[:50]}...")
            
            if new_tag:
                memory["tag"] = new_tag
                updates.append(f"Tag: {old_tag} → {new_tag}")
            
            if new_metadata:
                memory["metadata"].update(new_metadata)
                updates.append(f"Metadata updated")
            
            memory["updated_at"] = datetime.now().isoformat()
            
            if save_memories(memories):
                return f"✅ Memory updated: '{key}'\n" + "\n".join(updates)
            else:
                return f"⚠️ Memory updated in-memory but could not be saved to disk."
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool
def forget_memory(key: str) -> str:
    """
    Delete a specific memory by key.
    """
    memories = load_memories()
    original_count = len(memories)
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        if save_memories(memories):
            return f"✅ Memory forgotten: '{key}'"
        else:
            return f"⚠️ Memory deleted from in-memory but could not be saved to disk."
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool
def forget_memories_by_tag(tag: str) -> str:
    """
    Delete all memories with a specific tag.
    """
    memories = load_memories()
    original_count = len(memories)
    memories = [m for m in memories if m.get("tag", "general").lower() != tag.lower()]
    
    deleted_count = original_count - len(memories)
    
    if deleted_count > 0:
        if save_memories(memories):
            return f"✅ Forgotten {deleted_count} memory/memories with tag: '{tag}'"
        else:
            return f"⚠️ Memories deleted from in-memory but could not be saved to disk."
    
    return f"❌ No memories found with tag: '{tag}'"

@mcp.tool
def list_memory_tags() -> dict:
    """
    Get all unique memory tags and their counts.
    """
    memories = load_memories()
    tags = {}
    
    for memory in memories:
        tag = memory.get("tag", "general")
        tags[tag] = tags.get(tag, 0) + 1
    
    return {
        "total_tags": len(tags),
        "tags": tags
    }

@mcp.tool
def clear_all_memories() -> str:
    """
    Clear all memories. Use with caution!
    """
    if save_memories([]):
        return f"✅ All memories cleared"
    else:
        return f"⚠️ Memories cleared in-memory but could not be saved to disk."

@mcp.tool
def search_memories(query: str) -> dict:
    """
    Search memories by content or key.
    """
    memories = load_memories()
    query_lower = query.lower()
    
    results = [
        m for m in memories 
        if query_lower in m["key"].lower() or query_lower in m["content"].lower()
    ]
    
    return {
        "query": query,
        "results_count": len(results),
        "results": results
    }

@mcp.tool
def get_server_status() -> dict:
    """Get server status including file permissions and tag statistics."""
    memories = load_memories()
    
    # Calculate memory tags
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    status = {
        "memory_file_path": str(MEMORY_FILE),
        "memory_file_exists": MEMORY_FILE.exists(),
        "memories_count": len(memories),
        "memory_tags_count": len(memory_tags),
        "memory_tags": memory_tags,
        "can_write": False
    }
    
    # Test write permissions
    try:
        test_file = MEMORY_FILE.parent / ".write_test"
        test_file.touch()
        test_file.unlink()
        status["can_write"] = True
    except:
        status["can_write"] = False
        status["error"] = "No write permissions"
    
    return status

@mcp.tool
def get_help_documentation() -> dict:
    """
    Get comprehensive help documentation for all tools.
    """
    return {
        "server_name": "MCP-Server with Memory",
        "version": "0.4.0",
        "categories": {
            "Memory Management": {
                "tools": [
                    "memory_based_chat",
                    "create_memory",
                    "get_memory",
                    "get_memory_by_tag",
                    "list_memories",
                    "update_memory",
                    "forget_memory",
                    "forget_memories_by_tag",
                    "list_memory_tags",
                    "clear_all_memories",
                    "search_memories"
                ],
                "description": "Store, retrieve, and chat with long-term memory"
            },
            "Server Status": {
                "tools": ["get_server_status", "get_help_documentation"],
                "description": "Monitor server health and get help"
            }
        },
        "usage_examples": {
            "memory": {
                "create": "create_memory('user_name', 'Ali', 'profile')",
                "retrieve": "get_memory('user_name')",
                "search": "search_memories('Ali')",
                "chat": "memory_based_chat('what is my name?')"
            }
        }
    }

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/info")
def server_info() -> dict:
    """Get information about the server."""
    info = {
        "name": "MCP-Server",
        "version": "0.4.0",
        "description": "Memory-Based MCP Server with Tags and Chat",
        "tools": {
            "memory": [
                "memory_based_chat",
                "create_memory",
                "get_memory",
                "get_memory_by_tag",
                "list_memories",
                "update_memory",
                "forget_memory",
                "forget_memories_by_tag",
                "list_memory_tags",
                "clear_all_memories",
                "search_memories"
            ],
            "system": [
                "get_server_status",
                "get_help_documentation"
            ]
        },
        "resources": ["info://server/info"],
        "author": "Your Name",
        "files": {
            "memories": str(MEMORY_FILE)
        },
        "deployment_notes": "Set MEMORY_DIR env variable for custom storage location",
        "features": [
            "Memory-based chat responses",
            "Tag-based memory categorization",
            "Memory search functionality",
            "Timestamp tracking for memories",
            "Metadata support for memories",
            "Filter memories by tag"
        ]
    }
    return info

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server Starting...")
    print("=" * 60)
    print(f"📁 Memory file: {MEMORY_FILE}")
    print(f"📝 Loading data...")
    
    memories = load_memories()
    print(f"✅ Loaded {len(memories)} memories")
    
    # Test write permissions
    test_memories = memories if memories else []
    memories_saved = save_memories(test_memories)
    
    if memories_saved:
        print(f"✅ Write permissions OK")
    else:
        print(f"⚠️  Limited write permissions")
        print(f"⚠️  Memories will be stored in memory only")
        print(f"💡 Set MEMORY_DIR environment variable to a writable directory")
    
    print("=" * 60)
    print(f"🌐 Starting server on http://0.0.0.0:8000")
    print("=" * 60)
    
    mcp.run(transport='http', host='0.0.0.0', port=8000)
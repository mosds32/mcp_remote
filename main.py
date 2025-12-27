from fastmcp import FastMCP
import json
import os
from typing import Optional
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

# Firebase imports
import firebase_admin
from firebase_admin import credentials, firestore

mcp = FastMCP("MCP-Server")

# ------------------------------
# Firebase Configuration
# ------------------------------
FIREBASE_CREDENTIALS_PATH = os.getenv("FIREBASE_CREDENTIALS", "firebase-credentials.json")

# Initialize Firebase (required - will fail if not configured)
try:
    if not firebase_admin._apps:
        # Check if credentials are provided as JSON string in environment variable
        firebase_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
        if firebase_json:
            # Parse JSON string from environment variable
            cred_dict = json.loads(firebase_json)
            cred = credentials.Certificate(cred_dict)
            print("🔑 Using Firebase credentials from environment variable")
        else:
            # Fallback to file-based credentials
            cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
            print("📄 Using Firebase credentials from file")
        
        firebase_admin.initialize_app(cred)
    
    db = firestore.client()
    print("✅ Firebase initialized successfully")
except Exception as e:
    print(f"❌ Firebase initialization failed: {e}")
    raise RuntimeError("Firebase is required for this server. Please configure Firebase credentials.")

# ------------------------------
# Storage Functions
# ------------------------------
def load_memories():
    """Load memories from Firebase."""
    try:
        memories_ref = db.collection('memories')
        docs = memories_ref.stream()
        memories = []
        for doc in docs:
            memory_data = doc.to_dict()
            memory_data['id'] = doc.id
            memories.append(memory_data)
        return memories
    except Exception as e:
        print(f"⚠️  Error loading from Firebase: {e}")
        return []

def save_memory_to_firebase(memory_data):
    """Save a single memory to Firebase."""
    try:
        memories_ref = db.collection('memories')
        # Use key as document ID
        doc_ref = memories_ref.document(memory_data['key'])
        doc_ref.set(memory_data)
        return True
    except Exception as e:
        print(f"❌ Error saving to Firebase: {e}")
        return False

def delete_memory_from_firebase(key):
    """Delete a memory from Firebase."""
    try:
        memories_ref = db.collection('memories')
        doc_ref = memories_ref.document(key)
        doc_ref.delete()
        return True
    except Exception as e:
        print(f"❌ Error deleting from Firebase: {e}")
        return False

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
        tag: Optional tag for categorization
        metadata: Optional additional information
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
    
    if save_memory_to_firebase(new_memory):
        tag_info = f" [Tag: {new_memory['tag']}]" if tag else ""
        return f"✅ Memory created in Firebase: '{key}'{tag_info}\n💾 Content: {content}"
    else:
        return f"❌ Failed to save to Firebase"

@mcp.tool
def get_memory(key: str) -> dict:
    """Retrieve a specific memory by key."""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return {
                "found": True,
                "memory": memory,
                "storage": "Firebase"
            }
    
    return {
        "found": False,
        "message": f"No memory found with key: '{key}'"
    }

@mcp.tool
def update_memory(key: str, new_content: Optional[str] = None, new_tag: Optional[str] = None, new_metadata: Optional[dict] = None) -> str:
    """Update an existing memory's content, tag, or metadata."""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            old_content = memory["content"]
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
            
            if save_memory_to_firebase(memory):
                return f"✅ Memory updated in Firebase: '{key}'\n" + "\n".join(updates)
            else:
                return f"❌ Failed to update in Firebase"
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool
def forget_memory(key: str) -> str:
    """Delete a specific memory by key."""
    memories = load_memories()
    found = False
    for memory in memories:
        if memory["key"].lower() == key.lower():
            found = True
            break
    
    if found:
        if delete_memory_from_firebase(key):
            return f"✅ Memory forgotten from Firebase: '{key}'"
        else:
            return f"❌ Failed to delete from Firebase"
    else:
        return f"❌ No memory found with key: '{key}'"

@mcp.tool
def list_memories(tag: Optional[str] = None, search: Optional[str] = None) -> dict:
    """List all memories, optionally filtered by tag or search term."""
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
        "storage": "Firebase"
    }

@mcp.tool
def memory_based_chat(message: str, tag: Optional[str] = None) -> str:
    """
    Respond based on stored memories.
    Searches through memory content and keys for relevant information.
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
        return f"💾 {best_match['content']}\n[Source: {best_match['key']} | Storage: Firebase]"
    
    return "I don't have a memory about that yet."

@mcp.tool
def get_server_status() -> dict:
    """Get server status including Firebase connection and statistics."""
    memories = load_memories()
    
    memory_tags = {}
    for memory in memories:
        tag = memory.get("tag", "general")
        memory_tags[tag] = memory_tags.get(tag, 0) + 1
    
    return {
        "storage_type": "Firebase",
        "firebase_enabled": True,
        "firebase_initialized": True,
        "memories_count": len(memories),
        "memory_tags_count": len(memory_tags),
        "memory_tags": memory_tags,
    }

@mcp.tool
def clear_all_memories() -> str:
    """Clear all memories. Use with caution!"""
    try:
        memories = load_memories()
        batch = db.batch()
        memories_ref = db.collection('memories')
        
        for memory in memories:
            doc_ref = memories_ref.document(memory['key'])
            batch.delete(doc_ref)
        
        batch.commit()
        return f"✅ All {len(memories)} memories cleared from Firebase"
    except Exception as e:
        return f"❌ Error clearing Firebase: {e}"

# ------------------------------
# Resources
# ------------------------------
@mcp.resource("info://server/info")
def server_info() -> dict:
    """Get information about the server."""
    return {
        "name": "MCP-Server with Firebase",
        "version": "1.0.0",
        "description": "Memory-Based MCP Server with Firebase Storage",
        "storage": {
            "type": "Firebase",
            "firebase_enabled": True,
            "firebase_initialized": True
        },
        "tools": [
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
    print(f"💾 Storage: Firebase (Firestore) ONLY")
    
    try:
        memories = load_memories()
        print(f"✅ Loaded {len(memories)} memories from Firebase")
    except Exception as e:
        print(f"⚠️  Error loading from Firebase: {e}")
    
    print("=" * 60)
    print(f"🌐 Starting server on http://0.0.0.0:8000")
    print("=" * 60)
    
    mcp.run(transport='http', host='0.0.0.0', port=8000)
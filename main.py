from fastmcp import FastMCP
import json
import os
from pathlib import Path
from typing import Optional
from datetime import datetime
from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
import secrets

mcp = FastMCP("MCP-Server")

# ------------------------------
# Google OAuth Configuration
# ------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

# Auto-detect environment
BASE_URL = os.getenv("BASE_URL", "https://solar-violet-gazelle.fastmcp.app")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"{BASE_URL}/auth/callback")

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Session storage for authenticated users
authenticated_users = {}

# ------------------------------
# Authentication Middleware
# ------------------------------
async def get_current_user(request: Request):
    """Verify user is authenticated."""
    session_token = request.cookies.get("session_token")
    
    if not session_token or session_token not in authenticated_users:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return authenticated_users[session_token]

# ------------------------------
# Auth Routes
# ------------------------------
@mcp.custom_route("/")
async def home(request: Request):
    """Home page with login link."""
    session_token = request.cookies.get("session_token")
    is_authenticated = session_token and session_token in authenticated_users
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Memory Server</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .card {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{ color: #333; }}
            .btn {{
                display: inline-block;
                padding: 12px 24px;
                background: #4285f4;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 10px 5px;
            }}
            .btn:hover {{ background: #357ae8; }}
            .status {{ 
                padding: 10px;
                border-radius: 5px;
                margin: 10px 0;
            }}
            .success {{ background: #d4edda; color: #155724; }}
            .info {{ background: #d1ecf1; color: #0c5460; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🧠 MCP Memory Server</h1>
            {"<div class='status success'>✅ You are logged in!</div>" if is_authenticated else ""}
            <p>A secure memory server with Google Authentication</p>
            
            {"<a href='/dashboard' class='btn'>Go to Dashboard</a>" if is_authenticated else "<a href='/login' class='btn'>Login with Google</a>"}
            {"<a href='/logout' class='btn' style='background:#dc3545'>Logout</a>" if is_authenticated else ""}
            
            <div class='status info'>
                <strong>Server URL:</strong> {BASE_URL}<br>
                <strong>MCP Endpoint:</strong> {BASE_URL}/mcp
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@mcp.custom_route("/login")
async def login(request: Request):
    """Initiate Google OAuth login."""
    redirect_uri = REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

@mcp.custom_route("/auth/callback")
async def auth_callback(request: Request):
    """Handle OAuth callback."""
    try:
        token = await oauth.google.authorize_access_token(request)
        user = token.get('userinfo')
        
        if user:
            # Create session token
            session_token = secrets.token_urlsafe(32)
            authenticated_users[session_token] = {
                "email": user.get("email"),
                "name": user.get("name"),
                "picture": user.get("picture"),
                "authenticated_at": datetime.now().isoformat()
            }
            
            # Set cookie and redirect
            response = RedirectResponse(url="/dashboard")
            response.set_cookie(
                key="session_token",
                value=session_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=86400  # 24 hours
            )
            return response
        
        return JSONResponse({"error": "Authentication failed"}, status_code=400)
    
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

@mcp.custom_route("/logout")
async def logout(request: Request):
    """Logout user."""
    session_token = request.cookies.get("session_token")
    if session_token and session_token in authenticated_users:
        del authenticated_users[session_token]
    
    response = RedirectResponse(url="/")
    response.delete_cookie("session_token")
    return response

@mcp.custom_route("/me")
async def get_user_info(request: Request, user: dict = Depends(get_current_user)):
    """Get current user information."""
    return JSONResponse(user)

@mcp.custom_route("/dashboard")
async def dashboard(request: Request, user: dict = Depends(get_current_user)):
    """Protected dashboard route."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - MCP Memory Server</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .card {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }}
            .user-info {{
                display: flex;
                align-items: center;
                gap: 15px;
                margin-bottom: 20px;
            }}
            .user-info img {{
                border-radius: 50%;
                width: 60px;
                height: 60px;
            }}
            h1, h2 {{ color: #333; }}
            .btn {{
                display: inline-block;
                padding: 10px 20px;
                background: #4285f4;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 5px;
            }}
            .btn-danger {{ background: #dc3545; }}
            code {{
                background: #f4f4f4;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 0.9em;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="user-info">
                <img src="{user.get('picture', '')}" alt="Profile">
                <div>
                    <h1>Welcome, {user.get('name', 'User')}!</h1>
                    <p>{user.get('email', '')}</p>
                </div>
            </div>
            <a href="/" class="btn">Home</a>
            <a href="/logout" class="btn btn-danger">Logout</a>
        </div>
        
        <div class="card">
            <h2>🔌 MCP Connection</h2>
            <p>Use this URL to connect your MCP client:</p>
            <code>{BASE_URL}/mcp</code>
            
            <h3>Available Tools:</h3>
            <ul>
                <li><strong>memory_based_chat</strong> - Chat with your memories</li>
                <li><strong>create_memory</strong> - Store new memories</li>
                <li><strong>get_memory</strong> - Retrieve specific memory</li>
                <li><strong>list_memories</strong> - List all memories</li>
                <li><strong>update_memory</strong> - Update existing memory</li>
                <li><strong>forget_memory</strong> - Delete a memory</li>
                <li><strong>search_memories</strong> - Search through memories</li>
            </ul>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ------------------------------
# Cloud-Friendly Configuration
# ------------------------------
MEMORY_DIR = os.getenv("MEMORY_DIR", "/tmp")
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
# Memory-Based Chat Tool (Protected)
# ------------------------------
@mcp.tool(dependencies=[Depends(get_current_user)])
def memory_based_chat(message: str, tag: Optional[str] = None) -> str:
    """
    Respond based on stored memories.
    Searches through memory content and keys for relevant information.
    Optionally filter by tag.
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
        return f"📝 {best_match['content']}\n[Source: {best_match['key']}]"
    
    return "I don't have a memory about that yet."

# ------------------------------
# Memory Management Tools (Protected)
# ------------------------------
@mcp.tool(dependencies=[Depends(get_current_user)])
def create_memory(key: str, content: str, tag: Optional[str] = None, metadata: Optional[dict] = None) -> str:
    """Create a new memory with key-value pair."""
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
        return f"✅ Memory created: '{key}'{tag_info}\n📝 Content: {content}"
    else:
        return f"⚠️ Memory created in-memory but could not be saved to disk."

@mcp.tool(dependencies=[Depends(get_current_user)])
def get_memory(key: str) -> dict:
    """Retrieve a specific memory by key."""
    memories = load_memories()
    
    for memory in memories:
        if memory["key"].lower() == key.lower():
            return {"found": True, "memory": memory}
    
    return {"found": False, "message": f"No memory found with key: '{key}'"}

@mcp.tool(dependencies=[Depends(get_current_user)])
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
    
    return {"total_count": len(memories), "memories": memories}

@mcp.tool(dependencies=[Depends(get_current_user)])
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

@mcp.tool(dependencies=[Depends(get_current_user)])
def forget_memory(key: str) -> str:
    """Delete a specific memory by key."""
    memories = load_memories()
    original_count = len(memories)
    memories = [m for m in memories if m["key"].lower() != key.lower()]
    
    if len(memories) < original_count:
        if save_memories(memories):
            return f"✅ Memory forgotten: '{key}'"
        else:
            return f"⚠️ Memory deleted from in-memory but could not be saved to disk."
    
    return f"❌ No memory found with key: '{key}'"

@mcp.tool(dependencies=[Depends(get_current_user)])
def search_memories(query: str) -> dict:
    """Search memories by content or key."""
    memories = load_memories()
    query_lower = query.lower()
    
    results = [
        m for m in memories 
        if query_lower in m["key"].lower() or query_lower in m["content"].lower()
    ]
    
    return {"query": query, "results_count": len(results), "results": results}

@mcp.tool
def get_server_status() -> dict:
    """Get server status including authentication info."""
    memories = load_memories()
    
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
        "authenticated_users": len(authenticated_users),
        "auth_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
    }
    
    return status

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 FastMCP Memory Server with Google Auth Starting...")
    print("=" * 60)
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        print("⚠️  WARNING: Google OAuth not configured!")
        print("💡 Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")
    else:
        print("✅ Google OAuth configured")
    
    print(f"📁 Memory file: {MEMORY_FILE}")
    memories = load_memories()
    print(f"✅ Loaded {len(memories)} memories")
    print("=" * 60)
    print(f"🌐 Server URL: {BASE_URL}")
    print(f"🔐 Login at: {BASE_URL}/login")
    print(f"🔌 MCP Endpoint: {BASE_URL}/mcp")
    print("=" * 60)
    
    # Add session middleware
    mcp.app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
    
    mcp.run(transport='http', host='0.0.0.0', port=8000)
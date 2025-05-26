from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS
import base64
import hashlib
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import logging
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
ENCRYPTION_PASSWORD = os.environ.get('ENCRYPTION_PASSWORD', 'sreaty-tv-encryption-key')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')  # Change this in production

class StreamEncryption:
    def __init__(self, password: str):
        self.password = password.encode()
        
    def _get_fernet(self, salt: bytes) -> Fernet:
        """Generate Fernet cipher with given salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return Fernet(key)
    
    def encrypt_link(self, original_link: str) -> str:
        """Encrypt M3U8 link with timestamp and salt"""
        try:
            # Add timestamp for expiration (24 hours)
            expiry = datetime.now() + timedelta(hours=24)
            
            # Create data structure
            data = {
                'link': original_link,
                'expiry': expiry.isoformat(),
                'created': datetime.now().isoformat()
            }
            
            # Generate random salt
            salt = secrets.token_bytes(16)
            
            # Encrypt data
            fernet = self._get_fernet(salt)
            encrypted_data = fernet.encrypt(json.dumps(data).encode())
            
            # Combine salt + encrypted data and encode
            combined = salt + encrypted_data
            encrypted_link = base64.urlsafe_b64encode(combined).decode()
            
            logger.info(f"Link encrypted successfully. Expires: {expiry}")
            return encrypted_link
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    def decrypt_link(self, encrypted_link: str) -> str:
        """Decrypt M3U8 link and validate expiration"""
        try:
            # Decode the encrypted link
            combined = base64.urlsafe_b64decode(encrypted_link.encode())
            
            # Extract salt and encrypted data
            salt = combined[:16]
            encrypted_data = combined[16:]
            
            # Decrypt data
            fernet = self._get_fernet(salt)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Parse data
            data = json.loads(decrypted_data.decode())
            
            # Check expiration
            expiry = datetime.fromisoformat(data['expiry'])
            if datetime.now() > expiry:
                raise ValueError("Link has expired")
            
            logger.info("Link decrypted successfully")
            return data['link']
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise

# Initialize encryption handler
encryption_handler = StreamEncryption(ENCRYPTION_PASSWORD)

# In-memory storage (in production, use a proper database)
streams_db = {}
request_cache = {}

def rate_limit_check(ip: str, limit: int = 10, window: int = 60) -> bool:
    """Simple rate limiting"""
    now = datetime.now()
    
    if ip not in request_cache:
        request_cache[ip] = []
    
    # Remove old requests
    request_cache[ip] = [req_time for req_time in request_cache[ip] 
                        if now - req_time < timedelta(seconds=window)]
    
    # Check limit
    if len(request_cache[ip]) >= limit:
        return False
    
    # Add current request
    request_cache[ip].append(now)
    return True

def load_streams():
    """Load streams from file if exists"""
    try:
        if os.path.exists('streams.json'):
            with open('streams.json', 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading streams: {e}")
    return {}

def save_streams():
    """Save streams to file"""
    try:
        with open('streams.json', 'w') as f:
            json.dump(streams_db, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving streams: {e}")

# Load existing streams on startup
streams_db = load_streams()

@app.route('/')
def index():
    """Serve the main HTML page"""
    with open('sreaty_tv_enhanced.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    return html_content

@app.route('/api/streams', methods=['GET'])
def get_streams():
    """Get all available streams for users"""
    try:
        # Return only public stream info (no actual links)
        public_streams = {}
        for stream_id, stream_data in streams_db.items():
            if stream_data.get('active', True):
                public_streams[stream_id] = {
                    'id': stream_id,
                    'name': stream_data['name'],
                    'description': stream_data.get('description', ''),
                    'created': stream_data.get('created', ''),
                    'category': stream_data.get('category', 'General')
                }
        
        return jsonify({
            'success': True,
            'streams': public_streams
        })
    except Exception as e:
        logger.error(f"Error getting streams: {e}")
        return jsonify({'error': 'Failed to get streams'}), 500

@app.route('/api/stream/<stream_id>', methods=['GET'])
def get_stream_link(stream_id):
    """Get encrypted link for a specific stream"""
    try:
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit_check(client_ip, limit=20, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        if stream_id not in streams_db:
            return jsonify({'error': 'Stream not found'}), 404
        
        stream_data = streams_db[stream_id]
        if not stream_data.get('active', True):
            return jsonify({'error': 'Stream is not active'}), 404
        
        # Encrypt the original link
        encrypted_link = encryption_handler.encrypt_link(stream_data['link'])
        
        return jsonify({
            'success': True,
            'encrypted_link': encrypted_link,
            'stream_name': stream_data['name']
        })
        
    except Exception as e:
        logger.error(f"Error getting stream link: {e}")
        return jsonify({'error': 'Failed to get stream link'}), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if password == ADMIN_PASSWORD:
            # In production, use proper JWT tokens
            token = base64.b64encode(f"admin:{datetime.now().isoformat()}".encode()).decode()
            return jsonify({
                'success': True,
                'token': token
            })
        else:
            return jsonify({'error': 'Invalid password'}), 401
            
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/admin/streams', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin_streams():
    """Admin endpoint for stream management"""
    try:
        # Simple token validation (use proper JWT in production)
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit_check(client_ip, limit=10, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        if request.method == 'GET':
            # Get all streams for admin
            return jsonify({
                'success': True,
                'streams': streams_db
            })
        
        elif request.method == 'POST':
            # Add new stream
            data = request.get_json()
            
            required_fields = ['name', 'link']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'error': f'Missing {field}'}), 400
            
            # Validate M3U8 link
            link = data['link'].strip()
            if not link.startswith(('http://', 'https://')):
                return jsonify({'error': 'Invalid link format'}), 400
            
            # Generate unique ID
            stream_id = str(uuid.uuid4())
            
            # Create stream data
            stream_data = {
                'id': stream_id,
                'name': data['name'].strip(),
                'link': link,
                'description': data.get('description', '').strip(),
                'category': data.get('category', 'General').strip(),
                'active': data.get('active', True),
                'created': datetime.now().isoformat(),
                'updated': datetime.now().isoformat()
            }
            
            streams_db[stream_id] = stream_data
            save_streams()
            
            logger.info(f"New stream added: {stream_data['name']}")
            
            return jsonify({
                'success': True,
                'stream': stream_data
            })
        
        elif request.method == 'PUT':
            # Update stream
            data = request.get_json()
            stream_id = data.get('id')
            
            if not stream_id or stream_id not in streams_db:
                return jsonify({'error': 'Stream not found'}), 404
            
            # Update stream data
            stream_data = streams_db[stream_id]
            
            if 'name' in data:
                stream_data['name'] = data['name'].strip()
            if 'link' in data:
                link = data['link'].strip()
                if not link.startswith(('http://', 'https://')):
                    return jsonify({'error': 'Invalid link format'}), 400
                stream_data['link'] = link
            if 'description' in data:
                stream_data['description'] = data['description'].strip()
            if 'category' in data:
                stream_data['category'] = data['category'].strip()
            if 'active' in data:
                stream_data['active'] = data['active']
            
            stream_data['updated'] = datetime.now().isoformat()
            save_streams()
            
            logger.info(f"Stream updated: {stream_data['name']}")
            
            return jsonify({
                'success': True,
                'stream': stream_data
            })
        
        elif request.method == 'DELETE':
            # Delete stream
            data = request.get_json()
            stream_id = data.get('id')
            
            if not stream_id or stream_id not in streams_db:
                return jsonify({'error': 'Stream not found'}), 404
            
            stream_name = streams_db[stream_id]['name']
            del streams_db[stream_id]
            save_streams()
            
            logger.info(f"Stream deleted: {stream_name}")
            
            return jsonify({
                'success': True,
                'message': 'Stream deleted successfully'
            })
            
    except Exception as e:
        logger.error(f"Admin streams error: {e}")
        return jsonify({'error': 'Operation failed'}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_link():
    """Decrypt M3U8 links for streaming"""
    try:
        # Rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit_check(client_ip, limit=20, window=60):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        
        if not data or 'encrypted_link' not in data:
            return jsonify({'error': 'Missing encrypted_link parameter'}), 400
        
        encrypted_link = data['encrypted_link'].strip()
        quality = data.get('quality', 'auto')
        
        # Decrypt the link
        decrypted_link = encryption_handler.decrypt_link(encrypted_link)
        
        logger.info(f"Link decrypted for IP: {client_ip}, Quality: {quality}")
        
        return jsonify({
            'success': True,
            'decrypted_link': decrypted_link,
            'quality': quality
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Decryption API error: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'Sreaty TV Backend',
        'streams_count': len(streams_db)
    })

@app.route('/admin')
def admin_panel():
    """Admin panel for stream management"""
    admin_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sreaty TV - Admin Panel</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                margin: 0;
                color: #fff;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
            }
            .logo {
                font-size: 2.5rem;
                font-weight: bold;
                background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .login-panel, .admin-content {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 30px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                margin-bottom: 20px;
            }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; font-weight: bold; }
            input, textarea, select { 
                width: 100%; 
                padding: 12px; 
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.1);
                color: #fff;
                font-size: 16px;
            }
            input::placeholder, textarea::placeholder {
                color: rgba(255, 255, 255, 0.6);
            }
            button { 
                background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
                color: white; 
                padding: 12px 24px; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer;
                font-size: 16px;
                margin-right: 10px;
                margin-bottom: 10px;
            }
            button:hover { 
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(78, 205, 196, 0.4);
            }
            .btn-secondary {
                background: rgba(255, 255, 255, 0.2);
            }
            .btn-danger {
                background: linear-gradient(45deg, #ff4757, #ff3742);
            }
            .streams-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            .stream-card {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            .stream-title {
                font-size: 1.2rem;
                font-weight: bold;
                margin-bottom: 10px;
            }
            .stream-info {
                font-size: 0.9rem;
                opacity: 0.8;
                margin-bottom: 5px;
            }
            .stream-actions {
                margin-top: 15px;
            }
            .status-active {
                color: #4ecdc4;
            }
            .status-inactive {
                color: #ff6b6b;
            }
            .hidden { display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🔐 SREATY TV ADMIN</div>
            </div>

            <!-- Login Panel -->
            <div class="login-panel" id="loginPanel">
                <h2>Admin Login</h2>
                <div class="form-group">
                    <label for="adminPassword">Password:</label>
                    <input type="password" id="adminPassword" placeholder="Enter admin password">
                </div>
                <button onclick="adminLogin()">Login</button>
            </div>

            <!-- Admin Content -->
            <div class="admin-content hidden" id="adminContent">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2>Stream Management</h2>
                    <button onclick="logout()">Logout</button>
                </div>

                <!-- Add Stream Form -->
                <div style="background: rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 12px; margin-bottom: 30px;">
                    <h3>Add New Stream</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div class="form-group">
                            <label for="streamName">Stream Name:</label>
                            <input type="text" id="streamName" placeholder="Enter stream name">
                        </div>
                        <div class="form-group">
                            <label for="streamCategory">Category:</label>
                            <select id="streamCategory">
                                <option value="General">General</option>
                                <option value="Sports">Sports</option>
                                <option value="News">News</option>
                                <option value="Entertainment">Entertainment</option>
                                <option value="Movies">Movies</option>
                                <option value="Music">Music</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="streamLink">M3U8 Link:</label>
                        <input type="text" id="streamLink" placeholder="https://example.com/stream.m3u8">
                    </div>
                    <div class="form-group">
                        <label for="streamDescription">Description:</label>
                        <textarea id="streamDescription" placeholder="Stream description (optional)" rows="3"></textarea>
                    </div>
                    <button onclick="addStream()">Add Stream</button>
                    <button class="btn-secondary" onclick="clearForm()">Clear</button>
                </div>

                <!-- Streams List -->
                <div>
                    <h3>Existing Streams (<span id="streamsCount">0</span>)</h3>
                    <div class="streams-grid" id="streamsGrid">
                        <!-- Streams will be loaded here -->
                    </div>
                </div>
            </div>
        </div>

        <script>
            let authToken = localStorage.getItem('admin_token');
            
            // Check if already logged in
            if (authToken) {
                showAdminPanel();
            }

            async function adminLogin() {
                const password = document.getElementById('adminPassword').value;
                
                try {
                    const response = await fetch('/api/admin/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        authToken = data.token;
                        localStorage.setItem('admin_token', authToken);
                        showAdminPanel();
                    } else {
                        alert('Invalid password');
                    }
                } catch (error) {
                    alert('Login failed: ' + error.message);
                }
            }

            function showAdminPanel() {
                document.getElementById('loginPanel').classList.add('hidden');
                document.getElementById('adminContent').classList.remove('hidden');
                loadStreams();
            }

            function logout() {
                localStorage.removeItem('admin_token');
                authToken = null;
                document.getElementById('loginPanel').classList.remove('hidden');
                document.getElementById('adminContent').classList.add('hidden');
                document.getElementById('adminPassword').value = '';
            }

            async function loadStreams() {
                try {
                    const response = await fetch('/api/admin/streams', {
                        headers: { 'Authorization': `Bearer ${authToken}` }
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        displayStreams(data.streams);
                    }
                } catch (error) {
                    console.error('Failed to load streams:', error);
                }
            }

            function displayStreams(streams) {
                const grid = document.getElementById('streamsGrid');
                const count = Object.keys(streams).length;
                document.getElementById('streamsCount').textContent = count;
                
                grid.innerHTML = '';
                
                for (const [id, stream] of Object.entries(streams)) {
                    const card = document.createElement('div');
                    card.className = 'stream-card';
                    card.innerHTML = `
                        <div class="stream-title">${stream.name}</div>
                        <div class="stream-info">Category: ${stream.category}</div>
                        <div class="stream-info">Status: <span class="${stream.active ? 'status-active' : 'status-inactive'}">${stream.active ? 'Active' : 'Inactive'}</span></div>
                        <div class="stream-info">Created: ${new Date(stream.created).toLocaleDateString()}</div>
                        ${stream.description ? `<div class="stream-info">Description: ${stream.description}</div>` : ''}
                        <div class="stream-actions">
                            <button class="btn-secondary" onclick="editStream('${id}')">Edit</button>
                            <button class="btn-secondary" onclick="toggleStream('${id}', ${!stream.active})">${stream.active ? 'Deactivate' : 'Activate'}</button>
                            <button class="btn-danger" onclick="deleteStream('${id}')">Delete</button>
                        </div>
                    `;
                    grid.appendChild(card);
                }
            }

            async function addStream() {
                const name = document.getElementById('streamName').value.trim();
                const link = document.getElementById('streamLink').value.trim();
                const description = document.getElementById('streamDescription').value.trim();
                const category = document.getElementById('streamCategory').value;
                
                if (!name || !link) {
                    alert('Name and link are required');
                    return;
                }
                
                try {
                    const response = await fetch('/api/admin/streams', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${authToken}`
                        },
                        body: JSON.stringify({
                            name, link, description, category
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        clearForm();
                        loadStreams();
                        alert('Stream added successfully!');
                    } else {
                        alert('Failed to add stream: ' + data.error);
                    }
                } catch (error) {
                    alert('Failed to add stream: ' + error.message);
                }
            }

            async function deleteStream(id) {
                if (!confirm('Are you sure you want to delete this stream?')) {
                    return;
                }
                
                try {
                    const response = await fetch('/api/admin/streams', {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${authToken}`
                        },
                        body: JSON.stringify({ id })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        loadStreams();
                        alert('Stream deleted successfully!');
                    } else {
                        alert('Failed to delete stream: ' + data.error);
                    }
                } catch (error) {
                    alert('Failed to delete stream: ' + error.message);
                }
            }

            async function toggleStream(id, active) {
                try {
                    const response = await fetch('/api/admin/streams', {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${authToken}`
                        },
                        body: JSON.stringify({ id, active })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        loadStreams();
                    } else {
                        alert('Failed to update stream: ' + data.error);
                    }
                } catch (error) {
                    alert('Failed to update stream: ' + error.message);
                }
            }

            function clearForm() {
                document.getElementById('streamName').value = '';
                document.getElementById('streamLink').value = '';
                document.getElementById('streamDescription').value = '';
                document.getElementById('streamCategory').value = 'General';
            }

            // Handle Enter key
            document.getElementById('adminPassword').addEventListener('keyup', function(e) {
                if (e.key === 'Enter') adminLogin();
            });
        </script>
    </body>
    </html>
    """
    return admin_html

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

port = int(os.environ.get('PORT', 5000))

if __name__ == '__main__':
    print("🚀 Starting Enhanced Sreaty TV Server...")
    print("📺 Main site: http://localhost:5000")
    print("🔐 Admin panel: http://localhost:5000/admin")
    print("📡 API endpoints available")
    print("🔑 Default admin password: admin123 (change in production!)")
    
    app.run(debug=False, host='0.0.0.0', port=port)
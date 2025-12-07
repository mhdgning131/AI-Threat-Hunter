#!/usr/bin/env python3
import http.server
import socketserver
import json
import gzip
import argparse
import urllib.request
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple
from collections import Counter

# =============================================================================
# CONFIGURATION & LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ThreatHunter")

class Config:
    PORT = 8000
    DAYS = 7
    OLLAMA_URL = "http://127.0.0.1:11434"
    MODEL = "phi3:mini"
    LOGS_PATH = "/var/ossec/logs/archives"
    MAX_CONTEXT = 5000

# =============================================================================
# SERVICES
# =============================================================================

class OllamaService:
    
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url
        self.model = model
        self.chat_url = f"{base_url}/api/chat"
        self.tags_url = f"{base_url}/api/tags"
        self.pull_url = f"{base_url}/api/pull"

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(self.tags_url)
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except Exception:
            return False

    def ensure_model(self) -> bool:
        if not self.is_available():
            return False
            
        try:
            req = urllib.request.Request(self.tags_url)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                models = [m.get('name', '') for m in data.get('models', [])]
                
            # Check for exact or base match
            if any(self.model in m or m.startswith(self.model.split(':')[0]) for m in models):
                return True
                
            logger.info(f"Model {self.model} not found. Attempting to pull...")
            data = json.dumps({"name": self.model, "stream": False}).encode('utf-8')
            req = urllib.request.Request(self.pull_url, data=data, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=600) as response:
                return response.status == 200
        except Exception as e:
            logger.error(f"Model check failed: {e}")
            return False

    def query(self, prompt: str, context: str) -> str:
        system_prompt = (
            "ROLE: Elite Security Analyst. MODE: High-Precision/Low-Latency.\n"
            "TASK: Analyze raw JSON Wazuh logs for threats. Ignore low-level noise.\n"
            "OUTPUT RULES:\n"
            "1. NO Markdown. Use ONLY HTML tags (<b>, <ul>, <li>, <br>, <span style='color:red'>).\n"
            "2. NO conversational filler. Start directly with findings.\n"
            "3. STRUCTURE:\n"
            "   <b>🚨 Critical Threats:</b> <ul>...</ul>\n"
            "   <b>🔍 Analysis:</b> [Concise technical explanation]\n"
            "   <b>🛡️ Action:</b> [Specific remediation command/step]\n"
            "4. If no threats found, say: '<b>✅ No significant threats detected.</b>'"
        )
        
        full_prompt = (
            f"USER QUESTION: {prompt}\n\n"
            "INSTRUCTIONS: Answer the user's question based strictly on the logs below. "
            "Format your response in HTML as requested. Do NOT output raw JSON.\n\n"
            f"LOG DATA:\n{context}"
        )
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": full_prompt}
            ],
            "stream": False,
            "options": {"temperature": 0.3, "num_ctx": 2048}
        }

        try:
            proxy_handler = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(proxy_handler)
            
            json_data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.chat_url, 
                data=json_data, 
                headers={
                    'Content-Type': 'application/json',
                    'Content-Length': str(len(json_data))
                }
            )
            
            logger.info(f"Sending query to Ollama ({self.model})...")
            start_time = time.time()
            
            with opener.open(req, timeout=600) as response:
                if response.status != 200:
                    return f"Error: API returned status {response.status}"
                
                body = response.read().decode('utf-8')
                try:
                    result = json.loads(body)
                except json.JSONDecodeError:
                    return "Error: Invalid JSON response from API."
                
                answer = ""
                if "message" in result:
                    answer = result["message"].get("content", "")
                elif "response" in result:
                    answer = result.get("response", "")
                
                logger.info(f"Response received in {time.time() - start_time:.2f}s")
                
                if not answer:
                    logger.debug(f"Empty response body: {body[:200]}")
                    return "Error: AI returned empty response."
                    
                return answer

        except Exception as e:
            logger.error(f"Query failed: {e}")
            return f"Error: {str(e)}"

class LogService:   
    def __init__(self, logs_path: str, days: int):
        self.logs_path = logs_path
        self.days = days
        self.cache: List[Dict] = []
        self.stats: Dict = {}
        self.processed_files: List[str] = []

    def load_logs(self) -> Tuple[int, str]:
        self.cache = []
        self.processed_files = []
        self.stats = {
            'total': 0, 'files': 0, 'failed': 0,
            'levels': Counter(), 'agents': Counter(), 'rules': Counter()
        }
        
        today = datetime.now()
        logger.info(f"Loading logs from {self.logs_path} for last {self.days} days")
        
        for i in range(self.days):
            day = today - timedelta(days=i)
            base = Path(self.logs_path) / str(day.year) / day.strftime("%b")
            filename = f"ossec-archive-{day.strftime('%d')}.json"
            
            paths = [base / filename, base / (filename + ".gz")]
            
            for p in paths:
                if p.exists():
                    self._process_file(p)
                    break
        
        def get_severity(line: str) -> int:
            try:
                data = json.loads(line)
                return int(data.get('rule', {}).get('level', 0))
            except:
                return 0
        
        self.cache.sort(key=get_severity, reverse=True)
        
        self.cache = self.cache[:50]
        
        logger.info(f"Loaded {len(self.cache)} events.")
        return len(self.cache), "Logs loaded successfully"

    def _process_file(self, path: Path):
        try:
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
                count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            
                            is_agent = data.get('agent', {}).get('name') == 'Windows-Agent'
                            is_defender = data.get('data', {}).get('win', {}).get('system', {}).get('providerName') == 'Microsoft-Windows-Windows Defender'
                            
                            if is_agent and is_defender:
                                simplified_log = {
                                    "timestamp": data.get("timestamp"),
                                    "level": data.get("rule", {}).get("level"),
                                    "description": data.get("rule", {}).get("description"),
                                    "severity_name": data.get("data", {}).get("eventdata", {}).get("severity Name"),
                                    "threat_name": data.get("data", {}).get("eventdata", {}).get("threat Name"),
                                    "file_path": data.get("data", {}).get("eventdata", {}).get("path"),
                                    "full_log": data.get("full_log")
                                }
                                self.cache.append(json.dumps(simplified_log))
                                self._update_stats(line)
                                count += 1
                        except:
                            pass

                self.stats['files'] += 1
                self.stats['total'] += count
                self.processed_files.append(str(path))
                logger.info(f"✓ Processed: {path} ({count} events)")
        except Exception as e:
            logger.error(f"Failed to read {path}: {e}")
            self.stats['failed'] += 1

    def _update_stats(self, line: str):
        try:
            data = json.loads(line)
            level = data.get('rule', {}).get('level', 0)
            agent = data.get('agent', {}).get('name', 'unknown')
            rule_id = data.get('rule', {}).get('id')
            desc = data.get('rule', {}).get('description')
            self.stats['levels'][level] += 1
            self.stats['agents'][agent] += 1
            self.stats['rules'][f"{rule_id}: {desc}"] += 1
        except:
            pass

    def get_formatted_context(self, max_chars: int) -> str:
        if not self.cache:
            return "No logs available."
        
        lines = []
        total_len = 0
        
        for log_line in self.cache:
            if total_len + len(log_line) + 1 < max_chars:
                lines.append(log_line)
                total_len += len(log_line) + 1
            else:
                break
                
        return "\n".join(lines)

    def get_summary(self) -> Dict:
        return {
            "total": self.stats.get('total', 0),
            "critical": sum(v for k,v in self.stats.get('levels', {}).items() if k>=10),
            "files": self.stats.get('files', 0)
        }

# =============================================================================
# INTERFACE WEB
# =============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Threat Hunter</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #3b82f6;
            --border: #334155;
        }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-dark); color: var(--text-main); margin: 0; display: flex; height: 100vh; }
        .sidebar { width: 260px; background: var(--bg-card); border-right: 1px solid var(--border); padding: 20px; display: flex; flex-direction: column; gap: 20px; }
        .main { flex: 1; display: flex; flex-direction: column; }
        .header { padding: 20px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 1.1rem; }
        .chat-area { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 15px; }
        .input-area { padding: 20px; border-top: 1px solid var(--border); background: var(--bg-card); }
        .input-box { display: flex; gap: 10px; }
        input { flex: 1; padding: 12px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg-dark); color: white; outline: none; }
        input:focus { border-color: var(--accent); }
        button { padding: 12px 24px; background: var(--accent); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
        button:hover { opacity: 0.9; }
        .msg { padding: 15px; border-radius: 8px; max-width: 85%; line-height: 1.5; }
        .msg.user { align-self: flex-end; background: var(--accent); }
        .msg.bot { align-self: flex-start; background: var(--bg-card); border: 1px solid var(--border); }
        .msg.system { align-self: center; color: var(--text-muted); font-size: 0.9rem; font-style: italic; }
        .stat-card { background: var(--bg-dark); padding: 15px; border-radius: 6px; border: 1px solid var(--border); }
        .stat-val { font-size: 1.5rem; font-weight: bold; color: var(--accent); }
        .stat-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; }
        .status-indicator { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; }
        .online { background: #10b981; } .offline { background: #ef4444; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div style="font-size: 1.2rem; font-weight: bold; display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; background: var(--accent); border-radius: 6px;"></div>
            Threat Hunter
        </div>
        
        <div>
            <div class="stat-label">System Status</div>
            <div class="stat-card" style="margin-top: 10px;">
                <div style="display: flex; justify-content: space-between;">
                    <span>Ollama</span>
                    <span id="ollama-status"><span class="status-indicator offline"></span></span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-top: 5px;">
                    <span>Logs</span>
                    <span id="logs-status">--</span>
                </div>
            </div>
        </div>

        <div>
            <div class="stat-label">Events Analyzed</div>
            <div class="stat-card" style="margin-top: 10px;">
                <div class="stat-val" id="total-events">0</div>
                <div class="stat-label">Total Records</div>
            </div>
        </div>

        <button onclick="refreshLogs()" style="width: 100%; background: var(--bg-dark); border: 1px solid var(--border);">Refresh Data</button>
        <button onclick="clearChat()" style="width: 100%; background: var(--bg-dark); border: 1px solid var(--border);">Clear Chat</button>
    </div>

    <div class="main">
        <div class="header">AI Security Analyst Console</div>
        <div class="chat-area" id="chat">
            <div class="msg system">System initialized. Ready for analysis.</div>
        </div>
        <div class="input-area">
            <form class="input-box" onsubmit="event.preventDefault(); send();">
                <input type="text" id="prompt" placeholder="Describe the threat or query..." autocomplete="off">
                <button type="submit" id="sendBtn">Analyze</button>
            </form>
        </div>
    </div>

    <script>
        const chat = document.getElementById('chat');
        const prompt = document.getElementById('prompt');
        const sendBtn = document.getElementById('sendBtn');

        window.onload = updateStatus;

        async function send() {
            const text = prompt.value.trim();
            if (!text) return;
            
            addMsg(text, 'user');
            prompt.value = '';
            prompt.disabled = true;
            sendBtn.disabled = true;
            
            const loadId = addMsg('Analyzing...', 'bot');
            
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const data = await res.json();
                document.getElementById(loadId).remove();
                addMsg(data.response || data.error, 'bot');
            } catch (e) {
                document.getElementById(loadId).remove();
                addMsg('Connection error.', 'system');
            }
            
            prompt.disabled = false;
            sendBtn.disabled = false;
            prompt.focus();
        }

        async function updateStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('ollama-status').innerHTML = 
                    `<span class="status-indicator ${data.ollama ? 'online' : 'offline'}"></span>${data.model}`;
                document.getElementById('logs-status').textContent = data.logs > 0 ? 'Loaded' : 'Empty';
                document.getElementById('total-events').textContent = data.logs;
            } catch (e) { console.error(e); }
        }

        async function refreshLogs() {
            addMsg('Refreshing log data...', 'system');
            await fetch('/api/refresh', {method: 'POST'});
            await updateStatus();
            addMsg('Logs refreshed.', 'system');
        }

        function addMsg(text, type) {
            const div = document.createElement('div');
            div.className = 'msg ' + type;
            // Use innerHTML for bot messages to render HTML tags
            if (type === 'bot') {
                div.innerHTML = text;
            } else {
                div.textContent = text;
            }
            div.id = 'msg-' + Date.now();
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
            return div.id;
        }

        function clearChat() {
            chat.innerHTML = '<div class="msg system">Chat cleared.</div>';
        }
    </script>
</body>
</html>
"""

class AppHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())
        elif self.path == "/api/status":
            self._send_json(app.get_status())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/chat":
            self._handle_chat()
        elif self.path == "/api/refresh":
            app.log_service.load_logs()
            self._send_json({"status": "success", "message": "Logs refreshed"})
        else:
            self.send_error(404)

    def _handle_chat(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            response = app.ollama.query(data.get('message', ''), app.log_service.get_formatted_context(Config.MAX_CONTEXT))
            self._send_json({"response": response})
        except Exception as e:
            self._send_json({"error": str(e)})

    def _send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        pass

class Application:
    def __init__(self):
        self.ollama = None
        self.log_service = None

    def initialize(self, args):
        Config.PORT = args.port
        Config.DAYS = args.days
        Config.LOGS_PATH = args.logs_path
        Config.MODEL = args.model
        
        self.ollama = OllamaService(Config.OLLAMA_URL, Config.MODEL)
        self.log_service = LogService(Config.LOGS_PATH, Config.DAYS)
        
        logger.info("Initializing services...")
        if self.ollama.ensure_model():
            logger.info("Ollama service ready.")
        else:
            logger.warning("Ollama service not available.")
            
        self.log_service.load_logs()

    def get_status(self):
        return {
            "ollama": self.ollama.is_available(),
            "logs": self.log_service.stats.get('total', 0),
            "model": Config.MODEL
        }

app = Application()

def main():
    parser = argparse.ArgumentParser(description="Wazuh AI Threat Hunter")
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("-d", "--days", type=int, default=7)
    parser.add_argument("--logs-path", type=str, default="/var/ossec/logs/archives")
    parser.add_argument("--model", type=str, default="phi3:mini")
    args = parser.parse_args()
    
    app.initialize(args)
    
    logger.info(f"Starting web server on port {args.port}")
    
    class ThreadingSimpleServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True

    with ThreadingSimpleServer(("", args.port), AppHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped.")

if __name__ == "__main__":
    main()
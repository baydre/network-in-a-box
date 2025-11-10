#!/usr/bin/env python3

import logging
import os
import subprocess
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

class TestServer:
    def __init__(self):
        self.servers = {}
    
    def deploy_python_http(self, namespace: str, port: int) -> Tuple[bool, Optional[str]]:
        """Deploy a Python HTTP server in the specified namespace"""
        try:
            # Create a simple index.html
            server_dir = f"/tmp/server_{namespace}"
            os.makedirs(server_dir, exist_ok=True)
            with open(f"{server_dir}/index.html", "w") as f:
                f.write(f"Hello from {namespace}!")
            
            # Start Python HTTP server
            cmd = [
                "ip", "netns", "exec", namespace,
                "/usr/bin/python3", "-m", "http.server", str(port),
                "--directory", server_dir
            ]
            
            # Start server in background
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait briefly to ensure server starts
            time.sleep(1)
            
            # Check if server is running
            if process.poll() is None:
                self.servers[namespace] = process
                logger.info(f"Started Python HTTP server in {namespace} on port {port}")
                return True, None
            else:
                stdout, stderr = process.communicate()
                return False, f"Server failed to start: {stderr.decode()}"
                
        except Exception as e:
            return False, f"Failed to deploy server: {str(e)}"
    
    def deploy_nginx(self, namespace: str, port: int) -> Tuple[bool, Optional[str]]:
        """Deploy an Nginx server in the specified namespace"""
        try:
            # Create nginx config
            config_dir = f"/tmp/nginx_{namespace}"
            os.makedirs(config_dir, exist_ok=True)
            
            config = f"""
            worker_processes 1;
            error_log /dev/stderr;
            pid /tmp/nginx_{namespace}.pid;
            events {{
                worker_connections 1024;
            }}
            http {{
                access_log /dev/stdout;
                server {{
                    listen {port};
                    location / {{
                        return 200 'Hello from {namespace}\\n';
                    }}
                }}
            }}
            """
            
            config_file = f"{config_dir}/nginx.conf"
            with open(config_file, "w") as f:
                f.write(config)
            
            # Start nginx
            cmd = [
                "ip", "netns", "exec", namespace,
                "nginx", "-c", config_file,
                "-g", "daemon off;"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait briefly to ensure nginx starts
            time.sleep(1)
            
            if process.poll() is None:
                self.servers[namespace] = process
                logger.info(f"Started Nginx server in {namespace} on port {port}")
                return True, None
            else:
                stdout, stderr = process.communicate()
                return False, f"Nginx failed to start: {stderr.decode()}"
                
        except Exception as e:
            return False, f"Failed to deploy Nginx: {str(e)}"
    
    def stop_server(self, namespace: str) -> Tuple[bool, Optional[str]]:
        """Stop the server running in the specified namespace"""
        try:
            if namespace in self.servers:
                process = self.servers[namespace]
                process.terminate()
                process.wait(timeout=5)
                del self.servers[namespace]
                logger.info(f"Stopped server in {namespace}")
                return True, None
            return False, f"No server found in namespace {namespace}"
        except Exception as e:
            return False, f"Failed to stop server: {str(e)}"
    
    def cleanup(self):
        """Stop all running servers"""
        for namespace in list(self.servers.keys()):
            self.stop_server(namespace)
        
        # Clean up temporary directories
        subprocess.run(["rm", "-rf", "/tmp/server_*"], check=False)
        subprocess.run(["rm", "-rf", "/tmp/nginx_*"], check=False)
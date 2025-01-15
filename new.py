import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import paramiko
import socks
import os
import time
import select
import json
import netifaces
import logging
import socketserver
import hashlib
import dns.resolver

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FreeInternetApp")

class FreeInternetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Tunnel Manager")
        
        # Set fixed window size and disable resizing
        self.root.geometry("430x520")  # Width x Height
        self.root.resizable(False, False)  # Disable both horizontal and vertical resizing
        
        # Add configuration file handling
        self.config_file = 'tunnel_config.json'
        self.load_config()

        # Style configuration
        style = ttk.Style()
        style.configure('TButton', padding=6, relief="flat", background="#ccc")
        style.configure('TLabel', padding=6)
        style.configure('TEntry', padding=6)
        style.configure('TNotebook', padding=2)
        
        # Create main frame with padding
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0)

        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0)

        # Adjust the width of entry widgets and text areas
        entry_width = 30  # Reduced width for entry widgets
        text_width = 40   # Reduced width for text widget
        
        # Home tab (Payload)
        home_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(home_frame, text='Home')

        ttk.Label(home_frame, text="Payload:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=(0, 2))

        self.payload_text = scrolledtext.ScrolledText(home_frame, width=text_width, height=6, wrap=tk.WORD)
        self.payload_text.grid(row=1, column=0, padx=5, pady=(0, 5), sticky=(tk.W, tk.E))

        # Set default payload
        default_payload = (
            "GET / HTTP/1.1\n"
            "Host: uk1.vhserver.xyz\n"
            "Connection: Upgrade\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n"
            "Upgrade: websocket\n"
            "\n"
        )

        # Load saved payload or use default
        saved_payload = self.config.get('payload', default_payload)
        self.payload_text.insert('1.0', saved_payload)

        # Add binding to adjust height based on content
        self.payload_text.bind('<KeyRelease>', self.adjust_text_height)

        # Proxy Profile tab
        proxy_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(proxy_frame, text='Proxy Profile')

        ttk.Label(proxy_frame, text="Proxy:").grid(row=0, column=0, sticky=tk.W)
        self.proxy_entry = ttk.Entry(proxy_frame, width=entry_width)
        self.proxy_entry.grid(row=0, column=1, padx=5, pady=5)
        self.proxy_entry.insert(0, self.config.get('proxy', ''))

        ttk.Label(proxy_frame, text="Port:").grid(row=1, column=0, sticky=tk.W)
        self.port_entry = ttk.Entry(proxy_frame, width=entry_width)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.port_entry.insert(0, self.config.get('port', ''))

        # SSH Profile tab
        ssh_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(ssh_frame, text='SSH Profile')

        ttk.Label(ssh_frame, text="SSH Host:").grid(row=0, column=0, sticky=tk.W)
        self.ssh_host_entry = ttk.Entry(ssh_frame, width=entry_width)
        self.ssh_host_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ssh_host_entry.insert(0, self.config.get('ssh_host', ''))

        ttk.Label(ssh_frame, text="SSH User:").grid(row=1, column=0, sticky=tk.W)
        self.ssh_user_entry = ttk.Entry(ssh_frame, width=entry_width)
        self.ssh_user_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ssh_user_entry.insert(0, self.config.get('ssh_user', ''))

        ttk.Label(ssh_frame, text="SSH Password:").grid(row=2, column=0, sticky=tk.W)
        self.ssh_password_entry = ttk.Entry(ssh_frame, width=entry_width, show="*")
        self.ssh_password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.ssh_password_entry.insert(0, self.config.get('ssh_password', ''))

        # Logs tab
        logs_frame = ttk.Frame(self.notebook, padding="5")
        self.notebook.add(logs_frame, text='Logs')

        # Log window with increased size
        self.log_window = scrolledtext.ScrolledText(logs_frame, width=45, height=20)
        self.log_window.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Bottom controls frame for logs
        logs_control_frame = ttk.Frame(logs_frame)
        logs_control_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=(0, 5))

        # Autoscroll checkbox - left aligned
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.autoscroll_check = ttk.Checkbutton(
            logs_control_frame, 
            text="Auto-scroll", 
            variable=self.autoscroll_var
        )
        self.autoscroll_check.pack(side=tk.LEFT)

        # Clear logs button - right aligned
        self.clear_logs_button = ttk.Button(
            logs_control_frame,
            text="Clear Logs",
            command=self.clear_logs,
            style='Clear.TButton'
        )
        self.clear_logs_button.pack(side=tk.RIGHT)

        # Configure style for clear button
        style = ttk.Style()
        style.configure('Clear.TButton', padding=3)

        # Buttons and status at the bottom of main frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, pady=10)

        self.connect_button = ttk.Button(button_frame, text="Connect", command=self.connect)
        self.connect_button.pack(side=tk.LEFT, padx=5)

        self.disconnect_button = ttk.Button(button_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = ttk.Label(main_frame, text="Status: Offline", relief=tk.SUNKEN)
        self.status_label.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)

        self.ssh = None
        self.is_connected = False
        
        # Start periodic status updates
        self.update_network_status()
        self.root.after(1000, self.periodic_status_update)

    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = {}
        except Exception as e:
            self.config = {}
            print(f"Error loading config: {e}")

    def save_config(self):
        """Save configuration to file"""
        config = {
            'proxy': self.proxy_entry.get(),
            'port': self.port_entry.get(),
            'payload': self.payload_text.get('1.0', tk.END).strip(),
            'ssh_host': self.ssh_host_entry.get(),
            'ssh_user': self.ssh_user_entry.get(),
            'ssh_password': self.ssh_password_entry.get()
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Error saving config: {e}")

    def connect(self):
        """Establish connection"""
        # Save configuration before connecting
        self.save_config()
        
        # Get values from entries
        proxy = self.proxy_entry.get()
        port = self.port_entry.get()
        payload = self.payload_text.get('1.0', tk.END).strip()
        ssh_host = self.ssh_host_entry.get()
        ssh_user = self.ssh_user_entry.get()
        ssh_password = self.ssh_password_entry.get()
        
        # Disable connect button during connection attempt
        self.connect_button.config(state=tk.DISABLED)
        self.log("Connecting...")
        
        # Start connection in a separate thread
        thread = threading.Thread(
            target=self.connect_thread,
            args=(proxy, port, payload, ssh_user, ssh_host, ssh_password)
        )
        thread.daemon = True
        thread.start()

    def disconnect(self):
        """Disconnect and cleanup connections"""
        if hasattr(self, 'socks_server'):
            try:
                self.socks_server.close()
            except:
                pass
        
        if hasattr(self, 'tunnel_socket'):
            try:
                self.tunnel_socket.close()
            except:
                pass
            delattr(self, 'tunnel_socket')
        
        if self.ssh:
            try:
                self.ssh.close()
            except:
                pass
            self.ssh = None
        
        self.is_connected = False
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.log("Disconnected.")
        self.update_status("Offline")

        # Stop local proxy server
        if hasattr(self, 'proxy_server'):
            try:
                self.proxy_server.shutdown()
                self.proxy_server.server_close()
                self.local_proxy_running = False
                self.log("Local proxy server stopped")
            except:
                pass

    def update_status(self, message):
        """Update status label with basic message"""
        if message == "Connected":
            self.is_connected = True
            self.update_network_status()  # Force an immediate network status update
        elif message == "Offline":
            self.is_connected = False
            self.update_network_status()  # Force an immediate network status update
        else:
            self.status_label.config(text=f"Status: {message}")

    def update_network_status(self):
        """Update network status with IP information"""
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            ip_found = False
            
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:  # Check for IPv4 addresses
                    ip_info = addrs[netifaces.AF_INET][0]
                    if 'addr' in ip_info and not ip_info['addr'].startswith('127.'):
                        ip_found = True
                        ip_address = ip_info['addr']
                        connection_type = "Tunneled" if self.is_connected else "Direct"
                        status_message = f"Status: {connection_type} | Local IP: {ip_address}"
                        self.status_label.config(text=status_message)
                        break
            
            if not ip_found:
                self.status_label.config(text="Status: No network connection")
                
        except Exception as e:
            self.log(f"Status update error: {str(e)}")
            self.status_label.config(text="Status: Error getting network info")

    def log(self, message):
        """Add message to log window"""
        self.log_window.config(state=tk.NORMAL)
        self.log_window.insert(tk.END, message + "\n")
        if self.autoscroll_var.get():
            self.log_window.see(tk.END)
        self.log_window.config(state=tk.DISABLED)

    def connect_thread(self, proxy, port, payload, ssh_user, ssh_host, ssh_password):
        try:
            self.log(f"Setting up connection to proxy {proxy}:{port}")
            
            # Create a raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                # Connect to the proxy
                self.log(f"Connecting to proxy...")
                sock.connect((proxy, int(port)))
                
                # Create initial payload
                initial_payload = (
                    "GET / HTTP/1.1\r\n"
                    f"Host: {ssh_host}\r\n"
                    "Connection: Upgrade\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
                    "Upgrade: websocket\r\n"
                    "\r\n"
                )
                
                self.log(f"Sending payload:\n{initial_payload}")
                sock.send(initial_payload.encode())
                
                # Receive response
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                self.log(f"Received response:\n{response}")
                
                if "101 Switching Protocol" in response:
                    self.log("Connection successful!")
                    self.is_connected = True
                    self.tunnel_socket = sock
                    
                    # Create a local socket server for SOCKS
                    self.socks_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socks_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.socks_server.bind(('127.0.0.1', 1080))
                    self.socks_server.listen(5)
                    self.log("SOCKS server listening on 127.0.0.1:1080")
                    
                    # Start the SOCKS server thread
                    self.socks_thread = threading.Thread(target=self.handle_socks_connections)
                    self.socks_thread.daemon = True
                    self.socks_thread.start()
                    
                    # Setup SSH connection through the tunnel
                    if ssh_host and ssh_user and ssh_password:
                        self.setup_ssh_tunnel(ssh_host, ssh_user, ssh_password, proxy, port)
                    
                    self.update_status("Connected")
                    self.update_network_status()
                    self.root.after(1000, self.update_network_status)  # Update status every second
                    self.disconnect_button.config(state=tk.NORMAL)
                    
                else:
                    self.log("Connection failed - unexpected response")
                    sock.close()
                    self.disconnect()
                    return
                    
            except Exception as e:
                self.log(f"Socket error: {str(e)}")
                try:
                    sock.close()
                except:
                    pass
                self.disconnect()
                return
                
        except Exception as e:
            self.log(f"Connection error (detailed): {str(e)}")
            self.is_connected = False
            self.disconnect()

    def handle_socks_connections(self):
        """Handle incoming SOCKS connections"""
        while True:
            try:
                client, addr = self.socks_server.accept()
                self.log(f"New SOCKS connection from {addr}")
                
                # Start a new thread to handle this connection
                t = threading.Thread(target=self.handle_socks_client, args=(client,))
                t.daemon = True
                t.start()
            except Exception as e:
                if hasattr(self, 'is_connected') and self.is_connected:
                    self.log(f"SOCKS connection error: {str(e)}")
                break

    def handle_socks_client(self, client):
        """Handle individual SOCKS client connections with improved error handling"""
        try:
            # Read SOCKS version
            version = client.recv(1)
            if version == b'\x05':  # SOCKS5
                # Read authentication methods
                nmethods = client.recv(1)[0]
                methods = client.recv(nmethods)
                
                # Send authentication method (no auth required)
                client.send(b'\x05\x00')
                
                # Get request details
                version = client.recv(1)
                command = client.recv(1)
                reserved = client.recv(1)
                atyp = client.recv(1)
                
                if command == b'\x01':  # CONNECT
                    try:
                        if atyp == b'\x01':  # IPv4
                            addr = socket.inet_ntoa(client.recv(4))
                        elif atyp == b'\x03':  # Domain name
                            length = client.recv(1)[0]
                            addr = client.recv(length).decode()
                        else:
                            raise Exception("Unsupported address type")
                        
                        port = int.from_bytes(client.recv(2), 'big')
                        
                        try:
                            # Create SSH channel with retry mechanism
                            retries = 3
                            channel = None
                            last_error = None
                            
                            while retries > 0 and not channel:
                                try:
                                    transport = self.ssh.get_transport()
                                    if not transport or not transport.is_active():
                                        raise Exception("SSH transport is not active")
                                        
                                    channel = transport.open_channel(
                                        "direct-tcpip",
                                        (addr, port),
                                        ('127.0.0.1', 0)
                                    )
                                except Exception as e:
                                    last_error = e
                                    retries -= 1
                                    if retries > 0:
                                        self.log(f"Retrying channel creation... ({retries} attempts left)")
                                        time.sleep(1)
                            
                            if channel:
                                # Send success response
                                client.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                                
                                # Start bidirectional forwarding with timeout
                                self.forward_data_with_timeout(client, channel)
                            else:
                                raise last_error or Exception("Failed to create channel")
                            
                        except Exception as e:
                            self.log(f"Channel error: {str(e)}")
                            client.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                            
                    except Exception as e:
                        self.log(f"SOCKS protocol error: {str(e)}")
                        try:
                            client.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                        except:
                            pass
                        
        except Exception as e:
            self.log(f"SOCKS client error: {str(e)}")
        finally:
            try:
                client.close()
            except:
                pass

    def forward_data_with_timeout(self, client, channel):
        """Forward data between client and channel with timeout and keepalive"""
        try:
            client.settimeout(300)  # 5 minutes timeout
            channel.settimeout(300)
            
            while True:
                r, w, e = select.select([client, channel], [], [], 60)  # 1 minute select timeout
                
                if not r:  # Timeout occurred, send keepalive
                    try:
                        channel.send_ignore()
                        continue
                    except:
                        break
                    
                if client in r:
                    try:
                        data = client.recv(4096)
                        if len(data) == 0:
                            break
                        channel.send(data)
                    except:
                        break
                    
                if channel in r:
                    try:
                        data = channel.recv(4096)
                        if len(data) == 0:
                            break
                        client.send(data)
                    except:
                        break
                    
        except Exception as e:
            self.log(f"Forward error: {str(e)}")
        finally:
            try:
                client.close()
            except:
                pass
            try:
                channel.close()
            except:
                pass

    def periodic_status_update(self):
        """Update network status periodically"""
        self.update_network_status()
        self.root.after(1000, self.periodic_status_update)  # Schedule next update

    def setup_ssh_tunnel(self, ssh_host, ssh_user, ssh_password, proxy, port):
        """Setup SSH tunnel through the established connection"""
        try:
            self.log(f"Setting up SSH tunnel to {ssh_host}")
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if hasattr(self, 'tunnel_socket'):
                self.log("Using established tunnel for SSH connection")
                
                # Set keepalive options
                self.tunnel_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                # Set TCP keepalive options if on Windows
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    self.tunnel_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    self.tunnel_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 60)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    self.tunnel_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

                # Connect with keepalive settings
                self.ssh.connect(
                    hostname=ssh_host,
                    username=ssh_user,
                    password=ssh_password,
                    timeout=30,
                    sock=self.tunnel_socket,
                    disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']},
                    look_for_keys=False,
                    allow_agent=False
                )
                
                # Set SSH keepalive
                transport = self.ssh.get_transport()
                transport.set_keepalive(60)
                
                self.log("SSH connection established successfully")
                self.log("Setting up dynamic port forwarding...")
                
                try:
                    # Start dynamic port forwarding
                    transport.request_port_forward('', 1080)
                    self.log("Dynamic port forwarding established on port 1080")
                    
                    # Start forwarding thread
                    self.forward_thread = threading.Thread(
                        target=self.handle_forward,
                        args=(transport,),
                        daemon=True
                    )
                    self.forward_thread.start()
                    
                    # Wait a moment for the forwarding to start
                    time.sleep(2)
                    
                    # Test the connection
                    self.log("Testing SOCKS connection...")
                    sock = socks.socksocket()
                    sock.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)
                    sock.settimeout(10)
                    
                    try:
                        sock.connect(("www.google.com", 80))
                        sock.send(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
                        response = sock.recv(1024)
                        if response:
                            self.log("SOCKS connection test successful!")
                            self.log("You can now configure your browser to use SOCKS5 proxy at 127.0.0.1:1080")
                        sock.close()
                    except Exception as e:
                        self.log(f"SOCKS connection test failed: {str(e)}")
                        raise
                    
                except Exception as e:
                    self.log(f"Port forwarding error: {str(e)}")
                    raise
                    
            else:
                self.log("No tunnel socket available for SSH connection")
                self.disconnect()
                
        except Exception as e:
            self.log(f"SSH Tunnel error: {str(e)}")
            self.disconnect()

    def handle_forward(self, transport):
        """Handle the port forwarding"""
        while transport.is_active():
            try:
                chan = transport.accept(1)
                if chan is None:
                    continue
                
                thread = threading.Thread(
                    target=self.handle_channel,
                    args=(chan,),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                if transport and transport.is_active():
                    self.log(f"Forward handling error: {str(e)}")
                break

    def handle_channel(self, channel):
        """Handle individual channel connections"""
        try:
            while channel and not channel.closed:
                r, w, e = select.select([channel], [], [], 1)
                if channel in r:
                    data = channel.recv(32768)
                    if not data:
                        break
                    channel.send(data)
        except Exception as e:
            if channel and not channel.closed:
                self.log(f"Channel error: {str(e)}")
        finally:
            try:
                if channel:
                    channel.close()
            except:
                pass

    def adjust_text_height(self, event=None):
        """Adjust the height of the payload text widget based on content"""
        num_lines = int(self.payload_text.index('end-1c').split('.')[0])
        new_height = min(max(num_lines, 4), 8)  # Min 4 lines, Max 8 lines
        self.payload_text.configure(height=new_height)

    def clear_logs(self):
        """Clear the log window"""
        self.log_window.config(state=tk.NORMAL)
        self.log_window.delete('1.0', tk.END)
        self.log_window.config(state=tk.DISABLED)
        self.log("Logs cleared.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FreeInternetApp(root)
    root.mainloop()
import sys
import os
import time
import socket
import threading
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import defaultdict
import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import platform
import subprocess
import json
from scapy.all import sniff, IP, TCP, UDP, ICMP
import dpkt
from dpkt.compat import compat_ord
import warnings

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Constants
VERSION = "1.0.0"
THEME_COLORS = {
    "purple": {
        "bg": "#2a0a3a",
        "fg": "#e0a0ff",
        "button_bg": "#4a1a5a",
        "button_fg": "#ffffff",
        "text_bg": "#1a052a",
        "text_fg": "#ffffff",
        "terminal_bg": "#0a0515",
        "terminal_fg": "#a0ffa0",
        "highlight": "#bf40bf"
    },
    "green": {
        "bg": "#0a2a1a",
        "fg": "#a0ffc0",
        "button_bg": "#1a4a2a",
        "button_fg": "#ffffff",
        "text_bg": "#051a0a",
        "text_fg": "#ffffff",
        "terminal_bg": "#051505",
        "terminal_fg": "#a0ffa0",
        "highlight": "#40bf40"
    },
    "black": {
        "bg": "#0a0a0a",
        "fg": "#e0e0e0",
        "button_bg": "#2a2a2a",
        "button_fg": "#ffffff",
        "text_bg": "#050505",
        "text_fg": "#ffffff",
        "terminal_bg": "#050505",
        "terminal_fg": "#a0ffa0",
        "highlight": "#606060"
    }
}

class NetworkMonitor:
    def __init__(self):
        self.monitoring = False
        self.target_ip = ""
        self.packet_count = 0
        self.threats_detected = 0
        self.dos_count = 0
        self.ddos_count = 0
        self.port_scan_count = 0
        self.other_threats = 0
        self.packet_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.start_time = None
        self.sniffer_thread = None
        self.alert_threshold = 100  # Packets per second considered as attack
        self.port_scan_threshold = 20  # Ports scanned per minute
        self.ip_scan_window = {}  # Track port scans per IP
        self.last_alert_time = {}
        self.whitelist = set()
        self.blacklist = set()
        self.log_file = "security_log.txt"
        self.export_file = "network_data.json"
        
    def start_monitoring(self, ip):
        self.target_ip = ip
        self.monitoring = True
        self.start_time = datetime.datetime.now()
        self.sniffer_thread = threading.Thread(target=self._start_sniffing, daemon=True)
        self.sniffer_thread.start()
        
    def stop_monitoring(self):
        self.monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
            
    def _start_sniffing(self):
        try:
            sniff(prn=self._packet_handler, filter=f"host {self.target_ip}", store=False)
        except Exception as e:
            print(f"Sniffing error: {e}")
            
    def _packet_handler(self, packet):
        if not self.monitoring:
            return
            
        self.packet_count += 1
        current_time = datetime.datetime.now()
        
        # Basic packet analysis
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Track packet stats
            self.packet_stats["total"] += 1
            self.ip_stats[src_ip] += 1
            
            # Protocol specific tracking
            if TCP in packet:
                self.packet_stats["tcp"] += 1
                dst_port = packet[TCP].dport
                self.port_stats[dst_port] += 1
                
                # Check for SYN flood (DoS)
                if packet[TCP].flags == 'S':  # SYN packet
                    self.packet_stats["syn"] += 1
                    if self._check_dos_attack(src_ip, current_time):
                        self._log_threat("DoS", src_ip, f"SYN flood detected from {src_ip}")
                        self.dos_count += 1
                        self.threats_detected += 1
                        
                # Check for port scanning
                if self._check_port_scan(src_ip, dst_port, current_time):
                    self._log_threat("Port Scan", src_ip, f"Port scan detected from {src_ip}")
                    self.port_scan_count += 1
                    self.threats_detected += 1
                    
            elif UDP in packet:
                self.packet_stats["udp"] += 1
                dst_port = packet[UDP].dport
                self.port_stats[dst_port] += 1
                
                # Check for UDP flood (DDoS)
                if self._check_ddos_attack(src_ip, current_time):
                    self._log_threat("DDoS", src_ip, f"UDP flood detected from {src_ip}")
                    self.ddos_count += 1
                    self.threats_detected += 1
                    
            elif ICMP in packet:
                self.packet_stats["icmp"] += 1
                # Check for ICMP flood (Ping flood)
                if self._check_dos_attack(src_ip, current_time):
                    self._log_threat("DoS", src_ip, f"ICMP flood detected from {src_ip}")
                    self.dos_count += 1
                    self.threats_detected += 1
                    
    def _check_dos_attack(self, src_ip, current_time):
        """Check if packet rate exceeds threshold for DoS"""
        if src_ip not in self.last_alert_time:
            self.last_alert_time[src_ip] = current_time - datetime.timedelta(seconds=60)
            
        time_diff = (current_time - self.last_alert_time[src_ip]).total_seconds()
        if time_diff < 1 and self.ip_stats[src_ip] > self.alert_threshold:
            self.last_alert_time[src_ip] = current_time
            return True
        elif time_diff >= 1:
            self.ip_stats[src_ip] = 0  # Reset counter if more than 1 second passed
            self.last_alert_time[src_ip] = current_time
            
        return False
        
    def _check_ddos_attack(self, src_ip, current_time):
        """Check for distributed attack patterns"""
        # Simple implementation - can be enhanced with more sophisticated detection
        return self._check_dos_attack(src_ip, current_time)
        
    def _check_port_scan(self, src_ip, dst_port, current_time):
        """Check if source IP is scanning multiple ports"""
        if src_ip not in self.ip_scan_window:
            self.ip_scan_window[src_ip] = {
                'ports': set(),
                'start_time': current_time
            }
            
        window_data = self.ip_scan_window[src_ip]
        window_data['ports'].add(dst_port)
        
        time_diff = (current_time - window_data['start_time']).total_seconds()
        
        if time_diff > 60:  # 1 minute window
            # Reset window
            self.ip_scan_window[src_ip] = {
                'ports': set(),
                'start_time': current_time
            }
            return False
            
        return len(window_data['ports']) > self.port_scan_threshold
        
    def _log_threat(self, threat_type, source, message):
        """Log detected threats"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {threat_type.upper()} ALERT: {message}\n"
        
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except IOError as e:
            print(f"Error writing to log file: {e}")
            
    def get_stats(self):
        """Return current monitoring statistics"""
        uptime = datetime.datetime.now() - self.start_time if self.start_time else datetime.timedelta(0)
        
        return {
            "monitoring": self.monitoring,
            "target_ip": self.target_ip,
            "packet_count": self.packet_count,
            "threats_detected": self.threats_detected,
            "dos_count": self.dos_count,
            "ddos_count": self.ddos_count,
            "port_scan_count": self.port_scan_count,
            "other_threats": self.other_threats,
            "uptime": str(uptime),
            "packet_stats": dict(self.packet_stats),
            "top_ips": dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]),
            "top_ports": dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:5])
        }
        
    def export_data(self, filename):
        """Export collected data to JSON file"""
        data = self.get_stats()
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False
            
    def clear_stats(self):
        """Reset all statistics"""
        self.packet_count = 0
        self.threats_detected = 0
        self.dos_count = 0
        self.ddos_count = 0
        self.port_scan_count = 0
        self.other_threats = 0
        self.packet_stats.clear()
        self.ip_stats.clear()
        self.port_stats.clear()
        self.ip_scan_window.clear()
        self.last_alert_time.clear()

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Accurate Cyber Defense NetworK Security Tool v{VERSION}")
        self.root.geometry("1200x800")
        self.current_theme = "purple"
        
        # Initialize network monitor
        self.monitor = NetworkMonitor()
        
        # Setup UI
        self._setup_menu()
        self._setup_theme()
        self._setup_main_frame()
        self._setup_dashboard()
        self._setup_terminal()
        self._setup_status_bar()
        
        # Start periodic updates
        self._update_stats()
        
    def _setup_menu(self):
        """Create the main menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self._export_data)
        file_menu.add_command(label="Export Log", command=self._export_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=lambda: self._show_frame("dashboard"))
        view_menu.add_command(label="Terminal", command=lambda: self._show_frame("terminal"))
        view_menu.add_separator()
        view_menu.add_command(label="Purple Theme", command=lambda: self._change_theme("purple"))
        view_menu.add_command(label="Green Theme", command=lambda: self._change_theme("green"))
        view_menu.add_command(label="Black Theme", command=lambda: self._change_theme("black"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Stats", command=self._show_network_stats)
        tools_menu.add_command(label="Port Scanner", command=self._show_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self._show_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self._show_user_guide)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def _setup_theme(self):
        """Apply the current theme colors"""
        colors = THEME_COLORS[self.current_theme]
        style = ttk.Style()
        
        # Configure main window
        self.root.config(bg=colors["bg"])
        
        # Configure styles
        style.theme_create("cyber_theme", parent="alt", settings={
            "TFrame": {"configure": {"background": colors["bg"]}},
            "TLabel": {
                "configure": {
                    "background": colors["bg"],
                    "foreground": colors["fg"],
                    "font": ("Consolas", 10)
                }
            },
            "TButton": {
                "configure": {
                    "background": colors["button_bg"],
                    "foreground": colors["button_fg"],
                    "font": ("Consolas", 10),
                    "padding": 5,
                    "borderwidth": 1,
                    "relief": "raised"
                },
                "map": {
                    "background": [("active", colors["highlight"])],
                    "foreground": [("active", colors["button_fg"])]
                }
            },
            "TEntry": {
                "configure": {
                    "fieldbackground": colors["text_bg"],
                    "foreground": colors["text_fg"],
                    "insertcolor": colors["fg"],
                    "font": ("Consolas", 10)
                }
            },
            "TCombobox": {
                "configure": {
                    "fieldbackground": colors["text_bg"],
                    "foreground": colors["text_fg"],
                    "background": colors["button_bg"],
                    "font": ("Consolas", 10)
                }
            },
            "Vertical.TScrollbar": {
                "configure": {
                    "background": colors["button_bg"],
                    "arrowcolor": colors["fg"],
                    "troughcolor": colors["bg"]
                }
            }
        })
        
        style.theme_use("cyber_theme")
        
    def _setup_main_frame(self):
        """Create the main container frame"""
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create frames for different views
        self.frames = {}
        
        # Dashboard frame
        self.frames["dashboard"] = ttk.Frame(self.main_frame)
        
        # Terminal frame
        self.frames["terminal"] = ttk.Frame(self.main_frame)
        
        # Show dashboard by default
        self._show_frame("dashboard")
        
    def _setup_dashboard(self):
        """Setup the dashboard view"""
        frame = self.frames["dashboard"]
        colors = THEME_COLORS[self.current_theme]
        
        # IP Address Entry
        ip_frame = ttk.Frame(frame)
        ip_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ip_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        self.ip_entry = ttk.Entry(ip_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_btn = ttk.Button(ip_frame, text="Start Monitoring", command=self._start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(ip_frame, text="Stop Monitoring", command=self._stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Stats display
        stats_frame = ttk.Frame(frame)
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Left panel - numerical stats
        left_panel = ttk.Frame(stats_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.stats_text = tk.Text(
            left_panel,
            bg=colors["text_bg"],
            fg=colors["text_fg"],
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=10
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - charts
        right_panel = ttk.Frame(stats_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        # Threat distribution pie chart
        self.threat_chart_frame = ttk.Frame(right_panel)
        self.threat_chart_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Protocol distribution bar chart
        self.protocol_chart_frame = ttk.Frame(right_panel)
        self.protocol_chart_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Alerts log
        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(log_frame, text="Security Alerts:").pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg=colors["text_bg"],
            fg=colors["text_fg"],
            font=("Consolas", 9),
            wrap=tk.WORD,
            height=8
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def _setup_terminal(self):
        """Setup the terminal emulator"""
        frame = self.frames["terminal"]
        colors = THEME_COLORS[self.current_theme]
        
        # Terminal output
        self.terminal_output = tk.Text(
            frame,
            bg=colors["terminal_bg"],
            fg=colors["terminal_fg"],
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=20
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal input
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind("<Return>", self._execute_command)
        
        # Add welcome message
        self._terminal_print(f"Advanced Cyber Security Monitor Terminal v{VERSION}")
        self._terminal_print("Type 'help' for available commands\n")
        
    def _setup_status_bar(self):
        """Create the status bar at the bottom"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _show_frame(self, frame_name):
        """Show the specified frame"""
        frame = self.frames[frame_name]
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Hide other frames
        for name, f in self.frames.items():
            if name != frame_name:
                f.pack_forget()
                
    def _change_theme(self, theme_name):
        """Change the application theme"""
        self.current_theme = theme_name
        self._setup_theme()
        
        # Update all widgets with new colors
        colors = THEME_COLORS[theme_name]
        
        # Update dashboard widgets
        self.stats_text.config(
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        
        self.log_text.config(
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        
        # Update terminal widgets
        self.terminal_output.config(
            bg=colors["terminal_bg"],
            fg=colors["terminal_fg"]
        )
        
        # Redraw charts
        self._update_charts()
        
    def _start_monitoring(self):
        """Start monitoring the specified IP"""
        ip = self.ip_entry.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
            
        try:
            socket.inet_aton(ip)  # Validate IP address
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return
            
        self.monitor.start_monitoring(ip)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Monitoring {ip}")
        
        # Clear previous logs
        self.log_text.delete(1.0, tk.END)
        
        # Update UI
        self._update_stats()
        
    def _stop_monitoring(self):
        """Stop monitoring"""
        self.monitor.stop_monitoring()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped")
        
    def _update_stats(self):
        """Update the statistics display"""
        if self.monitor.monitoring:
            stats = self.monitor.get_stats()
            
            # Update stats text
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, f"Target IP: {stats['target_ip']}\n")
            self.stats_text.insert(tk.END, f"Monitoring Status: {'ACTIVE' if stats['monitoring'] else 'INACTIVE'}\n")
            self.stats_text.insert(tk.END, f"Uptime: {stats['uptime']}\n")
            self.stats_text.insert(tk.END, f"Total Packets: {stats['packet_count']}\n")
            self.stats_text.insert(tk.END, f"Threats Detected: {stats['threats_detected']}\n")
            self.stats_text.insert(tk.END, f"  - DoS Attacks: {stats['dos_count']}\n")
            self.stats_text.insert(tk.END, f"  - DDoS Attacks: {stats['ddos_count']}\n")
            self.stats_text.insert(tk.END, f"  - Port Scans: {stats['port_scan_count']}\n")
            self.stats_text.insert(tk.END, f"  - Other Threats: {stats['other_threats']}\n\n")
            
            # Top IPs
            self.stats_text.insert(tk.END, "Top Source IPs:\n")
            for ip, count in stats['top_ips'].items():
                self.stats_text.insert(tk.END, f"  - {ip}: {count} packets\n")
                
            # Top Ports
            self.stats_text.insert(tk.END, "\nTop Destination Ports:\n")
            for port, count in stats['top_ports'].items():
                self.stats_text.insert(tk.END, f"  - {port}: {count} packets\n")
                
            # Update charts
            self._update_charts()
            
            # Check for new alerts
            self._update_alerts()
            
            # Schedule next update
            self.root.after(2000, self._update_stats)
            
    def _update_charts(self):
        """Update the threat and protocol charts"""
        stats = self.monitor.get_stats()
        
        # Clear previous charts
        for widget in self.threat_chart_frame.winfo_children():
            widget.destroy()
            
        for widget in self.protocol_chart_frame.winfo_children():
            widget.destroy()
            
        # Threat distribution pie chart
        if stats['threats_detected'] > 0:
            labels = ['DoS', 'DDoS', 'Port Scan', 'Other']
            sizes = [
                stats['dos_count'],
                stats['ddos_count'],
                stats['port_scan_count'],
                stats['other_threats']
            ]
            
            fig, ax = plt.subplots(figsize=(5, 3), dpi=100)
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')  # Equal aspect ratio ensures pie is drawn as a circle
            ax.set_title('Threat Distribution')
            
            canvas = FigureCanvasTkAgg(fig, master=self.threat_chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        # Protocol distribution bar chart
        if stats['packet_count'] > 0:
            labels = ['TCP', 'UDP', 'ICMP', 'Other']
            sizes = [
                stats['packet_stats'].get('tcp', 0),
                stats['packet_stats'].get('udp', 0),
                stats['packet_stats'].get('icmp', 0),
                stats['packet_stats'].get('total', 0) - sum([
                    stats['packet_stats'].get('tcp', 0),
                    stats['packet_stats'].get('udp', 0),
                    stats['packet_stats'].get('icmp', 0)
                ])
            ]
            
            fig, ax = plt.subplots(figsize=(5, 3), dpi=100)
            ax.bar(labels, sizes, color=THEME_COLORS[self.current_theme]['highlight'])
            ax.set_title('Protocol Distribution')
            ax.set_ylabel('Packet Count')
            
            canvas = FigureCanvasTkAgg(fig, master=self.protocol_chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
    def _update_alerts(self):
        """Update the alerts log with new entries"""
        try:
            with open(self.monitor.log_file, "r") as f:
                content = f.read()
                
            current_content = self.log_text.get(1.0, tk.END)
            
            if content != current_content:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, content)
                self.log_text.see(tk.END)
        except IOError:
            pass
            
    def _terminal_print(self, message):
        """Print a message to the terminal"""
        self.terminal_output.insert(tk.END, message + "\n")
        self.terminal_output.see(tk.END)
        
    def _execute_command(self, event=None):
        """Execute a terminal command"""
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
            
        self._terminal_print(f"> {command}")
        
        # Process command
        cmd_parts = command.split()
        base_cmd = cmd_parts[0].lower()
        
        if base_cmd == "help":
            self._terminal_print("Available commands:")
            self._terminal_print("  help - Show this help message")
            self._terminal_print("  exit - Exit the terminal")
            self._terminal_print("  clear - Clear the terminal")
            self._terminal_print("  netstat - Show network statistics")
            self._terminal_print("  ifconfig /all - Show network interface details")
            self._terminal_print("  ping <ip> - Ping an IP address")
            self._terminal_print("  start monitoring <ip> - Start monitoring an IP")
            self._terminal_print("  stop - Stop monitoring")
        elif base_cmd == "exit":
            self._show_frame("dashboard")
        elif base_cmd == "clear":
            self.terminal_output.delete(1.0, tk.END)
        elif base_cmd == "netstat":
            self._execute_netstat()
        elif base_cmd == "ifconfig" and len(cmd_parts) > 1 and cmd_parts[1] == "/all":
            self._execute_ifconfig()
        elif base_cmd == "ping" and len(cmd_parts) > 1:
            ip = cmd_parts[1]
            threading.Thread(target=self._execute_ping, args=(ip,), daemon=True).start()
        elif base_cmd == "start" and len(cmd_parts) > 2 and cmd_parts[1] == "monitoring":
            ip = cmd_parts[2]
            self.root.after(0, lambda: self._start_monitoring_from_terminal(ip))
        elif base_cmd == "stop":
            self.root.after(0, self._stop_monitoring)
        else:
            self._terminal_print(f"Unknown command: {command}")
            self._terminal_print("Type 'help' for available commands")
            
    def _start_monitoring_from_terminal(self, ip):
        """Start monitoring from terminal command"""
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        self._start_monitoring()
        
    def _execute_netstat(self):
        """Execute netstat command"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            else:
                result = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True)
                
            self._terminal_print(result.stdout)
        except Exception as e:
            self._terminal_print(f"Error executing netstat: {e}")
            
    def _execute_ifconfig(self):
        """Execute ifconfig/ipconfig command"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
            else:
                result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                
            self._terminal_print(result.stdout)
        except Exception as e:
            self._terminal_print(f"Error executing ifconfig/ipconfig: {e}")
            
    def _execute_ping(self, ip):
        """Execute ping command"""
        try:
            count = "4" if platform.system() == "Windows" else "-c 4"
            result = subprocess.run(["ping", count, ip], capture_output=True, text=True)
            self._terminal_print(result.stdout)
        except Exception as e:
            self._terminal_print(f"Error executing ping: {e}")
            
    def _export_data(self):
        """Export collected data to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Data"
        )
        
        if filename:
            if self.monitor.export_data(filename):
                messagebox.showinfo("Success", f"Data exported to {filename}")
            else:
                messagebox.showerror("Error", "Failed to export data")
                
    def _export_log(self):
        """Export log to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Log"
        )
        
        if filename:
            try:
                with open(self.monitor.log_file, "r") as src, open(filename, "w") as dst:
                    dst.write(src.read())
                messagebox.showinfo("Success", f"Log exported to {filename}")
            except IOError as e:
                messagebox.showerror("Error", f"Failed to export log: {e}")
                
    def _show_network_stats(self):
        """Show detailed network statistics"""
        stats = self.monitor.get_stats()
        message = f"""
        Network Statistics:
        ------------------
        Target IP: {stats['target_ip']}
        Status: {'ACTIVE' if stats['monitoring'] else 'INACTIVE'}
        Uptime: {stats['uptime']}
        
        Packet Count: {stats['packet_count']}
        Threats Detected: {stats['threats_detected']}
          - DoS Attacks: {stats['dos_count']}
          - DDoS Attacks: {stats['ddos_count']}
          - Port Scans: {stats['port_scan_count']}
          - Other Threats: {stats['other_threats']}
        """
        
        messagebox.showinfo("Network Statistics", message.strip())
        
    def _show_port_scanner(self):
        """Show port scanner tool"""
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("Port Scanner")
        scanner_window.geometry("500x400")
        
        colors = THEME_COLORS[self.current_theme]
        
        # IP Address Entry
        ip_frame = ttk.Frame(scanner_window)
        ip_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ip_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        scan_ip_entry = ttk.Entry(ip_frame, width=20)
        scan_ip_entry.pack(side=tk.LEFT, padx=5)
        
        # Port range
        port_frame = ttk.Frame(scanner_window)
        port_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(port_frame, text="Port Range:").pack(side=tk.LEFT, padx=5)
        start_port_entry = ttk.Entry(port_frame, width=5)
        start_port_entry.pack(side=tk.LEFT, padx=5)
        start_port_entry.insert(0, "1")
        
        ttk.Label(port_frame, text="to").pack(side=tk.LEFT, padx=5)
        end_port_entry = ttk.Entry(port_frame, width=5)
        end_port_entry.pack(side=tk.LEFT, padx=5)
        end_port_entry.insert(0, "1024")
        
        # Scan button
        scan_btn = ttk.Button(
            scanner_window,
            text="Start Scan",
            command=lambda: self._run_port_scan(
                scan_ip_entry.get(),
                start_port_entry.get(),
                end_port_entry.get(),
                result_text
            )
        )
        scan_btn.pack(pady=5)
        
        # Results
        result_text = scrolledtext.ScrolledText(
            scanner_window,
            bg=colors["text_bg"],
            fg=colors["text_fg"],
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _run_port_scan(self, ip, start_port, end_port, result_widget):
        """Run a port scan and display results"""
        try:
            # Validate inputs
            socket.inet_aton(ip)
            start = int(start_port)
            end = int(end_port)
            
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("Ports must be between 1 and 65535")
            if start > end:
                raise ValueError("Start port must be less than or equal to end port")
                
            # Clear previous results
            result_widget.delete(1.0, tk.END)
            result_widget.insert(tk.END, f"Scanning {ip} ports {start}-{end}...\n")
            result_widget.see(tk.END)
            
            # Run scan in background
            threading.Thread(
                target=self._perform_port_scan,
                args=(ip, start, end, result_widget),
                daemon=True
            ).start()
            
        except (socket.error, ValueError) as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
            
    def _perform_port_scan(self, ip, start_port, end_port, result_widget):
        """Perform the actual port scanning"""
        open_ports = []
        
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        service = socket.getservbyport(port, 'tcp') if port <= 1024 else "unknown"
                        result_widget.insert(tk.END, f"Port {port} ({service}) is open\n")
                        result_widget.see(tk.END)
            except (socket.error, socket.timeout):
                continue
            except Exception as e:
                result_widget.insert(tk.END, f"Error scanning port {port}: {e}\n")
                result_widget.see(tk.END)
                
        result_widget.insert(tk.END, f"\nScan complete. Found {len(open_ports)} open ports.\n")
        result_widget.see(tk.END)
        
    def _show_packet_analyzer(self):
        """Show packet analyzer tool"""
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("Packet Analyzer")
        analyzer_window.geometry("800x600")
        
        colors = THEME_COLORS[self.current_theme]
        
        # Capture controls
        control_frame = ttk.Frame(analyzer_window)
        control_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(control_frame, text="Capture Filter:").pack(side=tk.LEFT, padx=5)
        filter_entry = ttk.Entry(control_frame, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        start_btn = ttk.Button(
            control_frame,
            text="Start Capture",
            command=lambda: self._start_packet_capture(filter_entry.get(), result_text)
        )
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = ttk.Button(
            control_frame,
            text="Stop Capture",
            command=self._stop_packet_capture,
            state=tk.DISABLED
        )
        stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Results
        result_text = scrolledtext.ScrolledText(
            analyzer_window,
            bg=colors["text_bg"],
            fg=colors["text_fg"],
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Store references for the capture thread
        self.capture_thread = None
        self.capture_running = False
        self.analyzer_window = analyzer_window
        self.analyzer_start_btn = start_btn
        self.analyzer_stop_btn = stop_btn
        self.analyzer_result_text = result_text
        
    def _start_packet_capture(self, filter_str, result_widget):
        """Start packet capture"""
        if self.capture_running:
            return
            
        self.capture_running = True
        self.analyzer_start_btn.config(state=tk.DISABLED)
        self.analyzer_stop_btn.config(state=tk.NORMAL)
        
        # Clear previous results
        result_widget.delete(1.0, tk.END)
        result_widget.insert(tk.END, f"Starting packet capture with filter: {filter_str}\n")
        result_widget.see(tk.END)
        
        # Start capture in background
        self.capture_thread = threading.Thread(
            target=self._perform_packet_capture,
            args=(filter_str, result_widget),
            daemon=True
        )
        self.capture_thread.start()
        
    def _stop_packet_capture(self):
        """Stop packet capture"""
        if not self.capture_running:
            return
            
        self.capture_running = False
        self.analyzer_start_btn.config(state=tk.NORMAL)
        self.analyzer_stop_btn.config(state=tk.DISABLED)
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1)
            
        if hasattr(self, 'analyzer_result_text'):
            self.analyzer_result_text.insert(tk.END, "\nPacket capture stopped.\n")
            self.analyzer_result_text.see(tk.END)
            
    def _perform_packet_capture(self, filter_str, result_widget):
        """Perform the actual packet capture"""
        try:
            sniff(
                prn=lambda pkt: self._process_packet(pkt, result_widget),
                filter=filter_str,
                store=False,
                stop_filter=lambda x: not self.capture_running
            )
        except Exception as e:
            result_widget.insert(tk.END, f"Capture error: {e}\n")
            result_widget.see(tk.END)
            
        self.analyzer_window.after(0, lambda: self.analyzer_stop_btn.config(state=tk.DISABLED))
        self.analyzer_window.after(0, lambda: self.analyzer_start_btn.config(state=tk.NORMAL))
        
    def _process_packet(self, packet, result_widget):
        """Process and display a captured packet"""
        if not self.capture_running:
            return
            
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
        packet_info = f"[{timestamp}] "
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_info += f"{src_ip} -> {dst_ip} "
            
            if TCP in packet:
                packet_info += f"TCP sport={packet[TCP].sport} dport={packet[TCP].dport} flags={packet[TCP].flags}"
            elif UDP in packet:
                packet_info += f"UDP sport={packet[UDP].sport} dport={packet[UDP].dport}"
            elif ICMP in packet:
                packet_info += "ICMP"
            else:
                packet_info += "Other"
                
            result_widget.insert(tk.END, packet_info + "\n")
            result_widget.see(tk.END)
            
    def _show_user_guide(self):
        """Show the user guide"""
        guide = f"""
        Advanced Cyber Security Monitor v{VERSION} - User Guide
        
        1. Monitoring Network Threats:
           - Enter the target IP address in the dashboard
           - Click "Start Monitoring" to begin
           - View detected threats in the Security Alerts section
           - Statistics and charts will update automatically
           
        2. Terminal Commands:
           - help: Show available commands
           - netstat: Show network connections
           - ifconfig /all: Show network interface details
           - ping <ip>: Ping an IP address
           - start monitoring <ip>: Start monitoring an IP
           - stop: Stop monitoring
           - clear: Clear the terminal
           - exit: Return to dashboard
           
        3. Tools:
           - Network Stats: View detailed statistics
           - Port Scanner: Scan for open ports
           - Packet Analyzer: Capture and analyze network packets
           
        4. Exporting Data:
           - Use File menu to export monitoring data or logs
        """
        
        messagebox.showinfo("User Guide", guide.strip())
        
    def _show_about(self):
        """Show about information"""
        about = f"""
        Advanced Cyber Security Monitor v{VERSION}
        
        A comprehensive tool for monitoring and analyzing
        network security threats in real-time.
        
        Features:
        - Real-time DoS/DDoS detection
        - Port scan detection
        - Network traffic analysis
        - Data visualization
        - Terminal with network commands
        
        Created for professional cybersecurity analysis.
        """
        
        messagebox.showinfo("About", about.strip())

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
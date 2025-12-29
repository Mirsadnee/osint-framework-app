"""
OSINT Framework Application
A comprehensive OSINT tool with CustomTkinter GUI
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import requests
import json
import webbrowser
from datetime import datetime
import os
import subprocess
import sys

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class OSINTApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("OSINT Framework - Intelligence Gathering Tool")
        self.geometry("1400x900")
        self.minsize(1200, 700)
        
        # Initialize variables
        self.results_text = None
        self.current_category = None
        
        # Create UI
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left sidebar for categories
        sidebar = ctk.CTkFrame(main_frame, width=250)
        sidebar.pack(side="left", fill="y", padx=(0, 10))
        sidebar.pack_propagate(False)
        
        # Title
        title_label = ctk.CTkLabel(
            sidebar, 
            text="OSINT Framework",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=20)
        
        # Category buttons
        categories = {
            "Username": self.show_username_tools,
            "Email": self.show_email_tools,
            "Domain/IP": self.show_domain_tools,
            "Phone": self.show_phone_tools,
            "Images": self.show_image_tools,
            "Social Media": self.show_social_tools,
            "People Search": self.show_people_tools,
            "Dark Web": self.show_darkweb_tools,
            "Blockchain": self.show_blockchain_tools,
            "Documents": self.show_document_tools,
            "Metadata": self.show_metadata_tools,
            "Search Engines": self.show_search_tools,
            "DNS": self.show_dns_tools,
            "Subdomain": self.show_subdomain_tools,
            "Vulnerability": self.show_vulnerability_tools,
        }
        
        for category, command in categories.items():
            btn = ctk.CTkButton(
                sidebar,
                text=category,
                command=command,
                width=220,
                height=40,
                font=ctk.CTkFont(size=14)
            )
            btn.pack(pady=5, padx=10)
        
        # Right side - Main content area
        content_frame = ctk.CTkFrame(main_frame)
        content_frame.pack(side="right", fill="both", expand=True)
        
        # Input section
        input_frame = ctk.CTkFrame(content_frame)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.input_label = ctk.CTkLabel(
            input_frame,
            text="Enter target:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.input_label.pack(side="left", padx=10, pady=10)
        
        self.input_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter username, email, domain, IP, etc...",
            width=400,
            height=35,
            font=ctk.CTkFont(size=12)
        )
        self.input_entry.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        
        self.search_btn = ctk.CTkButton(
            input_frame,
            text="Search",
            command=self.perform_search,
            width=100,
            height=35,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.search_btn.pack(side="left", padx=10, pady=10)
        
        # Tools section
        self.tools_frame = ctk.CTkFrame(content_frame)
        self.tools_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Results section
        results_label = ctk.CTkLabel(
            content_frame,
            text="Results:",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        results_label.pack(anchor="w", padx=10)
        
        self.results_text = ctk.CTkTextbox(
            content_frame,
            width=800,
            height=300,
            font=ctk.CTkFont(size=11)
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Status bar
        self.status_label = ctk.CTkLabel(
            content_frame,
            text="Ready",
            font=ctk.CTkFont(size=10)
        )
        self.status_label.pack(side="bottom", anchor="w", padx=10, pady=5)
        
        # Show default category
        self.show_username_tools()
        
    def update_status(self, message):
        self.status_label.configure(text=message)
        self.update()
        
    def log_result(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        self.results_text.insert("end", f"{prefix} {message}\n")
        self.results_text.see("end")
        self.update()
        
    def clear_results(self):
        self.results_text.delete("1.0", "end")
        
    def show_username_tools(self):
        self.current_category = "Username"
        self.input_label.configure(text="Enter username:")
        self.input_entry.configure(placeholder_text="Enter username...")
        self.clear_tools_frame()
        
        tools = [
            ("Sherlock", "Search username across social networks", self.run_sherlock),
            ("Namechk", "Check username availability", self.run_namechk),
            ("WhatsMyName", "Username enumeration", self.run_whatsmyname),
            ("Social Catfish", "Social media search", self.run_social_catfish),
            ("KnowEm", "Username search", self.run_knowem),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_email_tools(self):
        self.current_category = "Email"
        self.input_label.configure(text="Enter email:")
        self.input_entry.configure(placeholder_text="Enter email address...")
        self.clear_tools_frame()
        
        tools = [
            ("EmailRep", "Email reputation check", self.run_emailrep),
            ("Have I Been Pwned", "Check if email was breached", self.run_hibp),
            ("Hunter.io", "Email finder and verifier", self.run_hunter),
            ("Email Format", "Find email format patterns", self.run_email_format),
            ("Breach Directory", "Check breach database", self.run_breach_directory),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_domain_tools(self):
        self.current_category = "Domain/IP"
        self.input_label.configure(text="Enter domain/IP:")
        self.input_entry.configure(placeholder_text="Enter domain or IP address...")
        self.clear_tools_frame()
        
        tools = [
            ("WHOIS Lookup", "Domain registration info", self.run_whois),
            ("Shodan", "Internet connected device search", self.run_shodan),
            ("Censys", "Internet-wide search engine", self.run_censys),
            ("VirusTotal", "Domain/IP analysis", self.run_virustotal),
            ("SecurityTrails", "Domain history and DNS", self.run_securitytrails),
            ("DNS Dumpster", "DNS recon and research", self.run_dns_dumpster),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_phone_tools(self):
        self.current_category = "Phone"
        self.input_label.configure(text="Enter phone number:")
        self.input_entry.configure(placeholder_text="Enter phone number...")
        self.clear_tools_frame()
        
        tools = [
            ("TrueCaller", "Phone number lookup", self.run_truecaller),
            ("Sync.me", "Phone number search", self.run_syncme),
            ("PhoneInfoga", "Phone number OSINT", self.run_phoneinfoga),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_image_tools(self):
        self.current_category = "Images"
        self.input_label.configure(text="Enter image URL:")
        self.input_entry.configure(placeholder_text="Enter image URL or upload...")
        self.clear_tools_frame()
        
        tools = [
            ("Reverse Image Search", "Google reverse image search", self.run_reverse_image),
            ("TinEye", "Reverse image search", self.run_tineye),
            ("Yandex Images", "Image search", self.run_yandex_images),
            ("EXIF Data", "Extract metadata from images", self.run_exif),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_social_tools(self):
        self.current_category = "Social Media"
        self.input_label.configure(text="Enter username/URL:")
        self.input_entry.configure(placeholder_text="Enter social media username or URL...")
        self.clear_tools_frame()
        
        tools = [
            ("Facebook Search", "Search Facebook profiles", self.run_facebook_search),
            ("Twitter/X Search", "Search Twitter profiles", self.run_twitter_search),
            ("Instagram Search", "Search Instagram profiles", self.run_instagram_search),
            ("LinkedIn Search", "Search LinkedIn profiles", self.run_linkedin_search),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_people_tools(self):
        self.current_category = "People Search"
        self.input_label.configure(text="Enter name:")
        self.input_entry.configure(placeholder_text="Enter person's name...")
        self.clear_tools_frame()
        
        tools = [
            ("Pipl", "People search", self.run_pipl),
            ("Spokeo", "People search engine", self.run_spokeo),
            ("WhitePages", "People finder", self.run_whitepages),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_darkweb_tools(self):
        self.current_category = "Dark Web"
        self.input_label.configure(text="Enter search term:")
        self.input_entry.configure(placeholder_text="Enter search term...")
        self.clear_tools_frame()
        
        tools = [
            ("Tor Search", "Search Tor network", self.run_tor_search),
            ("Ahmia", "Tor search engine", self.run_ahmia),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_blockchain_tools(self):
        self.current_category = "Blockchain"
        self.input_label.configure(text="Enter address/transaction:")
        self.input_entry.configure(placeholder_text="Enter blockchain address or transaction hash...")
        self.clear_tools_frame()
        
        tools = [
            ("Blockchain Explorer", "Bitcoin/Ethereum explorer", self.run_blockchain_explorer),
            ("Etherscan", "Ethereum blockchain explorer", self.run_etherscan),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_document_tools(self):
        self.current_category = "Documents"
        self.input_label.configure(text="Enter document URL:")
        self.input_entry.configure(placeholder_text="Enter document URL...")
        self.clear_tools_frame()
        
        tools = [
            ("Document Metadata", "Extract document metadata", self.run_document_metadata),
            ("PDF Analysis", "Analyze PDF files", self.run_pdf_analysis),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_metadata_tools(self):
        self.current_category = "Metadata"
        self.input_label.configure(text="Enter file URL:")
        self.input_entry.configure(placeholder_text="Enter file URL...")
        self.clear_tools_frame()
        
        tools = [
            ("EXIFTool", "Extract metadata", self.run_exiftool),
            ("Metadata Viewer", "View file metadata", self.run_metadata_viewer),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_search_tools(self):
        self.current_category = "Search Engines"
        self.input_label.configure(text="Enter search query:")
        self.input_entry.configure(placeholder_text="Enter search query...")
        self.clear_tools_frame()
        
        tools = [
            ("Google Dorks", "Advanced Google search", self.run_google_dorks),
            ("Bing Search", "Bing search", self.run_bing_search),
            ("DuckDuckGo", "DuckDuckGo search", self.run_duckduckgo),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_dns_tools(self):
        self.current_category = "DNS"
        self.input_label.configure(text="Enter domain:")
        self.input_entry.configure(placeholder_text="Enter domain name...")
        self.clear_tools_frame()
        
        tools = [
            ("DNS Lookup", "DNS record lookup", self.run_dns_lookup),
            ("MX Records", "Mail exchange records", self.run_mx_records),
            ("NS Records", "Name server records", self.run_ns_records),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_subdomain_tools(self):
        self.current_category = "Subdomain"
        self.input_label.configure(text="Enter domain:")
        self.input_entry.configure(placeholder_text="Enter domain name...")
        self.clear_tools_frame()
        
        tools = [
            ("Subfinder", "Subdomain discovery", self.run_subfinder),
            ("Amass", "Subdomain enumeration", self.run_amass),
            ("Crt.sh", "Certificate transparency logs", self.run_crtsh),
        ]
        
        self.create_tool_buttons(tools)
        
    def show_vulnerability_tools(self):
        self.current_category = "Vulnerability"
        self.input_label.configure(text="Enter target:")
        self.input_entry.configure(placeholder_text="Enter domain, IP, or CVE...")
        self.clear_tools_frame()
        
        tools = [
            ("CVE Database", "CVE vulnerability search", self.run_cve_search),
            ("Exploit-DB", "Exploit database", self.run_exploitdb),
        ]
        
        self.create_tool_buttons(tools)
        
    def clear_tools_frame(self):
        for widget in self.tools_frame.winfo_children():
            widget.destroy()
            
    def create_tool_buttons(self, tools):
        # Create scrollable frame for tools
        scrollable_frame = ctk.CTkScrollableFrame(self.tools_frame)
        scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Title
        title = ctk.CTkLabel(
            scrollable_frame,
            text=f"{self.current_category} Tools",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=10)
        
        # Tool buttons in grid
        for i, (tool_name, description, command) in enumerate(tools):
            tool_frame = ctk.CTkFrame(scrollable_frame)
            tool_frame.pack(fill="x", padx=10, pady=5)
            
            tool_btn = ctk.CTkButton(
                tool_frame,
                text=tool_name,
                command=lambda cmd=command: self.run_tool(cmd),
                width=200,
                height=40,
                font=ctk.CTkFont(size=12, weight="bold")
            )
            tool_btn.pack(side="left", padx=10, pady=10)
            
            desc_label = ctk.CTkLabel(
                tool_frame,
                text=description,
                font=ctk.CTkFont(size=11),
                anchor="w"
            )
            desc_label.pack(side="left", padx=10, pady=10, fill="x", expand=True)
            
    def run_tool(self, tool_func):
        target = self.input_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target first!")
            return
            
        self.clear_results()
        self.update_status("Running tool...")
        
        # Run tool in separate thread to avoid freezing UI
        thread = threading.Thread(target=lambda: tool_func(target))
        thread.daemon = True
        thread.start()
        
    def perform_search(self):
        target = self.input_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target first!")
            return
            
        self.clear_results()
        self.update_status("Performing search...")
        self.log_result(f"Starting OSINT search for: {target}")
        self.log_result(f"Category: {self.current_category}")
        self.log_result("=" * 60)
        
        # Perform basic search based on category
        if self.current_category == "Username":
            self.run_basic_username_search(target)
        elif self.current_category == "Email":
            self.run_basic_email_search(target)
        elif self.current_category == "Domain/IP":
            self.run_basic_domain_search(target)
        else:
            self.log_result(f"Use specific tools from the {self.current_category} category")
            
    # Username Tools
    def run_sherlock(self, target):
        self.log_result(f"Running Sherlock for username: {target}")
        self.log_result("Note: Sherlock requires installation. Opening web search...")
        webbrowser.open(f"https://www.google.com/search?q=sherlock+osint+{target}")
        self.update_status("Search opened in browser")
        
    def run_namechk(self, target):
        self.log_result(f"Checking username availability: {target}")
        webbrowser.open(f"https://namechk.com/?q={target}")
        self.update_status("Namechk opened in browser")
        
    def run_whatsmyname(self, target):
        self.log_result(f"Running WhatsMyName for: {target}")
        webbrowser.open(f"https://whatsmyname.app/?q={target}")
        self.update_status("WhatsMyName opened in browser")
        
    def run_social_catfish(self, target):
        self.log_result(f"Searching Social Catfish for: {target}")
        webbrowser.open(f"https://socialcatfish.com/search/?q={target}")
        self.update_status("Social Catfish opened in browser")
        
    def run_knowem(self, target):
        self.log_result(f"Checking KnowEm for: {target}")
        webbrowser.open(f"https://knowem.com/?q={target}")
        self.update_status("KnowEm opened in browser")
        
    def run_basic_username_search(self, target):
        self.log_result(f"Performing basic username search for: {target}")
        self.log_result("Checking common platforms...")
        
        platforms = {
            "GitHub": f"https://github.com/{target}",
            "Twitter/X": f"https://twitter.com/{target}",
            "Instagram": f"https://instagram.com/{target}",
            "LinkedIn": f"https://linkedin.com/in/{target}",
            "Facebook": f"https://facebook.com/{target}",
        }
        
        for platform, url in platforms.items():
            self.log_result(f"{platform}: {url}")
            
    # Email Tools
    def run_emailrep(self, target):
        self.log_result(f"Checking EmailRep for: {target}")
        try:
            response = requests.get(f"https://emailrep.io/{target}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.log_result(f"Email: {data.get('email', 'N/A')}")
                self.log_result(f"Reputation: {data.get('reputation', 'N/A')}")
                self.log_result(f"Suspicious: {data.get('suspicious', 'N/A')}")
                self.log_result(f"Details: {json.dumps(data, indent=2)}")
            else:
                self.log_result(f"Error: {response.status_code}")
        except Exception as e:
            self.log_result(f"Error: {str(e)}")
            webbrowser.open(f"https://emailrep.io/{target}")
        self.update_status("EmailRep check completed")
        
    def run_hibp(self, target):
        self.log_result(f"Checking Have I Been Pwned for: {target}")
        webbrowser.open(f"https://haveibeenpwned.com/account/{target}")
        self.update_status("HIBP opened in browser")
        
    def run_hunter(self, target):
        self.log_result(f"Searching Hunter.io for: {target}")
        webbrowser.open(f"https://hunter.io/search/{target}")
        self.update_status("Hunter.io opened in browser")
        
    def run_email_format(self, target):
        self.log_result(f"Finding email format for: {target}")
        webbrowser.open(f"https://www.email-format.com/d/{target}/")
        self.update_status("Email Format opened in browser")
        
    def run_breach_directory(self, target):
        self.log_result(f"Checking Breach Directory for: {target}")
        webbrowser.open(f"https://breachdirectory.tk/?q={target}")
        self.update_status("Breach Directory opened in browser")
        
    def run_basic_email_search(self, target):
        self.log_result(f"Performing basic email analysis for: {target}")
        if "@" in target:
            domain = target.split("@")[1]
            self.log_result(f"Domain: {domain}")
            self.log_result(f"Email format: {target}")
        else:
            self.log_result("Invalid email format")
            
    # Domain/IP Tools
    def run_whois(self, target):
        self.log_result(f"Performing WHOIS lookup for: {target}")
        try:
            import whois
            try:
                w = whois.whois(target)
                self.log_result(f"Domain: {w.domain}")
                self.log_result(f"Registrar: {w.registrar}")
                self.log_result(f"Creation Date: {w.creation_date}")
                self.log_result(f"Expiration Date: {w.expiration_date}")
                self.log_result(f"Name Servers: {w.name_servers}")
                self.update_status("WHOIS lookup completed")
            except Exception as e:
                self.log_result(f"WHOIS lookup failed: {str(e)}")
                self.log_result("Opening web lookup...")
                webbrowser.open(f"https://whois.net/{target}")
                self.update_status("WHOIS web lookup opened")
        except ImportError:
            self.log_result("python-whois not installed. Opening web lookup...")
            webbrowser.open(f"https://whois.net/{target}")
            self.update_status("WHOIS web lookup opened")
        
    def run_shodan(self, target):
        self.log_result(f"Searching Shodan for: {target}")
        webbrowser.open(f"https://www.shodan.io/search?query={target}")
        self.update_status("Shodan opened in browser")
        
    def run_censys(self, target):
        self.log_result(f"Searching Censys for: {target}")
        webbrowser.open(f"https://search.censys.io/search?q={target}")
        self.update_status("Censys opened in browser")
        
    def run_virustotal(self, target):
        self.log_result(f"Checking VirusTotal for: {target}")
        webbrowser.open(f"https://www.virustotal.com/gui/search/{target}")
        self.update_status("VirusTotal opened in browser")
        
    def run_securitytrails(self, target):
        self.log_result(f"Searching SecurityTrails for: {target}")
        webbrowser.open(f"https://securitytrails.com/domain/{target}/overview")
        self.update_status("SecurityTrails opened in browser")
        
    def run_dns_dumpster(self, target):
        self.log_result(f"Searching DNS Dumpster for: {target}")
        webbrowser.open(f"https://dnsdumpster.com/")
        self.update_status("DNS Dumpster opened in browser")
        
    def run_basic_domain_search(self, target):
        self.log_result(f"Performing basic domain analysis for: {target}")
        try:
            import socket
            ip = socket.gethostbyname(target)
            self.log_result(f"IP Address: {ip}")
        except:
            self.log_result("Could not resolve domain to IP")
            
    # Phone Tools
    def run_truecaller(self, target):
        self.log_result(f"Searching TrueCaller for: {target}")
        webbrowser.open(f"https://www.truecaller.com/search/{target}")
        self.update_status("TrueCaller opened in browser")
        
    def run_syncme(self, target):
        self.log_result(f"Searching Sync.me for: {target}")
        webbrowser.open(f"https://sync.me/search/?number={target}")
        self.update_status("Sync.me opened in browser")
        
    def run_phoneinfoga(self, target):
        self.log_result(f"Running PhoneInfoga for: {target}")
        self.log_result("Note: PhoneInfoga requires installation")
        webbrowser.open(f"https://github.com/sundowndev/phoneinfoga")
        self.update_status("PhoneInfoga info opened")
        
    # Image Tools
    def run_reverse_image(self, target):
        self.log_result(f"Performing reverse image search for: {target}")
        webbrowser.open(f"https://www.google.com/searchbyimage?image_url={target}")
        self.update_status("Reverse image search opened")
        
    def run_tineye(self, target):
        self.log_result(f"Searching TinEye for: {target}")
        webbrowser.open(f"https://tineye.com/search?url={target}")
        self.update_status("TinEye opened in browser")
        
    def run_yandex_images(self, target):
        self.log_result(f"Searching Yandex Images for: {target}")
        webbrowser.open(f"https://yandex.com/images/search?url={target}")
        self.update_status("Yandex Images opened in browser")
        
    def run_exif(self, target):
        self.log_result(f"Extracting EXIF data from: {target}")
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            import requests
            
            response = requests.get(target, timeout=10)
            if response.status_code == 200:
                from io import BytesIO
                img = Image.open(BytesIO(response.content))
                exifdata = img.getexif()
                
                if exifdata:
                    for tag_id in exifdata:
                        tag = TAGS.get(tag_id, tag_id)
                        data = exifdata.get(tag_id)
                        self.log_result(f"{tag}: {data}")
                else:
                    self.log_result("No EXIF data found in image")
                self.update_status("EXIF extraction completed")
            else:
                self.log_result(f"Could not download image (Status: {response.status_code})")
                self.log_result("Opening web-based EXIF viewer...")
                webbrowser.open(f"https://exifdata.com/")
                self.update_status("EXIF web viewer opened")
        except ImportError:
            self.log_result("Pillow not installed. Opening web-based EXIF viewer...")
            webbrowser.open(f"https://exifdata.com/")
            self.update_status("EXIF web viewer opened")
        except Exception as e:
            self.log_result(f"Error extracting EXIF: {str(e)}")
            self.log_result("Opening web-based EXIF viewer...")
            webbrowser.open(f"https://exifdata.com/")
            self.update_status("EXIF web viewer opened")
        
    # Social Media Tools
    def run_facebook_search(self, target):
        self.log_result(f"Searching Facebook for: {target}")
        webbrowser.open(f"https://www.facebook.com/search/top/?q={target}")
        self.update_status("Facebook search opened")
        
    def run_twitter_search(self, target):
        self.log_result(f"Searching Twitter/X for: {target}")
        webbrowser.open(f"https://twitter.com/search?q={target}")
        self.update_status("Twitter search opened")
        
    def run_instagram_search(self, target):
        self.log_result(f"Searching Instagram for: {target}")
        webbrowser.open(f"https://www.instagram.com/{target}/")
        self.update_status("Instagram search opened")
        
    def run_linkedin_search(self, target):
        self.log_result(f"Searching LinkedIn for: {target}")
        webbrowser.open(f"https://www.linkedin.com/search/results/people/?keywords={target}")
        self.update_status("LinkedIn search opened")
        
    # People Search Tools
    def run_pipl(self, target):
        self.log_result(f"Searching Pipl for: {target}")
        webbrowser.open(f"https://pipl.com/search/?q={target}")
        self.update_status("Pipl opened in browser")
        
    def run_spokeo(self, target):
        self.log_result(f"Searching Spokeo for: {target}")
        webbrowser.open(f"https://www.spokeo.com/{target}")
        self.update_status("Spokeo opened in browser")
        
    def run_whitepages(self, target):
        self.log_result(f"Searching WhitePages for: {target}")
        webbrowser.open(f"https://www.whitepages.com/name/{target}")
        self.update_status("WhitePages opened in browser")
        
    # Dark Web Tools
    def run_tor_search(self, target):
        self.log_result(f"Searching Tor network for: {target}")
        self.log_result("Note: Requires Tor browser")
        webbrowser.open(f"https://ahmia.fi/search/?q={target}")
        self.update_status("Tor search opened")
        
    def run_ahmia(self, target):
        self.log_result(f"Searching Ahmia for: {target}")
        webbrowser.open(f"https://ahmia.fi/search/?q={target}")
        self.update_status("Ahmia opened in browser")
        
    # Blockchain Tools
    def run_blockchain_explorer(self, target):
        self.log_result(f"Searching blockchain for: {target}")
        webbrowser.open(f"https://www.blockchain.com/explorer/search?search={target}")
        self.update_status("Blockchain explorer opened")
        
    def run_etherscan(self, target):
        self.log_result(f"Searching Etherscan for: {target}")
        webbrowser.open(f"https://etherscan.io/search?q={target}")
        self.update_status("Etherscan opened in browser")
        
    # Document Tools
    def run_document_metadata(self, target):
        self.log_result(f"Extracting metadata from document: {target}")
        self.log_result("Note: Requires document download and analysis")
        webbrowser.open(f"https://www.metadata2go.com/")
        self.update_status("Document metadata tool opened")
        
    def run_pdf_analysis(self, target):
        self.log_result(f"Analyzing PDF: {target}")
        self.log_result("Note: Requires PDF download and analysis")
        webbrowser.open(f"https://www.pdf24.org/en/pdf-reader")
        self.update_status("PDF analysis tool opened")
        
    # Metadata Tools
    def run_exiftool(self, target):
        self.log_result(f"Running ExifTool on: {target}")
        self.log_result("Note: ExifTool requires installation")
        webbrowser.open(f"https://exiftool.org/")
        self.update_status("ExifTool info opened")
        
    def run_metadata_viewer(self, target):
        self.log_result(f"Viewing metadata for: {target}")
        webbrowser.open(f"https://www.metadata2go.com/")
        self.update_status("Metadata viewer opened")
        
    # Search Engine Tools
    def run_google_dorks(self, target):
        self.log_result(f"Google Dorks search for: {target}")
        dorks = [
            f'site:{target}',
            f'inurl:{target}',
            f'intitle:{target}',
            f'filetype:pdf {target}',
        ]
        for dork in dorks:
            self.log_result(f"Dork: {dork}")
        webbrowser.open(f"https://www.google.com/search?q={target}")
        self.update_status("Google Dorks search opened")
        
    def run_bing_search(self, target):
        self.log_result(f"Bing search for: {target}")
        webbrowser.open(f"https://www.bing.com/search?q={target}")
        self.update_status("Bing search opened")
        
    def run_duckduckgo(self, target):
        self.log_result(f"DuckDuckGo search for: {target}")
        webbrowser.open(f"https://duckduckgo.com/?q={target}")
        self.update_status("DuckDuckGo search opened")
        
    # DNS Tools
    def run_dns_lookup(self, target):
        self.log_result(f"Performing DNS lookup for: {target}")
        try:
            import socket
            self.log_result(f"A Record: {socket.gethostbyname(target)}")
        except Exception as e:
            self.log_result(f"Error: {str(e)}")
        webbrowser.open(f"https://dnschecker.org/#A/{target}")
        self.update_status("DNS lookup completed")
        
    def run_mx_records(self, target):
        self.log_result(f"Looking up MX records for: {target}")
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(target, 'MX')
            for mx in mx_records:
                self.log_result(f"MX: {mx.preference} {mx.exchange}")
            self.update_status("MX records lookup completed")
        except ImportError:
            self.log_result("dnspython not installed. Opening web lookup...")
            webbrowser.open(f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{target}")
            self.update_status("MX records web lookup opened")
        except Exception as e:
            self.log_result(f"DNS lookup failed: {str(e)}")
            self.log_result("Opening web lookup...")
            webbrowser.open(f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{target}")
            self.update_status("MX records web lookup opened")
        
    def run_ns_records(self, target):
        self.log_result(f"Looking up NS records for: {target}")
        try:
            import dns.resolver
            ns_records = dns.resolver.resolve(target, 'NS')
            for ns in ns_records:
                self.log_result(f"NS: {ns}")
            self.update_status("NS records lookup completed")
        except ImportError:
            self.log_result("dnspython not installed. Opening web lookup...")
            webbrowser.open(f"https://dnschecker.org/#NS/{target}")
            self.update_status("NS records web lookup opened")
        except Exception as e:
            self.log_result(f"DNS lookup failed: {str(e)}")
            self.log_result("Opening web lookup...")
            webbrowser.open(f"https://dnschecker.org/#NS/{target}")
            self.update_status("NS records web lookup opened")
        
    # Subdomain Tools
    def run_subfinder(self, target):
        self.log_result(f"Running Subfinder for: {target}")
        self.log_result("Note: Subfinder requires installation")
        webbrowser.open(f"https://github.com/projectdiscovery/subfinder")
        self.update_status("Subfinder info opened")
        
    def run_amass(self, target):
        self.log_result(f"Running Amass for: {target}")
        self.log_result("Note: Amass requires installation")
        webbrowser.open(f"https://github.com/OWASP/Amass")
        self.update_status("Amass info opened")
        
    def run_crtsh(self, target):
        self.log_result(f"Searching crt.sh for: {target}")
        webbrowser.open(f"https://crt.sh/?q={target}")
        self.update_status("crt.sh opened in browser")
        
    # Vulnerability Tools
    def run_cve_search(self, target):
        self.log_result(f"Searching CVE database for: {target}")
        webbrowser.open(f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={target}")
        self.update_status("CVE search opened")
        
    def run_exploitdb(self, target):
        self.log_result(f"Searching Exploit-DB for: {target}")
        webbrowser.open(f"https://www.exploit-db.com/search?q={target}")
        self.update_status("Exploit-DB opened in browser")

if __name__ == "__main__":
    app = OSINTApp()
    app.mainloop()


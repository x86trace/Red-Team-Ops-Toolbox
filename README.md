### Web Reconnaissance Tools

- **EyeWitness:** Takes screenshots of websites, provides server header info, and identifies default credentials if possible.
- **AWSBucketDump:** Enumerates AWS S3 buckets to look for loot.
- **AQUATONE:** Performs reconnaissance on domain names.
- **spoofcheck:** Checks if a domain can be spoofed, checking SPF and DMARC records for weak configurations.
- **Nmap:** Discovers hosts and services on a computer network, building a network map.
- **dnsrecon:** A tool for DNS enumeration.
- **dirsearch:** Brute forces directories and files in websites.
- **Sn1per:** An automated pentest recon scanner.

### OSINT and Reconnaissance

- **Social Mapper:** Automates target searching across multiple social media sites.
- **skiptracer:** Scrapes PII paywall sites to compile passive information on a target.
- **FOCA (Fingerprinting Organizations with Collected Archives):** Finds metadata and hidden information in documents.
- **theHarvester:** Gathers subdomain names, email addresses, virtual hosts, and more from public sources.
- **Metagoofil:** Extracts metadata from public documents (pdf, doc, xls, ppt) on target websites.
- **SimplyEmail:** Simplifies email reconnaissance.
- **truffleHog:** Searches through Git repositories for secrets in commit history.
- **Just-Metadata:** Gathers and analyzes metadata about IP addresses.
- **typofinder:** Finds domain typos and identifies the country of IP addresses.
- **pwnedOrNot:** Checks if an email account has been compromised in a data breach and finds passwords.
- **GitHarvester:** Harvests information from GitHub using Google Dorks.
- **pwndb:** Searches for leaked credentials using the Onion service with the same name.
- **LinkedInt:** LinkedIn Recon Tool.
- **CrossLinked:** Extracts valid employee names from an organization through search engine scraping.
- **findomain:** A fast domain enumeration tool that uses Certificate Transparency logs and APIs.

### Document Metadata and Exploitation

- **Maltego:** Delivers a clear threat picture for organizational environments.
- **SpiderFoot:** An open-source footprinting and intelligence-gathering tool.
- **datasploit:** An OSINT Framework for various recon techniques on Companies, People, Phone Numbers, Bitcoin Addresses, etc.
- **Recon-ng:** A full-featured Web Reconnaissance framework written in Python.

### Exploits and Payloads

- **WinRAR Remote Code Execution Proof of Concept:** Exploit for CVE-2018-20250.
- **Composite Moniker Proof of Concept:** Exploit for CVE-2017-8570.
- **Exploit toolkit CVE-2017-8759:** A Python script for testing Microsoft .NET Framework RCE.
- **CVE-2017-11882 Exploit:** Accepts over 17k bytes long command/code in maximum.
- **Adobe Flash Exploit CVE-2018-4878:** Exploit for Adobe Flash.
- **Exploit toolkit CVE-2017-0199:** A Python script for testing Microsoft Office RCE.
- **demiguise:** An HTA encryption tool for Red Teams.
- **Office-DDE-Payloads:** Collection of scripts and templates to generate Office documents embedded with DDE.
- **CACTUSTORCH:** Payload Generation for Adversary Simulations.
- **SharpShooter:** A payload creation framework for executing arbitrary CSharp source code.
- **Don’t kill my cat:** Generates obfuscated shellcode stored inside polyglot images.
- **Malicious Macro Generator Utility:** Generates obfuscated macros with an AV/Sandboxes escape mechanism.
- **SCT Obfuscator:** Cobalt Strike SCT payload obfuscator.
- **Invoke-Obfuscation:** PowerShell Obfuscator.
- **Invoke-CradleCrafter:** PowerShell remote download cradle generator and obfuscator.
- **Invoke-DOSfuscation:** cmd.exe Command Obfuscation Generator & Detection Test Harness.
- **morphHTA:** Morphs Cobalt Strike's evil.HTA.
- **Unicorn:** A tool for using a PowerShell downgrade attack to inject shellcode into memory.
- **Shellter:** A dynamic shellcode injection tool.
- **EmbedInHTML:** Embeds and hides any file in an HTML file.
- **SigThief:** Steals signatures and makes one invalid signature at a time.
- **Veil:** A tool for generating Metasploit payloads that bypass common anti-virus solutions.
- **CheckPlease:** Sandbox evasion modules written in various languages.
- **Invoke-PSImage:** Embeds a PowerShell script in the pixels of a PNG file and generates a one-liner to execute.
- **LuckyStrike:** A PowerShell-based utility for creating malicious Office macro documents.
- **ClickOnceGenerator:** Generates malicious ClickOnce applications for Red Team purposes.
- **macro_pack:** Automates obfuscation and generation of MS Office documents, VB scripts, and other formats for pentesting, demo, and social engineering assessments.
- **StarFighters:** A JavaScript and VBScript-Based Empire Launcher.
- **nps_payload:** Generates payloads for basic intrusion detection avoidance.

### Phishing and Social Engineering

- **King Phisher:** A tool for testing and promoting user awareness through simulated phishing attacks.
- **FiercePhish:** A phishing framework to manage phishing campaigns, schedule email sending, and more.
- **ReelPhish:** A real-time two-factor phishing tool.
- **Gophish:** An open-source phishing toolkit for businesses and penetration testers.
- **CredSniper:** A phishing framework for capturing 2FA tokens.
- **PwnAuth:** A web application framework for launching and managing OAuth abuse campaigns.
- **Phishing Frenzy:** A Ruby on Rails Phishing Framework.
- **Phishing Pretexts:** A library of pretexts for offensive phishing engagements.
- **Modlishka:** A flexible reverse proxy for ethical phishing campaigns.
- **Evilginx2:** A man-in-the-middle attack framework for phishing credentials and session cookies.

### Browser Exploitation Framework

- **BeEF (The Browser Exploitation Framework):** A penetration testing tool focusing on web browser exploitation.

### Adversary Simulation and Red Team Tools

- **Cobalt Strike:** Software for Adversary Simulations and Red Team Operations.
- **Empire:** A post-exploitation framework with Windows and Linux/OS X agents.
- **Metasploit Framework:** A computer security project for information about vulnerabilities and penetration testing.
- **SILENTTRINITY:** A post-exploitation agent powered by Python, IronPython, C#/.NET.
- **Pupy:** A remote administration and post-exploitation tool written in Python.
- **Koadic (COM Command & Control):** A Windows post-exploitation rootkit.
- **PoshC2:** A proxy-aware C2 framework written in PowerShell.
- **Merlin:** A cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang.
- **Quasar:** A fast and lightweight remote administration tool coded in C#.
- **Covenant:** A .NET command and control framework for red teamers.
- **FactionC2:** A C2 framework using websockets-based APIs.
- **DNScat2:** A tool for creating encrypted C&C channels over the DNS protocol.
- **Sliver:** A general-purpose cross-platform implant framework supporting C2 over Mutual-TLS, HTTP(S), and DNS.
- **EvilOSX:** A remote administration tool for macOS/OS X.
- **EggShell:** A post-exploitation surveillance tool written in Python.
- **Gcat:** A stealthy Python-based backdoor using Gmail as a command and control server.
- **TrevorC2:** A website for covert command execution that tunnels client/server communications.

### Rapid Attack Infrastructure and Infrastructure Setup

- **Rapid Attack Infrastructure (RAI):** Simplifies Red Team infrastructure setup.
- **Red Baron:** Provides modules and providers for Terraform to automate infrastructure setup.
- **EvilURL:** Generates unicode evil domains for IDN Homograph Attacks.
- **Domain Hunter:** Checks expired domains, bluecoat categorization, and Archive.org history for phishing and C2 domain names.
- **PowerDNS:** Executes PowerShell scripts using DNS only.
- **Chameleon:** A tool for evading proxy categorization.
- **CatMyFish:** Searches for categorized domains for whitelisted Cobalt Strike beacon C&C.
- **Malleable C2:** Redefines indicators in Beacon’s communication.
- **Malleable-C2-Randomizer:** Randomizes Cobalt Strike Malleable C2 profiles.
- **FindFrontableDomains:** Searches for potential frontable domains.
- **Postfix-Server-Setup:** Sets up a phishing server quickly.
- **DomainFrontingLists:** Lists domain frontable domains by CDN.
- **Apache2-Mod-Rewrite-Setup:** Quickly implements Mod-Rewrite in your infrastructure.
- **mod_rewrite rule:** Evades vendor sandboxes with a mod_rewrite rule.
- **external_c2 framework:** A Python framework for usage with Cobalt Strike’s External C2.
- **Malleable-C2-Profiles:** A collection of profiles used in different projects using Cobalt Strike.
- **ExternalC2:** A library for integrating communication channels with the Cobalt Strike External C2 server.
- **cs2modrewrite:** A tool to convert Cobalt Strike profiles to mod_rewrite scripts.
- **e2modrewrite:** A tool to convert Empire profiles to Apache mod_rewrite scripts.
- **redi:** An automated script for setting up Cobalt Strike redirectors (nginx reverse proxy, letsencrypt).
- **cat-sites:** A library of sites for categorization.
- **ycsm:** A script for resilient redirector setup using nginx reverse proxy and letsencrypt, compatible with popular Post-Ex Tools.
- **Domain Fronting Google App Engine:** A technique for domain fronting using Google App Engine.
- **DomainFrontDiscover:** Scripts and results for finding domain frontable CloudFront domains.
- **Automated Empire Infrastructure:** Automation scripts for Empire infrastructure setup.
- **Serving Random Payloads with NGINX:** Serves conditional Red Team payloads.
- **meek:** A blocking-resistant pluggable transport for Tor.
- **CobaltStrike-ToolKit:** Useful scripts for Cobalt Strike.
- **mkhtaccess_red:** Auto-generates an HTaccess file for payload delivery.
- **RedFile:** A flask WSGI application that serves files with intelligence.
- **keyserver:** Easily serves HTTP and DNS keys for payload protection.
- **DoHC2:** Leverages ExternalC2 for command and control via DNS over HTTPS (DoH).
- **HTran:** A connection bouncer for proxying connections.
- **ps1encode:** Generates and encodes PowerShell-based Metasploit payloads.
- **Worse PDF:** Turns a normal PDF file into a malicious one, stealing Net-NTLM Hashes from Windows machines.
- **SpookFlare:** Bypasses security measures and allows endpoint and network-side detection bypass.
- **GreatSCT:** An open-source project to generate application whitelist bypasses for both Red and Blue Teams.
- **nps:** Runs PowerShell without PowerShell.
- **Meterpreter_Paranoid_Mode.sh:** Secures Meterpreter connections by checking the certificate of the handler.
- **The Backdoor Factory (BDF):** Patches executable binaries with user-desired shellcode to continue normal execution.
- **MacroShop:** A collection of scripts for delivering payloads via Office Macros.
- **UnmanagedPowerShell:** Executes PowerShell from an unmanaged process.
- **evil-ssdp:** Spoofs SSDP replies to phish for NTLM hashes on a network.
- **Ebowla Framework:** For making environmental-keyed payloads.
- **make-pdf-embedded:** A tool to create a PDF document with an embedded file.
- **avet (AntiVirusEvasionTool):** Targets Windows machines with executable files using evasion techniques.
- **EvilClippy:** A cross-platform assistant for creating malicious MS Office documents.
- **CallObfuscator:** Obfuscates Windows APIs from static analysis tools and debuggers.
- **Donut:** A shellcode generation tool for injecting .NET assemblies into arbitrary Windows processes.

### Active Directory Enumeration and Lateral Movement

- **CrackMapExec:** A swiss army knife for pentesting networks.
- **PowerLessShell:** Relies on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe.
- **GoFetch:** Automatically exercises an attack plan generated by BloodHound.
- **ANGRYPUPPY:** Automates attack path execution in CobaltStrike.
- **DeathStar:** Automates gaining Domain Admin rights in Active Directory environments.
- **SharpHound:** A C# rewrite of the BloodHound Ingestor.
- **BloodHound.py:** A Python-based ingestor for BloodHound, based on Impacket.
- **Responder:** A LLMNR, NBT-NS, and MDNS poisoner with built-in rogue authentication server.
- **SessionGopher:** Extracts saved session information for remote access tools.
- **PowerSploit:** A collection of PowerShell modules to aid penetration testers.
- **Nishang:** A framework and collection of scripts and payloads for using PowerShell in offensive security.
- **Inveigh:** A Windows PowerShell LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool.
- **PowerUpSQL:** A PowerShell Toolkit for attacking SQL Server.
- **MailSniper:** A tool for searching through email in a Microsoft Exchange environment.
- **DomainPasswordSpray:** Performs a password spray attack against users of a domain.
- **WMIOps:** Uses WMI to perform various actions on hosts within a Windows environment.
- **Mimikatz:** A utility that enables the viewing of credential information from the Windows lsass.
- **LaZagne:** Retrieves stored passwords on a local computer.
- **mimipenguin:** Dumps the login password from the current Linux desktop user.
- **PsExec:** Launches Windows programs on remote Windows computers without needing to install software on the remote computer.
- **KeeThief:** Extracts KeePass 2.X key material from memory and backdoors
- **PSAttack**: Combines some of the best projects in the infosec PowerShell community into a self-contained custom PowerShell console.
- **Internal Monologue Attack**: Retrieves NTLM Hashes without touching LSASS.
- **Impacket**: A collection of Python classes for working with network protocols. Impacket focuses on providing low-level programmatic access to packets and, for some protocols (e.g., NMB, SMB1-3, and MS-DCERPC), the protocol implementation itself.
- **icebreaker**: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment.
- **Living Off The Land Binaries and Scripts (and now also Libraries)**: The goal of these lists is to document every binary, script, and library that can be used for other purposes than they are designed to.
- **WSUSpendu**: Designed for compromised WSUS servers to extend the compromise to clients.
- **Evilgrade**: A modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates.
- **NetRipper**: A post-exploitation tool targeting Windows systems, which uses API hooking to intercept network traffic and encryption-related functions from a low-privileged user, capturing both plain-text and encrypted traffic before encryption/after decryption.
- **LethalHTA**: A lateral movement technique using DCOM and HTA.
- **Invoke-PowerThIEf**: An Internet Explorer Post Exploitation library.
- **RedSnarf**: A pen-testing/red-teaming tool for Windows environments.
- **HoneypotBuster**: A Microsoft PowerShell module designed for red teams to find honeypots and honeytokens on the network or at the host.
- **PAExec**: Allows you to launch Windows programs on remote Windows computers without needing to install software on the remote computer first.

### Establish Foothold

- **Tunna**: A set of tools that wrap and tunnel any TCP communication over HTTP, used to bypass network restrictions in fully firewalled environments.
- **reGeorg**: The successor to reDuh, allowing you to pwn a bastion webserver and create SOCKS proxies through the DMZ for pivoting and pwning.
- **Blade**: A webshell connection tool based on console, currently under development and aims to be a choice of replacement for Chooper.
- **TinyShell**: A web shell framework.
- **PowerLurk**: A PowerShell toolset for building malicious WMI Event Subscriptions.
- **DAMP (The Discretionary ACL Modification Project)**: A project focused on achieving persistence through host-based Security Descriptor Modification.

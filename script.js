document.addEventListener('DOMContentLoaded', () => {
    const codeContainer = document.getElementById('code-container');
    const attackModal = document.getElementById('attack-modal');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const successScreen = document.getElementById('success-screen');
    const cursorElement = document.getElementById('cursor');
    const newsModal = document.getElementById('news-modal');
    const newsFeed = document.getElementById('news-feed');
    
    // Sample code snippets in different languages
    const codeSnippets = [
        // Python
        `def hack_mainframe(target_ip):
    print(f"Initializing attack on {target_ip}")
    firewall_bypass = SecurityProtocol.bypass()
    if firewall_bypass.success:
        encrypted_data = target.fetch_data()
        decryption_key = generate_master_key(algorithm="AES-256")
        decrypted_data = decrypt(encrypted_data, decryption_key)
        return {
            "status": "SUCCESS",
            "data": decrypted_data,
            "access_level": "ROOT"
        }
    return {"status": "FAILED", "reason": firewall_bypass.error_code}`,

        // JavaScript
        `async function penetrateSecuritySystem() {
    const targetSystems = await scanNetwork();
    const vulnerabilities = [];
    
    for (const system of targetSystems) {
        console.log(\`Analyzing \${system.hostname} (\${system.ip})\`);
        const systemVulnerabilities = await scanForVulnerabilities(system);
        vulnerabilities.push(...systemVulnerabilities);
    }
    
    if (vulnerabilities.length > 0) {
        console.log(\`Found \${vulnerabilities.length} potential exploits\`);
        const exploit = selectOptimalExploit(vulnerabilities);
        const shell = await deployExploit(exploit);
        
        if (shell.status === 'connected') {
            return await escalatePrivileges(shell);
        }
    }
    
    throw new Error('Penetration failed. Increased security measures detected.');
}`,

        // C++
        `#include <iostream>
#include <vector>
#include <string>
#include "NetworkExploit.h"

class SystemHacker {
private:
    std::string targetIP;
    std::vector<Vulnerability> knownVulnerabilities;
    EncryptionBreaker encryptionTools;
    
public:
    SystemHacker(std::string ip) : targetIP(ip) {
        std::cout << "Initializing hacking tools for target: " << targetIP << std::endl;
        loadExploitLibrary();
    }
    
    bool bypassFirewall() {
        FirewallAnalyzer analyzer(targetIP);
        FirewallType type = analyzer.detectFirewallType();
        
        switch(type) {
            case FirewallType::CISCO:
                return executeCiscoExploit();
            case FirewallType::FORTINET:
                return executeFortiguardBypass();
            default:
                return executeGenericBypass();
        }
    }
    
    std::vector<std::string> extractSensitiveData() {
        if (!bypassFirewall()) {
            throw std::runtime_error("Failed to bypass firewall. Aborting mission.");
        }
        
        DatabaseConnector connector(targetIP);
        return connector.extractAllTables();
    }
};`,

        // Java
        `public class SecurityBreacher {
    private String targetDomain;
    private Map<String, Vulnerability> vulnerabilityDatabase;
    private static final Logger logger = LogManager.getLogger(SecurityBreacher.class);
    
    public SecurityBreacher(String domain) {
        this.targetDomain = domain;
        this.vulnerabilityDatabase = VulnerabilityScanner.getLatestVulnerabilities();
        logger.info("Security breacher initialized for target: {}", targetDomain);
    }
    
    public BreachResult executeAttack() throws SecurityException {
        try {
            logger.debug("Starting reconnaissance phase...");
            List<ServerEndpoint> endpoints = scanForEndpoints();
            
            Optional<ServerEndpoint> vulnerableEndpoint = endpoints.stream()
                .filter(this::isVulnerableToAttack)
                .findFirst();
                
            if (vulnerableEndpoint.isPresent()) {
                ServerEndpoint target = vulnerableEndpoint.get();
                logger.info("Vulnerable endpoint found: {}", target.getUrl());
                
                Exploit exploit = buildExploitForEndpoint(target);
                BreachResult result = exploit.execute();
                
                if (result.isSuccessful()) {
                    DataExtractor extractor = new DataExtractor(result.getShellAccess());
                    return new BreachResult(true, extractor.extractAllData());
                }
            }
            
            return new BreachResult(false, "No vulnerabilities found");
        } catch (Exception e) {
            logger.error("Attack failed: {}", e.getMessage());
            throw new SecurityException("Attack interrupted by defensive systems");
        }
    }
}`
    ];
    
    let currentSnippetIndex = Math.floor(Math.random() * codeSnippets.length);
    let currentSnippet = codeSnippets[currentSnippetIndex];
    let displayedCode = '';
    let charIndex = 0;

    // Cursor position
    let cursorPosition = { x: 0, y: 0 };
    
    // Success screen data
    const usernames = ['admin', 'root', 'system', 'guest', 'user', 'operator', 'service', 'manager', 'supervisor', 'tech'];
    const domains = ['server1.local', 'dataserver.corp', 'mainframe.sys', 'backupnode.net', 'firewall01.internal', 'vpn.secure.net'];
    const ipRanges = ['192.168.1', '10.0.0', '172.16.0', '8.8.8', '54.231.0'];
    const commands = {
        'help': 'Display available commands',
        'ls': 'List files in current directory',
        'cat': 'Display file contents',
        'ping': 'Test network connection',
        'ssh': 'Connect to remote server',
        'whoami': 'Display current user',
        'ifconfig': 'Display network configuration',
        'netstat': 'Display network status',
        'pwd': 'Print working directory',
        'download': 'Download file from server',
        'backdoor': 'Install backdoor on remote system',
        'encrypt': 'Encrypt file or data',
        'decrypt': 'Decrypt file or data',
        'brute': 'Run brute force attack',
        'clear': 'Clear the terminal'
    };
    
    // Initialize cursor
    updateCursorPosition();
    
    // Helper function to check if modals are visible
    function isAnyModalVisible() {
        return attackModal.style.display === 'flex' || successScreen.style.display === 'flex' || successScreen.style.display === 'block';
    }
    
    // Handle typing
    document.addEventListener('keydown', (event) => {
        // If attack modal or success screen is visible, don't process typing
        if (isAnyModalVisible()) {
            return;
        }
        
        // For Enter key, show the attack modal
        if (event.key === 'Enter') {
            showAttackProgress();
            return;
        }
        
        // For any other key press, display code
        addCodeToDisplay();
    });
    
    function addCodeToDisplay() {
        // Decide if we display a single character or multiple characters
        const displayAmount = Math.random() < 0.7 ? 
            Math.floor(Math.random() * 5) + 1 : // Multiple chars (1-5)
            1; // Single char
        
        for (let i = 0; i < displayAmount; i++) {
            // Add next character from the code snippet
            if (charIndex < currentSnippet.length) {
                displayedCode += currentSnippet[charIndex];
                charIndex++;
            } else {
                // Move to next snippet when current one is finished
                currentSnippetIndex = (currentSnippetIndex + 1) % codeSnippets.length;
                currentSnippet = codeSnippets[currentSnippetIndex];
                charIndex = 0;
                displayedCode += '\n\n';
            }
        }
        
        // Update the display
        codeContainer.textContent = displayedCode;
        
        // Auto-scroll to bottom to show the latest code
        codeContainer.scrollTop = codeContainer.scrollHeight;
        
        // Update cursor position
        updateCursorPosition();
    }
    
    function updateCursorPosition() {
        // Get the current text
        const text = codeContainer.textContent;
        
        // Create a temporary span to measure where the cursor should be
        const temp = document.createElement('span');
        temp.style.visibility = 'hidden';
        temp.style.position = 'absolute';
        temp.style.whiteSpace = 'pre-wrap';
        temp.style.font = window.getComputedStyle(codeContainer).font;
        temp.style.width = window.getComputedStyle(codeContainer).width;
        
        // Add the text content up to the cursor position
        temp.textContent = text;
        document.body.appendChild(temp);
        
        // Get position
        const rect = temp.getBoundingClientRect();
        const containerRect = codeContainer.getBoundingClientRect();
        
        // Calculate cursor position
        const cursorLeft = (rect.width % containerRect.width) || 0;
        const cursorTop = rect.height - parseInt(window.getComputedStyle(codeContainer).lineHeight);
        
        // Position cursor
        cursorElement.style.left = cursorLeft + 'px';
        cursorElement.style.top = cursorTop + 'px';
        
        // Clean up
        document.body.removeChild(temp);
    }
    
    function showAttackProgress() {
        // Possible outcomes for the hack attempt
        const outcomes = [
            { text: "ATTACK IN PROGRESS", color: "#f00", success: true },
            { text: "ACCESS DENIED", color: "#f00", success: false },
            { text: "INVALID CREDENTIALS", color: "#f00", success: false },
            { text: "FIREWALL DETECTED", color: "#f00", success: false },
            { text: "CONNECTION REFUSED", color: "#f00", success: false },
            { text: "SECURITY BREACH DETECTED", color: "#f00", success: false },
            { text: "INTRUSION ALERT", color: "#f00", success: false },
            { text: "WRONGIE", color: "#f00", success: false }
        ];
        
        // Randomly select an outcome (70% chance of success, 30% chance of failure)
        const randomOutcome = Math.random() < 0.7 ? outcomes[0] : outcomes[Math.floor(Math.random() * (outcomes.length - 1)) + 1];
        
        // Update modal heading
        const modalHeading = attackModal.querySelector('h2');
        modalHeading.textContent = randomOutcome.text;
        modalHeading.style.color = randomOutcome.color;
        
        // Show the attack modal
        attackModal.style.display = 'flex';
        
        // Reset progress bar color and text at the start
        progressBar.style.backgroundColor = "#0f0";
        progressText.textContent = "0%";
        
        let progress = 0;
        const progressInterval = setInterval(() => {
            // If this is a failed attempt, progress will stop at a random point between 10% and 80%
            const maxProgress = randomOutcome.success ? 100 : Math.floor(Math.random() * 70) + 10;
            
            // Increase progress by a random amount between 1-5%
            progress += Math.floor(Math.random() * 5) + 1;
            
            if (progress >= maxProgress) {
                progress = maxProgress;
                clearInterval(progressInterval);
                
                // For failures, add a message and change color
                if (!randomOutcome.success) {
                    progressText.textContent = "FAILED";
                    progressBar.style.backgroundColor = "#f00"; // Red for failure
                    
                    // Keep the failed state visible for longer
                    setTimeout(() => {
                        attackModal.style.display = 'none';
                        
                        // Reset progress bar color and text after hiding
                        progressBar.style.backgroundColor = "#0f0";
                        progressBar.style.width = "0%";
                        progressText.textContent = "0%";
                    }, 3000);
                } else {
                    // For success, hide attack modal and show success screen
                    setTimeout(() => {
                        attackModal.style.display = 'none';
                        
                        // Reset progress bar width
                        progressBar.style.width = "0%";
                        
                        // Show success screen with data
                        showSuccessScreen();
                    }, 2000);
                }
            }
            
            // Update progress bar and text
            progressBar.style.width = `${progress}%`;
            if (randomOutcome.success || progress < maxProgress) {
                progressText.textContent = `${progress}%`;
            }
        }, 100);
    }
    
    function showSuccessScreen() {
        console.log("showSuccessScreen called");
        
        // Get the terminal and success screen elements
        const terminal = document.querySelector('.terminal');
        const successScreen = document.getElementById('success-screen');
        const progressContainer = document.querySelector('.progress-container');
        
        console.log("Elements found:", { 
            terminal: terminal, 
            successScreen: successScreen,
            progressContainer: progressContainer
        });
        
        // Hide progress container and terminal, show success screen
        if (progressContainer) progressContainer.style.display = 'none';
        if (terminal) terminal.style.display = 'none';
        
        // Ensure success screen is visible with flex display
        if (successScreen) {
            console.log("Setting success screen display to flex");
            successScreen.style.display = 'flex';
        } else {
            console.error("Success screen element not found!");
            return; // Exit if success screen not found
        }
        
        // Generate fake user accounts
        generateUserAccounts();
        
        // Generate server data
        generateServerData();
        
        // Generate network map with improved visibility
        const networkMap = generateNetworkMap();
        console.log("Network map generated:", networkMap);
        
        // Add initial system logs
        addSystemLogs();
        
        // After initial logs finish appearing, add network-specific logs
        setTimeout(() => {
            addSystemLog("Network scan complete - " + networkMap.nodes.length + " nodes identified");
        }, 3500);
        
        setTimeout(() => {
            addSystemLog("Establishing secure connection to primary server...");
        }, 4000);
        
        setTimeout(() => {
            addSystemLog("Connection established - Access level: Administrator");
        }, 4500);
        
        // Randomly add more system logs about different nodes over time
        setTimeout(() => {
            const randomNode = networkMap.nodes[Math.floor(Math.random() * networkMap.nodes.length)];
            addSystemLog(`Detected active connection on ${randomNode.type} at coordinates (${Math.floor(randomNode.x)},${Math.floor(randomNode.y)})`);
            
            // Make this node active and animate it
            randomNode.active = true;
            if (networkMap.getContext) {
                animateNode(networkMap.getContext('2d'), randomNode);
            }
        }, 6000);
        
        setTimeout(() => {
            addSystemLog("Network activity detected - Packet injection successful");
        }, 8000);
        
        setTimeout(() => {
            addSystemLog("Security protocols bypassed - Full system access granted");
        }, 10000);
        
        // Set up the command input
        setupCommandInput();
        
        // Start auto-typing demonstration
        simulateAutoTyping();
        
        // Add close button functionality
        const closeButton = document.getElementById('close-success');
        if (closeButton) {
            closeButton.addEventListener('click', () => {
                console.log("Close button clicked");
                successScreen.style.display = 'none';
                terminal.style.display = 'block'; // Make terminal visible again
            });
        } else {
            console.error("Close button not found!");
        }
    }
    
    function generateUserAccounts() {
        const usersTable = document.getElementById('users-table');
        let tableHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Privilege</th>
                        <th>Last Login</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        const privileges = ['Admin', 'User', 'Guest', 'System', 'Root'];
        const statuses = ['Active', 'Inactive', 'Locked', 'Expired'];
        
        // Generate random users
        for (let i = 0; i < 8; i++) {
            const username = usernames[Math.floor(Math.random() * usernames.length)];
            const privilege = privileges[Math.floor(Math.random() * privileges.length)];
            const lastLogin = `${Math.floor(Math.random() * 30) + 1}/${Math.floor(Math.random() * 12) + 1}/2023`;
            const status = statuses[Math.floor(Math.random() * statuses.length)];
            
            tableHTML += `
                <tr data-username="${username}" class="clickable-row">
                    <td>${username}</td>
                    <td>${privilege}</td>
                    <td>${lastLogin}</td>
                    <td>${status}</td>
                </tr>
            `;
        }
        
        tableHTML += `</tbody></table>`;
        usersTable.innerHTML = tableHTML;
        
        // Add click event to rows
        const userRows = usersTable.querySelectorAll('.clickable-row');
        userRows.forEach(row => {
            row.addEventListener('click', () => {
                const username = row.getAttribute('data-username');
                addSystemLog(`Accessed user profile: ${username}`);
                
                // Highlight selected row
                userRows.forEach(r => r.classList.remove('selected'));
                row.classList.add('selected');
            });
        });
    }
    
    function generateServerData() {
        const serversTable = document.getElementById('servers-table');
        let tableHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>IP Address</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        const statuses = ['Online', 'Vulnerable', 'Secured', 'Offline'];
        
        // Generate random servers
        for (let i = 0; i < 7; i++) {
            const domain = domains[Math.floor(Math.random() * domains.length)];
            const ipBase = ipRanges[Math.floor(Math.random() * ipRanges.length)];
            const ip = `${ipBase}.${Math.floor(Math.random() * 254) + 1}`;
            const status = statuses[Math.floor(Math.random() * statuses.length)];
            
            tableHTML += `
                <tr data-server="${domain}" data-ip="${ip}" class="clickable-row">
                    <td>${domain}</td>
                    <td>${ip}</td>
                    <td>${status}</td>
                </tr>
            `;
        }
        
        tableHTML += `</tbody></table>`;
        serversTable.innerHTML = tableHTML;
        
        // Add click event to rows
        const serverRows = serversTable.querySelectorAll('.clickable-row');
        serverRows.forEach(row => {
            row.addEventListener('click', () => {
                const server = row.getAttribute('data-server');
                const ip = row.getAttribute('data-ip');
                addSystemLog(`Connected to server: ${server} (${ip})`);
                
                // Highlight selected row
                serverRows.forEach(r => r.classList.remove('selected'));
                row.classList.add('selected');
            });
        });
    }
    
    function generateNetworkMap() {
        const networkContainer = document.querySelector('#network-map');
        let canvas = document.createElement('canvas');
        networkContainer.innerHTML = '';
        networkContainer.appendChild(canvas);
        
        // Set canvas size to match container
        const containerRect = networkContainer.getBoundingClientRect();
        canvas.width = containerRect.width || 400;  // Fallback width if container has no width
        canvas.height = containerRect.height || 300; // Fallback height if container has no height
        
        // Make sure canvas is visible
        canvas.style.width = '100%';
        canvas.style.height = '100%';
        canvas.style.display = 'block';
        
        const ctx = canvas.getContext('2d');
        
        // Generate nodes
        const numNodes = 15 + Math.floor(Math.random() * 10); // 15-24 nodes for better visibility
        const nodes = [];
        
        // Store nodes on the canvas object for reference in animations
        canvas.nodes = nodes;
        
        // Create different types of nodes
        for (let i = 0; i < numNodes; i++) {
            const nodeType = Math.random() < 0.3 ? 'server' : 'client';
            const node = {
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                radius: nodeType === 'server' ? 8 : 5, // Larger nodes
                connections: [],
                type: nodeType,
                active: Math.random() < 0.4 // Some nodes start active
            };
            nodes.push(node);
        }
        
        // Create connections - each node connects to 2-5 other nodes
        nodes.forEach(node => {
            const numConnections = 2 + Math.floor(Math.random() * 4);
            
            // Sort other nodes by distance
            const otherNodes = [...nodes].filter(n => n !== node);
            otherNodes.sort((a, b) => {
                const distA = Math.sqrt(Math.pow(a.x - node.x, 2) + Math.pow(a.y - node.y, 2));
                const distB = Math.sqrt(Math.pow(b.x - node.x, 2) + Math.pow(b.y - node.y, 2));
                return distA - distB;
            });
            
            // Connect to closest nodes
            for (let i = 0; i < Math.min(numConnections, otherNodes.length); i++) {
                node.connections.push(otherNodes[i]);
            }
        });
        
        // Draw the network
        function drawNetwork() {
            // Clear canvas
            ctx.fillStyle = '#001500';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Draw grid lines for effect
            ctx.strokeStyle = 'rgba(0, 50, 0, 0.3)';
            ctx.lineWidth = 0.5;
            
            // Horizontal grid lines
            for (let y = 0; y < canvas.height; y += 20) {
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(canvas.width, y);
                ctx.stroke();
            }
            
            // Vertical grid lines
            for (let x = 0; x < canvas.width; x += 20) {
                ctx.beginPath();
                ctx.moveTo(x, 0);
                ctx.lineTo(x, canvas.height);
                ctx.stroke();
            }
            
            // Draw connections
            nodes.forEach(node => {
                node.connections.forEach(connectedNode => {
                    ctx.beginPath();
                    ctx.moveTo(node.x, node.y);
                    ctx.lineTo(connectedNode.x, connectedNode.y);
                    
                    // Line opacity based on node activity
                    const activityLevel = (node.active && connectedNode.active) ? 0.8 : 0.3;
                    ctx.strokeStyle = `rgba(0, 255, 0, ${activityLevel})`;
                    ctx.lineWidth = 1.5;
                    ctx.stroke();
                });
            });
            
            // Draw nodes
            nodes.forEach(node => {
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
                
                // Brighter color for active nodes
                if (node.active) {
                    ctx.fillStyle = node.type === 'server' ? '#0f0' : '#0f8';
                    // Add glow effect for active nodes
                    ctx.shadowColor = '#0f0';
                    ctx.shadowBlur = 10;
                } else {
                    ctx.fillStyle = node.type === 'server' ? '#0a0' : '#080';
                    ctx.shadowBlur = 0;
                }
                
                ctx.fill();
                ctx.shadowBlur = 0; // Reset shadow
            });
        }
        
        // Initial draw
        drawNetwork();
        
        // Animate some nodes (3-5 random nodes)
        const numAnimatedNodes = 3 + Math.floor(Math.random() * 3);
        const shuffledNodes = [...nodes].sort(() => Math.random() - 0.5);
        
        for (let i = 0; i < numAnimatedNodes; i++) {
            const node = shuffledNodes[i];
            node.active = true; // Ensure animated nodes are active
            animateNode(ctx, node);
        }
        
        // Add click events to nodes
        canvas.addEventListener('click', (e) => {
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            // Check if any node was clicked
            for (const node of nodes) {
                const dx = node.x - x;
                const dy = node.y - y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance <= node.radius + 5) { // Added a small buffer for easier clicking
                    // Toggle node active state
                    node.active = !node.active;
                    console.log(`Node ${node.type} ${node.active ? 'activated' : 'deactivated'}`);
                    
                    // If activated, start animation
                    if (node.active) {
                        animateNode(ctx, node);
                    }
                    
                    // Redraw network to update all connections
                    drawNetwork();
                    break;
                }
            }
        });
        
        // Handle window resize
        window.addEventListener('resize', () => {
            // Update canvas size
            const containerRect = networkContainer.getBoundingClientRect();
            canvas.width = containerRect.width;
            canvas.height = containerRect.height;
            
            // Reposition nodes to fit new canvas size
            nodes.forEach(node => {
                // Maintain relative position
                node.x = (node.x / canvas.width) * containerRect.width;
                node.y = (node.y / canvas.height) * containerRect.height;
            });
            
            // Redraw the network
            drawNetwork();
        });
        
        return canvas;
    }
    
    function animateNode(ctx, node) {
        let radius = node.radius;
        let alpha = 0.8; // Higher initial opacity
        let maxRadius = node.radius * 2.5; // Larger pulse
        
        const animate = () => {
            // Clear the area around the node
            ctx.beginPath();
            ctx.arc(node.x, node.y, maxRadius + 2, 0, Math.PI * 2);
            ctx.fillStyle = '#001500';
            ctx.fill();
            
            // Redraw the node
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.fillStyle = node.type === 'server' ? '#0c0' : '#0f0';
            ctx.fill();
            
            // Draw the pulsing effect
            radius += 0.5; // Faster expansion
            alpha -= 0.02;
            
            if (radius <= maxRadius && alpha > 0) {
                // Draw multiple concentric circles for stronger effect
                for (let i = 0; i < 3; i++) {
                    const pulseRadius = radius - (i * 3);
                    if (pulseRadius > node.radius) {
                        ctx.beginPath();
                        ctx.arc(node.x, node.y, pulseRadius, 0, Math.PI * 2);
                        ctx.strokeStyle = `rgba(0, 255, 0, ${alpha * (1 - i * 0.2)})`;
                        ctx.lineWidth = 1.5 - (i * 0.3);
                        ctx.stroke();
                    }
                }
                
                requestAnimationFrame(animate);
            } else {
                // Reset and repeat with random delay
                radius = node.radius;
                alpha = 0.8;
                setTimeout(() => requestAnimationFrame(animate), 1000 + Math.random() * 2000);
            }
        };
        
        // Start animation
        animate();
        
        // Add occasional data packet animation from this node to another random node
        const sendDataPacket = () => {
            // Only if node is still in the DOM
            if (!document.contains(ctx.canvas)) return;
            
            // Find a random target node
            const nodes = ctx.canvas.nodes || [];
            if (nodes.length > 1) {
                // Pick a different node as target
                let targetNode;
                do {
                    targetNode = nodes[Math.floor(Math.random() * nodes.length)];
                } while (targetNode === node);
                
                // Animate a data packet
                let progress = 0;
                const animatePacket = () => {
                    if (!document.contains(ctx.canvas)) return; // Check if canvas still exists
                    
                    // Clear previous position
                    ctx.beginPath();
                    const prevX = node.x + (targetNode.x - node.x) * (progress - 0.02);
                    const prevY = node.y + (targetNode.y - node.y) * (progress - 0.02);
                    ctx.arc(prevX, prevY, 3, 0, Math.PI * 2);
                    ctx.fillStyle = '#001500';
                    ctx.fill();
                    
                    // Update position
                    progress += 0.02;
                    const x = node.x + (targetNode.x - node.x) * progress;
                    const y = node.y + (targetNode.y - node.y) * progress;
                    
                    // Draw packet
                    ctx.beginPath();
                    ctx.arc(x, y, 3, 0, Math.PI * 2);
                    ctx.fillStyle = '#0f0';
                    ctx.fill();
                    
                    if (progress < 1) {
                        requestAnimationFrame(animatePacket);
                    }
                };
                
                // Start packet animation
                animatePacket();
            }
            
            // Schedule next packet
            setTimeout(sendDataPacket, 3000 + Math.random() * 5000);
        };
        
        // Start sending packets with delay
        setTimeout(sendDataPacket, 2000 + Math.random() * 3000);
    }
    
    function addSystemLogs() {
        // Add initial system logs
        const initialLogs = [
            "System initialized",
            "Starting reconnaissance protocol",
            "Scanning target system for vulnerabilities",
            "Vulnerability detected: CVE-2023-34821",
            "Exploiting security flaw in authentication system",
            "Bypassing firewall using zero-day exploit",
            "Establishing remote connection",
            "Accessing system files",
            "Downloading user database",
            "Cracking password hashes...",
            "Access granted to admin panel"
        ];
        
        // Add each log with a delay for a more realistic appearance
        initialLogs.forEach((log, index) => {
            setTimeout(() => {
                addSystemLog(log);
            }, index * 300);
        });
    }
    
    function addSystemLog(message) {
        const systemLogs = document.getElementById('system-logs');
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        // Create timestamp
        const timestamp = new Date();
        const timeString = `${timestamp.getHours().toString().padStart(2, '0')}:${timestamp.getMinutes().toString().padStart(2, '0')}:${timestamp.getSeconds().toString().padStart(2, '0')}.${timestamp.getMilliseconds().toString().padStart(3, '0')}`;
        
        // Create colored segments
        const timeSpan = document.createElement('span');
        timeSpan.className = 'log-timestamp';
        timeSpan.textContent = `[${timeString}] `;
        
        const statusSpan = document.createElement('span');
        
        // Determine log type based on message content
        if (message.includes('error') || message.includes('failed') || message.includes('denied')) {
            statusSpan.className = 'log-error';
            statusSpan.textContent = 'ERROR: ';
        } else if (message.includes('warning') || message.includes('detected')) {
            statusSpan.className = 'log-warning';
            statusSpan.textContent = 'WARNING: ';
        } else if (message.includes('success') || message.includes('complete') || message.includes('granted')) {
            statusSpan.className = 'log-success';
            statusSpan.textContent = 'SUCCESS: ';
        } else {
            statusSpan.className = 'log-info';
            statusSpan.textContent = 'INFO: ';
        }
        
        const messageSpan = document.createElement('span');
        messageSpan.className = 'log-message';
        messageSpan.textContent = message;
        
        // Assemble log entry
        logEntry.appendChild(timeSpan);
        logEntry.appendChild(statusSpan);
        logEntry.appendChild(messageSpan);
        
        // Apply entry animation with slight delay
        logEntry.style.opacity = '0';
        logEntry.style.transform = 'translateX(-10px)';
        
        // Add to system logs
        systemLogs.appendChild(logEntry);
        
        // Scroll to the latest log
        systemLogs.scrollTop = systemLogs.scrollHeight;
        
        // Trigger animation
        setTimeout(() => {
            logEntry.style.transition = 'opacity 0.3s ease-out, transform 0.3s ease-out';
            logEntry.style.opacity = '1';
            logEntry.style.transform = 'translateX(0)';
        }, 50);
        
        // Limit the number of logs (keep the latest 100)
        while (systemLogs.children.length > 100) {
            systemLogs.removeChild(systemLogs.firstChild);
        }
    }
    
    function setupCommandInput() {
        const commandInput = document.getElementById('command-input');
        const commandOutput = document.getElementById('command-output');
        const commandCursor = document.createElement('span');
        commandCursor.id = 'command-cursor';
        commandCursor.innerHTML = '█';
        commandCursor.classList.add('command-cursor');
        
        // Add cursor to command output
        commandOutput.appendChild(commandCursor);
        
        commandInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                const command = commandInput.value.trim();
                if (command) {
                    // Display the command with typing animation
                    simulateTyping(command, commandOutput);
                    
                    // Process the command (after typing animation)
                    setTimeout(() => {
                        processCommand(command);
                        
                        // Clear input
                        commandInput.value = '';
                        
                        // Move cursor to a new line
                        const newLine = document.createElement('div');
                        newLine.appendChild(commandCursor);
                        commandOutput.appendChild(newLine);
                        
                        // Scroll to bottom
                        commandOutput.scrollTop = commandOutput.scrollHeight;
                        
                        // Start typing another command after a delay
                        if (Math.random() > 0.5) {
                            setTimeout(simulateAutoTyping, 2000 + Math.random() * 3000);
                        }
                    }, command.length * 50 + 100);
                }
            }
        });
        
        // Focus the input when clicking anywhere on the command panel
        const commandPanel = commandInput.closest('.data-panel');
        commandPanel.addEventListener('click', () => {
            commandInput.focus();
        });
    }
    
    function simulateTyping(text, outputElement) {
        const commandLine = document.createElement('div');
        const promptSpan = document.createElement('span');
        promptSpan.classList.add('prompt');
        promptSpan.textContent = '$';
        commandLine.appendChild(promptSpan);
        
        // Add space after prompt
        commandLine.appendChild(document.createTextNode(' '));
        
        // Create a span for the typed text
        const typedText = document.createElement('span');
        commandLine.appendChild(typedText);
        
        // Add the command line to output
        outputElement.appendChild(commandLine);
        
        // Typing animation
        let i = 0;
        function type() {
            if (i < text.length) {
                typedText.textContent += text.charAt(i);
                i++;
                setTimeout(type, 30 + Math.random() * 70); // Random typing speed
                
                // Scroll as we type
                outputElement.scrollTop = outputElement.scrollHeight;
            }
        }
        
        // Start typing
        type();
        
        // Remove old cursor and return command line for further use
        const cursor = outputElement.querySelector('#command-cursor');
        if (cursor) cursor.remove();
        
        return commandLine;
    }
    
    function processCommand(command) {
        const commandOutput = document.getElementById('command-output');
        const output = document.createElement('div');
        
        // Process command
        const parts = command.split(' ');
        const cmd = parts[0].toLowerCase();
        
        switch (cmd) {
            case 'help':
                let helpText = 'Available commands:\n';
                for (const [cmd, desc] of Object.entries(commands)) {
                    helpText += `  ${cmd.padEnd(12)} - ${desc}\n`;
                }
                output.textContent = helpText;
                break;
                
            case 'ls':
                output.textContent = [
                    'data.db', 
                    'users.conf', 
                    'security.log', 
                    'backup.tar.gz', 
                    'passwords.enc'
                ].join('\n');
                break;
                
            case 'cat':
                if (parts.length > 1) {
                    if (parts[1] === 'users.conf') {
                        output.textContent = 'USER_CONFIG={\n  admin: "********",\n  root: "********",\n  system: "********"\n}';
                    } else if (parts[1] === 'security.log') {
                        output.textContent = '[WARNING] Multiple failed login attempts detected\n[INFO] System update completed\n[ERROR] Unauthorized access attempt from 192.168.1.45';
                    } else {
                        output.textContent = `File "${parts[1]}" is encrypted or not readable.`;
                    }
                } else {
                    output.textContent = 'Usage: cat <filename>';
                }
                break;
                
            case 'ping':
                if (parts.length > 1) {
                    output.textContent = `PING ${parts[1]} (${parts[1]}): 56 data bytes\n64 bytes from ${parts[1]}: icmp_seq=0 ttl=64 time=15.ms\n64 bytes from ${parts[1]}: icmp_seq=1 ttl=64 time=18.ms\n64 bytes from ${parts[1]}: icmp_seq=2 ttl=64 time=16.ms\n\n--- ${parts[1]} ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss\nround-trip min/avg/max/stddev = 15.423/16.531/18.245/1.521 ms`;
                } else {
                    output.textContent = 'Usage: ping <host>';
                }
                break;
                
            case 'whoami':
                output.textContent = 'root@hacked_system';
                break;
                
            case 'ifconfig':
                output.textContent = 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n      inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n      inet6 fe80::215:5dff:fe00:1  prefixlen 64  scopeid 0x20<link>\n      ether 00:15:5d:00:00:01  txqueuelen 1000  (Ethernet)';
                break;
                
            case 'netstat':
                output.textContent = 'Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN\ntcp6       0      0 :::22                   :::*                    LISTEN';
                break;
                
            case 'pwd':
                output.textContent = '/root/hacked_system';
                break;
                
            case 'download':
                if (parts.length > 1) {
                    simulateFileDownload(parts[1], output);
                } else {
                    output.textContent = 'Usage: download <filename>';
                }
                break;
                
            case 'backdoor':
                simulateBackdoorInstallation(output);
                break;
                
            case 'encrypt':
            case 'decrypt':
                if (parts.length > 1) {
                    output.textContent = `${cmd.toUpperCase()} OPERATION SUCCESSFUL\nOriginal: ${parts.slice(1).join(' ')}\nResult: ${scrambleText(parts.slice(1).join(' '))}`;
                } else {
                    output.textContent = `Usage: ${cmd} <text>`;
                }
                break;
                
            case 'brute':
                simulateBruteForce(output);
                break;
                
            case 'clear':
                commandOutput.innerHTML = '';
                const cursor = document.createElement('span');
                cursor.id = 'command-cursor';
                cursor.innerHTML = '█';
                cursor.classList.add('command-cursor');
                commandOutput.appendChild(cursor);
                return; // No need to append output
                
            default:
                output.textContent = `Command not found: ${cmd}`;
        }
        
        commandOutput.appendChild(output);
        addSystemLog(`Command executed: ${command}`);
    }
    
    function simulateFileDownload(filename, output) {
        output.innerHTML = `Downloading ${filename}...\n`;
        
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.floor(Math.random() * 10) + 1;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                output.innerHTML += `Download complete: ${filename}`;
            } else {
                output.innerHTML = `Downloading ${filename}...\nProgress: ${progress}%`;
            }
        }, 200);
    }
    
    function simulateBackdoorInstallation(output) {
        const steps = [
            "Analyzing target system...",
            "Identifying security vulnerabilities...",
            "Bypassing intrusion detection...",
            "Creating hidden access point...",
            "Installing persistent backdoor...",
            "Covering tracks...",
            "Backdoor installation complete. System compromised."
        ];
        
        let stepIndex = 0;
        output.textContent = steps[0];
        
        const interval = setInterval(() => {
            stepIndex++;
            if (stepIndex < steps.length) {
                output.textContent += `\n${steps[stepIndex]}`;
            } else {
                clearInterval(interval);
            }
        }, 500);
    }
    
    function simulateBruteForce(output) {
        const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
        const passwordLength = 8;
        let attempts = 0;
        let displayedPassword = '';
        
        output.textContent = 'Starting brute force attack...';
        
        const interval = setInterval(() => {
            attempts++;
            
            // Build up the password character by character
            if (displayedPassword.length < passwordLength) {
                displayedPassword += characters.charAt(Math.floor(Math.random() * characters.length));
            }
            
            if (attempts < 30) {
                // Show random password attempts
                const randomAttempt = Array(passwordLength).fill().map(() => 
                    characters.charAt(Math.floor(Math.random() * characters.length))
                ).join('');
                
                output.textContent = `Attempting passwords...\nAttempts: ${attempts}\nCurrent: ${randomAttempt}`;
            } else {
                // Show success
                clearInterval(interval);
                output.textContent = `Brute force successful after ${attempts} attempts\nPassword found: ${displayedPassword}`;
            }
        }, 100);
    }
    
    function scrambleText(text) {
        // Simple text "encryption/decryption" for visual effect
        const chars = text.split('');
        for (let i = 0; i < chars.length; i++) {
            // Leave spaces alone
            if (chars[i] !== ' ') {
                // Shift character code
                const charCode = chars[i].charCodeAt(0);
                chars[i] = String.fromCharCode(charCode + 5);
            }
        }
        return chars.join('');
    }

    function simulateAutoTyping() {
        const commandInput = document.getElementById('command-input');
        
        // Don't auto-type if the user is currently typing
        if (document.activeElement === commandInput && commandInput.value !== '') {
            return;
        }
        
        // Clear any existing text
        commandInput.value = '';
        
        // Sample commands to auto-type
        const sampleCommands = [
            'ls -la',
            'cat /etc/passwd',
            'whoami',
            'ping 192.168.1.1',
            'ifconfig',
            'ssh root@server',
            'netstat -an',
            'cd /var/www',
            'backdoor',
            'brute',
            'download sensitive_data.txt',
            'encrypt "top secret message"'
        ];
        
        // Pick a random command
        const randomCommand = sampleCommands[Math.floor(Math.random() * sampleCommands.length)];
        
        // Type the command character by character
        let i = 0;
        function typeChar() {
            if (i < randomCommand.length) {
                commandInput.value += randomCommand.charAt(i);
                i++;
                
                // Random typing speed
                setTimeout(typeChar, 50 + Math.random() * 150);
            } else {
                // After typing, wait a moment then "press" Enter
                setTimeout(() => {
                    // Create and dispatch an Enter key event
                    const enterEvent = new KeyboardEvent('keydown', {
                        key: 'Enter',
                        code: 'Enter',
                        bubbles: true
                    });
                    commandInput.dispatchEvent(enterEvent);
                }, 500 + Math.random() * 1000);
            }
        }
        
        // Start typing after a small delay
        setTimeout(typeChar, 800 + Math.random() * 1200);
    }

    // Add Hacker News functionality
    
    // Show news modal with a keypress (press 'n')
    document.addEventListener('keydown', (event) => {
        if (event.key === 'n' && !isAnyModalVisible()) {
            showNewsModal();
        }
    });
    
    // Add close button functionality for news modal
    const closeNewsButton = document.getElementById('close-news');
    if (closeNewsButton) {
        closeNewsButton.addEventListener('click', () => {
            newsModal.style.display = 'none';
        });
    }
    
    // Function to show news modal and fetch news
    function showNewsModal() {
        newsModal.style.display = 'flex';
        
        // Show loading state
        const loadingElement = newsModal.querySelector('.news-loading');
        loadingElement.style.display = 'block';
        newsFeed.style.display = 'none';
        
        // Animate loading text with delays
        const loadingLines = loadingElement.querySelectorAll('.terminal-line');
        loadingLines.forEach((line, index) => {
            setTimeout(() => {
                line.style.visibility = 'visible';
                // If this is the last line, fetch news after a delay
                if (index === loadingLines.length - 1) {
                    setTimeout(fetchHackerNews, 800);
                }
            }, index * 600);
            line.style.visibility = 'hidden';
        });
    }
    
    // Function to fetch top stories from Hacker News
    async function fetchHackerNews() {
        try {
            // Get top stories IDs
            const response = await fetch('https://hacker-news.firebaseio.com/v0/topstories.json');
            const storyIds = await response.json();
            
            // Get details of top 10 stories
            const topStories = storyIds.slice(0, 10);
            const storyPromises = topStories.map(id => 
                fetch(`https://hacker-news.firebaseio.com/v0/item/${id}.json`)
                    .then(response => response.json())
            );
            
            const stories = await Promise.all(storyPromises);
            
            // Display stories after a small delay
            setTimeout(() => {
                displayHackerNews(stories);
            }, 500);
            
        } catch (error) {
            console.error('Error fetching Hacker News:', error);
            newsFeed.innerHTML = `<div class="error-message">ERROR: NETWORK CONNECTION COMPROMISED</div>`;
            
            // Hide loading, show news feed
            newsModal.querySelector('.news-loading').style.display = 'none';
            newsFeed.style.display = 'block';
        }
    }
    
    // Function to display Hacker News stories
    function displayHackerNews(stories) {
        // Hide loading screen
        newsModal.querySelector('.news-loading').style.display = 'none';
        
        // Clear existing content
        newsFeed.innerHTML = '';
        
        // Filter for tech and hacking related stories (optional)
        const hackerKeywords = ['hack', 'security', 'breach', 'cyber', 'data', 'tech', 'programming', 'code', 'encrypt', 'algorithm', 'ai', 'intelligence'];
        
        // Create HTML for each story with a delay
        stories.forEach((story, index) => {
            setTimeout(() => {
                // Check if story title contains tech or hacking keywords
                const storyTitle = story.title.toLowerCase();
                const isHackerRelated = hackerKeywords.some(keyword => storyTitle.includes(keyword));
                
                // Prepare hostnames for display
                let hostname = '';
                if (story.url) {
                    try {
                        hostname = new URL(story.url).hostname;
                    } catch (e) {
                        hostname = story.url;
                    }
                }
                
                // Format time
                const timeAgo = getTimeAgo(story.time);
                
                // Add a class if the story is hacking-related
                const hackerClass = isHackerRelated ? 'hacker-news' : '';
                
                // Create news item HTML
                const newsItem = document.createElement('div');
                newsItem.className = `news-item ${hackerClass}`;
                newsItem.innerHTML = `
                    <div class="news-title" onclick="window.open('${story.url || `https://news.ycombinator.com/item?id=${story.id}`}', '_blank')">
                        ${story.title}
                    </div>
                    ${story.url ? `<div class="news-url">${hostname}</div>` : ''}
                    <div class="news-meta">
                        <span class="news-score">${story.score} points</span>
                        <span class="news-author">${story.by}</span>
                        <span class="news-time">${timeAgo}</span>
                    </div>
                `;
                
                // Add item to feed
                newsFeed.appendChild(newsItem);
                
                // Scroll to new item
                newsFeed.scrollTop = newsFeed.scrollHeight;
                
                // If this is the last item, show the feed
                if (index === stories.length - 1) {
                    newsFeed.style.display = 'block';
                }
            }, index * 200); // Stagger the display of items
        });
    }
    
    // Helper function to format time ago
    function getTimeAgo(timestamp) {
        const now = Math.floor(Date.now() / 1000);
        const seconds = now - timestamp;
        
        if (seconds < 60) return `${seconds}s ago`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    }
}); 
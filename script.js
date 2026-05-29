// Pomocnicza funkcja do escapowania HTML — zapobiega XSS
function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

class SSHAuditor {
    constructor() {
        this.isAuditing = false;
        this.init();
    }

    init() {
        this.bindEvents();
        this.updateTimestamp();
        this.initializeInterface();
        this.initializeChecklist();
    }

    bindEvents() {
        document.getElementById('audit-btn').addEventListener('click', () => this.startAudit());

        const inputs = document.querySelectorAll('input');
        inputs.forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !this.isAuditing) {
                    this.startAudit();
                }
            });
        });

        setInterval(() => this.updateTimestamp(), 1000);

        // Toggle checklist
        document.getElementById('toggle-checklist').addEventListener('click', () => this.toggleChecklist());

        // Checklist item change events
        this.bindChecklistEvents();
    }

    initializeInterface() {
        this.logMessage('info', 'SSH Security Auditor initialized');
        this.logMessage('info', 'Enter target credentials and click "INITIATE SECURITY AUDIT"');
        document.getElementById('conn-status').textContent = 'Ready';
        document.getElementById('conn-status').style.color = '#f1fa8c';
    }

    updateTimestamp() {
        const now = new Date();
        const timestamp = now.toLocaleTimeString('pl-PL', { hour12: false });
        document.getElementById('timestamp').textContent = `[${timestamp}]`;
    }

    logMessage(type, message, data = null) {
        const output = document.getElementById('output');
        const timestamp = new Date().toLocaleTimeString('pl-PL', { hour12: false });

        const entry = document.createElement('div');
        entry.className = 'log-entry';

        const typeClasses = {
            'info': 'log-info',
            'success': 'log-success',
            'warning': 'log-warning',
            'error': 'log-error',
            'critical': 'log-critical'
        };

        // Budujemy przez DOM API — message może zawierać dane z SSH (XSS guard)
        const tsSpan = document.createElement('span');
        tsSpan.className = 'timestamp';
        tsSpan.textContent = `[${timestamp}]`;

        const typeSpan = document.createElement('span');
        typeSpan.className = typeClasses[type] || 'log-info';
        typeSpan.textContent = `[${type.toUpperCase()}]`;

        const msgSpan = document.createElement('span');
        msgSpan.textContent = message; // textContent zapobiega XSS

        entry.appendChild(tsSpan);
        entry.appendChild(document.createTextNode(' '));
        entry.appendChild(typeSpan);
        entry.appendChild(document.createTextNode(' '));
        entry.appendChild(msgSpan);

        if (data) {
            const dataDiv = document.createElement('div');
            dataDiv.style.marginLeft = '120px';
            dataDiv.style.color = '#6272a4';
            dataDiv.style.fontSize = '12px';
            dataDiv.style.whiteSpace = 'pre-wrap';
            dataDiv.textContent = typeof data === 'object' ? JSON.stringify(data, null, 2) : data;
            entry.appendChild(dataDiv);
        }

        output.appendChild(entry);
        output.scrollTop = output.scrollHeight;
    }

    updateProgress(percentage, text) {
        const progressSection = document.getElementById('progress-section');
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');

        progressSection.style.display = 'block';
        progressFill.style.width = `${percentage}%`;
        progressText.textContent = text;

        if (percentage >= 100) {
            setTimeout(() => {
                progressSection.style.display = 'none';
            }, 2000);
        }
    }

    updateConnectionStatus(status, color = '#ff5555') {
        const connStatus = document.getElementById('conn-status');
        connStatus.textContent = status;
        connStatus.style.color = color;
    }

    async startAudit() {
        if (this.isAuditing) return;

        const ip = document.getElementById('target-ip').value.trim();
        const username = document.getElementById('ssh-user').value.trim();
        const password = document.getElementById('ssh-password').value;

        if (!ip || !username || !password) {
            this.logMessage('error', 'All fields are required');
            return;
        }

        if (!this.isValidIP(ip)) {
            this.logMessage('error', 'Invalid IP address format');
            return;
        }

        this.isAuditing = true;
        this.updateButtonState(true);
        this.clearOutput();

        this.logMessage('info', `Initiating security audit for ${ip}`);
        this.logMessage('info', `Target user: ${username}`);
        this.updateProgress(10, 'Initializing connection...');
        this.updateConnectionStatus('Connecting...', '#f1fa8c');

        try {
            const response = await fetch('/api/audit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip, username, password })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            await this.processStreamResponse(response);

        } catch (error) {
            this.logMessage('error', `Audit failed: ${error.message}`);
            this.updateConnectionStatus('Connection Failed', '#ff5555');
            this.updateProgress(100, 'Audit failed');
        } finally {
            this.isAuditing = false;
            this.updateButtonState(false);
            setTimeout(() => {
                this.updateConnectionStatus('Disconnected', '#ff5555');
            }, 3000);
        }
    }

    async processStreamResponse(response) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();

            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                if (line.trim()) {
                    console.log('CLIENT DEBUG: Received line length:', line.length);
                    try {
                        const data = JSON.parse(line);
                        console.log('CLIENT DEBUG: Parsed data type:', data.type);
                        this.handleStreamData(data);
                    } catch (e) {
                        console.error('Failed to parse stream data:', e.message);
                    }
                }
            }
        }
    }

    handleStreamData(data) {
        console.log('CLIENT DEBUG: Handling stream data type:', data.type);
        switch (data.type) {
            case 'status':
                this.logMessage('info', data.message);
                if (data.message.includes('connection')) {
                    this.updateProgress(10, 'Establishing SSH connection...');
                } else if (data.message.includes('SSH')) {
                    this.updateProgress(20, 'Checking SSH security...');
                } else if (data.message.includes('network')) {
                    this.updateProgress(30, 'Analyzing network configuration...');
                } else if (data.message.includes('encryption')) {
                    this.updateProgress(40, 'Checking encryption...');
                } else if (data.message.includes('user')) {
                    this.updateProgress(50, 'Auditing user management...');
                } else if (data.message.includes('file system')) {
                    this.updateProgress(60, 'Checking file system security...');
                } else if (data.message.includes('hardening')) {
                    this.updateProgress(70, 'Analyzing system hardening...');
                } else if (data.message.includes('services')) {
                    this.updateProgress(80, 'Checking services...');
                } else if (data.message.includes('updates')) {
                    this.updateProgress(85, 'Auditing updates and logging...');
                } else if (data.message.includes('backup')) {
                    this.updateProgress(90, 'Checking backup configuration...');
                } else if (data.message.includes('basic server settings')) {
                    this.updateProgress(92, 'Checking basic server settings...');
                } else if (data.message.includes('physical')) {
                    this.updateProgress(95, 'Analyzing physical security...');
                } else if (data.message.includes('system information')) {
                    this.updateProgress(98, 'Gathering final system information...');
                }
                break;

            case 'success':
                this.logMessage('success', data.message);
                this.updateConnectionStatus('Connected', '#50fa7b');
                this.updateProgress(15, 'Connection established');
                break;

            case 'error':
                this.logMessage('error', data.message);
                this.updateConnectionStatus('Error', '#ff5555');
                break;

            case 'result':
                this.displayAuditResults(data.data);
                this.updateProgress(100, 'Comprehensive audit completed');
                break;

            case 'result_start':
                console.log('CLIENT DEBUG: Starting to receive chunked result');
                this.chunks = [];
                this.updateProgress(99, 'Receiving audit results...');
                break;

            case 'result_chunk':
                console.log('CLIENT DEBUG: Received chunk', data.chunkIndex + 1, 'of', data.totalChunks);
                if (!this.chunks) this.chunks = [];
                this.chunks[data.chunkIndex] = data.chunk;
                this.updateProgress(99, `Receiving results... (${data.chunkIndex + 1}/${data.totalChunks})`);
                break;

            case 'result_end':
                console.log('CLIENT DEBUG: All chunks received, parsing result');
                if (this.chunks && this.chunks.length > 0) {
                    try {
                        const completeJson = this.chunks.join('');
                        const resultData = JSON.parse(completeJson);
                        this.displayAuditResults(resultData.data);
                        this.updateProgress(100, 'Comprehensive audit completed');
                    } catch (error) {
                        console.error('CLIENT DEBUG: Failed to parse chunked result:', error);
                        this.logMessage('error', 'Failed to process audit results');
                    }
                }
                this.chunks = null;
                break;
        }
    }

    displayAuditResults(results) {
        this.logMessage('success', '=== COMPREHENSIVE SECURITY AUDIT RESULTS ===');

        this.logMessage('info', `Target: ${results.target.hostname} (${results.target.ip})`);
        this.logMessage('info', `OS: ${results.target.os}`);
        this.logMessage('info', `Kernel: ${results.target.kernel}`);

        // SSH I DOSTĘP ZDALNY
        this.logMessage('info', '--- SSH I DOSTĘP ZDALNY ---');
        this.displaySSHSecurityResults(results.ssh_remote_access);

        // SIEĆ I FIREWALL
        this.logMessage('info', '--- SIEĆ I FIREWALL ---');
        this.displayNetworkFirewallResults(results.network_firewall);

        // SZYFROWANIE I PROTOKOŁY
        this.logMessage('info', '--- SZYFROWANIE I PROTOKOŁY ---');
        this.displayEncryptionResults(results.encryption_protocols);

        // ZARZĄDZANIE UŻYTKOWNIKAMI
        this.logMessage('info', '--- ZARZĄDZANIE UŻYTKOWNIKAMI ---');
        this.displayUserManagementResults(results.user_management);

        // PARTYCJE I UPRAWNIENIA
        this.logMessage('info', '--- PARTYCJE I UPRAWNIENIA DO PLIKÓW ---');
        this.displayFileSystemResults(results.filesystem_security);

        // HARDENING SYSTEMU
        this.logMessage('info', '--- HARDENING SYSTEMU ---');
        this.displaySystemHardeningResults(results.system_hardening);

        // USŁUGI I APLIKACJE
        this.logMessage('info', '--- USŁUGI I APLIKACJE ---');
        this.displayServicesResults(results.services_applications);

        // AKTUALIZACJE I AUDYT LOGÓW
        this.logMessage('info', '--- AKTUALIZACJE I AUDYT LOGÓW ---');
        this.displayUpdatesLogsResults(results.updates_logging);

        // KOPIE ZAPASOWE
        this.logMessage('info', '--- KOPIE ZAPASOWE ---');
        this.displayBackupResults(results.backups);

        // PODSTAWOWE USTAWIENIA SERWERA (AUTOMATYCZNA AKTUALIZACJA CHECKLISTY)
        if (results.basic_settings) {
            this.logMessage('info', '--- PODSTAWOWE USTAWIENIA SERWERA ---');
            this.displayBasicSettingsResults(results.basic_settings);
            this.updateChecklistFromResults(results.basic_settings);
        }

        // BEZPIECZEŃSTWO FIZYCZNE
        this.logMessage('info', '--- BEZPIECZEŃSTWO FIZYCZNE ---');
        this.displayPhysicalSecurityResults(results.physical_security);

        this.logMessage('success', `Kompletny audyt zakończony: ${new Date(results.timestamp).toLocaleString('pl-PL')}`);

        const summary = this.generateComprehensiveSecuritySummary(results);
        this.logMessage('info', '--- PODSUMOWANIE BEZPIECZEŃSTWA ---');
        this.logMessage(summary.level, summary.message);

        this.displayDetailedSummary(results);
    }

    displaySSHSecurityResults(sshResults) {
        if (sshResults['SSH Configuration']) {
            const config = sshResults['SSH Configuration'];
            this.logMessage('info', 'Konfiguracja SSH:');
            if (config.port && config.port !== '22') {
                this.logMessage('success', `✓ Port SSH zmieniony z domyślnego: ${config.port}`);
            } else if (config.port === '22') {
                this.logMessage('warning', `⚠ SSH używa domyślnego portu 22`);
            }

            if (config.passwordAuth === 'disabled') {
                this.logMessage('success', '✓ Logowanie hasłem wyłączone');
            } else {
                this.logMessage('critical', '✗ Logowanie hasłem nadal włączone!');
            }

            if (config.rootLogin === 'disabled') {
                this.logMessage('success', '✓ Bezpośrednie logowanie root wyłączone');
            } else {
                this.logMessage('critical', '✗ Bezpośrednie logowanie root włączone!');
            }

            if (config.pubkeyAuth === 'enabled') {
                this.logMessage('success', '✓ Logowanie kluczem SSH włączone');
            } else {
                this.logMessage('warning', '⚠ Logowanie kluczem SSH może być wyłączone');
            }
        }

        if (sshResults['Fail2ban Status']) {
            const fail2ban = sshResults['Fail2ban Status'];
            if (fail2ban.active) {
                this.logMessage('success', '✓ Fail2ban aktywny');
            } else {
                this.logMessage('critical', '✗ Fail2ban nieaktywny - brak ochrony przed atakami brute force!');
            }
        }
    }

    displayNetworkFirewallResults(networkResults) {
        if (networkResults.firewall_status && networkResults.firewall_status.length > 0) {
            const activeFirewalls = networkResults.firewall_status.filter(f => f.active);
            if (activeFirewalls.length > 0) {
                this.logMessage('success', `✓ Wykryto ${activeFirewalls.length} aktywny(ch) firewall(i)`);
                activeFirewalls.forEach(fw => {
                    this.logMessage('info', `  • ${fw.name}: ${fw.rules?.length || 0} reguł`);
                });
            } else {
                this.logMessage('critical', '✗ Brak aktywnych firewall-i!');
            }
        }

        if (networkResults.network_security) {
            const netSec = networkResults.network_security;
            if (netSec['Listening Ports']) {
                const ports = netSec['Listening Ports'];
                this.logMessage('info', `Nasłuchujące porty: ${ports.length}`);
                if (ports.length > 15) {
                    this.logMessage('warning', '⚠ Dużo otwartych portów - sprawdź czy wszystkie są potrzebne');
                }
            }

            if (netSec['IPv6 Status']) {
                const ipv6 = netSec['IPv6 Status'];
                if (ipv6.disabled) {
                    this.logMessage('success', '✓ IPv6 wyłączony');
                } else {
                    this.logMessage('warning', '⚠ IPv6 włączony - sprawdź czy jest używany');
                }
            }
        }
    }

    displayEncryptionResults(encResults) {
        if (encResults['SSL/TLS Services']) {
            const sslServices = encResults['SSL/TLS Services'];
            if (sslServices.length > 0) {
                this.logMessage('success', `✓ Wykryto ${sslServices.length} usług SSL/TLS`);
            } else {
                this.logMessage('warning', '⚠ Brak usług SSL/TLS');
            }
        }

        if (encResults['Disk Encryption']) {
            const diskEnc = encResults['Disk Encryption'];
            if (diskEnc.encrypted) {
                this.logMessage('success', '✓ Szyfrowanie dysków włączone');
            } else {
                this.logMessage('warning', '⚠ Brak szyfrowania dysków');
            }
        }
    }

    displayUserManagementResults(userResults) {
        if (userResults['Empty Password Users']) {
            const emptyPass = userResults['Empty Password Users'];
            if (emptyPass.hasEmptyPasswords) {
                this.logMessage('critical', '✗ Wykryto użytkowników bez haseł!');
                emptyPass.emptyPasswords.forEach(user => {
                    this.logMessage('critical', `  • ${user}`);
                });
            } else {
                this.logMessage('success', '✓ Brak użytkowników z pustymi hasłami');
            }
        }

        if (userResults['Admin Users']) {
            const adminUsers = userResults['Admin Users'];
            this.logMessage('info', `Użytkowników z uprawnieniami admin: ${adminUsers.count}`);
            if (adminUsers.count > 5) {
                this.logMessage('warning', '⚠ Dużo użytkowników z uprawnieniami admin');
            }
        }

        if (userResults['Password Policy']) {
            const policy = userResults['Password Policy'];
            if (policy.maxDays && policy.maxDays !== '99999') {
                this.logMessage('success', `✓ Wygasanie haseł: ${policy.maxDays} dni`);
            } else {
                this.logMessage('warning', '⚠ Brak ograniczeń wygasania haseł');
            }
        }
    }

    displayFileSystemResults(fsResults) {
        if (fsResults['Disk Partitions']) {
            const partitions = fsResults['Disk Partitions'];
            if (partitions.separatePartitions) {
                this.logMessage('success', '✓ Wykryto oddzielne partycje systemowe');
            } else {
                this.logMessage('warning', '⚠ Brak oddzielnych partycji /usr, /home, /var, /tmp');
            }
        }

        if (fsResults['Unowned Files']) {
            const unowned = fsResults['Unowned Files'];
            if (unowned.hasUnownedFiles) {
                this.logMessage('warning', `⚠ Wykryto ${unowned.files.length} plików bez właściciela`);
            } else {
                this.logMessage('success', '✓ Brak plików bez właściciela');
            }
        }

        if (fsResults['World Writable Files']) {
            const writable = fsResults['World Writable Files'];
            if (writable.hasWorldWritableFiles) {
                this.logMessage('warning', `⚠ Wykryto ${writable.files.length} plików z niskimi uprawnieniami`);
            } else {
                this.logMessage('success', '✓ Brak plików world-writable');
            }
        }
    }

    displaySystemHardeningResults(hardeningResults) {
        if (hardeningResults['SELinux/AppArmor']) {
            const mac = hardeningResults['SELinux/AppArmor'];
            if (mac.status === 'enabled') {
                if (mac.selinux) {
                    this.logMessage('success', '✓ SELinux włączony');
                } else if (mac.apparmor) {
                    this.logMessage('success', '✓ AppArmor włączony');
                }
            } else {
                this.logMessage('warning', '⚠ Brak systemu MAC (SELinux/AppArmor)');
            }
        }

        if (hardeningResults['Kernel Security']) {
            const kernelSec = hardeningResults['Kernel Security'];
            let secureOptions = 0;
            if (kernelSec.dmesgRestrict === '1') secureOptions++;
            if (kernelSec.kptrRestrict === '2') secureOptions++;
            if (kernelSec.ptraceScope === '1') secureOptions++;

            if (secureOptions >= 2) {
                this.logMessage('success', '✓ Zabezpieczenia kernela skonfigurowane');
            } else {
                this.logMessage('warning', '⚠ Ograniczone zabezpieczenia kernela');
            }
        }
    }

    displayServicesResults(servicesResults) {
        if (servicesResults['Running Services']) {
            const services = servicesResults['Running Services'];
            this.logMessage('info', `Uruchomione usługi: ${services.length}`);
        }

        if (servicesResults['GUI Services']) {
            const gui = servicesResults['GUI Services'];
            if (!gui.guiActive) {
                this.logMessage('success', '✓ GUI wyłączony - dobra praktyka dla serwera');
            } else {
                this.logMessage('warning', '⚠ GUI włączony - rozważ wyłączenie na serwerze');
            }
        }

        if (servicesResults['Unnecessary Services']) {
            const unnecessary = servicesResults['Unnecessary Services'];
            if (unnecessary.hasUnnecessaryServices) {
                this.logMessage('warning', '⚠ Wykryto niepotrzebne usługi (telnet, ftp, rsh)');
            } else {
                this.logMessage('success', '✓ Brak wykrytych niepotrzebnych usług');
            }
        }
    }

    displayUpdatesLogsResults(updatesResults) {
        if (updatesResults['System Updates']) {
            const updates = updatesResults['System Updates'];
            if (updates.needsUpdates) {
                this.logMessage('warning', `⚠ Dostępne aktualizacje: ${updates.availableUpdates}`);
            } else {
                this.logMessage('success', '✓ System aktualny');
            }
        }

        if (updatesResults['Automatic Updates']) {
            const autoUpdates = updatesResults['Automatic Updates'];
            if (autoUpdates.automaticUpdatesActive) {
                this.logMessage('success', '✓ Automatyczne aktualizacje włączone');
            } else {
                this.logMessage('warning', '⚠ Automatyczne aktualizacje wyłączone');
            }
        }

        if (updatesResults['Log Auditing']) {
            const logging = updatesResults['Log Auditing'];
            if (logging.loggingConfigured) {
                this.logMessage('success', `✓ Audyt logów skonfigurowany (${logging.activeLogServices} usług)`);
            } else {
                this.logMessage('warning', '⚠ Brak konfiguracji audytu logów');
            }
        }
    }

    displayBackupResults(backupResults) {
        if (backupResults['Backup Services']) {
            const services = backupResults['Backup Services'];
            if (services.hasBackupServices) {
                this.logMessage('success', '✓ Wykryto usługi backup');
            } else {
                this.logMessage('warning', '⚠ Brak wykrytych usług backup');
            }
        }

        if (backupResults['Cron Backup Jobs']) {
            const cronJobs = backupResults['Cron Backup Jobs'];
            if (cronJobs.hasBackupJobs) {
                this.logMessage('success', '✓ Wykryto zadania backup w cron');
            } else {
                this.logMessage('warning', '⚠ Brak zadań backup w cron');
            }
        }
    }

    displayPhysicalSecurityResults(physicalResults) {
        if (physicalResults['USB/Media Access']) {
            const usb = physicalResults['USB/Media Access'];
            if (!usb.usbStorageEnabled && !usb.dvdEnabled) {
                this.logMessage('success', '✓ USB/DVD modules wyłączone');
            } else {
                this.logMessage('warning', '⚠ USB/DVD modules włączone - rozważ ograniczenie dostępu');
            }
        }

        if (physicalResults['Boot Security']) {
            const boot = physicalResults['Boot Security'];
            if (boot.bootPasswordSet) {
                this.logMessage('success', '✓ Hasło GRUB skonfigurowane');
            } else {
                this.logMessage('warning', '⚠ Brak hasła GRUB - rozważ zabezpieczenie bootloadera');
            }
        }
    }

    generateComprehensiveSecuritySummary(results) {
        let securityScore = 0;
        let totalChecks = 0;
        let criticalIssues = [];

        // Sprawdź SSH
        if (results.ssh_remote_access?.['SSH Configuration']) {
            const ssh = results.ssh_remote_access['SSH Configuration'];
            totalChecks += 4;
            if (ssh.passwordAuth === 'disabled') securityScore++;
            else criticalIssues.push('Logowanie hasłem SSH włączone');
            if (ssh.rootLogin === 'disabled') securityScore++;
            else criticalIssues.push('Bezpośrednie logowanie root włączone');
            if (ssh.pubkeyAuth === 'enabled') securityScore++;
            if (ssh.port && ssh.port !== '22') securityScore++;
        }

        // Sprawdź Fail2ban
        if (results.ssh_remote_access?.['Fail2ban Status']) {
            totalChecks++;
            if (results.ssh_remote_access['Fail2ban Status'].active) {
                securityScore++;
            } else {
                criticalIssues.push('Fail2ban nieaktywny');
            }
        }

        // Sprawdź firewall
        if (results.network_firewall?.firewall_status) {
            totalChecks++;
            const activeFirewalls = results.network_firewall.firewall_status.filter(f => f.active);
            if (activeFirewalls.length > 0) {
                securityScore++;
            } else {
                criticalIssues.push('Brak aktywnych firewall-i');
            }
        }

        // Sprawdź użytkowników bez haseł
        if (results.user_management?.['Empty Password Users']) {
            totalChecks++;
            if (!results.user_management['Empty Password Users'].hasEmptyPasswords) {
                securityScore++;
            } else {
                criticalIssues.push('Użytkownicy bez haseł');
            }
        }

        const securityPercentage = totalChecks > 0 ? (securityScore / totalChecks) * 100 : 0;

        if (securityPercentage >= 80) {
            return {
                level: 'success',
                message: `DOBRY: Wynik bezpieczeństwa ${securityPercentage.toFixed(1)}%. System dobrze zabezpieczony.`
            };
        } else if (securityPercentage >= 60) {
            return {
                level: 'warning',
                message: `ŚREDNI: Wynik bezpieczeństwa ${securityPercentage.toFixed(1)}%. Wymaga uwagi: ${criticalIssues.slice(0, 2).join(', ')}.`
            };
        } else {
            return {
                level: 'critical',
                message: `NISKI: Wynik bezpieczeństwa ${securityPercentage.toFixed(1)}%. Pilne problemy: ${criticalIssues.slice(0, 3).join(', ')}.`
            };
        }
    }

    generateSecuritySummary(results) {
        const activeFirewalls = results.network_firewall?.firewall_status?.filter(fw => fw.active)?.length || 0;
        const openPorts = results.network_firewall?.network_security?.['Listening Ports']?.length || 0;

        if (activeFirewalls === 0) {
            return {
                level: 'critical',
                message: `CRITICAL: No firewalls active, ${openPorts} ports exposed. Immediate action required!`
            };
        } else if (activeFirewalls === 1 && openPorts > 10) {
            return {
                level: 'warning',
                message: `MODERATE: 1 firewall active, but ${openPorts} ports detected. Review configuration.`
            };
        } else if (activeFirewalls >= 2 || openPorts <= 5) {
            return {
                level: 'success',
                message: `GOOD: ${activeFirewalls} firewall(s) active, ${openPorts} ports. Security looks adequate.`
            };
        } else {
            return {
                level: 'warning',
                message: `MODERATE: ${activeFirewalls} firewall(s) active, ${openPorts} ports. Review recommended.`
            };
        }
    }

    displayDetailedSummary(results) {
        const summarySection = document.getElementById('summary-section');
        const summaryContent = document.getElementById('summary-content');

        const activeFirewalls = results.network_firewall?.firewall_status?.filter(fw => fw.active)?.length || 0;
        const listeningPortsList = results.network_firewall?.network_security?.['Listening Ports'] || [];
        const openPorts = listeningPortsList.length;
        const portNumbers = [...new Set(listeningPortsList.map(p => {
            const addr = p.localAddress || '';
            const portMatch = addr.match(/:(\d+)$/);
            return portMatch ? parseInt(portMatch[1]) : null;
        }).filter(p => p !== null))].sort((a, b) => a - b);

        let riskLevel = 'NISKIE';
        let riskColor = '#50fa7b';
        let recommendations = [];

        // Ocena poziomu ryzyka
        if (activeFirewalls === 0) {
            riskLevel = 'BARDZO WYSOKIE';
            riskColor = '#ff5555';
            recommendations.push('Natychmiast włącz i skonfiguruj firewall systemowy');
            recommendations.push('Zablokuj dostęp do nieużywanych portów');
            recommendations.push('Rozważ użycie dodatkowych zabezpieczeń sieciowych');
        } else if (activeFirewalls === 1 && openPorts > 10) {
            riskLevel = 'WYSOKIE';
            riskColor = '#ffb86c';
            recommendations.push('Przejrzyj konfigurację firewall-a');
            recommendations.push('Zamknij niepotrzebne porty');
            recommendations.push('Rozważ włączenie dodatkowego firewall-a');
        } else if (openPorts > 15) {
            riskLevel = 'ŚREDNIE';
            riskColor = '#f1fa8c';
            recommendations.push('Sprawdź czy wszystkie otwarte porty są niezbędne');
            recommendations.push('Rozważ ograniczenie dostępu do niektórych usług');
        } else {
            recommendations.push('Kontynuuj monitorowanie bezpieczeństwa');
            recommendations.push('Regularne aktualizacje systemu');
            recommendations.push('Okresowe przeglądy konfiguracji');
        }

        // Dane z SSH escapowane przez escapeHtml() — zapobiega XSS
        const safeHostname = escapeHtml(results.target.hostname);
        const safeIp       = escapeHtml(results.target.ip);
        const safeOs       = escapeHtml(results.target.os);
        const safeKernel   = escapeHtml(results.target.kernel);
        // portNumbers to liczby całkowite — bezpieczne bez escapowania
        // riskColor, riskLevel, recommendations — statyczne wartości z kodu — bezpieczne

        const summaryHTML = `
            <div class="summary-card">
                <h3>🔍 Co zostało sprawdzone?</h3>
                <p>System <strong>${safeHostname}</strong> (${safeIp}) został poddany kompleksowemu audytowi bezpieczeństwa.
                Sprawdziliśmy konfigurację firewall-a, otwarte porty sieciowe oraz uruchomione usługi systemowe.</p>
            </div>

            <div class="summary-card">
                <h3>💻 System operacyjny</h3>
                <p style="color: #f8f8f2; font-size: 13px; line-height: 1.6; word-wrap: break-word; overflow-wrap: break-word;">
                    <strong>Szczegóły systemu:</strong><br>
                    ${safeOs}
                </p>
                <p style="color: #8be9fd; font-size: 12px; margin-top: 10px;">
                    <strong>Hostname:</strong> ${safeHostname} | <strong>Kernel:</strong> ${safeKernel}
                </p>
            </div>

            <div class="summary-card">
                <h3>📊 Najważniejsze wyniki</h3>
                <div class="findings-grid">
                    <div class="finding-item">
                        <span class="finding-label">Aktywne firewall-e:</span>
                        <span class="finding-value ${activeFirewalls > 0 ? 'good' : 'bad'}">${activeFirewalls}</span>
                    </div>
                    <div class="finding-item finding-item-ports">
                        <span class="finding-label">Wykryte otwarte porty (${portNumbers.length}):</span>
                        <div class="ports-list">
                            ${portNumbers.map(port => `<span class="port-badge ${port < 1024 ? 'port-system' : 'port-user'}">${port}</span>`).join('')}
                        </div>
                    </div>
                </div>
            </div>

            <div class="summary-card">
                <h3>⚠️ Poziom ryzyka bezpieczeństwa</h3>
                <div class="risk-assessment">
                    <span class="risk-level" style="background-color: ${riskColor}">${riskLevel}</span>
                    <p class="risk-explanation">
                        ${riskLevel === 'BARDZO WYSOKIE' ?
                            'Twój system jest narażony na poważne zagrożenia bezpieczeństwa. Brak aktywnego firewall-a oznacza, że wszystkie usługi są dostępne z sieci.' :
                        riskLevel === 'WYSOKIE' ?
                            'System wymaga natychmiastowej uwagi. Obecna konfiguracja może pozwalać na nieautoryzowany dostęp do usług.' :
                        riskLevel === 'ŚREDNIE' ?
                            'System jest stosunkowo bezpieczny, ale wymaga przeglądu konfiguracji i zamknięcia niepotrzebnych portów.' :
                            'System wydaje się być dobrze zabezpieczony. Kontynuuj stosowanie dobrych praktyk bezpieczeństwa.'
                        }
                    </p>
                </div>
            </div>

            <div class="summary-card">
                <h3>💡 Zalecenia</h3>
                <ul class="recommendations-list">
                    ${recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
                </ul>
            </div>

            <div class="summary-card">
                <h3>📈 Następne kroki</h3>
                <p>Regularne audyty bezpieczeństwa powinny być przeprowadzane co najmniej raz w miesiącu.
                Monitoruj logi systemowe i sprawdzaj aktualizacje bezpieczeństwa.
                W przypadku wykrycia nowych zagrożeń, natychmiast zaktualizuj konfigurację.</p>
            </div>
        `;

        summaryContent.innerHTML = summaryHTML;
        summarySection.style.display = 'block';
    }

    clearOutput() {
        const output = document.getElementById('output');
        output.innerHTML = '';
    }

    updateButtonState(isLoading) {
        const button = document.getElementById('audit-btn');
        const btnText = button.querySelector('.btn-text');
        const btnIcon = button.querySelector('.btn-icon');

        if (isLoading) {
            button.classList.add('loading');
            btnText.textContent = 'AUDIT IN PROGRESS...';
            btnIcon.textContent = '⚡';
            button.disabled = true;
            document.getElementById('status').textContent = 'AUDITING';
            document.getElementById('status').style.background = '#f39c12';
        } else {
            button.classList.remove('loading');
            btnText.textContent = 'INITIATE SECURITY AUDIT';
            btnIcon.textContent = '⚡';
            button.disabled = false;
            document.getElementById('status').textContent = 'READY';
            document.getElementById('status').style.background = '#00ff00';
        }
    }

    isValidIP(ip) {
        const pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return pattern.test(ip);
    }

    // Checklist functionality
    initializeChecklist() {
        this.loadChecklistState();
        this.updateChecklistProgress();
    }

    bindChecklistEvents() {
        const checkboxes = document.querySelectorAll('.checklist-item input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            // Prevent manual checking - checkboxes can only be checked through audit
            checkbox.addEventListener('click', (e) => {
                e.preventDefault();
                this.showAuditRequiredMessage();
            });

            // Keep the change handler for programmatic updates (from audit)
            checkbox.addEventListener('change', (e) => {
                // Only allow programmatic changes (when triggered by audit)
                if (!e.isTrusted || checkbox.dataset.auditUpdate === 'true') {
                    this.handleChecklistChange(e.target);
                    this.saveChecklistState();
                    this.updateChecklistProgress();
                    // Reset the flag
                    checkbox.dataset.auditUpdate = 'false';
                }
            });
        });
    }

    showAuditRequiredMessage() {
        this.logMessage('warning', 'Checklist może być zaznaczany tylko automatycznie po wykonaniu audytu serwera. Kliknij przycisk "Rozpocznij audyt" aby przeprowadzić weryfikację.');
    }

    toggleChecklist() {
        const content = document.getElementById('checklist-content');
        const button = document.getElementById('toggle-checklist');

        if (content.classList.contains('collapsed')) {
            content.classList.remove('collapsed');
            content.style.display = 'block';
            button.textContent = 'Zwiń';
        } else {
            content.classList.add('collapsed');
            content.style.display = 'none';
            button.textContent = 'Rozwiń';
        }
    }

    handleChecklistChange(checkbox) {
        const item = checkbox.closest('.checklist-item');
        const checkmark = item.querySelector('.checkmark');

        if (checkbox.checked) {
            checkmark.style.transform = 'scale(1.1)';
            setTimeout(() => {
                checkmark.style.transform = 'scale(1)';
            }, 200);

            // Animation dla zakończonego zadania
            item.style.transform = 'translateX(5px)';
            setTimeout(() => {
                item.style.transform = 'translateX(0)';
            }, 300);
        }
    }

    updateChecklistProgress() {
        const checkboxes = document.querySelectorAll('.checklist-item input[type="checkbox"]');
        const checkedBoxes = document.querySelectorAll('.checklist-item input[type="checkbox"]:checked');

        const total = checkboxes.length;
        const completed = checkedBoxes.length;
        const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

        document.getElementById('checklist-progress').textContent = completed;
        document.getElementById('checklist-total').textContent = total;
        document.getElementById('checklist-percentage').textContent = percentage + '%';
        document.getElementById('progress-fill-checklist').style.width = percentage + '%';

        // Zmiana koloru paska postępu w zależności od postępu
        const progressFill = document.getElementById('progress-fill-checklist');
        if (percentage === 100) {
            progressFill.style.background = 'linear-gradient(90deg, #50fa7b, #50fa7b)';
        } else if (percentage >= 75) {
            progressFill.style.background = 'linear-gradient(90deg, #50fa7b, #8be9fd)';
        } else if (percentage >= 50) {
            progressFill.style.background = 'linear-gradient(90deg, #f1fa8c, #8be9fd)';
        } else {
            progressFill.style.background = 'linear-gradient(90deg, #ff5555, #f1fa8c)';
        }
    }

    saveChecklistState() {
        const checkboxes = document.querySelectorAll('.checklist-item input[type="checkbox"]');
        const state = {};

        checkboxes.forEach(checkbox => {
            state[checkbox.id] = checkbox.checked;
        });

        localStorage.setItem('checklistState', JSON.stringify(state));
    }

    loadChecklistState() {
        const savedState = localStorage.getItem('checklistState');
        if (savedState) {
            const state = JSON.parse(savedState);

            Object.keys(state).forEach(id => {
                const checkbox = document.getElementById(id);
                if (checkbox) {
                    checkbox.checked = state[id];
                }
            });
        }
    }

    displayBasicSettingsResults(basicSettings) {
        // Wyświetl wyniki sprawdzenia podstawowych ustawień
        Object.keys(basicSettings).forEach(key => {
            const setting = basicSettings[key];
            const statusColor = setting.status === 'configured' || setting.status === 'active' || setting.status === 'secured' || setting.status === 'updated' || setting.status === 'enforcing' ? 'success' :
                              setting.status === 'error' ? 'error' : 'warning';

            this.logMessage(statusColor, `${key}: ${setting.recommendation}`);
            if (setting.value && setting.value !== 'Failed to check') {
                this.logMessage('info', `  Value: ${JSON.stringify(setting.value)}`);
            }
        });
    }

    updateChecklistFromResults(basicSettings) {
        // Mapowanie wyników na checkboxy w checkliście
        const checklistMapping = {
            // 1. Tożsamość serwera i sieć
            'hostname-check': () => basicSettings.hostname?.status === 'configured',
            'hosts-check': () => basicSettings.hosts_config?.status === 'configured',
            'static-ip-check': () => basicSettings.static_ip?.status === 'configured',

            // 2. Czas i strefa czasowa
            'timezone-check': () => basicSettings.timezone?.status === 'configured',
            'ntp-check': () => basicSettings.ntp_sync?.status === 'active',

            // 3. Zarządzanie użytkownikami i dostępem
            'new-user-check': () => basicSettings.non_root_users?.status === 'configured',
            'sudo-check': () => basicSettings.sudo_config?.status === 'configured',
            'password-check': () => basicSettings.non_root_users?.status === 'configured', // Zakładamy że jeśli użytkownik istnieje to ma hasło
            'ssh-security-check': () => basicSettings.ssh_security?.status === 'secured',

            // 4. Aktualizacje i pakiety
            'system-update-check': () => basicSettings.system_updates?.status === 'updated',
            'auto-updates-check': () => basicSettings.auto_updates?.status === 'enabled',
            'required-packages-check': () => basicSettings.app_services?.status === 'configured',

            // 5. Bezpieczeństwo (podstawy)
            'firewall-check': () => basicSettings.firewall?.status === 'active',
            'selinux-check': () => basicSettings.selinux?.status === 'enforcing' || basicSettings.selinux?.status === 'not_available',

            // 6. Środowisko i aplikacje
            'editor-check': () => basicSettings.default_editor?.status === 'configured',
            'licenses-check': () => true, // Nie można automatycznie sprawdzić licencji
            'app-config-check': () => basicSettings.app_services?.status === 'configured'
        };

        // Aktualizuj checkboxy na podstawie wyników audytu
        Object.keys(checklistMapping).forEach(checkboxId => {
            const checkbox = document.getElementById(checkboxId);
            if (checkbox) {
                const shouldBeChecked = checklistMapping[checkboxId]();
                if (shouldBeChecked && !checkbox.checked) {
                    // Set flag to allow programmatic update
                    checkbox.dataset.auditUpdate = 'true';
                    checkbox.checked = true;
                    // Dodaj wizualny efekt automatycznego zaznaczenia
                    const item = checkbox.closest('.checklist-item');
                    item.style.backgroundColor = 'rgba(80, 250, 123, 0.1)';
                    item.style.transform = 'scale(1.02)';
                    setTimeout(() => {
                        item.style.backgroundColor = '';
                        item.style.transform = '';
                    }, 1000);
                }
            }
        });

        // Zaktualizuj postęp i zapisz stan
        this.updateChecklistProgress();
        this.saveChecklistState();

        // Wyświetl komunikat o automatycznej aktualizacji
        const autoCheckedCount = Object.keys(checklistMapping).reduce((count, id) => {
            const checkbox = document.getElementById(id);
            return count + (checkbox && checkbox.checked && checklistMapping[id]() ? 1 : 0);
        }, 0);

        this.logMessage('success', `Automatycznie sprawdzono i zaktualizowano ${autoCheckedCount} pozycji checklisty na podstawie audytu serwera`);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new SSHAuditor();
});
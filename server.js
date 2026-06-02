require('dotenv').config();
const express = require('express');
const https = require('https');
const fs = require('fs');
const { Client } = require('ssh2');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 8443;
const isDev = process.env.NODE_ENV === 'development';
const debug = (...args) => isDev && console.log('[DEBUG]', ...args);

// ── CORS ──────────────────────────────────────────────────────────────────────
const corsOptions = {
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:8086',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-API-Token'],
};

// ── Rate limiter ──────────────────────────────────────────────────────────────
const auditLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuta
    max: 5,              // max 5 audytów/minutę per IP
    message: { error: 'Too many audit requests, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

// ── SSRF guard ────────────────────────────────────────────────────────────────
function isAllowedTarget(ip) {
    return true;
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(cors(corsOptions));
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            fontSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
        },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
}));
app.use(express.static(path.join(__dirname, 'public')));

function executeSSHCommand(connectionConfig, command) {
    return new Promise((resolve, reject) => {
        debug('Executing SSH command:', command);
        const conn = new Client();
        let isResolved = false;

        // Timeout po 30 sekundach
        const timeout = setTimeout(() => {
            if (!isResolved) {
                isResolved = true;
                debug('SSH command timed out:', command);
                conn.end();
                reject(new Error(`SSH command timeout after 30 seconds: ${command}`));
            }
        }, 30000);

        conn.on('ready', () => {
            conn.exec(command, (err, stream) => {
                if (err) {
                    clearTimeout(timeout);
                    conn.end();
                    if (!isResolved) {
                        isResolved = true;
                        return reject(err);
                    }
                    return;
                }

                let output = '';
                let errorOutput = '';

                stream.on('close', (code, signal) => {
                    clearTimeout(timeout);
                    conn.end();
                    if (!isResolved) {
                        isResolved = true;
                        resolve({
                            stdout: output,
                            stderr: errorOutput,
                            exitCode: code
                        });
                    }
                }).on('data', (data) => {
                    output += data.toString();
                }).stderr.on('data', (data) => {
                    errorOutput += data.toString();
                });
            });
        }).on('error', (err) => {
            clearTimeout(timeout);
            if (!isResolved) {
                isResolved = true;
                reject(err);
            }
        });

        conn.connect(connectionConfig);
    });
}

async function checkSSHSecurity(connectionConfig) {
    const checks = [
        {
            name: 'SSH Configuration',
            command: 'grep -E "(Port|PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|MaxAuthTries)" /etc/ssh/sshd_config 2>/dev/null || echo "No SSH config found"',
            parser: (output) => {
                const config = {};
                const lines = output.split('\n');
                lines.forEach(line => {
                    if (line.includes('Port ') && !line.startsWith('#')) {
                        config.port = line.replace('Port ', '').trim();
                    }
                    if (line.includes('PasswordAuthentication') && !line.startsWith('#')) {
                        config.passwordAuth = line.includes('no') ? 'disabled' : 'enabled';
                    }
                    if (line.includes('PermitRootLogin') && !line.startsWith('#')) {
                        config.rootLogin = line.includes('no') ? 'disabled' : 'enabled';
                    }
                    if (line.includes('PubkeyAuthentication') && !line.startsWith('#')) {
                        config.pubkeyAuth = line.includes('yes') ? 'enabled' : 'disabled';
                    }
                    if (line.includes('MaxAuthTries') && !line.startsWith('#')) {
                        config.maxAuthTries = line.replace('MaxAuthTries', '').trim();
                    }
                });
                return config;
            }
        },
        {
            name: 'Fail2ban Status',
            command: 'systemctl is-active fail2ban 2>/dev/null && fail2ban-client status 2>/dev/null || echo "fail2ban not active"',
            parser: (output) => {
                return {
                    active: output.includes('active') || output.includes('Status'),
                    details: output
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkNetworkSecurity(connectionConfig) {
    const checks = [
        {
            name: 'Listening Ports',
            command: 'ss -tuln | grep LISTEN',
            parser: (output) => {
                const ports = output.split('\n').filter(line => line.trim()).map(line => {
                    const parts = line.split(/\s+/);
                    return {
                        protocol: parts[0],
                        localAddress: parts[4] || 'unknown',
                        state: parts[1]
                    };
                });
                return ports;
            }
        },
        {
            name: 'IPv6 Status',
            command: 'cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "1"',
            parser: (output) => {
                return {
                    disabled: output.trim() === '1',
                    status: output.trim() === '1' ? 'disabled' : 'enabled'
                };
            }
        },
        {
            name: 'Network Services',
            command: 'systemctl list-units --type=service --state=active | grep -E "(network|ssh|ftp|http|telnet)"',
            parser: (output) => {
                return output.split('\n').filter(line => line.trim()).map(line => {
                    return line.split(/\s+/)[0];
                });
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkEncryptionProtocols(connectionConfig) {
    const checks = [
        {
            name: 'SSL/TLS Services',
            command: 'ss -tuln | grep -E ":443|:993|:995|:465|:587" || echo "No SSL services found"',
            parser: (output) => {
                return output.split('\n').filter(line => line.trim() && !line.includes('No SSL'));
            }
        },
        {
            name: 'Disk Encryption',
            command: 'lsblk -f | grep -i crypt || echo "No encrypted disks found"',
            parser: (output) => {
                return {
                    encrypted: !output.includes('No encrypted disks'),
                    details: output
                };
            }
        },
        {
            name: 'Mail Encryption',
            command: 'systemctl is-active postfix dovecot 2>/dev/null || echo "Mail services not running"',
            parser: (output) => {
                return {
                    mailServicesActive: !output.includes('not running'),
                    details: output
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkUserManagement(connectionConfig) {
    const checks = [
        {
            name: 'Empty Password Users',
            command: 'awk -F: \'($2 == "" ) { print $1 }\' /etc/shadow 2>/dev/null || echo "Cannot access shadow file"',
            parser: (output) => {
                return {
                    emptyPasswords: output.split('\n').filter(line => line.trim() && !line.includes('Cannot access')),
                    hasEmptyPasswords: !output.includes('Cannot access') && output.trim() !== ''
                };
            }
        },
        {
            name: 'Admin Users',
            command: 'getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr "," "\\n" | sort | uniq | grep -v "^$" || echo "No admin groups found"',
            parser: (output) => {
                return {
                    adminUsers: output.split('\n').filter(line => line.trim() && !line.includes('No admin')),
                    count: output.split('\n').filter(line => line.trim() && !line.includes('No admin')).length
                };
            }
        },
        {
            name: 'Password Policy',
            command: 'grep -E "(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" /etc/login.defs 2>/dev/null || echo "No password policy found"',
            parser: (output) => {
                const policy = {};
                const lines = output.split('\n');
                lines.forEach(line => {
                    if (line.includes('PASS_MAX_DAYS') && !line.startsWith('#')) {
                        policy.maxDays = line.split(/\s+/)[1];
                    }
                    if (line.includes('PASS_MIN_DAYS') && !line.startsWith('#')) {
                        policy.minDays = line.split(/\s+/)[1];
                    }
                    if (line.includes('PASS_WARN_AGE') && !line.startsWith('#')) {
                        policy.warnAge = line.split(/\s+/)[1];
                    }
                });
                return policy;
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkFileSystemSecurity(connectionConfig) {
    const checks = [
        {
            name: 'Disk Partitions',
            command: 'df -h | grep -E "/(usr|home|var|tmp)\\b" || echo "Standard partitions not found"',
            parser: (output) => {
                const partitions = output.split('\n').filter(line => line.trim() && !line.includes('not found'));
                return {
                    separatePartitions: partitions.length > 0,
                    partitions: partitions
                };
            }
        },
        {
            name: 'Unowned Files',
            command: 'find / -nouser -o -nogroup 2>/dev/null | head -20 || echo "No unowned files found"',
            parser: (output) => {
                const unownedFiles = output.split('\n').filter(line => line.trim() && !line.includes('No unowned'));
                return {
                    hasUnownedFiles: unownedFiles.length > 0,
                    files: unownedFiles.slice(0, 10)
                };
            }
        },
        {
            name: 'World Writable Files',
            command: 'find / -type f -perm -002 2>/dev/null | head -20 || echo "No world-writable files found"',
            parser: (output) => {
                const writableFiles = output.split('\n').filter(line => line.trim() && !line.includes('No world-writable'));
                return {
                    hasWorldWritableFiles: writableFiles.length > 0,
                    files: writableFiles.slice(0, 10)
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkSystemHardening(connectionConfig) {
    const checks = [
        {
            name: 'SELinux/AppArmor',
            command: 'getenforce 2>/dev/null || apparmor_status 2>/dev/null | head -5 || echo "No MAC system found"',
            parser: (output) => {
                return {
                    selinux: output.includes('Enforcing') || output.includes('Permissive'),
                    apparmor: output.includes('apparmor'),
                    status: output.includes('No MAC') ? 'disabled' : 'enabled',
                    details: output
                };
            }
        },
        {
            name: 'Kernel Security',
            command: 'sysctl kernel.dmesg_restrict kernel.kptr_restrict kernel.yama.ptrace_scope 2>/dev/null || echo "Kernel security options not found"',
            parser: (output) => {
                const security = {};
                const lines = output.split('\n');
                lines.forEach(line => {
                    if (line.includes('dmesg_restrict')) {
                        security.dmesgRestrict = line.split('=')[1]?.trim();
                    }
                    if (line.includes('kptr_restrict')) {
                        security.kptrRestrict = line.split('=')[1]?.trim();
                    }
                    if (line.includes('ptrace_scope')) {
                        security.ptraceScope = line.split('=')[1]?.trim();
                    }
                });
                return security;
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkServicesAndApplications(connectionConfig) {
    const checks = [
        {
            name: 'Running Services',
            command: 'systemctl list-units --type=service --state=running | grep -v systemd | head -20',
            parser: (output) => {
                return output.split('\n').filter(line => line.trim() && line.includes('.service')).map(line => {
                    return line.split(/\s+/)[0];
                });
            }
        },
        {
            name: 'GUI Services',
            command: 'systemctl is-active gdm lightdm xdm sddm display-manager 2>/dev/null | grep active || echo "No GUI services active"',
            parser: (output) => {
                return {
                    guiActive: !output.includes('No GUI'),
                    activeServices: output.split('\n').filter(line => line.includes('active'))
                };
            }
        },
        {
            name: 'Unnecessary Services',
            command: 'systemctl list-units --type=service --state=running | grep -E "(telnet|rsh|ftp|tftp|talk|finger)" || echo "No unnecessary services found"',
            parser: (output) => {
                const unnecessaryServices = output.split('\n').filter(line => line.trim() && !line.includes('No unnecessary'));
                return {
                    hasUnnecessaryServices: unnecessaryServices.length > 0,
                    services: unnecessaryServices
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkUpdatesAndLogs(connectionConfig) {
    const checks = [
        {
            name: 'System Updates',
            command: 'apt list --upgradable 2>/dev/null | wc -l || yum check-update 2>/dev/null | wc -l || echo "Cannot check updates"',
            parser: (output) => {
                const updateCount = parseInt(output.trim()) || 0;
                return {
                    availableUpdates: updateCount,
                    needsUpdates: updateCount > 1
                };
            }
        },
        {
            name: 'Automatic Updates',
            command: 'systemctl is-active unattended-upgrades apt-daily.timer dnf-automatic.timer 2>/dev/null || echo "No automatic updates configured"',
            parser: (output) => {
                return {
                    automaticUpdatesActive: output.includes('active'),
                    details: output
                };
            }
        },
        {
            name: 'Log Auditing',
            command: 'systemctl is-active auditd rsyslog systemd-journald 2>/dev/null | grep active | wc -l',
            parser: (output) => {
                const activeLogServices = parseInt(output.trim()) || 0;
                return {
                    activeLogServices: activeLogServices,
                    loggingConfigured: activeLogServices > 0
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkBackups(connectionConfig) {
    const checks = [
        {
            name: 'Backup Services',
            command: 'systemctl list-units --type=service | grep -E "(backup|rsync|bacula|amanda)" || echo "No backup services found"',
            parser: (output) => {
                const backupServices = output.split('\n').filter(line => line.trim() && !line.includes('No backup'));
                return {
                    hasBackupServices: backupServices.length > 0,
                    services: backupServices
                };
            }
        },
        {
            name: 'Cron Backup Jobs',
            command: 'crontab -l 2>/dev/null | grep -E "(backup|rsync)" || echo "No backup cron jobs found"',
            parser: (output) => {
                const backupJobs = output.split('\n').filter(line => line.trim() && !line.includes('No backup'));
                return {
                    hasBackupJobs: backupJobs.length > 0,
                    jobs: backupJobs
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

async function checkPhysicalSecurity(connectionConfig) {
    const checks = [
        {
            name: 'USB/Media Access',
            command: 'lsmod | grep -E "(usb_storage|sr_mod)" && echo "USB/DVD modules loaded" || echo "USB/DVD modules not loaded"',
            parser: (output) => {
                return {
                    usbStorageEnabled: output.includes('usb_storage'),
                    dvdEnabled: output.includes('sr_mod'),
                    details: output
                };
            }
        },
        {
            name: 'Boot Security',
            command: 'grep -i "password" /boot/grub*/grub.cfg 2>/dev/null || echo "GRUB password not found"',
            parser: (output) => {
                return {
                    bootPasswordSet: !output.includes('not found') && output.includes('password'),
                    details: output.includes('password') ? 'GRUB password configured' : 'No GRUB password found'
                };
            }
        }
    ];

    const results = {};
    for (const check of checks) {
        try {
            const result = await executeSSHCommand(connectionConfig, check.command);
            results[check.name] = check.parser(result.stdout);
        } catch (error) {
            results[check.name] = { error: error.message };
        }
    }
    return results;
}

function detectFirewallStatus(connectionConfig) {
    return new Promise(async (resolve) => {
        const firewallChecks = [
            {
                name: 'iptables',
                command: 'sudo iptables -L -n | head -20',
                parser: (output) => {
                    if (output.includes('Chain INPUT') || output.includes('Chain OUTPUT')) {
                        const rules = output.split('\n').filter(line =>
                            line.includes('ACCEPT') ||
                            line.includes('DROP') ||
                            line.includes('REJECT')
                        );
                        return {
                            active: rules.length > 3,
                            rules: rules.slice(0, 10),
                            type: 'iptables'
                        };
                    }
                    return { active: false, rules: [], type: 'iptables' };
                }
            },
            {
                name: 'ufw',
                command: 'sudo ufw status verbose',
                parser: (output) => {
                    const active = output.toLowerCase().includes('status: active');
                    const rules = output.split('\n').filter(line =>
                        line.includes('ALLOW') ||
                        line.includes('DENY') ||
                        line.includes('REJECT')
                    );
                    return {
                        active: active,
                        rules: rules.slice(0, 10),
                        type: 'ufw'
                    };
                }
            },
            {
                name: 'firewalld',
                command: 'sudo firewall-cmd --state && sudo firewall-cmd --list-all',
                parser: (output) => {
                    const active = output.toLowerCase().includes('running');
                    const rules = output.split('\n').filter(line =>
                        line.includes('services:') ||
                        line.includes('ports:') ||
                        line.includes('protocols:')
                    );
                    return {
                        active: active,
                        rules: rules.slice(0, 10),
                        type: 'firewalld'
                    };
                }
            }
        ];

        const results = [];

        for (const check of firewallChecks) {
            try {
                const result = await executeSSHCommand(connectionConfig, check.command);
                const parsed = check.parser(result.stdout);

                if (parsed.active || parsed.rules.length > 0) {
                    results.push({
                        name: check.name,
                        ...parsed,
                        rawOutput: result.stdout
                    });
                }
            } catch (error) {
                results.push({
                    name: check.name,
                    active: false,
                    error: error.message,
                    type: check.name
                });
            }
        }

        resolve(results);
    });
}

async function checkBasicSettings(connectionConfig) {
    const results = {};

    try {
        // 1. Tożsamość serwera i sieć
        try {
            const hostnameResult = await executeSSHCommand(connectionConfig, 'hostname && cat /etc/hostname 2>/dev/null');
            const hostname = hostnameResult.stdout.trim().split('\n')[0];
            results.hostname = {
                status: hostname && hostname !== 'localhost' ? 'configured' : 'default',
                value: hostname,
                recommendation: hostname === 'localhost' ? 'Change hostname in /etc/hostname' : 'Hostname is properly configured'
            };
        } catch (error) {
            results.hostname = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify hostname' };
        }

        try {
            const hostsResult = await executeSSHCommand(connectionConfig, 'cat /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^$"');
            const hostsEntries = hostsResult.stdout.trim().split('\n').filter(line => line.trim());
            results.hosts_config = {
                status: hostsEntries.length > 2 ? 'configured' : 'basic',
                value: hostsEntries.length,
                recommendation: hostsEntries.length > 2 ? 'Hosts file has custom entries' : 'Consider adding custom DNS entries to /etc/hosts'
            };
        } catch (error) {
            results.hosts_config = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify /etc/hosts' };
        }

        try {
            const netResult = await executeSSHCommand(connectionConfig, 'ip addr show | grep "inet " | grep -v "127.0.0.1" | head -1');
            const networkInfo = netResult.stdout.trim();
            const staticCheckCmd = [
                '(grep -ql "addresses:" /etc/netplan/*.yaml 2>/dev/null && echo "netplan")',
                '(grep -q "iface.*static" /etc/network/interfaces 2>/dev/null && echo "interfaces")',
                '(grep -rl "BOOTPROTO=none\\|BOOTPROTO=static" /etc/sysconfig/network-scripts/ 2>/dev/null | grep -q "ifcfg-" && echo "sysconfig")',
                '(sudo grep -rql "method=manual" /etc/NetworkManager/system-connections/ 2>/dev/null && echo "networkmanager")',
                '(grep -rql "method=manual" /etc/NetworkManager/system-connections/ 2>/dev/null && echo "networkmanager")',
                '(find /etc/systemd/network/ -name "*.network" -exec grep -l "Address=" {} \\; 2>/dev/null | grep -q . && echo "systemd-networkd")',
                'echo "dhcp"'
            ].join(' || ');
            const hasStaticConfig = await executeSSHCommand(connectionConfig, staticCheckCmd);
            const configMethod = hasStaticConfig.stdout.trim();
            const isStatic = configMethod !== 'dhcp';
            const methodLabels = {
                'netplan': 'Netplan',
                'interfaces': '/etc/network/interfaces',
                'sysconfig': 'sysconfig (RHEL/CentOS)',
                'networkmanager': 'NetworkManager',
                'systemd-networkd': 'systemd-networkd'
            };
            results.static_ip = {
                status: isStatic ? 'configured' : 'dhcp',
                value: networkInfo,
                method: methodLabels[configMethod] || configMethod,
                recommendation: isStatic
                    ? `Static IP configured via ${methodLabels[configMethod] || configMethod}`
                    : 'Configure static IP address, gateway and DNS servers'
            };
        } catch (error) {
            results.static_ip = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify network configuration' };
        }

        // 2. Czas i strefa czasowa
        try {
            const timezoneResult = await executeSSHCommand(connectionConfig, 'timedatectl status 2>/dev/null | grep "Time zone" || date +%Z');
            results.timezone = {
                status: timezoneResult.stdout.includes('UTC') ? 'default' : 'configured',
                value: timezoneResult.stdout.trim(),
                recommendation: timezoneResult.stdout.includes('UTC') ? 'Consider setting appropriate timezone' : 'Timezone is configured'
            };
        } catch (error) {
            results.timezone = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify timezone' };
        }

        try {
            const ntpResult = await executeSSHCommand(connectionConfig, 'systemctl status ntp 2>/dev/null || systemctl status chrony 2>/dev/null || systemctl status systemd-timesyncd 2>/dev/null || echo "no_ntp"');
            results.ntp_sync = {
                status: ntpResult.stdout.includes('active (running)') ? 'active' : 'inactive',
                value: ntpResult.stdout.includes('ntp') ? 'ntp' : ntpResult.stdout.includes('chrony') ? 'chrony' : 'systemd-timesyncd',
                recommendation: ntpResult.stdout.includes('active') ? 'Time synchronization is active' : 'Configure NTP synchronization'
            };
        } catch (error) {
            results.ntp_sync = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify time synchronization' };
        }

        // 3. Zarządzanie użytkownikami
        try {
            const usersResult = await executeSSHCommand(connectionConfig, 'getent passwd | grep -E ":/home/|:/Users/" | wc -l');
            const userCount = parseInt(usersResult.stdout.trim());
            results.non_root_users = {
                status: userCount > 0 ? 'configured' : 'missing',
                value: userCount,
                recommendation: userCount > 0 ? `Found ${userCount} user account(s)` : 'Create non-root user account'
            };
        } catch (error) {
            results.non_root_users = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify user accounts' };
        }

        try {
            const sudoResult = await executeSSHCommand(connectionConfig, 'getent group sudo wheel 2>/dev/null | grep -v "^$" | wc -l');
            const sudoGroups = parseInt(sudoResult.stdout.trim());
            results.sudo_config = {
                status: sudoGroups > 0 ? 'configured' : 'missing',
                value: sudoGroups,
                recommendation: sudoGroups > 0 ? 'Sudo groups are configured' : 'Configure sudo access for users'
            };
        } catch (error) {
            results.sudo_config = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify sudo configuration' };
        }

        try {
            const sshConfigResult = await executeSSHCommand(connectionConfig, 'grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config 2>/dev/null || echo "default_config"');
            const sshConfig = sshConfigResult.stdout;
            const rootLoginDisabled = sshConfig.includes('PermitRootLogin no') || sshConfig.includes('PermitRootLogin prohibit-password');
            const pubkeyEnabled = sshConfig.includes('PubkeyAuthentication yes') || !sshConfig.includes('PubkeyAuthentication no');

            results.ssh_security = {
                status: rootLoginDisabled && pubkeyEnabled ? 'secured' : 'needs_hardening',
                value: { rootLoginDisabled, pubkeyEnabled },
                recommendation: rootLoginDisabled && pubkeyEnabled ? 'SSH security is properly configured' : 'Harden SSH configuration - disable root login and enable key auth'
            };
        } catch (error) {
            results.ssh_security = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify SSH configuration' };
        }

        // 4. Aktualizacje
        try {
            const updatesResult = await executeSSHCommand(connectionConfig, 'apt list --upgradable 2>/dev/null | wc -l || yum check-update 2>/dev/null | wc -l || echo "0"');
            const updatesCount = parseInt(updatesResult.stdout.trim());
            results.system_updates = {
                status: updatesCount <= 1 ? 'updated' : 'updates_available',
                value: Math.max(0, updatesCount - 1),
                recommendation: updatesCount <= 1 ? 'System is up to date' : `${updatesCount - 1} updates available - run system update`
            };
        } catch (error) {
            results.system_updates = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify system updates' };
        }

        try {
            const autoUpdateResult = await executeSSHCommand(connectionConfig, 'ls /etc/apt/apt.conf.d/*unattended* 2>/dev/null || systemctl status dnf-automatic 2>/dev/null || echo "manual"');
            results.auto_updates = {
                status: autoUpdateResult.stdout.includes('unattended') || autoUpdateResult.stdout.includes('active') ? 'enabled' : 'manual',
                value: autoUpdateResult.stdout.includes('unattended') ? 'apt-unattended' : autoUpdateResult.stdout.includes('dnf-automatic') ? 'dnf-automatic' : 'manual',
                recommendation: autoUpdateResult.stdout.includes('manual') ? 'Consider enabling automatic security updates' : 'Automatic updates are configured'
            };
        } catch (error) {
            results.auto_updates = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify automatic updates' };
        }

        // 5. Bezpieczeństwo
        try {
            const firewallResult = await executeSSHCommand(connectionConfig, 'ufw status 2>/dev/null || systemctl status firewalld 2>/dev/null || iptables -L INPUT | grep -c "ACCEPT\\|DROP\\|REJECT"');
            const firewallActive = firewallResult.stdout.includes('Status: active') ||
                                 firewallResult.stdout.includes('active (running)') ||
                                 (parseInt(firewallResult.stdout.trim()) > 0);
            results.firewall = {
                status: firewallActive ? 'active' : 'inactive',
                value: firewallResult.stdout.includes('ufw') ? 'ufw' : firewallResult.stdout.includes('firewalld') ? 'firewalld' : 'iptables',
                recommendation: firewallActive ? 'Firewall is active' : 'Enable and configure firewall'
            };
        } catch (error) {
            results.firewall = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify firewall status' };
        }

        try {
            const selinuxResult = await executeSSHCommand(connectionConfig, 'getenforce 2>/dev/null || sestatus 2>/dev/null || echo "not_available"');
            results.selinux = {
                status: selinuxResult.stdout.includes('Enforcing') ? 'enforcing' :
                       selinuxResult.stdout.includes('Permissive') ? 'permissive' :
                       selinuxResult.stdout.includes('not_available') ? 'not_available' : 'disabled',
                value: selinuxResult.stdout.trim(),
                recommendation: selinuxResult.stdout.includes('Enforcing') ? 'SELinux is properly enforcing' :
                              selinuxResult.stdout.includes('not_available') ? 'SELinux not available on this system' :
                              'Consider enabling SELinux for enhanced security'
            };
        } catch (error) {
            results.selinux = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify SELinux status' };
        }

        // 6. Środowisko
        try {
            const editorResult = await executeSSHCommand(connectionConfig, 'echo $EDITOR || which nano vim vi 2>/dev/null | head -1');
            results.default_editor = {
                status: editorResult.stdout.trim() ? 'configured' : 'not_set',
                value: editorResult.stdout.trim() || 'not set',
                recommendation: editorResult.stdout.trim() ? 'Default editor is configured' : 'Set default editor with EDITOR environment variable'
            };
        } catch (error) {
            results.default_editor = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify default editor' };
        }

        try {
            const servicesResult = await executeSSHCommand(connectionConfig, 'systemctl list-unit-files --type=service --state=enabled | grep -E "(apache|nginx|mysql|postgresql|redis)" | wc -l');
            const servicesCount = parseInt(servicesResult.stdout.trim());
            results.app_services = {
                status: servicesCount > 0 ? 'configured' : 'none',
                value: servicesCount,
                recommendation: servicesCount > 0 ? `Found ${servicesCount} application service(s) configured` : 'No major application services detected'
            };
        } catch (error) {
            results.app_services = { status: 'error', value: 'Failed to check', recommendation: 'Unable to verify application services' };
        }

    } catch (error) {
        console.error('Error in checkBasicSettings:', error);
    }

    return results;
}

// ── API endpoint ──────────────────────────────────────────────────────────────
app.post('/api/audit', auditLimiter, async (req, res) => {
    const { ip, username, password } = req.body;

    if (!ip || !username || !password) {
        return res.status(400).json({
            error: 'Missing required parameters: ip, username, password'
        });
    }

    // Server-side IP validation (SSRF guard)
    const ipPattern = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    if (!ipPattern.test(ip) || !isAllowedTarget(ip)) {
        return res.status(400).json({ error: 'Invalid or disallowed target IP' });
    }

    const connectionConfig = {
        host: ip,
        username: username,
        password: password,
        port: 22,
        readyTimeout: 10000
    };

    try {
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Transfer-Encoding': 'chunked',
        });

        const sendUpdate = (data) => {
            debug('Sending update to client:', data.type);
            try {
                res.write(JSON.stringify(data) + '\n');
            } catch (error) {
                console.error('ERROR: Failed to send update to client:', error);
            }
        };

        sendUpdate({
            type: 'status',
            message: 'Establishing SSH connection...',
            timestamp: new Date().toISOString()
        });

        const basicInfo = await executeSSHCommand(connectionConfig, 'whoami && hostname && uname -a');

        sendUpdate({
            type: 'success',
            message: `Connected to ${basicInfo.stdout.split('\n')[1]} as ${basicInfo.stdout.split('\n')[0]}`,
            timestamp: new Date().toISOString()
        });

        sendUpdate({
            type: 'status',
            message: 'Checking SSH and remote access security...',
            timestamp: new Date().toISOString()
        });

        const sshSecurityResults = await checkSSHSecurity(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Analyzing network and firewall configuration...',
            timestamp: new Date().toISOString()
        });

        const networkSecurityResults = await checkNetworkSecurity(connectionConfig);
        const firewallResults = await detectFirewallStatus(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Checking encryption and protocols...',
            timestamp: new Date().toISOString()
        });

        const encryptionResults = await checkEncryptionProtocols(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Auditing user management...',
            timestamp: new Date().toISOString()
        });

        const userManagementResults = await checkUserManagement(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Checking file system security...',
            timestamp: new Date().toISOString()
        });

        const fileSystemResults = await checkFileSystemSecurity(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Analyzing system hardening...',
            timestamp: new Date().toISOString()
        });

        const systemHardeningResults = await checkSystemHardening(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Checking services and applications...',
            timestamp: new Date().toISOString()
        });

        const servicesResults = await checkServicesAndApplications(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Auditing updates and logging...',
            timestamp: new Date().toISOString()
        });

        const updatesLogsResults = await checkUpdatesAndLogs(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Checking backup configuration...',
            timestamp: new Date().toISOString()
        });

        const backupResults = await checkBackups(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Checking basic server settings...',
            timestamp: new Date().toISOString()
        });

        const basicSettingsResults = await checkBasicSettings(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Analyzing physical security...',
            timestamp: new Date().toISOString()
        });

        const physicalSecurityResults = await checkPhysicalSecurity(connectionConfig);

        sendUpdate({
            type: 'status',
            message: 'Gathering system information...',
            timestamp: new Date().toISOString()
        });

        let systemInfo;
        try {
            debug('Starting system info collection...');
            systemInfo = await executeSSHCommand(connectionConfig,
                'cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo "Unknown OS"');
            debug('System info collected successfully');
        } catch (error) {
            console.warn('Warning: Failed to gather system information:', error.message);
            systemInfo = { stdout: 'Unknown OS (connection timeout)', stderr: '', exitCode: 1 };
        }

        debug('Creating audit result...');
        const auditResult = {
            target: {
                ip: ip,
                hostname: basicInfo.stdout.split('\n')[1]?.trim() || 'Unknown',
                user: basicInfo.stdout.split('\n')[0]?.trim() || username,
                os: systemInfo.stdout.trim(),
                kernel: basicInfo.stdout.split('\n')[2]?.trim() || 'Unknown'
            },
            ssh_remote_access: sshSecurityResults,
            network_firewall: {
                firewall_status: firewallResults,
                network_security: networkSecurityResults
            },
            encryption_protocols: encryptionResults,
            user_management: userManagementResults,
            filesystem_security: fileSystemResults,
            system_hardening: systemHardeningResults,
            services_applications: servicesResults,
            updates_logging: updatesLogsResults,
            backups: backupResults,
            basic_settings: basicSettingsResults,
            physical_security: physicalSecurityResults,
            timestamp: new Date().toISOString(),
            audit_status: 'completed'
        };

        debug('Sending final result to client...');

        const resultMessage = {
            type: 'result',
            data: auditResult,
            timestamp: new Date().toISOString()
        };

        const jsonString = JSON.stringify(resultMessage);
        debug('Result JSON size:', jsonString.length, 'characters');

        if (jsonString.length > 8192) {
            debug('Splitting large JSON into chunks');

            sendUpdate({
                type: 'result_start',
                timestamp: new Date().toISOString()
            });

            const chunkSize = 4096;
            const chunks = [];
            for (let i = 0; i < jsonString.length; i += chunkSize) {
                chunks.push(jsonString.substring(i, i + chunkSize));
            }

            for (let i = 0; i < chunks.length; i++) {
                sendUpdate({
                    type: 'result_chunk',
                    chunk: chunks[i],
                    chunkIndex: i,
                    totalChunks: chunks.length,
                    timestamp: new Date().toISOString()
                });
            }

            sendUpdate({
                type: 'result_end',
                timestamp: new Date().toISOString()
            });
        } else {
            sendUpdate(resultMessage);
        }

        debug('Ending response...');
        res.end();

    } catch (error) {
        console.error('SSH Audit Error:', error);

        if (!res.headersSent) {
            res.status(500).json({
                error: 'SSH connection failed',
                details: isDev ? error.message : 'Check server logs for details'
            });
        } else {
            res.write(JSON.stringify({
                type: 'error',
                message: isDev ? `Connection failed: ${error.message}` : 'Connection failed',
                timestamp: new Date().toISOString()
            }) + '\n');
            res.end();
        }
    }
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// ── HTTPS server ──────────────────────────────────────────────────────────────
const certDir = path.join(__dirname, 'certs');
const tlsOptions = {
    key:  fs.readFileSync(path.join(certDir, 'key.pem')),
    cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
};

https.createServer(tlsOptions, app).listen(PORT, '0.0.0.0', () => {
    console.log(`🔥 SSH Security Auditor running on https://localhost:${PORT}`);
    console.log(`🔒 HTTPS aktywne (self-signed cert — zaakceptuj wyjątek w przeglądarce)`);
    console.log(`⚡ Ready to audit remote systems`);
});

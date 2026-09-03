const isLocalDevelopment = ['localhost', '127.0.0.1'].includes(window.location.hostname);
const API_BASE_URL = window.WAZUH_API_BASE_URL || (isLocalDevelopment ? '' : 'https://wazuh-attack-correlator.onrender.com');

function apiUrl(path) {
  return `${API_BASE_URL}${path}`;
}

const SAMPLE_WAZUH_LOGS = `[
  {
    "timestamp": "2026-08-24T08:15:10.123+0000",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: Attempt to login using a non-existent user",
      "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": {
      "id": "000",
      "name": "wazuh-manager",
      "ip": "192.168.1.10"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "data": {
      "srcip": "198.51.100.50",
      "srcuser": "root"
    },
    "location": "/var/log/auth.log",
    "full_log": "Aug 24 08:15:10 wazuh-manager sshd[4120]: Failed password for root from 198.51.100.50 port 43212 ssh2"
  },
  {
    "timestamp": "2026-08-24T08:15:25.456+0000",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: Attempt to login using a non-existent user",
      "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": {
      "id": "000",
      "name": "wazuh-manager",
      "ip": "192.168.1.10"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "data": {
      "srcip": "198.51.100.50",
      "srcuser": "admin"
    },
    "location": "/var/log/auth.log",
    "full_log": "Aug 24 08:15:25 wazuh-manager sshd[4125]: Failed password for invalid user admin from 198.51.100.50 port 43218 ssh2"
  },
  {
    "timestamp": "2026-08-24T08:20:00.100+0000",
    "rule": {
      "id": "31101",
      "level": 7,
      "description": "SQL injection attempt detected in HTTP request",
      "groups": ["web", "accesslog", "sql_injection", "attack"]
    },
    "agent": {
      "id": "001",
      "name": "web-server-01",
      "ip": "192.168.1.101"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "data": {
      "srcip": "203.0.113.88",
      "url": "/search?q=admin' OR '1'='1",
      "http_user_agent": "sqlmap/1.7#stable",
      "status": "200"
    },
    "location": "(web-server-01) 192.168.1.101->/var/log/nginx/access.log",
    "full_log": "203.0.113.88 - - [24/Aug/2026:08:20:00 +0000] \\"GET /search?q=admin' OR '1'='1 HTTP/1.1\\" 200 4520 \\"-\\" \\"sqlmap/1.7#stable\\""
  },
  {
    "timestamp": "2026-08-24T08:20:15.200+0000",
    "rule": {
      "id": "30101",
      "level": 6,
      "description": "Web server 403 Forbidden - Access to sensitive endpoint blocked",
      "groups": ["web", "accesslog", "forbidden"]
    },
    "agent": {
      "id": "001",
      "name": "web-server-01",
      "ip": "192.168.1.101"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "data": {
      "srcip": "203.0.113.88",
      "url": "/admin/config.php",
      "status": "403"
    },
    "location": "(web-server-01) 192.168.1.101->/var/log/nginx/access.log",
    "full_log": "203.0.113.88 - - [24/Aug/2026:08:20:15 +0000] \\"GET /admin/config.php HTTP/1.1\\" 403 210 \\"-\\" \\"Mozilla/5.0\\""
  },
  {
    "timestamp": "2026-08-24T08:25:00.000+0000",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: Failed login attempt",
      "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": {
      "id": "002",
      "name": "db-server-02",
      "ip": "192.168.1.102"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "data": {
      "srcip": "192.0.2.77",
      "srcuser": "postgres"
    },
    "location": "(db-server-02) 192.168.1.102->/var/log/auth.log",
    "full_log": "Aug 24 08:25:00 db-server-02 sshd[5230]: Failed password for postgres from 192.0.2.77 port 51234 ssh2"
  },
  {
    "timestamp": "2026-08-24T08:25:30.000+0000",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: Failed login attempt",
      "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": {
      "id": "002",
      "name": "db-server-02",
      "ip": "192.168.1.102"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "data": {
      "srcip": "192.0.2.77",
      "srcuser": "dbadmin"
    },
    "location": "(db-server-02) 192.168.1.102->/var/log/auth.log",
    "full_log": "Aug 24 08:25:30 db-server-02 sshd[5238]: Failed password for dbadmin from 192.0.2.77 port 51240 ssh2"
  }
]`;

const SAMPLE_MANAGER_ATTACK = `[
  {
    "timestamp": "2026-08-24T09:00:00Z",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: Attempt to login using a non-existent user",
      "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": { "id": "000", "name": "wazuh-manager", "ip": "192.168.1.10" },
    "manager": { "name": "wazuh-manager" },
    "data": { "srcip": "198.51.100.50", "srcuser": "root" },
    "location": "/var/log/auth.log",
    "full_log": "Failed password for root from 198.51.100.50"
  },
  {
    "timestamp": "2026-08-24T09:00:15Z",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: Attempt to login using a non-existent user",
      "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": { "id": "000", "name": "wazuh-manager", "ip": "192.168.1.10" },
    "manager": { "name": "wazuh-manager" },
    "data": { "srcip": "198.51.100.50", "srcuser": "admin" },
    "location": "/var/log/auth.log",
    "full_log": "Failed password for invalid user admin from 198.51.100.50"
  }
]`;

const SAMPLE_AGENT_ATTACK = `[
  {
    "timestamp": "2026-08-24T09:10:00Z",
    "rule": {
      "id": "31101",
      "level": 7,
      "description": "SQL injection attempt detected in HTTP request",
      "groups": ["web", "accesslog", "sql_injection", "attack"]
    },
    "agent": { "id": "001", "name": "web-server-01", "ip": "192.168.1.101" },
    "manager": { "name": "wazuh-manager" },
    "data": { "srcip": "203.0.113.88", "url": "/search?q=admin' OR '1'='1", "http_user_agent": "sqlmap/1.7" },
    "location": "(web-server-01) 192.168.1.101->/var/log/nginx/access.log"
  },
  {
    "timestamp": "2026-08-24T09:10:20Z",
    "rule": {
      "id": "30101",
      "level": 6,
      "description": "Web server 403 Forbidden - Access to sensitive endpoint blocked",
      "groups": ["web", "accesslog", "forbidden"]
    },
    "agent": { "id": "001", "name": "web-server-01", "ip": "192.168.1.101" },
    "manager": { "name": "wazuh-manager" },
    "data": { "srcip": "203.0.113.88", "url": "/admin/config.php", "status": "403" },
    "location": "(web-server-01) 192.168.1.101->/var/log/nginx/access.log"
  }
]`;

const suspiciousPatterns = [
  "union select", "or '1'='1", "or 1=1", "sql injection", "xp_", "sleep(", "--",
  "<script", "javascript:", "../", "..\\", "cmd=", "/etc/passwd", "wp-admin",
  "wp-login.php", "/.git", "/.env", "/config.php", "/phpmyadmin", "pma", "xmlrpc.php"
];

const scannerPatterns = [
  "sqlmap", "nmap", "masscan", "dirbuster", "nikto", "acunetix", "havij", "whatweb"
];

const sensitiveEndpoints = [
  "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma", "/xmlrpc.php",
  "/.git", "/.env", "/config.php", "/.htaccess", "/.well-known"
];

const WAZUH_AUTH_RULE_IDS = new Set(["5503", "5504", "5710", "5711", "5712", "5716", "5720", "2501", "2502"]);
const WAZUH_WEB_ATTACK_RULE_IDS = new Set(["30101", "30102", "30103", "30104", "30112", "30115", "31101", "31102", "31103", "31104", "31105", "31106", "31164", "31165"]);

function parseCsvRow(line) {
  const values = [];
  let current = '';
  let inQuotes = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"') {
      if (inQuotes && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      values.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  values.push(current);
  return values.map((value) => value.trim().replace(/\r$/, ''));
}

function parseCsvText(text) {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0);
  if (lines.length < 2) return [];

  const headers = parseCsvRow(lines[0]).map((header) => {
    const cleaned = header.trim().replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase();
    return cleaned || 'column';
  });

  const records = [];
  for (let index = 1; index < lines.length; index += 1) {
    const values = parseCsvRow(lines[index]);
    if (values.length === 0 || values.every((value) => value.trim() === '')) continue;

    const record = {};
    for (let headerIndex = 0; headerIndex < headers.length; headerIndex += 1) {
      const header = headers[headerIndex];
      const value = values[headerIndex] || '';
      record[header] = value;
    }

    if (record.remote_ip || record.local_ip) {
      record.ip = record.remote_ip || record.local_ip;
    }
    if (!record.event && record.process_name) {
      record.event = record.process_name;
    }
    if (!record.message && record.command_line) {
      record.message = record.command_line;
    }

    records.push(record);
  }
  return records;
}

function normalizeLogInput(rawInput) {
  if (rawInput === null || rawInput === undefined) return [];
  if (typeof rawInput === 'string') {
    const text = rawInput.trim();
    if (!text) return [];

    if (text.includes(',') && !text.trim().startsWith('{') && !text.trim().startsWith('[')) {
      const firstLine = text.split(/\r?\n/).find((line) => line.trim().length > 0) || '';
      if (firstLine.includes(',') && (firstLine.toLowerCase().includes('time') || firstLine.toLowerCase().includes('ip') || firstLine.toLowerCase().includes('event'))) {
        return parseCsvText(text);
      }
    }

    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) return parsed.filter((item) => item && typeof item === 'object');
      if (parsed && typeof parsed === 'object') return [parsed];
    } catch (error) {
      // fall through to line-based parsing
    }

    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const items = [];

    for (const line of lines) {
      try {
        const parsedLine = JSON.parse(line);
        if (parsedLine && typeof parsedLine === 'object') {
          items.push(parsedLine);
          continue;
        }
      } catch (error) {
        // ignore and parse key=value
      }

      const entry = {};
      const assignments = line.split(/\s+(?=[A-Za-z0-9_\-]+=)/g);
      for (const assignment of assignments) {
        if (!assignment.includes('=')) continue;
        const [rawKey, ...rawRest] = assignment.split('=');
        const key = rawKey.trim();
        const value = rawRest.join('=').trim().replace(/^['"]|['"]$/g, '');
        if (key) entry[key] = value;
      }
      if (Object.keys(entry).length) items.push(entry);
    }
    return items;
  }

  if (Array.isArray(rawInput)) return rawInput.filter((item) => item && typeof item === 'object');
  if (rawInput && typeof rawInput === 'object') return [rawInput];
  return [];
}

function extractTargetInfo(entry) {
  const agent = entry.agent;
  const manager = entry.manager;

  let agentId = '';
  let agentName = '';
  let agentIp = '';
  let managerName = '';

  if (agent && typeof agent === 'object') {
    agentId = String(agent.id !== undefined && agent.id !== null ? agent.id : '').trim();
    agentName = String(agent.name || '').trim();
    agentIp = String(agent.ip || '').trim();
  } else if (typeof agent === 'string') {
    agentName = agent.trim();
  }

  if (manager && typeof manager === 'object') {
    managerName = String(manager.name || '').trim();
  } else if (typeof manager === 'string') {
    managerName = manager.trim();
  }

  if (!agentId) agentId = String(entry.agent_id || entry.agentId || '').trim();
  if (!agentName) agentName = String(entry.agent_name || entry.agentName || '').trim();
  if (!agentIp) agentIp = String(entry.agent_ip || entry.agentIp || '').trim();
  if (!managerName) managerName = String(entry.manager_name || entry.managerName || '').trim();

  const location = String(entry.location || '');
  if (!agentName && location.includes('(') && location.includes(')')) {
    const match = location.match(/\(([^)]+)\)/);
    if (match) agentName = match[1].trim();
  }

  const explicitTarget = String(entry.target_type || entry.target_role || entry.node_type || entry.host_type || entry.role || '').toLowerCase().trim();
  const isManagerFlag = entry.is_manager;

  let role = 'unknown';
  if (isManagerFlag === true || String(isManagerFlag).toLowerCase() === 'true') {
    role = 'manager';
  } else if (isManagerFlag === false || String(isManagerFlag).toLowerCase() === 'false') {
    role = 'agent';
  } else if (['manager', 'wazuh-manager', 'wazuh_manager', 'master'].includes(explicitTarget)) {
    role = 'manager';
  } else if (['agent', 'wazuh-agent', 'wazuh_agent', 'endpoint', 'node'].includes(explicitTarget)) {
    role = 'agent';
  } else if (agentId === '000' || agentId === '0') {
    role = 'manager';
  } else if (['wazuh-manager', 'manager', 'master'].includes(agentName.toLowerCase())) {
    role = 'manager';
  } else if (agentId && agentId !== '000' && agentId !== '0') {
    role = 'agent';
  } else if (agentName) {
    role = 'agent';
  } else if (location.startsWith('wazuh-manager')) {
    role = 'manager';
  } else if (managerName && !agentName && !agentId) {
    role = 'manager';
  }

  const targetId = agentId ? agentId : (role === 'manager' ? '000' : '');
  const targetName = agentName ? agentName : (managerName ? managerName : (role === 'manager' ? 'wazuh-manager' : ''));

  return { role, id: targetId, name: targetName, ip: agentIp };
}

function extractIpFromEntry(entry) {
  if (entry.data && typeof entry.data === 'object') {
    const candidate = entry.data.srcip || entry.data.src_ip || entry.data.source_ip || entry.data.client_ip || entry.data.remote_ip;
    if (candidate) return String(candidate).trim();
  }
  const candidate = entry.ip || entry.src_ip || entry.source_ip || entry.srcip || entry.remote_ip || entry.client_ip;
  if (candidate) return String(candidate).trim();

  const text = `${entry.full_log || ''} ${entry.message || ''}`;
  const match = text.match(/\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i);
  if (match) return match[1];

  return 'unknown';
}

function extractUserFromEntry(entry) {
  if (entry.data && typeof entry.data === 'object') {
    const candidate = entry.data.srcuser || entry.data.dstuser || entry.data.user || entry.data.username || entry.data.target_user;
    if (candidate) return String(candidate).trim();
  }
  const candidate = entry.user || entry.username || entry.user_name || entry.srcuser || entry.dstuser || entry.account || entry['Account Name'];
  if (candidate) return String(candidate).trim();

  const fullLog = String(entry.full_log || '');
  const match = fullLog.match(/for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_\-.]+)\s+from/i);
  if (match) return match[1].trim();

  return '';
}

function extractPathFromEntry(entry) {
  if (entry.data && typeof entry.data === 'object') {
    const candidate = entry.data.url || entry.data.uri || entry.data.path || entry.data.request;
    if (candidate) return String(candidate).trim();
  }
  return String(entry.path || entry.uri || entry.url || entry.request || '').trim();
}

function extractUserAgentFromEntry(entry) {
  if (entry.data && typeof entry.data === 'object') {
    const candidate = entry.data.http_user_agent || entry.data.user_agent || entry.data.ua;
    if (candidate) return String(candidate).toLowerCase().trim();
  }
  return String(entry.user_agent || entry.http_user_agent || entry.ua || '').toLowerCase().trim();
}

function extractMessageFromEntry(entry) {
  if (entry.rule && typeof entry.rule === 'object' && entry.rule.description) {
    return String(entry.rule.description).trim();
  }
  if (entry.data && typeof entry.data === 'object' && entry.data.message) {
    return String(entry.data.message).trim();
  }
  return String(entry.message || entry.full_log || entry['Command Line'] || entry.command_line || '').trim();
}

function isAuthFailureEvent(entry) {
  if (entry.rule && typeof entry.rule === 'object') {
    const ruleId = String(entry.rule.id || '');
    if (WAZUH_AUTH_RULE_IDS.has(ruleId)) return true;
    const groups = entry.rule.groups;
    if (Array.isArray(groups)) {
      const groupSet = new Set(groups.map((g) => String(g).toLowerCase()));
      if (['authentication_failed', 'authentication_failures', 'invalid_login', 'sshd'].some((g) => groupSet.has(g))) return true;
    }
  }

  const event = String(entry.event || '').toLowerCase();
  if (/login_failed|failed_login|auth_failure|authentication_failed/.test(event)) return true;

  const msg = `${extractMessageFromEntry(entry)} ${String(entry.full_log || '')}`.toLowerCase();
  if (/failed password|failed login|invalid user|authentication failed|login failed/.test(msg)) return true;

  return false;
}

function isSensitiveEndpointAccess(entry) {
  const path = extractPathFromEntry(entry).toLowerCase();
  return sensitiveEndpoints.some((pattern) => path.includes(pattern));
}

function isKnownScannerActivity(entry) {
  const userAgent = extractUserAgentFromEntry(entry);
  if (scannerPatterns.some((pattern) => userAgent.includes(pattern))) return true;

  const payload = `${extractPathFromEntry(entry)} ${extractMessageFromEntry(entry)} ${String(entry.query || '')} ${String(entry.full_log || '')}`.toLowerCase();
  return scannerPatterns.some((pattern) => payload.includes(pattern));
}

function isSuspiciousWebActivity(entry) {
  if (entry.rule && typeof entry.rule === 'object') {
    const ruleId = String(entry.rule.id || '');
    if (WAZUH_WEB_ATTACK_RULE_IDS.has(ruleId)) return true;
    const groups = entry.rule.groups;
    if (Array.isArray(groups)) {
      const groupSet = new Set(groups.map((g) => String(g).toLowerCase()));
      if (['sql_injection', 'web_scan', 'xss', 'path_traversal', 'attack', 'attacks'].some((g) => groupSet.has(g))) return true;
    }
    const level = Number(entry.rule.level);
    if (!isNaN(level) && level >= 7) return true;
  }

  const path = extractPathFromEntry(entry);
  const msg = extractMessageFromEntry(entry);
  const fullLog = String(entry.full_log || '');
  const userAgent = extractUserAgentFromEntry(entry);
  const event = String(entry.event || '').toLowerCase();

  const payload = `${path} ${msg} ${fullLog} ${userAgent} ${String(entry.query || '')}`.toLowerCase();
  if (!payload.trim()) return false;

  if (/blocked|denied|rejected/.test(event)) return true;

  const status = String(entry.status || (entry.data && entry.data.status) || '').trim();
  if (status === '403' && isSensitiveEndpointAccess(entry)) return true;

  if (isSensitiveEndpointAccess(entry)) return true;
  if (isKnownScannerActivity(entry)) return true;
  if (suspiciousPatterns.some((pattern) => payload.includes(pattern))) return true;
  if (/(union|select|drop|insert|update|delete).*(from|table)/i.test(payload)) return true;
  if (/(?:\b(?:or|and)\s+\d+=\d+|'.*'.*'.*')/i.test(payload)) return true;

  return false;
}

function buildTargetSummary(targetRole, targets) {
  if (targetRole === 'manager') {
    const mgrNames = targets.filter((t) => t.role === 'manager').map((t) => t.name || 'wazuh-manager');
    const mgrName = mgrNames[0] || 'wazuh-manager';
    return `Wazuh Manager (ID: 000, Name: ${mgrName})`;
  } else if (targetRole === 'agent') {
    const agentStrs = targets.filter((t) => t.role === 'agent').map((t) => `${t.name || 'agent'} (ID: ${t.id || 'N/A'})`);
    return `Wazuh Agent(s): ${agentStrs.join(', ') || 'Monitored Agent'}`;
  } else if (targetRole === 'both') {
    const agentStrs = targets.filter((t) => t.role === 'agent').map((t) => `${t.name || 'agent'} (ID: ${t.id || 'N/A'})`);
    return `Wazuh Manager (ID: 000) & Wazuh Agent(s): ${agentStrs.join(', ') || 'Monitored Agent'}`;
  }
  return 'Unknown Target';
}

function buildReason(ip, targetRole, targetSummary, failedLogins, suspiciousEvents, failedUsernames, sensitiveCount, scannerCount) {
  const reasons = [];

  if (targetRole === 'manager') {
    reasons.push(`[Target: Wazuh Manager] Attack targeted the central Wazuh Manager (${targetSummary}).`);
  } else if (targetRole === 'agent') {
    reasons.push(`[Target: Wazuh Agent] Attack targeted monitored agent endpoint(s) (${targetSummary}).`);
  } else if (targetRole === 'both') {
    reasons.push(`[Target: Wazuh Manager & Agent] Multi-target attack directed at both the Wazuh Manager and monitored Agent(s) (${targetSummary}).`);
  }

  if (failedLogins.length) {
    reasons.push(`${failedLogins.length} failed login attempt(s) were observed from ${ip}.`);
  }

  if (failedUsernames.length > 1) {
    reasons.push(`Multiple usernames were targeted from ${ip}: ${failedUsernames.sort().join(', ')}.`);
  } else if (failedUsernames.length === 1) {
    reasons.push(`Targeted username: ${failedUsernames[0]}.`);
  }

  if (suspiciousEvents.length) {
    const topEvent = suspiciousEvents[0];
    const path = extractPathFromEntry(topEvent) || 'request';
    const msg = extractMessageFromEntry(topEvent) || 'suspicious request';
    const pathText = String(path).toLowerCase();

    if (/(union|select|or '1'='1|or 1=1|sql|script)/.test(pathText)) {
      reasons.push(`The request to ${path} shows SQL injection or script-related payloads: ${msg}.`);
    } else if (['blocked_request', 'blocked', 'denied', 'rejected'].includes(String(topEvent.event || '').toLowerCase())) {
      reasons.push(`The WAF or gateway blocked an anomalous request from ${ip}: ${msg}.`);
    } else if (isSensitiveEndpointAccess(topEvent)) {
      reasons.push(`The request targeted a sensitive endpoint from ${ip}: ${path}.`);
    } else if (scannerCount) {
      reasons.push(`Traffic from ${ip} contained known scanning or reconnaissance signatures: ${msg}.`);
    } else {
      reasons.push(`The traffic pattern for ${ip} includes anomalous web activity: ${msg}.`);
    }
  }

  if (sensitiveCount && !suspiciousEvents.some(isSensitiveEndpointAccess)) {
    reasons.push(`${sensitiveCount} request(s) targeted sensitive admin or configuration endpoints.`);
  }

  if (scannerCount && !suspiciousEvents.some(isKnownScannerActivity)) {
    reasons.push(`${scannerCount} request(s) included scanner or reconnaissance signatures.`);
  }

  return reasons.join(' ');
}

function correlateLogs(logs) {
  const report = {
    is_attack_attempt: false,
    alerts: [],
    summary: {
      total_events: 0,
      analyzed_ips: [],
      target_ips: [],
      attack_count: 0,
      risk_level: 'low',
      manager_attacks: 0,
      agent_attacks: 0,
      target_distribution: { manager: 0, agent: 0, both: 0, unknown: 0 },
      affected_agents: [],
      affected_managers: []
    }
  };

  const records = normalizeLogInput(logs);
  const grouped = new Map();

  for (const rawEntry of records) {
    if (!rawEntry || typeof rawEntry !== 'object') continue;
    const entry = { ...rawEntry };
    entry._ip = extractIpFromEntry(entry);
    entry._target = extractTargetInfo(entry);

    const bucket = grouped.get(entry._ip) || [];
    bucket.push(entry);
    grouped.set(entry._ip, bucket);
  }

  report.summary.total_events = Array.from(grouped.values()).reduce((sum, items) => sum + items.length, 0);
  report.summary.analyzed_ips = Array.from(grouped.keys()).sort();

  const targetIps = [];
  const alerts = [];
  const allAffectedAgents = new Set();
  const allAffectedManagers = new Set();

  for (const [ip, entries] of grouped.entries()) {
    const failedLogins = entries.filter(isAuthFailureEvent);
    const suspiciousEvents = entries.filter(isSuspiciousWebActivity);
    const sensitiveAccesses = entries.filter(isSensitiveEndpointAccess);
    const scannerHits = entries.filter(isKnownScannerActivity);
    const failedUsernames = Array.from(new Set(failedLogins.map(extractUserFromEntry).filter(Boolean)));

    if (!failedLogins.length && !suspiciousEvents.length && !sensitiveAccesses.length && !scannerHits.length) continue;

    let isAttack = false;
    if (failedLogins.length >= 2) isAttack = true;
    if (suspiciousEvents.length) isAttack = true;
    if (sensitiveAccesses.length) isAttack = true;
    if (scannerHits.length) isAttack = true;
    if (failedUsernames.length >= 2) isAttack = true;

    if (!isAttack) continue;

    const rolesPresent = new Set(entries.map((e) => e._target.role));
    const hasManager = rolesPresent.has('manager');
    const hasAgent = rolesPresent.has('agent');

    let targetRole = 'unknown';
    if (hasManager && hasAgent) {
      targetRole = 'both';
    } else if (hasManager) {
      targetRole = 'manager';
    } else if (hasAgent) {
      targetRole = 'agent';
    }

    const uniqueTargetsMap = new Map();
    for (const entry of entries) {
      const t = entry._target;
      const key = `${t.role}:${t.id}:${t.name}`;
      if (!uniqueTargetsMap.has(key) && (t.role !== 'unknown' || entries.length === 1)) {
        uniqueTargetsMap.set(key, {
          role: t.role,
          id: t.id,
          name: t.name,
          ip: t.ip
        });
      }
    }

    const targetsList = Array.from(uniqueTargetsMap.values());
    const targetSummary = buildTargetSummary(targetRole, targetsList);

    const targetedAgentNames = Array.from(new Set(
      targetsList.filter((t) => t.role === 'agent' && (t.name || t.id)).map((t) => t.name || `Agent-${t.id}`)
    )).sort();

    const targetedAgentIds = Array.from(new Set(
      targetsList.filter((t) => t.role === 'agent' && t.id).map((t) => t.id)
    )).sort();

    const targetedManagerNames = Array.from(new Set(
      targetsList.filter((t) => t.role === 'manager').map((t) => t.name || 'wazuh-manager')
    )).sort();

    if (targetedAgentNames.length) {
      targetedAgentNames.forEach((name) => allAffectedAgents.add(name));
    } else if (targetedAgentIds.length) {
      targetedAgentIds.forEach((id) => allAffectedAgents.add(id));
    }

    if (hasManager) {
      (targetedManagerNames.length ? targetedManagerNames : ['wazuh-manager']).forEach((m) => allAffectedManagers.add(m));
    }

    targetIps.push(ip);
    alerts.push({
      ip,
      target_type: targetRole,
      target_summary: targetSummary,
      targets: targetsList,
      severity: suspiciousEvents.length || failedLogins.length >= 2 || sensitiveAccesses.length || scannerHits.length || failedUsernames.length >= 2 ? 'high' : 'medium',
      reason: buildReason(ip, targetRole, targetSummary, failedLogins, suspiciousEvents, failedUsernames, sensitiveAccesses.length, scannerHits.length),
      evidence: {
        target_type: targetRole,
        is_manager_attack: hasManager,
        is_agent_attack: hasAgent,
        targeted_agents: targetedAgentNames,
        targeted_agent_ids: targetedAgentIds,
        targeted_managers: targetedManagerNames,
        failed_login_count: failedLogins.length,
        suspicious_event_count: suspiciousEvents.length,
        sensitive_endpoint_count: sensitiveAccesses.length,
        scanner_signature_count: scannerHits.length,
        unique_failed_usernames: failedUsernames,
        failed_login_examples: failedLogins.slice(0, 3).map(extractMessageFromEntry),
        suspicious_examples: suspiciousEvents.slice(0, 3).map((e) => extractPathFromEntry(e) || extractMessageFromEntry(e))
      }
    });
  }

  if (alerts.length) {
    report.is_attack_attempt = true;
    report.alerts = alerts;
    report.summary.attack_count = alerts.length;
    report.summary.target_ips = targetIps.sort();
    report.summary.risk_level = 'high';
    report.summary.manager_attacks = alerts.filter((a) => a.target_type === 'manager' || a.target_type === 'both').length;
    report.summary.agent_attacks = alerts.filter((a) => a.target_type === 'agent' || a.target_type === 'both').length;

    const dist = { manager: 0, agent: 0, both: 0, unknown: 0 };
    alerts.forEach((a) => {
      dist[a.target_type] = (dist[a.target_type] || 0) + 1;
    });
    report.summary.target_distribution = dist;
    report.summary.affected_agents = Array.from(allAffectedAgents).sort();
    report.summary.affected_managers = Array.from(allAffectedManagers).sort();
  }

  return report;
}

function renderSummary(summary) {
  const cards = [
    { label: 'Total Events', value: summary.total_events },
    { label: 'Analyzed IPs', value: summary.analyzed_ips.length },
    { label: 'Attack Alerts', value: summary.attack_count },
    { label: 'Manager Attacks', value: summary.manager_attacks || 0, extraClass: 'manager-card' },
    { label: 'Agent Attacks', value: summary.agent_attacks || 0, extraClass: 'agent-card' }
  ];

  const container = document.getElementById('summary-grid');
  container.innerHTML = cards.map((card) => `
    <div class="summary-card ${card.extraClass || ''}">
      <span class="label">${card.label}</span>
      <span class="value">${card.value}</span>
    </div>
  `).join('');

  const riskBadge = document.getElementById('risk-badge');
  riskBadge.textContent = summary.risk_level.toUpperCase();
  riskBadge.classList.remove('high', 'medium');
  if (summary.risk_level === 'high') riskBadge.classList.add('high');
  if (summary.risk_level === 'medium') riskBadge.classList.add('medium');
}

function renderAlerts(alerts) {
  const container = document.getElementById('alerts-container');
  const countTag = document.getElementById('alerts-count-tag');

  if (countTag) {
    countTag.textContent = `${alerts.length} alert${alerts.length === 1 ? '' : 's'}`;
  }

  if (!alerts.length) {
    container.innerHTML = '<p>No suspicious attack activity detected.</p>';
    return;
  }

  container.innerHTML = alerts.map((alert) => {
    const severityClass = alert.severity === 'high' ? 'severity-high' : 'severity-medium';
    const targetType = alert.target_type || 'unknown';
    const targetBadgeLabel = targetType === 'manager'
      ? 'TARGET: WAZUH MANAGER'
      : targetType === 'agent'
      ? `TARGET: WAZUH AGENT (${(alert.evidence.targeted_agents && alert.evidence.targeted_agents[0]) || 'ENDPOINT'})`
      : targetType === 'both'
      ? 'TARGET: MANAGER & AGENT'
      : 'TARGET: UNKNOWN';

    const evidence = [
      `Target Summary: ${alert.target_summary}`,
      `Failed login attempts: ${alert.evidence.failed_login_count}`,
      `Suspicious events: ${alert.evidence.suspicious_event_count}`,
      ...(alert.evidence.targeted_agents && alert.evidence.targeted_agents.length ? [`Targeted Agent(s): ${alert.evidence.targeted_agents.join(', ')}`] : []),
      ...(alert.evidence.unique_failed_usernames && alert.evidence.unique_failed_usernames.length ? [`Targeted Users: ${alert.evidence.unique_failed_usernames.join(', ')}`] : []),
      ...(alert.evidence.failed_login_examples && alert.evidence.failed_login_examples.length ? [`Auth Failure Examples: ${alert.evidence.failed_login_examples.join('; ')}`] : []),
      ...(alert.evidence.suspicious_examples && alert.evidence.suspicious_examples.length ? [`Suspicious Payloads: ${alert.evidence.suspicious_examples.join('; ')}`] : [])
    ];

    return `
      <article class="alert-card">
        <div class="alert-header">
          <div class="alert-title-wrap">
            <span class="alert-title">${alert.ip}</span>
            <span class="target-badge ${targetType}">${targetBadgeLabel}</span>
          </div>
          <span class="severity-tag ${severityClass}">${alert.severity}</span>
        </div>
        <div class="alert-target-info">
          <strong>Attack Destination:</strong> ${alert.target_summary}
        </div>
        <p>${alert.reason}</p>
        <ul class="evidence-list">
          ${evidence.map((item) => `<li>${item}</li>`).join('')}
        </ul>
      </article>
    `;
  }).join('');
}

function renderDetails(report) {
  const detailsContainer = document.getElementById('details-container');

  if (!report.alerts.length) {
    detailsContainer.innerHTML = '<p>No attack details available.</p>';
    return;
  }

  detailsContainer.innerHTML = report.alerts.map((alert) => {
    const failedExamples = alert.evidence.failed_login_examples && alert.evidence.failed_login_examples.length
      ? alert.evidence.failed_login_examples
      : ['None captured'];
    const suspiciousExamples = alert.evidence.suspicious_examples && alert.evidence.suspicious_examples.length
      ? alert.evidence.suspicious_examples
      : ['None captured'];

    const targetType = alert.target_type || 'unknown';
    const highlightClass = targetType === 'manager' ? 'highlight-manager' : (targetType === 'agent' ? 'highlight-agent' : '');

    const items = [
      { key: 'Attacker Source IP', value: alert.ip },
      { key: 'Wazuh Target Role', value: targetType.toUpperCase() },
      { key: 'Target Entity Details', value: alert.target_summary },
      { key: 'Targeted Agents', value: (alert.evidence.targeted_agents && alert.evidence.targeted_agents.join(', ')) || 'None' },
      { key: 'Severity Level', value: alert.severity.toUpperCase() },
      { key: 'Failed Logins', value: alert.evidence.failed_login_count },
      { key: 'Suspicious Events', value: alert.evidence.suspicious_event_count },
      { key: 'Targeted Usernames', value: (alert.evidence.unique_failed_usernames && alert.evidence.unique_failed_usernames.join(', ')) || 'N/A' },
      { key: 'Attack Correlation Reason', value: alert.reason },
      { key: 'Sample Auth Events', value: failedExamples.join(' | ') },
      { key: 'Sample Web Payloads', value: suspiciousExamples.join(' | ') }
    ];

    return `
      <div class="detail-card">
        <h4>Target Investigation for Attacker ${alert.ip}</h4>
        <div class="detail-grid">
          ${items.map((item) => `
            <div class="detail-item ${item.key.includes('Target') ? highlightClass : ''}">
              <span class="key">${item.key}</span>
              <div class="value">${item.value}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');
}

let latestReport = null;

function showReport(report) {
  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('report-content').classList.remove('hidden');

  const mgrCount = report.summary.manager_attacks || 0;
  const agentCount = report.summary.agent_attacks || 0;
  let targetSummaryText = '';
  if (mgrCount > 0 && agentCount > 0) {
    targetSummaryText = `Correlation identified attacks targeting both the Wazuh Manager (${mgrCount}) and monitored Wazuh Agents (${agentCount}).`;
  } else if (mgrCount > 0) {
    targetSummaryText = `Attacks are specifically targeting the central Wazuh Manager server.`;
  } else if (agentCount > 0) {
    targetSummaryText = `Attacks are targeting monitored Wazuh Agent endpoint(s) (${report.summary.affected_agents.join(', ') || 'Agent Nodes'}).`;
  }

  document.getElementById('executive-summary').textContent = report.is_attack_attempt
    ? `Suspicious activity was detected for ${report.summary.target_ips.length} source IP address(es). ${targetSummaryText} Immediate containment is advised.`
    : 'No suspicious attack patterns were detected. The log set appears to reflect normal operational activity.';

  latestReport = report;
  renderSummary(report.summary);
  renderAlerts(report.alerts);
  renderDetails(report);
}

function generateReport(customText) {
  const text = customText !== undefined ? customText : document.getElementById('log-input').value;
  const logs = normalizeLogInput(text);
  const report = correlateLogs(logs);
  showReport(report);
}

// Check Wazuh Connection Status via Backend API
async function checkWazuhConnection() {
  const pill = document.getElementById('wazuh-status-pill');
  const text = document.getElementById('wazuh-status-text');
  const banner = document.getElementById('live-info-banner');
  const bannerText = document.getElementById('live-banner-text');

  pill.className = 'status-pill checking';
  text.textContent = 'Wazuh: Checking...';

  try {
    const res = await fetch(apiUrl('/api/wazuh/test'));
    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        pill.className = 'status-pill connected';
        text.textContent = `Wazuh: Connected (${data.agent_count} Node${data.agent_count === 1 ? '' : 's'})`;
        banner.classList.remove('hidden');
        bannerText.textContent = `Connected to Wazuh SIEM (${data.host}). ${data.agent_count} node(s) discovered.`;
        return;
      }
    }
  } catch (err) {
    // API not running or connection failed
  }

  pill.className = 'status-pill disconnected';
  text.textContent = 'Wazuh: Offline (Configure)';
  banner.classList.add('hidden');
}

// Sync live alerts directly from attached Wazuh SIEM
async function syncLiveWazuhAlerts() {
  const syncBtn = document.getElementById('sync-wazuh');
  const originalHtml = syncBtn.innerHTML;
  syncBtn.innerHTML = '⏳ Syncing...';
  syncBtn.disabled = true;

  try {
    const res = await fetch(apiUrl('/api/wazuh/sync'));
    const report = await res.json();
    if (!res.ok || report.error) {
      throw new Error(report.error || `Sync request failed (HTTP ${res.status})`);
    }
    if (report && report.summary) {
      showReport(report);
      const fetchedCount = report.meta ? report.meta.fetched_count : 0;
      const metaInfo = ` (Fetched ${fetchedCount} live alerts from Wazuh)`;
      document.getElementById('executive-summary').textContent += metaInfo;
      syncBtn.innerHTML = '✔ Synced!';
      setTimeout(() => {
        syncBtn.innerHTML = originalHtml;
        syncBtn.disabled = false;
      }, 2000);
      if (fetchedCount === 0) {
        const diagnosticMessage = report.diagnostics?.message || report.meta?.status || 'Wazuh returned no alerts';
        throw new Error(diagnosticMessage);
      }
      return;
    }
  } catch (err) {
    alert(`Could not sync live alerts from Wazuh: ${err.message}`);
  }

  syncBtn.innerHTML = originalHtml;
  syncBtn.disabled = false;
}

// Load and Save Settings Modal
async function openSettingsModal() {
  const modal = document.getElementById('settings-modal');
  modal.classList.remove('hidden');

  try {
    const res = await fetch(apiUrl('/api/wazuh/config'));
    if (res.ok) {
      const cfg = await res.json();
      document.getElementById('wazuh-host-input').value = cfg.host || '';
      document.getElementById('wazuh-indexer-input').value = cfg.indexer_host || '';
      document.getElementById('wazuh-user-input').value = cfg.username || '';
      if (cfg.has_password) {
        document.getElementById('wazuh-pass-input').placeholder = '•••••••• (Saved)';
      }
    }
  } catch (err) {
    // ignore
  }
}

function closeSettingsModal() {
  document.getElementById('settings-modal').classList.add('hidden');
  document.getElementById('connection-test-result').classList.add('hidden');
}

async function testWazuhConnectionFromModal() {
  const host = document.getElementById('wazuh-host-input').value.trim();
  const indexerHost = document.getElementById('wazuh-indexer-input').value.trim();
  const username = document.getElementById('wazuh-user-input').value.trim();
  const password = document.getElementById('wazuh-pass-input').value;
  const resultBox = document.getElementById('connection-test-result');
  const testBtn = document.getElementById('test-connection-btn');

  testBtn.textContent = 'Testing...';
  testBtn.disabled = true;
  resultBox.classList.remove('hidden', 'success', 'error');
  resultBox.textContent = 'Connecting to Wazuh...';

  try {
    const res = await fetch(apiUrl('/api/wazuh/test'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, indexer_host: indexerHost, username, password })
    });
    const data = await res.json();
    if (data.success) {
      resultBox.classList.add('success');
      resultBox.textContent = `✔ ${data.message || 'Connected successfully to Wazuh SIEM!'}`;
    } else {
      resultBox.classList.add('error');
      resultBox.textContent = `✖ ${data.message || data.error || 'Connection failed'}`;
    }
  } catch (err) {
    resultBox.classList.add('error');
    resultBox.textContent = `✖ Request error: ${err.message}`;
  }

  testBtn.textContent = 'Test Connection';
  testBtn.disabled = false;
  checkWazuhConnection();
}

async function saveWazuhSettingsFromModal() {
  const host = document.getElementById('wazuh-host-input').value.trim();
  const indexerHost = document.getElementById('wazuh-indexer-input').value.trim();
  const username = document.getElementById('wazuh-user-input').value.trim();
  const password = document.getElementById('wazuh-pass-input').value;
  const saveBtn = document.getElementById('save-settings-btn');

  saveBtn.textContent = 'Saving...';
  saveBtn.disabled = true;

  try {
    const payload = { host, indexer_host: indexerHost, username };
    if (password) payload.password = password;

    const res = await fetch(apiUrl('/api/wazuh/config'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      alert('Wazuh configuration saved successfully!');
      closeSettingsModal();
      checkWazuhConnection();
    }
  } catch (err) {
    alert(`Failed to save settings: ${err.message}`);
  }

  saveBtn.textContent = 'Save Settings';
  saveBtn.disabled = false;
}

// Agents Inventory Modal
async function openAgentsModal() {
  const modal = document.getElementById('agents-modal');
  const container = document.getElementById('agents-list-container');
  modal.classList.remove('hidden');
  container.innerHTML = '<p>Querying Wazuh nodes & agents...</p>';

  try {
    const res = await fetch(apiUrl('/api/wazuh/agents'));
    if (res.ok) {
      const data = await res.json();
      const agents = data.agents || [];
      if (!agents.length) {
        container.innerHTML = '<p>No agents discovered or Wazuh server is unreachable.</p>';
        return;
      }

      container.innerHTML = `
        <table class="agents-table">
          <thead>
            <tr>
              <th>Role</th>
              <th>Node ID</th>
              <th>Name</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>OS / Platform</th>
            </tr>
          </thead>
          <tbody>
            ${agents.map((ag) => {
              const isManager = ag.id === '000' || ag.id === 0 || String(ag.name).toLowerCase().includes('manager');
              const roleClass = isManager ? 'manager' : 'agent';
              const roleLabel = isManager ? 'Manager' : 'Agent';
              const os = (ag.os && ag.os.name) || ag.platform || 'N/A';
              return `
                <tr>
                  <td><span class="node-role-badge ${roleClass}">${roleLabel}</span></td>
                  <td><strong>${ag.id}</strong></td>
                  <td>${ag.name || 'N/A'}</td>
                  <td>${ag.ip || 'N/A'}</td>
                  <td><span style="color: ${ag.status === 'active' ? 'var(--success)' : 'var(--muted)'}; font-weight: 700;">${ag.status || 'unknown'}</span></td>
                  <td>${os}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;
      return;
    }
  } catch (err) {
    // ignore
  }

  container.innerHTML = '<p>Could not load agent inventory. Please verify that the correlation server is running and Wazuh credentials are valid.</p>';
}

function closeAgentsModal() {
  document.getElementById('agents-modal').classList.add('hidden');
}

function loadWazuhSample() {
  document.getElementById('log-input').value = SAMPLE_WAZUH_LOGS;
  generateReport(SAMPLE_WAZUH_LOGS);
}

function loadManagerSample() {
  document.getElementById('log-input').value = SAMPLE_MANAGER_ATTACK;
  generateReport(SAMPLE_MANAGER_ATTACK);
}

function loadAgentSample() {
  document.getElementById('log-input').value = SAMPLE_AGENT_ATTACK;
  generateReport(SAMPLE_AGENT_ATTACK);
}

function clearInput() {
  document.getElementById('log-input').value = '';
  document.getElementById('report-content').classList.add('hidden');
  document.getElementById('empty-state').classList.remove('hidden');
  latestReport = null;
}

function processLogFile(file) {
  if (!file) return;

  const name = file.name.toLowerCase();
  const isSupported = /\.(json|csv|log|txt)$/i.test(name) || file.type === 'application/json' || file.type === 'text/csv' || file.type === 'text/plain';

  if (!isSupported) {
    alert('Please drop a JSON or CSV log file.');
    return;
  }

  const reader = new FileReader();
  reader.onload = function () {
    const text = String(reader.result || '');
    document.getElementById('log-input').value = text;
    generateReport(text);
  };
  reader.readAsText(file);
}

function handleFileSelection(event) {
  const file = event.target.files && event.target.files[0];
  processLogFile(file);
  event.target.value = '';
}

function handleDragAndDrop(event) {
  event.preventDefault();
  document.getElementById('dropzone').classList.remove('dragover');

  const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
  processLogFile(file);
}

function downloadReportFile() {
  if (!latestReport) {
    alert('No report available to download yet.');
    return;
  }

  const { jsPDF } = window.jspdf || {};
  if (!jsPDF) {
    alert('PDF export library is not available. Please refresh the page and try again.');
    return;
  }

  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const margin = 40;
  const pageWidth = doc.internal.pageSize.getWidth();
  const contentWidth = pageWidth - margin * 2;
  let y = 50;

  const addWrappedText = (text, fontSize, weight = 'normal', color = [0, 0, 0]) => {
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    if (weight === 'bold') {
      doc.setFont('helvetica', 'bold');
    } else {
      doc.setFont('helvetica', 'normal');
    }

    const lines = doc.splitTextToSize(String(text || ''), contentWidth);
    doc.text(lines, margin, y);
    y += (lines.length * (fontSize + 4));
    return y;
  };

  addWrappedText('Wazuh Security Log Correlation Report', 20, 'bold', [15, 23, 42]);
  y += 6;
  addWrappedText(`Risk Level: ${latestReport.summary.risk_level.toUpperCase()}`, 11, 'bold');
  addWrappedText(`Total Events: ${latestReport.summary.total_events} | Attack Alerts: ${latestReport.summary.attack_count}`, 11);
  addWrappedText(`Attacks on Wazuh Manager: ${latestReport.summary.manager_attacks || 0} | Attacks on Wazuh Agent(s): ${latestReport.summary.agent_attacks || 0}`, 11);
  if (latestReport.summary.affected_agents && latestReport.summary.affected_agents.length) {
    addWrappedText(`Affected Agents: ${latestReport.summary.affected_agents.join(', ')}`, 11);
  }
  if (latestReport.summary.affected_managers && latestReport.summary.affected_managers.length) {
    addWrappedText(`Affected Managers: ${latestReport.summary.affected_managers.join(', ')}`, 11);
  }
  y += 12;

  if (latestReport.alerts.length) {
    addWrappedText('Correlated Attack Findings', 15, 'bold', [37, 99, 235]);
    y += 4;
    latestReport.alerts.forEach((alert) => {
      if (y > 700) {
        doc.addPage();
        y = 50;
      }

      addWrappedText(`Attacker IP: ${alert.ip} [Target: ${alert.target_type.toUpperCase()} - ${alert.target_summary}]`, 12, 'bold', [15, 23, 42]);
      addWrappedText(`Severity: ${alert.severity.toUpperCase()}`, 11);
      addWrappedText(`Reason: ${alert.reason}`, 11);
      addWrappedText(`Failed login attempts: ${alert.evidence.failed_login_count}`, 11);
      addWrappedText(`Suspicious events: ${alert.evidence.suspicious_event_count}`, 11);
      if (alert.evidence.unique_failed_usernames && alert.evidence.unique_failed_usernames.length) {
        addWrappedText(`Targeted Usernames: ${alert.evidence.unique_failed_usernames.join(', ')}`, 11);
      }
      y += 10;
    });
  } else {
    addWrappedText('No suspicious activity detected.', 12, 'bold', [22, 101, 52]);
  }

  doc.save('wazuh_security_report.pdf');
}

function handleExportPdf() {
  if (latestReport) {
    downloadReportFile();
    return;
  }
  window.print();
}

// Bind DOM Events
document.getElementById('generate-report').addEventListener('click', () => generateReport());
document.getElementById('sync-wazuh').addEventListener('click', syncLiveWazuhAlerts);
document.getElementById('load-wazuh-sample').addEventListener('click', loadWazuhSample);
document.getElementById('load-manager-sample').addEventListener('click', loadManagerSample);
document.getElementById('load-agent-sample').addEventListener('click', loadAgentSample);
document.getElementById('clear-input').addEventListener('click', clearInput);
document.getElementById('download-report').addEventListener('click', downloadReportFile);
document.getElementById('export-pdf').addEventListener('click', handleExportPdf);
document.getElementById('browse-file').addEventListener('click', () => document.getElementById('file-input').click());
document.getElementById('file-input').addEventListener('change', handleFileSelection);

document.getElementById('open-settings').addEventListener('click', openSettingsModal);
document.getElementById('close-settings').addEventListener('click', closeSettingsModal);
document.getElementById('test-connection-btn').addEventListener('click', testWazuhConnectionFromModal);
document.getElementById('save-settings-btn').addEventListener('click', saveWazuhSettingsFromModal);
document.getElementById('wazuh-status-pill').addEventListener('click', openSettingsModal);

document.getElementById('view-agents').addEventListener('click', openAgentsModal);
document.getElementById('close-agents').addEventListener('click', closeAgentsModal);
document.getElementById('close-agents-btn').addEventListener('click', closeAgentsModal);
document.getElementById('refresh-agents-btn').addEventListener('click', openAgentsModal);

const dropzone = document.getElementById('dropzone');
dropzone.addEventListener('dragover', (event) => {
  event.preventDefault();
  dropzone.classList.add('dragover');
});
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', handleDragAndDrop);
dropzone.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    document.getElementById('file-input').click();
  }
});

// Initialize
document.getElementById('log-input').value = SAMPLE_WAZUH_LOGS;
generateReport(SAMPLE_WAZUH_LOGS);
checkWazuhConnection();

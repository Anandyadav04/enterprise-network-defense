/**
 * frontend/src/api/client.js
 * ────────────────────────────
 * Centralized API client and network layer for Enterprise SOC Platform.
 *
 * Provides:
 *   - Configurable API Base URL via VITE_API_BASE environment variable
 *   - Unified error handling and response parsing
 *   - CSV export utilities for threat audit trails
 *   - Clean separation of concerns (resolves React Fast-Refresh warnings)
 */

export const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api/v1'

/* ── Generic Request Wrapper with Timeout ── */
async function request(endpoint, options = {}, timeoutMs = 8000) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const url = `${API_BASE}${endpoint}`
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    })
    clearTimeout(timeoutId)
    return response
  } catch (err) {
    clearTimeout(timeoutId)
    throw err
  }
}

/* ── Alerts & Incidents API ── */
export async function fetchAlerts(limit = 1000) {
  try {
    const res = await request(`/alerts/?limit=${limit}`)
    if (!res.ok) return []
    return await res.json()
  } catch {
    return []
  }
}

export async function fetchOpenCriticalCount() {
  try {
    const res = await request('/alerts/critical-count')
    if (!res.ok) return 0
    return await res.json()
  } catch {
    return 0
  }
}

export async function updateAlertStatusApi(eventId, status = 'ACKNOWLEDGED', analystNote = null) {
  try {
    const res = await request(`/alerts/${eventId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status,
        analyst_note: analystNote,
      }),
    })
    return res.ok
  } catch (err) {
    console.error('updateAlertStatusApi failed:', err)
    return false
  }
}

export async function mitigateAlert(eventId) {
  return await updateAlertStatusApi(
    eventId,
    'ACKNOWLEDGED',
    'Threat mitigated: IP blocked and incident acknowledged by SOC analyst'
  )
}

/* ── MITRE ATT&CK Knowledge Base Mapping ── */
export const MITRE_MAP = {
  HTTP_EXPLOIT: {
    tactic: 'Initial Access & Discovery',
    tacticId: 'TA0001 / TA0007',
    id: 'T1190 / T1083',
    name: 'Exploit Public-Facing App / File Discovery',
    desc: 'Adversary probes web application for path traversal, dot-dot sequences, LFI, and unauthorized administrative endpoints.',
    remediation: 'Verify Web Application Firewall (WAF) rule signatures, sanitize download parameter inputs, and enforce host Netfilter DROP.',
  },
  SQL_INJECTION: {
    tactic: 'Initial Access & Execution',
    tacticId: 'TA0001 / TA0002',
    id: 'T1190 / T1059',
    name: 'SQL Injection / Command Shell Execution',
    desc: 'Malicious SQL syntax (UNION SELECT, comment tags, xp_cmdshell) designed to manipulate backend database engine.',
    remediation: 'Utilize parameterized PreparedStatements, restrict DB user privileges, and quarantine offending IP on perimeter firewall.',
  },
  BRUTE_FORCE: {
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    id: 'T1110.001',
    name: 'Password Guessing / Credential Spray',
    desc: 'Automated rapid dictionary attack targeting authentication endpoints to compromise user or administrator accounts.',
    remediation: 'Enforce account lockouts, rate limiting, mandatory MFA, and temporary firewall block for repeated failures.',
  },
  MALWARE: {
    tactic: 'Command & Control',
    tacticId: 'TA0011',
    id: 'T1071.001',
    name: 'Web Protocols / C2 Beaconing',
    desc: 'Outbound HTTP communication matching Trojan/botnet beacon patterns (Trickbot, Cobalt Strike, Emotet) with bot IDs.',
    remediation: 'Isolate compromised internal host from DMZ/LAN, terminate outbound C2 socket, and run endpoint EDR scan.',
  },
  C2_COMMUNICATION: {
    tactic: 'Command & Control',
    tacticId: 'TA0011',
    id: 'T1071',
    name: 'Application Layer Protocol',
    desc: 'Heartbeat signals and payload extraction communications with adversary command and control infrastructure.',
    remediation: 'Blackhole destination IP on pfSense WAN and sinkhole upstream DNS requests.',
  },
  PORT_SCAN: {
    tactic: 'Reconnaissance',
    tacticId: 'TA0043',
    id: 'T1046',
    name: 'Network Service Discovery',
    desc: 'Automated SYN/Connect scans probing DMZ port availability and service fingerprints across host ranges.',
    remediation: 'Enable adaptive IPS port-scan thresholding and silence unneeded external ports.',
  },
  DOS_DDOS: {
    tactic: 'Impact',
    tacticId: 'TA0040',
    id: 'T1498.001',
    name: 'Network Denial of Service (HTTP Flood)',
    desc: 'Volumetric request flood attempting web server thread exhaustion and application latency spikes.',
    remediation: 'Deploy SYN cookies, reverse proxy rate limiting, and automated machine-speed IP quarantine.',
  },
  DATA_EXFILTRATION: {
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    desc: 'Unusual outbound data volumes departing internal subnets to unauthorized external destinations.',
    remediation: 'Inspect egress payload sizes and revoke session tokens for offending credentials.',
  },
  DNS_TUNNELING: {
    tactic: 'Command & Control & Exfiltration',
    tacticId: 'TA0011 / TA0010',
    id: 'T1071.004',
    name: 'DNS C2 / Tunneling',
    desc: 'Data payloads covertly encoded in base64/hex inside recursive DNS subdomains.',
    remediation: 'Block malicious nameservers, monitor DNS request entropy, and enforce internal resolver policies.',
  },
}

/* ── Web Audio API Synthetic SOC Siren / Alert Chime ── */
export function playSocAlertSound() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext
    if (!AudioCtx) return
    const ctx = new AudioCtx()
    if (ctx.state === 'suspended') {
      ctx.resume()
    }
    const osc = ctx.createOscillator()
    const gain = ctx.createGain()
    osc.type = 'sine'
    // Crisp dual-tone SOC beep: 880Hz (A5) ramping to 440Hz (A4)
    osc.frequency.setValueAtTime(880, ctx.currentTime)
    osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.22)
    gain.gain.setValueAtTime(0.12, ctx.currentTime)
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.22)
    osc.connect(gain)
    gain.connect(ctx.destination)
    osc.start()
    osc.stop(ctx.currentTime + 0.22)
  } catch {
    // Audio context may be restricted by autoplay policy before first gesture
  }
}

/* ── Network Flows Telemetry API ── */
export async function fetchFlowEvents(limit = 100) {
  try {
    const res = await request(`/events/?limit=${limit}`)
    if (!res.ok) return { flows: [], total: 0 }
    return await res.json()
  } catch {
    return { flows: [], total: 0 }
  }
}

/* ── Active IPS & Firewall Mitigations API ── */
export async function fetchMitigationRules(status = 'ALL', search = '') {
  try {
    let endpoint = `/mitigation/rules?status=${status}`
    if (search) endpoint += `&search=${encodeURIComponent(search)}`
    const res = await request(endpoint)
    if (!res.ok) return []
    return await res.json()
  } catch {
    return []
  }
}

export async function fetchMitigationStats() {
  try {
    const res = await request('/mitigation/stats')
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function blockIpApi(payload) {
  try {
    const res = await request('/mitigation/block', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function unblockIpApi(ipOrRuleId, note = 'Manual unblock via SOC Dashboard') {
  try {
    const res = await request(`/mitigation/unblock/${encodeURIComponent(ipOrRuleId)}`, {
      method: 'POST',
      body: JSON.stringify({ analyst_note: note }),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchIncidentReport(ruleId) {
  try {
    const res = await request(`/mitigation/incident-report/${ruleId}`)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

/* ── CSV Export Utility ── */
export function exportAlertsToCSV(alerts = []) {
  if (!alerts.length) return

  const headers = ['Timestamp (UTC)', 'Risk Tier', 'Risk Score', 'Classification', 'Source IP', 'Destination IP', 'Signature', 'Status']
  const rows = alerts.map(a => [
    `"${a.timestamp || ''}"`,
    `"${a.risk_tier || ''}"`,
    a.risk_score || 0,
    `"${a.ai_attack_class || ''}"`,
    `"${a.src_ip || ''}"`,
    `"${a.dst_ip || ''}"`,
    `"${(a.suricata_signature || '').replace(/"/g, '""')}"`,
    `"${a.status || ''}"`
  ])

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.setAttribute('href', url)
  link.setAttribute('download', `soc_threat_alerts_${new Date().toISOString().slice(0, 10)}.csv`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/* ── IP Address Validator ── */
export function isValidIP(ip) {
  if (!ip || typeof ip !== 'string') return false
  const trimmed = ip.trim()
  // IPv4 regex (0.0.0.0 to 255.255.255.255)
  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  // Basic IPv6 check
  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$/
  return ipv4Pattern.test(trimmed) || ipv6Pattern.test(trimmed)
}

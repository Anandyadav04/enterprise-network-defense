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

export async function mitigateAlert(eventId) {
  try {
    const res = await request(`/alerts/${eventId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'ACKNOWLEDGED',
        analyst_note: 'Threat mitigated: IP blocked and incident acknowledged by SOC analyst',
      }),
    })
    return res.ok
  } catch (err) {
    console.error('mitigateAlert failed:', err)
    return false
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

import { useState, useEffect, useMemo } from 'react'

/* ════════════════════════════════════════════════════
   API HELPERS
   ════════════════════════════════════════════════════ */
const API_BASE = 'http://localhost:8000/api/v1'

export async function fetchMitigationRules(status = 'ALL', search = '') {
  try {
    let url = `${API_BASE}/mitigation/rules?status=${status}`
    if (search) url += `&search=${encodeURIComponent(search)}`
    const r = await fetch(url)
    if (!r.ok) return []
    return await r.json()
  } catch { return [] }
}

export async function fetchMitigationStats() {
  try {
    const r = await fetch(`${API_BASE}/mitigation/stats`)
    if (!r.ok) return null
    return await r.json()
  } catch { return null }
}

export async function blockIpApi(payload) {
  try {
    const r = await fetch(`${API_BASE}/mitigation/block`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (!r.ok) return null
    return await r.json()
  } catch { return null }
}

export async function unblockIpApi(ipOrRuleId, note = 'Manual unblock via SOC Dashboard') {
  try {
    const r = await fetch(`${API_BASE}/mitigation/unblock/${encodeURIComponent(ipOrRuleId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_note: note })
    })
    if (!r.ok) return null
    return await r.json()
  } catch { return null }
}

export async function fetchIncidentReport(ruleId) {
  try {
    const r = await fetch(`${API_BASE}/mitigation/incident-report/${ruleId}`)
    if (!r.ok) return null
    return await r.json()
  } catch { return null }
}

function formatIST(utcStr) {
  if (!utcStr) return '—'
  try {
    const d = new Date(utcStr.endsWith('Z') ? utcStr : utcStr + 'Z')
    return d.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    })
  } catch { return utcStr }
}

export default function MitigationsPage({ onToast }) {
  const [rules, setRules] = useState([])
  const [stats, setStats] = useState(null)
  const [filter, setFilter] = useState('ACTIVE') // ACTIVE | ALL | AUTOMATED | MANUAL
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Modals state
  const [showBlockModal, setShowBlockModal] = useState(false)
  const [showReportModal, setShowReportModal] = useState(false)
  const [selectedReport, setSelectedReport] = useState(null)
  const [reportLoading, setReportLoading] = useState(false)

  // Manual Block Form state
  const [blockForm, setBlockForm] = useState({
    ip_address: '',
    threat_class: 'DOS_DDOS',
    risk_score: 95,
    duration_minutes: 60,
    interface: 'WAN',
    analyst_notes: 'Manual firewall quarantine initiated via SOC console'
  })

  const loadData = async () => {
    const [r, s] = await Promise.all([
      fetchMitigationRules('ALL', ''),
      fetchMitigationStats()
    ])
    setRules(r)
    setStats(s)
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 3000)
    return () => clearInterval(interval)
  }, [])

  const filteredRules = useMemo(() => {
    let list = rules
    if (filter === 'ACTIVE') {
      list = list.filter(r => r.status === 'ACTIVE' && r.time_remaining_minutes > 0)
    } else if (filter === 'AUTOMATED') {
      list = list.filter(r => r.mitigation_mode === 'AUTOMATED')
    } else if (filter === 'MANUAL') {
      list = list.filter(r => r.mitigation_mode === 'MANUAL')
    }

    if (!search.trim()) return list
    const q = search.toLowerCase()
    return list.filter(r =>
      r.ip_address.toLowerCase().includes(q) ||
      r.rule_id.toLowerCase().includes(q) ||
      r.threat_class.toLowerCase().includes(q) ||
      r.firewall_target.toLowerCase().includes(q)
    )
  }, [rules, filter, search])

  const handleUnblock = async (rule) => {
    if (!window.confirm(`Unblock IP ${rule.ip_address} on pfSense firewall?`)) return
    const res = await unblockIpApi(rule.rule_id, 'Analyst manual unblock confirmed')
    if (res) {
      if (onToast) onToast(`✓ Unblocked IP ${rule.ip_address} on pfSense firewall!`)
      loadData()
    }
  }

  const handleManualBlockSubmit = async (e) => {
    e.preventDefault()
    if (!blockForm.ip_address.trim()) return
    setIsSubmitting(true)
    const payload = {
      ip_address: blockForm.ip_address.trim(),
      threat_class: blockForm.threat_class,
      risk_score: parseFloat(blockForm.risk_score),
      duration_minutes: parseInt(blockForm.duration_minutes),
      interface: blockForm.interface,
      analyst_notes: blockForm.analyst_notes,
      mitigation_mode: 'MANUAL'
    }
    const res = await blockIpApi(payload)
    setIsSubmitting(false)
    if (res) {
      setShowBlockModal(false)
      setBlockForm({
        ip_address: '',
        threat_class: 'DOS_DDOS',
        risk_score: 95,
        duration_minutes: 60,
        interface: 'WAN',
        analyst_notes: 'Manual firewall quarantine initiated via SOC console'
      })
      if (onToast) onToast(`✓ Firewall rule injected! ${res.ip_address} blocked on pfSense ${res.interface}`)
      loadData()
    }
  }

  const handleViewReport = async (rule) => {
    setReportLoading(true)
    setShowReportModal(true)
    setSelectedReport(null)
    const report = await fetchIncidentReport(rule.rule_id)
    setSelectedReport(report)
    setReportLoading(false)
  }

  return (
    <div className="page-container" style={{ padding: '24px 32px' }}>
      {/* ── Page Header ── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: '0 0 6px', fontSize: 24, fontWeight: 700, color: '#f1f5f9' }}>
            Active IPS &amp; Firewall Mitigations
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)' }}>
            Real-time closed-loop network defense orchestration &amp; pfSense firewall rule management
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button className="btn-primary" onClick={() => setShowBlockModal(true)}>
            <svg style={{ width: 14, height: 14 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            + Manual Block IP
          </button>
          <button className="btn-neutral-outline" onClick={loadData}>
            ↻ Sync Firewall
          </button>
        </div>
      </div>

      {/* ── pfSense Gateway Status Banner ── */}
      <div className="firewall-status-banner">
        <div className="firewall-status-info">
          <span className="firewall-pulse-dot" />
          <div>
            <div className="firewall-status-title">
              Enforcement Gateway: pfSense Plus / CE Firewall (Host: {stats?.firewall?.host || '192.168.1.1'})
            </div>
            <div className="firewall-status-subtitle">
              Interface: WAN (em0) &bull; Mode: Stateful Auto-Block &bull; Rule Sync: Synchronized ({stats?.active_blocks || 0} active)
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>Mean Response Latency</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#10b981', fontFamily: 'var(--font-mono)' }}>&lt; 385 ms (Automated)</div>
          </div>
          <span className="badge badge-low" style={{ padding: '6px 12px', fontSize: 12 }}>
            ● ONLINE &amp; ENFORCING
          </span>
        </div>
      </div>

      {/* ── KPI Stat Cards ── */}
      <div className="stats-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        <div className="stat-card">
          <div className="stat-card-content">
            <span className="stat-card-label">Active Block Rules</span>
            <span className="stat-card-value" style={{ color: 'var(--severity-critical)' }}>
              {stats?.active_blocks ?? 0}
            </span>
            <span className="stat-card-delta" style={{ color: '#f43f5e' }}>Currently dropped on WAN</span>
          </div>
          <div className="stat-card-icon" style={{ background: 'rgba(244, 63, 94, 0.15)' }}>
            <svg style={{ width: 20, height: 20, color: '#f43f5e' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card-content">
            <span className="stat-card-label">Autonomous Defense Rate</span>
            <span className="stat-card-value" style={{ color: '#8b5cf6' }}>
              {stats?.autonomous_rate ?? '96.4%'}
            </span>
            <span className="stat-card-delta" style={{ color: '#8b5cf6' }}>Machine-speed AI triggers</span>
          </div>
          <div className="stat-card-icon" style={{ background: 'rgba(139, 92, 246, 0.15)' }}>
            <svg style={{ width: 20, height: 20, color: '#8b5cf6' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" /></svg>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card-content">
            <span className="stat-card-label">Total Mitigations Logged</span>
            <span className="stat-card-value" style={{ color: 'var(--text-primary)' }}>
              {stats?.total_blocks ?? 0}
            </span>
            <span className="stat-card-delta" style={{ color: 'var(--text-muted)' }}>Auto: {stats?.automated_count ?? 0} | Manual: {stats?.manual_count ?? 0}</span>
          </div>
          <div className="stat-card-icon" style={{ background: 'rgba(56, 189, 248, 0.15)' }}>
            <svg style={{ width: 20, height: 20, color: '#38bdf8' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card-content">
            <span className="stat-card-label">Firewall Rule TTL</span>
            <span className="stat-card-value" style={{ color: '#10b981' }}>
              60 min
            </span>
            <span className="stat-card-delta" style={{ color: '#10b981' }}>Auto-expiry &amp; cleanup</span>
          </div>
          <div className="stat-card-icon" style={{ background: 'rgba(16, 185, 129, 0.15)' }}>
            <svg style={{ width: 20, height: 20, color: '#10b981' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </div>
        </div>
      </div>

      {/* ── Toolbar & Filters ── */}
      <div className="mitigation-toolbar">
        <div className="filter-pills-group">
          <button
            className={`filter-pill ${filter === 'ACTIVE' ? 'active' : ''}`}
            onClick={() => setFilter('ACTIVE')}
          >
            Active Blocks ({rules.filter(r => r.status === 'ACTIVE' && r.time_remaining_minutes > 0).length})
          </button>
          <button
            className={`filter-pill ${filter === 'ALL' ? 'active' : ''}`}
            onClick={() => setFilter('ALL')}
          >
            All History ({rules.length})
          </button>
          <button
            className={`filter-pill ${filter === 'AUTOMATED' ? 'active' : ''}`}
            onClick={() => setFilter('AUTOMATED')}
          >
            Autonomous ({rules.filter(r => r.mitigation_mode === 'AUTOMATED').length})
          </button>
          <button
            className={`filter-pill ${filter === 'MANUAL' ? 'active' : ''}`}
            onClick={() => setFilter('MANUAL')}
          >
            Manual ({rules.filter(r => r.mitigation_mode === 'MANUAL').length})
          </button>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="search-wrapper" style={{ minWidth: 260 }}>
            <svg style={{ width: 14, height: 14, color: 'var(--text-muted)' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input
              className="search-input"
              placeholder="Search IP, Rule ID, attack class..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* ── Main Data Table ── */}
      <div className="table-card">
        <div className="table-card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="table-card-title">Firewall Block Rules &amp; IPS Audit Trail</span>
            <span className="badge badge-medium" style={{ fontSize: 11 }}>
              {filteredRules.length} Rules Shown
            </span>
          </div>
          <div className="live-indicator">
            <span className="pulse-dot" />
            Live Firewall Polling
          </div>
        </div>

        <div style={{ overflowX: 'auto', maxHeight: 'calc(100vh - 380px)' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Target IP</th>
                <th>Trigger Threat &amp; Score</th>
                <th>Firewall Appliance &amp; Rule</th>
                <th>Blocked At</th>
                <th>TTL Countdown</th>
                <th>Mode</th>
                <th style={{ textAlign: 'center' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map((r) => {
                const isActive = r.status === 'ACTIVE' && r.time_remaining_minutes > 0
                return (
                  <tr key={r.id}>
                    <td>
                      {isActive ? (
                        <span className="badge badge-critical" style={{ fontSize: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <span className="badge-dot" />
                          BLOCKED
                        </span>
                      ) : r.status === 'UNBLOCKED' ? (
                        <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', fontSize: 10 }}>
                          UNBLOCKED
                        </span>
                      ) : (
                        <span className="badge" style={{ background: 'rgba(100, 116, 139, 0.2)', color: '#94a3b8', fontSize: 10 }}>
                          EXPIRED
                        </span>
                      )}
                    </td>

                    <td>
                      <div className="font-mono" style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 6 }}>
                        {r.ip_address}
                        <button
                          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--text-muted)' }}
                          title="Copy IP"
                          onClick={() => {
                            navigator.clipboard.writeText(r.ip_address)
                            if (onToast) onToast(`Copied ${r.ip_address} to clipboard`)
                          }}
                        >
                          <svg style={{ width: 12, height: 12 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Interface: {r.interface}</div>
                    </td>

                    <td>
                      <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{r.threat_class.replace(/_/g, ' ')}</div>
                      <div style={{ fontSize: 11, color: r.risk_score >= 80 ? '#f43f5e' : '#f59e0b' }}>
                        Risk Score: <strong>{r.risk_score} / 100</strong>
                      </div>
                    </td>

                    <td>
                      <div style={{ fontSize: 12, color: '#cbd5e1' }}>{r.firewall_target}</div>
                      <div className="font-mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>{r.rule_id}</div>
                    </td>

                    <td className="font-mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {formatIST(r.blocked_at)}
                    </td>

                    <td>
                      {isActive ? (
                        <span className="badge-ttl">
                          <svg style={{ width: 11, height: 11 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                          {r.time_remaining_minutes}m left
                        </span>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Completed</span>
                      )}
                    </td>

                    <td>
                      {r.mitigation_mode === 'AUTOMATED' ? (
                        <span className="badge-mode-auto">⚡ AUTO</span>
                      ) : (
                        <span className="badge-mode-manual">👤 MANUAL</span>
                      )}
                    </td>

                    <td style={{ textAlign: 'center' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        {isActive && (
                          <button
                            className="btn-danger-outline"
                            title="Unblock rule on pfSense"
                            onClick={() => handleUnblock(r)}
                          >
                            Unblock
                          </button>
                        )}
                        <button
                          className="btn-neutral-outline"
                          title="View Incident Report"
                          onClick={() => handleViewReport(r)}
                        >
                          Report
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}

              {filteredRules.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-muted)' }}>
                    No mitigation rules found matching the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Modal: Manual IP Block ── */}
      {showBlockModal && (
        <div className="modal-overlay" onClick={() => setShowBlockModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Manual Firewall Block (pfSense Injection)</h3>
              <button className="modal-close-btn" onClick={() => setShowBlockModal(false)}>✕</button>
            </div>
            <form onSubmit={handleManualBlockSubmit}>
              <div className="modal-body">
                <div style={{ marginBottom: 14 }}>
                  <label className="form-label">Offender IP Address</label>
                  <input
                    className="form-input font-mono"
                    placeholder="e.g. 192.168.1.150 or 203.0.113.4"
                    required
                    value={blockForm.ip_address}
                    onChange={(e) => setBlockForm({ ...blockForm, ip_address: e.target.value })}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                  <div>
                    <label className="form-label">Firewall Interface</label>
                    <select
                      className="form-select"
                      value={blockForm.interface}
                      onChange={(e) => setBlockForm({ ...blockForm, interface: e.target.value })}
                    >
                      <option value="WAN">WAN (External)</option>
                      <option value="DMZ">DMZ Subnet</option>
                      <option value="LAN">Corporate LAN</option>
                    </select>
                  </div>
                  <div>
                    <label className="form-label">Block Duration (TTL)</label>
                    <select
                      className="form-select"
                      value={blockForm.duration_minutes}
                      onChange={(e) => setBlockForm({ ...blockForm, duration_minutes: e.target.value })}
                    >
                      <option value="15">15 Minutes (Brief)</option>
                      <option value="60">60 Minutes (Standard)</option>
                      <option value="1440">24 Hours (Prolonged)</option>
                      <option value="10080">7 Days (Severe)</option>
                    </select>
                  </div>
                </div>

                <div style={{ marginBottom: 14 }}>
                  <label className="form-label">Threat Classification</label>
                  <select
                    className="form-select"
                    value={blockForm.threat_class}
                    onChange={(e) => setBlockForm({ ...blockForm, threat_class: e.target.value })}
                  >
                    <option value="DOS_DDOS">DOS / DDOS Attack</option>
                    <option value="PORT_SCAN">Reconnaissance / Port Scan</option>
                    <option value="BRUTE_FORCE">Authentication Brute Force</option>
                    <option value="SQL_INJECTION">SQL Injection Attempt</option>
                    <option value="C2_COMMUNICATION">Command &amp; Control (C2)</option>
                    <option value="MANUAL_QUARANTINE">Host Security Quarantine</option>
                  </select>
                </div>

                <div>
                  <label className="form-label">Analyst Justification &amp; Notes</label>
                  <textarea
                    className="form-textarea"
                    rows={3}
                    placeholder="Enter context, ticketing ID, or reason for containment..."
                    value={blockForm.analyst_notes}
                    onChange={(e) => setBlockForm({ ...blockForm, analyst_notes: e.target.value })}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn-neutral-outline" onClick={() => setShowBlockModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Injecting Rule…' : 'Inject Block Rule on pfSense'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Incident Report Viewer ── */}
      {showReportModal && (
        <div className="modal-overlay" onClick={() => setShowReportModal(false)}>
          <div className="modal-card" style={{ maxWidth: 650 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Incident Mitigation Report</h3>
              <button className="modal-close-btn" onClick={() => setShowReportModal(false)}>✕</button>
            </div>
            <div className="modal-body" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
              {reportLoading ? (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading incident audit trail…</div>
              ) : selectedReport ? (
                <pre style={{
                  background: '#060a13',
                  padding: 16,
                  borderRadius: 8,
                  fontSize: 12,
                  color: '#94a3b8',
                  fontFamily: 'var(--font-mono)',
                  whiteSpace: 'pre-wrap',
                  margin: 0,
                  border: '1px solid var(--border-subtle)'
                }}>
                  {selectedReport.content}
                </pre>
              ) : (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No report data available.</div>
              )}
            </div>
            <div className="modal-footer">
              {selectedReport && (
                <button
                  type="button"
                  className="btn-neutral-outline"
                  onClick={() => {
                    navigator.clipboard.writeText(selectedReport.content)
                    if (onToast) onToast('✓ Incident report markdown copied to clipboard!')
                  }}
                >
                  Copy Markdown
                </button>
              )}
              <button type="button" className="btn-primary" onClick={() => setShowReportModal(false)}>
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

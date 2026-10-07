import { useState, useEffect, useMemo, useCallback } from 'react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie
} from 'recharts'
import './index.css'
import MitigationsPage from './MitigationsPage'
import {
  fetchAlerts,
  fetchOpenCriticalCount,
  mitigateAlert,
  updateAlertStatusApi,
  fetchMitigationStats,
  blockIpApi,
  fetchFlowEvents,
  exportAlertsToCSV,
  fetchMitigationRules,
  MITRE_MAP,
  playSocAlertSound
} from './api/client'

/* Format a UTC ISO string to IST (UTC+5:30) */
function formatIST(utcStr) {
  if (!utcStr) return '—'
  try {
    const d = new Date(utcStr.endsWith('Z') ? utcStr : utcStr + 'Z')
    return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  } catch { return utcStr }
}

function getISTTime(utcStr) {
  if (!utcStr) return ''
  try {
    const d = new Date(utcStr.endsWith('Z') ? utcStr : utcStr + 'Z')
    return d.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hour12: false })
  } catch { return '' }
}

/* ════════════════════════════════════════════════════
   ICONS  (inline SVG — no dependencies)
   ════════════════════════════════════════════════════ */
const Icon = {
  Dashboard: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  ),
  Shield: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  Lock: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
  Zap: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  ),
  Activity: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  Cpu: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" /><rect x="9" y="9" width="6" height="6" /><line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" /><line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" /><line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" /><line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" />
    </svg>
  ),
  AlertTriangle: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  TrendingUp: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" /><polyline points="17 6 23 6 23 12" />
    </svg>
  ),
  Search: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  Globe: (p) => (
    <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
}

/* ════════════════════════════════════════════════════
   SEVERITY HELPERS
   ════════════════════════════════════════════════════ */
const SEVERITY_CONFIG = {
  CRITICAL: { cls: 'badge-critical', color: '#f43f5e' },
  HIGH:     { cls: 'badge-high',     color: '#f59e0b' },
  MEDIUM:   { cls: 'badge-medium',   color: '#38bdf8' },
  LOW:      { cls: 'badge-low',      color: '#10b981' },
}

function SeverityBadge({ tier }) {
  const cfg = SEVERITY_CONFIG[tier] || SEVERITY_CONFIG.LOW
  return (
    <span className={`badge ${cfg.cls}`}>
      <span className="badge-dot" />
      {tier}
    </span>
  )
}

/* ════════════════════════════════════════════════════
   CHART TOOLTIP (custom)
   ════════════════════════════════════════════════════ */
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: 8, padding: '8px 12px', fontSize: 12
    }}>
      <div style={{ color: '#94a3b8', marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color, fontWeight: 600 }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  )
}

/* ════════════════════════════════════════════════════
   STAT CARD
   ════════════════════════════════════════════════════ */
function StatCard({ label, value, delta, deltaColor, iconBg, icon: IconComp, iconColor }) {
  return (
    <div className="stat-card">
      <div className="stat-card-content">
        <span className="stat-card-label">{label}</span>
        <span className="stat-card-value" style={{ color: iconColor || 'var(--text-primary)' }}>{value}</span>
        {delta && (
          <span className="stat-card-delta" style={{ color: deltaColor || 'var(--severity-low)' }}>
            {delta}
          </span>
        )}
      </div>
      <div className="stat-card-icon" style={{ background: iconBg }}>
        <IconComp style={{ width: 20, height: 20, color: iconColor }} />
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════════
   ALERT INVESTIGATION FORENSICS MODAL
   ════════════════════════════════════════════════════ */
function AlertInvestigationModal({ alert, onClose, onMitigate, onStatusUpdate, blockedIpSet }) {
  const [analystNote, setAnalystNote] = useState(alert?.analyst_note || '')
  const [isUpdating, setIsUpdating] = useState(false)
  const [copiedId, setCopiedId] = useState(false)

  // Close on Escape
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  if (!alert) return null

  const mitre = MITRE_MAP[alert.ai_attack_class] || {
    tactic: 'General Threat Activity',
    tacticId: 'TA0000',
    id: 'T1000',
    name: alert.ai_attack_class?.replace(/_/g, ' ') || 'Unknown Vector',
    desc: 'Unusual network payload signature flagged by Deep Packet Inspection (Suricata).',
    remediation: 'Review host access controls and block offender IP on perimeter gateway.',
  }

  const isQuarantined = blockedIpSet?.has(alert.src_ip)

  const handleCopyId = () => {
    navigator.clipboard?.writeText(alert.event_id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  const handleResolve = async (newStatus) => {
    setIsUpdating(true)
    await onStatusUpdate(alert.event_id, newStatus, analystNote)
    setIsUpdating(false)
    onClose()
  }

  return (
    <div className="investigation-modal-backdrop" onClick={onClose}>
      <div className="investigation-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="investigation-header">
          <div>
            <div className="investigation-title">
              <Icon.Shield style={{ width: 18, height: 18, color: '#818cf8' }} />
              Incident Forensics #{alert.id || alert.event_id?.slice(0, 8)}
              <SeverityBadge tier={alert.risk_tier} />
              <span className={`badge ${alert.status === 'ACKNOWLEDGED' ? 'badge-low' : alert.status === 'CLOSED' ? 'badge' : 'badge-critical'}`}>
                {alert.status}
              </span>
            </div>
            <div className="investigation-subtitle">
              <span>Event ID: <strong className="font-mono">{alert.event_id}</strong></span>
              <button
                className="btn btn-ghost"
                style={{ padding: '2px 6px', fontSize: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}
                onClick={handleCopyId}
              >
                {copiedId ? '✓ Copied' : 'Copy ID'}
              </button>
              <span>•</span>
              <span>Detected: {formatIST(alert.timestamp)}</span>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose}>&times;</button>
        </div>

        {/* Body */}
        <div className="investigation-body">
          {/* MITRE ATT&CK Card */}
          <div className="mitre-box">
            <div className="mitre-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="mitre-tag">{mitre.id}</span>
                <span className="mitre-title">{mitre.name}</span>
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa' }}>
                {mitre.tactic} ({mitre.tacticId})
              </span>
            </div>
            <div className="mitre-desc">{mitre.desc}</div>
            <div className="mitre-remediation">
              <strong>SOC Playbook Remediation:</strong> {mitre.remediation}
            </div>
          </div>

          {/* Forensic Specs Grid */}
          <div className="specs-grid">
            <div className="spec-cell">
              <div className="spec-label">Attacker (Source IP)</div>
              <div className="spec-value" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {alert.src_ip}
                {isQuarantined && (
                  <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 4, background: 'rgba(244,63,94,0.15)', color: '#f43f5e', border: '1px solid rgba(244,63,94,0.3)', fontWeight: 700 }}>
                    ⊘ QUARANTINED
                  </span>
                )}
              </div>
            </div>

            <div className="spec-cell">
              <div className="spec-label">Target (Destination IP)</div>
              <div className="spec-value">{alert.dst_ip || 'DMZ Web Server (10.0.2.80)'}</div>
            </div>

            <div className="spec-cell">
              <div className="spec-label">AI Risk Confidence</div>
              <div className="spec-value" style={{ color: alert.risk_score >= 90 ? '#f43f5e' : '#f59e0b' }}>
                {alert.risk_score}% ({alert.risk_tier})
              </div>
            </div>
          </div>

          {/* Suricata DPI Signature */}
          <div className="spec-cell" style={{ background: 'rgba(0,0,0,0.3)' }}>
            <div className="spec-label">Suricata DPI Signature Match</div>
            <div className="spec-value" style={{ color: '#e2e8f0', fontFamily: 'monospace', fontSize: 12 }}>
              {alert.suricata_signature || 'Generic anomaly detected by transformer flow inference engine'}
            </div>
          </div>

          {/* Analyst Investigation Notes */}
          <div>
            <label className="form-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Analyst Investigation Notes &amp; Audit Trail</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Persisted in PostgreSQL</span>
            </label>
            <textarea
              className="form-textarea"
              rows={3}
              placeholder="Record forensic observations, IOC verification, or containment notes..."
              value={analystNote}
              onChange={(e) => setAnalystNote(e.target.value)}
            />
          </div>
        </div>

        {/* Footer Actions */}
        <div className="analyst-action-bar">
          <div style={{ display: 'flex', gap: 8 }}>
            {alert.src_ip && (
              isQuarantined ? (
                <span className="badge badge-low" style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)', fontSize: 11, padding: '6px 12px' }}>
                  ✓ Host Quarantined on Firewall
                </span>
              ) : (
                <button
                  className="btn-block-ip critical"
                  style={{ padding: '7px 14px' }}
                  onClick={() => { onMitigate(alert); onClose(); }}
                >
                  <svg style={{ width: 12, height: 12 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                  Block IP on Firewall (60m TTL)
                </button>
              )
            )}
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            {alert.status === 'OPEN' && (
              <button
                className="btn-neutral-outline"
                style={{ fontSize: 12, padding: '7px 12px' }}
                disabled={isUpdating}
                onClick={() => handleResolve('ACKNOWLEDGED')}
              >
                ✓ Mark Acknowledged
              </button>
            )}
            <button
              className="btn-primary"
              style={{ fontSize: 12, padding: '7px 14px' }}
              disabled={isUpdating}
              onClick={() => handleResolve('CLOSED')}
            >
              {isUpdating ? 'Saving…' : 'Save Note & Close Incident'}
            </button>
            <button
              className="btn-ghost"
              style={{ fontSize: 12, padding: '7px 12px' }}
              onClick={onClose}
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ════════════════════════════════════════════════════
   DASHBOARD PAGE
   ════════════════════════════════════════════════════ */
function DashboardPage({ alerts, onMitigate, onNavigate, mitigationStats, blockedIpSet, onSelectAlert, audioEnabled, onToggleAudio }) {
  const stats = useMemo(() => {
    const total = alerts.length
    const critical = alerts.filter(a => a.risk_tier === 'CRITICAL').length
    const high = alerts.filter(a => a.risk_tier === 'HIGH').length
    const uniqueIPs = new Set(alerts.map(a => a.src_ip).filter(ip => ip && ip !== '—')).size
    return { total, critical, high, uniqueIPs }
  }, [alerts])

  // Top Adversary Malicious Source IPs
  const topAdversaries = useMemo(() => {
    const map = {}
    alerts.forEach(a => {
      if (!a.src_ip || a.src_ip === '—') return
      if (!map[a.src_ip]) {
        map[a.src_ip] = {
          ip: a.src_ip,
          count: 0,
          highestTier: 'LOW',
          topAttack: a.ai_attack_class || 'UNKNOWN',
          sampleAlert: a
        }
      }
      map[a.src_ip].count += 1
      if (a.risk_tier === 'CRITICAL') map[a.src_ip].highestTier = 'CRITICAL'
      else if (a.risk_tier === 'HIGH' && map[a.src_ip].highestTier !== 'CRITICAL') map[a.src_ip].highestTier = 'HIGH'
    })
    return Object.values(map)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
  }, [alerts])

  // DEFCON Posture Assessment
  const posture = useMemo(() => {
    const openCrit = alerts.filter(a => a.risk_tier === 'CRITICAL' && a.status === 'OPEN').length
    const totalOffenders = topAdversaries.length || 1
    const containedOffenders = topAdversaries.filter(adv => blockedIpSet?.has(adv.ip)).length
    const containmentPct = Math.min(100, Math.round((containedOffenders / totalOffenders) * 100))

    if (openCrit >= 10) {
      return {
        level: 'DEFCON 1',
        cls: 'defcon-1',
        tagCls: 'crit',
        title: 'CRITICAL INTRUSION CAMPAIGN ACTIVE',
        desc: `${openCrit} Unmitigated critical threat payloads detected. Host Netfilter and pfSense perimeter active.`,
        containmentPct
      }
    } else if (openCrit > 0) {
      return {
        level: 'DEFCON 2',
        cls: 'defcon-2',
        tagCls: 'warn',
        title: 'ELEVATED THREAT DETECTED — TRIAGE REQUIRED',
        desc: `${openCrit} Critical alert(s) pending analyst review. Rapid quarantine available.`,
        containmentPct
      }
    } else {
      return {
        level: 'DEFCON 5',
        cls: 'defcon-5',
        tagCls: 'ok',
        title: 'PERIMETER DEFENSE SECURE & CONTAINED',
        desc: `All detected threat incidents acknowledged or blackholed at firewall gateway.`,
        containmentPct: 100
      }
    }
  }, [alerts, blockedIpSet, topAdversaries])

  // Attack class distribution
  const distribution = useMemo(() => {
    const counts = {}
    alerts.forEach(a => {
      const cls = a.ai_attack_class || 'UNKNOWN'
      counts[cls] = (counts[cls] || 0) + 1
    })
    const colors = {
      PORT_SCAN: '#f43f5e', BENIGN: '#10b981', MALWARE: '#f59e0b',
      C2_COMMUNICATION: '#8b5cf6', DATA_EXFILTRATION: '#ec4899',
      BRUTE_FORCE: '#f97316', SQL_INJECTION: '#06b6d4', DNS_TUNNELING: '#3b82f6',
      HTTP_EXPLOIT: '#eab308', DOS_DDOS: '#ef4444', UNKNOWN: '#64748b',
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([name, value]) => ({ name: name.replace(/_/g, ' '), value, color: colors[name] || '#64748b' }))
  }, [alerts])

  // Timeline — group by minute
  const timeline = useMemo(() => {
    const buckets = {}
    alerts.forEach(a => {
      if (!a.timestamp) return
      const minute = getISTTime(a.timestamp) // HH:MM in IST
      if (!minute) return
      buckets[minute] = (buckets[minute] || 0) + 1
    })
    return Object.entries(buckets)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(-20)
      .map(([time, count]) => ({ time, alerts: count }))
  }, [alerts])

  const maxDist = distribution.length ? Math.max(...distribution.map(d => d.value)) : 1

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1>Enterprise SOC Dashboard</h1>
          <p>Real-time overview of your network security posture and autonomous defense loop</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', paddingTop: 4 }}>
          <button
            className={`btn-soc-audio ${audioEnabled ? 'active' : ''}`}
            onClick={onToggleAudio}
            title={audioEnabled ? 'Mute SOC siren sound' : 'Enable audio alarm on critical threats'}
          >
            {audioEnabled ? '🔊 Siren: ON' : '🔇 Siren: OFF'}
          </button>
        </div>
      </div>

      <div className="page-body">
        {/* ── DEFCON Posture Banner ── */}
        <div className={`posture-banner ${posture.cls}`}>
          <div className="posture-left">
            <span className={`defcon-tag ${posture.tagCls}`}>
              <span className="pulse-dot" style={{ width: 7, height: 7 }} />
              {posture.level}
            </span>
            <div>
              <div className="posture-headline">
                {posture.title}
              </div>
              <div className="posture-desc">{posture.desc}</div>
            </div>
          </div>
          <div className="posture-actions">
            <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Adversary Containment</span>
              <strong style={{ fontSize: 14, color: posture.containmentPct >= 80 ? '#10b981' : '#f59e0b', fontFamily: 'monospace' }}>
                {posture.containmentPct}% Quarantined
              </strong>
            </div>
            {stats.critical > 0 && (
              <button
                className="btn-primary"
                style={{ fontSize: 11, padding: '7px 12px' }}
                onClick={() => onNavigate && onNavigate('alerts')}
              >
                Triage Threats &rarr;
              </button>
            )}
          </div>
        </div>

        {/* ── Stat Cards ── */}
        <div className="stats-grid">
          <StatCard
            label="Total Threat Events"
            value={stats.total}
            delta="Live stream active"
            deltaColor="var(--severity-low)"
            iconBg="rgba(99, 102, 241, 0.1)"
            icon={Icon.Activity}
            iconColor="#818cf8"
          />
          <StatCard
            label="Critical Threats"
            value={stats.critical}
            delta={stats.critical > 0 ? "Requires investigation" : "All clean"}
            deltaColor={stats.critical > 0 ? "var(--severity-critical)" : "var(--severity-low)"}
            iconBg="rgba(244, 63, 94, 0.1)"
            icon={Icon.AlertTriangle}
            iconColor="#f43f5e"
          />
          <StatCard
            label="High Severity"
            value={stats.high}
            delta="Elevated risk"
            deltaColor="var(--severity-high)"
            iconBg="rgba(245, 158, 11, 0.1)"
            icon={Icon.Shield}
            iconColor="#f59e0b"
          />
          <StatCard
            label="Unique Attackers"
            value={stats.uniqueIPs}
            delta={`${mitigationStats?.active_blocks ?? 0} actively blocked`}
            deltaColor="var(--text-muted)"
            iconBg="rgba(56, 189, 248, 0.1)"
            icon={Icon.Globe}
            iconColor="#38bdf8"
          />
        </div>

        {/* ── Charts Row ── */}
        <div className="charts-grid">
          {/* Timeline Chart */}
          <div className="chart-card">
            <div className="chart-card-header">
              <div>
                <div className="chart-card-title">Threat Velocity Timeline</div>
                <div className="chart-card-subtitle">Events per minute in IST</div>
              </div>
              <div className="live-indicator">
                <span className="pulse-dot" />
                Live
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline} margin={{ top: 5, right: 5, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="alerts" stroke="#6366f1" strokeWidth={2} fill="url(#alertGrad)" name="Alerts" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Attack Distribution */}
          <div className="chart-card">
            <div className="chart-card-header">
              <div>
                <div className="chart-card-title">Attack Class Distribution</div>
                <div className="chart-card-subtitle">By AI classification engine</div>
              </div>
            </div>
            {distribution.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '40px 0', textAlign: 'center' }}>No data yet</div>
            ) : (
              <ul className="distribution-list">
                {distribution.slice(0, 6).map((d) => (
                  <li key={d.name} className="distribution-item">
                    <span className="distribution-dot" style={{ background: d.color }} />
                    <span className="distribution-label">{d.name}</span>
                    <span className="distribution-value">{d.value}</span>
                    <div className="distribution-bar-track" style={{ maxWidth: 80 }}>
                      <div className="distribution-bar-fill" style={{ width: `${(d.value / maxDist) * 100}%`, background: d.color }} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* ── Top Adversaries & Active Firewall Row ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          {/* Top Adversaries */}
          <div className="adversary-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>Top Threat Adversaries</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Ranked by incident frequency</div>
              </div>
              <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', fontSize: 11 }}>
                {topAdversaries.length} Offender Subnets
              </span>
            </div>

            {topAdversaries.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '24px 0', textAlign: 'center' }}>
                No hostile source IPs identified yet
              </div>
            ) : (
              <div>
                {topAdversaries.map(adv => {
                  const isBlocked = blockedIpSet?.has(adv.ip)
                  return (
                    <div key={adv.ip} className="adversary-row">
                      <div className="adversary-info">
                        <span className="adversary-ip">{adv.ip}</span>
                        {isBlocked ? (
                          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 4, background: 'rgba(244, 63, 94, 0.15)', color: '#f43f5e', fontWeight: 700, border: '1px solid rgba(244, 63, 94, 0.3)' }}>
                            ⊘ QUARANTINED
                          </span>
                        ) : (
                          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 4, background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', fontWeight: 700, border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                            ⚠️ ACTIVE
                          </span>
                        )}
                        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                          {adv.topAttack.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 700, fontFamily: 'monospace', color: '#818cf8' }}>
                          {adv.count} hits
                        </span>
                        {!isBlocked ? (
                          <button
                            className="btn-block-ip critical"
                            style={{ fontSize: 10, padding: '3px 8px' }}
                            onClick={() => onMitigate(adv.sampleAlert)}
                            title={`Drop ${adv.ip} on pfSense firewall`}
                          >
                            Block IP
                          </button>
                        ) : (
                          <button
                            className="btn btn-ghost"
                            style={{ fontSize: 10, padding: '3px 6px' }}
                            onClick={() => onSelectAlert && onSelectAlert(adv.sampleAlert)}
                          >
                            Inspect
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Active Firewall & IPS Status */}
          <div className="table-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div className="table-card-header">
              <span className="table-card-title">Firewall &amp; Host IPS State</span>
              <div className="live-indicator"><span className="pulse-dot" />pfSense Plus</div>
            </div>
            <div style={{ padding: '0 20px 20px', flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span className="firewall-pulse-dot" />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                    Host Netfilter (iptables) &bull; pfSense WAN ({mitigationStats?.firewall?.host || '192.168.1.1'})
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Active Hardware Microsegmentation &bull; Real-time Redis Rule Bus
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                <div className="spec-cell">
                  <div className="spec-label">Active Drop Rules</div>
                  <div className="spec-value" style={{ color: '#f43f5e' }}>{mitigationStats?.active_blocks ?? 0} rules</div>
                </div>
                <div className="spec-cell">
                  <div className="spec-label">Quarantine TTL</div>
                  <div className="spec-value">60 Minutes</div>
                </div>
                <div className="spec-cell">
                  <div className="spec-label">Default Policy</div>
                  <div className="spec-value" style={{ color: '#10b981' }}>Stateful Inspect</div>
                </div>
              </div>

              <button
                className="btn-primary"
                style={{ fontSize: 12, padding: '8px 16px', alignSelf: 'flex-start', marginTop: 4 }}
                onClick={() => onNavigate && onNavigate('mitigations')}
              >
                Open Firewall Rules Manager &rarr;
              </button>
            </div>
          </div>
        </div>

        {/* ── Recent Alerts mini-table ── */}
        <div className="table-card">
          <div className="table-card-header">
            <span className="table-card-title">Recent Threat Events</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Click row for deep investigation</span>
              <div className="live-indicator">
                <span className="pulse-dot" />
                Polling every 3s
              </div>
            </div>
          </div>
          <div style={{ overflowX: 'auto', maxHeight: 320 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Classification &amp; MITRE</th>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th style={{ textAlign: 'center' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 8).map((a) => {
                  const mitre = MITRE_MAP[a.ai_attack_class]
                  return (
                    <tr
                      key={a.event_id}
                      className="clickable-row"
                      onClick={() => onSelectAlert && onSelectAlert(a)}
                    >
                      <td className="font-mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {formatIST(a.timestamp)}
                      </td>
                      <td><SeverityBadge tier={a.risk_tier} /></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="attack-name">{a.ai_attack_class?.replace(/_/g, ' ')}</span>
                          {mitre && (
                            <span className="mitre-tag" style={{ fontSize: 9, padding: '1px 5px' }}>
                              {mitre.id.split(' ')[0]}
                            </span>
                          )}
                        </div>
                        {a.suricata_signature && <div className="attack-signature">{a.suricata_signature}</div>}
                      </td>
                      <td className="font-mono" style={{ fontSize: 12 }}>
                        {a.src_ip}
                        {blockedIpSet?.has(a.src_ip) && (
                          <span
                            style={{
                              marginLeft: 6,
                              fontSize: 9,
                              padding: '1px 5px',
                              borderRadius: 4,
                              background: 'rgba(244, 63, 94, 0.15)',
                              color: '#f43f5e',
                              fontWeight: 700,
                              border: '1px solid rgba(244, 63, 94, 0.3)'
                            }}
                            title="Host is actively dropped by pfSense & Host-IPS"
                          >
                            ⊘ QUARANTINED
                          </span>
                        )}
                      </td>
                      <td className="font-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>{a.dst_ip || '—'}</td>
                      <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                        {a.status === "ACKNOWLEDGED" ? (
                          blockedIpSet?.has(a.src_ip) ? (
                            <span className="badge badge-low" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)', fontSize: 11, padding: '3px 8px' }}>
                              ✓ Blocked
                            </span>
                          ) : (
                            <button
                              className={`btn-block-ip ${a.risk_tier === "CRITICAL" ? 'critical' : ''}`}
                              onClick={() => onMitigate(a)}
                              title={a.src_ip ? `Re-block ${a.src_ip} on pfSense firewall (60m TTL)` : 'Acknowledge threat'}
                            >
                              <svg style={{ width: 10, height: 10 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                              {a.src_ip ? 'Block IP' : 'Acknowledge'}
                            </button>
                          )
                        ) : blockedIpSet?.has(a.src_ip) ? (
                          <button
                            className="btn-neutral-outline"
                            style={{ fontSize: 11, padding: '4px 10px', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                            onClick={() => onMitigate(a)}
                            title="IP already dropped by firewall. Click to acknowledge event."
                          >
                            ✓ Quarantined (Ack)
                          </button>
                        ) : (
                          <button
                            className={`btn-block-ip ${a.risk_tier === "CRITICAL" ? 'critical' : ''}`}
                            onClick={() => onMitigate(a)}
                            title={a.src_ip ? `Drop ${a.src_ip} on pfSense firewall (60m TTL)` : 'Acknowledge threat'}
                          >
                            <svg style={{ width: 10, height: 10 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                            {a.src_ip ? 'Block IP' : 'Acknowledge'}
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
                {alerts.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Waiting for events…</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}

/* ════════════════════════════════════════════════════
   NETWORK FLOWS PAGE
   ════════════════════════════════════════════════════ */
const PROTOCOL_COLORS = {
  TCP: '#6366f1', UDP: '#38bdf8', DNS: '#10b981',
  HTTP: '#f59e0b', HTTPS: '#8b5cf6', ICMP: '#f43f5e', OTHER: '#64748b',
}

const SAMPLE_FLOWS = [
  { id: 1, src: '192.168.1.45', dst: '10.0.0.1',   sport: 54213, dport: 80,   proto: 'HTTP',  bytes: 12450, pkts: 23,  dur: '0.8s',   status: 'ACTIVE'  },
  { id: 2, src: '192.168.1.12', dst: '8.8.8.8',    sport: 52100, dport: 53,   proto: 'DNS',   bytes: 340,   pkts: 2,   dur: '0.02s',  status: 'CLOSED'  },
  { id: 3, src: '10.0.0.200',   dst: '192.168.1.5', sport: 443,   dport: 51200, proto: 'HTTPS', bytes: 85200, pkts: 142, dur: '12.4s',  status: 'ACTIVE'  },
  { id: 4, src: '192.168.1.88', dst: '172.16.0.1', sport: 60001, dport: 22,   proto: 'TCP',   bytes: 4200,  pkts: 18,  dur: '3.1s',   status: 'FLAGGED' },
  { id: 5, src: '10.0.0.50',    dst: '10.0.0.1',   sport: 58432, dport: 443,  proto: 'HTTPS', bytes: 22100, pkts: 56,  dur: '5.6s',   status: 'ACTIVE'  },
  { id: 6, src: '192.168.1.90', dst: '1.1.1.1',    sport: 53001, dport: 53,   proto: 'DNS',   bytes: 512,   pkts: 4,   dur: '0.03s',  status: 'CLOSED'  },
  { id: 7, src: '192.168.1.45', dst: '10.0.0.5',   sport: 49800, dport: 3306, proto: 'TCP',   bytes: 980,   pkts: 7,   dur: '0.4s',   status: 'FLAGGED' },
  { id: 8, src: '172.16.0.10',  dst: '192.168.1.2', sport: 443,  dport: 58100, proto: 'HTTPS', bytes: 62400, pkts: 98,  dur: '9.2s',   status: 'ACTIVE'  },
]

const FLOW_TIMELINE = Array.from({ length: 20 }, (_, i) => ({
  time: `${String(Math.floor(i / 2 + 10)).padStart(2, '0')}:${i % 2 === 0 ? '00' : '30'}`,
  TCP: Math.floor(Math.random() * 80 + 20),
  UDP: Math.floor(Math.random() * 40 + 5),
  DNS: Math.floor(Math.random() * 20 + 2),
}))

function NetworkFlowsPage() {
  const [protoFilter, setProtoFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [liveFlows, setLiveFlows] = useState([])

  useEffect(() => {
    let isMounted = true
    const loadFlows = async () => {
      try {
        const data = await fetchFlowEvents(100)
        if (isMounted && data.flows && data.flows.length > 0) {
          setLiveFlows(data.flows)
        }
      } catch {}
    }
    loadFlows()
    const id = setInterval(() => {
      if (document.hidden) return
      loadFlows()
    }, 3000)
    return () => {
      isMounted = false
      clearInterval(id)
    }
  }, [])

  const currentFlows = liveFlows.length > 0 ? liveFlows : SAMPLE_FLOWS
  const totalBytes = currentFlows.reduce((s, f) => s + (f.bytes || 0), 0)
  const activeFlows = currentFlows.filter(f => f.status === 'ACTIVE').length
  const flaggedFlows = currentFlows.filter(f => f.status === 'FLAGGED').length

  const protoDist = useMemo(() => {
    const counts = {}
    currentFlows.forEach(f => {
      const p = (f.proto || 'TCP').toUpperCase()
      counts[p] = (counts[p] || 0) + (f.bytes || 512)
    })
    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
      color: PROTOCOL_COLORS[name] || '#64748b'
    }))
  }, [currentFlows])

  const flowTimeline = useMemo(() => {
    const buckets = {}
    currentFlows.forEach(f => {
      if (!f.timestamp) return
      const t = getISTTime(f.timestamp)
      if (!t) return
      if (!buckets[t]) {
        buckets[t] = { time: t, TCP: 0, UDP: 0, DNS: 0, HTTP: 0, HTTPS: 0, TOTAL: 0 }
      }
      const p = (f.proto || 'TCP').toUpperCase()
      if (buckets[t][p] !== undefined) {
        buckets[t][p] += (f.pkts || 1)
      }
      buckets[t].TOTAL += (f.pkts || 1)
    })
    const list = Object.values(buckets).sort((a, b) => a.time.localeCompare(b.time)).slice(-20)
    return list.length > 0 ? list : FLOW_TIMELINE
  }, [currentFlows])

  const displayed = currentFlows.filter(f =>
    (protoFilter === 'ALL' || f.proto === protoFilter) &&
    (statusFilter === 'ALL' || f.status === statusFilter)
  )

  const fmtBytes = (b) => b >= 1024 ? `${(b / 1024).toFixed(1)} KB` : `${b} B`

  return (
    <>
      <div className="page-header">
        <h1>Network Flows</h1>
        <p>Live bidirectional flow table with protocol breakdown and anomaly flags</p>
      </div>

      <div className="page-body">
        {/* ── Stat Cards ── */}
        <div className="stats-grid">
          <StatCard label="Active Flows"   value={activeFlows}          delta="Currently tracking"         deltaColor="var(--severity-low)"      iconBg="rgba(99,102,241,0.1)"   icon={Icon.Activity}       iconColor="#818cf8" />
          <StatCard label="Flagged Flows"  value={flaggedFlows}         delta={flaggedFlows > 0 ? "Threats detected" : "All clean"} deltaColor={flaggedFlows > 0 ? "var(--severity-critical)" : "var(--severity-low)"} iconBg="rgba(244,63,94,0.1)" icon={Icon.AlertTriangle} iconColor="#f43f5e" />
          <StatCard label="Total Bytes"    value={fmtBytes(totalBytes)} delta="Session total"              deltaColor="var(--text-muted)"         iconBg="rgba(56,189,248,0.1)"   icon={Icon.TrendingUp}     iconColor="#38bdf8" />
          <StatCard label="Protocols"      value={protoDist.length}     delta="Active protocol types"      deltaColor="var(--text-muted)"         iconBg="rgba(139,92,246,0.1)" icon={Icon.Globe}          iconColor="#8b5cf6" />
        </div>

        {/* ── Charts ── */}
        <div className="charts-grid">
          {/* Flow volume timeline */}
          <div className="chart-card">
            <div className="chart-card-header">
              <div>
                <div className="chart-card-title">Flow Volume Timeline</div>
                <div className="chart-card-subtitle">Packets/s by protocol</div>
              </div>
              <div className="live-indicator"><span className="pulse-dot" />Live</div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={flowTimeline} margin={{ top: 5, right: 5, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="tcpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6366f1" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="udpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="TCP" stroke="#6366f1" strokeWidth={2} fill="url(#tcpGrad)" name="TCP" />
                <Area type="monotone" dataKey="UDP" stroke="#38bdf8" strokeWidth={2} fill="url(#udpGrad)" name="UDP" />
                <Area type="monotone" dataKey="DNS" stroke="#10b981" strokeWidth={1.5} fill="none" name="DNS" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Protocol distribution */}
          <div className="chart-card">
            <div className="chart-card-header">
              <div>
                <div className="chart-card-title">Protocol Mix</div>
                <div className="chart-card-subtitle">By total bytes transferred</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <ResponsiveContainer width={140} height={140}>
                <PieChart>
                  <Pie data={protoDist} cx="50%" cy="50%" innerRadius={38} outerRadius={58} dataKey="value" paddingAngle={3}>
                    {protoDist.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <ul className="distribution-list" style={{ flex: 1 }}>
                {protoDist.map(d => (
                  <li key={d.name} className="distribution-item">
                    <span className="distribution-dot" style={{ background: d.color }} />
                    <span className="distribution-label">{d.name}</span>
                    <span className="distribution-value">{fmtBytes(d.value)}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* ── Flow Table ── */}
        <div className="table-card">
          <div className="table-card-header">
            <span className="table-card-title">Live Flow Table</span>
            <div style={{ display: 'flex', gap: 8 }}>
              {['ALL', 'TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS'].map(p => (
                <button
                  key={p}
                  className={`btn btn-ghost`}
                  style={{ padding: '4px 10px', fontSize: 11, background: protoFilter === p ? 'rgba(99,102,241,0.2)' : '', color: protoFilter === p ? '#818cf8' : '' }}
                  onClick={() => setProtoFilter(p)}
                >{p}</button>
              ))}
              <div style={{ width: 1, background: 'rgba(255,255,255,0.08)', margin: '0 4px' }} />
              {['ALL', 'ACTIVE', 'FLAGGED', 'CLOSED'].map(s => (
                <button
                  key={s}
                  className="btn btn-ghost"
                  style={{ padding: '4px 10px', fontSize: 11, background: statusFilter === s ? 'rgba(244,63,94,0.15)' : '', color: statusFilter === s ? '#f43f5e' : '' }}
                  onClick={() => setStatusFilter(s)}
                >{s}</button>
              ))}
            </div>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Source IP : Port</th>
                  <th>Destination IP : Port</th>
                  <th>Protocol</th>
                  <th>Bytes</th>
                  <th>Packets</th>
                  <th>Duration</th>
                  <th style={{ textAlign: 'center' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {displayed.map(f => (
                  <tr key={f.id}>
                    <td className="font-mono" style={{ fontSize: 12 }}>{f.src}<span style={{ color: 'var(--text-muted)' }}>:{f.sport}</span></td>
                    <td className="font-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>{f.dst}<span>:{f.dport}</span></td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600, color: PROTOCOL_COLORS[f.proto] || '#64748b' }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: PROTOCOL_COLORS[f.proto] || '#64748b', display: 'inline-block' }} />
                        {f.proto}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>{fmtBytes(f.bytes)}</td>
                    <td style={{ fontSize: 12 }}>{f.pkts}</td>
                    <td className="font-mono" style={{ fontSize: 12 }}>{f.dur}</td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={`badge ${f.status === 'FLAGGED' ? 'badge-critical' : f.status === 'ACTIVE' ? 'badge-low' : 'badge-medium'}`}>
                        <span className="badge-dot" />
                        {f.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="table-footer">
            <span>Showing {displayed.length} flows</span>
            <div className="live-indicator"><span className="pulse-dot" />Live capture</div>
          </div>
        </div>
      </div>
    </>
  )
}

/* ════════════════════════════════════════════════════
   AI MODELS PAGE
   ════════════════════════════════════════════════════ */
// Real classification results — CSE-CIC-IDS2018 balanced test (9,200 flows)
const MODEL_METRICS = [
  { cls: 'MALWARE',          precision: 99.9, recall: 98.9, f1: 99.4, color: '#8b5cf6' },
  { cls: 'DOS / DDOS',       precision: 96.7, recall: 95.9, f1: 96.3, color: '#f43f5e' },
  { cls: 'HTTP EXPLOIT',     precision: 99.6, recall: 47.8, f1: 64.6, color: '#eab308' },
  { cls: 'BENIGN',           precision: 96.0, recall: 62.7, f1: 75.9, color: '#10b981' },
  { cls: 'BRUTE FORCE',      precision: 72.8, recall: 99.2, f1: 84.0, color: '#f59e0b' },
  { cls: 'SQL INJECTION',    precision: 65.7, recall: 100.0, f1: 79.3, color: '#06b6d4' },
]

const TRAINING_HISTORY = [
  { epoch: 1, loss: 1.62, acc: 65 },
  { epoch: 2, loss: 1.18, acc: 76 },
  { epoch: 3, loss: 0.83, acc: 84 },
  { epoch: 4, loss: 0.59, acc: 87 },
  { epoch: 5, loss: 0.44, acc: 89 },
  { epoch: 6, loss: 0.32, acc: 91 },
]

function MetricBar({ value, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${value}%`, background: color, borderRadius: 3, transition: 'width 0.8s ease' }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 600, color, minWidth: 38, textAlign: 'right' }}>{value.toFixed(1)}%</span>
    </div>
  )
}

function AIModelsPage() {
  const [activeTab, setActiveTab] = useState('metrics')

  return (
    <>
      <div className="page-header">
        <h1>AI Models</h1>
        <p>Transformer encoder performance, training history, and ONNX model details</p>
      </div>

      <div className="page-body">
        {/* ── Model Info Cards ── */}
        <div className="stats-grid">
          <StatCard label="Overall Accuracy" value="87.2%"    delta="CSE-CIC-IDS2018 balanced test"  deltaColor="var(--severity-low)"  iconBg="rgba(99,102,241,0.1)"  icon={Icon.TrendingUp}     iconColor="#818cf8" />
          <StatCard label="Model Type"        value="Transformer" delta="Encoder + Classifier head" deltaColor="var(--text-muted)" iconBg="rgba(56,189,248,0.1)"  icon={Icon.Cpu}            iconColor="#38bdf8" />
          <StatCard label="Attack Classes"    value="6"       delta="Multi-class classification"    deltaColor="var(--text-muted)" iconBg="rgba(139,92,246,0.1)"  icon={Icon.Shield}         iconColor="#8b5cf6" />
          <StatCard label="Runtime"           value="ONNX"    delta="opset_version=18, sub-ms"      deltaColor="var(--severity-low)" iconBg="rgba(16,185,129,0.1)" icon={Icon.Activity}       iconColor="#10b981" />
        </div>

        {/* ── Architecture box ── */}
        <div className="chart-card" style={{ marginBottom: 0 }}>
          <div className="chart-card-header">
            <div>
              <div className="chart-card-title">Model Architecture</div>
              <div className="chart-card-subtitle">NetworkTransformerClassifier — CSE-CIC-IDS2018 · PyTorch → ONNX</div>
            </div>
            <span className="badge badge-low" style={{ fontSize: 11 }}><span className="badge-dot" />Deployed</span>
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', padding: '4px 0 8px' }}>
            {[
              { label: 'Input Dimension', value: '14 flow features' },
              { label: 'Embedding (d_model)', value: '64' },
              { label: 'Attention Heads', value: '4 (nhead=4)' },
              { label: 'Encoder Layers', value: '3 stacked' },
              { label: 'FFN Dimension', value: '256 (d_model × 4)' },
              { label: 'Dropout', value: '0.10' },
              { label: 'Dataset', value: 'CSE-CIC-IDS2018' },
              { label: 'Optimizer', value: 'AdamW lr=0.001' },
              { label: 'Loss Function', value: 'Weighted CrossEntropy' },
              { label: 'Export Format', value: 'ONNX opset 18' },
            ].map(p => (
              <div key={p.label} style={{
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 8, padding: '8px 14px', minWidth: 160,
              }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>{p.label}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{p.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Tabs ── */}
        <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: 0 }}>
          {[['metrics', 'Per-Class Metrics'], ['training', 'Training History']].map(([id, label]) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer', padding: '10px 18px',
                fontSize: 13, fontWeight: 600,
                color: activeTab === id ? '#818cf8' : 'var(--text-muted)',
                borderBottom: activeTab === id ? '2px solid #818cf8' : '2px solid transparent',
                marginBottom: -1,
              }}
            >{label}</button>
          ))}
        </div>

        {activeTab === 'metrics' && (
          <div className="table-card">
            <div className="table-card-header">
              <span className="table-card-title">Classification Report — Balanced Test Set</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>CSE-CIC-IDS2018 · 9,200 test flows · 6 attack classes</span>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Attack Class</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1-Score</th>
                  <th style={{ minWidth: 140 }}>F1 Visual</th>
                </tr>
              </thead>
              <tbody>
                {MODEL_METRICS.map(m => (
                  <tr key={m.cls}>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ width: 8, height: 8, borderRadius: '50%', background: m.color, display: 'inline-block' }} />
                        <span style={{ fontWeight: 600, fontSize: 13 }}>{m.cls}</span>
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 13, color: m.precision > 90 ? '#10b981' : m.precision > 75 ? '#f59e0b' : '#f43f5e' }}>{m.precision.toFixed(1)}%</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 13, color: m.recall > 90 ? '#10b981' : m.recall > 65 ? '#f59e0b' : '#f43f5e' }}>{m.recall.toFixed(1)}%</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: m.color }}>{m.f1.toFixed(1)}%</td>
                    <td style={{ minWidth: 140 }}><MetricBar value={m.f1} color={m.color} /></td>
                  </tr>
                ))}
                <tr style={{ borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                  <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>MACRO AVG</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#10b981' }}>88.5%</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#10b981' }}>84.1%</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#10b981' }}>83.3%</td>
                  <td><MetricBar value={83.3} color="#10b981" /></td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>WEIGHTED AVG</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#818cf8' }}>90.2%</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#818cf8' }}>87.2%</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: '#818cf8' }}>86.7%</td>
                  <td><MetricBar value={86.7} color="#818cf8" /></td>
                </tr>
              </tbody>
            </table>
            <div className="table-footer">
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                HTTP Exploit precision is 99.6% — recall is lower because XSS flows have near-identical flow stats to benign HTTPS.
                Payload-level detection (Suricata DPI) is the primary layer for these as per the Detection Responsibility Matrix.
              </span>
            </div>
          </div>
        )}

        {activeTab === 'training' && (
          <div className="chart-card">
            <div className="chart-card-header">
              <div>
                <div className="chart-card-title">Training Loss &amp; Accuracy</div>
                <div className="chart-card-subtitle">6 epochs — AdamW lr=0.001 · Weighted CrossEntropy · Google Colab T4 GPU · CSE-CIC-IDS2018</div>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={TRAINING_HISTORY} margin={{ top: 5, right: 20, bottom: 0, left: -10 }}>
                <defs>
                  <linearGradient id="accGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0.4} />
                  </linearGradient>
                  <linearGradient id="lossGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#f43f5e" stopOpacity={0.4} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="epoch" tickFormatter={e => `Ep ${e}`} tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis yAxisId="acc" orientation="right" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} tickFormatter={v => `${v}%`} domain={[50, 100]} />
                <YAxis yAxisId="loss" orientation="left" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} domain={[0, 2.5]} />
                <Tooltip content={<ChartTooltip />} />
                <Bar yAxisId="loss" dataKey="loss" name="Train Loss" fill="url(#lossGrad)" radius={[4,4,0,0]} />
                <Bar yAxisId="acc" dataKey="acc" name="Train Acc %" fill="url(#accGrad)" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>

            {/* Epoch breakdown table */}
            <table className="data-table" style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th>Epoch</th>
                  <th>Train Loss</th>
                  <th>Train Accuracy</th>
                  <th style={{ minWidth: 140 }}>Accuracy</th>
                </tr>
              </thead>
              <tbody>
                {TRAINING_HISTORY.map(h => (
                  <tr key={h.epoch}>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{h.epoch} / 6</td>
                    <td style={{ fontFamily: 'monospace', color: h.loss < 0.5 ? '#10b981' : '#f59e0b' }}>{h.loss.toFixed(2)}</td>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600, color: '#818cf8' }}>{h.acc}%</td>
                    <td><MetricBar value={h.acc} color="#818cf8" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

/* ════════════════════════════════════════════════════
   ALERTS PAGE
   ════════════════════════════════════════════════════ */
function AlertsPage({ alerts, onMitigate, blockedIpSet, onSelectAlert }) {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL') // 'ALL' | 'OPEN' | 'ACKNOWLEDGED' | 'CLOSED'
  const [severityFilter, setSeverityFilter] = useState('ALL') // 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  const [timeFilter, setTimeFilter] = useState('ALL') // 'ALL' | '1h' | '6h' | '24h'
  const [currentTime, setCurrentTime] = useState(() => Date.now())

  const handleTimeFilter = useCallback((tw) => {
    setTimeFilter(tw)
    setCurrentTime(Date.now())
  }, [])

  const filtered = useMemo(() => {
    let list = alerts
    if (statusFilter !== 'ALL') {
      list = list.filter(a => a.status === statusFilter)
    }
    if (severityFilter !== 'ALL') {
      list = list.filter(a => a.risk_tier === severityFilter)
    }
    if (timeFilter !== 'ALL') {
      const hours = timeFilter === '1h' ? 1 : timeFilter === '6h' ? 6 : 24
      const cutoff = currentTime - hours * 60 * 60 * 1000
      list = list.filter(a => {
        if (!a.timestamp) return true
        const t = new Date(a.timestamp.endsWith('Z') ? a.timestamp : a.timestamp + 'Z').getTime()
        return isNaN(t) || t >= cutoff
      })
    }
    if (!search.trim()) return list
    const q = search.toLowerCase()
    return list.filter(a =>
      a.ai_attack_class?.toLowerCase().includes(q) ||
      a.src_ip?.includes(q) ||
      a.suricata_signature?.toLowerCase().includes(q) ||
      a.risk_tier?.toLowerCase().includes(q)
    )
  }, [alerts, search, statusFilter, severityFilter, timeFilter, currentTime])

  const criticalCount = alerts.filter(a => a.risk_tier === 'CRITICAL' && a.status === 'OPEN').length
  const openCount = alerts.filter(a => a.status === 'OPEN').length
  const mitigatedCount = alerts.filter(a => a.status === 'ACKNOWLEDGED').length
  const closedCount = alerts.filter(a => a.status === 'CLOSED').length

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1>Threat Alerts &amp; Incident Records</h1>
          <p>Durable security threat records persisted in PostgreSQL with MITRE ATT&amp;CK context — click any row for deep forensic inspection</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', paddingTop: 4 }}>
          <div className="search-wrapper">
            <Icon.Search />
            <input
              className="search-input"
              placeholder="Search attacks, IPs, signatures, MITRE…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button
            className="btn btn-ghost"
            onClick={() => exportAlertsToCSV(filtered)}
            title="Export filtered threats to CSV audit trail"
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <svg style={{ width: 13, height: 13 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export CSV
          </button>
        </div>
      </div>

      <div className="page-body">
        <div className="table-card">
          <div className="table-card-header" style={{ flexDirection: 'column', gap: 12, alignItems: 'stretch' }}>
            {/* Filter Bar Row 1: Status & Live indicator */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Status:</span>
                <div style={{ display: 'flex', gap: 4 }}>
                  {[
                    ['ALL', `All (${alerts.length})`],
                    ['OPEN', `Open (${openCount})`],
                    ['ACKNOWLEDGED', `Acknowledged (${mitigatedCount})`],
                    ['CLOSED', `Closed (${closedCount})`]
                  ].map(([st, lbl]) => (
                    <button
                      key={st}
                      className="btn btn-ghost"
                      style={{
                        padding: '4px 10px',
                        fontSize: 11,
                        fontWeight: 600,
                        background: statusFilter === st ? 'rgba(99,102,241,0.2)' : '',
                        color: statusFilter === st ? '#818cf8' : 'var(--text-muted)'
                      }}
                      onClick={() => setStatusFilter(st)}
                    >
                      {lbl}
                    </button>
                  ))}
                </div>

                {criticalCount > 0 && (
                  <span className="badge badge-critical" style={{ marginLeft: 6 }}>
                    <span className="badge-dot" />
                    {criticalCount} Critical Open
                  </span>
                )}
              </div>

              <div className="live-indicator">
                <span className="pulse-dot" />
                Live PostgreSQL Threat Store
              </div>
            </div>

            {/* Filter Bar Row 2: Severity & Time Range */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 10, flexWrap: 'wrap', gap: 10 }}>
              {/* Severity chips */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Severity:</span>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                  const isActive = severityFilter === sev
                  const colorMap = {
                    CRITICAL: '#f43f5e',
                    HIGH: '#f59e0b',
                    MEDIUM: '#38bdf8',
                    LOW: '#10b981',
                    ALL: '#818cf8'
                  }
                  return (
                    <button
                      key={sev}
                      className="btn btn-ghost"
                      style={{
                        padding: '3px 8px',
                        fontSize: 10,
                        fontWeight: 700,
                        background: isActive ? `${colorMap[sev]}25` : '',
                        color: isActive ? colorMap[sev] : 'var(--text-muted)',
                        border: isActive ? `1px solid ${colorMap[sev]}50` : '1px solid transparent'
                      }}
                      onClick={() => setSeverityFilter(sev)}
                    >
                      {sev}
                    </button>
                  )
                })}
              </div>

              {/* Time window chips */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Window:</span>
                {[
                  ['ALL', 'All Time'],
                  ['1h', 'Last 1h'],
                  ['6h', 'Last 6h'],
                  ['24h', 'Last 24h']
                ].map(([tw, label]) => (
                  <button
                    key={tw}
                    className="btn btn-ghost"
                    style={{
                      padding: '3px 8px',
                      fontSize: 10,
                      fontWeight: 600,
                      background: timeFilter === tw ? 'rgba(255,255,255,0.1)' : '',
                      color: timeFilter === tw ? 'var(--text-primary)' : 'var(--text-muted)'
                    }}
                    onClick={() => handleTimeFilter(tw)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div style={{ overflowY: 'auto', maxHeight: 'calc(100vh - 280px)' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>AI Classification &amp; MITRE</th>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'center' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => {
                  const mitre = MITRE_MAP[a.ai_attack_class]
                  return (
                    <tr
                      key={a.event_id}
                      className="clickable-row"
                      onClick={() => onSelectAlert && onSelectAlert(a)}
                    >
                      <td className="font-mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {formatIST(a.timestamp)}
                      </td>
                      <td><SeverityBadge tier={a.risk_tier} /></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="attack-name">{a.ai_attack_class?.replace(/_/g, ' ')}</span>
                          {mitre && (
                            <span className="mitre-tag" style={{ fontSize: 9, padding: '1px 5px' }}>
                              {mitre.id.split(' ')[0]}
                            </span>
                          )}
                        </div>
                        {a.suricata_signature && <div className="attack-signature">{a.suricata_signature}</div>}
                        <div className="attack-confidence">Confidence: <span>{a.risk_score}%</span></div>
                      </td>
                      <td className="font-mono" style={{ fontSize: 12 }}>
                        {a.src_ip}
                        {blockedIpSet?.has(a.src_ip) && (
                          <span
                            style={{
                              marginLeft: 6,
                              fontSize: 9,
                              padding: '1px 5px',
                              borderRadius: 4,
                              background: 'rgba(244, 63, 94, 0.15)',
                              color: '#f43f5e',
                              fontWeight: 700,
                              border: '1px solid rgba(244, 63, 94, 0.3)'
                            }}
                            title="Host is actively dropped by pfSense & Host-IPS"
                          >
                            ⊘ QUARANTINED
                          </span>
                        )}
                      </td>
                      <td className="font-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>{a.dst_ip || '—'}</td>
                      <td>
                        {a.status === 'ACKNOWLEDGED' ? (
                          blockedIpSet?.has(a.src_ip) ? (
                            <span className="badge badge-low" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)', fontSize: 10 }}>
                              BLOCKED
                            </span>
                          ) : (
                            <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8', border: '1px solid rgba(99, 102, 241, 0.3)', fontSize: 10 }}>
                              ACKNOWLEDGED
                            </span>
                          )
                        ) : a.status === 'CLOSED' ? (
                          <span className="badge" style={{ background: 'rgba(100, 116, 139, 0.2)', color: '#94a3b8', fontSize: 10 }}>
                            CLOSED
                          </span>
                        ) : (
                          <span className="badge badge-critical" style={{ fontSize: 10 }}>
                            OPEN
                          </span>
                        )}
                      </td>
                      <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          {a.status === 'ACKNOWLEDGED' ? (
                            blockedIpSet?.has(a.src_ip) ? (
                              <span style={{ color: '#10b981', fontSize: 12, fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                                ✓ Blocked
                              </span>
                            ) : (
                              <button
                                className={`btn-block-ip ${a.risk_tier === "CRITICAL" ? 'critical' : ''}`}
                                onClick={() => onMitigate(a)}
                                title={a.src_ip ? `Re-block ${a.src_ip} on pfSense firewall (60m TTL)` : 'Acknowledge threat'}
                              >
                                <svg style={{ width: 10, height: 10 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                                {a.src_ip ? 'Block IP' : 'Acknowledge'}
                              </button>
                            )
                          ) : blockedIpSet?.has(a.src_ip) ? (
                            <button
                              className="btn-neutral-outline"
                              style={{ fontSize: 11, padding: '4px 9px', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                              onClick={() => onMitigate(a)}
                              title="IP already dropped by firewall. Click to acknowledge event."
                            >
                              ✓ Quarantined (Ack)
                            </button>
                          ) : (
                            <button
                              className={`btn-block-ip ${a.risk_tier === "CRITICAL" ? 'critical' : ''}`}
                              onClick={() => onMitigate(a)}
                              title={a.src_ip ? `Drop ${a.src_ip} on pfSense firewall (60m TTL)` : 'Acknowledge threat'}
                            >
                              <svg style={{ width: 10, height: 10 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                              {a.src_ip ? 'Block IP' : 'Acknowledge'}
                            </button>
                          )}
                          <button
                            className="btn btn-ghost"
                            style={{ padding: '4px 6px', fontSize: 11 }}
                            onClick={() => onSelectAlert && onSelectAlert(a)}
                            title="Inspect forensic payload & MITRE mapping"
                          >
                            🔍
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
                {filtered.length === 0 && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>
                    {search ? 'No results match your search filters' : 'No threat records in this category'}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="table-footer">
            <span>Showing {filtered.length} of {alerts.length} events {search && '(filtered)'}</span>
            <div className="live-indicator">
              <span className="pulse-dot" />
              Polling every 3s
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

/* ════════════════════════════════════════════════════
   APP SHELL
   ════════════════════════════════════════════════════ */
export default function App() {
  const [page, setPage] = useState('dashboard')
  const [alerts, setAlerts] = useState([])
  const [criticalCount, setCriticalCount] = useState(0)
  const [mitigationStats, setMitigationStats] = useState(null)
  const [activeRules, setActiveRules] = useState([])
  const [apiConnected, setApiConnected] = useState(true)
  const [toast, setToast] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [audioEnabled, setAudioEnabled] = useState(false)

  const showToast = (msg) => {
    setToast(msg)
    setTimeout(() => setToast(null), 4000)
  }

  useEffect(() => {
    let isMounted = true
    const load = async () => {
      try {
        const [a, c, m, r] = await Promise.all([
          fetchAlerts(1000),
          fetchOpenCriticalCount(),
          fetchMitigationStats(),
          fetchMitigationRules('ACTIVE')
        ])
        if (!isMounted) return
        
        // Audio siren check if new critical alerts arrived
        if (audioEnabled && c > criticalCount && criticalCount > 0) {
          playSocAlertSound()
        }

        setAlerts(a)
        setCriticalCount(c)
        if (m) setMitigationStats(m)
        if (Array.isArray(r)) setActiveRules(r)
        setApiConnected(true)
      } catch {
        if (isMounted) setApiConnected(false)
      }
    }
    load()
    const id = setInterval(() => {
      if (document.hidden) return
      load()
    }, 3000)
    return () => {
      isMounted = false
      clearInterval(id)
    }
  }, [audioEnabled, criticalCount])

  const blockedIpSet = useMemo(() => {
    const s = new Set()
    activeRules.forEach(rule => {
      if (rule.status === 'ACTIVE' && rule.ip_address) {
        s.add(rule.ip_address)
      }
    })
    return s
  }, [activeRules])

  const handleMitigate = async (alertObj) => {
    const eventId = typeof alertObj === 'string' ? alertObj : alertObj.event_id
    const ip = typeof alertObj === 'object' ? alertObj.src_ip : null
    const threatClass = typeof alertObj === 'object' ? alertObj.ai_attack_class : 'CRITICAL_THREAT'
    const riskScore = typeof alertObj === 'object' ? alertObj.risk_score : 95.0

    // Optimistically update local state immediately
    setAlerts(prev => prev.map(a => a.event_id === eventId ? { ...a, status: 'ACKNOWLEDGED' } : a))
    setCriticalCount(prev => Math.max(0, prev - 1))
    
    // 1. Mark alert as acknowledged
    await mitigateAlert(eventId)

    // 2. Inject firewall block rule on pfSense
    if (ip) {
      const blockRes = await blockIpApi({
        ip_address: ip,
        threat_class: threatClass,
        risk_score: riskScore,
        event_id: eventId,
        duration_minutes: 60,
        interface: 'WAN',
        mitigation_mode: 'MANUAL',
        analyst_notes: `One-click SOC mitigation from Threat Alerts for ${ip}`
      })
      if (blockRes) {
        showToast(blockedIpSet.has(ip)
          ? `✓ Alert acknowledged & quarantine refreshed for ${ip}`
          : `✓ Injected pfSense Block Rule! ${ip} dropped on WAN (60m TTL)`)
      }
    } else {
      showToast('✓ Alert marked as Mitigated')
    }

    const [s, freshRules] = await Promise.all([
      fetchMitigationStats(),
      fetchMitigationRules('ACTIVE')
    ])
    if (s) setMitigationStats(s)
    if (Array.isArray(freshRules)) setActiveRules(freshRules)
  }

  const handleStatusUpdate = async (eventId, newStatus, analystNote) => {
    setAlerts(prev => prev.map(a => a.event_id === eventId ? { ...a, status: newStatus, analyst_note: analystNote } : a))
    if (newStatus === 'CLOSED' || newStatus === 'ACKNOWLEDGED') {
      setCriticalCount(prev => Math.max(0, prev - 1))
    }
    const ok = await updateAlertStatusApi(eventId, newStatus, analystNote)
    if (ok) {
      showToast(`✓ Incident #${eventId.slice(0, 8)} status updated to ${newStatus}`)
    } else {
      showToast(`⚠️ Failed to update incident status`)
    }
  }

  const NAV = [
    { id: 'dashboard',   label: 'Dashboard',             icon: Icon.Dashboard },
    { id: 'alerts',      label: 'Threat Alerts',         icon: Icon.Shield, badge: criticalCount || null },
    { id: 'mitigations', label: 'Active IPS & Firewall', icon: Icon.Lock,   badge: mitigationStats?.active_blocks || null },
    { id: 'flows',       label: 'Network Flows',         icon: Icon.Activity },
    { id: 'models',      label: 'AI Models',             icon: Icon.Cpu },
  ]

  return (
    <div className="app-shell">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">
            <Icon.Shield style={{ width: 20, height: 20, color: 'white' }} />
          </div>
          <div className="sidebar-brand-text">
            <h2>Enterprise Security</h2>
            <span>SOC Platform</span>
          </div>
        </div>

        <div className="sidebar-section-label">Navigation</div>
        <ul className="sidebar-nav">
          {NAV.map((item) => (
            <li key={item.id}>
              <a
                className={page === item.id ? 'active' : ''}
                onClick={() => setPage(item.id)}
              >
                <item.icon />
                {item.label}
                {item.badge && <span className="nav-badge">{item.badge}</span>}
              </a>
            </li>
          ))}
        </ul>

        <div className="sidebar-bottom">
          <div className={`system-status ${apiConnected ? '' : 'offline'}`}>
            <span className="system-status-dot" />
            {apiConnected ? 'All systems operational' : 'API Connecting…'}
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main-content">
        {page === 'dashboard' && (
          <DashboardPage
            alerts={alerts}
            onMitigate={handleMitigate}
            onNavigate={setPage}
            mitigationStats={mitigationStats}
            blockedIpSet={blockedIpSet}
            onSelectAlert={setSelectedAlert}
            audioEnabled={audioEnabled}
            onToggleAudio={() => {
              const next = !audioEnabled
              setAudioEnabled(next)
              if (next) playSocAlertSound()
              showToast(next ? '🔊 SOC Siren Enabled' : '🔇 SOC Siren Muted')
            }}
          />
        )}
        {page === 'alerts' && (
          <AlertsPage
            alerts={alerts}
            onMitigate={handleMitigate}
            blockedIpSet={blockedIpSet}
            onSelectAlert={setSelectedAlert}
          />
        )}
        {page === 'mitigations' && <MitigationsPage onToast={showToast} />}
        {page === 'flows' && <NetworkFlowsPage />}
        {page === 'models' && <AIModelsPage />}
      </main>

      {/* ── Alert Investigation Modal ── */}
      {selectedAlert && (
        <AlertInvestigationModal
          key={selectedAlert.event_id}
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onMitigate={handleMitigate}
          onStatusUpdate={handleStatusUpdate}
          blockedIpSet={blockedIpSet}
        />
      )}

      {/* ── Toast Feedback Notification ── */}
      {toast && (
        <div className="toast-feedback">
          <span className="firewall-pulse-dot" />
          <span>{toast}</span>
        </div>
      )}
    </div>
  )
}

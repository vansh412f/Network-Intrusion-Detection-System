import { memo, useCallback, useState, useEffect, useMemo, useRef } from 'react'
import { motion } from 'framer-motion'
import { Download, SearchX, ChevronLeft, ChevronRight } from 'lucide-react'
import { ThreatRow }  from './ThreatRow'
import { Card }       from '../../ui/Card'

const ITEMS_PER_PAGE = 10

function exportToCSV(alerts) {
  const headers = ['Time', 'Source IP', 'Threat Type', 'Severity', 'Confidence %', 'Blocked']
  const rows    = alerts.map(a => [
    new Date(a.createdAt).toLocaleString(),
    a.source_ip,
    a.threat_type || 'DDoS',
    a.severity    || 'LOW',
    Math.round(a.probability * 10) / 10,
    a.blocked ? 'Yes' : 'No'
  ])
  const csv  = [headers, ...rows].map(r => r.join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `nids-alerts-${Date.now()}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

function ThreatTableInner({ alerts, onBlockIP, isAuthenticated }) {
  const [currentPage, setCurrentPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [direction, setDirection] = useState(1)

  const isInitialMount = useRef(true)

  useEffect(() => {
    isInitialMount.current = false
  }, [])

  // Reset to page 1 when new alert arrives or filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [alerts.length, severityFilter, typeFilter])

  // Filter alerts before pagination
  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      const matchSeverity = severityFilter === 'ALL' || (alert.severity || 'LOW') === severityFilter
      const matchType     = typeFilter === 'ALL' || (alert.threat_type || 'DDoS') === typeFilter
      return matchSeverity && matchType
    })
  }, [alerts, severityFilter, typeFilter])

  const totalPages  = Math.max(1, Math.ceil(filteredAlerts.length / ITEMS_PER_PAGE))
  const startIndex  = (currentPage - 1) * ITEMS_PER_PAGE
  const endIndex    = Math.min(startIndex + ITEMS_PER_PAGE, filteredAlerts.length)
  const pageAlerts  = useMemo(
    () => filteredAlerts.slice(startIndex, endIndex),
    [filteredAlerts, startIndex, endIndex]
  )

  const handleExport = useCallback(() => exportToCSV(filteredAlerts), [filteredAlerts])

  const goTo = (page) => {
    const target = Math.max(1, Math.min(totalPages, page))
    if (target !== currentPage) {
      setDirection(target > currentPage ? 1 : -1)
      setCurrentPage(target)
    }
  }
  const hasPrev = currentPage > 1
  const hasNext = currentPage < totalPages

  return (
    <Card className="overflow-hidden flex flex-col h-full">

      {/* ── Header ── */}
      <div
        className="flex items-center justify-between border-b px-4 py-2.5 sm:px-5 flex-wrap gap-2"
        style={{ borderColor: 'var(--color-border-card)' }}
      >
        <div className="flex items-center gap-2 flex-wrap">
          <h2
            className="text-sm font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Threat Log
          </h2>
          <span
            className="rounded-full px-2 py-0.5"
            style={{
              fontSize:        '10px',
              backgroundColor: 'var(--color-border-card)',
              color:           'var(--color-text-muted)'
            }}
          >
            {filteredAlerts.length}
          </span>
        </div>

        {/* Filters & Export */}
        <div className="flex items-center gap-2">
          {/* Severity filter */}
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="rounded-lg border px-2 py-1 outline-none text-xs"
            style={{
              borderColor:     'var(--color-border-card)',
              backgroundColor: 'var(--color-bg-card)',
              color:           'var(--color-text-secondary)',
              fontSize:        '11px'
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>

          {/* Type filter */}
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="rounded-lg border px-2 py-1 outline-none text-xs"
            style={{
              borderColor:     'var(--color-border-card)',
              backgroundColor: 'var(--color-bg-card)',
              color:           'var(--color-text-secondary)',
              fontSize:        '11px'
            }}
          >
            <option value="ALL">All Types</option>
            <option value="DDoS">DDoS</option>
            <option value="MANUAL">Manual Test</option>
          </select>

          <button
            onClick={handleExport}
            disabled={filteredAlerts.length === 0}
            className="flex items-center gap-1.5 rounded-lg border px-2.5 py-1 transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-40"
            style={{
              fontSize:        '11px',
              fontWeight:      500,
              borderColor:     'var(--color-border-card)',
              backgroundColor: 'var(--color-bg-card)',
              color:           'var(--color-text-secondary)'
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--color-primary-blue)'
              e.currentTarget.style.color       = 'var(--color-primary-blue)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--color-border-card)'
              e.currentTarget.style.color       = 'var(--color-text-secondary)'
            }}
          >
            <Download size={11} strokeWidth={1.75} aria-hidden="true" />
            <span className="hidden sm:inline">Export</span>
          </button>
        </div>
      </div>

      {/* ── Table ── */}
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-sm">
          <thead>
            <tr
              className="border-b"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)'
              }}
            >
              {[
                { label: 'Time', class: 'min-w-[80px] text-left' },
                { label: 'Source IP', class: 'min-w-[120px] text-left' },
                { label: 'Type', class: 'min-w-[80px] text-left' },
                { label: 'Severity', class: 'min-w-[80px] text-left' },
                { label: 'Confidence', class: 'w-[72px] text-left' },
                { label: 'Actions', class: 'min-w-[60px] text-right' }
              ].map(col => (
                <th
                  key={col.label}
                  className={`whitespace-nowrap px-4 py-2 font-semibold uppercase ${col.class}`}
                  style={{
                    fontSize:      '10px',
                    letterSpacing: '0.07em',
                    color:         'var(--color-text-muted)'
                  }}
                >
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-14 text-center">
                  <div className="flex flex-col items-center gap-3">
                    <SearchX
                      size={28}
                      strokeWidth={1.25}
                      style={{ color: 'var(--color-text-muted)', opacity: 0.4 }}
                      aria-hidden="true"
                    />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
                      No threats found
                    </p>
                    <p style={{ fontSize: '10px', color: 'var(--color-text-muted)', opacity: 0.6 }}>
                      Sensor is actively monitoring
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              pageAlerts.map((alert, index) => (
                <ThreatRow
                  key={alert._id || index}
                  alert={alert}
                  onBlockIP={onBlockIP}
                  isAuthenticated={isAuthenticated}
                  direction={direction}
                  index={index}
                  skipAnim={isInitialMount.current}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* ── Pagination footer ── */}
      {filteredAlerts.length > 0 && (
        <div
          className="flex items-center justify-between border-t px-4 py-2.5 sm:px-5"
          style={{ borderColor: 'var(--color-border-card)' }}
        >
          {/* Count info */}
          <p style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
            Showing{' '}
            <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              {startIndex + 1}–{endIndex}
            </span>
            {' '}of{' '}
            <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              {filteredAlerts.length}
            </span>
            {' '}threats
          </p>

          {/* Page controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => goTo(currentPage - 1)}
              disabled={!hasPrev}
              className="flex items-center justify-center rounded-lg border p-1.5 transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-30"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)',
                color:           'var(--color-text-secondary)'
              }}
              onMouseEnter={e => { if (hasPrev) e.currentTarget.style.borderColor = 'var(--color-border-hover)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--color-border-card)' }}
              aria-label="Previous page"
            >
              <ChevronLeft size={13} strokeWidth={2} />
            </button>

            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', minWidth: '64px', textAlign: 'center' }}>
              Page{' '}
              <span style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>
                {currentPage}
              </span>
              {' '}of{' '}
              <span style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>
                {totalPages}
              </span>
            </span>

            <button
              onClick={() => goTo(currentPage + 1)}
              disabled={!hasNext}
              className="flex items-center justify-center rounded-lg border p-1.5 transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-30"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)',
                color:           'var(--color-text-secondary)'
              }}
              onMouseEnter={e => { if (hasNext) e.currentTarget.style.borderColor = 'var(--color-border-hover)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--color-border-card)' }}
              aria-label="Next page"
            >
              <ChevronRight size={13} strokeWidth={2} />
            </button>
          </div>
        </div>
      )}

    </Card>
  )
}

export const ThreatTable = memo(ThreatTableInner)
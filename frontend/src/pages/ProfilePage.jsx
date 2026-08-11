import { useState, useEffect, useRef } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import { useAuth } from '../hooks/useAuth'
import { useSocket } from '../hooks/useSocket'
import { Header } from '../components/layout/Header'
import { Footer } from '../components/layout/Footer'
import { Card } from '../components/ui/Card'
import { LoadingSpinner } from '../components/ui/LoadingSpinner'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'

const api = axios.create({
  baseURL: API_URL,
  withCredentials: true
})

const SEVERITIES = [
  { value: 'NONE',     label: 'None',     desc: 'No alert emails — fully unsubscribed' },
  { value: 'LOW',      label: 'Low',      desc: 'Receive all alert emails' },
  { value: 'MEDIUM',   label: 'Medium',   desc: 'Receive medium and above' },
  { value: 'HIGH',     label: 'High',     desc: 'Receive high and critical only' },
  { value: 'CRITICAL', label: 'Critical', desc: 'Receive critical threats only' }
]

const SEVERITY_STYLES = {
  NONE:     { border: 'rgba(100,116,139,0.4)',  bg: 'rgba(100,116,139,0.1)',  text: '#94a3b8' },
  LOW:      { border: 'rgba(234,179,8,0.4)',    bg: 'rgba(234,179,8,0.1)',    text: '#facc15' },
  MEDIUM:   { border: 'rgba(249,115,22,0.4)',   bg: 'rgba(249,115,22,0.1)',   text: '#fb923c' },
  HIGH:     { border: 'rgba(239,68,68,0.4)',    bg: 'rgba(239,68,68,0.1)',    text: '#f87171' },
  CRITICAL: { border: 'rgba(185,28,28,0.4)',    bg: 'rgba(185,28,28,0.2)',    text: '#f87171' }
}

export default function ProfilePage({ addToast }) {
  const { user, isAuthenticated, loading: authLoading } = useAuth()
  const { isConnected } = useSocket()
  const [searchParams] = useSearchParams()

  const [name,               setName]               = useState('')
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [minSeverity,        setMinSeverity]        = useState('LOW')
  const [saving,             setSaving]             = useState(false)
  const [loadingProfile,     setLoadingProfile]     = useState(true)

  // Track last saved state to detect dirty form
  const savedState = useRef({ name: '', emailNotifications: true, minSeverity: 'LOW' })

  const isDirty = (
    name               !== savedState.current.name               ||
    emailNotifications !== savedState.current.emailNotifications ||
    minSeverity        !== savedState.current.minSeverity
  )

  const syncSavedState = (n, notif, sev) => {
    savedState.current = { name: n, emailNotifications: notif, minSeverity: sev }
  }

  // Detect redirect from unsubscribe link
  useEffect(() => {
    if (searchParams.get('unsubscribed') === 'true') {
      addToast?.('You have been unsubscribed from alert emails', 'success')
    }
  }, [searchParams, addToast])

  useEffect(() => {
    if (!isAuthenticated) return
    const fetchProfile = async () => {
      try {
        const res = await api.get('/api/auth/me')
        if (res.data.success) {
          const n     = res.data.user.name                   || ''
          const notif = res.data.user.email_notifications    ?? true
          const sev   = res.data.user.min_severity_for_email ?? 'LOW'
          setName(n)
          setEmailNotifications(notif)
          setMinSeverity(sev)
          syncSavedState(n, notif, sev)  // Seed saved state on load
        }
      } catch {
        addToast?.('Failed to load profile settings', 'error')
      } finally {
        setLoadingProfile(false)
      }
    }
    fetchProfile()
  }, [isAuthenticated, addToast])

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center" style={{ backgroundColor: 'var(--color-bg-page)' }}>
        <LoadingSpinner size="lg" label="Loading profile..." />
      </div>
    )
  }

  if (!isAuthenticated) return <Navigate to="/login" replace />

  const handleSave = async () => {
    setSaving(true)
    try {
      await api.patch('/api/auth/me', {
        name,
        email_notifications:    emailNotifications,
        min_severity_for_email: minSeverity
      })
      syncSavedState(name, emailNotifications, minSeverity)  // Update saved state after save
      addToast?.('Profile settings saved', 'success')
    } catch (error) {
      addToast?.(error.response?.data?.message || 'Failed to save settings', 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleUnsubscribe = async () => {
    setSaving(true)
    try {
      await api.patch('/api/auth/me', { min_severity_for_email: 'NONE' })
      setMinSeverity('NONE')
      syncSavedState(name, emailNotifications, 'NONE')  // Update saved state after unsubscribe
      addToast?.('Unsubscribed from all alert emails', 'success')
    } catch {
      addToast?.('Failed to unsubscribe', 'error')
    } finally {
      setSaving(false)
    }
  }

  const selectedSeverityDesc = SEVERITIES.find(s => s.value === minSeverity)?.desc || ''

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--color-bg-page)' }}>
      <Header isConnected={isConnected} />

      <main className="mx-auto max-w-2xl px-3 py-8 sm:px-6 space-y-6">

        {/* Page title */}
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--color-text-primary)' }}>Profile</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-text-muted)' }}>
            Manage your account and notification preferences
          </p>
        </div>

        {/* Account card */}
        <Card className="p-6 space-y-5">
          <h2 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Account</h2>

          <div className="flex items-center gap-4">
            <div
              className="flex h-14 w-14 items-center justify-center rounded-full text-2xl font-bold text-white flex-shrink-0"
              style={{ backgroundColor: 'var(--color-primary-blue)' }}
            >
              {user?.name?.charAt(0)?.toUpperCase() || 'U'}
            </div>
            <div className="min-w-0">
              <p className="font-semibold truncate" style={{ color: 'var(--color-text-primary)' }}>{user?.name}</p>
              <p className="text-sm truncate" style={{ color: 'var(--color-text-muted)' }}>{user?.email}</p>
            </div>
          </div>

          {/* Name edit */}
          <div>
            <label
              className="mb-1.5 block text-xs font-semibold"
              style={{ color: 'var(--color-text-secondary)' }}
              htmlFor="profile-name"
            >
              Display Name
            </label>
            <input
              id="profile-name"
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              minLength={2}
              maxLength={50}
              className="w-full rounded-xl border px-4 py-2.5 text-sm outline-none transition-colors duration-150"
              style={{
                backgroundColor: 'var(--color-bg-page)',
                borderColor:     'var(--color-border-card)',
                color:           'var(--color-text-primary)'
              }}
              onFocus={e => e.currentTarget.style.borderColor = 'var(--color-primary-blue)'}
              onBlur={e  => e.currentTarget.style.borderColor = 'var(--color-border-card)'}
            />
          </div>

          {/* Info grid */}
          <div className="grid grid-cols-2 gap-3">
            <div
              className="rounded-lg border px-4 py-3"
              style={{ borderColor: 'var(--color-border-card)', backgroundColor: 'var(--color-bg-page)' }}
            >
              <p className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Role</p>
              <p className="mt-1 text-sm font-semibold capitalize" style={{ color: 'var(--color-text-primary)' }}>{user?.role || 'analyst'}</p>
            </div>
            <div
              className="rounded-lg border px-4 py-3"
              style={{ borderColor: 'var(--color-border-card)', backgroundColor: 'var(--color-bg-page)' }}
            >
              <p className="text-xs font-medium uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Status</p>
              <p className="mt-1 flex items-center gap-1.5 text-sm font-semibold" style={{ color: '#34d399' }}>
                <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ backgroundColor: '#34d399' }} />
                Verified
              </p>
            </div>
          </div>

          {/* User ID */}
          <div
            className="rounded-lg border px-4 py-3"
            style={{ borderColor: 'var(--color-border-card)', backgroundColor: 'var(--color-bg-page)' }}
          >
            <p className="text-xs font-medium uppercase tracking-wider mb-1" style={{ color: 'var(--color-text-muted)' }}>User ID</p>
            <p className="font-mono text-sm" style={{ color: 'var(--color-text-secondary)' }}>
              {user?.userId || '—'}
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
              This is your anonymous identifier shown in the blocklist
            </p>
          </div>
        </Card>

        {/* Notifications card */}
        {loadingProfile ? (
          <Card className="flex items-center justify-center p-12">
            <LoadingSpinner size="md" label="Loading preferences..." />
          </Card>
        ) : (
          <Card className="p-6 space-y-6">
            <h2 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Email Notifications</h2>

            {/* Toggle */}
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>Threat Alert Emails</p>
                <p className="mt-0.5 text-xs" style={{ color: 'var(--color-text-muted)' }}>
                  Receive email notifications when threats are detected
                </p>
              </div>
              <button
                onClick={() => setEmailNotifications(prev => !prev)}
                className="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none"
                style={{ backgroundColor: emailNotifications ? 'var(--color-primary-blue)' : 'var(--color-border-card)' }}
                role="switch"
                aria-checked={emailNotifications}
                aria-label="Toggle threat alert emails"
              >
                <span
                  className="pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg transition duration-200"
                  style={{ transform: emailNotifications ? 'translateX(20px)' : 'translateX(0)' }}
                />
              </button>
            </div>

            {/* Severity selector */}
            {emailNotifications && (
              <div className="space-y-3">
                <div>
                  <p className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>Minimum Severity</p>
                  <p className="mt-0.5 text-xs" style={{ color: 'var(--color-text-muted)' }}>
                    Only receive emails for threats at or above this level
                  </p>
                </div>
                <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
                  {SEVERITIES.map(({ value, label }) => {
                    const isSelected = minSeverity === value
                    const styles     = SEVERITY_STYLES[value]
                    return (
                      <button
                        key={value}
                        onClick={() => setMinSeverity(value)}
                        className="rounded-lg border px-2 py-2 text-xs font-semibold transition-all duration-150"
                        style={{
                          borderColor:     isSelected ? styles.border : 'var(--color-border-card)',
                          backgroundColor: isSelected ? styles.bg    : 'var(--color-bg-page)',
                          color:           isSelected ? styles.text  : 'var(--color-text-muted)'
                        }}
                      >
                        {label}
                      </button>
                    )
                  })}
                </div>
                <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                  {selectedSeverityDesc}
                </p>

                {/* Smart Cooldown Note */}
                <div className="mt-4 rounded-lg bg-blue-500/10 border border-blue-500/20 p-3">
                  <p className="text-xs flex items-start gap-2" style={{ color: '#93c5fd' }}>
                    <span className="text-base leading-none">⏱️</span>
                    <span>
                      <strong>Smart Cooldown Active:</strong> To prevent your inbox from being flooded during a heavy attack (like a DDoS simulation), our system strictly limits alerts to a maximum of <strong>1 email per 15 minutes</strong>.
                    </span>
                  </p>
                </div>
              </div>
            )}

            {/* Unsubscribe note */}
            <div
              className="rounded-lg border p-4"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'rgba(255,255,255,0.02)'
              }}
            >
              <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>
                To unsubscribe instantly without logging in, click the{' '}
                <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  Unsubscribe from Alerts
                </span>
                {' '}button in any threat alert email. You can re-subscribe here by selecting a severity level above.
              </p>
              {minSeverity !== 'NONE' && (
                <button
                  onClick={handleUnsubscribe}
                  disabled={saving}
                  className="mt-3 text-xs font-medium transition-colors duration-150 disabled:opacity-50"
                  style={{ color: '#ef4444' }}
                  onMouseEnter={e => e.currentTarget.style.textDecoration = 'underline'}
                  onMouseLeave={e => e.currentTarget.style.textDecoration = 'none'}
                >
                  Unsubscribe from all emails
                </button>
              )}
              {minSeverity === 'NONE' && (
                <p className="mt-2 text-xs font-medium" style={{ color: '#34d399' }}>
                  ✓ You are currently unsubscribed from all alert emails
                </p>
              )}
            </div>

            {/* Save button — disabled when clean, centered */}
            <div
              className="flex justify-center border-t pt-4"
              style={{ borderColor: 'var(--color-border-card)' }}
            >
              <button
                onClick={handleSave}
                disabled={saving || !isDirty}
                className="flex items-center gap-2 rounded-lg px-6 py-2.5 text-sm font-semibold text-white transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50"
                style={{ backgroundColor: 'var(--color-primary-blue)' }}
                onMouseEnter={e => { if (!saving && isDirty) e.currentTarget.style.backgroundColor = 'var(--color-primary-hover)' }}
                onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'var(--color-primary-blue)' }}
              >
                {saving ? (
                  <>
                    <span
                      className="h-4 w-4 rounded-full border-2 animate-spin"
                      style={{ borderColor: 'rgba(255,255,255,0.3)', borderTopColor: 'white' }}
                    />
                    Saving...
                  </>
                ) : 'Save Changes'}
              </button>
            </div>
          </Card>
        )}

      </main>

      <Footer />
    </div>
  )
}
import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Shield,
  LayoutDashboard,
  BarChart2,
  BookOpen,
  Wifi,
  WifiOff,
  Video,
  Cpu,
  User,
  LogOut,
  LogIn,
  Menu,
  X
} from 'lucide-react'
import { useAuth } from '../../hooks/useAuth'

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/analytics', label: 'Analytics',  icon: BarChart2 },
  { to: '/docs',      label: 'Docs',       icon: BookOpen }
]

const LIVE_STATUS_ROUTES = ['/dashboard', '/analytics']

export function Header({ isConnected, onOpenManualInput, onOpenDemo }) {
  const { user, isAuthenticated, logout } = useAuth()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const showLiveBadge = LIVE_STATUS_ROUTES.includes(location.pathname)

  return (
    <header
      className="sticky top-0 z-40 border-b backdrop-blur-md"
      style={{
        backgroundColor: 'rgba(6, 11, 24, 0.85)',
        borderColor:     'var(--color-border-card)'
      }}
    >
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">

        <Link to="/" className="flex items-center gap-2 flex-shrink-0">
          <Shield size={20} strokeWidth={1.75} style={{ color: 'var(--color-primary-blue)' }} />
          <span className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>
            NIDS SOC
          </span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex absolute left-1/2 -translate-x-1/2">
          {NAV_LINKS.map(({ to, label, icon: Icon }) => {
            const isActive = location.pathname === to
            return (
              <Link
                key={to}
                to={to}
                className="relative flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors duration-150"
                style={{
                  color:           isActive ? 'var(--color-primary-blue)' : 'var(--color-text-secondary)',
                  backgroundColor: isActive ? 'rgba(59, 130, 246, 0.1)' : 'transparent'
                }}
                onMouseEnter={e => {
                  if (!isActive) e.currentTarget.style.color = 'var(--color-text-primary)'
                }}
                onMouseLeave={e => {
                  if (!isActive) e.currentTarget.style.color = 'var(--color-text-secondary)'
                }}
              >
                <Icon size={14} strokeWidth={1.75} aria-hidden="true" />
                {label}
                {isActive && (
                  <span
                    className="absolute bottom-0 left-3 right-3 h-px rounded-full"
                    style={{ backgroundColor: 'var(--color-primary-blue)' }}
                  />
                )}
              </Link>
            )
          })}
        </nav>

        <div className="flex items-center gap-2">

          {showLiveBadge && (
            <div className="flex items-center gap-1.5">
              <div className="relative flex h-2 w-2">
                {isConnected && (
                  <span
                    className="absolute inline-flex h-full w-full rounded-full animate-ping"
                    style={{ backgroundColor: 'var(--color-live-green)', opacity: 0.6 }}
                  />
                )}
                <span
                  className="relative inline-flex h-2 w-2 rounded-full"
                  style={{ backgroundColor: isConnected ? 'var(--color-live-green)' : 'var(--color-alert-red)' }}
                />
              </div>
              <span
                className="hidden text-xs font-medium sm:block"
                style={{ color: isConnected ? 'var(--color-live-green)' : 'var(--color-alert-red)' }}
              >
                {isConnected ? 'Live' : 'Offline'}
              </span>
            </div>
          )}

          {onOpenDemo && (
            <button
              onClick={onOpenDemo}
              title="Demo Video"
              className="hidden sm:flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors duration-150 border"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)',
                color:           'var(--color-text-secondary)'
              }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--color-text-primary)'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-secondary)'}
            >
              <Video size={13} strokeWidth={1.75} aria-hidden="true" />
              Demo
            </button>
          )}

          {onOpenManualInput && (
            <button
              onClick={onOpenManualInput}
              title="Manual Prediction"
              className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold text-white transition-colors duration-150"
              style={{ backgroundColor: 'var(--color-primary-blue)' }}
              onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-primary-hover)'}
              onMouseLeave={e => e.currentTarget.style.backgroundColor = 'var(--color-primary-blue)'}
            >
              <Cpu size={13} strokeWidth={1.75} aria-hidden="true" />
              <span className="hidden sm:inline">Predict</span>
            </button>
          )}

          {isAuthenticated ? (
            <div className="hidden md:flex items-center gap-2">
              <Link
                to="/profile"
                className="flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors duration-150"
                style={{
                  borderColor:     'var(--color-border-card)',
                  backgroundColor: 'var(--color-bg-card)',
                  color:           'var(--color-text-secondary)'
                }}
                onMouseEnter={e => e.currentTarget.style.color = 'var(--color-text-primary)'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-secondary)'}
              >
                <div
                  className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold text-white"
                  style={{ backgroundColor: 'var(--color-primary-blue)' }}
                >
                  {user?.name?.charAt(0)?.toUpperCase() || 'U'}
                </div>
                <span className="max-w-[80px] truncate">{user?.name}</span>
              </Link>
              <button
                onClick={logout}
                title="Logout"
                className="flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors duration-150"
                style={{
                  borderColor:     'var(--color-border-card)',
                  backgroundColor: 'var(--color-bg-card)',
                  color:           'var(--color-text-secondary)'
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.borderColor = 'rgba(239,68,68,0.4)'
                  e.currentTarget.style.color = '#ef4444'
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = 'var(--color-border-card)'
                  e.currentTarget.style.color = 'var(--color-text-secondary)'
                }}
              >
                <LogOut size={13} strokeWidth={1.75} aria-hidden="true" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          ) : (
            <Link
              to="/login"
              className="hidden md:flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors duration-150"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)',
                color:           'var(--color-text-secondary)'
              }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'rgba(59,130,246,0.4)'
                e.currentTarget.style.color = 'var(--color-primary-blue)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--color-border-card)'
                e.currentTarget.style.color = 'var(--color-text-secondary)'
              }}
            >
              <LogIn size={13} strokeWidth={1.75} aria-hidden="true" />
              Login
            </Link>
          )}

          <button
            onClick={() => setMobileOpen(prev => !prev)}
            className="flex md:hidden items-center justify-center rounded-lg p-1.5 transition-colors duration-150"
            style={{
              color:           'var(--color-text-secondary)',
              backgroundColor: mobileOpen ? 'var(--color-bg-hover)' : 'transparent'
            }}
            aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
          >
            {mobileOpen
              ? <X size={18} strokeWidth={1.75} />
              : <Menu size={18} strokeWidth={1.75} />
            }
          </button>

        </div>
      </div>

      {mobileOpen && (
        <div
          className="border-t md:hidden animate-fade-slide"
          style={{
            borderColor:     'var(--color-border-card)',
            backgroundColor: 'var(--color-bg-card)'
          }}
        >
          <div className="mx-auto max-w-7xl space-y-1 px-4 py-3">
            {NAV_LINKS.map(({ to, label, icon: Icon }) => {
              const isActive = location.pathname === to
              return (
                <Link
                  key={to}
                  to={to}
                  onClick={() => setMobileOpen(false)}
                  className="flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150"
                  style={{
                    color:           isActive ? 'var(--color-primary-blue)' : 'var(--color-text-secondary)',
                    backgroundColor: isActive ? 'rgba(59,130,246,0.08)' : 'transparent'
                  }}
                >
                  <Icon size={16} strokeWidth={1.75} aria-hidden="true" />
                  {label}
                </Link>
              )
            })}

            <div
              className="my-2 border-t"
              style={{ borderColor: 'var(--color-border-card)' }}
            />

            {onOpenDemo && (
              <button
                onClick={() => { onOpenDemo(); setMobileOpen(false) }}
                className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150"
                style={{ color: 'var(--color-text-secondary)' }}
              >
                <Video size={16} strokeWidth={1.75} aria-hidden="true" />
                Demo Video
              </button>
            )}

            {onOpenManualInput && (
              <button
                onClick={() => { onOpenManualInput(); setMobileOpen(false) }}
                className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150"
                style={{ color: 'var(--color-primary-blue)' }}
              >
                <Cpu size={16} strokeWidth={1.75} aria-hidden="true" />
                Manual Prediction
              </button>
            )}

            {isAuthenticated ? (
              <>
                <Link
                  to="/profile"
                  onClick={() => setMobileOpen(false)}
                  className="flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150"
                  style={{ color: 'var(--color-text-secondary)' }}
                >
                  <User size={16} strokeWidth={1.75} aria-hidden="true" />
                  {user?.name || 'Profile'}
                </Link>
                <button
                  onClick={() => { logout(); setMobileOpen(false) }}
                  className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150"
                  style={{ color: '#ef4444' }}
                >
                  <LogOut size={16} strokeWidth={1.75} aria-hidden="true" />
                  Logout
                </button>
              </>
            ) : (
              <Link
                to="/login"
                onClick={() => setMobileOpen(false)}
                className="flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-150"
                style={{ color: 'var(--color-primary-blue)' }}
              >
                <LogIn size={16} strokeWidth={1.75} aria-hidden="true" />
                Login
              </Link>
            )}
          </div>
        </div>
      )}
    </header>
  )
}
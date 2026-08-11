import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, LogIn } from 'lucide-react'
import { useAuth } from '../../hooks/useAuth'

export function LoginForm() {
  const { login } = useAuth()
  const navigate  = useNavigate()

  const [email,        setEmail]        = useState('')
  const [password,     setPassword]     = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error,        setError]        = useState('')
  const [loading,      setLoading]      = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await login(email, password)
      // Success toast is fired in AuthContext or parent — no toast here
      navigate('/dashboard', { replace: true })
    } catch (err) {
      // Inline error is sufficient — no addToast on failure
      setError(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="mb-8">
        <div
          className="mb-4 flex h-10 w-10 items-center justify-center rounded-xl border lg:hidden"
          style={{
            backgroundColor: 'rgba(59,130,246,0.1)',
            borderColor:     'rgba(59,130,246,0.2)'
          }}
        >
          <LogIn size={18} strokeWidth={1.75} style={{ color: 'var(--color-primary-blue)' }} aria-hidden="true" />
        </div>
        <h2
          className="text-2xl font-bold"
          style={{ color: 'var(--color-text-primary)' }}
        >
          Welcome back
        </h2>
        <p
          className="mt-1.5"
          style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}
        >
          Sign in to your analyst account
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">

        {/* Email */}
        <div>
          <label
            className="mb-1.5 block text-xs font-semibold"
            style={{ color: 'var(--color-text-secondary)' }}
            htmlFor="login-email"
          >
            Email address
          </label>
          <input
            id="login-email"
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
            autoComplete="email"
            placeholder="analyst@company.com"
            className="w-full rounded-xl border px-4 py-2.5 text-sm outline-none transition-colors duration-150"
            style={{
              backgroundColor: 'var(--color-bg-card)',
              borderColor:     'var(--color-border-card)',
              color:           'var(--color-text-primary)'
            }}
            onFocus={e => e.currentTarget.style.borderColor = 'var(--color-primary-blue)'}
            onBlur={e  => e.currentTarget.style.borderColor = 'var(--color-border-card)'}
          />
        </div>

        {/* Password */}
        <div>
          <label
            className="mb-1.5 block text-xs font-semibold"
            style={{ color: 'var(--color-text-secondary)' }}
            htmlFor="login-password"
          >
            Password
          </label>
          <div className="relative">
            <input
              id="login-password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              placeholder="••••••••"
              className="w-full rounded-xl border px-4 py-2.5 pr-10 text-sm outline-none transition-colors duration-150"
              style={{
                backgroundColor: 'var(--color-bg-card)',
                borderColor:     'var(--color-border-card)',
                color:           'var(--color-text-primary)'
              }}
              onFocus={e => e.currentTarget.style.borderColor = 'var(--color-primary-blue)'}
              onBlur={e  => e.currentTarget.style.borderColor = 'var(--color-border-card)'}
            />
            <button
              type="button"
              onClick={() => setShowPassword(prev => !prev)}
              className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-0.5 transition-colors duration-150"
              style={{ color: 'var(--color-text-muted)' }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--color-text-secondary)'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-muted)'}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword
                ? <EyeOff size={15} strokeWidth={1.75} />
                : <Eye    size={15} strokeWidth={1.75} />
              }
            </button>
          </div>
        </div>

        {/* Inline error */}
        {error && (
          <div
            className="rounded-xl border px-4 py-2.5 text-sm"
            style={{
              borderColor:     'rgba(239,68,68,0.3)',
              backgroundColor: 'rgba(239,68,68,0.08)',
              color:           '#fca5a5'
            }}
            role="alert"
          >
            {error}
            {(error.includes('Invalid') || error.includes('not found')) && (
              <p className="mt-1.5" style={{ fontSize: '12px', color: '#94a3b8' }}>
                Don't have an account?{' '}
                <Link
                  to="/register"
                  style={{ color: 'var(--color-primary-blue)', fontWeight: 600 }}
                >
                  Register here →
                </Link>
              </p>
            )}
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-xl py-2.5 text-sm font-semibold text-white transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50"
          style={{ backgroundColor: 'var(--color-primary-blue)' }}
          onMouseEnter={e => { if (!loading) e.currentTarget.style.backgroundColor = 'var(--color-primary-hover)' }}
          onMouseLeave={e => e.currentTarget.style.backgroundColor = 'var(--color-primary-blue)'}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <span
                className="h-4 w-4 rounded-full border-2 animate-spin"
                style={{ borderColor: 'rgba(255,255,255,0.3)', borderTopColor: 'white' }}
              />
              Signing in...
            </span>
          ) : (
            'Sign in'
          )}
        </button>
      </form>

      <p
        className="mt-6 text-center text-sm"
        style={{ color: 'var(--color-text-muted)' }}
      >
        Don't have an account?{' '}
        <Link
          to="/register"
          className="font-medium transition-colors duration-150"
          style={{ color: 'var(--color-primary-blue)' }}
          onMouseEnter={e => e.currentTarget.style.textDecoration = 'underline'}
          onMouseLeave={e => e.currentTarget.style.textDecoration = 'none'}
        >
          Create one
        </Link>
      </p>
    </div>
  )
}
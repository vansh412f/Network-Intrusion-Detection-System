import { useState, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, CheckCircle, UserPlus } from 'lucide-react'
import { useAuth } from '../../hooks/useAuth'
import { GoogleLogin } from '@react-oauth/google'

function getPasswordStrength(password) {
  if (!password) return { score: 0, label: '', color: '' }

  let score = 0
  if (password.length >= 8)          score++
  if (password.length >= 12)         score++
  if (/[A-Z]/.test(password))        score++
  if (/[0-9]/.test(password))        score++
  if (/[^A-Za-z0-9]/.test(password)) score++

  if (score <= 1) return { score, label: 'Weak',      color: '#ef4444' }
  if (score <= 2) return { score, label: 'Fair',      color: '#fb923c' }
  if (score <= 3) return { score, label: 'Good',      color: '#f59e0b' }
  if (score <= 4) return { score, label: 'Strong',    color: '#10b981' }
  return             { score, label: 'Very Strong', color: '#10b981' }
}

export function RegisterForm({ addToast }) {
  const { register, googleLogin } = useAuth()
  const navigate = useNavigate()

  const [name,         setName]         = useState('')
  const [email,        setEmail]        = useState('')
  const [password,     setPassword]     = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error,        setError]        = useState('')
  const [success,      setSuccess]      = useState('')
  const [loading,      setLoading]      = useState(false)

  const strength = useMemo(() => getPasswordStrength(password), [password])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const message = await register(name, email, password)
      setSuccess(message)
      addToast('Account created — check your email', 'success')
      setName('')
      setEmail('')
      setPassword('')
    } catch (err) {
      setError(err)
      addToast(err, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleGoogleSuccess = async (credentialResponse) => {
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      await googleLogin(credentialResponse.credential)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err)
      addToast(err, 'error')
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div className="flex flex-col items-center gap-5 text-center">
        <div
          className="flex h-16 w-16 items-center justify-center rounded-2xl border"
          style={{
            backgroundColor: 'rgba(16,185,129,0.1)',
            borderColor:     'rgba(16,185,129,0.2)'
          }}
        >
          <CheckCircle
            size={32}
            strokeWidth={1.5}
            style={{ color: '#10b981' }}
            aria-hidden="true"
          />
        </div>
        <div>
          <h2
            className="text-xl font-bold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Check your email
          </h2>
          <p
            className="mt-2 max-w-xs leading-relaxed"
            style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}
          >
            {success}
          </p>
        </div>
        <Link
          to="/login"
          className="rounded-xl px-6 py-2.5 text-sm font-semibold text-white transition-colors duration-150"
          style={{ backgroundColor: 'var(--color-primary-blue)' }}
          onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-primary-hover)'}
          onMouseLeave={e => e.currentTarget.style.backgroundColor = 'var(--color-primary-blue)'}
        >
          Go to Login
        </Link>
      </div>
    )
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
          <UserPlus size={18} strokeWidth={1.75} style={{ color: 'var(--color-primary-blue)' }} aria-hidden="true" />
        </div>
        <h2
          className="text-2xl font-bold"
          style={{ color: 'var(--color-text-primary)' }}
        >
          Create account
        </h2>
        <p
          className="mt-1.5"
          style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}
        >
          Register as a SOC analyst
        </p>
      </div>

      <div className="mb-6 flex justify-center">
        <GoogleLogin
          onSuccess={handleGoogleSuccess}
          onError={() => setError('Google sign up was unsuccessful. Please try again.')}
          theme="outline"
          size="large"
          width="100%"
          text="signup_with"
          shape="rectangular"
        />
      </div>

      <div className="relative mb-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t" style={{ borderColor: 'var(--color-border-card)' }} />
        </div>
        <div className="relative flex justify-center text-xs">
          <span className="px-2" style={{ backgroundColor: 'var(--color-bg-page)', color: 'var(--color-text-muted)' }}>
            Or continue with email
          </span>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">

        <div>
          <label
            className="mb-1.5 block text-xs font-semibold"
            style={{ color: 'var(--color-text-secondary)' }}
            htmlFor="reg-name"
          >
            Full Name
          </label>
          <input
            id="reg-name"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            required
            minLength={2}
            maxLength={50}
            autoComplete="name"
            placeholder="Your name"
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

        <div>
          <label
            className="mb-1.5 block text-xs font-semibold"
            style={{ color: 'var(--color-text-secondary)' }}
            htmlFor="reg-email"
          >
            Email address
          </label>
          <input
            id="reg-email"
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

        <div>
          <label
            className="mb-1.5 block text-xs font-semibold"
            style={{ color: 'var(--color-text-secondary)' }}
            htmlFor="reg-password"
          >
            Password
          </label>
          <div className="relative">
            <input
              id="reg-password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
              placeholder="Min 8 characters"
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
          {password && (
            <div className="mt-2">
              <div className="flex items-center gap-2">
                <div
                  className="h-1 flex-1 overflow-hidden rounded-full"
                  style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}
                >
                  <div
                    className="h-full rounded-full transition-all duration-300"
                    style={{
                      width:           `${(strength.score / 5) * 100}%`,
                      backgroundColor: strength.color
                    }}
                  />
                </div>
                <span
                  className="w-20 text-right text-xs"
                  style={{ color: strength.color }}
                >
                  {strength.label}
                </span>
              </div>
            </div>
          )}
        </div>

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
          </div>
        )}

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
              <span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
              Creating account...
            </span>
          ) : (
            'Create account'
          )}
        </button>
      </form>

      <p
        className="mt-6 text-center text-sm"
        style={{ color: 'var(--color-text-muted)' }}
      >
        Already have an account?{' '}
        <Link
          to="/login"
          className="font-medium transition-colors duration-150"
          style={{ color: 'var(--color-primary-blue)' }}
          onMouseEnter={e => e.currentTarget.style.textDecoration = 'underline'}
          onMouseLeave={e => e.currentTarget.style.textDecoration = 'none'}
        >
          Sign in
        </Link>
      </p>
    </div>
  )
}
import { createContext, useState, useEffect, useCallback, useRef } from 'react'
import axios from 'axios'

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes

const api = axios.create({
  baseURL:         import.meta.env.VITE_API_URL || 'http://localhost:3000',
  withCredentials: true
})

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null)
  const [loading, setLoading] = useState(true)

  const inactivityTimer = useRef(null)

  // ── Logout ───────────────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    try {
      await api.post('/api/auth/logout')
    } catch {
      // Even if request fails, clear local state
    } finally {
      setUser(null)
      if (inactivityTimer.current) {
        clearTimeout(inactivityTimer.current)
        inactivityTimer.current = null
      }
    }
  }, [])

  // ── Inactivity timer ──────────────────────────────────────────────────────
  const resetInactivityTimer = useCallback(() => {
    if (inactivityTimer.current) clearTimeout(inactivityTimer.current)
    inactivityTimer.current = setTimeout(() => {
      logout()
    }, INACTIVITY_TIMEOUT_MS)
  }, [logout])

  // Start/stop activity tracking based on auth state
  useEffect(() => {
    if (!user) {
      if (inactivityTimer.current) {
        clearTimeout(inactivityTimer.current)
        inactivityTimer.current = null
      }
      return
    }

    const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']

    const handleActivity = () => resetInactivityTimer()

    events.forEach(e => window.addEventListener(e, handleActivity, { passive: true }))
    resetInactivityTimer() // Start the timer immediately on login

    return () => {
      events.forEach(e => window.removeEventListener(e, handleActivity))
      if (inactivityTimer.current) clearTimeout(inactivityTimer.current)
    }
  }, [user, resetInactivityTimer])

  // ── Session restore ───────────────────────────────────────────────────────
  useEffect(() => {
    const restoreSession = async () => {
      try {
        const res = await api.get('/api/auth/me')
        if (res.data.success) setUser(res.data.user)
      } catch {
        setUser(null)
      } finally {
        setLoading(false)
      }
    }
    restoreSession()
  }, [])

  // ── Login ────────────────────────────────────────────────────────────────
  const login = useCallback(async (email, password) => {
    try {
      const res = await api.post('/api/auth/login', { email, password })
      if (res.data.success) {
        setUser(res.data.user)
        return res.data.user
      }
    } catch (err) {
      throw err.response?.data?.message || 'Login failed. Please try again.'
    }
  }, [])

  // ── Google Login ─────────────────────────────────────────────────────────
  const googleLogin = useCallback(async (credential) => {
    try {
      const res = await api.post('/api/auth/google', { credential })
      if (res.data.success) {
        setUser(res.data.user)
        return res.data.user
      }
    } catch (err) {
      throw err.response?.data?.message || 'Google authentication failed. Please try again.'
    }
  }, [])

  // ── Register ─────────────────────────────────────────────────────────────
  const register = useCallback(async (name, email, password) => {
    try {
      const res = await api.post('/api/auth/register', { name, email, password })
      if (res.data.success) return res.data.message
    } catch (err) {
      throw err.response?.data?.message || 'Registration failed. Please try again.'
    }
  }, [])

  const value = {
    user,
    loading,
    login,
    googleLogin,
    logout,
    register,
    isAuthenticated: user !== null
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export default AuthContext
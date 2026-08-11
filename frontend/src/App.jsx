import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'

import { useToast } from './hooks/useToast'
import { Toast } from './components/ui/Toast'
import { ProtectedRoute } from './components/layout/ProtectedRoute'

import LandingPage    from './pages/LandingPage'
import DashboardPage  from './pages/DashboardPage'
import AuthPage       from './pages/AuthPage'
import AnalyticsPage  from './pages/AnalyticsPage'
import DocsPage       from './pages/DocsPage'
import ProfilePage    from './pages/ProfilePage'
import UnsubscribedPage from './pages/UnsubscribedPage'

const VITE_SENSOR_URL = import.meta.env.VITE_SENSOR_URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'

export default function App() {
  const { toasts, addToast, removeToast } = useToast()

  // Wake up Render backend on app load
  useEffect(() => {
    fetch(`${API_URL}/health`).catch(() => {})
  }, [])

  return (
    <>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/dashboard" element={<DashboardPage addToast={addToast} sensorUrl={VITE_SENSOR_URL} />} />
        <Route path="/login" element={<AuthPage mode="login" addToast={addToast} />} />
        <Route path="/register" element={<AuthPage mode="register" addToast={addToast} />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/docs" element={<DocsPage />} />
        <Route path="/unsubscribed" element={<UnsubscribedPage />} />
        <Route path="/profile" element={<ProtectedRoute><ProfilePage addToast={addToast} /></ProtectedRoute>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toast toasts={toasts} onRemove={removeToast} />
    </>
  )
}
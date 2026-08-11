import { Navigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'
import { LoginForm } from '../components/auth/LoginForm'
import { RegisterForm } from '../components/auth/RegisterForm'
import { Header } from '../components/layout/Header'
import { Footer } from '../components/layout/Footer'

export default function AuthPage({ mode, addToast }) {
  const { isAuthenticated } = useAuth()

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  return (
    <div
      className="flex flex-col min-h-screen"
      style={{ backgroundColor: 'var(--color-bg-page)' }}
    >
      <Header />

      <div className="flex flex-1">
        <div className="hidden lg:flex lg:w-1/2 flex-col items-center justify-center p-12 relative overflow-hidden">
          <div
            className="absolute inset-0"
            style={{
              background: 'radial-gradient(ellipse at 50% 40%, rgba(59,130,246,0.08) 0%, transparent 70%)'
            }}
          />

          <div
            className="absolute inset-0 border-r"
            style={{ borderColor: 'var(--color-border-card)' }}
          />

          <div className="relative z-10 flex flex-col items-center gap-8 text-center">
            <div
              className="flex h-16 w-16 items-center justify-center rounded-2xl border"
              style={{
                backgroundColor: 'rgba(59,130,246,0.1)',
                borderColor:     'rgba(59,130,246,0.2)',
                boxShadow:       '0 0 40px rgba(59,130,246,0.15)'
              }}
            >
              <Shield
                size={32}
                strokeWidth={1.5}
                style={{ color: 'var(--color-primary-blue)' }}
                aria-hidden="true"
              />
            </div>

            <div>
              <h1
                className="text-2xl font-bold"
                style={{ color: 'var(--color-text-primary)' }}
              >
                NIDS SOC Dashboard
              </h1>
              <p
                className="mt-2 max-w-xs leading-relaxed"
                style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}
              >
                Real-time network intrusion detection powered by XGBoost ML
                with 99.85% accuracy on CIC-DDoS2019 dataset.
              </p>
            </div>

            <div className="flex gap-8">
              {[
                { value: '99.85%', label: 'Accuracy'    },
                { value: '15',     label: 'ML Features'  },
                { value: '<100ms', label: 'Alert Latency' }
              ].map(({ value, label }) => (
                <div key={label} className="flex flex-col items-center gap-1">
                  <span
                    className="text-xl font-bold"
                    style={{ color: 'var(--color-primary-blue)' }}
                  >
                    {value}
                  </span>
                  <span
                    style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}
                  >
                    {label}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap justify-center gap-2">
              {['XGBoost', 'React', 'Node.js', 'MongoDB', 'Socket.io', 'Docker'].map(tech => (
                <span
                  key={tech}
                  className="rounded-full border px-3 py-1"
                  style={{
                    fontSize:        '11px',
                    borderColor:     'var(--color-border-card)',
                    color:           'var(--color-text-muted)'
                  }}
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="flex w-full lg:w-1/2 items-center justify-center p-6 sm:p-12">
          <div className="w-full max-w-md">
            {mode === 'login'
              ? <LoginForm />
              : <RegisterForm addToast={addToast} />
            }
          </div>
        </div>
      </div>

      <Footer />
    </div>
  )
}
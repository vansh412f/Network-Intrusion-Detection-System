import { useState, useEffect, useRef } from 'react'
import { Header } from '../components/layout/Header'
import { Footer } from '../components/layout/Footer'
import { Card } from '../components/ui/Card'
import { DocsSidebar } from '../components/docs/DocsSidebar'
import { CodeBlock } from '../components/docs/CodeBlock'
import { MethodBadge, AuthBadge } from '../components/docs/MethodBadge'
import { SectionTitle } from '../components/docs/SectionTitle'
import { SECTIONS, API_ROUTES, WS_EVENTS, ML_FEATURES } from '../components/docs/DocsData'
import { BookOpen, Globe, Brain, Terminal, Zap, Layers, Shield, Mail, ChevronRight } from 'lucide-react'

const ICON_MAP = { BookOpen, Globe, Brain, Terminal, Zap, Layers, Shield, Mail }
const mappedSections = SECTIONS.map(s => ({ ...s, icon: ICON_MAP[s.icon] || BookOpen }))

function useScrollspy(ids) {
  const [activeId, setActiveId] = useState(ids[0])
  const observersRef = useRef([])

  useEffect(() => {
    observersRef.current.forEach(obs => obs.disconnect())
    observersRef.current = []

    const handleIntersect = (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) setActiveId(entry.target.id)
      })
    }
    const observer = new IntersectionObserver(handleIntersect, { rootMargin: '-80px 0px -55% 0px', threshold: 0 })
    observersRef.current.push(observer)

    ids.forEach(id => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })
    return () => observersRef.current.forEach(obs => obs.disconnect())
  }, [ids])

  return [activeId, setActiveId]
}

export default function DocsPage() {
  const [activeId, setActiveId] = useScrollspy(mappedSections.map(s => s.id))

  const scrollTo = (id) => {
    setActiveId(id)
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--color-bg-page)' }}>
      <Header />
      <div className="mx-auto max-w-7xl px-3 py-6 sm:px-6">
        <div className="flex gap-6">
          <DocsSidebar sections={mappedSections} activeId={activeId} scrollTo={scrollTo} />
          <main className="min-w-0 flex-1 space-y-10">
            
            <div>
              <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text-primary)' }}>Documentation</h1>
              <p style={{ marginTop: '4px', fontSize: '14px', color: 'var(--color-text-muted)' }}>Technical reference for the NIDS SOC Dashboard</p>
            </div>

            <section id="overview" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={BookOpen} title="Overview" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  NIDS SOC Dashboard is a full-stack real-time network intrusion detection system.
                  A Python sensor captures live or simulated network traffic, extracts 15 flow features,
                  and runs them through a trained XGBoost model with 99.85% accuracy on the CIC-DDoS2019 dataset.
                </p>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Detected threats are posted to the Node.js backend, saved to MongoDB Atlas, and pushed
                  to all connected React clients via Socket.io in under 100ms. Email alerts are sent based on severity thresholds, and IPs can be blocked with a 30-minute TTL.
                </p>
                <div className="flex flex-wrap gap-2 pt-2">
                  {['XGBoost', 'React 19', 'Node.js 20', 'MongoDB Atlas', 'Socket.io'].map(tag => (
                    <span key={tag} className="rounded-full border px-2.5 py-1" style={{ fontSize: '11px', borderColor: 'var(--color-border-card)', color: 'var(--color-text-muted)' }}>
                      {tag}
                    </span>
                  ))}
                </div>
              </Card>
            </section>

            <section id="architecture" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Layers} title="Architecture" />
              <Card className="p-5">
                <CodeBlock>
{`Sensor (Python)          Backend (Node.js)         Frontend (React)
─────────────────        ──────────────────         ────────────────
Capture packets          Express 5 REST API         Vite + React 19
  │                        │                          │
Extract 15 features      Socket.io Server           useSocket hook
  │                        │                          │
XGBoost prediction       MongoDB Atlas              Recharts graphs
  │                        │                          │
POST /internal/alert ──► Save + emit ──────────►  WebSocket client
  │                        │                          │
GET /blocklist/ips   ◄── Blocklist cache ◄──────  Real-time updates`}
                </CodeBlock>
              </Card>
              <Card className="p-5">
                <h3 className="mb-3 text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Key Design Decisions</h3>
                <ul className="space-y-2.5">
                  {[
                    'Dashboard is public read — auth required only for block/predict actions',
                    'JWT stored in httpOnly cookie — not localStorage',
                    'Sensor authenticated via shared secret using timingSafeEqual',
                    'Email verification required before login',
                    'Max 50 alerts stored — oldest pruned automatically',
                    'Geo enrichment via ip-api.com — private IPs skipped',
                    'In-memory blocklist cache synced to MongoDB on startup'
                  ].map(item => (
                    <li key={item} className="flex gap-2.5" style={{ fontSize: '13px', color: 'var(--color-text-secondary)' }}>
                      <ChevronRight size={14} strokeWidth={2} style={{ color: 'var(--color-primary-blue)', flexShrink: 0, marginTop: '2px' }} />
                      {item}
                    </li>
                  ))}
                </ul>
              </Card>
            </section>

            <section id="sensor-modes" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Terminal} title="Sensor Modes" subtitle="Real packet capture vs. simulated demo traffic" />
              <Card className="p-5 space-y-4">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  The Python sensor (<code>sensor/sensor.py</code>) runs in one of two modes, selected via the <code> --mode</code> flag. Both modes use the same XGBoost model and post alerts to the backend over authenticated REST endpoints.
                </p>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--color-border-card)' }}>
                    <h3 className="text-sm font-semibold mb-2" style={{ color: '#10b981' }}>Simulate Mode (default)</h3>
                    <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--color-text-secondary)' }}>Generates synthetic network flow features every 2 seconds. Injects a DDoS attack every 90-120 seconds. Safe for CI/CD and demos.</p>
                  </div>
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--color-border-card)' }}>
                    <h3 className="text-sm font-semibold mb-2" style={{ color: '#ef4444' }}>Real Mode</h3>
                    <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--color-text-secondary)' }}>Binds Scapy to your network interface and captures live TCP/UDP packets. Requires admin/root privileges.</p>
                  </div>
                </div>
                <CodeBlock>{`# Simulate mode — safe default\npython sensor.py --mode simulate\n\n# Real mode — requires admin + env config\npython sensor.py --mode real`}</CodeBlock>
              </Card>
            </section>

            <section id="integration" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Globe} title="Website Integration" subtitle="Add DDoS detection to your stack" />
              <Card className="p-5 space-y-4">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  NIDS is designed as a sidecar service — it monitors network traffic at the edge and alerts your SOC dashboard when DDoS patterns are detected.
                </p>
                <CodeBlock>{`Internet → Load Balancer / Reverse Proxy
               ↓
        Your Production Website
               ↓
NIDS Sensor (real mode on public NIC)
               ↓
 Node.js Backend → SOC Dashboard`}</CodeBlock>
              </Card>
            </section>

            <section id="demo" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Globe} title="Live Demo" subtitle="Important notes for the live environment" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  The backend and sensor are deployed on Render's free tier. 
                  <strong> If the dashboard shows "Backend Disconnected", it may take up to 60 seconds for the server to wake up from cold start.</strong>
                </p>
                <div className="flex flex-col gap-2">
                  <a href="https://nids-soc.netlify.app" target="_blank" rel="noreferrer" style={{ color: 'var(--color-primary-blue)', fontSize: '14px', textDecoration: 'underline' }}>Frontend (Netlify)</a>
                  <a href="https://network-intrusion-detection-system-7mh6.onrender.com/health" target="_blank" rel="noreferrer" style={{ color: 'var(--color-primary-blue)', fontSize: '14px', textDecoration: 'underline' }}>Backend Health (Render)</a>
                </div>
              </Card>
            </section>

            <section id="ml" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Brain} title="ML Model" subtitle="XGBoost threat prediction engine" />
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                {[
                  { label: 'Algorithm', value: 'XGBoost 3.2.0' },
                  { label: 'Accuracy',  value: '99.85%' },
                  { label: 'Dataset',   value: 'CIC-DDoS2019' }
                ].map(({ label, value }) => (
                  <Card key={label} className="p-4 text-center">
                    <p className="font-semibold uppercase" style={{ fontSize: '10px', letterSpacing: '0.08em', color: 'var(--color-text-muted)' }}>{label}</p>
                    <p className="mt-2 text-xl font-bold" style={{ color: 'var(--color-text-primary)' }}>{value}</p>
                  </Card>
                ))}
              </div>
              <Card className="p-5 space-y-3">
                <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Severity Mapping & Attack Distribution</h3>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Predictions require ≥80% confidence to be flagged. Severity is mapped as: <strong>CRITICAL (≥99%)</strong>, <strong>HIGH (≥94%)</strong>, <strong>MEDIUM (≥85%)</strong>, <strong>LOW (≥80%)</strong>.
                  <br /><br />
                  The Python sensor runs in two modes: <strong>real</strong> (Scapy packet capture) and <strong>simulate</strong> (synthetic traffic). In simulate mode, attack tiers are distributed as: 40% Low, 30% Medium, 20% High, 10% Critical.
                </p>
              </Card>
              <Card className="overflow-hidden">
                <div className="border-b px-5 py-3" style={{ borderColor: 'var(--color-border-card)' }}>
                  <p className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>15 Input Features</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <tbody>
                      {ML_FEATURES.map(({ name, desc }) => (
                        <tr key={name} className="border-b" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                          <td className="px-4 py-2.5 font-mono" style={{ fontSize: '12px', color: 'var(--color-text-primary)' }}>{name}</td>
                          <td className="px-4 py-2.5" style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{desc}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </section>

            <section id="api" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Terminal} title="API Reference" subtitle="Backend routes (Express 5)" />
              <Card className="overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'var(--color-border-card)' }}>
                        {['Method', 'Route', 'Auth', 'Description'].map(h => (
                          <th key={h} className="px-4 py-2.5 text-left font-semibold uppercase" style={{ fontSize: '10px', letterSpacing: '0.08em', color: 'var(--color-text-muted)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {API_ROUTES.map(({ method, route, auth, desc }) => (
                        <tr key={`${method}-${route}`} className="border-b" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                          <td className="px-4 py-2.5"><MethodBadge method={method} /></td>
                          <td className="px-4 py-2.5 font-mono" style={{ fontSize: '12px', color: 'var(--color-text-primary)' }}>{route}</td>
                          <td className="px-4 py-2.5"><AuthBadge auth={auth} /></td>
                          <td className="px-4 py-2.5" style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>{desc}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </section>

            <section id="websockets" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Zap} title="Socket.io Events" subtitle="Real-time push events from server" />
              <div className="space-y-3">
                {WS_EVENTS.map(({ event, payload, desc }) => (
                  <Card key={event} className="p-4 space-y-2">
                    <span className="font-mono font-bold" style={{ fontSize: '13px', color: 'var(--color-primary-blue)' }}>{event}</span>
                    <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>{desc}</p>
                    <CodeBlock>{payload}</CodeBlock>
                  </Card>
                ))}
              </div>
            </section>

            <section id="auth" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Layers} title="Authentication & Security" subtitle="JWT, cookies, and identity" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Authentication uses <strong>JWT</strong> tokens stored strictly in <strong>httpOnly</strong> cookies to prevent XSS attacks. For security, sessions feature a <strong>5-minute inactivity auto-logout</strong>.
                </p>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Users must verify their email addresses via a token link before logging in. In the database, users are assigned an anonymous <code>userId</code> (e.g., <code>user_a1b2c3</code>), ensuring that analyst emails are never exposed when attributing actions like IP blocking.
                </p>
              </Card>
            </section>

            <section id="blocklist" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Shield} title="Blocklist" subtitle="TTL-based rate-limited IP blocking" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  The blocklist utilizes MongoDB's <code>expireAfterSeconds</code> TTL index to automatically remove blocked IPs after <strong>30 minutes</strong>. 
                  In the demo environment, a cron job refreshes blocks every 25 minutes to prevent them from expiring entirely while the Render server is idle.
                </p>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  To prevent abuse, the <code>/api/blocklist/block</code> endpoint is strictly rate-limited to <strong>3 blocks per 30 minutes</strong> per user. Block actions emit the <code>IPBlocked</code> WebSocket event to instantly update the UI.
                </p>
              </Card>
            </section>

            <section id="email" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Mail} title="Email Alerts" subtitle="Severity-based notification system" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Threat alerts and registration verifications are dispatched using a custom <strong>Google Apps Script Web API</strong>. This architecture completely bypasses strict SMTP blocks on free-tier hosting providers (like Render).
                </p>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  To prevent abuse and exhaustion of the 100 emails/day Google quota, the system enforces a strict <strong>15-minute rate limit per user</strong> for all email notifications. Analysts can customize their threshold to receive alerts (e.g., <code>HIGH</code>, <code>CRITICAL</code>) or <code>NONE</code>.
                </p>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Every email contains a secure, one-click <strong>unsubscribe link</strong> with a signed JWT that instantly sets their threshold to <code>NONE</code> without requiring login.
                </p>
              </Card>
            </section>

            <section id="manual" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Terminal} title="Manual Prediction" subtitle="Live testing against the ML model" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  The manual prediction UI allows analysts to inject 15 arbitrary flow features into the pipeline. 
                  The backend spins up a <code>predict_manual.py</code> subprocess, piping the JSON features via <code>stdin</code> and reading the prediction from <code>stdout</code>.
                </p>
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  To assist testing, the UI offers 5 calibrated templates matching specific confidence ranges: Normal (0-20%), Low (80-84%), Medium (85-93%), High (94-98%), and Critical (99-100%).
                </p>
              </Card>
            </section>

            <section id="running" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Terminal} title="Running Locally" />
              <Card className="p-5 space-y-5">
                {[
                  { step: '1. Clone and install', code: `git clone https://github.com/vansh412f/nids-soc\ncd NIDS_ML\n\n# Backend\ncd backend && npm install\n\n# Frontend\ncd ../frontend && npm install` },
                  { step: '2. Start backend', code: `cd backend\nnode server.js` },
                  { step: '3. Start frontend', code: `cd frontend\nnpm run dev` },
                  { step: '4. Start sensor', code: `cd sensor\npip install -r requirements.txt\npython sensor.py --mode simulate` }
                ].map(({ step, code }) => (
                  <div key={step} className="space-y-2">
                    <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>{step}</h3>
                    <CodeBlock>{code}</CodeBlock>
                  </div>
                ))}
              </Card>
            </section>

            <section id="docker" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Layers} title="Docker Guide" subtitle="Pulling and running official images" />
              <Card className="p-5 space-y-4">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  Both the Node.js backend and Python sensor are containerized and published to Docker Hub automatically by the CI/CD pipeline on every push to main.
                </p>
                <div className="space-y-2">
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Pull directly from Docker Hub</h3>
                  <CodeBlock>{`# Pull the backend image\ndocker pull vansh412f/nids-backend:latest\n\n# Pull the Python sensor image\ndocker pull vansh412f/nids-sensor:latest`}</CodeBlock>
                </div>
                <div className="space-y-2 mt-4">
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Run locally with Docker Compose</h3>
                  <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--color-text-secondary)' }}>We provide a unified <code>docker-compose.yml</code> at the root of the repository that spins up the Frontend, Backend, and Sensor simultaneously.</p>
                  <CodeBlock>{`docker-compose up --build`}</CodeBlock>
                </div>
              </Card>
            </section>

            <section id="kubernetes" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Globe} title="Kubernetes (K8s)" subtitle="Production-grade orchestration manifests" />
              <Card className="p-5 space-y-4">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  While the live demo runs on Netlify and Render, this project is fully architected for enterprise Kubernetes deployments (AWS EKS, Google GKE). The <code>k8s/</code> directory contains all required manifests.
                </p>
                <ul className="space-y-2.5">
                  {[
                    'Deployments: Manages ReplicaSets for the backend and frontend.',
                    'Services: ClusterIP for backend microservice routing.',
                    'Ingress: Uses nginx-ingress-controller with TLS (cert-manager) and WebSocket support annotations.',
                    'ConfigMaps & Secrets: Injects environment variables securely into pods.'
                  ].map(item => (
                    <li key={item} className="flex gap-2.5" style={{ fontSize: '13px', color: 'var(--color-text-secondary)' }}>
                      <ChevronRight size={14} strokeWidth={2} style={{ color: 'var(--color-primary-blue)', flexShrink: 0, marginTop: '2px' }} />
                      {item}
                    </li>
                  ))}
                </ul>
                <CodeBlock>{`# Apply all Kubernetes manifests instantly\nkubectl apply -f k8s/`}</CodeBlock>
              </Card>
            </section>

            <section id="cicd" className="scroll-mt-24 space-y-4">
              <SectionTitle icon={Zap} title="CI/CD Pipeline" subtitle="GitHub Actions workflow" />
              <Card className="p-5 space-y-3">
                <p style={{ fontSize: '14px', lineHeight: '1.7', color: 'var(--color-text-secondary)' }}>
                  A zero-downtime deployment pipeline is defined in <code>.github/workflows/cd.yml</code>. It enforces strict Continuous Integration and Delivery standards.
                </p>
                <div className="grid gap-3 sm:grid-cols-2 mt-2">
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--color-border-card)' }}>
                    <h3 className="text-sm font-semibold mb-2" style={{ color: '#3b82f6' }}>Continuous Integration (CI)</h3>
                    <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--color-text-secondary)' }}>Triggers on every push. It builds the Docker images natively on the runner to ensure no compilation errors exist before deployment.</p>
                  </div>
                  <div className="rounded-lg border p-4" style={{ borderColor: 'var(--color-border-card)' }}>
                    <h3 className="text-sm font-semibold mb-2" style={{ color: '#10b981' }}>Continuous Delivery (CD)</h3>
                    <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--color-text-secondary)' }}>If the build succeeds, it authenticates with Docker Hub using repository secrets and pushes the newly tagged <code>:latest</code> images for public consumption.</p>
                  </div>
                </div>
              </Card>
            </section>

          </main>
        </div>
      </div>
      <Footer />
    </div>
  )
}
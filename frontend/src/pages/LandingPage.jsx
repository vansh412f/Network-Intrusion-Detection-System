import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useInView } from 'react-intersection-observer'
import {
  Brain, Zap, Radio, ShieldOff, Mail, Container,
  Shield, ArrowRight, Terminal, LayoutDashboard
} from 'lucide-react'
import { Header } from '../components/layout/Header'
import { Footer } from '../components/layout/Footer'
import { RadarAnimation } from './landing/RadarAnimation'
import { TypingText }     from './landing/TypingText'
import { AnimatedStat }   from './landing/AnimatedStat'
import { FeatureCard }    from './landing/FeatureCard'
import { HowItWorks }     from './landing/HowItWorks'

// ── Data ─────────────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon:   Brain,
    title:  'XGBoost ML Model',
    desc:   '99.85% accuracy on CIC-DDoS2019 dataset with 15 optimized network flow features.',
    accent: '#3b82f6'
  },
  {
    icon:   Zap,
    title:  'Real-Time Detection',
    desc:   'Sub-100ms threat alerts via WebSocket push from sensor to dashboard.',
    accent: '#f59e0b'
  },
  {
    icon:   Radio,
    title:  'Live Packet Capture',
    desc:   'Python sensor with Scapy captures and classifies network traffic in real-time.',
    accent: '#10b981'
  },
  {
    icon:   ShieldOff,
    title:  'IP Blocklist',
    desc:   'One-click IP blocking with in-memory cache synced across sensor and dashboard.',
    accent: '#ef4444'
  },
  {
    icon:   Mail,
    title:  'Email Alerts',
    desc:   'Severity-based email notifications with configurable thresholds per analyst.',
    accent: '#a78bfa'
  },
  {
    icon:   Container,
    title:  'Docker + K8s Ready',
    desc:   'Containerized microservices with Kubernetes manifests for production deployment.',
    accent: '#22d3ee'
  }
]

const STATS = [
  { label: 'Model Accuracy', value: '99.85', suffix: '%',          accent: '#3b82f6' },
  { label: 'ML Features',    value: '15',     suffix: '',           accent: '#10b981' },
  { label: 'Alert Latency',  value: '<100ms', suffix: '',           accent: '#ef4444', isString: true },
  { label: 'Dataset',        value: 'CIC-DDoS2019', suffix: '',    accent: '#a78bfa', isString: true }
]

const HOW_IT_WORKS = [
  {
    icon:  Terminal,
    title: 'Packet Capture',
    desc:  'Python sensor using Scapy captures live or simulated network traffic and extracts 15 flow features per window.',
    tags:  ['Python 3.11', 'Scapy', 'Simulate / Real']
  },
  {
    icon:  Brain,
    title: 'ML Classification',
    desc:  'XGBoost model trained on CIC-DDoS2019 classifies each flow as benign or malicious with 99.85% accuracy.',
    tags:  ['XGBoost', '99.85% Accuracy', '15 Features']
  },
  {
    icon:  LayoutDashboard,
    title: 'SOC Alert',
    desc:  'Threats are saved to MongoDB, broadcast via Socket.io in <100ms, and displayed on the live SOC dashboard.',
    tags:  ['Socket.io', 'MongoDB Atlas', '<100ms Latency']
  }
]

// ── Main page ─────────────────────────────────────────────────────────────────

export default function LandingPage() {
  const [statsRef,    statsInView]    = useInView({ triggerOnce: true, threshold: 0.3 })
  const [featuresRef, featuresInView] = useInView({ triggerOnce: true, threshold: 0.1 })
  const [howRef,      howInView]      = useInView({ triggerOnce: true, threshold: 0.1 })

  const heroContainer = {
    hidden: {},
    show:   { transition: { staggerChildren: 0.09 } }
  }
  const heroItem = {
    hidden: { opacity: 0, y: 22 },
    show:   { opacity: 1, y: 0, transition: { duration: 0.55, ease: [0.16, 1, 0.3, 1] } }
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--color-bg-page)' }}>

      <Header />

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0"
          style={{
            backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.10) 1px, transparent 1px)',
            backgroundSize:  '28px 28px',
            WebkitMaskImage: 'linear-gradient(to bottom, rgba(0,0,0,0.6) 0%, transparent 90%)',
            maskImage:       'linear-gradient(to bottom, rgba(0,0,0,0.6) 0%, transparent 90%)'
          }}
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0"
          style={{ background: 'var(--gradient-hero)' }}
        />

        <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
          <div className="flex flex-col items-center gap-10 pt-10 pb-16 sm:pt-14 sm:pb-20 lg:flex-row lg:gap-14">

            {/* Left — text */}
            <motion.div
              variants={heroContainer}
              initial="hidden"
              animate="show"
              className="flex flex-1 flex-col items-center text-center lg:items-start lg:text-left"
            >
              <motion.div variants={heroItem}>
                <div
                  className="mb-5 inline-flex items-center gap-2 rounded-full border px-3 py-1.5"
                  style={{
                    borderColor:     'var(--color-border-card)',
                    backgroundColor: 'var(--color-bg-card)'
                  }}
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full animate-pulse-glow flex-shrink-0"
                    style={{ backgroundColor: 'var(--color-live-green)' }}
                  />
                  <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--color-text-muted)' }}>
                    ML-Powered Threat Detection — Live
                  </span>
                </div>
              </motion.div>

              <motion.h1
                variants={heroItem}
                className="text-3xl font-bold leading-tight sm:text-4xl lg:text-5xl"
                style={{ color: 'var(--color-text-primary)' }}
              >
                {'Network Intrusion'.split(' ').map((word, i) => (
                  <motion.span
                    key={i}
                    className="inline-block mr-3"
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0  }}
                    transition={{ duration: 0.5, delay: 0.1 + i * 0.08, ease: [0.16, 1, 0.3, 1] }}
                  >
                    {word}
                  </motion.span>
                ))}
                <br />
                {'Detection System'.split(' ').map((word, i) => (
                  <motion.span
                    key={i}
                    className="inline-block mr-3"
                    style={{ color: 'var(--color-primary-blue)' }}
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0  }}
                    transition={{ duration: 0.5, delay: 0.28 + i * 0.08, ease: [0.16, 1, 0.3, 1] }}
                  >
                    {word}
                  </motion.span>
                ))}
              </motion.h1>

              <motion.p
                variants={heroItem}
                className="mt-5 max-w-lg leading-relaxed"
                style={{ fontSize: '15px', color: 'var(--color-text-secondary)' }}
              >
                A smart security system that watches your network 24/7 and automatically
                flags dangerous traffic — so threats are caught before they cause damage.
              </motion.p>

              <motion.div variants={heroItem} className="mt-8 flex flex-wrap items-center gap-3">
                <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}>
                  <Link
                    to="/dashboard"
                    className="flex items-center gap-2 rounded-lg px-6 py-2.5 text-sm font-semibold text-white"
                    style={{
                      backgroundColor: 'var(--color-primary-blue)',
                      boxShadow:       '0 0 24px rgba(59,130,246,0.25)'
                    }}
                  >
                    Open Dashboard
                    <ArrowRight size={14} strokeWidth={2} />
                  </Link>
                </motion.div>
                <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
                  <Link
                    to="/docs"
                    className="flex items-center gap-2 rounded-lg border px-6 py-2.5 text-sm font-medium"
                    style={{
                      borderColor:     'var(--color-border-card)',
                      backgroundColor: 'var(--color-bg-card)',
                      color:           'var(--color-text-secondary)'
                    }}
                  >
                    Read Docs
                  </Link>
                </motion.div>
              </motion.div>

              <motion.div variants={heroItem} className="mt-7">
                <TypingText />
              </motion.div>
            </motion.div>

            {/* Right — radar */}
            <motion.div
              className="flex flex-1 items-center justify-center"
              initial={{ opacity: 0, scale: 0.88 }}
              animate={{ opacity: 1, scale: 1   }}
              transition={{ duration: 0.7, delay: 0.25, type: 'spring', stiffness: 100, damping: 18 }}
            >
              <RadarAnimation />
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── Stats strip ───────────────────────────────────────────────────── */}
      <section
        ref={statsRef}
        className="border-y"
        style={{
          borderColor:     'var(--color-border-card)',
          backgroundColor: 'rgba(13,20,32,0.6)'
        }}
      >
        <div className="mx-auto grid max-w-6xl grid-cols-2 sm:grid-cols-4">
          {STATS.map((stat, i) => (
            <AnimatedStat
              key={stat.label}
              {...stat}
              index={i}
              inView={statsInView}
            />
          ))}
        </div>
      </section>

      {/* ── Features (20/80 Split) ────────────────────────────────────────── */}
      <section ref={featuresRef} className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
        <div className="flex flex-col gap-8 lg:flex-row lg:items-start lg:gap-10">
          <motion.div
            className="lg:w-1/5 flex flex-col justify-start"
            initial={{ opacity: 0, y: 16 }}
            animate={featuresInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5 }}
          >
            <h2
              className="text-xl font-bold sm:text-2xl"
              style={{ color: 'var(--color-text-primary)' }}
            >
              Built for Security Operations
            </h2>
            <p
              className="mt-3 text-sm leading-relaxed"
              style={{ color: 'var(--color-text-muted)' }}
            >
              Catch network attacks the moment they happen — automatically, accurately, in real time.
            </p>
          </motion.div>

          <div className="lg:w-4/5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((feature, i) => (
              <FeatureCard
                key={feature.title}
                {...feature}
                index={i}
                inView={featuresInView}
              />
            ))}
          </div>
        </div>
      </section>

      {/* ── How It Works (20/80 Split) ────────────────────────────────────── */}
      <section
        ref={howRef}
        className="border-t"
        style={{
          borderColor:     'var(--color-border-card)',
          backgroundColor: 'rgba(13,20,32,0.4)'
        }}
      >
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-start lg:gap-10">
            <div className="order-2 lg:order-1 lg:w-4/5">
              <HowItWorks items={HOW_IT_WORKS} inView={howInView} />
            </div>

            <motion.div
              className="order-1 lg:order-2 lg:w-1/5 flex flex-col justify-start"
              initial={{ opacity: 0, y: 16 }}
              animate={howInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.5 }}
            >
              <h2
                className="text-xl font-bold sm:text-2xl"
                style={{ color: 'var(--color-text-primary)' }}
              >
                How It Works
              </h2>
              <p
                className="mt-3 text-sm leading-relaxed"
                style={{ color: 'var(--color-text-muted)' }}
              >
                Three seamless stages from raw packet capture to analyst threat alerts.
              </p>
            </motion.div>
          </div>
        </div>
      </section>

      <Footer />

    </div>
  )
}
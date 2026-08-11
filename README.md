<div align="center">
  <img src="./frontend/public/favicon.svg" alt="NIDS SOC Logo" width="120" />
  
  # Network Intrusion Detection System (NIDS) & SOC Dashboard
  
  **An enterprise-grade, real-time ML-powered Security Operations Center.**
  
  [![React](https://img.shields.io/badge/React-19.2-blue?style=for-the-badge&logo=react)](https://react.dev)
  [![Vite](https://img.shields.io/badge/Vite-8.0-646CFF?style=for-the-badge&logo=vite)](https://vitejs.dev/)
  [![Node.js](https://img.shields.io/badge/Node.js-Express%205-339933?style=for-the-badge&logo=nodedotjs)](https://nodejs.org/)
  [![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python)](https://www.python.org/)
  [![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=for-the-badge&logo=mongodb)](https://www.mongodb.com/)
  [![XGBoost](https://img.shields.io/badge/XGBoost-1.7-F37626?style=for-the-badge)](https://xgboost.readthedocs.io/)
</div>

<br />

## Table of Contents
- [1. System Overview & Philosophy](#1-system-overview-philosophy)
- [2. System Architecture & Data Flow](#2-system-architecture-data-flow)
- [3. Frontend Deep Dive (React 19 + Vite)](#3-frontend-deep-dive-react-19-vite)
- [4. Backend Deep Dive (Node.js + Express 5)](#4-backend-deep-dive-nodejs-express-5)
- [5. Sensor & ML Engine (Python + Scapy + XGBoost)](#5-sensor-ml-engine-python-scapy-xgboost)
- [6. Security, Fallbacks & Tradeoffs Summary](#6-security-fallbacks-tradeoffs-summary)
- [7. AI Context Guide (Instructions for AI Agents)](#7-ai-context-guide-instructions-for-ai-agents)
- [8. Deployment & Local Setup](#8-deployment-local-setup)
- [9. File-by-File Component Architecture (Frontend)](#9-filebyfile-component-architecture-frontend)
- [10. Complete Database Schema & API Specification](#10-complete-database-schema-api-specification)
- [11. The Machine Learning Engine (Detailed)](#11-the-machine-learning-engine-detailed)
- [12. Security Operations Center (SOC) Playbook](#12-security-operations-center-soc-playbook)
- [13. System Resilience and Failure States](#13-system-resilience-and-failure-states)
- [14. Extending the Application (Developer Guide)](#14-extending-the-application-developer-guide)
- [15. Conclusion](#15-conclusion)
- [16. Comprehensive API Reference Guide](#16-comprehensive-api-reference-guide)
- [17. Comprehensive Data Dictionary](#17-comprehensive-data-dictionary)
- [18. Troubleshooting & Operational Runbook](#18-troubleshooting-operational-runbook)
- [19. Architectural Scaling Plan (Future Roadmap)](#19-architectural-scaling-plan-future-roadmap)
- [20. Code Style and Contribution Guidelines](#20-code-style-and-contribution-guidelines)
- [21. Final System State Machine Review](#21-final-system-state-machine-review)
- [22. UI Design System & Theming Engine](#22-ui-design-system-theming-engine)
- [23. Continuous Integration & Deployment (CI/CD)](#23-continuous-integration-deployment-cicd)
- [24. Database Backup & Disaster Recovery](#24-database-backup-disaster-recovery)
- [25. Final Note for AI Assistants (Context Initialization)](#25-final-note-for-ai-assistants-context-initialization)

---

## 1. System Overview & Philosophy

The NIDS SOC Dashboard is a comprehensive, full-stack cybersecurity application designed to ingest real-time network traffic, evaluate it against a trained XGBoost machine learning model, and broadcast threats to a web-based Security Operations Center (SOC) dashboard. 

### Core Objectives
1. **Accurate Detection:** Utilize a pre-trained XGBoost model (trained on the CIC-DDoS2019 dataset) to differentiate benign traffic from DDoS/malicious traffic based on 15 specific network flow features.
2. **Real-time Responsiveness:** Deliver sub-second latency from the moment a packet is flagged by the Python sensor to the moment the UI pulses red on the analyst's screen, achieved via WebSockets (`socket.io`).
3. **Premium Aesthetics & UX:** Provide a dark-mode, glassmorphism-inspired UI with high-performance micro-animations (`framer-motion`), making the SOC look and feel like a state-of-the-art enterprise tool rather than a standard admin template.
4. **Resilience & Fallbacks:** Implement robust rate-limiting, deterministic fallbacks for third-party APIs (like geo-location), and memory-efficient architectures to prevent OOM errors on free-tier hosting (e.g., Render).

### The Technology Stack
- **Frontend:** React 19, Vite, React Router v6, TailwindCSS v4, Framer Motion, Recharts, React Simple Maps, @react-oauth/google.
- **Backend:** Node.js, Express 5, Socket.io, Mongoose (MongoDB Atlas), JWT, Nodemailer, bcryptjs, google-auth-library.
- **Sensor/ML Engine:** Python 3.11+, Scapy, XGBoost, Pandas, Numpy, Joblib.

---

## 2. System Architecture & Data Flow

The system is strictly divided into three decoupled layers. They communicate over HTTP REST and WebSockets.

### 2.1 Layer Breakdown

1. **The Python Sensor (`sensor.py`)**
   - **Role:** The data ingestor and inference engine.
   - **Environment:** Runs locally or on a dedicated edge node. It requires root privileges to sniff packets via Scapy (if in `real` mode).
   - **Output:** Posts JSON payloads to the Backend's internal REST API (`/api/internal/alert` and `/api/internal/stats`).

2. **The Node.js Backend (`server.js`)**
   - **Role:** The central nervous system. It handles database persistence, authentication, rate limiting, and real-time broadcasting.
   - **Environment:** Hosted on Render (or similar PaaS).
   - **Output:** Emits WebSocket events (`ThreatDetected`, `LiveStats`, `IPBlocked`, `IPUnblocked`) to all connected frontend clients.

3. **The React Frontend (`App.jsx`)**
   - **Role:** The visualization layer.
   - **Environment:** Served via static hosting, runs in the client's browser.
   - **Output:** Consumes WebSocket events to mutate React state, rendering D3/Recharts graphs, framer-motion animations, and interactive threat tables.

### 2.2 The Complete Data Flow Lifecycle

**Step 1: Packet Capture & Feature Extraction**
The `sensor.py` script captures network packets in 2-second overlapping windows. It aggregates packets by flow (Source IP <-> Destination IP). Once a window closes, it calculates 15 statistical features (e.g., `Flow IAT Mean`, `Bwd Packets/s`, `ACK Flag Count`).

**Step 2: ML Inference**
The features are formatted into a Pandas DataFrame and passed to the loaded XGBoost model (`nids_model.pkl`). The model outputs a probability (0.0 to 1.0). If the probability exceeds the `ALERT_THRESHOLD` (0.80), the flow is classified as a threat.

**Step 3: Internal API Post**
The sensor immediately issues an HTTP POST request to the backend at `/api/internal/alert`. This endpoint is secured using a shared secret defined in the `.env` file (`X-Sensor-Secret`). This prevents unauthorized endpoints from spamming the DB with fake alerts.

**Step 4: Persistence & Broadcasting**
The Express backend receives the payload, validates it using `zod`, computes the severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL` based on probability percentages), and saves it to MongoDB. Immediately after successful save, it calls `io.emit('ThreatDetected', data)`. 

*Tradeoff Note:* The backend does not wait for the email service to finish sending threat alerts before emitting the WebSocket event. Email sending is fire-and-forget to maintain strict real-time UI performance.

**Step 5: Frontend State Mutation**
The frontend `useSocket.js` hook catches the `ThreatDetected` event. It limits the local state array to a maximum of 500 alerts (to prevent browser memory leaks). It enriches the alert with Geo-location data (via `geoUtils.js`) and updates the React Context. The UI re-renders, triggering `framer-motion` layout animations, pulsing severity badges, and plotting new dots on the World Map.

---

## 3. Frontend Deep Dive (React 19 + Vite)

The frontend is not just a UI; it is a complex state machine dealing with rapid, asynchronous data streams.

### 3.1 Styling Architecture (Tailwind CSS + CSS Variables)
We intentionally avoided littering the React components with raw hex codes. All colors are mapped to CSS variables in `frontend/src/index.css`.
- **Backgrounds:** `var(--color-bg-page)`, `var(--color-bg-card)`, `var(--color-bg-elevated)`.
- **Text:** `var(--color-text-primary)`, `var(--color-text-secondary)`, `var(--color-text-muted)`.
- **Borders:** `var(--color-border-card)`, `var(--color-border-hover)`.
- **Severity Mapping:** Specific variables for `low`, `medium`, `high`, `critical` that control both the background tint (`rgba`) and the solid border/text colors.

*AI Instruction:* When creating new components, you MUST use these CSS variables. Do not use generic Tailwind classes like `bg-gray-800` or `text-white`. Use `style={{ backgroundColor: 'var(--color-bg-card)' }}`.

### 3.2 State Management (`useSocket.js` & `AuthContext.jsx`)
- **`AuthContext.jsx`:** Manages the JWT lifecycle. Because the JWT is stored in an `httpOnly` cookie, the frontend cannot read it. Instead, the context hits `/api/auth/me` on mount. It also implements an inactivity timer. If the user does not move the mouse or press a key for 5 minutes (300,000ms), they are automatically logged out for security purposes.
- **`useSocket.js`:** The most critical hook in the app. It initializes `socket.io-client`. It listens for 4 events. 
  - *Tradeoff:* We cap `alerts` at 500 items. If a massive DDoS attack sends 10,000 alerts, keeping them all in the React DOM would crash the browser. We slice the array: `setAlerts(prev => [enrichedAlert, ...prev].slice(0, 500))`.

### 3.3 Geo-Enrichment Mechanism
When a new IP is detected, `geoUtils.js` attempts to map it to a physical location.
- **Primary Mechanism:** Hits `http://ip-api.com/json/`.
- **Fallback Mechanism:** `ip-api.com` restricts free tiers to 45 requests per minute. If the rate limit is hit, the application gracefully degrades to a deterministic hash function `mockGeoData(ip)`. This ensures that even during a heavy DDoS attack, the World Map continues to populate with visual data without throwing 429 errors in the console.

### 3.4 Animation Philosophy (Framer Motion)
Animations are used to convey state changes without overwhelming the user.
- **Layout Animations:** The `ThreatTable` uses `<motion.tr layout>` so that when new rows are added, existing rows slide down smoothly rather than snapping.
- **AnimatePresence:** Used for modals (like the Manual Input Modal) and blocklist items, allowing them to fade/slide out smoothly when unmounted.
- **Performance Tradeoff:** Animations are disabled for elements that update more than 10 times a second (e.g., the raw terminal logs) to save CPU cycles.

### 3.5 Core Pages and Components
- **`DashboardPage.jsx`:** The primary grid. Orchestrates the layout of `StatCard`s, the `ThreatTable`, the `ThreatOriginMapSection`, and the `BlocklistPanel`.
- **`AnalyticsPage.jsx`:** Heavy on `recharts`. Contains `SeverityDonutChart`, `ThreatTypesBarChart`, and `TopIPsTable`. It calculates statistics on the fly based on the local 500-alert window.
- **`ManualInputModal.jsx`:** A complex form allowing analysts to manually test the XGBoost model. It validates 15 features, ensuring no negative values, and provides 5 pre-calibrated templates (Normal, Low, Medium, High, Critical) that guarantee specific probability ranges based on our empirical testing.



---

## 4. Backend Deep Dive (Node.js + Express 5)

The backend acts as the secure middleman between the Python sensor and the frontend clients. It is built for asynchronous high throughput.

### 4.1 Routing & Endpoints
The Express app is structured into modular routes:
- **`alert.js`:** Handles `/api/internal/alert` (incoming threats), `/api/internal/stats` (incoming traffic metrics), `/api/alerts` (frontend fetching historical data), and `/api/predict/manual` (invoking the python script for manual testing).
- **`auth.js`:** Handles standard auth `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, and email verification links.
- **`blocklist.js`:** Handles `/api/blocklist/block`, `/api/blocklist/unblock`, and `/api/blocklist/ips`.

### 4.2 Real-time Broadcasting (Socket.io)
We use `Socket.io` rather than native WebSockets for built-in reconnection logic and broadcasting capabilities.
- When an alert is saved, the backend does **not** target a specific user. It calls `io.emit()` which broadcasts to every single active tab and connected client globally.
- *Tradeoff:* For a multi-tenant SaaS, you would use `io.to('company_room').emit()`. For this single-SOC instance, global broadcast is intentionally used for simplicity and speed.

### 4.3 Security & Rate Limiting
Because this system deals with network security, the backend itself must be resilient.
- **JWT & Cookies:** Tokens are signed using `JWT_SECRET` and stored exclusively in `httpOnly`, `sameSite: strict` cookies. The frontend cannot access `document.cookie` to read the token, immunizing the app against XSS attacks stealing session tokens.
- **Helmet:** Express uses `helmet()` to set standard HTTP security headers (HSTS, Content-Security-Policy, X-Frame-Options).
- **Express-Rate-Limit:** 
  - Login: Max 10 attempts per 15 minutes.
  - Registration: Max 5 attempts per hour.
  - Manual Prediction: Max 10 per 15 minutes (to prevent CPU exhaustion from spawning python processes).
  - Blocklist Actions: Max 3 per 30 minutes (to prevent demo abuse).
- **Internal Sensor Secret:** All traffic from the Python sensor must include the `X-Sensor-Secret` header. This is validated using a timing-safe string comparison (`crypto.timingSafeEqual`) to prevent timing attacks.

### 4.4 MongoDB Schemas & TTL Caching
We use Mongoose for ODM.
- **Alert Schema:** Stores IPs, probabilities, extracted features, and severity. Crucially, it has an index: `{ createdAt: 1 }, { expireAfterSeconds: 2592000 }`. MongoDB will automatically delete alerts older than 30 days.
- **Blocklist Schema:** Stores blocked IPs. It has a TTL index of 30 minutes (`expireAfterSeconds: 1800`).
- **In-Memory Cache:** To prevent hitting the database for every single packet that the sensor processes, the backend maintains a JavaScript `Set()` called `blockedIPsCache`. When the sensor asks for blocked IPs (`/api/blocklist/ips`), it returns this Set in memory (0ms latency) instead of querying Mongo. The Set is synchronized with Mongo whenever an IP is blocked or unblocked.

### 4.5 Child Process Orchestration (Manual Prediction)
When a user submits a manual prediction via the UI, the Node backend must ask Python for the answer.
- It uses `child_process.spawn()` to execute `sensor/predict_manual.py`.
- It pipes the 15 features as a JSON string to the python script's `stdin`.
- It reads the result from `stdout`.
- *Fallback Mechanism:* If the python script hangs (e.g., infinite loop, bad input), a 15-second `setTimeout` kills the child process via `python.kill()` and returns a `504 Gateway Timeout` to the frontend, preventing the Express worker thread from hanging permanently.

### 4.6 Email Service Integration
The backend uses `nodemailer` connected to a Gmail SMTP server.
- **Verification:** When a user registers, they receive a JWT-signed verification link. They cannot log in until `verified` is true.
- **Threat Alerts:** If a `CRITICAL` alert fires, the system queries the DB for all verified users whose `min_severity_for_email` allows it, and fires off an HTML-formatted email.
- **Unsubscribe Logic:** Every email contains a 1-click unsubscribe link (signed via JWT). Clicking it sets the user's email preference to `NONE` without requiring them to log in.

---

## 5. Sensor & ML Engine (Python + Scapy + XGBoost)

The `sensor.py` script is the tip of the spear. It is a highly optimized packet sniffer and feature extractor.

### 5.1 Operating Modes
The sensor accepts a `--mode` argument.
- **`--mode real`:** Binds to a physical network interface (e.g., `eth0`, `Wi-Fi`) using Scapy's `AsyncSniffer`. It inspects actual TCP/UDP packets on the network.
- **`--mode simulate`:** The default mode for demonstrations. It generates highly realistic synthetic traffic based on strict statistical distributions. It maintains a ratio of roughly 40% Low, 30% Medium, 20% High, and 10% Critical attacks.

### 5.2 Feature Extraction Logic (The 2-Second Window)
To classify a DDoS attack, looking at a single packet is useless. You must look at a "Flow" (a stream of packets between two IPs) over a window of time.
- The sensor aggregates packets into a dictionary keyed by IP.
- Every `WINDOW_SECONDS` (default: 2), a separate thread locks the dictionary, copies the data, and clears the buffer.
- For each flow containing more than `MIN_PACKETS` (10), it calculates:
  - `Flow Duration` (microseconds)
  - `IAT (Inter-Arrival Time)`: Mean, Max, Std (critical for detecting automated botnet rhythms vs human erratic rhythms).
  - `Packet Lengths`: Max, Min, Total.
  - `Flags`: Specifically, the `ACK Flag Count`.
- *Performance Tradeoff:* Scapy is notoriously slow in pure Python. To compensate, we do not store full packet payloads. We immediately extract lengths and timestamps, discarding the rest of the payload to save RAM.

### 5.3 XGBoost Pipeline
The Machine Learning model was trained offline on the CIC-DDoS2019 dataset.
- **Model:** `nids_model.pkl` (XGBoost Classifier).
- **Encoder:** `nids_encoder.pkl` (LabelEncoder for the ACK flag, which is categorical '0' or '1').
- **Metadata:** `nids_metadata.json` (Ensures the pandas DataFrame columns are ordered *exactly* as they were during training, preventing silent feature-mismatch errors).
- **Thresholding:** The model uses `.predict_proba()`. Even if the model predicts '1' (Malicious), we only trigger an alert if the probability strictly exceeds `ALERT_THRESHOLD` (0.80). This aggressively reduces false positives in an enterprise environment.

### 5.4 The "ACK Flag + Packet Length" Super-Additive Interaction
Through empirical testing (documented in `ManualInputData.js`), we discovered the specific triggers for the XGBoost model.
- Setting `ACK Flag Count = 1` combined with a high `Fwd Packets Length Total` skyrockets the malicious probability to 99.99%.
- Lowering the packet lengths while maintaining a high packets-per-second rate drops the probability to the 80%-90% range (LOW/MEDIUM severity). 
- This understanding allows the `simulate` mode to generate incredibly precise synthetic attacks that fall exactly into the desired severity buckets.



---

## 6. Security, Fallbacks & Tradeoffs Summary

Every complex system requires compromises. Here is a summary of the explicit tradeoffs made in this architecture:

### 6.1 State and Memory
- **Browser Memory:** By capping the frontend alerts array at 500 items, we guarantee the browser will not crash during a massive flood of WebSocket events. Older alerts fall off the UI. If historical data is needed, the user can refresh the page to hit the `/api/alerts` endpoint.
- **Database Storage:** Capping the MongoDB storage at 500 items (via the `trimAlerts` function) keeps the database query times under 10ms. A true enterprise system would pipe old alerts to a cold-storage data lake (e.g., AWS S3 or Snowflake) rather than deleting them, but for this application, bounding the DB size guarantees perpetual performance on free-tier hosting.

### 6.2 Rate Limiting the Analysts
- **Demo Abuse Protection:** We limit IP blocking to 3 actions per 30 minutes. Why? Because in a public demo environment, malicious users might try to write thousands of entries to the blocklist database, exhausting storage and API limits.
- **ML CPU Protection:** The `predict_manual.py` script spins up a heavy Python runtime and loads a serialized XGBoost model into RAM. Doing this concurrently 100 times would crash the Node.js server. Thus, manual predictions are heavily rate-limited.

### 6.3 The "Cold Start" Reality
- The backend is hosted on Render's free tier. If no traffic hits the server for 15 minutes, the instance spins down. 
- When the first user connects, it takes ~60 seconds for the Node.js server to boot up, connect to MongoDB, and accept WebSocket connections. 
- **Frontend Fallback:** The frontend handles this gracefully. The `BackendLog.jsx` panel will explicitly show `[Socket.io] Disconnected` and will automatically reconnect once the server wakes up. The UI does not freeze or throw unhandled exceptions during this blackout.

---

## 7. AI Context Guide (Instructions for AI Agents)

**If you are an AI assistant (like Claude, GPT-4, or Gemini) reading this file, you must adhere to the following rules when modifying this codebase:**

1. **CSS Variables are Mandatory:** Do NOT add raw hex codes to React components. If you are instructed to create a new widget, you must use `var(--color-bg-card)`, `var(--color-border-card)`, `var(--color-text-primary)`, etc. If a new color is fundamentally required, define it in `index.css` first.
2. **Animation Restraint:** Do NOT add `framer-motion` layout animations to lists that update rapidly (e.g., the `SensorLog` or `BackendLog`). These components receive updates multiple times a second; animating them will cause severe CPU thrashing. Reserve animations for the `ThreatTable`, `StatCard` mounting, and modals.
3. **API Contracts:** The frontend expects the backend to return `{ success: true, ...data }` or `{ success: false, message: "...", errors: {} }`. Do not alter this standard JSON envelope.
4. **Environment Variables:** The frontend uses `import.meta.env.VITE_BACKEND_URL`. The backend uses `process.env.CLIENT_URL_PROD`. Do not mix Node.js `process.env` syntax into Vite React files.
5. **No Synthetic State Mismatches:** If you modify `ThreatDetected` in `useSocket.js`, you MUST also modify the manual prediction response in `ManualInputModal.jsx`, as they both feed into the same alert array. Maintain schema parity.

---

## 8. Deployment & Local Setup

### 8.1 Prerequisites
- Node.js v20+
- Python 3.11+
- MongoDB Atlas Account (or local MongoDB)

### 8.2 Environment Variables

**Backend (`backend/.env` or root `.env`)**
```env
PORT=3000
NODE_ENV=development
MONGO_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/nids
JWT_SECRET=super_secure_random_string_here
JWT_EXPIRES_IN=7d
SENSOR_SECRET=shared_secret_between_python_and_node

# Allowed frontend URLs for CORS
CLIENT_URL_DEV=http://localhost:5173
CLIENT_URL_PROD=https://your-frontend-domain.com

# Email config (for alerts/verification)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_specific_password
EMAIL_FROM="NIDS SOC <your_email@gmail.com>"
```

**Frontend (`frontend/.env`)**
```env
VITE_BACKEND_URL=http://localhost:3000
```

**Sensor (`.env`)**
```env
BACKEND_URL=http://localhost:3000
SENSOR_SECRET=shared_secret_between_python_and_node
INTERFACE=eth0      # Change based on OS (e.g., Wi-Fi on Windows)
MY_IP=192.168.1.100 # Your local machine's IP
PYTHON_PATH=python  # Path to python executable
```

### 8.3 Running Locally

**1. Install Dependencies**
```bash
# Backend
cd backend && npm install

# Frontend
cd frontend && npm install

# Python Sensor (Recommended: use a virtual environment)
cd sensor
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

**2. Start the Backend**
```bash
cd backend
npm run dev
# Listens on http://localhost:3000
```

**3. Start the Frontend**
```bash
cd frontend
npm run dev
# Listens on http://localhost:5173
```

**4. Start the Sensor (Simulate Mode)**
```bash
cd sensor
python sensor.py --mode simulate
# Begins generating traffic and sending to the backend
```

**5. Start the Sensor (Real Mode)**
*(Requires admin/root privileges to sniff interfaces)*
```bash
cd sensor
sudo python sensor.py --mode real
```

---

<div align="center">
  <p style="color: #64748b; font-size: 12px; margin-top: 40px;">
    <i>Designed and engineered as a comprehensive demonstration of real-time full-stack ML capabilities.</i><br/>
    <i>Powered by XGBoost and React 19.</i>
  </p>
</div>


---

## 9. File-by-File Component Architecture (Frontend)

To truly understand the frontend without looking at the code, one must understand the exact component hierarchy and data passing logic.

### 9.1 Root & Routing
- **`main.jsx` & `App.jsx`**: The application roots. `App.jsx` handles `react-router-dom` configuration with protected routes. It wraps the entire application in the `AuthProvider` and `ToastProvider`. The `SocketProvider` is only active within authenticated routes to prevent unauthorized WebSocket handshakes.
- **`index.css`**: Defines Tailwind v4 config inline using `@theme` and `@plugin`. It sets all CSS variables mapped to the design system.

### 9.2 Contexts and Hooks
- **`AuthContext.jsx`**: Provides `user`, `login()`, `logout()`, `register()`, and `loading`. It includes an inactivity timer. If `Date.now() - lastActivity > 300000ms`, it automatically triggers `logout()`.
- **`useSocket.js`**: The central data ingestion hook. It maintains:
  - `isConnected`: Boolean reflecting the Socket.io status.
  - `alerts`: Array of the latest 500 alert objects.
  - `liveStats`: Array of the latest 200 window statistics objects.
  - `topIPs`: A derived array that maps `alerts` by IP and counts them, sorting in descending order.
  - `geoCount`: An integer tracking how many IPs were successfully mapped to a country via `geoUtils.js`.

### 9.3 Dashboard Page Components (`/components/dashboard/`)
The `DashboardPage.jsx` orchestrates these heavily interactive components:
- **`StatCard.jsx` & `LiveStatsPanel.jsx`**: Displays real-time packet processing rates. `StatCard` uses `framer-motion`'s `useMotionValue` and `animate` to create smooth count-up animations for numbers like total flows and packets, avoiding hard jumps in the UI.
- **`ThreatTable.jsx`**: The core data table. It maps over `alerts`. 
  - To maintain 60 FPS, the rows are virtualized or sliced.
  - It uses `<AnimatePresence>` for new rows sliding down.
  - Contains sub-components like `SeverityBadge.jsx` (which pulses for CRITICAL alerts) and `ConfidenceCell.jsx` (which renders a colored progress bar indicating the exact XGBoost probability).
- **`BlocklistPanel.jsx`**: Displays the active MongoDB blocklist. It receives the blocklist array and allows analysts to click "Unblock". It has an animated "Expires in X min" indicator derived from the backend's TTL.

### 9.4 Analytics Page Components (`/components/analytics/`)
The `AnalyticsPage.jsx` aggregates the data held in `useSocket.js` using `recharts` for visualization.
- **`SessionSummaryCard.jsx`**: Shows total threats, unique IPs, and a visual bar of what percentage of threats have been actively blocked by the analyst.
- **`SeverityDonutChart.jsx`**: A `PieChart` (from Recharts) binding to the `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` counts.
- **`ThreatTypesBarChart.jsx`**: Currently charts `DDoS` vs `Manual-Test` threats.
- **`TopIPsTable.jsx`**: Renders a leaderboard of attacking IPs. It includes a mini severity stacked bar under each IP to show the composition of their attacks (e.g., 50% High, 50% Critical).
- **`TopAttackerCard.jsx`**: Isolates the single most aggressive IP from the leaderboard, highlights it in red, and displays its geographical location prominently.

### 9.5 Logging Panels (`/components/logs/`)
- **`LogPanel.jsx`**: A generic macOS-terminal-styled window component. It supports syntax highlighting and auto-scrolling to the bottom as new logs arrive.
- **`SensorLog.jsx`**: Simulates the standard output of the Python sensor. It listens to the `liveStats` array and synthetically injects "Benign" flow logs alongside the actual "Malicious" alert logs, providing a visceral sense of the traffic being processed.
- **`BackendLog.jsx`**: Listens to WebSocket connection states, MongoDB saves, and emit actions, outputting a chronological trace of the backend's internal operations.

### 9.6 Modals (`/components/modals/`)
- **`DemoVideoModal.jsx`**: Simply embeds a YouTube iframe showing the system running in `real` mode, complete with backdrop blur.
- **`ManualInputModal.jsx`**: 
  - Imports `FEATURE_GROUPS` and `TEMPLATES` from `ManualInputData.js`.
  - Groups the 15 features into logical sections (Timing, Packet Rate, Packet Size, Counts).
  - Maintains state for `features`, `errors`, and `warnings`. It validates against documented `min`/`max` values and warns the user if they input biologically impossible network rates.
  - Calls `api.predictManual(features)` and renders the result via a Toast notification.



---

## 10. Complete Database Schema & API Specification

The backend acts as the source of truth, enforcing data integrity before it ever touches MongoDB or the WebSocket broadcast stream.

### 10.1 MongoDB Schemas (Mongoose)

#### A. User Schema (`models/User.js`)
- `userId`: String (Unique, Auto-generated 6-character alphanumeric).
- `name`: String (2-50 chars).
- `email`: String (Unique).
- `password`: String (Hashed via `bcryptjs` with salt round 12).
- `email_notifications`: Boolean (Default: true).
- `min_severity_for_email`: Enum (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Default: `LOW`.
- `role`: Enum (`analyst`, `admin`).
- `verified`: Boolean.
- **Hooks:** Uses a `pre('save')` hook to automatically hash the password and generate the unique `userId` if it doesn't exist.

#### B. Alert Schema (`models/Alert.js`)
- `source_ip`: String.
- `probability`: Number (0-100).
- `threat_type`: String (Enum: `DDoS`, `Manual-Test`).
- `features`: Mixed Object (Stores the exact 15 JSON features received from the sensor for forensic playback).
- `severity`: String (Enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `blocked`: Boolean (Default: false).
- `sensor_timestamp`: Date.
- **Indexes:** 
  - `{ source_ip: 1 }` for fast IP lookups.
  - `{ createdAt: -1 }` for sorting.
  - `{ createdAt: 1 }` with `expireAfterSeconds: 2592000` (TTL 30 days) to prevent free-tier DB quota exhaustion.

#### C. Blocklist Schema (`models/Blocklist.js`)
- `ip`: String (Unique).
- `blockedBy`: String (Tracks which analyst blocked it).
- `reason`: String (Max 200 chars).
- **Indexes:** 
  - `{ createdAt: 1 }` with `expireAfterSeconds: 1800` (TTL 30 minutes).

### 10.2 REST API Specification

#### Authentication Endpoints (`/api/auth`)
- **`POST /register`**: Validates via Zod. Creates unverified User. Sends JWT-signed verification email via Nodemailer. Rate-limited to 5 per hour.
- **`POST /login`**: Validates credentials. Sets `httpOnly` cookie with JWT. Returns User object. Rate-limited to 10 per 15 minutes.
- **`POST /logout`**: Clears the `token` cookie.
- **`GET /me`**: Returns the current user profile based on the JWT payload. Requires authentication.
- **`PATCH /me`**: Allows updating `name`, `email_notifications`, and `min_severity_for_email`.
- **`GET /verify?token=`**: Verifies the email token, sets `user.verified = true`, and returns an HTML success page.
- **`GET /unsubscribe?token=`**: Sets `min_severity_for_email` to `NONE` using a JWT in the URL query, returning an HTML redirect.

#### Alert Endpoints (`/api`)
- **`POST /internal/alert`**: The sensor ingestion endpoint. Requires `X-Sensor-Secret`. Saves to MongoDB, calculates severity, triggers email dispatch via Nodemailer, and emits `ThreatDetected` to Socket.io.
- **`POST /internal/stats`**: Requires `X-Sensor-Secret`. Validates traffic metrics and emits `LiveStats` via Socket.io. Does NOT save to MongoDB (too high volume).
- **`GET /alerts`**: Fetches the last 500 alerts from MongoDB, stripping the bulky `features` object to reduce payload size.

#### Blocklist Endpoints (`/api/blocklist`)
- **`GET /ips`**: Requires `X-Sensor-Secret`. Used by the Python sensor. It reads directly from the backend's in-memory `blockedIPsCache` Set, allowing the sensor to download the blocklist in 0ms without hitting MongoDB.
- **`GET /`**: Returns the full blocklist array from MongoDB with metadata (who blocked it, when).
- **`POST /block`**: Requires Auth. Adds IP to DB and `blockedIPsCache`. Updates any existing alerts in the DB with `blocked: true`. Emits `IPBlocked`. Rate-limited to 3 per 30 minutes.
- **`POST /unblock`**: Requires Auth. Removes IP from DB and cache. Reverts `blocked: false` on past alerts. Emits `IPUnblocked`.

### 10.3 The Manual Prediction Proxy Route
- **`POST /predict/manual`**: 
  - Validates all 15 features strictly via Zod. 
  - Spawns a child process (`spawn(python, [predict_manual.py])`).
  - Pipes features into `stdin`.
  - Sets a 15-second `setTimeout` to kill the process if it hangs.
  - Parses JSON from `stdout`.
  - If the prediction is a threat, it loops back and calls the internal `saveAndEmitAlert` function, spoofing the source IP as `MANUAL:<userId>`.



---

## 11. The Machine Learning Engine (Detailed)

This project does not rely on static signature matching (like Snort or Suricata). It relies on behavioral anomaly detection via XGBoost.

### 11.1 The CIC-DDoS2019 Dataset Connection
The model (`nids_model.pkl`) was trained on the CIC-DDoS2019 dataset, heavily preprocessed to avoid overfitting. 
- The original dataset contained over 80 features. Through feature importance analysis, this was reduced to exactly 15 features.
- Why 15? Because calculating 80 statistical features per flow in real-time in Python is computationally impossible at line-rate. 15 features strike the optimal balance between accuracy (99%+) and computation speed.

### 11.2 The 15 Features Defined
1. **Flow Duration (μs)**: Total time between the first and last packet of a flow.
2. **Flow IAT (Inter-Arrival Time) Mean/Max/Std**: The statistical distribution of the time between packets. *Critical for distinguishing automated bots (low Std) from human browsing (high Std).*
3. **Fwd/Bwd Packets/s**: Packet transmission rates.
4. **Flow Packets/s & Flow Bytes/s**: Overall throughput.
5. **Packet Length Max/Min/Total**: The size of the payloads. *Botnets often use fixed-size payloads or zero-byte payloads.*
6. **Total Backward Packets & Fwd Act Data Packets**: Identifies asymmetrical flows (e.g., a SYN flood has zero backward packets).
7. **ACK Flag Count**: Categorical (0 or 1). Indicates if the flow relies on acknowledgement. *A SYN flood has an ACK count of 0, making it a massive indicator of malice.*

### 11.3 Feature Encoding & Metadata Alignment
- XGBoost requires strict column ordering. The `nids_metadata.json` file stores the `final_column_order`.
- The `predict_manual.py` and `sensor.py` scripts explicitly build Pandas DataFrames and reorder the columns to match `final_column_order`.
- The `ACK Flag Count` is passed through a `LabelEncoder` (`nids_encoder.pkl`), transforming '0'/'1' into one-hot encoded columns `ACK Flag Count_0` and `ACK Flag Count_1`.

### 11.4 Threat Emulation Mechanics (`sensor.py` simulate mode)
The `generate_attack_features()` function in the sensor is an engineering marvel. It dynamically generates JSON payloads that explicitly trigger specific probability buckets in the XGBoost model based on extensive reverse-engineering of the model's decision trees.

- **LOW Severity (81-84%)**: Triggered by generating a baseline flow of 9,000 packets/sec with zero packet length and zero ACK flags.
- **MEDIUM Severity (88-91%)**: Triggered by pulling the `Packet Length Max` slightly up to ~20 bytes, while introducing slight variance in the IAT Std.
- **HIGH Severity (94-96%)**: Triggered by setting `Packet Length Max` to 500 bytes and removing all other features.
- **CRITICAL Severity (98-99%)**: Triggered by combining an `ACK Flag Count` of 1, a `Fwd Packet Length Min` of 40, and a massive `Fwd Packets Length Total` of 100,000. This triggers the "super-additive" effect in XGBoost's deep trees.

### 11.5 Real Mode vs Simulate Mode
When run in `--mode real`, the sensor uses `scapy.all.AsyncSniffer`.
- It filters traffic strictly between `MY_IP` and the outside world.
- It intercepts TCP/UDP frames, grouping them by `flow_key`.
- It maintains a `packet_store` in memory.
- A background thread wakes up every 2 seconds (`WINDOW_SECONDS`), copies the `packet_store` (via a thread lock), and calculates the 15 features natively for every flow containing more than 10 packets.
- *Tradeoff:* Pure Python is slow. In a production 10-Gigabit environment, Scapy will drop packets. A true enterprise sensor would use eBPF, DPDK, or a Rust/C++ packet parser. The Python sensor here is proof-of-concept.

---

## 12. Security Operations Center (SOC) Playbook

If you are an analyst sitting in front of this dashboard, here is exactly how the system is designed to be operated during a live incident.

1. **Monitor the Grid:** 
   - Watch the `LiveStatsPanel`. If `FLOWS` jumps from 5 to 5,000, you are under a volumetric attack.
   - The `ThreatTable` will begin populating. Do not panic; the system limits the UI to 500 rows to prevent your browser from crashing.
2. **Identify the Source:**
   - Look at the `AnalyticsPage`. The `TopAttackerCard` will instantly highlight the IP generating the most alerts in the current session.
   - Check the `ThreatOriginMapSection`. If a massive cluster of red dots appears in a specific geographic region, you may be facing a coordinated regional botnet.
3. **Take Action:**
   - Click the red `Block` button next to the IP in the `ThreatTable` or the Leaderboard.
   - This triggers the backend block API. The backend synchronizes its in-memory `blockedIPsCache`.
   - The Python sensor (`sensor.py`) checks this cache every 30 seconds. Once it downloads the updated list, it will *suppress* alerts from that IP.
   - In a production environment, this blocklist would be pushed directly to AWS WAF, Cloudflare, or local `iptables` to drop the packets at the edge.
4. **Review & Audit:**
   - Read the `BackendLog` and `SensorLog` to confirm the WebSocket broadcasts were successful.
   - If the attack exceeds `MEDIUM` severity, expect an automated email in your inbox summarizing the incident with confidence probabilities.



---

## 13. System Resilience and Failure States

The system has been explicitly designed to handle failure gracefully.

### 13.1 Rate Limit Degradation
- **Geo-API Exhaustion:** If the `ip-api.com` rate limit (45 req/min) is exceeded, `geoUtils.js` automatically returns mock data via a deterministic hash function `mockGeoData(ip)`. The user will see a flag and country, allowing the map to continue functioning, rather than crashing the component or displaying undefined data.
- **Manual Input Exhaustion:** If an analyst attempts to run more than 10 manual XGBoost predictions in 15 minutes, the backend replies with a 429 status code. The frontend catches this and renders an error toast, rather than spinning the loading wheel indefinitely.

### 13.2 Connection Blackouts
- If the Express backend crashes or goes to sleep (Render free tier), the `socket.io-client` natively attempts to reconnect using exponential backoff.
- The `useSocket` hook tracks this connection state. The `BackendLog` panel immediately reflects `OFFLINE`, and the header status indicator pulses amber instead of green.
- Once the backend wakes up, the socket connects, the state switches to `LIVE`, and traffic resumes processing without a page refresh.

### 13.3 Memory Leaks & Garbage Collection
- **Frontend DOM Leak Prevention:** The `alerts` array in React state is strictly sliced via `slice(0, MAX_ALERTS)` where `MAX_ALERTS = 500`. 
- **Backend DB Leak Prevention:** Mongoose TTL indexes wipe documents based on `createdAt`, bypassing Express entirely.
- **Sensor Memory Management:** The `packet_store` dict is completely cleared every `WINDOW_SECONDS`. If a massive SYN flood hits, the dictionary only holds 2 seconds worth of data before being garbage collected by Python.

---

## 14. Extending the Application (Developer Guide)

If you are a developer looking to extend the NIDS architecture, follow these guidelines to prevent breaking the tight integration between the layers.

### 14.1 Adding a New ML Feature
If you retrain the XGBoost model with a 16th feature (e.g., `TCP Window Size`):
1. **Sensor:** Update `generate_benign_features()` and `generate_attack_features()` in `sensor.py` to include the new key. Update `run_window_loop()` to extract it from Scapy.
2. **Backend:** Update the `manualPredictSchema` in `schemas/alertSchemas.js` to validate the new field.
3. **Frontend:** Update `FEATURE_GROUPS` and `TEMPLATES` in `ManualInputData.js`. Add the min/max/step definitions so the UI can render the input field.
4. **Python ML Script:** Update `build_model_input` in `predict_manual.py` to correctly parse and cast the new feature into the Pandas DataFrame before prediction.

### 14.2 Adding a New Analytics Chart
1. **File:** Create a new component in `frontend/src/components/analytics/`.
2. **Data Source:** Do NOT add a new WebSocket event. Instead, derive your chart data purely from the existing `alerts` array passed from `useSocket.js`. 
3. **Rendering:** Use `recharts`. If you need custom colors, use the existing `SEVERITY_COLORS` dictionary imported from the UI utilities to maintain design consistency.
4. **Performance:** Wrap the component in `React.memo` to prevent re-rendering every time a new packet arrives unless the underlying aggregate statistics actually change.

### 14.3 Implementing Hardware Enforcement
Currently, the "Block" button saves the IP to MongoDB. To enforce this on actual hardware:
1. Write a bash script on your edge router that queries `http://<backend-url>/api/blocklist/ips` every 60 seconds.
2. Have the bash script parse the JSON array.
3. Loop through the array and execute `iptables -A INPUT -s <IP> -j DROP`.
4. Ensure the script passes the `X-Sensor-Secret` header in the curl request to authenticate.

---

## 15. Conclusion

The NIDS SOC Dashboard demonstrates that a Machine Learning security tool does not have to be a clunky, terminal-only application. By tightly integrating Python's data science capabilities (XGBoost, Pandas, Scapy) with the extreme real-time responsiveness of Node.js/WebSockets, and the beautiful, layout-animated rendering capabilities of React 19 and Framer Motion, it is possible to build a premium, enterprise-grade Security Operations Center.

This entire architecture—from the low-level packet sniffing to the high-level React state management—was explicitly designed to handle high-throughput, asynchronous data streams safely, securely, and elegantly.

<br/>

<div align="center">
  <p style="color: var(--color-text-muted); font-size: 14px;">
    <i>End of Documentation.</i>
  </p>
</div>


---

## 16. Comprehensive API Reference Guide

This section documents the exact payloads, headers, and responses required for every single REST endpoint in the Express backend. This acts as the authoritative contract between the Frontend/Sensor and the Backend.

### 16.1 Internal API (Sensor to Backend)
These endpoints are exclusively for the Python sensor and are protected by the `X-Sensor-Secret` header.

#### `POST /api/internal/alert`
Ingests a newly detected threat.
- **Headers:** `Content-Type: application/json`, `X-Sensor-Secret: <your_secret>`
- **Request Body (JSON):**
  ```json
  {
    "source_ip": "192.168.1.100",
    "probability": 0.985,
    "threat_type": "DDoS",
    "features": {
      "Flow Duration": 15000,
      "Flow IAT Mean": 2.5,
      "Flow IAT Max": 10.0,
      "Flow IAT Std": 0.5,
      "Fwd Packets/s": 5000,
      "Bwd Packets/s": 0,
      "Flow Packets/s": 5000,
      "Flow Bytes/s": 100000,
      "Packet Length Max": 500,
      "Packet Length Min": 40,
      "Packet Length Total": 15000,
      "Total Backward Packets": 0,
      "Fwd Act Data Packets": 10,
      "ACK Flag Count": 1
    }
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "alert": {
      "_id": "64abcdef...",
      "source_ip": "192.168.1.100",
      "severity": "CRITICAL",
      "blocked": false,
      "createdAt": "2023-10-01T12:00:00Z"
    }
  }
  ```
- **Failure Modes:** Returns 401 if secret is missing/wrong. Returns 400 if Zod validation fails (e.g., negative probability).

#### `POST /api/internal/stats`
Ingests window statistics (processed every 2 seconds by the sensor).
- **Headers:** `X-Sensor-Secret: <your_secret>`
- **Request Body:**
  ```json
  {
    "total_flows_processed": 50,
    "benign_flows": 45,
    "malicious_flows": 5,
    "total_packets_processed": 10000
  }
  ```
- **Response:** `{ "success": true, "message": "Stats broadcasted" }`. This data is NEVER saved to MongoDB, it is merely emitted to Socket.io to drive the UI metrics.

### 16.2 Authentication API

#### `POST /api/auth/register`
Creates a new analyst account.
- **Request Body:** `{ "name": "John Doe", "email": "john@soc.local", "password": "secure_password" }`
- **Response (201 Created):** `{ "success": true, "message": "Verification email sent." }`

#### `POST /api/auth/login`
Authenticates and returns an HttpOnly cookie.
- **Request Body:** `{ "email": "john@soc.local", "password": "secure_password" }`
- **Response (200 OK):** Sets `Set-Cookie: token=...; HttpOnly; SameSite=Strict`
  ```json
  {
    "success": true,
    "user": {
      "userId": "AB12CD",
      "name": "John Doe",
      "role": "analyst",
      "verified": true,
      "email_notifications": true
    }
  }
  ```

#### `GET /api/auth/me`
Fetches the active session based on the HttpOnly cookie. Used by the React app on mount to rehydrate state.
- **Response:** `{ "success": true, "user": { ... } }`

### 16.3 Blocklist API

#### `GET /api/blocklist/ips`
Used by the Python sensor to synchronize its block list.
- **Headers:** `X-Sensor-Secret: <your_secret>`
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "count": 2,
    "ips": ["10.0.0.5", "192.168.1.50"]
  }
  ```
- **Performance Note:** This endpoint reads from a JavaScript `Set()` in memory, completely bypassing MongoDB, ensuring 0ms latency even if queried rapidly.

#### `POST /api/blocklist/block`
Used by the Frontend Analyst to drop an IP.
- **Headers:** Cookie auth required.
- **Request Body:** `{ "ip": "10.0.0.5", "reason": "Aggressive SYN Flood" }`
- **Response (201 Created):** `{ "success": true, "block": { ... } }`
- **Side Effects:** Automatically updates all historical alerts for `10.0.0.5` setting `blocked: true`, and emits `IPBlocked` to all WebSocket clients.

### 16.4 Manual Prediction API

#### `POST /api/predict/manual`
Allows testing the XGBoost model remotely via the frontend modal.
- **Headers:** Cookie auth required.
- **Request Body:** `{ "features": { ...exactly 15 keys... } }`
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "probability": 0.95,
    "severity": "HIGH",
    "alertId": "64abcd...",
    "source_ip": "MANUAL:AB12CD"
  }
  ```
- **Execution Path:** Express spawns `sensor/predict_manual.py`, passes features via stdin, parses stdout, saves a dummy alert to Mongo, and emits it to Socket.io so the UI map updates visually.


---

## 17. Comprehensive Data Dictionary

Understanding the strict typing and validation applied throughout the pipeline is critical. The system utilizes `zod` for request validation before data reaches Mongoose, ensuring that poisoned payloads are rejected at the edge.

### 17.1 Zod Validation Schemas (`backend/schemas/`)

#### `alertSchema.js`
When the sensor submits an alert, Zod strictly checks every field to ensure the XGBoost model isn't poisoned or the DB corrupted.
- `source_ip`: Must be a valid IPv4 or IPv6 string.
- `probability`: Must be a `z.number().min(0).max(1)`.
- `threat_type`: Must be `z.enum(['DDoS', 'Manual-Test', 'Port-Scan'])`.
- `features`: An object containing exactly the 15 numeric keys. Any additional keys are explicitly stripped by `z.object(...).strict()`.

#### `authSchema.js`
- `registerSchema`:
  - `name`: `z.string().min(2).max(50)`
  - `email`: `z.string().email()`
  - `password`: `z.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)` (Requires uppercase, lowercase, and number).

### 17.2 Derived Data Attributes

#### Severity Calculation Logic
Severity is not passed by the sensor; it is deterministically calculated by the backend upon ingestion to prevent the sensor from manipulating urgency.
- **`CRITICAL`**: `probability >= 0.98`
- **`HIGH`**: `probability >= 0.90` and `< 0.98`
- **`MEDIUM`**: `probability >= 0.85` and `< 0.90`
- **`LOW`**: `probability >= 0.80` and `< 0.85`
- **Discarded**: `probability < 0.80` (Never reaches the database).

#### Geo-Enrichment Structure
When `geoUtils.js` maps an IP, it attaches a standardized object to the alert payload before passing it to the React Context:
```javascript
geo: {
  country: "United States",
  countryCode: "US",
  city: "Ashburn",
  lat: 39.0438,
  lon: -77.4874,
  isp: "Amazon.com"
}
```
If the API rate limit is hit, the fallback deterministic mock generator guarantees this identical schema format, replacing real values with pseudorandom realistic data (e.g., mapping IP octets to coordinates).

### 17.3 Memory Caches & Expirations

- **`blockedIPsCache`**: A native JS `Set`. O(1) lookup.
- **Mongoose TTL `Alerts`**: `expireAfterSeconds: 2592000` (30 days). Evaluated every 60 seconds by a background MongoDB thread.
- **Mongoose TTL `Blocklist`**: `expireAfterSeconds: 1800` (30 mins). Evaluated every 60 seconds.
- **JWT Expiration**: 7 days (`7d`).
- **React Inactivity Timeout**: 5 minutes (`300000ms`). Resets on `mousemove` or `keydown`.

---

## 18. Troubleshooting & Operational Runbook

If the system experiences a degradation, follow these specific troubleshooting steps.

### 18.1 Frontend Not Receiving Live Data
**Symptoms:** The UI loads, but the `LiveStats` remain at 0, and the `BackendLog` shows `[Socket.io] Connected` but no `Live Stats Received` messages.
**Root Causes:**
1. The Python Sensor is not running.
2. The Python Sensor is running in `--mode real` but lacks root/admin privileges, causing Scapy to fail silently.
3. The `SENSOR_SECRET` in `sensor/.env` does not match the `SENSOR_SECRET` in `backend/.env`, causing the backend to silently drop the stats POST requests.
**Resolution:** Verify the Python terminal for `401 Unauthorized` errors. Run the sensor with `sudo` if in real mode.

### 18.2 High Database CPU / OOM Errors
**Symptoms:** The Node.js server crashes with `JavaScript heap out of memory`, or MongoDB Atlas emails a CPU alert.
**Root Causes:**
1. The `trimAlerts()` function in `alert.js` failed, and the database has accumulated > 10,000 alerts.
2. The frontend connected to the socket but the `MAX_ALERTS` slice logic in `useSocket.js` was modified or removed, causing the React Virtual DOM to hold gigabytes of data.
**Resolution:** Run `db.alerts.deleteMany({})` in the MongoDB console to flush the cache, and ensure the 500-item array cap in `useSocket.js` is strictly enforced.

### 18.3 React App Blank Screen (Vite Errors)
**Symptoms:** The browser shows a blank white screen, console shows `process is not defined`.
**Root Causes:**
A developer attempted to use `process.env.VITE_BACKEND_URL` instead of Vite's required syntax `import.meta.env.VITE_BACKEND_URL` in a React component.
**Resolution:** Search the frontend directory for `process.env` and replace it with `import.meta.env`.

### 18.4 IP Map Fails to Render Dots
**Symptoms:** The world map is blank, but the `ThreatTable` is populated.
**Root Causes:**
The `geoUtils.js` module is throwing an unhandled exception before returning the mocked data. Or, `react-simple-maps` is failing to parse coordinates that are out of bounds (e.g., `lat > 90` or `lat < -90`).
**Resolution:** Check the browser console. If `ip-api.com` is returning HTML instead of JSON due to an ISP block, ensure the `catch` block in `fetchGeoData` gracefully falls back to `mockGeoData()`.



---

## 19. Architectural Scaling Plan (Future Roadmap)

While this system functions perfectly as a standalone application, scaling it to handle enterprise-grade traffic (e.g., 10+ Gbps line rates, 1 million alerts per second) requires fundamentally shifting several architectural components. This section documents exactly how this application should be migrated to handle extreme scale.

### 19.1 Scaling the Ingestion Engine (The Sensor)
**Current State:** 
The Python sensor uses `scapy` to sniff packets. `scapy` is notoriously slow and relies on the Python Global Interpreter Lock (GIL). It caps out around 5,000-10,000 packets per second before dropping frames.
**Scaling Path:**
1. **Migration to eBPF / XDP:** Rewrite the packet capture layer using eBPF (Extended Berkeley Packet Filter) or XDP (eXpress Data Path) via C or Rust. This allows packets to be analyzed directly in the kernel space without copying them to user space.
2. **Feature Extraction in C++:** Compute the 15 statistical flow features natively in a C++ microservice (e.g., using DPDK). 
3. **gRPC instead of HTTP REST:** The sensor currently sends HTTP POST requests to the backend. This adds massive HTTP header overhead for every single alert. Switching to gRPC with Protobufs would reduce payload size by ~80% and drastically lower CPU overhead on the Node.js server.

### 19.2 Scaling the Message Broker
**Current State:** 
The backend directly saves to MongoDB and emits to Socket.io in a single Node.js Express thread.
**Scaling Path:**
1. **Implement Apache Kafka / Redis PubSub:** The sensor should not talk to Express. It should publish threats directly to a Kafka topic (e.g., `nids-threats`).
2. **Decouple the Workers:** 
   - *Worker A (Database Writer)*: Consumes from Kafka and batch-inserts into MongoDB (or Snowflake for cold storage).
   - *Worker B (WebSocket Broadcaster)*: Consumes from Kafka and broadcasts to UI clients.
   - *Worker C (Email/Alerting)*: Consumes from Kafka and processes `nodemailer` requests asynchronously.
This completely prevents a database slowdown from impacting the real-time WebSocket UI.

### 19.3 Scaling the Frontend UI
**Current State:** 
The React frontend handles up to 500 alerts in local state, enriching them sequentially via `geoUtils.js`.
**Scaling Path:**
1. **Web Workers:** Move the `geoUtils.js` processing into a dedicated Web Worker to prevent blocking the React main thread during massive alert spikes.
2. **Canvas / WebGL Rendering:** If the requirement shifts from 500 alerts to 50,000 alerts on screen, HTML DOM nodes (`<tr>`, `<div>`) will crash the browser. The `ThreatTable` and Map must be rewritten using `HTML5 Canvas` or `WebGL` (via Three.js or Deck.gl) to GPU-accelerate the rendering of thousands of data points simultaneously.

### 19.4 Database Migration
**Current State:** 
MongoDB Atlas handles everything. It is a Document store, which is highly flexible but not optimized for time-series analytics.
**Scaling Path:**
1. **Time-Series DB:** Migrate the `Alerts` and `Stats` collections to a dedicated Time-Series database like InfluxDB or TimescaleDB (PostgreSQL). These databases are explicitly designed to ingest millions of rows per second and can execute aggregations (e.g., "Find average severity over the last 5 minutes") exponentially faster than MongoDB.
2. **Cold Storage:** Implement AWS S3 or Google Cloud Storage to archive alerts older than 30 days in Parquet format, allowing analysts to run Amazon Athena SQL queries against historical data without paying for expensive NVMe database storage.

---

## 20. Code Style and Contribution Guidelines

If you are a developer tasked with modifying this repository, you must adhere strictly to the established code style.

### 20.1 JavaScript / React Conventions
- **Functional Components:** All React components MUST be functional components utilizing Hooks. Class components are strictly prohibited.
- **Prop Types / Zod:** Since this is not a TypeScript codebase, you MUST document expected props. If writing backend routes, Zod schemas are mandatory for all `req.body` data.
- **CSS-in-JS vs Tailwind:** Do not use styled-components or inline styles unless dynamically driving animations (e.g., `framer-motion`). All static styling MUST utilize Tailwind v4 utility classes mapped to our CSS variables in `index.css`.
- **Imports:** Group your imports:
  1. React / Core Libraries
  2. Third-party packages (framer-motion, lucide-react)
  3. Internal Contexts / Hooks
  4. Internal Components

### 20.2 Python Conventions
- **PEP 8:** Follow standard PEP 8 formatting.
- **Type Hinting:** Even though it's Python, you MUST use type hints for all function arguments and return types (e.g., `def calculate_iat(packets: list) -> float:`). This drastically improves readability and AI comprehension.
- **Docstrings:** Every function in `sensor.py` must have a Google-style docstring explaining what it does, its arguments, and its return values.
- **No Global Variables:** Except for explicitly defined configuration constants at the top of the file (e.g., `WINDOW_SECONDS = 2`), do not rely on global state. Pass state explicitly.

---

## 21. Final System State Machine Review

To tie it all together, let us trace a single packet from the wire to the analyst's eyeballs, assuming an attack scenario.

1. **[0ms] Packet Arrival:** A malicious TCP SYN packet arrives at `eth0`.
2. **[1ms] Scapy Intercept:** `sensor.py`'s `AsyncSniffer` captures the packet. It strips the payload, keeping only `IP Src`, `IP Dst`, `Time`, and `Flags`. It appends this to the `packet_store` dictionary under the key `192.168.1.100-10.0.0.5`.
3. **[2000ms] Window Closes:** The background thread locks the dictionary. It sees the flow has 5,000 packets.
4. **[2010ms] Feature Extraction:** The Python math functions calculate the `IAT Mean`, `Packet Length Total`, and observe `ACK Flag Count == 0`.
5. **[2015ms] Inference:** The Pandas DataFrame is passed to XGBoost. The model evaluates the decision trees and outputs `probability = 0.99`.
6. **[2020ms] HTTP POST:** The sensor packages a JSON payload and sends it to `/api/internal/alert` with the `X-Sensor-Secret`.
7. **[2040ms] Backend Ingestion:** Express validates the payload via Zod, calculates `severity = CRITICAL`, and writes to MongoDB.
8. **[2060ms] Email Dispatch:** Node.js realizes it is `CRITICAL`. It fires an async request to Nodemailer.
9. **[2065ms] Broadcast:** `io.emit('ThreatDetected', payload)` fires, pushing data over the active WebSocket connections.
10. **[2100ms] React Ingestion:** `useSocket.js` receives the event. It triggers `geoUtils.js` which immediately hashes the IP to find coordinates.
11. **[2105ms] React Context Update:** The `alerts` array is updated. 
12. **[2116ms] Browser Paint:** The `ThreatTable` receives the new prop. `framer-motion` animates the old rows down by 40 pixels. The new row fades in with a red pulsating `CRITICAL` badge. The `ThreatOriginMapSection` paints a new SVG circle at the coordinates.
13. **[Total Latency: ~116ms]**: From the moment the time window closed on the sensor, the analyst sees the threat pulsing on screen in just over one-tenth of a second.

*This concludes the architectural documentation.*


---

## 22. UI Design System & Theming Engine

To maintain the premium "Security Operations Center" aesthetic, the frontend employs a highly specific design system. This system is heavily reliant on CSS variables mapped through Tailwind CSS v4. Understanding this layer is crucial for adding new visual components without breaking the aesthetic cohesion.

### 22.1 The "Glassmorphism" Philosophy
The dashboard relies on visual depth to organize information, utilizing semi-transparent backgrounds over a dark canvas.

- **`var(--color-bg-page)`**: The absolute bottom layer (`#020617` - Slate 950).
- **`var(--color-bg-card)`**: The primary component background (`rgba(15, 23, 42, 0.4)`). This relies on a low opacity value, creating the "glass" effect when overlaid on the page.
- **`var(--color-bg-elevated)`**: Used for floating elements like dropdowns, tooltips, and modals (`#1e293b`). This must be solid to prevent text bleed-through from underlying layers.
- **Backdrop Blur**: Whenever `var(--color-bg-card)` is used, it MUST be accompanied by a `backdrop-blur-md` class in Tailwind to ensure the content beneath is diffused correctly.

### 22.2 Typography Hierarchy
We do not use browser default fonts. The system relies entirely on standard Sans-serif stacks heavily optimized via Tailwind.

- **Primary Text (`var(--color-text-primary)`)**: Used for data points and main headers (`#f8fafc`).
- **Secondary Text (`var(--color-text-secondary)`)**: Used for column headers, sub-labels, and standard body copy (`#94a3b8`).
- **Muted Text (`var(--color-text-muted)`)**: Used for timestamps, disabled buttons, and non-critical logs (`#64748b`).
- **Monospace (`font-mono`)**: Mandatory for all IP addresses, hashes, IDs, and raw terminal output logs to ensure vertical alignment when scanning data vertically.

### 22.3 The Severity Token System
Colors are semantic. Never use a color without it meaning something.

- **LOW (`var(--color-low)`)**: `#3b82f6` (Blue). Indicates anomalous but non-threatening traffic (e.g., a port scan that was blocked by default firewall rules).
- **MEDIUM (`var(--color-medium)`)**: `#eab308` (Yellow). Indicates suspicious patterns requiring analyst review.
- **HIGH (`var(--color-high)`)**: `#f97316` (Orange). Indicates a confirmed attack that is currently being mitigated automatically.
- **CRITICAL (`var(--color-critical)`)**: `#ef4444` (Red). Indicates a severe attack that has bypassed automatic mitigation or requires immediate manual intervention (like a zero-day DDoS vector).

These tokens are used dynamically in React components via the `getSeverityColor(severity)` utility function found in `frontend/src/utils/colors.js`.

### 22.4 SVGs and Iconography
- The project exclusively utilizes **Lucide React** (`lucide-react`) for iconography. 
- Do not import FontAwesome or Heroicons.
- All icons must explicitly declare `size={16}` (for inline text), `size={20}` (for standard buttons), or `size={24}` (for primary navigation tabs) to maintain strict grid alignment.

---

## 23. Continuous Integration & Deployment (CI/CD)

Currently, the system is deployed manually via PaaS (Render, Vercel). For an enterprise deployment, a robust CI/CD pipeline (e.g., GitHub Actions) is required to prevent regressions.

### 23.1 Proposed GitHub Actions Pipeline

**1. Linting & Formatting (`.github/workflows/lint.yml`)**
- Runs `eslint` on the `frontend` and `backend` directories.
- Runs `flake8` and `black` on the `sensor` directory to enforce PEP 8 compliance.
- Blocks pull requests if style violations exist.

**2. Automated Testing (`.github/workflows/test.yml`)**
- **Backend:** Spins up a transient MongoDB instance via Docker. Runs `jest` against the Express routes using `supertest` to verify JWT issuance, blocklist CRUD operations, and Zod schema validations.
- **Sensor:** Uses `pytest`. Mocks the `scapy` sniffer and tests the `generate_attack_features()` function to ensure the XGBoost model consistently returns the correct probability buckets. *This is critical—if the model drifts, the entire UI breaks.*
- **Frontend:** Runs React Testing Library to verify that the `AuthContext` successfully handles simulated `401` backend responses and forces a logout.

**3. Production Build & Deploy (`.github/workflows/deploy.yml`)**
- **Frontend:** Executes `npm run build` using Vite. The resulting `dist` folder is synced to an AWS S3 bucket and invalidated via CloudFront.
- **Backend:** Builds a minimal Docker container (`node:20-alpine`) containing the Express app and the Python runtime. The image is pushed to AWS ECR and deployed to AWS ECS Fargate, scaling based on CPU utilization to handle massive WebSocket connection spikes.

---

<br/>

<div align="center">
  <p style="color: var(--color-text-muted); font-size: 14px;">
    <i>Final Verification: System Documentation Complete.</i>
  </p>
</div>


---

## 24. Database Backup & Disaster Recovery

Given the real-time nature of this SOC dashboard, data loss can severely impact post-incident forensics. 

### 24.1 Automated Snapshots (MongoDB Atlas)
- The cluster is configured to take continuous snapshots every 6 hours with a 7-day retention policy.
- In the event of a catastrophic database corruption (e.g., an analyst inadvertently drops the `Alerts` collection), the system can perform a point-in-time recovery (PITR) within a 5-minute window.

### 24.2 Cold Storage Archival Strategy
Since Mongoose TTL indices automatically delete documents older than 30 days to save on storage costs, a secondary script should be deployed:
- **`cron_backup.py`**: A lightweight Python script that runs daily at 00:00 UTC.
- It queries `/api/alerts?limit=100000&days=1`.
- It converts the JSON response into an Apache Parquet file (highly compressed columnar storage).
- It uploads the Parquet file to an AWS S3 bucket (`s3://nids-soc-archives/YYYY/MM/DD/alerts.parquet`).
- This completely separates real-time operational data from historical forensic data, allowing the Node.js backend to remain blazingly fast while preserving compliance data indefinitely.

---

## 25. Final Note for AI Assistants (Context Initialization)

If an AI (like Claude or GPT-4) is reading this entire document because the user pasted it into a fresh chat window:

1. **Acknowledge Comprehension**: Start your response by confirming you understand the tri-layer architecture (React 19 Frontend, Express 5 Backend, Python Scapy/XGBoost Sensor).
2. **State Management**: Remember that `useSocket.js` caps the frontend state at 500 items, and Mongoose TTL caps the backend state at 30 days. Do not suggest querying the database for "all time" stats without warning the user of potential OOM errors.
3. **Styling**: Remember that all CSS is handled via Tailwind v4 referencing CSS variables (`var(--color-bg-card)`). Never inject raw hex codes into JSX.
4. **Rate Limits**: Be aware of the `express-rate-limit` middleware when writing load-testing scripts or simulating massive API traffic.

**You are now fully synchronized with the NIDS SOC environment.** 
Ready to defend the network.

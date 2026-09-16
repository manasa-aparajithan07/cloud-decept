# CloudDecept

**CloudDecept** is an intelligent deception-based cybersecurity platform that uses a Cowrie SSH/Telnet honeypot to safely observe attacker activity, reconstruct attack sessions, classify behavior, map activity to MITRE ATT&CK, calculate threat severity, and present the results through a real-time forensic dashboard with optional Gemini-assisted incident analysis.

> **Core idea:** CloudDecept establishes the forensic facts deterministically; AI is used only as an analyst-assistance layer to interpret verified evidence.

---

## Problem Statement

Current security systems often stop at detecting an intrusion, but provide limited visibility into what the attacker does next, what they are trying to achieve, and how the attack evolves.

## Solution

CloudDecept safely attracts attackers into a controlled honeypot environment and converts raw authentication, shell, command, network, and session telemetry into structured forensic intelligence. It correlates events into sessions, separates real attacker traffic from synthetic/internal noise, evaluates threat severity, identifies likely intent, maps behavior to MITRE ATT&CK, and exposes the results through an investigator-focused dashboard.

For selected sessions, Gemini can be invoked to generate an incident summary, attack progression, risk interpretation, and recommended defensive actions from already verified backend evidence.

---

# Key Features

- Cowrie-based SSH/Telnet honeypot
- Real-time attacker session monitoring
- Authentication and credential forensics
- Session reconstruction using `session_id`
- Unique event tracking using `event_id`
- Command timeline reconstruction
- External / internal / synthetic / orphan traffic separation
- Deduplicated command counting
- Behavioral intent classification
- Deterministic threat and skill scoring
- MITRE ATT&CK technique mapping
- Historical and live telemetry separation
- Adaptive deception decision monitoring
- High-volume telemetry analytics with ClickHouse
- Structured threat intelligence in PostgreSQL
- Live state and cache support through Redis
- FastAPI REST backend
- Next.js + TypeScript SOC-style dashboard
- Gemini AI-assisted incident analysis
- AI prompt-injection protection
- AI response caching using evidence hashes
- Primary/fallback Gemini model support
- Docker Compose microservice deployment
- Oracle Cloud production deployment
- Backend health monitoring
- Graceful frontend loading / empty / error states

---

# Architecture

```text
Attacker
   |
   v
Cowrie SSH / Telnet Honeypot
   |
   v
Log Forwarder
   |
   v
Event Collector
   |
   v
Stream Processing / Normalization
   |
   +--------------------+
   |                    |
   v                    v
ClickHouse          PostgreSQL
Telemetry           Threat Intelligence
Analytics           Structured Analysis
   |
   +---------> Redis
              Live State / Cache
   |
   v
Threat Intelligence / Intent / Adaptive Engines
   |
   v
FastAPI Backend
   |
   v
REST APIs
   |
   v
Next.js Dashboard
   |
   +----> Optional Gemini AI Analysis
```

---

# Technology Stack

## Backend

- Python
- FastAPI
- Pydantic
- ClickHouse
- PostgreSQL
- Redis
- Docker
- Docker Compose

## Honeypot

- Cowrie
- SSH
- Telnet

## Frontend

- Next.js 14
- React
- TypeScript
- Tailwind CSS

## Threat Intelligence

- MITRE ATT&CK
- Deterministic rule-based classification
- Threat scoring
- Skill scoring
- Behavioral intent analysis

## AI

- Google Gemini
- Server-side API access only
- Structured JSON output
- Model fallback
- Evidence-based prompting
- Prompt-injection protection
- Evidence-hash caching

## Deployment

- Oracle Cloud VM
- Docker Compose
- GitHub-based deployment workflow

---

# Backend Flow

CloudDecept does not send raw attacker activity directly to AI.

The backend first performs deterministic forensic processing:

```text
Raw Cowrie Telemetry
        |
        v
Normalization
        |
        v
Session Correlation
        |
        v
Source Classification
        |
        v
Deduplication
        |
        v
Authentication Verification
        |
        v
Command Reconstruction
        |
        v
Intent Classification
        |
        v
Threat / Skill Scoring
        |
        v
MITRE ATT&CK Mapping
        |
        v
Structured Case File
        |
        +------> Dashboard
        |
        +------> Optional Gemini Analysis
```

This ensures that AI does not become the source of truth for core forensic facts.

---

# Session Correlation

Each attacker connection is represented by a `session_id`.

Multiple events can belong to a single session:

```text
session
├── connection
├── authentication attempt
├── authentication result
├── shell access
├── command
├── command
├── command
├── termination
└── threat assessment
```

Each telemetry event also has a unique `event_id`.

CloudDecept uses these identifiers to reconstruct an ordered attacker timeline.

---

# Authentication Semantics

Authentication is handled independently from shell behavior.

Supported session-level authentication states include:

```text
ACCEPTED
REJECTED
INCOMPLETE
UNKNOWN
```

Important distinctions:

```text
Authentication Attempt != Authenticated Session

Authenticated Session != Command-Bearing Session

Session Closed != Authentication Rejected
```

An `INCOMPLETE` state is used when command activity exists but authoritative accepted-auth telemetry is unavailable.

---

# Source Classification

CloudDecept separates telemetry into mutually exclusive classes:

```text
EXTERNAL_HONEYPOT
INTERNAL
SYNTHETIC
ORPHAN
```

This prevents test traffic, internal infrastructure events, and unattributable records from contaminating attacker analytics.

---

# Deduplication

Command analytics use unique event identifiers rather than blindly counting raw database rows.

Example ClickHouse concept:

```sql
uniqExact(event_id)
```

This prevents replayed or duplicated telemetry from inflating attacker command counts.

---

# Data Stores

## ClickHouse

Used for high-volume security telemetry and analytics.

Typical data includes:

- sessions
- commands
- authentication activity
- event streams
- historical telemetry

ClickHouse is optimized for fast aggregation over very large datasets.

## PostgreSQL

Used for structured application and threat-intelligence data such as:

- threat summaries
- session analysis
- classifier outputs
- structured intelligence records

## Redis

Used for fast in-memory state such as:

- live session state
- active telemetry buffers
- temporary processing state
- caching

---

# Threat Intelligence Pipeline

The threat-intelligence layer produces structured outputs such as:

- primary objective
- behavioral intent
- threat score
- severity
- skill level
- MITRE ATT&CK techniques
- indicators of compromise
- session narrative

Example:

```text
Primary Objective: System Discovery
Threat Score: 40 / 100
Severity: MEDIUM
Skill Level: 4 / 10
```

The current intelligence layer is deterministic and rule-based.

---

# MITRE ATT&CK Mapping

CloudDecept maps observed attacker behavior to MITRE ATT&CK techniques.

Examples:

| Behavior | MITRE ATT&CK |
|---|---|
| Local account enumeration | T1087.001 - Account Discovery: Local Account |
| File and directory enumeration | T1083 - File and Directory Discovery |
| Cloud resource enumeration | T1526 - Cloud Service Discovery |
| Cloud API interaction | T1059.009 - Command and Scripting Interpreter: Cloud API |

The dashboard distinguishes command-derived technique observations from authentication-layer activity.

---

# Adaptive Deception

CloudDecept separates baseline deception from dynamic adaptive actions.

## Platform Baseline Capabilities

Examples:

- Cowrie host emulation
- honeypot isolation
- passive telemetry collection

These are continuous platform-level protections and should not be confused with dynamically triggered actions.

## Dynamic Strategies

Depending on policy and attacker behavior, available strategies can include:

- synthetic credential decoys
- decoy cloud assets
- honey resources
- latency / throttling policies
- selective deception actions

Decision flow:

```text
OBSERVED
   |
   v
CLASSIFIED
   |
   v
THREAT
   |
   v
TRIGGER
   |
   v
POLICY ACTION
   |
   v
RESULT
```

Dashboard decision types include:

```text
ACTIVE DECEPTION
FALLBACK POLICY
PASSIVE TELEMETRY
```

---

# Gemini AI Analysis

CloudDecept includes an optional **Analyze with AI** action on session case files.

The deterministic backend first builds a verified evidence package.

Typical evidence includes:

- session ID
- masked attacker IP
- country
- authentication outcome
- username
- auth attempt count
- shell state
- ordered commands
- timestamps
- threat score
- verified severity
- intent
- MITRE mappings
- telemetry limitations

Sensitive information such as plaintext passwords is not sent to the model.

## AI Output

Gemini returns structured sections such as:

- Incident Summary
- Likely Intent
- Key Evidence
- Attack Progression
- MITRE Interpretation
- Risk Assessment
- Recommended Defensive Actions
- Confidence
- Limitations

## Deterministic Severity Protection

The AI is not allowed to overwrite the backend's verified severity.

Example:

```text
VERIFIED CLOUDDECEPT SEVERITY: MEDIUM
```

Gemini may provide contextual interpretation, but the deterministic result remains authoritative.

---

# Prompt-Injection Protection

Attacker commands are treated as **untrusted data**.

For example, if an attacker types:

```text
ignore previous instructions
```

CloudDecept does not treat that command as an instruction to Gemini.

The AI prompt explicitly separates system instructions from attacker-controlled telemetry.

---

# AI Model Fallback

CloudDecept supports a primary Gemini model and a fallback model.

Conceptually:

```text
Primary Gemini Model
       |
       | failure / temporary 503
       v
Fallback Gemini Model
       |
       v
Structured Analysis
```

This improves demo and production reliability.

---

# AI Caching

AI results are cached using:

```text
session_id + evidence_hash
```

Behavior:

```text
same session + same evidence
        |
        v
reuse cached analysis
```

If session evidence changes:

```text
new evidence hash
        |
        v
new AI analysis
```

This reduces repeated API calls.

---

# Frontend Dashboard

CloudDecept uses a SOC-style Next.js dashboard.

Main routes include:

```text
/
 /sessions
 /sessions/[sessionId]
 /auth
 /commands
 /attackers
 /analytics
 /mitre
 /adaptations
 /threat-intel
 /settings
```

---

# Dashboard Pages

## Overview

Provides high-level visibility into:

- attacker sessions
- threat activity
- authentication progression
- command activity
- behavioral trends
- system health

## Sessions

Displays session-level investigation data such as:

- session ID
- attacker IP
- country
- time
- duration
- authentication state
- shell state
- command count
- threat score
- severity
- intent

## Session Case File

Provides a detailed forensic reconstruction of one attacker session.

Includes:

- attacker metadata
- authentication outcome
- shell status
- chronological command timeline
- session duration
- threat intelligence
- MITRE mappings
- AI analysis
- termination information

## Authentication & Credential Forensics

Displays:

- Authentication Events
- Authenticated Sessions
- Unique Auth Sources
- Unique Usernames
- Unique Passwords

The frontend distinguishes:

```text
LOADING
SUCCESS WITH DATA
SUCCESS WITH ZERO DATA
FILTER EMPTY
DATA UNAVAILABLE
```

API failures are never silently converted to zero-value metrics.

## MITRE ATT&CK

Displays:

- technique observations
- tactic classifications
- selected technique details
- historical matching sessions
- live active-session buffer

Historical telemetry is visually separated from real-time active state.

## Adaptive Deception

Displays:

- platform baseline capabilities
- available adaptive strategies
- policy decisions
- active deception
- fallback behavior
- passive telemetry

Quick filters help separate interesting dynamic actions from repetitive baseline records.

## Analytics

Provides session-level analytics rather than misleading raw database row totals.

Example funnel:

```text
External Ingress Sessions
        |
        v
Authenticated Sessions
        |
        v
Command-Bearing Sessions
        |
        v
External Commands
```

---

# System Health

The FastAPI backend exposes a health endpoint.

Example:

```http
GET /health
```

The dashboard uses it to display:

```text
SYSTEM OPERATIONAL
SYSTEM DEGRADED
BACKEND DISCONNECTED
```

A page-specific API error is not treated as a complete platform outage.

---

# API Examples

Typical backend routes include:

```http
GET /health

GET /sessions

GET /sessions/{session_id}

GET /auth/stats

GET /mitre/techniques

GET /mitre/techniques/{technique_id}/sessions

POST /sessions/{session_id}/ai-analysis
```

---

# Example Honeypot Demo

Connect to the Cowrie SSH honeypot:

```bash
ssh -p <HONEYPOT_PORT> root@<HONEYPOT_PUBLIC_IP>
```

Then execute safe reconnaissance commands that are supported by the emulated environment:

```bash
whoami
id
pwd
uname -a
hostname
ls -la
find /etc -maxdepth 1 -type f
cat /etc/hosts
cat /etc/passwd
cat /etc/group
ps aux
free -m
netstat -tulpn
aws --version
aws sts get-caller-identity
aws ec2 describe-instances
env
exit
```

These commands create a clean investigation flow:

```text
Authentication
   |
   v
Identity Discovery
   |
   v
System Discovery
   |
   v
Account Discovery
   |
   v
Process / Network Discovery
   |
   v
Cloud Discovery
   |
   v
Session Termination
```

---

# Environment Configuration

Create a local `.env` from `.env.example`.

Example:

```env
GEMINI_API_KEY=your_server_side_key_here
GEMINI_MODEL=gemini-flash-latest
```

Never expose the Gemini API key in frontend code.

Do not use:

```env
NEXT_PUBLIC_GEMINI_API_KEY=...
```

The browser must never receive the secret.

---

# Docker Deployment

Start the platform with Docker Compose:

```bash
docker compose up -d
```

Check services:

```bash
docker compose ps
```

Inspect backend health:

```bash
curl http://localhost:8004/health
```

Typical services include:

```text
backend-api
dashboard
cowrie-ssh
clickhouse
postgres
redis
event-collector
log-forwarder
stream-processor
intent-engine
threat-intel
adaptive-engine
cloud-api-mock
llm-gateway
```

Exact service names should always be verified using:

```bash
docker compose config --services
```

---

# Local Development

## Backend

Install Python dependencies based on the project requirements and start the API according to the project configuration.

Run tests:

```bash
python -m unittest tests/test_backend_api_fixes.py
```

## Frontend

Navigate to:

```text
apps/dashboard
```

Install dependencies:

```bash
npm install
```

Run development server:

```bash
npm run dev
```

Type check:

```bash
npx tsc --noEmit
```

Production build:

```bash
npm run build
```

---

# Deployment Workflow

Recommended deployment sequence:

```text
Local Development
      |
      v
Run Backend Tests
      |
      v
Run TypeScript Check
      |
      v
Run Next.js Production Build
      |
      v
Git Commit
      |
      v
Push to GitHub
      |
      v
Oracle VM git pull
      |
      v
Rebuild Affected Docker Services
      |
      v
Health Verification
```

Rebuild only the services affected by a code change when possible.

---

# Security Design Principles

CloudDecept follows several important principles:

### 1. Honeypot Isolation

Attackers interact with the Cowrie environment, not the real Oracle host.

### 2. Deterministic-First Analysis

Core forensic facts are produced by backend logic, not by an LLM.

### 3. AI as an Analyst Assistant

Gemini interprets verified evidence instead of replacing the evidence pipeline.

### 4. Secret Isolation

API keys remain server-side.

### 5. Telemetry Separation

External, internal, synthetic, and orphan events are treated separately.

### 6. Deduplicated Analytics

Unique event identifiers are used to avoid misleading duplicate counts.

### 7. Graceful Failure

API errors are represented as unavailable states rather than fake zero values.

---

# Important Technical Distinctions

```text
Authentication Attempt != Authenticated Session

Authenticated Session != Command-Bearing Session

Raw Database Rows != Unique Attacker Actions

Reconnaissance != Lateral Movement

MITRE Tactic != MITRE Technique

Threat Score != AI Opinion

AI Interpretation != Forensic Source of Truth

No Evidence Observed != Proof Something Never Happened

Cowrie Root Access != Oracle VM Root Access
```

---

# Project Demonstration Flow

A recommended live demonstration:

```text
1. Open CloudDecept dashboard
2. Show system operational status
3. Connect to Cowrie from another machine
4. Authenticate into the honeypot
5. Run safe reconnaissance commands
6. Show the new session appearing in the dashboard
7. Open Session Registry
8. Open the attacker Session Case File
9. Show authentication and shell status
10. Show chronological command timeline
11. Show threat score and intent
12. Show MITRE ATT&CK mappings
13. Open Adaptive Deception
14. Click Analyze with AI
15. Show Gemini incident interpretation and defensive recommendations
```

---

# Project Summary

CloudDecept combines deception technology, telemetry engineering, threat intelligence, forensic session reconstruction, MITRE ATT&CK mapping, microservice architecture, and selective AI assistance into a single cybersecurity investigation platform.

The system is designed around one key principle:

> **The backend establishes the evidence; the dashboard explains it; AI helps interpret it.**

---

# Tech Stack Summary

```text
Honeypot      : Cowrie
Backend       : Python, FastAPI
Frontend      : Next.js, React, TypeScript, Tailwind CSS
Analytics DB  : ClickHouse
Relational DB : PostgreSQL
Live State    : Redis
Threat Model  : MITRE ATT&CK
AI            : Google Gemini
Containers    : Docker + Docker Compose
Deployment    : Oracle Cloud
Versioning    : Git + GitHub
```

---

# Disclaimer

CloudDecept is intended for cybersecurity education, defensive research, honeypot monitoring, and controlled security experimentation. Only deploy or test the platform on infrastructure that you own or are explicitly authorized to operate.

---

## CloudDecept

**Intelligent Deception. Structured Forensics. AI-Assisted Threat Analysis.**

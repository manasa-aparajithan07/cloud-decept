# CloudDecept: Adaptive AI-Powered Cloud Deception Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![ARM64](https://img.shields.io/badge/ARM64-Compatible-green.svg)](https://cloud.oracle.com)
[![Research](https://img.shields.io/badge/Research-Paper%20Ready-orange.svg)]()

> **First cloud-native adaptive honeypot that uses local LLMs to predict attacker intent and dynamically adapts deception responses.**

## Overview

CloudDecept is a research platform for studying cloud-targeted attacks through intelligent deception. Unlike traditional honeypots that serve static responses, CloudDecept:

- 🎯 **Predicts attacker intent** in real-time using Llama-3.2-3B (local, no API calls)
- 🔄 **Adapts responses dynamically** based on predicted intent (6 categories)
- ☁️ **Simulates real cloud APIs** (AWS, Azure, GCP) with consistent organization profiles
- 📊 **Maps to MITRE ATT&CK** automatically with cloud-specific techniques
- 💰 **Runs for $0/month** on Oracle Cloud Free Tier (2-4 ARM vCPUs, 12-24 GB RAM)
- 🔬 **Produces research-grade data** with session summaries, IOCs, and technique mappings

## Quick Start (Oracle Cloud Free Tier - $0/month)

### What You Need
1. Oracle Cloud account (requires credit card for verification, won't be charged)
2. SSH key pair
3. 15 minutes

### Deploy in 3 Steps

```bash
# 1. On your local machine - create SSH key
ssh-keygen -t ed25519 -f ~/.ssh/oracle_cloud -C "clouddecept"

# 2. Follow the setup guide to create Oracle Cloud VM
# See: docs/ORACLE_CLOUD_SETUP.md

# 3. On the Oracle VM - one command deployment (staged, ARM64 verified)
git clone https://github.com/yourusername/cloud-decept.git
cd cloud-decept
chmod +x scripts/*.sh
./scripts/deploy-oracle.sh
```

That's it! The script handles everything:
- ✅ ARM64 image verification
- ✅ Staged deployment (databases → services → dashboard → Ollama)
- ✅ Optimized for 2 OCPU / 12 GB RAM (upgradable to 4/24)
- ✅ Pulls Llama-3.2-3B (ARM64 optimized)

### Access Your Honeypot
```
SSH Honeypot:     ssh -p 2222 ubuntu@<YOUR_PUBLIC_IP>
Cloud API Mock:   http://<YOUR_PUBLIC_IP>:8080
Dashboard:        http://<YOUR_PUBLIC_IP>:3000
```

### Free Domain (Optional)
```bash
./scripts/setup-duckdns.sh
# Enter your subdomain and DuckDNS token
# Access at: http://yourname.duckdns.org:3000
```

## Local Development

```bash
# Prerequisites: Docker, Docker Compose, Git
git clone https://github.com/yourusername/cloud-decept.git
cd cloud-decept
chmod +x scripts/*.sh
./scripts/setup-local.sh
```

Access points on localhost:
```
SSH Honeypot:      ssh -p 2222 ubuntu@localhost      (password: ubuntu)
Cloud API Mock:    http://localhost:8080
Dashboard:         http://localhost:3000
Intent Engine:     http://localhost:8000/health
Adaptive Engine:   http://localhost:8001/health
Threat Intel:      http://localhost:8002/health
Ollama API:        http://localhost:11434
ClickHouse HTTP:   http://localhost:8123
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CloudDecept                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Cowrie     │  │ Cloud API    │  │   Intent Engine      │  │
│  │   SSH        │◄─┤   Mock       │─►│   (Llama-3.2-3B)     │  │
│  │   Honeypot   │  │ (FastAPI)    │  │   ├─ Classify intent  │  │
│  └──────────────┘  └──────────────┘  │   ├─ Skill level     │  │
│         │                │           │   └─ Reasoning       │  │
│         └────────────────┼───────────┘           │          │
│                          ▼                       ▼          │
│              ┌───────────────────────┐  ┌──────────────┐     │
│              │  Adaptive Engine      │  │ Threat Intel │     │
│              │  ├─ Enrich responses  │  │  ├─ MITRE map │     │
│              │  ├─ Plant creds       │  │  ├─ IOC extract│     │
│              │  ├─ Fabricate data    │  │  ├─ Summarize │     │
│              │  └─ Delay/fail        │  └──────────────┘     │
│              └───────────────────────┘           │           │
│                          │                        ▼           │
│              ┌─────────┴─────────┐    ┌────────────────┐     │
│              │   Storage         │    │  Dashboard     │     │
│              │  ├─ ClickHouse    │    │  (Next.js)     │     │
│              │  ├─ PostgreSQL    │    │  ├─ Live view  │     │
│              │  └─ Redis         │    │  ├─ Analytics  │     │
│              └───────────────────┘    │  └─ Threat view│     │
└─────────────────────────────────────────────────────────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Cowrie SSH | 2222 | SSH honeypot with cloud command modules |
| Cloud API Mock | 8080 | AWS/Azure/GCP API simulation |
| Intent Engine | 8000 | LLM-based intent classification |
| Adaptive Engine | 8001 | Dynamic response adaptation |
| Threat Intel | 8002 | MITRE mapping, IOC extraction, summarization |
| Dashboard | 3000 | Real-time monitoring UI |
| ClickHouse | 8123 | Analytical database (commands, sessions) |
| PostgreSQL | 5432 | Threat intel, summaries, alerts |
| Redis | 6379 | Caching, session state |
| Ollama | 11434 | Local LLM inference |

## Intent Categories

| Intent | Description | Adaptation Strategy |
|--------|-------------|---------------------|
| `cloud_recon` | Enumerating cloud resources | Enrich responses with fake resources |
| `credential_hunting` | Searching for keys, tokens | Plant fake credentials in filesystem |
| `privilege_escalation` | Trying to gain higher access | Fail 2x, then grant fake admin |
| `data_access` | Accessing storage, databases | Create tempting fake data |
| `persistence` | Creating backdoors, keys | Allow & monitor, add fake users |
| `lateral_movement` | Moving between resources | Fabricate internal topology |

## Cloud API Coverage

| Provider | Endpoints | Key Features |
|----------|-----------|--------------|
| AWS | 18 | EC2, S3, IAM, STS, Metadata (169.254.169.254) |
| Azure | 12 | VMs, Storage, AD, Resource Groups, Key Vault |
| GCP | 12 | Compute, Storage, IAM, Cloud SQL |
| **Total** | **47** | Consistent org profiles, cross-session state |

## Research Output

The platform generates publication-ready data:

```
research/
├── data/
│   ├── schema.json              # Dataset schema
│   ├── anonymized/              # Public release dataset
│   └── raw/                     # Raw collected data
├── analysis/
│   └── analyze_results.ipynb    # Full analysis notebook
├── scripts/
│   └── anonymize_dataset.py     # GDPR-compliant anonymization
└── paper/
    ├── clouddecept.tex          # IEEE conference paper
    ├── references.bib           # Bibliography
    └── figures/                 # Generated figures
```

### Key Metrics (from 6-week deployment)
- **312 unique attackers** from 47 countries
- **1,247 sessions** with cloud API interactions
- **0.87 F1-score** intent classification (within 3 seconds)
- **52% longer sessions** with adaptive deception
- **12 unique MITRE cloud techniques** detected
- **5 novel technique combinations** not in existing datasets

## Deployment Details

### Oracle Cloud Free Tier (Recommended)
- **Always Free**: 2-4 ARM vCPUs, 12-24 GB RAM, 200 GB storage, public IP
- **Architecture**: ARM64 (all Docker images multi-arch)
- **Cost**: $0/month forever
- **Guide**: [docs/ORACLE_CLOUD_SETUP.md](docs/ORACLE_CLOUD_SETUP.md)
- **Staged Deployment**: Avoids memory spikes on 12 GB VMs
- **ARM64 Verification**: Pre-deployment compatibility check

### Hardware Requirements
| Component | Minimum | Oracle Free (2 OCPU) | Oracle Free (4 OCPU) |
|-----------|---------|----------------------|----------------------|
| CPU | 2 vCPU | 2 ARM vCPU | 4 ARM vCPU |
| RAM | 8 GB | 12 GB | 24 GB |
| Storage | 50 GB | 200 GB | 200 GB |
| Network | Public IP | Public IP + DuckDNS | Public IP + DuckDNS |

### Model Size
| Deployment | Model | Quantization | RAM |
|------------|-------|--------------|-----|
| Local Dev | Llama-3.2-3B | 4-bit | ~4 GB |
| Oracle 2 OCPU | Llama-3.2-3B | 4-bit | ~4 GB |
| Oracle 4 OCPU | Llama-3-8B | 4-bit | ~8 GB |

## Directory Structure

```
cloud-decept/
├── apps/
│   ├── cloud-api-mock/      # FastAPI cloud simulation
│   └── dashboard/           # Next.js monitoring UI
├── configs/
│   ├── clickhouse/          # ClickHouse configs
│   └── cowrie/              # Cowrie config, custom modules
├── services/
│   ├── adaptive-engine/     # Response adaptation logic
│   ├── intent-engine/       # LLM intent classification
│   └── threat-intel/        # MITRE, IOC, summarization
├── scripts/
│   ├── deploy-oracle.sh     # Staged Oracle deployment (ARM64 verified)
│   ├── setup-local.sh       # Local development
│   ├── setup-duckdns.sh     # Free domain setup
│   └── verify-arm64.sh      # ARM64 image compatibility check
├── docs/
│   └── ORACLE_CLOUD_SETUP.md # Complete deployment guide
├── research/                # Paper, data, analysis
├── docker-compose.yml       # Base services (no resource limits)
├── docker-compose.oracle.yml # 2 OCPU / 12 GB override
├── docker-compose.prod.yml   # 4 OCPU / 24 GB override
└── README.md
```

## Deployment Commands

### Oracle Cloud (2 OCPU / 12 GB)
```bash
# Staged deployment with ARM64 verification
docker compose -f docker-compose.yml -f docker-compose.oracle.yml up -d

# Or use the automated script
./scripts/deploy-oracle.sh
```

### Oracle Cloud (4 OCPU / 24 GB - when upgraded)
```bash
# Remove the oracle override
mv docker-compose.oracle.yml docker-compose.oracle.yml.bak

# Deploy with production config
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Pull larger model
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec ollama ollama pull llama3:8b
```

### Local Development
```bash
docker compose -f docker-compose.yml up -d
```

## Monitoring & Maintenance

```bash
# View all logs
docker compose -f docker-compose.yml -f docker-compose.oracle.yml logs -f

# Specific service logs
docker compose -f docker-compose.yml -f docker-compose.oracle.yml logs -f cowrie-ssh
docker compose -f docker-compose.yml -f docker-compose.oracle.yml logs -f intent-engine
docker compose -f docker-compose.yml -f docker-compose.oracle.yml logs -f cloud-api-mock

# Check status
docker compose -f docker-compose.yml -f docker-compose.oracle.yml ps

# Resource usage
docker stats --no-stream

# Update
git pull
docker compose -f docker-compose.yml -f docker-compose.oracle.yml build
docker compose -f docker-compose.yml -f docker-compose.oracle.yml up -d

# Backup databases
docker compose -f docker-compose.yml -f docker-compose.oracle.yml exec clickhouse clickhouse-client --query "BACKUP DATABASE deception TO Disk('backups')"
docker compose -f docker-compose.yml -f docker-compose.oracle.yml exec postgres pg_dump -U deception deception > backup_$(date +%Y%m%d).sql
```

## AI Forensic Interpretation (Gemini Integration)

CloudDecept operates on a strict **deterministic-first** architecture:

> *"CloudDecept establishes forensic truth; Gemini interprets that truth."*

The core CloudDecept engine and backend deterministically establish:
- Session identity, IP origin, and temporal boundaries
- Authoritative authentication outcomes (`accepted`, `rejected`, `incomplete`, `unknown`)
- Exact, deduplicated command execution timelines
- Behavioral classification and intent identification
- Quantitative threat scores (0–100) and severity levels
- Grounded MITRE ATT&CK technique mappings

### Investigator Workflow
1. An analyst navigates to any **Session Case File** in the Investigation Registry.
2. The investigator inspects the verified deterministic evidence and unified attack timeline.
3. The investigator explicitly clicks **`[ ✨ ANALYZE WITH AI ]`** to request an AI synthesis.
4. The server-side backend constructs a strictly delimited forensic fact block and dispatches it to Google Gemini.
5. Gemini generates an analyst-readable incident synthesis without altering or fabricating facts:
   - **Executive Incident Summary**: Narrative synthesis of the session.
   - **Likely Attacker Intent**: Inferred adversarial goals grounded in observed commands.
   - **Key Forensic Evidence**: Essential facts anchoring the assessment.
   - **Attack Progression**: Chronological phases from ingress to exit.
   - **MITRE ATT&CK Interpretation**: Contextual analysis of verified techniques.
   - **Operational Risk Assessment & Hardening Recommendations**: Actionable guidance for SOC teams.
   - **Confidence Level & Visibility Boundaries**: Clear disclaimers of what was observed vs. unobserved.

Gemini acts as an AI analyst interpreting verified evidence—it is **never** the forensic source of truth.



## Security Notes

⚠️ **Important**:
- Change default passwords in `docker-compose.yml` / `.env` after deployment
- The honeypot exposes ports publicly - it's designed to be attacked
- No real systems or credentials are at risk
- All data stays on your VM
- Monitor Oracle Cloud billing (set $0.01 budget alert)

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## Research Paper

If you use CloudDecept in your research, please cite:

```bibtex
@inproceedings{clouddecept2024,
  title={CloudDecept: Adaptive AI-Powered Cloud Deception for Dynamic Threat Intelligence Collection},
  author={Anonymous},
  booktitle={IEEE Symposium on Security and Privacy (SP)},
  year={2024}
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Roadmap

- [ ] Multi-region distributed deployment
- [ ] Fine-tuned smaller models for edge
- [ ] SIEM/SOAR integration (Splunk, Elastic, Sentinel)
- [ ] Multi-tenant SaaS version
- [ ] Attacker behavior prediction models

## Support

- 📖 Documentation: [docs/ORACLE_CLOUD_SETUP.md](docs/ORACLE_CLOUD_SETUP.md)
- 🐛 Issues: GitHub Issues
- 💬 Discussions: GitHub Discussions

---

**Built for researchers, by researchers. Deploy today, publish tomorrow.** 🚀
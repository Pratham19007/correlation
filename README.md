# Wazuh Log Correlation & Attack Detector

A security correlation engine that directly connects to **Wazuh SIEM/XDR** (API and Indexer) to ingest alert logs, correlate attacks by source IP, and detect whether the attack targets the **Wazuh Manager** (ID: 000) or monitored **Wazuh Agents** (ID: 001+).

## Features

- **Live Wazuh SIEM Attachment**: Authenticates with Wazuh REST API (`https://<host>:55000`) and Wazuh Indexer (`https://<host>:9200`) using JWT and Basic authentication.
- **Wazuh Target Identification**: Differentiates between attacks targeting the central **Wazuh Manager** (`agent.id: "000"` / `wazuh-manager`) versus monitored **Wazuh Agents** (`agent.id: "001+"` / named endpoints) or multi-target attacks hitting both.
- **Node & Agent Inventory Discovery**: Automatically discovers connected Wazuh nodes and maps agent IDs to target roles.
- **Real-Time Live Sync**: Pulls live alerts from Wazuh with a single click or CLI command.
- **Multi-Cloud Deployable**: Ready for 1-click deployment on **Vercel**, **Render**, **Docker**, and **Linux systemd**.

---

## Deploy to Vercel

The project includes [`vercel.json`](file:///c:/correlation/vercel.json) and [`api/index.py`](file:///c:/correlation/api/index.py) for Vercel Serverless Functions and Static Frontend hosting.

### Method A: Via GitHub (Recommended)
1. Push your repository to GitHub:
   ```bash
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git branch -M main
   git push -u origin main
   ```
2. Go to [vercel.com/new](https://vercel.com/new), select your repository, and click **Deploy**.
3. *(Optional)* Under **Environment Variables** in Vercel settings, add:
   - `WAZUH_HOST`: `https://<wazuh-public-url>:55000`
   - `WAZUH_INDEXER_HOST`: `https://<wazuh-public-url>:9200`
   - `WAZUH_USER`: `admin`
   - `WAZUH_PASSWORD`: `l6ArtMq7XC*XGtK08mwGBCPsWXh?Lgxv`
   - `WAZUH_VERIFY_SSL`: `false`

### Method B: Via Vercel CLI
```bash
npm install -g vercel
vercel
```

---

## Deploy to Render

The project includes [`render.yaml`](file:///c:/correlation/render.yaml) for 1-click Blueprint deployment as a Python Web Service.

### Method A: Via GitHub (Blueprint)
1. Push your repository to GitHub.
2. Log in to [render.com](https://render.com), go to **Blueprints** -> **New Blueprint Instance**.
3. Select your repository. Render will automatically detect [`render.yaml`](file:///c:/correlation/render.yaml) and deploy your web service.

### Method B: As a Docker Service on Render
1. Create a **New Web Service** on Render.
2. Select **Docker** environment (it will use [`Dockerfile`](file:///c:/correlation/Dockerfile)).

---

## Local & Server Deployment

### Run Locally (Production Server)
```bash
py -m correlation_tool.server 8000
```
Then visit `http://localhost:8000` in your browser.

### Run with Docker Compose
```bash
docker compose up -d
```

### Deploy as Linux Service (`172.16.20.62`)
```bash
sudo cp wazuh-correlator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-correlator
```

---

## CLI Usage

```bash
# Test connection to Wazuh
py -m correlation_tool.cli --test-wazuh

# List all discovered Wazuh agents & manager
py -m correlation_tool.cli --list-agents

# Pull live alerts from Wazuh and correlate
py -m correlation_tool.cli --live --summary

# Run unit tests
py -m unittest discover tests
```

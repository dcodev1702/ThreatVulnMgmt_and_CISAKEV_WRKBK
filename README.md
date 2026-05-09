# Threat & Vulnerability Management + CISA KEV Workbook

A Microsoft Sentinel workbook ([`MDE_TVM_Regional_Vulnerability_Workbook.workbook.json`](MDE_TVM_Regional_Vulnerability_Workbook.workbook.json)) that surfaces **Defender for Endpoint TVM** vulnerabilities by `MachineGroup` region, joined against the **CISA Known Exploited Vulnerabilities (KEV)** catalog so analysts can see exactly which hosts are exposed to actively-exploited CVEs.

The data plane is a single **Logic App + Direct-Ingestion DCR** that pulls TVM via Microsoft Graph `runHuntingQuery` and the public CISA KEV JSON feed, then writes both into custom analytics tables in the Sentinel workspace.

> **Authentication stance:** UAMI + RBAC only. **No** storage shared keys, **no** SAS, **no** Function keys, **no** client secrets, **no** App Registration credentials.

---

## Architecture

```mermaid
flowchart TB
    classDef ms fill:#1e3a5f,stroke:#4a90e2,color:#9ec5fe,stroke-width:2px
    classDef azure fill:#3d1f1a,stroke:#d97706,color:#fbbf24,stroke-width:2px
    classDef compute fill:#1a3d2e,stroke:#10b981,color:#6ee7b7,stroke-width:2px
    classDef store fill:#2d1f4a,stroke:#7c3aed,color:#c4b5fd,stroke-width:2px
    classDef worker fill:#3d1a1a,stroke:#dc2626,color:#fca5a5,stroke-width:2px

    Graph["Microsoft Graph<br/><i>POST /security/runHuntingQuery</i><br/>ThreatHunting.Read.All"]:::ms
    KEV["CISA KEV Catalog<br/><i>known_exploited_vulnerabilities.json</i><br/>Public HTTPS feed"]:::ms

    subgraph SentinelRG["Resource Group · Sentinel · eastus2"]
        Trigger["Recurrence Trigger<br/><i>DailyAt04UTC</i>"]:::azure
        LA["Logic App Consumption<br/><b>la-tvm-graph-ingest</b><br/>UAMI: mi-tvm-graph-ingest"]:::azure
        DCR["Direct-Ingestion DCR<br/><b>dcr-tvm-graph-ingest</b><br/>2 streams · 2 dataFlows"]:::store
        subgraph LAW["Log Analytics · DIBSecCom"]
            TVM["TvmRegional_CL<br/><i>~3,200 rows/day · 18 devices</i>"]:::compute
            KEVT["CisaKev_CL<br/><i>~1,500 KEV CVEs · 260 vendors</i>"]:::compute
        end
        WB["Sentinel Workbook<br/><b>TVM-By-Region</b><br/>5 KQL panels + KEV matches"]:::worker
    end

    Teams(["Analyst<br/>via Sentinel / Azure Portal"]):::ms

    Trigger --> LA
    LA -->|"audience: graph.microsoft.com"| Graph
    LA -->|GET| KEV
    LA -->|"POST chunks · audience: monitor.azure.com"| DCR
    DCR -->|Custom-TvmRegional_CL| TVM
    DCR -->|Custom-CisaKev_CL| KEVT
    TVM --> WB
    KEVT --> WB
    WB --> Teams
```

### Why this shape

| Concern | Resolution |
|---|---|
| `DeviceTvmSoftwareVulnerabilities` is **lake-only** in Sentinel — 0 rows in LAW analytics | Logic App calls Microsoft Graph advanced hunting (which **does** see it) and POSTs the projection to a custom analytics table. |
| Workbook can't POST to Graph (data sources are GET-only for Graph) | The workbook reads the post-ingested `TvmRegional_CL` table directly. |
| KEV catalog changes daily and matters cross-tenant | Same Logic App fetches CISA's public JSON and writes `CisaKev_CL` — co-located with TVM so a single KQL `join` produces the KEV-match grid. |
| Need passwordless auth end to end | UAMI granted Graph app role `ThreatHunting.Read.All` and `Monitoring Metrics Publisher` on the DCR. No secrets stored anywhere. |

---

## Logic App — both branches share `InitializeNow`

```mermaid
flowchart TB
    classDef trig fill:#1e3a5f,stroke:#4a90e2,color:#9ec5fe,stroke-width:2px
    classDef init fill:#3d1f1a,stroke:#d97706,color:#fbbf24,stroke-width:2px
    classDef tvm fill:#1a3d2e,stroke:#10b981,color:#6ee7b7,stroke-width:2px
    classDef kev fill:#2d1f4a,stroke:#7c3aed,color:#c4b5fd,stroke-width:2px
    classDef post fill:#3d1a1a,stroke:#dc2626,color:#fca5a5,stroke-width:2px

    Trig["Recurrence · DailyAt04UTC"]:::trig
    Now["InitializeNow<br/><i>variables('Now') = utcNow()</i>"]:::init

    subgraph TVMBranch["TVM branch · ~3,200 rows · chunkSize 1000"]
        RHQ["RunHuntingQuery<br/><i>POST graph.microsoft.com</i>"]:::tvm
        ShapeT["ShapeRows<br/><i>Select 13 cols</i>"]:::tvm
        InitT["InitializeRowCount<br/>InitializeChunkIndex"]:::tvm
        IfT{"IfHasRows<br/><i>RowCount > 0</i>"}:::tvm
        UntilT["UntilAllChunksSent<br/><i>ComposeChunk → PostChunk → Increment</i>"]:::tvm
    end

    subgraph KEVBranch["KEV branch · ~1,500 rows · chunkSize 500"]
        Get["GetKev<br/><i>GET cisa.gov</i>"]:::kev
        ShapeK["ShapeKevRows<br/><i>Select 14 cols</i>"]:::kev
        InitK["InitializeKevRowCount<br/>InitializeKevChunkIndex"]:::kev
        IfK{"IfHasKevRows<br/><i>KevRowCount > 0</i>"}:::kev
        UntilK["UntilAllKevChunksSent<br/><i>ComposeKevChunk → PostKevChunk → Increment</i>"]:::kev
    end

    Post["DCR · dcr-tvm-graph-ingest<br/><i>POST /streams/Custom-{table} → 204 NoContent</i>"]:::post

    Trig --> Now
    Now --> RHQ
    Now --> Get
    RHQ --> ShapeT --> InitT --> IfT --> UntilT --> Post
    Get --> ShapeK --> InitK --> IfK --> UntilK --> Post
```

The two branches run in parallel because both start with `runAfter: { InitializeNow: [Succeeded] }`. The DCR enforces stream-to-table mapping, so cross-contamination is impossible — each branch posts to its own `streamName` parameter.

---

## Workbook — KEV match logic

The KEV section joins the **latest snapshot per `(DeviceId, CveId)`** in `TvmRegional_CL` to the **latest snapshot per `CveId`** in `CisaKev_CL`, then sorts ransomware-linked KEVs first and soonest CISA due dates first.

```mermaid
flowchart LR
    classDef src fill:#1a3d2e,stroke:#10b981,color:#6ee7b7,stroke-width:2px
    classDef src2 fill:#2d1f4a,stroke:#7c3aed,color:#c4b5fd,stroke-width:2px
    classDef join fill:#3d1f1a,stroke:#d97706,color:#fbbf24,stroke-width:2px
    classDef out fill:#3d1a1a,stroke:#dc2626,color:#fca5a5,stroke-width:2px

    DI["DeviceInfo<br/><i>Region filter · MachineGroup</i>"]:::src
    TVM["TvmRegional_CL<br/><i>arg_max by DeviceId, CveId</i>"]:::src
    KEV["CisaKev_CL<br/><i>arg_max by CveId</i>"]:::src2

    Join1{"join kind=inner<br/>on DeviceId"}:::join
    Join2{"join kind=inner<br/>on CveId"}:::join

    Out["KEV-matched grid<br/><i>Device · CVE · KEV Name · Vendor</i><br/><i>Ransomware · CISA Due · Severity</i>"]:::out

    DI --> Join1
    TVM --> Join1
    Join1 --> Join2
    KEV --> Join2
    Join2 --> Out
```

**Live validation:** 19 KEV matches across 6 hosts, 14 unique KEV CVEs, 6 already past CISA due date.

---

## Repository contents

| File | Purpose |
|---|---|
| [`deploy-tvm-graph-ingest.bicep`](deploy-tvm-graph-ingest.bicep) | UAMI · `CisaKev_CL` custom table · DCR (2 streams, 2 dataFlows) · Logic App · role assignments |
| [`tvm-graph-ingest.workflow.json`](tvm-graph-ingest.workflow.json) | Logic App workflow definition (TVM + KEV branches sharing `InitializeNow`) |
| [`grant-graph-permission.ps1`](grant-graph-permission.ps1) | Idempotent grant of Graph `ThreatHunting.Read.All` app role to the UAMI |
| [`deploy-tvm-workbook.bicep`](deploy-tvm-workbook.bicep) | Publishes the workbook via `loadTextContent()` of the JSON |
| [`MDE_TVM_Regional_Vulnerability_Workbook.workbook.json`](MDE_TVM_Regional_Vulnerability_Workbook.workbook.json) | Workbook source (Region/Device/Lookback parameters · TVM panels · CISA KEV section) |

---

## Deployment

> Replace the parameter defaults in [`deploy-tvm-graph-ingest.bicep`](deploy-tvm-graph-ingest.bicep) and [`deploy-tvm-workbook.bicep`](deploy-tvm-workbook.bicep) with your subscription, RG, and workspace.

```powershell
$sub = '<your-subscription-id>'
$rg  = 'Sentinel'

# 1. Deploy UAMI, custom table, DCR, Logic App, and role assignments
az deployment group create -g $rg --subscription $sub `
    --template-file .\deploy-tvm-graph-ingest.bicep

# 2. Grant Microsoft Graph ThreatHunting.Read.All to the UAMI (admin consent equivalent)
.\grant-graph-permission.ps1

# 3. Publish the workbook
az deployment group create -g $rg --subscription $sub `
    --template-file .\deploy-tvm-workbook.bicep

# 4. Trigger the first run manually (Recurrence next fires at 04:00 UTC)
az rest --method POST `
    --uri "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Logic/workflows/la-tvm-graph-ingest/triggers/DailyAt04UTC/run?api-version=2019-05-01"
```

### Validation

```kql
// TVM ingestion
TvmRegional_CL
| summarize Rows=count(), Devices=dcount(DeviceId), Cves=dcount(CveId), Latest=max(TimeGenerated)

// KEV ingestion
CisaKev_CL
| summarize Rows=count(), Cves=dcount(CveId), Vendors=dcount(VendorProject), Latest=max(TimeGenerated)

// KEV-matched hosts (mirror of the workbook panel)
let LatestKev = CisaKev_CL | where isnotempty(CveId) | summarize arg_max(TimeGenerated, *) by CveId;
let LatestTvm = TvmRegional_CL
    | where TimeGenerated > ago(7d)
    | where isnotempty(DeviceId) and isnotempty(CveId)
    | summarize arg_max(TimeGenerated, *) by DeviceId, CveId;
LatestTvm
| join kind=inner LatestKev on CveId
| project DeviceName, CveId, VulnerabilityName, VendorProject, KnownRansomwareCampaignUse, DueDate
```

---

## Operational notes

- **DCR data-plane cache.** When you add a new stream/dataFlow to the DCR, the Logs Ingestion endpoint can take ~5 minutes to pick up the change. The first 1–2 runs may return `400 InvalidStream` even though the ARM control plane shows the stream — wait, then re-trigger.
- **Custom table must pre-exist.** The DCR validates that destination tables exist at deployment time, so [`deploy-tvm-graph-ingest.bicep`](deploy-tvm-graph-ingest.bicep) declares `CisaKev_CL` (`Microsoft.OperationalInsights/workspaces/tables@2025-02-01`) **before** the DCR and uses `dependsOn` on the DCR.
- **DCR location must match workspace region.** UAMIs cannot be moved across regions, so pin `param location = '<workspaceRegion>'` rather than relying on `resourceGroup().location`.
- **Recurrence fires on creation.** The Logic App fires its `Recurrence` trigger immediately when first deployed, before role assignments propagate. The first run usually fails on `RunHuntingQuery` (Forbidden) — re-trigger after the role assignment lands.
- **CISA KEV feed is anonymous HTTPS.** No auth required; the GET sends `Accept: application/json` and a friendly `User-Agent`.

---

## Architecture decisions that were tried and abandoned

| Approach | Why it was abandoned |
|---|---|
| Sentinel **Summary Rule** over `DeviceTvmSoftwareVulnerabilities` | Source table is 0 rows in LAW analytics tier in this tenant — Summary Rule had nothing to summarize. |
| Sentinel **KQL Job** writing to `TvmRegional_KQL_CL` | TVM tables are not in the data lake System Tables tier in this tenant. |
| Workbook **Sentinel Data Lake** data source | Workbook source has a per-tenant table allowlist that excludes `DeviceTvmSoftwareVulnerabilities` even though the table is queryable from Defender's Data Lake KQL page. |
| Workbook **Custom Endpoint** to a Function App proxy (`func-tvm-xdr-hunt-proxy`) | Workbook Custom Endpoints can't acquire/forward an Entra Bearer token for a custom audience; EasyAuth blocked every workbook call. The whole proxy stack was decommissioned. |
| Workbook **Microsoft Graph** data source | Graph data source supports GET/GETARRAY only; cannot POST to `runHuntingQuery`. |

The final Logic App + DCR design is the only path that satisfies "no source-table dependency, no secrets, queryable from a workbook."

---

## License

MIT

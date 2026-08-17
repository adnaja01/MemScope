# MemScope - Digital Memory Forensics Application

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python)
![PySide6](https://img.shields.io/badge/PySide6-Latest-41CD52?style=flat-square&logo=qt)
![Volatility3](https://img.shields.io/badge/Volatility3-Integrated-FF6B6B?style=flat-square)
![SQLite](https://img.shields.io/badge/SQLite-Case_Database-003B57?style=flat-square&logo=sqlite)

*Enhancing Digital Memory Forensics Through Automated Workflow Integration*

</div>

---

## Executive Summary

MemScope is a cross-platform digital memory forensics application that unifies the entire volatile memory analysis workflow into a single graphical environment. The platform integrates memory acquisition, SHA-256 integrity verification, Volatility 3 forensic analysis, threat intelligence enrichment, and structured case management—eliminating the need for investigators to manually orchestrate multiple disconnected tools.

The application addresses critical challenges in modern digital forensics: the rising prevalence of fileless malware that leaves no disk traces, the fragmentation of existing forensic workflows, and the need for accessible, reproducible investigation processes. MemScope reduces complexity, minimizes human error, and accelerates incident response timelines.

---

## Technology Stack

| Category | Technology | Version |
|----------|-----------|---------|
| Core Language | Python | 3.8+ |
| GUI Framework | PySide6 | Latest |
| Memory Analysis | Volatility 3 | Latest |
| Database | SQLite | Built-in |
| Windows Acquisition | WinPMEM | Latest |
| Linux Acquisition | LiME | Latest |
| Integrity Verification | SHA-256 | Standard |
| Threat Intelligence | VirusTotal API | v3 |
| Threat Intelligence | AbuseIPDB API | v2 |
| Threat Intelligence | AlienVault OTX API | Latest |
| Testing Environment | VirtualBox | Latest |

### Core Dependencies

```txt
PySide6>=6.4.0
volatility3>=2.0.0
requests>=2.28.0
sqlite3>=3.0.0
hashlib>=3.0.0
```

---

## Feature Set

### Memory Acquisition

**Automated Acquisition**
- One-click memory capture with administrative privilege detection
- Cross-platform support for Windows (WinPMEM) and Linux (LiME)
- Automatic operating system detection and appropriate tool selection
- Real-time acquisition progress monitoring
- Post-acquisition metadata collection including timestamp, user, and system information

**Acquisition Metadata**
- Capture timestamp and duration
- Acquiring user identification
- Target system information
- Dump file size and location
- Acquisition method and tool version

### Integrity Verification

**SHA-256 Hashing**
- Automatic hash generation immediately following acquisition
- Hash value stored in case database with associated metadata
- Verification capability for loaded memory dumps
- Tamper detection for previously acquired evidence

**Stored Hash Information**
- SHA-256 hash value
- Generation timestamp
- Acquisition user
- Dump file location
- Dump file size

### Analysis Modes

**Quick Triage**
- Designed for rapid incident response scenarios
- Running process enumeration
- Active network connection analysis
- Command history extraction
- Minimal time-to-results optimization

**Standard Analysis**
- Comprehensive forensic investigation
- Hidden process detection
- Loaded module enumeration
- Suspicious memory region identification
- DLL analysis
- Process relationship mapping
- Extended artifact extraction

**Custom Analysis**
- Manual plugin selection from Volatility 3 framework
- Support for any Volatility 3 plugin
- Flexible parameter configuration
- Batch plugin execution

### Threat Intelligence Enrichment

**Integrated Lookup Services**

| Service | Purpose | Data Types |
|---------|---------|------------|
| VirusTotal | Malware and hash reputation | File hashes, URLs, domains |
| AbuseIPDB | IP address reputation | IPv4, IPv6 addresses |
| AlienVault OTX | Threat intelligence feeds | IPs, domains, hashes, URLs |

**Enrichment Features**
- Automatic lookup of extracted IP addresses, domains, and hashes
- API response caching to minimize redundant requests
- Rate limit handling and request throttling
- Enrichment results integrated into analysis reports

### Case Management

**SQLite Database**
- Structured storage for all investigation data
- Investigation metadata and timestamps
- Hash values and integrity records
- Analysis results and plugin outputs
- Threat intelligence findings
- Report generation information
- Reference management for raw memory dumps

**Database Schema**
- Investigations table with case identifiers
- Acquisition records with metadata
- Hash records with verification status
- Analysis results with plugin outputs
- Threat intelligence lookup results
- Report generation history

### Investigation History

**History Tracking Features**
- Complete acquisition history
- Analysis session history
- Metadata review and filtering
- Case summaries for previous investigations
- Report regeneration from historical data
- Timeline visualization of investigation activities

### Report Generation

**Report Contents**
- Case identification information
- Acquisition details and metadata
- SHA-256 verification results
- Analysis findings by plugin
- Threat intelligence enrichment results
- Investigation timeline
- Investigator notes and conclusions

**Report Formats**
- Structured text reports
- Formatted output for legal documentation
- Exportable case summaries

---

## Database Schema

### Investigations Table

```sql
{
  id: INTEGER PRIMARY KEY,
  case_name: TEXT,
  investigator: TEXT,
  created_at: TIMESTAMP,
  status: TEXT,
  notes: TEXT,
  dump_path: TEXT,
  dump_size: INTEGER,
  os_type: TEXT
}
```

### Acquisition Records Table

```sql
{
  id: INTEGER PRIMARY KEY,
  investigation_id: INTEGER,
  tool: TEXT,
  tool_version: TEXT,
  acquired_at: TIMESTAMP,
  acquired_by: TEXT,
  dump_path: TEXT,
  dump_size: INTEGER,
  os_type: TEXT,
  FOREIGN KEY (investigation_id) REFERENCES investigations(id)
}
```

### Hash Records Table

```sql
{
  id: INTEGER PRIMARY KEY,
  investigation_id: INTEGER,
  hash_value: TEXT,
  hash_algorithm: TEXT,
  generated_at: TIMESTAMP,
  dump_path: TEXT,
  dump_size: INTEGER,
  FOREIGN KEY (investigation_id) REFERENCES investigations(id)
}
```

### Analysis Results Table

```sql
{
  id: INTEGER PRIMARY KEY,
  investigation_id: INTEGER,
  plugin_name: TEXT,
  plugin_output: TEXT,
  analysis_mode: TEXT,
  executed_at: TIMESTAMP,
  FOREIGN KEY (investigation_id) REFERENCES investigations(id)
}
```

### Threat Intelligence Results Table

```sql
{
  id: INTEGER PRIMARY KEY,
  investigation_id: INTEGER,
  artifact_type: TEXT,
  artifact_value: TEXT,
  service: TEXT,
  result: TEXT,
  queried_at: TIMESTAMP,
  FOREIGN KEY (investigation_id) REFERENCES investigations(id)
}
```

---

## Application Architecture

### Module Structure

**GUI Module**
- PySide6-based graphical interface
- Central dashboard for workflow navigation
- Results visualization panels
- Investigation history browser
- Report generation interface

**Acquisition Module**
- Windows acquisition via WinPMEM
- Linux acquisition via LiME
- Automated tool selection based on OS detection
- Post-acquisition metadata generation

**Hashing Module**
- SHA-256 hash calculation
- Hash metadata storage
- Verification for loaded dumps

**Analysis Module**
- Volatility 3 integration layer
- Plugin execution management
- Results parsing and formatting
- Analysis mode configuration

**Threat Intelligence Module**
- API client implementations
- Response caching system
- Rate limit management
- Result normalization

**Database Module**
- SQLite connection management
- CRUD operations for all entities
- Schema migration support
- Query optimization

**History Module**
- Investigation retrieval
- Timeline generation
- Case summary construction
- Report regeneration

### Workflow Flow

```
                +----------------+
                |    MemScope    |
                +----------------+
                        |
                        v
             Operating System Detection
                        |
          +-------------+-------------+
          |                           |
          v                           v
       Windows                      Linux
       WinPMEM                      LiME
          |                           |
          +-------------+-------------+
                        |
                        v
             Memory Acquisition
                        |
                        v
            SHA-256 Hash Generation
                        |
                        v
            Volatility 3 Analysis
                        |
                        v
        Threat Intelligence Lookup
      (VirusTotal / AbuseIPDB / OTX)
                        |
                        v
             SQLite Case Database
                        |
                        v
      History  •  Reports  •  GUI Results
```

---

## Installation and Deployment

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git
- Administrator or root privileges on target system
- WinPMEM (Windows) or LiME (Linux)
- Linux kernel symbols generated via dwarf2json (Linux only)

### Installation Procedure

**1. Clone the repository**

```bash
git clone https://github.com/yourusername/MemScope.git
cd MemScope
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Configure Windows environment**
- Ensure WinPMEM is available on the system
- Launch PowerShell as Administrator
- Verify WinPMEM driver installation

**4. Configure Linux environment**
- Compile LiME kernel module
- Ensure sudo or root privileges
- Generate kernel symbols using dwarf2json
- Place symbols in the configured symbol directory

**5. Launch application**

```bash
python main.py
```

---

## Typical Investigation Workflow

1. Launch MemScope application
2. Detect target operating system
3. Acquire RAM memory image
4. Verify integrity via automatic SHA-256 hash generation
5. Store metadata in case database
6. Select analysis mode (Quick Triage, Standard, or Custom)
7. Execute Volatility 3 plugins
8. Enrich findings through threat intelligence lookups
9. Review analysis results
10. Generate professional forensic report
11. Save investigation to history for future reference

---

## Known Issues and Limitations

| Issue | Description | Workaround |
|-------|-------------|------------|
| Forensic Footprint | Live memory acquisition always introduces a small footprint | Minimize running processes during acquisition |
| Kernel Symbols | Linux analysis depends on correct kernel symbols | Generate symbols using dwarf2json before analysis |
| Plugin Coverage | Analysis depth limited by available Volatility 3 plugins | Use Custom Analysis for specific plugin requirements |
| API Rate Limits | Threat intelligence services enforce rate limits | Caching implemented; monitor API quota usage |
| Storage Requirements | RAM dumps can be several gigabytes in size | Ensure sufficient disk space before acquisition |

---

## Future Development Roadmap

### Phase 2 Features

| Feature | Priority | Estimated Complexity |
|---------|----------|---------------------|
| AI-assisted forensic analysis for anomaly detection | High | High |
| Machine learning-based suspicious pattern identification | High | High |
| Additional OS support (macOS, BSD) | Medium | High |
| Cloud-based case synchronization | Medium | Medium |
| Additional memory acquisition frameworks | Medium | Medium |
| Advanced report templates with customization | Medium | Low |
| Multi-user case management with role-based access | Low | Medium |
| Plugin marketplace for community contributions | Low | High |

---

## Challenges Addressed

During development, several technical challenges were identified and resolved:

- **Privilege Management** — Administrator and root privilege requirements for memory acquisition
- **Storage Handling** — Management of large RAM dump files (potentially gigabytes in size)
- **Symbol Generation** — Linux kernel symbol generation for accurate analysis
- **Compatibility** — Volatility 3 compatibility across different operating system versions
- **Evidence Integrity** — Ensuring memory acquisition integrity without compromising evidence
- **API Management** — Threat intelligence API rate limiting mitigated through caching

---

## Research Background

This software was developed as part of an undergraduate thesis at the Sarajevo School of Science and Technology.

**Title:** MemScope: Enhancing Digital Memory Forensics Through Automated Workflow Integration

The project investigates how integrating acquisition, integrity verification, analysis, and case management into a unified workflow can reduce complexity and improve accessibility in digital memory forensics.

---

## Testing Guidelines

### Functional Testing Checklist
- Application launch and initialization
- Operating system detection accuracy
- Memory acquisition on Windows and Linux
- SHA-256 hash generation and verification
- Quick Triage analysis execution
- Standard Analysis plugin execution
- Custom Analysis plugin selection
- Threat intelligence API integration
- Database record creation and retrieval
- Investigation history browsing
- Report generation and export
- Error handling for insufficient privileges
- Graceful handling of missing dependencies

---

## Acknowledgements

This project builds upon several outstanding open-source projects:

- Volatility Foundation
- Velocidex (WinPMEM)
- LiME (Linux Memory Extractor)
- Qt for Python (PySide6)
- VirusTotal
- AbuseIPDB
- AlienVault Open Threat Exchange

---

## Author

**Adna Jašarević**

Bachelor of Science in Computer Science


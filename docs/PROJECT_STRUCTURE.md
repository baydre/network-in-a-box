# Project Structure

This document provides a comprehensive overview of the Network-in-a-Box project organization.

## Directory Structure

```
network-in-a-box/
├── README.md                    # Main project documentation
├── test_suite.py                # Comprehensive integration tests
├── test_rules.json              # Test configuration for validation
├── src/                         # Core implementation
│   ├── vpcctl.py               # Main CLI tool and VPC orchestration
│   ├── exceptions.py           # Custom exception classes
│   ├── validation.py           # Input validation and safety checks  
│   ├── state.py                # Persistent state management
│   ├── monitor.py              # Network monitoring and health checks
│   ├── network_validator.py    # Network connectivity validation
│   ├── policy.py               # Security policy management
│   ├── test_servers.py         # Test application deployment
│   └── __init__.py             # Package initialization
├── docs/                       # Documentation hub
│   ├── README.md               # Documentation index and navigation
│   ├── task.md                 # Original project requirements
│   ├── validation_framework.md # Testing methodology
│   ├── REQUIREMENTS_COMPLIANCE.md # Requirements validation
│   └── COMPLIANCE_CHECK.md     # Implementation verification matrix
├── policies/                   # Security policy templates
│   └── default-policy.json     # Example security rules
└── Configuration Files
    ├── .gitignore                 # Git ignore patterns
    └── .vscode/                   # VS Code workspace settings
```

## File Categories

### Core Implementation (`src/`)

| File | Purpose | Lines | Key Features |
|------|---------|-------|-------------|
| **vpcctl.py** | Main orchestration engine | ~1200 | CLI, VPC lifecycle, NAT setup, peering |
| **validation.py** | Input validation & safety | ~300 | Name/CIDR/IP validation, conflict detection |
| **state.py** | State management | ~200 | Persistent storage, file locking, consistency |
| **network_validator.py** | Network testing | ~400 | Connectivity tests, health checks |
| **policy.py** | Security management | ~150 | JSON policy parsing, iptables rules |
| **monitor.py** | System monitoring | ~100 | Resource monitoring, diagnostics |
| **test_servers.py** | Test applications | ~100 | Python web server deployment |
| **exceptions.py** | Error handling | ~50 | Custom exception hierarchy |

### Documentation (`docs/`)

| File | Purpose | Audience | Content |
|------|---------|----------|---------|
| **README.md** | Documentation hub | All | Navigation and organization |
| **task.md** | Original requirements | Developers | Project specifications |
| **validation_framework.md** | Testing methodology | QA/Developers | Test case framework |
| **REQUIREMENTS_COMPLIANCE.md** | Compliance validation | Stakeholders | Requirements matrix |
| **COMPLIANCE_CHECK.md** | Implementation check | Technical leads | Detailed compliance |

### Testing & Validation

| File | Purpose | Coverage | Status |
|------|---------|----------|--------|
| **test_suite.py** | Integration tests | 13 tests, 100% pass rate | Complete |
| **test_rules.json** | Test configuration | Validation rules | Complete |

### Security & Policies (`policies/`)

| File | Purpose | Format | Usage |
|------|---------|---------|--------|
| **default-policy.json** | Security template | JSON rules | Policy examples |

## Module Dependencies

```
┌─────────────────────────────────────────────────────────────┐
│                       vpcctl.py                             │
│                   (Main Orchestrator)                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
│ validation.py│  │   state.py  │  │  policy.py  │
│              │  │             │  │             │
│ • Name check │  │ • File lock │  │ • JSON parse│
│ • CIDR valid │  │ • Persist   │  │ • iptables  │
│ • IP valid   │  │ • Consistency│  │ • Rules mgmt│
└──────────────┘  └─────────────┘  └─────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
│network_      │  │ monitor.py  │  │test_servers │
│validator.py  │  │             │  │.py          │
│              │  │ • Resource  │  │             │
│ • Ping tests │  │   monitor   │  │ • Web server│
│ • Connectivity│  │ • Health    │  │ • Test apps │
│ • Validation │  │   checks    │  │ • Deploy    │
└──────────────┘  └─────────────┘  └─────────────┘
```

## Design Principles

### Modularity
- Each module has a single, clear responsibility
- Minimal coupling between components
- Easy to test and maintain independently

### Error Handling
- Custom exception hierarchy in `exceptions.py`
- Comprehensive validation before operations
- Graceful degradation and recovery

### State Management  
- Persistent state with atomic operations
- File locking for concurrent access safety
- State validation and consistency checks

### Testability
- Comprehensive integration test suite
- Isolated test environments  
- Automated validation of all features

### Documentation
- Self-documenting code with clear naming
- Comprehensive external documentation
- Examples and usage guides for all features

## Development Workflow

### For New Features:
1. Update relevant modules in `src/`
2. Add tests to `test_suite.py`
3. Update documentation in `docs/`  
4. Validate compliance with requirements

### For Bug Fixes:
1. Identify affected module(s)
2. Add regression test if needed
3. Fix issue with minimal impact
4. Validate with full test suite

### For Documentation:
1. Update relevant files in `docs/`
2. Update cross-references
3. Maintain consistency across documents
4. Update this structure guide if needed

---

*This structure ensures maintainability, testability, and clarity for all project stakeholders.*
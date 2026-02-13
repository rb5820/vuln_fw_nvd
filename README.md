# Vulnerability Source - NVD Base

A simplified base module for National Vulnerability Database (NVD) integration in Odoo 18.

## Overview

This module provides the foundational NVD integration capabilities and serves as the base for specialized NVD extensions. It has been simplified to focus on core functionality, with advanced features moved to dedicated extension modules.

## Features

### 🔧 Core Functionality
- **NVD Data Source**: Basic NVD source definition and configuration
- **Simple API Integration**: Basic NVD API v2.0 connectivity
- **Basic Vulnerability Import**: Creates standard vulnerability records from NVD CVE data
- **Sync Logging**: Tracks synchronization activities and results
- **Rate Limiting**: Respects NVD API rate limits

### 📊 Basic Data Processing
- **CVE Import**: Creates vulnerability records with basic CVE information
- **CVSS Scoring**: Extracts basic CVSS scores (v3.1, v3.0, v2.0)
- **Severity Mapping**: Maps CVSS scores to severity levels
- **Update Detection**: Simple update detection based on modification dates

## Architecture

### Models
- **`vuln.source.nvd.importer`**: Basic NVD importer configuration
- **`vuln.fw.nvd.sync.log`**: Synchronization logging and tracking

### Specialized Extensions
For advanced functionality, install the specialized extension modules:

- **`vuln_fw_nvd_cpe`**: CPE (Common Platform Enumeration) specific features
  - Asset matching and CPE dictionary management
  - CPE-based vulnerability correlation
  - Asset inventory integration

- **`vuln_fw_nvd_cve`**: CVE (Common Vulnerabilities and Exposures) specific features
  - Advanced CVE analytics and risk assessment
  - Threat intelligence integration
  - Timeline tracking and collaboration tools
  - Advanced reporting and dashboards

## Installation

### Prerequisites
- Odoo 18.0+
- `vuln_fw_core` module (base vulnerability management)
- Python packages: `requests`, `python-dateutil`

### Installation Steps
1. Install the base module through the Odoo interface
2. Configure the NVD data source
3. Optionally install specialized extension modules for advanced features

## Configuration

### Basic Setup
1. The module automatically creates an NVD data source
2. Configure an NVD importer instance
3. Optionally set an API key for increased rate limits
4. Run manual synchronization or set up scheduled jobs

### API Configuration
- **API Endpoint**: Uses NVD API v2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
- **Rate Limits**: 10 requests per minute (50 with API key)
- **Data Format**: JSON responses from NVD

## Usage

### Manual Synchronization
```python
# Get importer instance
importer = self.env['vuln.source.nvd.importer'].search([('active', '=', True)], limit=1)

# Sync recent CVEs (last 7 days)
start_date = datetime.now() - timedelta(days=7)
result = importer.sync_from_nvd(start_date=start_date)
```

### Automated Synchronization
Set up scheduled actions (cron jobs) to automatically sync NVD data:
- Daily sync for recent CVEs
- Weekly full sync for comprehensive updates
- Error handling and notification

## Data Flow

1. **NVD API Call**: Fetch CVE data from NVD API v2.0
2. **Basic Processing**: Extract essential CVE information
3. **Vulnerability Creation**: Create/update standard vulnerability records
4. **Logging**: Track synchronization results and statistics
5. **Extension Processing**: Specialized modules can extend the imported data

## Limitations

This base module intentionally provides minimal functionality:
- **No Advanced Analytics**: Use `vuln_fw_nvd_cve` for analytics
- **No CPE Matching**: Use `vuln_fw_nvd_cpe` for asset correlation
- **Basic CVSS Parsing**: Only extracts base scores, not detailed metrics
- **Simple UI**: No advanced views or dashboards

## Development

### Extending the Base Module
The base module provides hooks for extension modules:

```python
# Extension modules can inherit from the importer
class ExtendedImporter(models.Model):
    _inherit = 'vuln.source.nvd.importer'
    
    def _post_process_vulnerability(self, vulnerability, nvd_data):
        # Add custom processing logic
        pass
```

### Adding Custom Processing
Extension modules can add processing steps during import:
- Override processing methods
- Add custom fields to vulnerability records
- Implement specialized data extraction

## Migration Notes

This module replaces the previous complex NVD module with:
- **Simplified Models**: Removed complex CVSS parsing models
- **Focused Functionality**: Core import functionality only
- **Extension Architecture**: Specialized features moved to extension modules

## Troubleshooting

### Common Issues
1. **API Rate Limits**: Configure API key or adjust sync frequency
2. **Network Connectivity**: Check NVD API accessibility
3. **Missing Extensions**: Install appropriate extension modules for advanced features

### Logging
Enable debug logging to troubleshoot issues:
```ini
[options]
log_level = debug
```

## License
LGPL-3.0

---

For advanced functionality, install:
- [vuln_fw_nvd_cpe](../vuln_fw_nvd_cpe/README.md) - CPE-specific features
- [vuln_fw_nvd_cve](../vuln_fw_nvd_cve/README.md) - CVE enhancements and analytics
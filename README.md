# Vulnerability Framework - National Vulnerability Database

Advanced NVD API integration module for comprehensive vulnerability management in Odoo 18.

## Overview

This module provides complete National Vulnerability Database (NVD) integration with advanced features including zero trust webhook systems, comprehensive CPE/CVE data management, and robust API connectivity. It includes both core functionality and specialized webhook integrations for real-time vulnerability data processing.

## Features

### 🔧 Core NVD Integration
- **Advanced API Connectivity**: Full NVD API v2.0 integration with authentication & rate limiting
- **Multi-endpoint Support**: CVE, CPE, and vulnerability data endpoints
- **Comprehensive Sync Operations**: Sample, full, and scheduled synchronization modes
- **Robust Error Handling**: Advanced sync logging with detailed error tracking

### 🔒 Zero Trust Webhook System
- **Secure Webhook Processing**: Zero trust architecture for external webhook integration
- **Payload Queueing**: Automatic payload queuing with blocked host tracking
- **Host Management**: Allowed/blocked host management system
- **CPE 2.3 URI Processing**: Advanced CPE processing through webhook endpoints

### 📊 Data Management
- **CPE Dictionary**: Complete CPE 2.3 dictionary with vendor/product correlation
- **CVE Database**: Comprehensive CVE data with timeline tracking
- **Reference Management**: NVD reference links and documentation tracking
- **Sync Logging**: Detailed synchronization activity logs with performance metrics

### 🎯 Advanced Features
- **Dashboard Views**: Real-time vulnerability statistics and monitoring
- **Vendor/Product Management**: Structured vendor and product cataloging
- **Webhook Integration**: External system integration capabilities
- **Migration Tools**: Database migration and data transformation utilities

## Architecture

### Core Models
- **`VulnFwNvdApiConnector`**: Advanced NVD API connector with authentication and rate limiting
- **`VulnFwNvdSyncLog`**: Comprehensive synchronization logging and performance tracking
- **`VulnFwNvdReference`**: NVD reference links and documentation management
- **`VulnFwNvdCpeDictionary`**: CPE 2.3 dictionary with vendor/product correlation
- **`VulnFwNvdCveDictionary`**: CVE database with timeline and severity tracking

### Webhook System
- **`VulnFwNvdWebhook`**: Core webhook configuration and management
- **`VulnFwNvdWebhookReceiver`**: Zero trust webhook receiver with validation
- **`VulnFwNvdWebhookPayloadQueue`**: Payload queueing system for blocked hosts
- **`VulnFwNvdWebhookAllowedHost`**: Whitelist management for trusted hosts
- **`VulnFwNvdWebhookBlockedHost`**: Security tracking for blocked hosts
- **`VulnFwNvdWebhookLog`**: Comprehensive webhook activity logging

### Data Management
- **`VulnFwNvdVendor`**: Structured vendor information management
- **`VulnFwNvdProduct`**: Product cataloging with vendor correlation
- **`MigrationVendorProduct`**: Database migration utilities

## Installation

### Prerequisites
- Odoo 18.0+
- Python packages: `requests`, `python-dateutil`
- Base Odoo modules: `base`, `mail`

### Installation Steps
1. Install the module through the Odoo interface
2. Configure NVD API connector with optional API key
3. Set up webhook receivers for real-time integration
4. Configure allowed hosts for zero trust webhook system

## Configuration

### NVD API Setup
1. Navigate to **Vulnerability Framework → Configuration → NVD API Connectors**
2. Create or configure the API connector
3. Set NVD API key for increased rate limits (optional)
4. Configure sync schedules and data retention policies

### Zero Trust Webhook System
1. Go to **Vulnerability Framework → Configuration → Webhook Receivers**
2. Configure webhook endpoints and authentication
3. Set up allowed host whitelist for security
4. Enable payload queueing for blocked host recovery

### API Configuration
- **API Endpoint**: NVD API v2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
- **Rate Limits**: 10 requests per minute (50 with API key)
- **Data Format**: JSON responses with CPE 2.3 URI support
- **Webhook Endpoints**: `/webhook/nvd/cpe` for external integrations

## Usage

### Manual Synchronization
```python
# Get API connector instance
connector = self.env['vuln.fw.nvd.api.connector'].search([('active', '=', True)], limit=1)

# Sync recent CVEs (last 7 days)
start_date = datetime.now() - timedelta(days=7)
result = connector.sync_nvd_data(start_date=start_date)
```

### Webhook Integration
```python
# Process webhook payload
webhook_data = {
    'cpe_uri': 'cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*',
    'action': 'vulnerability_update',
    'timestamp': datetime.now().isoformat()
}

# Send to webhook endpoint
response = requests.post(
    'http://your-odoo.com/webhook/nvd/cpe',
    json=webhook_data,
    headers={'Content-Type': 'application/json'}
)
```

### Automated Synchronization
Configure scheduled actions through **Settings → Technical → Scheduled Actions**:
- **Daily CVE Sync**: Recent vulnerability updates
- **Weekly Full Sync**: Comprehensive database refresh
- **Webhook Processing**: Real-time payload queue processing

## Data Flow

1. **NVD API Integration**: Advanced multi-endpoint data retrieval from NVD API v2.0
2. **Zero Trust Webhook Processing**: Secure external data reception with host validation
3. **Comprehensive Data Processing**: CPE 2.3 URI parsing, CVE timeline tracking
4. **Database Management**: Structured storage with vendor/product correlation
5. **Payload Queueing**: Automatic queuing for blocked hosts with recovery processing
6. **Dashboard Analytics**: Real-time statistics and vulnerability monitoring
7. **Sync Logging**: Detailed operation tracking with performance metrics

## Zero Trust Security Features

### Host Validation
- **Whitelist Management**: Configure trusted hosts for webhook access
- **Automatic Blocking**: Block suspicious or unauthorized webhook attempts
- **Payload Queueing**: Queue payloads from blocked hosts for later processing
- **Recovery Processing**: Process queued payloads when hosts are unblocked

### Security Logging
- **Webhook Activity**: Track all webhook requests and responses
- **Security Events**: Log blocked attempts and security violations
- **Access Patterns**: Monitor host access patterns and behavior
- **Simple UI**: No advanced views or dashboards

## Development

### Extending the Module
The module provides comprehensive APIs for extension:

```python
# Extend API connector functionality
class CustomNvdConnector(models.Model):
    _inherit = 'vuln.fw.nvd.api.connector'
    
    def _post_process_cve_data(self, cve_data):
        # Add custom CVE processing logic
        super()._post_process_cve_data(cve_data)
        # Custom processing here
```

### Webhook Integration
```python
# Custom webhook processor
class CustomWebhookProcessor(models.Model):
    _inherit = 'vuln.fw.nvd.webhook.receiver'
    
    def process_custom_payload(self, payload):
        # Implement custom payload processing
        if self._validate_payload_security(payload):
            return self._process_secure_payload(payload)
        else:
            self._queue_blocked_payload(payload)
```

### Adding Custom Views
Extend dashboard and management views:
- Override existing view records with `vuln_fw_nvd_*` naming convention
- Add custom actions following `action_vuln_fw_nvd_*` pattern
- Implement specialized reporting views

## Migration Notes

This module represents a complete refactoring with:
- **Consistent Naming**: All components follow `vuln_fw_nvd_*` naming convention
- **Zero Trust Architecture**: Advanced webhook security with payload queueing
- **Comprehensive Models**: Full CPE/CVE data management with correlation
- **Advanced API Integration**: Multi-endpoint support with robust error handling

## Troubleshooting

### Common Issues
1. **API Rate Limits**: Configure NVD API key or adjust sync frequency
2. **Webhook Security**: Verify allowed host configuration for zero trust system
3. **Payload Queue**: Monitor blocked host recovery and queue processing
4. **Network Connectivity**: Check NVD API and webhook endpoint accessibility

### Security Considerations
- **Webhook Endpoints**: Ensure proper firewall configuration for webhook access
- **Host Whitelisting**: Regularly review and update allowed host lists
- **Payload Validation**: Monitor webhook logs for suspicious activity
- **Queue Management**: Set appropriate queue retention and processing policies

### Performance Tuning
- **Sync Frequency**: Balance data freshness with API rate limits
- **Batch Processing**: Configure appropriate batch sizes for large datasets
- **Index Optimization**: Ensure database indexes on frequently queried fields
- **Queue Processing**: Optimize payload queue processing intervals

### Logging and Debugging
Enable comprehensive logging for troubleshooting:
```ini
[options]
log_level = debug
```

Monitor specific components:
- **NVD Sync**: Check sync logs for API connectivity issues
- **Webhook Processing**: Monitor webhook logs for security events
- **Queue Management**: Track payload queue processing status
- **Database Operations**: Monitor database performance and indexing

## License
LGPL-3.0

---

## Module Structure

```
vuln_fw_nvd/
├── models/                     # Core data models
│   ├── vuln_fw_nvd_api_connector.py
│   ├── vuln_fw_nvd_webhook_*.py
│   └── ...
├── views/                      # User interface definitions
│   ├── vuln_fw_nvd_dashboard_views.xml
│   ├── vuln_fw_nvd_webhook_*.xml
│   └── menus.xml
├── controllers/                # HTTP controllers
│   └── vuln_fw_nvd_webhooks_controller.py
├── data/                       # Default data and configuration
├── security/                   # Access control
└── static/description/         # Module assets
```
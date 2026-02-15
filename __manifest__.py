# -*- coding: utf-8 -*-
{
    'name': 'Vulnerability NVD API Connector',
    'version': '18.0.1.0.0',
    'category': 'Security',
    'summary': 'Core NVD API connector for vulnerability data',
    'description': """
        Core National Vulnerability Database (NVD) API connector that provides:
        * Advanced NVD API connectivity with authentication & rate limiting
        * Multi-endpoint support (CVE, CPE, vulnerability data)
        * Configurable sync operations (sample, full, scheduled)
        * Foundation for specialized NVD extensions (CPE/CVE modules)
        * Robust error handling and sync logging
        
        For specialized features use:
        * vuln_fw_nvd_cpe: CPE dictionary management and matching
        * vuln_fw_nvd_cve: CVE-specific enhancements and analytics
    """,
    'author': 'RB5820',
    'website': 'https://www.attiesatelier.be',
    'depends': [
        'base',
        'mail',
    ],
    'external_dependencies': {
        'python': ['requests', 'python-dateutil'],
    },
    'data': [
        'security/security.xml',
        'security/ir.model.access.csv',
        'views/menus.xml',
        'views/vuln_fw_nvd_connector_views.xml',
        'views/vuln_fw_nvd_reference_views.xml',
        'views/vuln_fw_nvd_sync_log_views.xml',
        'views/vuln_fw_nvd_webhook_views.xml',
        'views/vuln_fw_nvd_webhook_receiver_views.xml',
        'views/vuln_fw_nvd_webhook_payload_queue_views.xml',
        'views/dashboard_views.xml',
        'data/ir_cron.xml',
        #
        'data/vuln_fw_nvd_api_connector.xml',
    ],
    'demo': [
        'demo/nvd_demo.xml',
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'OPL-1',
}
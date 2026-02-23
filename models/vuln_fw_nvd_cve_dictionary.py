# -*- coding: utf-8 -*-
"""Base CVE Dictionary model for NVD integration - shared across modules"""
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdCveDictionary(models.Model):
    """Base Common Vulnerabilities and Exposures (CVE) Dictionary - minimal fields for cross-module compatibility
    
    This base model allows both CPE and CVE modules to work with CVE dictionary
    entries independently. Each module can inherit and extend this model with
    their specific functionality:
    - vuln_fw_nvd_cve module adds full CVE management, analytics, enhancements
    - vuln_fw_nvd_cpe module can add CPE-CVE relationships and matching
    
    Both modules benefit from each other's enhancements through inheritance.
    """
    _name = 'vuln.fw.nvd.cve.dictionary'
    _description = 'Common Vulnerabilities and Exposures (CVE) Dictionary Entry (Base)'
    _order = 'published_date desc, cve_id'
    _rec_name = 'cve_id'

    # === CORE CVE FIELDS (Required for all modules) ===
    cve_id = fields.Char(
        string='CVE ID',
        required=True,
        index=True,
        help='CVE identifier (e.g., CVE-2023-12345)'
    )
    
    # === CVSS SCORES ===
    cvss_v2_score = fields.Float(
        string='CVSS v2 Score',
        digits=(3, 1),
        help='CVSS v2 base score (0.0-10.0)',
        default=0.0
    )
    
    cvss_v3_score = fields.Float(
        string='CVSS v3 Score',
        digits=(3, 1),
        help='CVSS v3 base score (0.0-10.0)',
        default=0.0
    )
    
    cvss_v2_vector = fields.Char(
        string='CVSS v2 Vector',
        help='CVSS v2 vector string'
    )
    
    cvss_v3_vector = fields.Char(
        string='CVSS v3 Vector',
        help='CVSS v3 vector string'
    )
    
    # === DESCRIPTION ===
    description = fields.Text(
        string='Description',
        help='CVE description from NVD'
    )
    
    # === TIMELINE ===
    published_date = fields.Datetime(
        string='Published Date',
        index=True,
        help='CVE publication date'
    )
    
    last_modified = fields.Datetime(
        string='Last Modified',
        help='Last modification date from NVD'
    )
    
    # === STATUS ===
    vuln_status = fields.Selection([
        ('Analyzed', 'Analyzed'),
        ('Modified', 'Modified'),
        ('Undergoing Analysis', 'Undergoing Analysis'),
        ('Awaiting Analysis', 'Awaiting Analysis'),
        ('Received', 'Received'),
        ('Rejected', 'Rejected'),
        ('Deferred', 'Deferred')
    ], string='Vulnerability Status', help='NVD analysis status')
    
    # === METADATA ===
    nvd_id = fields.Char(
        string='NVD ID',
        help='Internal NVD identifier'
    )
    
    source_identifier = fields.Char(
        string='Source',
        help='Source of the CVE (e.g., cve@mitre.org)'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Whether this CVE is active'
    )
    
    sync_date = fields.Datetime(
        string='Sync Date',
        help='Last synchronization date from NVD'
    )
    
    # === COMPUTED FIELDS ===
    severity_level = fields.Selection([
        ('none', 'None'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], string='Severity', compute='_compute_severity_level', store=True,
       help='Severity level based on CVSS scores')
    
    @api.depends('cvss_v3_score', 'cvss_v2_score')
    def _compute_severity_level(self):
        """Compute severity level based on CVSS scores"""
        for record in self:
            # Prefer CVSS v3, fallback to v2
            score = record.cvss_v3_score or record.cvss_v2_score
            
            if score == 0.0:
                record.severity_level = 'none'
            elif score < 4.0:
                record.severity_level = 'low'
            elif score < 7.0:
                record.severity_level = 'medium'
            elif score < 9.0:
                record.severity_level = 'high'
            else:
                record.severity_level = 'critical'
    
    def name_get(self):
        """Display CVE ID with severity emoji"""
        result = []
        for record in self:
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢',
                'none': '⚪'
            }.get(record.severity_level, '⚪')
            
            name = f"{severity_emoji} {record.cve_id}"
            result.append((record.id, name))
        return result
    
    _sql_constraints = [
        ('cve_id_unique', 'UNIQUE(cve_id)', 'CVE ID must be unique!'),
    ]

    @api.model
    def create_from_api_data(self, api_cve_data):
        """Create or update CVE from NVD API data format (vulnerabilities[].cve)"""
        if not api_cve_data:
            raise ValueError("Missing CVE API data")
        
        cve_id = api_cve_data.get('id')
        if not cve_id:
            raise ValueError("Missing CVE ID in API data")
        
        # Check if CVE already exists
        existing_cve = self.search([('cve_id', '=', cve_id)], limit=1)
        if existing_cve:
            # Update existing CVE
            existing_cve._update_from_api_data(api_cve_data)
            return existing_cve
        
        # Extract data from API format
        descriptions = api_cve_data.get('descriptions', [])
        description = ""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # Extract published date
        published_date_str = api_cve_data.get('published')
        published_date = None
        if published_date_str:
            try:
                # Parse ISO format timestamp (e.g., '2021-08-26T15:15:06.993')
                from datetime import datetime
                published_date = datetime.fromisoformat(published_date_str.replace('Z', '+00:00'))
            except Exception as e:
                _logger.warning(f"Failed to parse published date '{published_date_str}': {e}")

        last_modified_date_str = api_cve_data.get('lastModified')
        last_modified_date = None
        if last_modified_date_str:
            try:
                # Parse ISO format timestamp (e.g., '2021-08-26T15:15:06.993')
                from datetime import datetime
                last_modified_date = datetime.fromisoformat(last_modified_date_str.replace('Z', '+00:00'))
            except Exception as e:
                _logger.warning(f"Failed to parse last modified date '{last_modified_date_str}': {e}")
        
        # Extract CVSS scores from metrics
        cvss_v3_score = 0.0
        cvss_v2_score = 0.0
        
        metrics = api_cve_data.get('metrics', {})
        
        # CVSS v3.1
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            cvss_data = cvss_v31[0].get('cvssData', {})
            cvss_v3_score = cvss_data.get('baseScore', 0.0)
        
        # CVSS v3.0
        if cvss_v3_score == 0.0:
            cvss_v30 = metrics.get('cvssMetricV30', [])
            if cvss_v30:
                cvss_data = cvss_v30[0].get('cvssData', {})
                cvss_v3_score = cvss_data.get('baseScore', 0.0)
        
        # CVSS v2
        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            cvss_data = cvss_v2[0].get('cvssData', {})
            cvss_v2_score = cvss_data.get('baseScore', 0.0)
        
        # Create CVE record
        vals = {
            'cve_id': cve_id,
            'cvss_v3_score': cvss_v3_score,
            'cvss_v2_score': cvss_v2_score,
            'description': description,
            'published_date': published_date,
            'last_modified': last_modified_date,
            'vuln_status': 'Analyzed',  # Default status for API-created CVEs
            'active': True,
        }
        
        return self.create(vals)

    def _update_from_api_data(self, api_cve_data):
        """Update CVE from NVD API data format"""
        for record in self:
            # Extract updated data from API format
            descriptions = api_cve_data.get('descriptions', [])
            description = record.description
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
            
            # Extract dates
            last_modified_date_str = api_cve_data.get('lastModified')
            last_modified_date = record.last_modified
            if last_modified_date_str:
                try:
                    # Parse ISO format timestamp (e.g., '2021-08-26T15:15:06.993')
                    from datetime import datetime
                    last_modified_date = datetime.fromisoformat(last_modified_date_str.replace('Z', '+00:00'))
                except Exception as e:
                    _logger.warning(f"Failed to parse last modified date '{last_modified_date_str}': {e}")
                    last_modified_date = record.last_modified
            
            # Extract CVSS scores
            cvss_v3_score = record.cvss_v3_score
            cvss_v2_score = record.cvss_v2_score
            
            metrics = api_cve_data.get('metrics', {})
            
            # CVSS v3.1
            cvss_v31 = metrics.get('cvssMetricV31', [])
            if cvss_v31:
                cvss_data = cvss_v31[0].get('cvssData', {})
                cvss_v3_score = cvss_data.get('baseScore', cvss_v3_score)
            
            # CVSS v3.0
            if cvss_v3_score == record.cvss_v3_score:
                cvss_v30 = metrics.get('cvssMetricV30', [])
                if cvss_v30:
                    cvss_data = cvss_v30[0].get('cvssData', {})
                    cvss_v3_score = cvss_data.get('baseScore', cvss_v3_score)
            
            # CVSS v2
            cvss_v2 = metrics.get('cvssMetricV2', [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get('cvssData', {})
                cvss_v2_score = cvss_data.get('baseScore', cvss_v2_score)
            
            # Update record
            record.write({
                'cvss_v3_score': cvss_v3_score,
                'cvss_v2_score': cvss_v2_score,
                'description': description,
                'last_modified': last_modified_date,
                'sync_date': fields.Datetime.now(),
            })
    
    @api.model
    def create_from_webhook(self, webhook_data):
        """Create CVE from NVD webhook data"""
        cve_id = webhook_data.get('cveId')
        if not cve_id:
            raise ValueError("Missing cveId in webhook data")
        
        # Extract CVSS scores
        cvss_v3_score = 0.0
        cvss_v2_score = 0.0
        
        base_metric_v3 = webhook_data.get('baseMetricV3', {})
        if base_metric_v3:
            cvss_v3 = base_metric_v3.get('cvssV3', {})
            cvss_v3_score = cvss_v3.get('baseScore', 0.0)
        
        base_metric_v2 = webhook_data.get('baseMetricV2', {})
        if base_metric_v2:
            cvss_v2 = base_metric_v2.get('cvssV2', {})
            cvss_v2_score = cvss_v2.get('baseScore', 0.0)
        
        # Create CVE record
        vals = {
            'cve_id': cve_id,
            'cvss_v3_score': cvss_v3_score,
            'cvss_v2_score': cvss_v2_score,
            'description': webhook_data.get('description', ''),
            'published_date': self._parse_webhook_date(webhook_data.get('publishedDate')),
            'last_modified': self._parse_webhook_date(webhook_data.get('lastModifiedDate')),
            'vuln_status': 'Analyzed',  # Webhooks are for published CVEs
            'active': True,
        }
        
        return self.create(vals)

    def _update_from_webhook(self, webhook_data):
        """Update CVE from NVD webhook data"""
        for record in self:
            # Extract updated data
            cvss_v3_score = 0.0
            cvss_v2_score = 0.0
            
            base_metric_v3 = webhook_data.get('baseMetricV3', {})
            if base_metric_v3:
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                cvss_v3_score = cvss_v3.get('baseScore', 0.0)
            
            base_metric_v2 = webhook_data.get('baseMetricV2', {})
            if base_metric_v2:
                cvss_v2 = base_metric_v2.get('cvssV2', {})
                cvss_v2_score = cvss_v2.get('baseScore', 0.0)
            
            # Update record
            record.write({
                'cvss_v3_score': cvss_v3_score,
                'cvss_v2_score': cvss_v2_score,
                'description': webhook_data.get('description', record.description),
                'last_modified': self._parse_webhook_date(webhook_data.get('lastModifiedDate')),
            })

    def _parse_webhook_date(self, date_str):
        """Parse webhook date string to datetime object"""
        if not date_str:
            return None
        try:
            # Parse ISO format timestamp (e.g., '2021-08-26T15:15:06.993')
            from datetime import datetime
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception as e:
            _logger.warning(f"Failed to parse webhook date '{date_str}': {e}")
            return None

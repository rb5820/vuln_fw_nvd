# -*- coding: utf-8 -*-
"""Base CVE Dictionary model for NVD integration - shared across modules"""
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdCveDictionary(models.Model):
    """Base CVE Dictionary - minimal fields for cross-module compatibility
    
    This base model allows both CPE and CVE modules to work with CVE dictionary
    entries independently. Each module can inherit and extend this model with
    their specific functionality:
    - vuln_fw_nvd_cve module adds full CVE management, analytics, enhancements
    - vuln_fw_nvd_cpe module can add CPE-CVE relationships and matching
    
    Both modules benefit from each other's enhancements through inheritance.
    """
    _name = 'vuln.fw.nvd.cve.dictionary'
    _description = 'CVE Dictionary Entry (Base)'
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

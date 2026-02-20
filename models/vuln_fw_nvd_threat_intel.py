# -*- coding: utf-8 -*-
"""Threat Intelligence model for NVD vulnerability framework"""
from odoo import models, fields, api, _
import logging
from datetime import timedelta

_logger = logging.getLogger(__name__)


class VulnFwNvdThreatIntel(models.Model):
    """Threat Intelligence data for vulnerabilities"""
    _name = 'vuln.fw.nvd.threat.intel'
    _description = 'NVD Threat Intelligence'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'collection_timestamp desc'

    cve_id = fields.Many2one(
        'vuln.fw.nvd.cve.dictionary',
        string='CVE',
        required=True,
        ondelete='cascade',
        tracking=True
    )

    collection_timestamp = fields.Datetime(
        string='Collection Timestamp',
        default=fields.Datetime.now,
        required=True,
        tracking=True
    )

    source = fields.Selection([
        ('exploitdb', 'ExploitDB'),
        ('metasploit', 'Metasploit'),
        ('threat_feed', 'Threat Feed'),
        ('social_media', 'Social Media'),
        ('dark_web', 'Dark Web'),
        ('hacker_forum', 'Hacker Forum'),
        ('security_research', 'Security Research'),
        ('other', 'Other')
    ], string='Intelligence Source', required=True, tracking=True)

    source_url = fields.Char(
        string='Source URL',
        help='URL where the intelligence was found'
    )

    confidence_level = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('confirmed', 'Confirmed')
    ], string='Confidence Level', default='medium', required=True, tracking=True)

    intel_type = fields.Selection([
        ('exploit_available', 'Exploit Available'),
        ('active_exploitation', 'Active Exploitation'),
        ('poc_available', 'PoC Available'),
        ('weaponized', 'Weaponized'),
        ('ransomware', 'Ransomware Related'),
        ('botnet', 'Botnet Activity'),
        ('data_leak', 'Data Leak'),
        ('zero_day', 'Zero Day'),
        ('supply_chain', 'Supply Chain Attack'),
        ('other', 'Other')
    ], string='Intelligence Type', required=True, tracking=True)

    title = fields.Char(
        string='Title',
        required=True,
        tracking=True
    )

    content = fields.Text(
        string='Content',
        help='Detailed intelligence content'
    )

    author = fields.Char(
        string='Author/Source',
        help='Author or source of the intelligence'
    )

    tags = fields.Char(
        string='Tags',
        help='Comma-separated tags for categorization'
    )

    malware_names = fields.Char(
        string='Malware Names',
        help='Associated malware names'
    )

    actor_names = fields.Char(
        string='Threat Actor Names',
        help='Associated threat actor names'
    )

    affected_products = fields.Text(
        string='Affected Products',
        help='Products affected by this threat'
    )

    mitigation_steps = fields.Text(
        string='Mitigation Steps',
        help='Recommended mitigation steps'
    )

    references = fields.Text(
        string='References',
        help='Additional references and sources'
    )

    is_active = fields.Boolean(
        string='Active',
        default=True,
        help='Whether this intelligence is still active/relevant'
    )

    verification_status = fields.Selection([
        ('unverified', 'Unverified'),
        ('verified', 'Verified'),
        ('false_positive', 'False Positive')
    ], string='Verification Status', default='unverified', tracking=True)

    verified_by = fields.Many2one(
        'res.users',
        string='Verified By',
        tracking=True
    )

    verified_date = fields.Datetime(
        string='Verified Date',
        tracking=True
    )

    # Computed fields
    days_since_collection = fields.Integer(
        string='Days Since Collection',
        compute='_compute_days_since_collection',
        store=True
    )

    @api.depends('collection_timestamp')
    def _compute_days_since_collection(self):
        """Compute days since intelligence was collected"""
        for record in self:
            if record.collection_timestamp:
                delta = fields.Datetime.now() - record.collection_timestamp
                record.days_since_collection = delta.days
            else:
                record.days_since_collection = 0

    @api.model
    def create(self, vals):
        """Override create to add verification logic"""
        record = super().create(vals)

        # Auto-verify high confidence intelligence from trusted sources
        if (record.confidence_level in ['high', 'confirmed'] and
            record.source in ['security_research', 'exploitdb']):
            record.write({
                'verification_status': 'verified',
                'verified_by': self.env.user.id,
                'verified_date': fields.Datetime.now()
            })

        return record

    def action_verify_intelligence(self):
        """Mark intelligence as verified"""
        self.write({
            'verification_status': 'verified',
            'verified_by': self.env.user.id,
            'verified_date': fields.Datetime.now()
        })

    def action_mark_false_positive(self):
        """Mark intelligence as false positive"""
        self.write({
            'verification_status': 'false_positive',
            'verified_by': self.env.user.id,
            'verified_date': fields.Datetime.now()
        })

    @api.model
    def cleanup_old_intelligence(self, days=90):
        """Clean up old intelligence data"""
        cutoff_date = fields.Datetime.now() - timedelta(days=days)
        old_records = self.search([
            ('collection_timestamp', '<', cutoff_date),
            ('is_active', '=', True),
            ('verification_status', '!=', 'verified')
        ])

        old_records.write({'is_active': False})
        _logger.info("Deactivated %d old threat intelligence records", len(old_records))

        return len(old_records)
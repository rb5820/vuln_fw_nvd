# -*- coding: utf-8 -*-
"""Asset CPE Subscription Model - Tracks which assets have registered/subscribed to CPE URIs for vulnerability monitoring"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdAssetCpeSubscription(models.Model):
    """Track asset subscriptions to CPE URIs for vulnerability monitoring
    
    Each subscription represents an asset (from Lansweeper) that has registered
    interest in monitoring a specific CPE URI for vulnerabilities.
    """
    
    _name = 'vuln.fw.nvd.asset.cpe.subscription'
    _description = 'Asset CPE Subscription'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'subscribed_date desc'
    
    # === CORE DATA ===
    cpe_dictionary_id = fields.Many2one(
        'vuln.fw.nvd.cpe.dictionary',
        string='CPE Dictionary Entry',
        required=True,
        ondelete='cascade',
        index=True,
        tracking=True
    )
    
    cpe_uri = fields.Char(
        string='CPE URI',
        related='cpe_dictionary_id.cpe_name',
        store=True,
        readonly=True
    )
    
    # === ASSET INFORMATION (from Lansweeper) ===
    asset_id = fields.Integer(
        string='Asset ID',
        required=True,
        index=True,
        tracking=True,
        help='Lansweeper asset ID (computer/device)'
    )
    
    asset_name = fields.Char(
        string='Asset Name',
        required=True,
        tracking=True,
        help='Computer name or asset identifier from Lansweeper'
    )
    
    software_id = fields.Integer(
        string='Software ID',
        help='Lansweeper software product ID on the asset'
    )
    
    software_name = fields.Char(
        string='Software Name',
        help='Software product name from Lansweeper'
    )
    
    software_version = fields.Char(
        string='Software Version',
        help='Software version on the asset'
    )
    
    # === SUBSCRIPTION STATUS ===
    state = fields.Selection([
        ('pending', '⏳ Pending'),
        ('active', '✅ Active'),
        ('failed', '❌ Failed'),
        ('inactive', '🚫 Inactive'),
        ('archived', '📦 Archived')
    ], string='Status', default='pending', tracking=True, index=True)
    
    # === TIMESTAMPS ===
    subscribed_date = fields.Datetime(
        string='Subscription Date',
        default=fields.Datetime.now,
        readonly=True,
        tracking=True,
        help='When the asset subscribed to this CPE'
    )
    
    activated_date = fields.Datetime(
        string='Activated Date',
        readonly=True,
        tracking=True,
        help='When the subscription was activated'
    )
    
    deactivated_date = fields.Datetime(
        string='Deactivated Date',
        readonly=True,
        tracking=True
    )
    
    last_sync_date = fields.Datetime(
        string='Last Sync',
        readonly=True,
        help='Last time vulnerabilities were synced for this asset-CPE combination'
    )
    
    # === METADATA ===
    source_system = fields.Char(
        string='Source System',
        default='lansweeper_connector',
        readonly=True,
        help='Which system registered this subscription (e.g., lansweeper_connector)'
    )
    
    webhook_payload = fields.Json(
        string='Registration Payload',
        readonly=True,
        help='Original webhook payload that registered this asset'
    )
    
    notes = fields.Text(
        string='Notes',
        help='Additional notes about this subscription'
    )
    
    # === VULNERABILITIES TRACKING ===
    vulnerability_count = fields.Integer(
        string='Vulnerability Count',
        compute='_compute_vulnerability_count',
        store=True,
        help='Number of vulnerabilities found for this asset-CPE combination'
    )
    
    critical_vulnerability_count = fields.Integer(
        string='Critical Vulnerabilities',
        compute='_compute_critical_vulnerability_count',
        store=True,
        help='Number of critical vulnerabilities'
    )
    
    @api.depends('cpe_dictionary_id')
    def _compute_vulnerability_count(self):
        """Count vulnerabilities for this CPE"""
        for record in self:
            try:
                if record.cpe_dictionary_id:
                    record.vulnerability_count = self.env['vuln.fw.nvd.cve'].sudo().search_count([
                        ('cpe_ids', 'in', record.cpe_dictionary_id.id)
                    ])
                else:
                    record.vulnerability_count = 0
            except KeyError:
                # CVE model not yet loaded
                record.vulnerability_count = 0
    
    @api.depends('cpe_dictionary_id')
    def _compute_critical_vulnerability_count(self):
        """Count critical vulnerabilities for this CPE"""
        for record in self:
            try:
                if record.cpe_dictionary_id:
                    record.critical_vulnerability_count = self.env['vuln.fw.nvd.cve'].sudo().search_count([
                        ('cpe_ids', 'in', record.cpe_dictionary_id.id),
                        ('cvss_v3_base_score', '>=', 9.0)
                    ])
                else:
                    record.critical_vulnerability_count = 0
            except KeyError:
                # CVE model not yet loaded
                record.critical_vulnerability_count = 0
    
    def name_get(self):
        """Custom display name"""
        return [
            (record.id, f"{record.asset_name} → {record.software_name} ({record.cpe_uri})")
            for record in self
        ]
    
    @api.model
    def create_from_webhook(self, cpe_uri, asset_data, payload):
        """Create subscription from webhook payload
        
        Args:
            cpe_uri (str): CPE 2.3 format URI
            asset_data (dict): Asset information {'asset_id', 'asset_name', 'software_id', 'software_name', 'software_version'}
            payload (dict): Original webhook payload
            
        Returns:
            record: Created or existing subscription record
        """
        # Find or create CPE dictionary entry
        cpe_dict = self.env['vuln.fw.nvd.cpe.dictionary'].sudo().search([
            ('cpe_name', '=', cpe_uri)
        ], limit=1)
        
        if not cpe_dict:
            _logger.warning(f"CPE not found: {cpe_uri}")
            raise ValidationError(_("CPE URI not found in dictionary: %s") % cpe_uri)
        
        # Check if subscription already exists
        existing = self.search([
            ('cpe_dictionary_id', '=', cpe_dict.id),
            ('asset_id', '=', asset_data.get('asset_id')),
            ('state', '!=', 'archived')
        ], limit=1)
        
        if existing:
            _logger.info(f"Subscription already exists: {existing.id}")
            # Update last sync
            existing.write({'last_sync_date': fields.Datetime.now()})
            return existing
        
        # Create new subscription
        subscription = self.create({
            'cpe_dictionary_id': cpe_dict.id,
            'asset_id': asset_data.get('asset_id'),
            'asset_name': asset_data.get('asset_name'),
            'software_id': asset_data.get('software_id'),
            'software_name': asset_data.get('software_name'),
            'software_version': asset_data.get('software_version'),
            'state': 'pending',
            'webhook_payload': payload,
            'last_sync_date': fields.Datetime.now()
        })
        
        _logger.info(f"Created new asset CPE subscription: {subscription.id}")
        return subscription
    
    def action_activate(self):
        """Activate the subscription"""
        for record in self:
            record.write({
                'state': 'active',
                'activated_date': fields.Datetime.now()
            })
        _logger.info(f"Activated {len(self)} subscription(s)")
        return True
    
    def action_deactivate(self):
        """Deactivate the subscription"""
        for record in self:
            record.write({
                'state': 'inactive',
                'deactivated_date': fields.Datetime.now()
            })
        _logger.info(f"Deactivated {len(self)} subscription(s)")
        return True
    
    def action_archive(self):
        """Archive the subscription"""
        for record in self:
            record.write({
                'state': 'archived',
                'deactivated_date': fields.Datetime.now()
            })
        _logger.info(f"Archived {len(self)} subscription(s)")
        return True
    
    def action_reactivate(self):
        """Reactivate an archived subscription"""
        for record in self:
            record.write({
                'state': 'active',
                'activated_date': fields.Datetime.now(),
                'deactivated_date': None
            })
        _logger.info(f"Reactivated {len(self)} subscription(s)")
        return True
    
    def create(self, vals_list):
        """Override create to increment CPE subscriber_count"""
        records = super().create(vals_list)
        for record in records:
            if record.cpe_dictionary_id:
                record.cpe_dictionary_id.subscriber_count += 1
        return records
    
    def unlink(self):
        """Override unlink to decrement CPE subscriber_count"""
        cpe_dictionaries = self.mapped('cpe_dictionary_id')
        result = super().unlink()
        for cpe in cpe_dictionaries:
            if cpe.subscriber_count > 0:
                cpe.subscriber_count -= 1
        return result

    def _notify_cve_update(self, cve_id, cve_data):
        """Notify this subscription about CVE updates"""
        # For now, just log the notification
        # In the future, this could send emails, create activities, etc.
        _logger.info(f"🔔 Notifying subscription {self.id} (asset: {self.asset_name}) about CVE {cve_id}")
        
        # Update vulnerability counts
        self._update_vulnerability_counts()
        
        # Could create activity or send notification here
        # self.activity_schedule(
        #     'mail.mail_activity_data_todo',
        #     summary=f'CVE Update: {cve_id}',
        #     note=f'New or updated vulnerability {cve_id} affects CPE {self.cpe_uri}'
        # )

    def _update_vulnerability_counts(self):
        """Update vulnerability counts for this subscription"""
        for record in self:
            # Count vulnerabilities for this CPE
            vuln_count = self.env['vuln.fw.nvd.cve.dictionary'].search_count([
                ('cpe_dictionary_ids', 'in', record.cpe_dictionary_id.id)
            ])
            
            # Count critical vulnerabilities
            critical_count = self.env['vuln.fw.nvd.cve.dictionary'].search_count([
                ('cpe_dictionary_ids', 'in', record.cpe_dictionary_id.id),
                ('severity_level', '=', 'critical')
            ])
            
            record.write({
                'vulnerability_count': vuln_count,
                'critical_vulnerability_count': critical_count,
                'last_vulnerability_check': fields.Datetime.now()
            })

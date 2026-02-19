# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging
from datetime import timedelta
from collections import Counter

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhookBlockedHost(models.Model):
    """
    Webhook Blocked Host - Tracks hosts that have been blocked for review.
    Helps administrators identify legitimate hosts that need to be allowlisted.
    """
    _name = 'vuln.fw.nvd.webhook.blocked.host'
    _description = 'Webhook Blocked Host Review'
    _order = 'first_blocked desc, blocked_count desc'
    _rec_name = 'source_ip'
    
    # === HOST INFO ===
    
    source_ip = fields.Char(
        string='Source IP',
        required=True,
        index=True,
        help='IP address that was blocked'
    )
    
    # === STATISTICS ===
    
    blocked_count = fields.Integer(
        string='Blocked Attempts',
        default=1,
        help='Number of times this host was blocked'
    )
    
    first_blocked = fields.Datetime(
        string='First Blocked',
        default=fields.Datetime.now,
        required=True,
        help='When this host was first blocked'
    )
    
    last_blocked = fields.Datetime(
        string='Last Blocked',
        default=fields.Datetime.now,
        required=True,
        help='When this host was last blocked'
    )
    
    # === REVIEW STATUS ===
    
    review_status = fields.Selection([
        ('pending', '⏳ Pending Review'),
        ('investigating', '🔍 Investigating'),
        ('approved', '✅ Approved for Allowlist'),
        ('rejected', '❌ Permanently Blocked'),
        ('ignored', '⏭️ Ignored')
    ], string='Review Status', default='pending', 
       help='Administrative review status')
    
    # === CONTEXT INFO ===
    
    user_agent = fields.Text(
        string='User Agents',
        help='User agent strings seen from this host'
    )
    
    endpoints_attempted = fields.Text(
        string='Endpoints Attempted',
        help='Webhook endpoints this host tried to access'
    )
    
    payload_samples = fields.Text(
        string='Payload Samples',
        help='Sample payloads from this host (first few attempts)'
    )
    
    # === REVIEW NOTES ===
    
    review_notes = fields.Text(
        string='Review Notes',
        help='Administrative notes about this blocked host'
    )
    
    reviewed_by = fields.Many2one(
        'res.users',
        string='Reviewed By',
        help='User who reviewed this blocked host'
    )
    
    reviewed_date = fields.Datetime(
        string='Reviewed Date',
        help='When this host was reviewed'
    )
    
    # === ACTIONS ===
    
    def action_approve_and_allowlist(self):
        """Approve host and add to allowlist."""
        self.ensure_one()
        
        if self.review_status == 'approved':
            raise UserError("This host is already approved.")
        
        # Create allowed host entry
        allowed_host_vals = {
            'name': f"Auto-approved: {self.source_ip}",
            'host_type': 'ip_single',
            'host_pattern': self.source_ip,
            'host_description': f"Auto-approved from blocked host review. Originally blocked {self.blocked_count} times.",
            'require_token': True,
            'require_signature': False,
            'require_https': True,
            'sequence': 50
        }
        
        allowed_host = self.env['vuln.fw.nvd.webhook.allowed.host'].create(allowed_host_vals)
        
        # Update review status
        self.write({
            'review_status': 'approved',
            'reviewed_by': self.env.user.id,
            'reviewed_date': fields.Datetime.now(),
            'review_notes': f"Approved and added to allowlist (ID: {allowed_host.id})"
        })
        
        _logger.info(f"Approved blocked host {self.source_ip} and added to allowlist")
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'Host Approved',
                'message': f'Host {self.source_ip} has been added to the allowlist',
                'type': 'success',
            }
        }
    
    def action_reject_permanently(self):
        """Permanently reject this host."""
        self.ensure_one()
        
        self.write({
            'review_status': 'rejected',
            'reviewed_by': self.env.user.id,
            'reviewed_date': fields.Datetime.now()
        })
        
        _logger.info(f"Permanently rejected blocked host {self.source_ip}")
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'Host Rejected',
                'message': f'Host {self.source_ip} has been permanently blocked',
                'type': 'warning',
            }
        }
    
    def action_mark_investigating(self):
        """Mark host as under investigation."""
        self.write({
            'review_status': 'investigating',
            'reviewed_by': self.env.user.id,
            'reviewed_date': fields.Datetime.now()
        })
    
    def action_view_blocked_attempts(self):
        """View webhook payload queue records that were blocked from this IP."""
        self.ensure_one()
        
        return {
            'name': _('Blocked Webhook Attempts from %s') % self.source_ip,
            'type': 'ir.actions.act_window',
            'res_model': 'vuln.fw.nvd.webhook.payload.queue',
            'view_mode': 'list,form',
            'domain': [
                ('source_ip', '=', self.source_ip),
                ('status', 'in', ['failed', 'blocked'])
            ],
            'context': {
                'search_default_source_ip': self.source_ip,
                'search_default_blocked': True,
            },
            'target': 'current',
        }
    
    @api.model
    def record_blocked_host(self, source_ip, endpoint=None, user_agent=None, payload_sample=None):
        """
        Record a blocked host attempt for administrative review.
        
        Args:
            source_ip (str): IP address that was blocked
            endpoint (str): Endpoint that was attempted
            user_agent (str): User agent from request
            payload_sample (str): Sample of payload (truncated for security)
        """
        existing = self.search([('source_ip', '=', source_ip)], limit=1)
        
        if existing:
            # Update existing record
            vals = {
                'blocked_count': existing.blocked_count + 1,
                'last_blocked': fields.Datetime.now()
            }
            
            # Append new information
            if endpoint:
                endpoints = existing.endpoints_attempted or ''
                if endpoint not in endpoints:
                    vals['endpoints_attempted'] = f"{endpoints}\n{endpoint}".strip()
            
            if user_agent:
                agents = existing.user_agent or ''
                if user_agent not in agents:
                    vals['user_agent'] = f"{agents}\n{user_agent}".strip()
            
            if payload_sample and existing.blocked_count < 5:  # Only store first 5 samples
                samples = existing.payload_samples or ''
                vals['payload_samples'] = f"{samples}\n---\n{payload_sample}".strip()
            
            existing.write(vals)
            _logger.debug(f"Updated blocked host record for {source_ip} (total: {existing.blocked_count + 1})")
            return existing
        else:
            # Create new record
            vals = {
                'source_ip': source_ip,
                'blocked_count': 1,
                'endpoints_attempted': endpoint or '',
                'user_agent': user_agent or '',
                'payload_samples': payload_sample or ''
            }
            
            new_record = self.create(vals)
            _logger.info(f"Created new blocked host record for {source_ip}")
            return new_record
    
    @api.model
    def cleanup_old_blocked_hosts(self, days=30):
        """Clean up old blocked host records that were rejected or ignored."""
        cutoff_date = fields.Datetime.now() - timedelta(days=days)
        
        old_records = self.search([
            ('review_status', 'in', ['rejected', 'ignored']),
            ('last_blocked', '<', cutoff_date)
        ])
        
        count = len(old_records)
        old_records.unlink()
        
        _logger.info(f"Cleaned up {count} old blocked host records")
        return count
    
    def name_get(self):
        """Custom display name."""
        result = []
        for record in self:
            name = f"{record.source_ip} ({record.blocked_count} blocks)"
            if record.review_status != 'pending':
                name += f" [{record.review_status.upper()}]"
            result.append((record.id, name))
        return result
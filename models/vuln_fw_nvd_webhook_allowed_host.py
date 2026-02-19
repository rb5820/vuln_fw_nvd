# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import ipaddress
import re
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhookAllowedHost(models.Model):
    """
    Webhook Allowed Host - Zero Trust principle for webhook source validation.
    Defines which hosts/IPs are allowed to send webhooks to specific receivers.
    """
    _name = 'vuln.fw.nvd.webhook.allowed.host'
    _description = 'Webhook Allowed Host'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'sequence, name'
    
    # === BASIC INFO ===
    
    name = fields.Char(
        string='Host Name/Description',
        required=True,
        tracking=True,
        help='Descriptive name for this allowed host'
    )
    
    sequence = fields.Integer(
        string='Sequence',
        default=10,
        help='Order for evaluation (lower numbers evaluated first)'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True,
        tracking=True,
        help='Enable/disable this host allowlist entry'
    )
    
    # === HOST CONFIGURATION ===
    
    host_type = fields.Selection([
        ('ip_single', '🎯 Single IP Address'),
        ('ip_range', '🌐 IP Range (CIDR)'),
        ('hostname', '🔗 Hostname/FQDN'),
        ('wildcard', '⭐ Wildcard Pattern'),
        ('any', '🌍 Any Host (Not Recommended)')
    ], string='Host Type', required=True, default='ip_single', tracking=True,
       help='Type of host specification')
    
    host_pattern = fields.Char(
        string='Host Pattern',
        required=True,
        tracking=True,
        help='IP address, CIDR range, hostname, or wildcard pattern'
    )
    
    host_description = fields.Text(
        string='Host Details',
        help='Additional information about this host source'
    )
    
    # === SECURITY SETTINGS ===
    
    require_token = fields.Boolean(
        string='Require Webhook Token',
        default=True,
        help='Require valid webhook token for this host'
    )
    
    require_signature = fields.Boolean(
        string='Require HMAC Signature',
        default=False,
        help='Require valid HMAC signature for this host'
    )
    
    require_https = fields.Boolean(
        string='Require HTTPS',
        default=True,
        help='Only allow requests over HTTPS from this host'
    )
    
    # === RELATIONSHIPS ===
    
    receiver_ids = fields.Many2many(
        'vuln.fw.nvd.webhook.receiver',
        'webhook_base_receiver_allowed_host_rel',
        'allowed_host_id',
        'receiver_id',
        string='Webhook Receivers',
        help='Webhook receivers this host is allowed to access'
    )
    
    # === STATISTICS ===
    
    total_requests = fields.Integer(
        string='Total Requests',
        default=0,
        readonly=True,
        help='Total number of requests from this host'
    )
    
    allowed_requests = fields.Integer(
        string='Allowed Requests',
        default=0,
        readonly=True,
        help='Number of allowed requests from this host'
    )
    
    blocked_requests = fields.Integer(
        string='Blocked Requests',
        default=0,
        readonly=True,
        help='Number of blocked requests from this host'
    )
    
    last_request = fields.Datetime(
        string='Last Request',
        readonly=True,
        help='When the last request was received from this host'
    )
    
    last_status = fields.Selection([
        ('allowed', '✅ Allowed'),
        ('blocked', '🚫 Blocked'),
        ('error', '❌ Error'),
    ], string='Last Status', readonly=True,
       help='Status of the last request from this host')
    
    endpoints_accessed = fields.Text(
        string='Endpoints Accessed',
        readonly=True,
        help='List of webhook endpoints this host has accessed'
    )
    
    last_endpoint = fields.Char(
        string='Last Endpoint',
        readonly=True,
        help='Most recent endpoint accessed by this host'
    )
    
    # === VALIDATION ===
    
    @api.constrains('host_pattern', 'host_type')
    def _validate_host_pattern(self):
        """Validate host pattern format based on type."""
        for record in self:
            if not record.host_pattern:
                continue
                
            try:
                if record.host_type == 'ip_single':
                    ipaddress.ip_address(record.host_pattern)
                elif record.host_type == 'ip_range':
                    ipaddress.ip_network(record.host_pattern, strict=False)
                elif record.host_type == 'hostname':
                    # Basic hostname validation
                    if not re.match(r'^[a-zA-Z0-9\-\.]+$', record.host_pattern):
                        raise ValidationError(_('Invalid hostname format'))
                elif record.host_type == 'wildcard':
                    # Allow wildcards with basic validation
                    if not re.match(r'^[a-zA-Z0-9\-\.\*\?]+$', record.host_pattern):
                        raise ValidationError(_('Invalid wildcard pattern'))
                # 'any' type doesn't need validation
                        
            except ValueError as e:
                raise ValidationError(
                    _('Invalid host pattern "%(pattern)s" for type "%(type)s": %(error)s') % {
                        'pattern': record.host_pattern,
                        'type': record.host_type,
                        'error': str(e)
                    }
                )
    
    # === HOST MATCHING METHODS ===
    
    def check_host_allowed(self, source_ip, receiver_id=None):
        """
        Check if a host is allowed to access webhook receivers.
        
        Args:
            source_ip (str): IP address of the requesting host
            receiver_id (int): Optional specific receiver ID to check
            
        Returns:
            tuple: (allowed: bool, matched_host: record or None, reason: str)
        """
        domain = [('active', '=', True)]
        if receiver_id:
            domain.append(('receiver_ids', 'in', [receiver_id]))
        
        allowed_hosts = self.search(domain, order='sequence')
        
        for host in allowed_hosts:
            try:
                if host._matches_host_pattern(source_ip):
                    # Update statistics (endpoint will be tracked separately by caller)
                    host._update_request_stats('allowed', '/api/cpe/webhook')
                    _logger.info(f"Host {source_ip} allowed by rule: {host.name}")
                    return True, host, f"Matched allowlist rule: {host.name}"
            except Exception as e:
                _logger.error(f"Error checking host pattern {host.name}: {e}")
                host._update_request_stats('error', '/api/cpe/webhook')
                continue
        
        # No match found - blocked by zero trust
        _logger.warning(f"Host {source_ip} blocked - not in allowlist for receiver {receiver_id}")
        return False, None, "Host not in allowlist (Zero Trust)"
    
    def _matches_host_pattern(self, source_ip):
        """Check if source IP matches this host pattern."""
        self.ensure_one()
        
        if self.host_type == 'any':
            return True
        elif self.host_type == 'ip_single':
            return source_ip == self.host_pattern
        elif self.host_type == 'ip_range':
            try:
                network = ipaddress.ip_network(self.host_pattern, strict=False)
                return ipaddress.ip_address(source_ip) in network
            except ValueError:
                return False
        elif self.host_type == 'hostname':
            # For hostname matching, we'd need reverse DNS lookup
            # For now, exact match only
            return source_ip == self.host_pattern
        elif self.host_type == 'wildcard':
            # Convert wildcard pattern to regex
            pattern = self.host_pattern.replace('.', r'\.')
            pattern = pattern.replace('*', '.*')
            pattern = pattern.replace('?', '.')
            return bool(re.match(f'^{pattern}$', source_ip))
        
        return False
    
    def _update_request_stats(self, status, endpoint=None):
        """Update request statistics and endpoint tracking."""
        self.ensure_one()
        
        vals = {
            'total_requests': self.total_requests + 1,
            'last_request': fields.Datetime.now(),
            'last_status': status
        }
        
        if status == 'allowed':
            vals['allowed_requests'] = self.allowed_requests + 1
        elif status == 'blocked':
            vals['blocked_requests'] = self.blocked_requests + 1
        
        # Update endpoint tracking
        if endpoint:
            vals['last_endpoint'] = endpoint
            
            # Add to endpoints_accessed list if not already there
            current_endpoints = self.endpoints_accessed or ''
            endpoint_lines = [line.strip() for line in current_endpoints.split('\n') if line.strip()]
            
            endpoint_entry = f"{endpoint} (last accessed: {fields.Datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
            
            # Remove old entry for same endpoint if exists
            endpoint_lines = [line for line in endpoint_lines if not line.startswith(endpoint + ' ')]
            
            # Add new entry at the top
            endpoint_lines.insert(0, endpoint_entry)
            
            # Keep only last 10 endpoint entries
            endpoint_lines = endpoint_lines[:10]
            
            vals['endpoints_accessed'] = '\n'.join(endpoint_lines)
        
        self.sudo().write(vals)
    
    # === ACTION METHODS ===
    
    def action_view_request_logs(self):
        """View webhook request logs related to this allowed host."""
        self.ensure_one()
        
        # Search for payload queue records that match this host's IP pattern
        domain = []
        if self.host_type == 'ip_single':
            domain = [('source_ip', '=', self.host_pattern)]
        elif self.host_type == 'ip_range':
            # For IP range, we'd need to find all IPs in the range that have logs
            # For simplicity, we'll show all logs and let user filter
            domain = [('source_ip', '!=', False)]
        else:
            # For hostname/wildcard/any, show all logs
            domain = [('source_ip', '!=', False)]
        
        return {
            'name': _('Webhook Request Logs for %s') % self.name,
            'type': 'ir.actions.act_window',
            'res_model': 'vuln.fw.nvd.webhook.payload.queue',
            'view_mode': 'list,form',
            'domain': domain,
            'context': {
                'default_allowed_host_id': self.id,
                'search_default_source_ip': self.host_pattern if self.host_type == 'ip_single' else False,
            },
            'target': 'current',
        }
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to trigger blocked payload reprocessing"""
        allowed_hosts = super().create(vals_list)
        
        # For each new allowed host, check for blocked payloads to reprocess
        for host in allowed_hosts:
            try:
                host._reprocess_blocked_payloads()
            except Exception as e:
                _logger.error(f"Failed to reprocess blocked payloads for {host.name}: {e}")
        
        return allowed_hosts
    
    def write(self, vals):
        """Override write to trigger blocked payload reprocessing if host pattern changes"""
        result = super().write(vals)
        
        # If host pattern or active status changed, reprocess blocked payloads
        if 'host_pattern' in vals or 'active' in vals:
            for host in self:
                if host.active:  # Only reprocess if host is active
                    try:
                        host._reprocess_blocked_payloads()
                    except Exception as e:
                        _logger.error(f"Failed to reprocess blocked payloads for {host.name}: {e}")
        
        return result
    
    def _reprocess_blocked_payloads(self):
        """Reprocess blocked payloads for this allowed host pattern"""
        if not self.active:
            return
        
        # Find blocked payloads that match this host pattern
        blocked_payloads = self.env['vuln.fw.nvd.webhook.payload.queue'].sudo().search([
            ('state', '=', 'blocked'),
            ('receiver_id', 'in', self.receiver_ids.ids)
        ])
        
        reprocessed_count = 0
        for payload in blocked_payloads:
            try:
                # Check if this payload's source IP matches our pattern
                if self._matches_ip_pattern(payload.source_ip):
                    # Change status from blocked to pending for reprocessing
                    payload.write({
                        'state': 'pending',
                        'error_message': f'Reprocessed: Host {payload.source_ip} added to allowlist {self.name}',
                        'retry_count': 0  # Reset retry count
                    })
                    
                    # Trigger async processing
                    payload.with_delay(eta=5)._process_payload_async()
                    
                    reprocessed_count += 1
                    _logger.info(f"Reprocessing blocked payload {payload.id} from {payload.source_ip}")
                    
            except Exception as e:
                _logger.error(f"Failed to reprocess payload {payload.id}: {e}")
        
        if reprocessed_count > 0:
            _logger.info(f"Reprocessed {reprocessed_count} blocked payloads for allowed host {self.name}")
            
            # Update blocked host records to show they've been allowed
            blocked_hosts = self.env['vuln.fw.nvd.webhook.blocked.host'].sudo().search([
                ('source_ip', '=', 'pattern_match')  # We'll need to enhance this search
            ])
        
        return reprocessed_count

    def _matches_ip_pattern(self, source_ip):
        """Check if source IP matches this host's pattern"""
        try:
            if not self.active:
                return False
                
            if self.host_type == 'any':
                return True
            elif self.host_type == 'ip_single':
                return source_ip == self.host_pattern
            elif self.host_type == 'ip_range':
                import ipaddress
                try:
                    network = ipaddress.ip_network(self.host_pattern, strict=False)
                    ip = ipaddress.ip_address(source_ip)
                    return ip in network
                except ValueError:
                    return False
            elif self.host_type == 'hostname':
                # For hostname matching, we'd need reverse DNS lookup
                # For now, just do simple string comparison
                return source_ip == self.host_pattern
            elif self.host_type == 'wildcard':
                import fnmatch
                return fnmatch.fnmatch(source_ip, self.host_pattern)
                
            return False
            
        except Exception as e:
            _logger.error(f"Error matching IP {source_ip} against pattern {self.host_pattern}: {e}")
            return False

    # === UTILITY METHODS ===
    
    @api.model
    def create_default_localhost_rule(self, receiver_ids=None):
        """Create default localhost allowlist rule for development."""
        localhost_rule = self.search([
            ('name', '=', 'Localhost Development'),
            ('host_pattern', '=', '127.0.0.0/8')
        ])
        
        if not localhost_rule:
            vals = {
                'name': 'Localhost Development',
                'host_type': 'ip_range',
                'host_pattern': '127.0.0.0/8',
                'host_description': 'Allow localhost for development and testing',
                'require_token': False,
                'require_signature': False,
                'require_https': False,
                'sequence': 100
            }
            
            if receiver_ids:
                vals['receiver_ids'] = [(6, 0, receiver_ids)]
                
            localhost_rule = self.create(vals)
            _logger.info(f"Created default localhost allowlist rule: {localhost_rule.id}")
        
        return localhost_rule
    
    def name_get(self):
        """Custom display name."""
        result = []
        for record in self:
            name = f"{record.name} ({record.host_pattern})"
            if not record.active:
                name += " [INACTIVE]"
            result.append((record.id, name))
        return result
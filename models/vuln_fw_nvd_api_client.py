# -*- coding: utf-8 -*-
"""API Client Management for REST API Access"""
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import secrets
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdApiClient(models.Model):
    """
    API Client Configuration - Manages external systems that can access the REST API
    
    This is separate from webhook receivers:
    - Webhook Receivers: Inbound webhooks (external → vuln_fw_nvd)
    - API Clients: Bidirectional REST API (external ↔ vuln_fw_nvd)
    """
    _name = 'vuln.fw.nvd.api.client'
    _description = 'VulnFW NVD REST API Client'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'name'
    
    # === BASIC CONFIGURATION ===
    
    name = fields.Char(
        string='Client Name',
        required=True,
        tracking=True,
        help='Descriptive name for this API client (e.g., "Production Lansweeper Server")'
    )
    
    description = fields.Text(
        string='Description',
        help='Purpose and details about this API client'
    )
    
    client_type = fields.Selection([
        ('lansweeper', 'Lansweeper Connector'),
        ('custom', 'Custom Integration'),
        ('internal', 'Internal System'),
        ('partner', 'Partner System'),
    ], string='Client Type', default='custom', required=True, tracking=True)
    
    active = fields.Boolean(
        string='Active',
        default=True,
        tracking=True,
        help='Enable/disable API access for this client'
    )
    
    # === AUTHENTICATION ===
    
    api_token = fields.Char(
        string='API Token',
        required=True,
        tracking=True,
        copy=False,
        help='Secret token for API authentication. Keep this secure!'
    )
    
    token_expires = fields.Datetime(
        string='Token Expires',
        tracking=True,
        help='Optional expiration date for the API token'
    )
    
    # === ACCESS CONTROL ===
    
    allowed_ip_addresses = fields.Text(
        string='Allowed IP Addresses',
        help='Comma-separated list of allowed IP addresses or CIDR ranges (e.g., 192.168.1.0/24)'
    )
    
    enforce_ip_whitelist = fields.Boolean(
        string='Enforce IP Whitelist',
        default=False,
        tracking=True,
        help='If enabled, only requests from allowed IPs will be accepted'
    )
    
    allowed_endpoints = fields.Selection([
        ('all', 'All Endpoints'),
        ('subscribe_only', 'CPE Subscribe Only'),
        ('sync_only', 'CPE Sync Only'),
        ('custom', 'Custom Selection'),
    ], string='Allowed Endpoints', default='all', required=True, tracking=True,
       help='Which API endpoints this client can access')
    
    can_subscribe_cpe = fields.Boolean(
        string='Can Subscribe CPE',
        default=True,
        help='Allow POST /api/v1/cpe/subscribe'
    )
    
    can_sync_cpe = fields.Boolean(
        string='Can Sync CPE',
        default=True,
        help='Allow POST /api/v1/cpe/sync'
    )
    
    # === RATE LIMITING ===
    
    rate_limit_enabled = fields.Boolean(
        string='Enable Rate Limiting',
        default=True,
        help='Limit the number of API requests per time period'
    )
    
    rate_limit_requests = fields.Integer(
        string='Max Requests',
        default=100,
        help='Maximum number of requests allowed'
    )
    
    rate_limit_period = fields.Selection([
        ('minute', 'Per Minute'),
        ('hour', 'Per Hour'),
        ('day', 'Per Day'),
    ], string='Rate Limit Period', default='hour')
    
    # === STATISTICS ===
    
    total_requests = fields.Integer(
        string='Total API Requests',
        default=0,
        readonly=True,
        help='Total number of API requests made'
    )
    
    successful_requests = fields.Integer(
        string='Successful Requests',
        default=0,
        readonly=True
    )
    
    failed_requests = fields.Integer(
        string='Failed Requests',
        default=0,
        readonly=True
    )
    
    last_request_date = fields.Datetime(
        string='Last Request',
        readonly=True,
        help='Timestamp of the last API request'
    )
    
    last_request_ip = fields.Char(
        string='Last Request IP',
        readonly=True
    )
    
    # === METADATA ===
    
    notes = fields.Text(
        string='Notes',
        help='Internal notes about this API client'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    _sql_constraints = [
        ('unique_api_token', 'UNIQUE(api_token)', 'API token must be unique!'),
        ('unique_name', 'UNIQUE(name, company_id)', 'Client name must be unique per company!'),
    ]
    
    @api.model
    def generate_token(self):
        """Generate a secure random API token"""
        return secrets.token_urlsafe(32)
    
    @api.model
    def create(self, vals):
        """Auto-generate token if not provided"""
        if not vals.get('api_token'):
            vals['api_token'] = self.generate_token()
        return super().create(vals)
    
    def action_regenerate_token(self):
        """Regenerate API token"""
        self.ensure_one()
        
        new_token = self.generate_token()
        self.write({
            'api_token': new_token,
            'token_expires': False,  # Clear expiration
        })
        
        _logger.info(f"🔄 API token regenerated for client: {self.name}")
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Token Regenerated'),
                'message': _('New API token has been generated. Update your client configuration.'),
                'type': 'warning',
                'sticky': True,
            }
        }
    
    def validate_request(self, request_ip=None):
        """
        Validate if a request from this client should be allowed
        
        Args:
            request_ip: IP address of the request (optional for IP validation)
            
        Returns:
            tuple: (allowed: bool, reason: str)
        """
        self.ensure_one()
        
        # Check if client is active
        if not self.active:
            return False, 'API client is deactivated'
        
        # Check token expiration
        if self.token_expires and fields.Datetime.now() > self.token_expires:
            return False, 'API token has expired'
        
        # Check IP whitelist if enforced
        if self.enforce_ip_whitelist and request_ip:
            if not self.allowed_ip_addresses:
                return False, 'No IP addresses allowed'
            
            allowed_ips = [ip.strip() for ip in self.allowed_ip_addresses.split(',')]
            if request_ip not in allowed_ips:
                # TODO: Add CIDR range checking
                return False, f'IP address {request_ip} not in whitelist'
        
        return True, 'OK'
    
    def log_request(self, success=True, request_ip=None):
        """Log an API request"""
        self.ensure_one()
        
        vals = {
            'total_requests': self.total_requests + 1,
            'last_request_date': fields.Datetime.now(),
        }
        
        if success:
            vals['successful_requests'] = self.successful_requests + 1
        else:
            vals['failed_requests'] = self.failed_requests + 1
        
        if request_ip:
            vals['last_request_ip'] = request_ip
        
        self.write(vals)
    
    @api.model
    def authenticate(self, api_token):
        """
        Authenticate an API request by token
        
        Args:
            api_token: The API token from the request
            
        Returns:
            recordset: The authenticated API client or empty recordset
        """
        if not api_token:
            return self.env['vuln.fw.nvd.api.client']
        
        client = self.search([
            ('api_token', '=', api_token),
            ('active', '=', True)
        ], limit=1)
        
        if client:
            # Check if token is expired
            if client.token_expires and fields.Datetime.now() > client.token_expires:
                _logger.warning(f"⚠️ Expired token used: {client.name}")
                return self.env['vuln.fw.nvd.api.client']
        
        return client

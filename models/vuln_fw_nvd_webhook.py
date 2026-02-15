# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import logging
import requests
import json
from datetime import datetime

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhook(models.Model):
    """
    Base Webhook Configuration for NVD vulnerability data.
    Sends vulnerability framework updates to external systems.
    """
    _name = 'vuln.fw.nvd.webhook'
    _description = 'NVD Webhook Configuration'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'name'
    
    # === CORE WEBHOOK CONFIGURATION ===
    
    name = fields.Char(
        string='Webhook Name',
        required=True,
        tracking=True,
        help='Descriptive name for this webhook configuration'
    )
    
    webhook_type = fields.Selection([
        ('outbound', 'Outbound - Send Data'),
        ('inbound', 'Inbound - Receive Updates'),
    ], string='Webhook Type', default='outbound', required=True,
       help='Direction of webhook: send to external system or receive from external system')
    
    # === OUTBOUND WEBHOOK FIELDS ===
    
    target_url = fields.Char(
        string='Target URL',
        help='URL where data will be sent (for outbound webhooks)'
    )
    
    http_method = fields.Selection([
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH')
    ], string='HTTP Method', default='POST',
       help='HTTP method to use for outbound webhook requests')
    
    # === AUTHENTICATION ===
    
    auth_type = fields.Selection([
        ('none', 'No Authentication'),
        ('api_key', 'API Key'),
        ('bearer', 'Bearer Token'),
        ('oauth2', 'OAuth2'),
        ('basic', 'Basic Auth'),
    ], string='Authentication Type', default='api_key',
       help='Authentication method for webhook requests')
    
    api_key = fields.Char(
        string='API Key',
        help='API key for webhook authentication'
    )
    
    api_key_header = fields.Char(
        string='API Key Header',
        default='X-API-Key',
        help='Header name for API key (e.g., X-API-Key, Authorization)'
    )
    
    bearer_token = fields.Char(
        string='Bearer Token',
        help='Bearer token for authentication'
    )
    
    client_id = fields.Char(
        string='OAuth2 Client ID',
        help='OAuth2 Client ID'
    )
    
    client_secret = fields.Char(
        string='OAuth2 Client Secret',
        help='OAuth2 Client Secret'
    )
    
    basic_auth_user = fields.Char(
        string='Basic Auth User',
        help='Username for basic authentication'
    )
    
    basic_auth_password = fields.Char(
        string='Basic Auth Password',
        help='Password for basic authentication'
    )
    
    # === WEBHOOK TRIGGERS ===
    
    trigger_on_create = fields.Boolean(
        string='Trigger on Create',
        default=True,
        help='Send webhook when record is created'
    )
    
    trigger_on_write = fields.Boolean(
        string='Trigger on Update',
        default=True,
        help='Send webhook when record is updated'
    )
    
    trigger_on_delete = fields.Boolean(
        string='Trigger on Delete',
        default=False,
        help='Send webhook when record is deleted'
    )
    
    # === WEBHOOK PAYLOAD ===
    
    custom_headers = fields.Text(
        string='Custom Headers (JSON)',
        help='Additional HTTP headers as JSON (e.g., {"X-Custom": "value"})'
    )
    
    # === STATUS & TRACKING ===
    
    active = fields.Boolean(
        string='Active',
        default=True,
        tracking=True,
        help='Enable/disable this webhook'
    )
    
    last_triggered = fields.Datetime(
        string='Last Triggered',
        readonly=True,
        tracking=True,
        help='Date/time when webhook was last triggered'
    )
    
    last_status = fields.Selection([
        ('success', 'Success'),
        ('error', 'Error'),
        ('pending', 'Pending'),
    ], string='Last Status', readonly=True, tracking=True,
       help='Status of last webhook trigger')
    
    last_error = fields.Text(
        string='Last Error',
        readonly=True,
        tracking=True,
        help='Error message from last failed webhook'
    )
    
    # === STATISTICS ===
    
    total_triggers = fields.Integer(
        string='Total Triggers',
        default=0,
        readonly=True,
        help='Total number of times this webhook was triggered'
    )
    
    successful_triggers = fields.Integer(
        string='Successful Triggers',
        default=0,
        readonly=True,
        help='Number of successful webhook triggers'
    )
    
    failed_triggers = fields.Integer(
        string='Failed Triggers',
        default=0,
        readonly=True,
        help='Number of failed webhook triggers'
    )
    
    # === RELATIONSHIPS ===
    
    webhook_log_ids = fields.One2many(
        'vuln.fw.nvd.webhook.log',
        'webhook_id',
        string='Webhook Logs',
        readonly=True,
        help='History of webhook triggers and responses'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
        help='Company for this webhook'
    )
    
    # === CONSTRAINTS ===
    
    @api.constrains('target_url', 'webhook_type')
    def _check_target_url_required(self):
        """Ensure target_url is set for outbound webhooks."""
        for record in self:
            if record.webhook_type == 'outbound' and not record.target_url:
                raise ValidationError(_('Target URL is required for outbound webhooks.'))
    
    # === METHODS ===
    
    def test_webhook(self):
        """Test webhook with sample data."""
        self.ensure_one()
        
        if not self.active:
            raise UserError(_('Webhook must be active to test.'))
        
        if not self.target_url:
            raise UserError(_('Target URL is required for outbound webhooks.'))
        
        # Create sample payload
        payload = {
            'event': 'test',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'id': 0,
                'name': 'test_event',
                'type': 'test',
            }
        }
        
        try:
            response = self._send_webhook(payload)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Webhook Test Successful'),
                    'message': _('Status Code: %s\nResponse: %s') % (
                        response.status_code,
                        response.text[:200] if response.text else 'No response body'
                    ),
                    'type': 'success',
                    'sticky': True,
                }
            }
        except Exception as e:
            _logger.error("Webhook test failed: %s", str(e), exc_info=True)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Webhook Test Failed'),
                    'message': _('Error: %s') % str(e),
                    'type': 'error',
                    'sticky': True,
                }
            }
    
    def _send_webhook(self, payload):
        """
        Send webhook to target URL.
        
        Args:
            payload (dict): Payload data to send
            
        Returns:
            requests.Response: Response from webhook endpoint
        """
        self.ensure_one()
        
        if not self.active or not self.target_url:
            return None
        
        headers = {'Content-Type': 'application/json'}
        
        # Add authentication headers
        if self.auth_type == 'api_key' and self.api_key:
            headers[self.api_key_header] = self.api_key
        elif self.auth_type == 'bearer' and self.bearer_token:
            headers['Authorization'] = f'Bearer {self.bearer_token}'
        elif self.auth_type == 'basic' and self.basic_auth_user and self.basic_auth_password:
            import base64
            credentials = base64.b64encode(
                f'{self.basic_auth_user}:{self.basic_auth_password}'.encode()
            ).decode()
            headers['Authorization'] = f'Basic {credentials}'
        
        # Add custom headers
        if self.custom_headers:
            try:
                custom_headers = json.loads(self.custom_headers)
                headers.update(custom_headers)
            except json.JSONDecodeError:
                _logger.warning("Invalid JSON in custom headers for webhook %s", self.id)
        
        # Send request
        _logger.info("Sending webhook to %s with method %s", self.target_url, self.http_method)
        
        response = requests.request(
            method=self.http_method,
            url=self.target_url,
            json=payload,
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        return response
    
    def _trigger_webhook(self, record, event_type, payload=None):
        """
        Trigger webhook for an event.
        
        Args:
            record: The record triggering the event
            event_type (str): Type of event (create, write, delete)
            payload (dict): Custom payload (if None, subclass will build it)
        """
        self.ensure_one()
        
        if not self.active:
            return
        
        if not self._should_trigger(event_type):
            return
        
        try:
            if payload is None:
                payload = self._build_payload(record, event_type)
            
            response = self._send_webhook(payload)
            
            # Log successful webhook
            self.env['vuln.fw.nvd.webhook.log'].create({
                'webhook_id': self.id,
                'event_type': event_type,
                'status': 'success',
                'status_code': response.status_code,
                'request_payload': json.dumps(payload),
                'response_body': response.text[:1000] if response.text else '',
            })
            
            # Update webhook statistics
            self.write({
                'last_triggered': datetime.now(),
                'last_status': 'success',
                'last_error': '',
                'total_triggers': self.total_triggers + 1,
                'successful_triggers': self.successful_triggers + 1,
            })
            
            _logger.info("✅ Webhook triggered successfully for %s", self.name)
            
        except Exception as e:
            error_msg = str(e)
            _logger.error("❌ Webhook failed for %s: %s", self.name, error_msg, exc_info=True)
            
            # Log failed webhook
            self.env['vuln.fw.nvd.webhook.log'].create({
                'webhook_id': self.id,
                'event_type': event_type,
                'status': 'error',
                'error_message': error_msg,
            })
            
            # Update webhook statistics
            self.write({
                'last_triggered': datetime.now(),
                'last_status': 'error',
                'last_error': error_msg[:500],
                'total_triggers': self.total_triggers + 1,
                'failed_triggers': self.failed_triggers + 1,
            })
    
    def _should_trigger(self, event_type):
        """Check if webhook should trigger for given event type."""
        if event_type == 'create':
            return self.trigger_on_create
        elif event_type == 'write':
            return self.trigger_on_write
        elif event_type == 'delete':
            return self.trigger_on_delete
        return False
    
    def _build_payload(self, record, event_type):
        """Build webhook payload from record. Override in subclass for custom behavior."""
        return {
            'event': event_type,
            'timestamp': datetime.now().isoformat(),
            'webhook_id': self.id,
            'record_id': record.id,
        }

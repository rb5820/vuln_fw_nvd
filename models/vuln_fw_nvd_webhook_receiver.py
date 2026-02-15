# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging
import json

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhookReceiver(models.Model):
    """
    Base Webhook Receiver - Configuration for receiving inbound webhooks from external systems.
    """
    _name = 'vuln.fw.nvd.webhook.receiver'
    _description = 'NVD Webhook Receiver'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'name'
    
    # === BASIC CONFIGURATION ===
    
    name = fields.Char(
        string='Receiver Name',
        required=True,
        tracking=True,
        help='Descriptive name for this webhook receiver'
    )
    
    description = fields.Text(
        string='Description',
        help='Description of what this receiver does'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True,
        tracking=True,
        help='Enable/disable this webhook receiver'
    )
    
    # === SECURITY ===
    
    webhook_token = fields.Char(
        string='Webhook Token',
        required=True,
        tracking=True,
        help='Secret token to validate incoming webhook requests'
    )
    
    allowed_sources = fields.Text(
        string='Allowed Sources (IPs)',
        help='Comma-separated list of allowed IP addresses. Leave empty to allow all.'
    )
    
    validate_signature = fields.Boolean(
        string='Validate Signature',
        default=True,
        help='Require valid HMAC signature in X-Webhook-Signature header'
    )
    
    # === STATISTICS ===
    
    total_received = fields.Integer(
        string='Total Received',
        default=0,
        readonly=True,
        help='Total number of webhook events received'
    )
    
    successful_processed = fields.Integer(
        string='Successfully Processed',
        default=0,
        readonly=True,
        help='Number of successfully processed webhooks'
    )
    
    failed_processed = fields.Integer(
        string='Failed to Process',
        default=0,
        readonly=True,
        help='Number of failed webhook processing attempts'
    )
    
    last_received = fields.Datetime(
        string='Last Received',
        readonly=True,
        help='When the last webhook was received'
    )
    
    last_status = fields.Selection([
        ('success', 'Success'),
        ('error', 'Error'),
    ], string='Last Status', readonly=True,
       help='Status of last webhook processing')
    
    last_error = fields.Text(
        string='Last Error',
        readonly=True,
        help='Error message from last failed webhook'
    )
    
    # === RELATIONSHIPS ===
    
    receiver_log_ids = fields.One2many(
        'vuln.fw.nvd.webhook.receiver.log',
        'receiver_id',
        string='Received Webhooks',
        readonly=True,
        help='History of received webhooks'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
        help='Company for this webhook receiver'
    )
    
    # === CONSTRAINTS ===
    
    @api.constrains('webhook_token')
    def _check_webhook_token(self):
        """Ensure webhook token is set and not too short."""
        for record in self:
            if not record.webhook_token or len(record.webhook_token) < 8:
                raise ValidationError(_('Webhook token must be at least 8 characters long.'))
    
    # === METHODS ===
    
    def process_webhook(self, payload, source_ip=None, signature=None):
        """
        Process incoming webhook payload.
        
        Args:
            payload (dict): The webhook payload
            source_ip (str): IP address of webhook source
            signature (str): HMAC signature from X-Webhook-Signature header
            
        Returns:
            tuple: (success: bool, message: str, result: any)
        """
        self.ensure_one()
        
        if not self.active:
            return (False, "Webhook receiver is not active", None)
        
        # Validate source IP
        if self.allowed_sources and source_ip:
            allowed_ips = [ip.strip() for ip in self.allowed_sources.split(',')]
            if source_ip not in allowed_ips:
                return (False, f"Source IP {source_ip} not in allowed list", None)
        
        # Validate signature
        if self.validate_signature and signature:
            if not self._validate_signature(payload, signature):
                return (False, "Invalid webhook signature", None)
        
        try:
            result = self._process_payload(payload)
            
            # Log successful processing
            self.env['vuln.fw.nvd.webhook.receiver.log'].create({
                'receiver_id': self.id,
                'status': 'success',
                'payload': json.dumps(payload),
                'source_ip': source_ip,
            })
            
            # Update statistics
            self.write({
                'total_received': self.total_received + 1,
                'successful_processed': self.successful_processed + 1,
                'last_received': fields.Datetime.now(),
                'last_status': 'success',
                'last_error': '',
            })
            
            _logger.info("✅ Webhook received and processed successfully")
            return (True, "Webhook processed successfully", result)
            
        except Exception as e:
            error_msg = str(e)
            _logger.error("❌ Webhook processing failed: %s", error_msg, exc_info=True)
            
            # Log failed processing
            self.env['vuln.fw.nvd.webhook.receiver.log'].create({
                'receiver_id': self.id,
                'status': 'error',
                'payload': json.dumps(payload),
                'source_ip': source_ip,
                'error_message': error_msg,
            })
            
            # Update statistics
            self.write({
                'total_received': self.total_received + 1,
                'failed_processed': self.failed_processed + 1,
                'last_received': fields.Datetime.now(),
                'last_status': 'error',
                'last_error': error_msg[:500],
            })
            
            return (False, error_msg, None)
    
    def _validate_signature(self, payload, signature):
        """Validate HMAC signature of webhook payload."""
        import hmac
        import hashlib
        
        if not signature:
            return False
        
        payload_str = json.dumps(payload, sort_keys=True)
        expected_signature = hmac.new(
            self.webhook_token.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def _process_payload(self, payload):
        """
        Process webhook payload. Override in subclass for custom behavior.
        
        Args:
            payload (dict): The webhook payload
            
        Returns:
            any: Processing result
        """
        return {'status': 'processed', 'payload': payload}

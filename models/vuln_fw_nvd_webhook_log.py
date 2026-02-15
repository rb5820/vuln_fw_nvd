# -*- coding: utf-8 -*-

from odoo import models, fields
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhookLog(models.Model):
    """
    Base Webhook Log - Tracks all webhook triggers and responses.
    """
    _name = 'vuln.fw.nvd.webhook.log'
    _description = 'NVD Webhook Log'
    _order = 'create_date desc'
    _rec_name = 'webhook_id'
    
    # === RELATIONSHIPS ===
    
    webhook_id = fields.Many2one(
        'vuln.fw.nvd.webhook',
        string='Webhook',
        required=True,
        ondelete='cascade',
        help='The webhook that triggered this log entry'
    )
    
    # === EVENT INFORMATION ===
    
    event_type = fields.Selection([
        ('create', 'Create'),
        ('write', 'Update'),
        ('delete', 'Delete'),
        ('test', 'Test'),
    ], string='Event Type', required=True,
       help='Type of event that triggered the webhook')
    
    # === REQUEST INFORMATION ===
    
    request_payload = fields.Text(
        string='Request Payload',
        help='JSON payload sent in webhook request'
    )
    
    request_headers = fields.Text(
        string='Request Headers',
        help='HTTP headers sent with webhook request'
    )
    
    # === RESPONSE INFORMATION ===
    
    status = fields.Selection([
        ('success', 'Success'),
        ('error', 'Error'),
        ('pending', 'Pending'),
    ], string='Status', default='pending',
       help='Status of the webhook trigger')
    
    status_code = fields.Integer(
        string='HTTP Status Code',
        help='HTTP response status code'
    )
    
    response_body = fields.Text(
        string='Response Body',
        help='Response body from webhook endpoint'
    )
    
    error_message = fields.Text(
        string='Error Message',
        help='Error message if webhook failed'
    )
    
    # === METADATA ===
    
    duration_ms = fields.Float(
        string='Duration (ms)',
        help='Time taken to send webhook in milliseconds'
    )
    
    created_date = fields.Datetime(
        string='Created',
        default=fields.Datetime.now,
        readonly=True,
        help='When this log entry was created'
    )
    
    # === DISPLAY ===
    
    def name_get(self):
        """Custom display name for log entries."""
        result = []
        for record in self:
            name = f"{record.webhook_id.name} - {record.event_type} ({record.status})"
            result.append((record.id, name))
        return result

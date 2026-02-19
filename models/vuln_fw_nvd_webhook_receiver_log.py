# -*- coding: utf-8 -*-

from odoo import models, fields
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhookReceiverLog(models.Model):
    """
    Base Webhook Receiver Log - Tracks all received webhook events.
    """
    _name = 'vuln.fw.nvd.webhook.receiver.log'
    _description = 'National Vulnerability Database Webhook Receiver Log'
    _inherit = ['mail.thread']
    _order = 'create_date desc'
    _rec_name = 'receiver_id'
    
    # === RELATIONSHIPS ===
    
    receiver_id = fields.Many2one(
        'vuln.fw.nvd.webhook.receiver',
        string='Receiver',
        required=True,
        ondelete='cascade',
        help='The webhook receiver that received this event'
    )
    
    payload_queue_id = fields.Many2one(
        'vuln.fw.nvd.webhook.payload.queue',
        string='Payload Queue Entry',
        ondelete='set null',
        help='Link to queued payload for async processing'
    )
    
    # === REQUEST INFORMATION ===
    
    source_ip = fields.Char(
        string='Source IP',
        help='IP address of webhook source'
    )
    
    payload = fields.Text(
        string='Payload',
        help='Complete webhook payload received'
    )
    
    # === PROCESSING INFORMATION ===
    
    status = fields.Selection([
        ('received', '📥 Received'),
        ('queued', '⏳ Queued'),
        ('test_response', '🧪 Test Response'),
        ('blocked', '🚫 Blocked'),
        ('success', '✅ Success'),
        ('error', '❌ Error'),
    ], string='Status', default='received', tracking=True,
       help='Status of webhook processing')
    
    response = fields.Text(
        string='Response Payload',
        help='Outbound response payload sent back to client'
    )
    
    endpoint = fields.Char(
        string='Endpoint',
        help='Webhook endpoint that handled the request'
    )
    
    notes = fields.Text(
        string='Notes',
        help='Additional processing notes or details'
    )
    
    error_message = fields.Text(
        string='Error Message',
        tracking=True,
        help='Error message if webhook processing failed'
    )
    
    # === METADATA ===
    
    created_date = fields.Datetime(
        string='Created',
        default=fields.Datetime.now,
        readonly=True,
        help='When this webhook was received'
    )
    
    # === DISPLAY ===
    
    def name_get(self):
        """Custom display name for log entries."""
        result = []
        for record in self:
            name = f"{record.receiver_id.name} - {record.status}"
            if record.source_ip:
                name += f" ({record.source_ip})"
            result.append((record.id, name))
        return result

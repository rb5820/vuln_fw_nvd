# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import json
import logging
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhookPayloadQueue(models.Model):
    """
    Webhook Payload Queue for asynchronous processing.
    Stores received payloads for processing by background jobs.
    """
    _name = 'vuln.fw.nvd.webhook.payload.queue'
    _description = 'Webhook Payload Queue'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'
    
    # === STATUS & STATE ===
    state = fields.Selection([
        ('pending', '⏳ Pending'),
        ('blocked', '🚫 Blocked (Zero Trust)'),
        ('processing', '🔄 Processing'),
        ('success', '✅ Success'),
        ('error', '❌ Error'),
        ('ignored', '⏭️ Ignored'),
        ('retry', '🔄 Retry'),
        ('manual_review', '📋 Manual Review')
    ], string='Processing Status', default='pending', tracking=True, index=True)
    
    # === PAYLOAD INFO ===
    receiver_id = fields.Many2one(
        'vuln.fw.nvd.webhook.receiver',
        string='Receiver',
        required=True,
        ondelete='cascade',
        index=True
    )
    
    payload = fields.Text(
        string='Payload',
        required=True,
        help='Raw JSON payload data'
    )
    
    payload_size = fields.Integer(
        string='Payload Size (bytes)',
        compute='_compute_payload_size',
        store=True
    )
    
    # === PROCESSING INFO ===
    priority = fields.Integer(
        string='Priority',
        default=0,
        help='Higher priority processed first (negative for lower priority)'
    )
    
    retry_count = fields.Integer(
        string='Retry Count',
        default=0,
        tracking=True,
        help='Number of failed processing attempts'
    )
    
    max_retries = fields.Integer(
        string='Max Retries',
        default=3,
        help='Maximum number of retry attempts'
    )
    
    # === TIMESTAMPS ===
    received_date = fields.Datetime(
        string='Received At',
        default=fields.Datetime.now,
        required=True
    )
    
    processing_started = fields.Datetime(
        string='Processing Started',
        readonly=True,
        tracking=True
    )
    
    processing_completed = fields.Datetime(
        string='Processing Completed',
        readonly=True,
        tracking=True
    )
    
    # === RESULTS ===
    process_result = fields.Text(
        string='Processing Result',
        readonly=True,
        help='JSON result from payload processing'
    )
    
    error_message = fields.Text(
        string='Error Message',
        readonly=True,
        tracking=True,
        help='Error details if processing failed'
    )
    
    processing_duration = fields.Float(
        string='Processing Duration (seconds)',
        readonly=True,
        compute='_compute_processing_duration',
        store=True
    )
    
    # === METADATA ===
    source_ip = fields.Char(
        string='Source IP',
        help='IP address that sent the webhook'
    )
    
    signature = fields.Char(
        string='Request Signature',
        help='HMAC signature for verification'
    )
    
    tags = fields.Text(
        string='Tags',
        help='Comma-separated tags for filtering/organization'
    )
    
    # === RELATIONSHIPS ===
    webhook_log_ids = fields.One2many(
        'vuln.fw.nvd.webhook.receiver.log',
        'payload_queue_id',
        string='Related Logs'
    )
    
    # === METHODS ===
    
    @api.depends('payload')
    def _compute_payload_size(self):
        """Compute payload size in bytes"""
        for record in self:
            record.payload_size = len(record.payload.encode('utf-8')) if record.payload else 0
    
    @api.depends('processing_started', 'processing_completed')
    def _compute_processing_duration(self):
        """Compute processing duration"""
        for record in self:
            if record.processing_started and record.processing_completed:
                delta = record.processing_completed - record.processing_started
                record.processing_duration = delta.total_seconds()
            else:
                record.processing_duration = 0
    
    def action_process_now(self):
        """Manual trigger to process this payload immediately"""
        self.ensure_one()
        try:
            return self._process_payload()
        except Exception as e:
            self.write({
                'state': 'failed',
                'error_message': str(e)
            })
            raise
    
    def _process_payload(self):
        """
        Process the queued payload.
        Called by cron job or manually.
        """
        self.ensure_one()
        
        if self.state not in ['pending', 'error']:
            raise UserError(f"Cannot process payload in {self.state} state")
        
        if self.retry_count >= self.max_retries:
            self.write({'state': 'error', 'error_message': 'Max retries exceeded'})
            _logger.warning("Payload %d exceeded max retries", self.id)
            return False
        
        try:
            # Mark as processing
            self.write({
                'state': 'processing',
                'processing_started': fields.Datetime.now()
            })
            
            # Parse payload JSON
            try:
                payload_data = json.loads(self.payload)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON payload: {str(e)}")
            
            # Process through receiver
            result = self.receiver_id._process_payload(payload_data)
            
            # Mark as completed
            self.write({
                'state': 'success',
                'processing_completed': fields.Datetime.now(),
                'process_result': json.dumps(result) if result else '{}'
            })
            
            _logger.info(
                "Processed payload %d for receiver %s: %s",
                self.id,
                self.receiver_id.name,
                result
            )
            
            return True
        
        except Exception as e:
            # Increment retry count
            self.retry_count += 1
            
            if self.retry_count >= self.max_retries:
                state = 'error'
            else:
                state = 'retry'
            
            self.write({
                'state': state,
                'error_message': str(e),
                'processing_completed': fields.Datetime.now()
            })
            
            _logger.error(
                "Error processing payload %d (attempt %d/%d): %s",
                self.id,
                self.retry_count,
                self.max_retries,
                str(e)
            )
            
            return False
    
    @api.model
    def process_pending_payloads(self, batch_size=50, time_limit=3600):
        """
        Process pending payloads from queue.
        Called by cron job.
        
        Args:
            batch_size: Number of payloads to process per run
            time_limit: Maximum seconds to spend processing (for cron limits)
        """
        start_time = datetime.now()
        processed = 0
        failed = 0
        
        # Get pending and retry payloads, ordered by priority then age
        pending = self.search([
            ('state', 'in', ['pending', 'retry'])
        ], order='priority desc, received_date asc', limit=batch_size)
        
        for payload in pending:
            # Check time limit
            if (datetime.now() - start_time).total_seconds() > time_limit:
                _logger.info("Cron job time limit reached after processing %d payloads", processed)
                break
            
            try:
                if payload._process_payload():
                    processed += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                _logger.error("Exception processing payload %d: %s", payload.id, str(e))
        
        _logger.info(
            "Payload queue processing complete: %d processed, %d failed",
            processed,
            failed
        )
        
        return {
            'processed': processed,
            'failed': failed,
            'total': len(pending)
        }
    
    def action_retry(self):
        """Retry failed payloads"""
        failed = self.filtered(lambda x: x.state in ['error', 'retry'])
        if not failed:
            raise UserError("No failed payloads to retry")
        
        failed.write({
            'state': 'pending',
            'retry_count': 0,
            'error_message': ''
        })
        
        _logger.info("Marked %d failed payloads for retry", len(failed))
        return True
    
    def action_view_payload(self):
        """Display payload in a readable format"""
        self.ensure_one()
        try:
            payload_data = json.loads(self.payload)
            formatted = json.dumps(payload_data, indent=2)
        except:
            formatted = self.payload
        
        return {
            'type': 'ir.actions.act_window',
            'name': f'Payload {self.id}',
            'res_model': 'vuln.fw.nvd.webhook.payload.queue',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
    
    def action_send_to_review(self):
        """Send pending, retry, or failed payload to manual review"""
        for record in self:
            if record.state not in ['pending', 'retry', 'error']:
                raise UserError(
                    f"Cannot send {record.state} payload to review. "
                    "Only pending, retry, or error payloads can be reviewed."
                )
            record.write({'state': 'manual_review'})
        
        _logger.info("Moved %d payloads to manual review", len(self))
        
        # Create a notification
        if len(self) == 1:
            self.message_post(
                body=f"<p>Payload moved to <strong>Manual Review</strong> by {self.env.user.name}</p>",
                subtype_xmlid='mail.mt_comment'
            )
    
    def action_review_done(self):
        """Complete review and mark for processing"""
        for record in self:
            if record.state != 'manual_review':
                raise UserError(
                    f"Only payloads in Manual Review can be processed. "
                    f"This payload is {record.state}."
                )
            record.write({
                'state': 'pending',
                'retry_count': 0,
                'error_message': ''
            })
        
        _logger.info("Completed review for %d payloads, marked for processing", len(self))
        
        # Create a notification
        if len(self) == 1:
            self[0].message_post(
                body=f"<p>Review completed by <strong>{self.env.user.name}</strong>. Marked for processing.</p>",
                subtype_xmlid='mail.mt_comment'
            )
    
    def _process_payload_async(self):
        """Process webhook payload asynchronously"""
        self.ensure_one()
        
        if self.state != 'pending':
            _logger.warning(f"Payload queue {self.id} is not in pending state: {self.state}")
            return
        
        try:
            # Mark as processing
            self.write({
                'state': 'processing',
                'processing_started': fields.Datetime.now()
            })
            
            # Parse payload
            payload_data = json.loads(self.payload) if self.payload else {}
            _logger.info(f"Processing queued payload {self.id} from source: {self.source_ip}")
            
            # Determine processing based on payload content
            if payload_data.get('cpe_uri'):
                result = self._process_cpe_payload(payload_data)
            else:
                result = self._process_generic_payload(payload_data)
            
            # Mark as successful
            self.write({
                'state': 'success',
                'processing_completed': fields.Datetime.now(),
                'process_result': json.dumps(result)
            })
            
            _logger.info(f"Successfully processed queued payload {self.id}")
            
        except Exception as e:
            self.retry_count += 1
            error_msg = f"Async processing failed: {str(e)}"
            _logger.error(f"Failed to process queued payload {self.id}: {error_msg}")
            
            if self.retry_count >= self.max_retries:
                self.write({
                    'state': 'error',
                    'processing_completed': fields.Datetime.now(),
                    'error_message': error_msg
                })
            else:
                self.write({
                    'state': 'retry',
                    'error_message': error_msg
                })
                # Schedule retry
                self.with_delay(eta=300)._process_payload_async()  # Retry in 5 minutes
    
    def _process_cpe_payload(self, payload_data):
        """Process CPE-specific payload"""
        token = payload_data.get('token')
        cpe_uri = payload_data.get('cpe_uri')
        source = payload_data.get('source', 'external_system')
        metadata = payload_data.get('metadata', {})
        
        if not token or not cpe_uri:
            raise ValueError(f"Missing required fields - Token: {bool(token)}, CPE: {bool(cpe_uri)}")
        
        # Validate token against receiver
        if self.receiver_id.webhook_token != token:
            raise ValueError(f"Invalid webhook token")
        
        # Process CPE URI
        cpe_dict = self.env['vuln.fw.nvd.cpe.dictionary'].process_cpe_uri(
            cpe_uri, 
            source=source,
            metadata=metadata
        )
        
        if cpe_dict:
            return {
                'status': 'success',
                'message': 'CPE processed successfully',
                'cpe_id': cpe_dict.id,
                'cpe_name': cpe_dict.cpe_name,
                'vendor': cpe_dict.vendor,
                'product': cpe_dict.product,
                'version': cpe_dict.version
            }
        else:
            raise ValueError(f"Failed to process CPE URI: {cpe_uri}")
    
    def _process_generic_payload(self, payload_data):
        """Process generic webhook payload"""
        # Handle non-CPE payloads (like tests)
        if payload_data.get('test') is True:
            return {
                'status': 'success',
                'message': 'Test payload processed',
                'test_detected': True
            }
        
        # Add other payload type handling here
        return {
            'status': 'success',
            'message': 'Generic payload processed',
            'payload_type': 'unknown'
        }

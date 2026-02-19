# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdSyncLog(models.Model):
    _name = 'vuln.fw.nvd.sync.log'
    _description = 'National Vulnerability Database Synchronization Log'
    _check_company_auto = True
    _order = 'sync_date desc'

    sync_date = fields.Datetime(
        string='Sync Date',
        required=True,
        default=fields.Datetime.now,
        help='Date and time when sync was performed'
    )
    
    status = fields.Selection([
        ('running', 'Running'),
        ('success', 'Success'),
        ('error', 'Error'),
        ('partial', 'Partial Success')
    ], string='Status', required=True, default='running')
    
    start_date = fields.Datetime(
        string='Start Date Filter',
        help='Start date used for filtering NVD data'
    )
    
    end_date = fields.Datetime(
        string='End Date Filter',
        help='End date used for filtering NVD data'
    )
    
    total_processed = fields.Integer(
        string='Total Processed',
        default=0,
        help='Total number of CVEs processed'
    )
    
    created_count = fields.Integer(
        string='Created',
        default=0,
        help='Number of new vulnerability records created'
    )
    
    updated_count = fields.Integer(
        string='Updated',
        default=0,
        help='Number of existing vulnerability records updated'
    )
    
    error_count = fields.Integer(
        string='Errors',
        default=0,
        help='Number of errors encountered during sync'
    )
    
    duration = fields.Float(
        string='Duration (minutes)',
        help='Time taken to complete the synchronization'
    )
    
    message = fields.Text(
        string='Message',
        help='Sync result message or error details'
    )
    
    details = fields.Text(
        string='Details',
        help='Detailed log information'
    )
    
    # Company Support
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    def name_get(self):
        """Custom display name for sync logs"""
        result = []
        for record in self:
            name = f"NVD Sync {record.sync_date.strftime('%Y-%m-%d %H:%M')} - {record.status.title()}"
            result.append((record.id, name))
        return result
    
    def action_view_created_vulnerabilities(self):
        """View vulnerabilities created in this sync"""
        self.ensure_one()
        
        domain = [
            ('source_id.code', '=', 'NVD'),
            ('create_date', '>=', self.sync_date),
            ('create_date', '<=', self.sync_date + fields.Datetime.to_datetime('00:01:00'))
        ]
        
        return {
            'type': 'ir.actions.act_window',
            'name': f'Vulnerabilities Created - {self.sync_date}',
            'res_model': 'nvd.vulnerability',
            'view_mode': 'list,form',
            'domain': domain,
            'context': {'search_default_group_by_severity': 1}
        }
    
    @api.model
    def cleanup_old_logs(self, days=30):
        """Clean up old sync logs to prevent database bloat"""
        cutoff_date = fields.Datetime.now() - fields.Datetime.timedelta(days=days)
        old_logs = self.search([('sync_date', '<', cutoff_date)])
        
        if old_logs:
            count = len(old_logs)
            old_logs.unlink()
            _logger.info(f"Cleaned up {count} old NVD sync logs")
            
        return count
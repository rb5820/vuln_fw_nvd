# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdReference(models.Model):
    """
    Centralized model for storing all NVD references/URLs.
    Used across CPE products, vendors, CVEs, and other NVD data.
    """
    _name = 'vuln.fw.nvd.reference'
    _description = 'National Vulnerability Database Reference/URL'
    _order = 'url'
    _rec_name = 'url'
    
    # === CORE FIELDS ===
    url = fields.Char(
        string='URL',
        required=True,
        index=True,
        help='Reference URL from NVD API'
    )
    
    entity_name = fields.Char(
        string='Entity Name',
        index=True,
        help='Name of the NVD entity this reference belongs to (e.g., cisco, windows, CVE-2024-1234)'
    )
    
    entity_type = fields.Selection([
        ('vendor', 'Vendor'),
        ('product', 'Product'),
        ('cve', 'CVE'),
        ('other', 'Other'),
    ], string='Entity Type',
       help='Type of NVD entity this reference belongs to')
    
    ref_type = fields.Selection([
        ('version', 'Version'),
        ('vendor', 'Vendor'),
        ('product', 'Product'),
        ('advisory', 'Advisory'),
        ('patch', 'Patch'),
        ('issue', 'Issue Tracking'),
        ('exploit', 'Exploit'),
        ('mitigation', 'Mitigation'),
        ('third_party', 'Third Party Advisory'),
        ('other', 'Other'),
    ], string='Reference Type',
       help='Type of reference from NVD (e.g., Version, Vendor, Advisory)')
    
    description = fields.Text(
        string='Description',
        help='Additional information about this reference'
    )
    
    # === METADATA ===
    last_checked = fields.Datetime(
        string='Last Checked',
        help='Last time this URL was verified/checked'
    )
    
    status = fields.Selection([
        ('active', 'Active'),
        ('broken', 'Broken/404'),
        ('redirected', 'Redirected'),
        ('unknown', 'Unknown'),
    ], string='Status',
       default='unknown',
       help='URL status (active, broken, etc.)')
    
    usage_count = fields.Integer(
        string='Usage Count',
        compute='_compute_usage_count',
        store=True,
        help='Number of NVD entities referencing this URL'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Whether this reference is active'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    # === COMPUTED FIELDS ===
    @api.depends()
    def _compute_usage_count(self):
        """Compute total usage count across all NVD entities. Override in dependent modules."""
        for ref in self:
            ref.usage_count = 0
    
    # === CONSTRAINTS ===
    _sql_constraints = [
        ('url_unique', 'unique(url)', 'This URL already exists in the reference database!')
    ]
    
    # === METHODS ===
    @api.model
    def get_or_create_reference(self, url, ref_type=None, description=None, entity_name=None, entity_type=None, verbose=False):
        """
        Get existing reference or create new one.
        
        Args:
            url (str): Reference URL
            ref_type (str): Reference type (version, vendor, etc.)
            description (str): Optional description
            entity_name (str): Name of the entity (e.g., 'cisco', 'windows')
            entity_type (str): Type of entity ('vendor', 'product', 'cve')
            verbose (bool): Log detailed information (default False for cleaner output)
            
        Returns:
            vuln.fw.nvd.reference: Reference record
        """
        if not url:
            _logger.warning("❌ [REFERENCE] get_or_create_reference called with empty URL")
            return self.env['vuln.fw.nvd.reference']
        
        try:
            # Search for existing reference
            reference = self.search([('url', '=', url)], limit=1)
            
            if reference:
                if verbose:
                    _logger.info("🔍 [REFERENCE] Found existing reference: %s (ID: %s)", url[:80], reference.id)
                # Update fields if provided and not set
                update_vals = {}
                if ref_type and not reference.ref_type:
                    update_vals['ref_type'] = ref_type
                if entity_name and not reference.entity_name:
                    update_vals['entity_name'] = entity_name
                if entity_type and not reference.entity_type:
                    update_vals['entity_type'] = entity_type
                if update_vals:
                    reference.write(update_vals)
                    if verbose:
                        _logger.info("✏️ [REFERENCE] Updated reference with: %s", update_vals)
                return reference
            
            # Create new reference
            vals = {
                'url': url,
                'ref_type': ref_type or 'other',
                'description': description,
                'entity_name': entity_name,
                'entity_type': entity_type,
            }
            
            reference = self.create(vals)
            if verbose:
                _logger.info("✅ [REFERENCE] Created new reference: %s (ID: %s, Type: %s, Entity: %s/%s)", 
                            url[:80], reference.id, ref_type, entity_type, entity_name)
            return reference
            
        except Exception as e:
            _logger.error("❌ [REFERENCE] Error in get_or_create_reference for URL %s: %s", url[:80], str(e))
            import traceback
            _logger.error("❌ [REFERENCE] Traceback: %s", traceback.format_exc())
            return self.env['vuln.fw.nvd.reference']
    
    def action_check_url(self):
        """Check if URL is still accessible."""
        self.ensure_one()
        
        try:
            import requests
            response = requests.head(self.url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                self.status = 'active'
            elif response.status_code == 404:
                self.status = 'broken'
            elif response.status_code in [301, 302, 303, 307, 308]:
                self.status = 'redirected'
            else:
                self.status = 'unknown'
            
            self.last_checked = fields.Datetime.now()
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('URL Check Complete'),
                    'message': _('URL status: %s') % self.status,
                    'type': 'success' if self.status == 'active' else 'warning'
                }
            }
            
        except Exception as e:
            _logger.error("Error checking URL %s: %s", self.url, str(e))
            self.status = 'unknown'
            self.last_checked = fields.Datetime.now()
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('URL Check Failed'),
                    'message': _('Error: %s') % str(e),
                    'type': 'error'
                }
            }

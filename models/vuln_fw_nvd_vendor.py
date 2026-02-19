# -*- coding: utf-8 -*-
"""NVD Vendor Model - Shared across all vulnerability framework modules
Provides a canonical vendor registry for NVD-related data (CVE, CPE, etc.)
"""
from odoo import api, fields, models, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdVendor(models.Model):
    """Shared vendor model for NVD framework
    
    Stores normalized vendor information accessible to:
    - vuln_fw_nvd_cpe: CPE entries
    - vuln_fw_nvd_cve: CVE vendor attribution
    - Other vulnerability modules
    """
    _name = 'vuln.fw.nvd.vendor'
    _description = 'National Vulnerability Database Vendor (Shared)'
    _order = 'name'
    _rec_name = 'name'
    
    # === CORE FIELDS ===
    name = fields.Char(
        string='Vendor Name',
        required=True,
        index=True,
        help='Normalized vendor name from NVD (e.g., microsoft, adobe, google)'
    )
    
    custom_name = fields.Char(
        string='Custom Name',
        help='Your custom vendor name (e.g., Microsoft Corporation, Adobe Inc.)'
    )
    
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
        help='Human-readable vendor name. Uses custom_name if available, otherwise name'
    )
    
    description = fields.Text(
        string='Description',
        help='Vendor description or additional information'
    )
    
    website = fields.Char(
        string='Website',
        help='Vendor official website'
    )
    
    # === RELATIONSHIPS ===
    product_ids = fields.One2many(
        'vuln.fw.nvd.product',
        'vendor_id',
        string='Products',
        help='Products from this vendor'
    )
    
    # === STATISTICS ===
    product_count = fields.Integer(
        string='Product Count',
        compute='_compute_product_count',
        store=True,
        help='Number of unique products from this vendor'
    )
    
    cpe_dictionary_count = fields.Integer(
        string='CPE Dictionary Entries',
        compute='_compute_cpe_dictionary_count',
        help='Number of CPE dictionary entries linked to this vendor'
    )
    
    # === METADATA ===
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Inactive vendors are hidden from views'
    )
    
    created_date = fields.Datetime(
        string='Created',
        readonly=True,
        default=fields.Datetime.now
    )
    
    # === COMPUTE METHODS ===
    @api.depends('product_ids')
    def _compute_product_count(self):
        """Count unique products from this vendor"""
        for record in self:
            record.product_count = len(record.product_ids)
    
    def _compute_cpe_dictionary_count(self):
        """Count CPE dictionary entries linked to this vendor"""
        for record in self:
            count = self.env['vuln.fw.nvd.cpe.dictionary'].search_count([
                ('main_vendor_id', '=', record.id)
            ])
            record.cpe_dictionary_count = count
    
    @api.depends('custom_name', 'name')
    def _compute_display_name(self):
        """Compute display name from custom_name or normalized name"""
        for record in self:
            record.display_name = record.custom_name or record.name
    
    # === SEARCH & FILTERING ===
    def _search_display_name(self, operator, value):
        """Allow searching by display name"""
        return ['|', ('custom_name', operator, value), ('name', operator, value)]
    
    # === CONSTRAINTS ===
    _sql_constraints = [
        ('name_uniq', 'UNIQUE(name)', 'Vendor name must be unique')
    ]
    
    # === LIFECYCLE METHODS ===
    @api.model_create_multi
    @api.returns('self', lambda value: value.id)
    def create(self, vals_list):
        """Normalize vendor name on creation"""
        for vals in vals_list:
            if vals.get('name'):
                vals['name'] = vals['name'].lower().strip()
        return super().create(vals_list)
    
    def write(self, vals):
        """Normalize vendor name on update"""
        if vals.get('name'):
            vals['name'] = vals['name'].lower().strip()
        return super().write(vals)
    
    # === HELPER METHODS ===
    @api.model
    def get_or_create(self, vendor_name):
        """Get or create vendor by name (normalized)
        
        Args:
            vendor_name (str): Vendor name (will be normalized to lowercase)
            
        Returns:
            vuln.fw.nvd.vendor: The vendor record
        """
        if not vendor_name:
            return None
        
        normalized_name = vendor_name.lower().strip()
        vendor = self.search([('name', '=', normalized_name)], limit=1)
        
        if not vendor:
            vendor = self.create({'name': normalized_name})
        
        return vendor

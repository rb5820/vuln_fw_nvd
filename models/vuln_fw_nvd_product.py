# -*- coding: utf-8 -*-
"""NVD Product Model - Shared across all vulnerability framework modules
Provides a canonical product registry for NVD-related data (CVE, CPE, etc.)
"""
from odoo import api, fields, models, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdProduct(models.Model):
    """Shared product model for NVD framework
    
    Stores normalized product information accessible to:
    - vuln_fw_nvd_cpe: CPE entries
    - vuln_fw_nvd_cve: CVE product attribution
    - Other vulnerability modules
    """
    _name = 'vuln.fw.nvd.product'
    _description = 'National Vulnerability Database Product (Shared)'
    _order = 'vendor_id, name'
    _rec_name = 'display_name'
    
    # === CORE FIELDS ===
    name = fields.Char(
        string='Product Name',
        required=True,
        index=True,
        help='Normalized product name from NVD (e.g., windows, office, chrome)'
    )
    
    vendor_id = fields.Many2one(
        'vuln.fw.nvd.vendor',
        string='Vendor',
        required=True,
        index=True,
        help='Vendor that produces this product'
    )
    
    vendor_name = fields.Char(
        related='vendor_id.name',
        string='Vendor Name',
        store=True,
        readonly=True
    )
    
    custom_name = fields.Char(
        string='Custom Name',
        help='Your custom product name (e.g., Windows Server 2019)'
    )
    
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
        help='Human-readable product name (vendor: product)'
    )
    
    description = fields.Text(
        string='Description',
        help='Product description or additional information'
    )
    
    category = fields.Selection(
        [
            ('os', 'Operating System'),
            ('application', 'Application/Software'),
            ('hardware', 'Hardware'),
            ('firmware', 'Firmware'),
            ('library', 'Library'),
            ('other', 'Other'),
        ],
        string='Category',
        help='Product category for classification'
    )
    
    # === RELATIONSHIPS ===
    # No reverse relationships to CPE dictionary to avoid FK constraints
    
    # === STATISTICS ===
    cpe_dictionary_count = fields.Integer(
        string='CPE Dictionary Entries',
        compute='_compute_cpe_dictionary_count',
        help='Number of CPE dictionary entries linked to this product'
    )
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Inactive products are hidden from views'
    )
    
    created_date = fields.Datetime(
        string='Created',
        readonly=True,
        default=fields.Datetime.now
    )
    
    # === COMPUTE METHODS ===
    @api.depends('vendor_id.custom_name', 'vendor_id.name', 'custom_name', 'name')
    def _compute_display_name(self):
        """Compute display name as vendor: product"""
        for record in self:
            vendor_name = record.vendor_id.display_name if record.vendor_id else 'Unknown'
            product_name = record.custom_name or record.name
            record.display_name = f"{vendor_name}: {product_name}"
    
    def _compute_cpe_dictionary_count(self):
        """Count CPE dictionary entries linked to this product"""
        for record in self:
            count = self.env['vuln.fw.nvd.cpe.dictionary'].search_count([
                ('main_product_id', '=', record.id)
            ])
            record.cpe_dictionary_count = count
    
    # === SEARCH & FILTERING ===
    def _search_display_name(self, operator, value):
        """Allow searching by display name"""
        return ['|', ('custom_name', operator, value), ('name', operator, value)]
    
    # === CONSTRAINTS ===
    _sql_constraints = [
        ('name_vendor_uniq', 'UNIQUE(name, vendor_id)', 
         'Product name must be unique per vendor')
    ]
    
    # === LIFECYCLE METHODS ===
    @api.model_create_multi
    @api.returns('self', lambda value: value.id)
    def create(self, vals_list):
        """Normalize product name on creation"""
        for vals in vals_list:
            if vals.get('name'):
                vals['name'] = vals['name'].lower().strip()
        return super().create(vals_list)
    
    def write(self, vals):
        """Normalize product name on update"""
        if vals.get('name'):
            vals['name'] = vals['name'].lower().strip()
        return super().write(vals)
    
    # === HELPER METHODS ===
    @api.model
    def get_or_create(self, vendor_id, product_name):
        """Get or create product by vendor and name (normalized)
        
        Args:
            vendor_id (int): ID of vuln.fw.nvd.vendor record
            product_name (str): Product name (will be normalized to lowercase)
            
        Returns:
            vuln.fw.nvd.product: The product record
        """
        if not vendor_id or not product_name:
            return None
        
        normalized_name = product_name.lower().strip()
        product = self.search([
            ('vendor_id', '=', vendor_id),
            ('name', '=', normalized_name)
        ], limit=1)
        
        if not product:
            product = self.create({
                'vendor_id': vendor_id,
                'name': normalized_name
            })
        
        return product

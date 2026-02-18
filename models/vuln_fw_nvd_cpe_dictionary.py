# -*- coding: utf-8 -*-
"""Base CPE Dictionary model for NVD integration - shared across modules"""
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeDictionary(models.Model):
    """Base CPE Dictionary - minimal fields for cross-module compatibility
    
    This base model allows both CPE and CVE modules to work with CPE dictionary
    entries independently. Each module can inherit and extend this model with
    their specific functionality:
    - vuln_fw_nvd_cpe module adds full CPE management, API sync, vendor/product linking
    - vuln_fw_nvd_cve module adds CVE-CPE matching, affected products, configuration nodes
    
    Both modules benefit from each other's enhancements through inheritance.
    """
    _name = 'vuln.fw.nvd.cpe.dictionary'
    _description = 'CPE Dictionary Entry (Base)'
    _order = 'cpe_name'
    _rec_name = 'title'

    # === CORE CPE FIELDS (Required for all modules) ===
    cpe_name = fields.Char(
        string='CPE Name',
        required=True,
        index=True,
        help='CPE 2.3 formatted name (e.g., cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*)'
    )
    
    cpe_name_id = fields.Char(
        string='CPE Name ID',
        index=True,
        help='Unique CPE identifier from NIST'
    )
    
    title = fields.Char(
        string='Title',
        required=True,
        help='Human-readable title for the CPE entry'
    )
    
    # === PARSED CPE COMPONENTS (CPE 2.3 Standard) ===
    part = fields.Selection([
        ('a', 'Application'),
        ('h', 'Hardware'),
        ('o', 'Operating System')
    ], string='Part', required=True, index=True, help='CPE part component')
    
    vendor = fields.Char(
        string='Vendor',
        required=True,
        index=True,
        help='Vendor or manufacturer name'
    )
    
    product = fields.Char(
        string='Product',
        required=True,
        index=True,
        help='Product name'
    )
    
    version = fields.Char(
        string='Version',
        index=True,
        help='Product version'
    )
    
    update_component = fields.Char(
        string='Update',
        help='Update or patch level'
    )
    
    edition = fields.Char(
        string='Edition',
        help='Product edition'
    )
    
    language = fields.Char(
        string='Language',
        help='Language localization'
    )
    
    sw_edition = fields.Char(
        string='Software Edition',
        help='Software edition (CPE 2.3)'
    )
    
    target_sw = fields.Char(
        string='Target Software',
        help='Target software environment'
    )
    
    target_hw = fields.Char(
        string='Target Hardware',
        help='Target hardware platform'
    )
    
    # === VULNERABILITY STATUS ===
    is_vulnerable = fields.Boolean(
        string='Is Vulnerable',
        default=False,
        help='Whether this CPE is marked as vulnerable in its most recent CVE configuration context'
    )
    
    other = fields.Char(
        string='Other',
        help='Other qualifying information'
    )
    
    # === METADATA (Shared across modules) ===
    deprecated = fields.Boolean(
        string='Deprecated',
        default=False,
        index=True,
        help='Whether this CPE entry is deprecated'
    )
    
    deprecated_date = fields.Datetime(
        string='Deprecated Date',
        help='Date when this CPE was deprecated'
    )
    
    last_modified = fields.Datetime(
        string='Last Modified',
        help='Last modification timestamp from NIST'
    )
    
    sync_date = fields.Datetime(
        string='Sync Date',
        default=fields.Datetime.now,
        help='Date when this CPE was last synchronized'
    )
    
    # === ACTIVE STATE ===
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Set to False to hide this CPE entry'
    )
    
    # === SEARCH SUPPORT ===
    search_text = fields.Text(
        string='Search Text',
        compute='_compute_search_text',
        store=True,
        help='Searchable text combining all CPE components'
    )
    
    @api.depends('cpe_name', 'title', 'vendor', 'product', 'version')
    def _compute_search_text(self):
        """Compute searchable text for full-text search"""
        for record in self:
            parts = [
                record.cpe_name or '',
                record.title or '',
                record.vendor or '',
                record.product or '',
                record.version or '',
            ]
            record.search_text = ' '.join([p.lower() for p in parts if p])
    
    _sql_constraints = [
        ('cpe_name_unique', 'UNIQUE(cpe_name)', 'CPE name must be unique!'),
    ]
    
    def _format_display_version(self):
        """Format version string for display - can be overridden in child modules
        
        This method provides a hook for child modules to customize how the CPE
        entry is displayed. By default, it shows: "vendor product version"
        
        Can be overridden in inheriting modules to add custom formatting.
        Use super()._format_display_version() to call the parent implementation.
        
        Returns:
            str: Formatted display string for the CPE entry
        """
        if self.version and self.version != '*':
            return f"{self.vendor} {self.product} {self.version}"
        return f"{self.vendor} {self.product}"
    
    def name_get(self):
        """Display CPE with vendor, product, version"""
        result = []
        for record in self:
            name = record._format_display_version()
            if record.part:
                part_icon = {'a': '📱', 'h': '🖥️', 'o': '💿'}.get(record.part, '')
                name = f"{part_icon} {name}"
            result.append((record.id, name))
        return result

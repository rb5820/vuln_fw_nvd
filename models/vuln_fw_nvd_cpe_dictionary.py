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
    
    update = fields.Char(
        string='Update',
        help='Product update'
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
    
    @api.model
    def process_cpe_uri(self, cpe_uri, source='external_system', metadata=None):
        """Parse CPE 2.3 URI and create/update CPE dictionary entry
        
        CPE 2.3 URI format:
        cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        
        Args:
            cpe_uri (str): CPE 2.3 formatted URI
            source (str): Source system that sent this CPE (e.g., lansweeper_connector)
            metadata (dict): Additional metadata from source system
            
        Returns:
            vuln.fw.nvd.cpe.dictionary: Created or updated CPE record
        """
        if not cpe_uri:
            return None
        
        metadata = metadata or {}
        
        try:
            # Parse CPE URI
            if not cpe_uri.startswith('cpe:2.3:'):
                _logger.warning(f"Invalid CPE URI format: {cpe_uri}")
                return None
            
            # Split CPE components
            parts = cpe_uri.split(':')
            if len(parts) < 13:  # cpe:2.3 + 11 minimum components
                _logger.warning(f"CPE URI missing required components: {cpe_uri}")
                return None
            
            # Extract components (handle missing components as empty strings)
            part = parts[2] if len(parts) > 2 else '*'
            vendor = parts[3] if len(parts) > 3 else '*'
            product = parts[4] if len(parts) > 4 else '*'
            version = parts[5] if len(parts) > 5 else '*'
            update = parts[6] if len(parts) > 6 else '*'
            edition = parts[7] if len(parts) > 7 else '*'
            language = parts[8] if len(parts) > 8 else '*'
            sw_edition = parts[9] if len(parts) > 9 else '*'
            target_sw = parts[10] if len(parts) > 10 else '*'
            target_hw = parts[11] if len(parts) > 11 else '*'
            other = parts[12] if len(parts) > 12 else '*'
            
            # Normalize wildcards
            vendor = vendor if vendor != '*' else ''
            product = product if product != '*' else ''
            version = version if version != '*' else ''
            update = update if update != '*' else ''
            edition = edition if edition != '*' else ''
            language = language if language != '*' else ''
            sw_edition = sw_edition if sw_edition != '*' else ''
            target_sw = target_sw if target_sw != '*' else ''
            target_hw = target_hw if target_hw != '*' else ''
            other = other if other != '*' else ''
            
            # Validate required fields
            if not vendor or not product or not part:
                _logger.warning(f"CPE URI missing required fields (part, vendor, product): {cpe_uri}")
                return None
            
            # Build title
            title = f"{vendor} {product}"
            if version:
                title += f" {version}"
            
            # Search for existing CPE
            existing_cpe = self.search([
                ('cpe_name', '=', cpe_uri)
            ], limit=1)
            
            if existing_cpe:
                # Update existing record
                existing_cpe.write({
                    'sync_date': fields.Datetime.now(),
                })
                _logger.info(f"Updated CPE: {cpe_uri}")
                return existing_cpe
            else:
                # Create new CPE record
                cpe_data = {
                    'cpe_name': cpe_uri,
                    'title': title,
                    'part': part,
                    'vendor': vendor,
                    'product': product,
                    'version': version,
                    'update': update,
                    'edition': edition,
                    'language': language,
                    'sw_edition': sw_edition,
                    'target_sw': target_sw,
                    'target_hw': target_hw,
                    'other': other,
                    'sync_date': fields.Datetime.now(),
                    'active': True,
                }
                
                new_cpe = self.create(cpe_data)
                _logger.info(f"Created new CPE: {cpe_uri}")
                return new_cpe
                
        except Exception as e:
            _logger.exception(f"Error processing CPE URI {cpe_uri}: {str(e)}")
            return None


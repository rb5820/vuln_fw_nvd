# -*- coding: utf-8 -*-
"""Migration script to consolidate vendor/product from CPE module to main NVD module

This script migrates existing vendor and product data from vuln_fw_nvd_cpe module's
vendor/product tables to the new shared tables in vuln_fw_nvd main module.

Run this script during module update or manually after module installation.
"""
from odoo import api, models, _
import logging

_logger = logging.getLogger(__name__)


def migrate_vendors_and_products(env):
    """Migrate vendor and product data from CPE module to main module
    
    This function:
    1. Copies vendors from vuln_fw_nvd_cpe.vendor to vuln_fw_nvd.vendor
    2. Copies products from vuln_fw_nvd_cpe.product to vuln_fw_nvd.product
    3. Updates CPE dictionary records to reference new vendor/product records
    4. Validates referential integrity
    """
    _logger.info("=== Starting Vendor/Product Migration ===")
    
    # Check if old CPE vendor table exists
    cpe_vendor_model = 'vuln.fw.nvd.cpe.vendor'
    cpe_product_model = 'vuln.fw.nvd.cpe.product'
    
    if not env[cpe_vendor_model]._table_exists():
        _logger.info("No existing CPE vendor table found. Migration skipped.")
        return
    
    # === MIGRATE VENDORS ===
    _logger.info("Starting vendor migration...")
    
    cpe_vendors = env[cpe_vendor_model].search([])
    main_vendor_model = env['vuln.fw.nvd.vendor']
    
    vendor_mapping = {}  # Map old vendor ID -> new vendor ID
    
    for cpe_vendor in cpe_vendors:
        # Get or create vendor in main module
        main_vendor = main_vendor_model.search([
            ('name', '=', cpe_vendor.name.lower().strip())
        ], limit=1)
        
        if not main_vendor:
            # Create new vendor in main module
            main_vendor = main_vendor_model.create({
                'name': cpe_vendor.name,
                'custom_name': cpe_vendor.custom_name if hasattr(cpe_vendor, 'custom_name') else '',
                'website': cpe_vendor.website if hasattr(cpe_vendor, 'website') else '',
                'description': cpe_vendor.description if hasattr(cpe_vendor, 'description') else '',
            })
            _logger.info(f"Created vendor: {main_vendor.name}")
        
        vendor_mapping[cpe_vendor.id] = main_vendor.id
    
    _logger.info(f"Migrated {len(vendor_mapping)} vendors")
    
    # === MIGRATE PRODUCTS ===
    _logger.info("Starting product migration...")
    
    cpe_products = env[cpe_product_model].search([])
    main_product_model = env['vuln.fw.nvd.product']
    
    product_mapping = {}  # Map old product ID -> new product ID
    
    for cpe_product in cpe_products:
        # Get new vendor ID
        if cpe_product.vendor_id.id not in vendor_mapping:
            _logger.warning(f"Vendor {cpe_product.vendor_id.id} not found in mapping. Skipping product.")
            continue
        
        new_vendor_id = vendor_mapping[cpe_product.vendor_id.id]
        
        # Get or create product in main module
        main_product = main_product_model.search([
            ('vendor_id', '=', new_vendor_id),
            ('name', '=', cpe_product.name.lower().strip())
        ], limit=1)
        
        if not main_product:
            # Create new product in main module
            main_product = main_product_model.create({
                'vendor_id': new_vendor_id,
                'name': cpe_product.name,
                'custom_name': cpe_product.custom_name if hasattr(cpe_product, 'custom_name') else '',
                'category': cpe_product.category if hasattr(cpe_product, 'category') else 'other',
                'description': cpe_product.description if hasattr(cpe_product, 'description') else '',
            })
            _logger.info(f"Created product: {main_product.display_name}")
        
        product_mapping[cpe_product.id] = main_product.id
    
    _logger.info(f"Migrated {len(product_mapping)} products")
    
    # === UPDATE CPE DICTIONARY RECORDS ===
    _logger.info("Updating CPE dictionary records...")
    
    cpe_dict_model = env['vuln.fw.nvd.cpe.dictionary']
    
    # Update vendor_id references
    cpe_records_with_vendor = cpe_dict_model.search([('vendor_id', '!=', False)])
    
    updated_count = 0
    for cpe_record in cpe_records_with_vendor:
        if cpe_record.vendor_id.id in vendor_mapping:
            new_vendor_id = vendor_mapping[cpe_record.vendor_id.id]
            cpe_record.vendor_id = new_vendor_id
            updated_count += 1
    
    _logger.info(f"Updated {updated_count} CPE records with new vendor_id")
    
    # Update product_id references  
    cpe_records_with_product = cpe_dict_model.search([('product_id', '!=', False)])
    
    product_updated_count = 0
    for cpe_record in cpe_records_with_product:
        if cpe_record.product_id.id in product_mapping:
            new_product_id = product_mapping[cpe_record.product_id.id]
            cpe_record.product_id = new_product_id
            product_updated_count += 1
    
    _logger.info(f"Updated {product_updated_count} CPE records with new product_id")
    
    # === VALIDATE MIGRATION ===
    _logger.info("Validating migration...")
    
    orphaned_vendors = cpe_dict_model.search([
        ('vendor_id', '!=', False),
        ('vendor_id.id', '!=', False)  # Ensure vendor_id points to valid record
    ])
    
    if orphaned_vendors:
        _logger.warning(f"Found {len(orphaned_vendors)} CPE records with potentially orphaned vendor references")
    else:
        _logger.info("Migration validation passed - no orphaned vendor references")
        _logger.info("=== Vendor/Product Migration Complete ===")
    
    # === RE-ESTABLISH FOREIGN KEY CONSTRAINTS ===
    _logger.info("Re-establishing foreign key constraints...")
    
    try:
        # Note: Odoo automatically manages FK constraints, so this is for documentation
        # FK constraints will be properly set by Odoo's field definition after data is valid
        _logger.info("Foreign key constraints will be re-established automatically by Odoo")
    except Exception as e:
        _logger.warning(f"Could not re-establish FK constraints: {e}")
        _logger.info("=== Vendor/Product Migration Complete ===")


@api.model
def post_init_hook(env):
    """Post-init hook called after module installation
    
    This hook runs the migration automatically when the module is installed.
    """
    _logger.info("Running post-init hook for vendor/product migration")
    migrate_vendors_and_products(env)

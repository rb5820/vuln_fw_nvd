# -*- coding: utf-8 -*-
"""Basic NVD Data Synchronization"""
from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import json
import logging
import requests
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class NvdConnector(models.Model):
    """NVD API Connector - Core API connector for NVD vulnerability and CPE data"""
    _name = 'vuln.fw.nvd.connector'
    _description = 'NVD API Connector'
    _inherit = ['mail.thread']
    _check_company_auto = True
    
    name = fields.Char(
        string='Importer Name',
        required=True,
        default='NVD Importer'
    )
    
    api_key = fields.Char(
        string='NVD API Key',
        help='Optional API key for NVD requests (recommended for higher rate limits)'
    )
    
    api_url = fields.Char(
        string='API URL',
        default='https://services.nvd.nist.gov/rest/json/cves/2.0',
        help='Base URL for the NVD CVE API endpoint (can be customized for different data sources)'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Enable/disable this importer'
    )
    
    last_sync_date = fields.Datetime(
        string='Last Sync Date',
        help='Date and time of the last successful synchronization'
    )
    
    batch_size = fields.Integer(
        string='Batch Size',
        default=100,
        help='Number of records to process per batch'
    )
    
    auto_sync = fields.Boolean(
        string='Auto Sync',
        default=False,
        help='Enable automatic synchronization via scheduled action'
    )
    
    sync_interval = fields.Integer(
        string='Sync Interval (hours)',
        default=24,
        help='Hours between automatic synchronizations'
    )
    
    notes = fields.Text(
        string='Notes',
        help='Additional configuration notes'
    )
    
    # Computed fields
    sync_log_count = fields.Integer(
        string='Sync Logs',
        compute='_compute_sync_log_count'
    )
    
    def _compute_sync_log_count(self):
        for record in self:
            # Count all sync logs since importer_id relationship may not be set
            record.sync_log_count = self.env['vuln.fw.nvd.sync.log'].search_count([])
    
    def action_sync_nvd(self):
        """Simple NVD data synchronization"""
        if not self.active:
            raise UserError(_('This importer is not active. Please activate it first.'))
        
        sync_log = self.env['vuln.fw.nvd.sync.log'].create({
            'sync_date': fields.Datetime.now(),
            'status': 'running'
        })
        
        try:
            # Basic NVD API call
            url = self.api_url or "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {'Accept': 'application/json'}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            # Limit to recent CVEs for demo purposes
            params = {
                'resultsPerPage': min(self.batch_size or 20, 100),
                'startIndex': 0
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])
            
            sync_log.write({
                'end_time': fields.Datetime.now(),
                'status': 'success',
                'total_items': total_results,
                'processed_items': len(vulnerabilities),
                'notes': f'Successfully retrieved {len(vulnerabilities)} CVE records from NVD API'
            })
            
            # Update last sync date
            self.write({
                'last_sync_date': fields.Datetime.now()
            })
            
            _logger.info(f'NVD sync completed successfully. Retrieved {len(vulnerabilities)} CVE records.')
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD Sync Complete'),
                    'message': f'Successfully retrieved {len(vulnerabilities)} CVE records from NVD',
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except Exception as e:
            sync_log.write({
                'end_time': fields.Datetime.now(),
                'status': 'error',
                'error_message': str(e)
            })
            _logger.error(f'NVD sync failed: {str(e)}')
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }
    
    def action_view_sync_logs(self):
        """View sync logs for this importer"""
        return {
            'name': _('Sync Logs'),
            'type': 'ir.actions.act_window',
            'res_model': 'vuln.fw.nvd.sync.log',
            'view_mode': 'list,form',
            'domain': [('importer_id', '=', self.id)],
            'context': {'default_importer_id': self.id}
        }
    
    name = fields.Char(
        string='Importer Name',
        required=True,
        default='NVD Importer'
    )
    
    api_key = fields.Char(
        string='NVD API Key',
        help='Optional API key for NVD requests (recommended for higher rate limits)'
    )
    
    api_key = fields.Char(
        string='NVD API Key',
        help='Optional API key for increased rate limits'
    )
    
    last_sync_date = fields.Datetime(
        string='Last Sync Date',
        help='Last successful synchronization date'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True
    )
    
    # Company Support
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    @api.model
    def sync_from_nvd(self, start_date=None, end_date=None, results_per_page=2000):
        """Basic synchronization from NVD API - creates simple vulnerability records"""
        _logger.info("Starting NVD sync - results_per_page: %s, start_date: %s, end_date: %s", 
                    results_per_page, start_date, end_date)
        
        try:
            # Check if vulnerability.vulnerability model exists
            try:
                vuln_model = self.env['vulnerability.vulnerability']
                _logger.debug("vulnerability.vulnerability model found and accessible")
                # Standard CVE sync mode
                return self._sync_cve_data(start_date, end_date, results_per_page)
            except Exception as model_error:
                _logger.error("vulnerability.vulnerability model not accessible: %s", str(model_error))
                
                # Check if CPE module is available as an alternative
                try:
                    # Check if the CPE extension fields are available on this model
                    if hasattr(self, 'enable_cpe_processing'):
                        _logger.info("CPE module detected - using standalone NVD mode")
                        # Create a simple log entry instead of full vulnerability record
                        return self._sync_cve_data_simple(start_date, end_date, results_per_page)
                    else:
                        _logger.info("CPE extension not available on importer model")
                        raise UserError(_("NVD module requires either the vulnerability framework (vuln_source_core) or CPE module (vuln_fw_nvd_cpe) to be installed for functionality."))
                except Exception as cpe_check_error:
                    _logger.info("Neither vulnerability framework nor CPE module available: %s", str(cpe_check_error))
                    raise UserError(_("NVD module requires either the vulnerability framework (vuln_source_core) or CPE module (vuln_fw_nvd_cpe) to be installed for functionality."))
                
        except requests.RequestException as e:
            _logger.error("NVD API request failed: %s", str(e))
            raise UserError(_("NVD API request failed: %s") % str(e))
        except Exception as e:
            _logger.error("NVD sync failed: %s", str(e))
            raise UserError(_("NVD synchronization failed: %s") % str(e))
    
    def _sync_cve_data(self, start_date=None, end_date=None, results_per_page=2000):
        """Sync CVE data for vulnerability management"""
        _logger.info("Starting CVE data sync for vulnerability management")
        
        # Use configurable API URL
        base_url = self.api_url or "https://services.nvd.nist.gov/rest/json/cves/2.0"
        _logger.debug("Using API endpoint: %s", base_url)
        
        # Build parameters - adjust for free API usage
        if self.api_key:
            # With API key: higher rate limits (50 requests per 30 seconds)
            max_results_per_page = min(results_per_page, 2000)  # NVD limit
            rate_limit_sleep = 0.6  # 50 requests per 30 seconds = ~1.67 req/sec
            _logger.info("Using authenticated API with higher rate limits")
        else:
            # Free API: lower rate limits (5 requests per 30 seconds)
            max_results_per_page = min(results_per_page, 100)  # Smaller batches for free API
            rate_limit_sleep = 6.0  # 5 requests per 30 seconds = 1 req/6 seconds
            _logger.info("Using free API with rate limiting (5 requests per 30 seconds)")
        
        params = {
            'resultsPerPage': max_results_per_page,
            'startIndex': 0
        }
        
        if start_date:
            params['pubStartDate'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            _logger.debug("Using start date filter: %s", params['pubStartDate'])
        if end_date:
            params['pubEndDate'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            _logger.debug("Using end date filter: %s", params['pubEndDate'])
        
        _logger.info("NVD API request parameters: %s", params)
        
        # Headers - configure for API access type
        headers = {
            'User-Agent': 'Odoo-NVD-Connector/1.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
            _logger.info("Using NVD API key - enhanced rate limits enabled")
        else:
            _logger.info("Using free NVD API - applying rate limiting for 5 requests per 30 seconds")
        
        total_processed = 0
        created_count = 0
        updated_count = 0
        
        while True:
            _logger.info("Making NVD API request - startIndex: %s", params['startIndex'])
            
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            
            _logger.info("Received %s vulnerabilities from NVD API (total available: %s)", 
                        len(vulnerabilities), total_results)
            
            if not vulnerabilities:
                _logger.info("No more vulnerabilities to process, stopping sync")
                break
            
            for i, vuln_item in enumerate(vulnerabilities, 1):
                cve = vuln_item.get('cve', {})
                cve_id = cve.get('id', '')
                
                if not cve_id:
                    _logger.warning("Skipping vulnerability item %s - no CVE ID found", i)
                    continue
                
                _logger.debug("Processing CVE %s (%s/%s)", cve_id, i, len(vulnerabilities))
                
                # Check if vulnerability exists
                try:
                    existing = self.env['vulnerability.vulnerability'].search([
                        ('cve_id', '=', cve_id)
                    ], limit=1)
                    _logger.debug("Existing vulnerability check for %s: %s", cve_id, 'found' if existing else 'not found')
                except Exception as search_error:
                    _logger.error("Error searching for existing vulnerability %s: %s", cve_id, str(search_error))
                    continue
                
                if existing:
                    # Simple update check
                    nvd_modified = self._parse_nvd_date(cve.get('lastModified'))
                    _logger.debug("CVE %s exists - checking if update needed (NVD modified: %s, local modified: %s)", 
                                 cve_id, nvd_modified, existing.last_modified if hasattr(existing, 'last_modified') else 'N/A')
                    
                    if nvd_modified and hasattr(existing, 'last_modified') and nvd_modified > existing.last_modified:
                        _logger.info("Updating existing vulnerability: %s", cve_id)
                        try:
                            self._update_basic_vulnerability(existing, cve)
                            updated_count += 1
                            _logger.debug("Successfully updated vulnerability: %s", cve_id)
                        except Exception as update_error:
                            _logger.error("Failed to update vulnerability %s: %s", cve_id, str(update_error))
                            continue
                    else:
                        _logger.debug("CVE %s is up to date, skipping", cve_id)
                else:
                    # Create new basic record
                    _logger.info("Creating new vulnerability: %s", cve_id)
                    try:
                        new_vuln = self._create_basic_vulnerability(cve)
                        if new_vuln:
                            created_count += 1
                            _logger.debug("Successfully created vulnerability: %s (ID: %s)", cve_id, new_vuln.id)
                        else:
                            _logger.warning("Failed to create vulnerability %s - _create_basic_vulnerability returned None", cve_id)
                    except Exception as create_error:
                        _logger.error("Failed to create vulnerability %s: %s", cve_id, str(create_error))
                        continue
                
                total_processed += 1
            
            # Check if there are more results
            total_results = data.get('totalResults', 0)
            if params['startIndex'] + len(vulnerabilities) >= total_results:
                _logger.info("Reached end of results - processed %s/%s total CVEs", total_processed, total_results)
                break
            
            params['startIndex'] += len(vulnerabilities)
            _logger.debug("Moving to next batch - startIndex: %s", params['startIndex'])
            
            # Respect NVD rate limits based on API key availability
            import time
            if self.api_key:
                # API key: 50 requests per 30 seconds
                time.sleep(0.6)
                _logger.debug("Applied API key rate limiting (0.6s delay)")
            else:
                # Free API: 5 requests per 30 seconds
                time.sleep(6.0)
                _logger.info("Applied free API rate limiting (6.0s delay) - request %s of batch", 
                            params['startIndex'] // max_results_per_page)
        
        # Log results with API usage context
        self.last_sync_date = fields.Datetime.now()
        
        api_type = "authenticated API" if self.api_key else "free API"
        message = f'Processed {total_processed} CVEs using {api_type}: {created_count} created, {updated_count} updated'
        
        if not self.api_key and total_processed > 0:
            message += " (Consider adding an API key for faster synchronization)"
        
        return {
            'total_processed': total_processed,
            'created': created_count,
            'updated': updated_count,
            'status': 'success',
            'message': message
        }
    
    def _create_basic_vulnerability(self, cve_data):
        """Create basic vulnerability record from NVD CVE data"""
        cve_id = cve_data.get('id', '')
        _logger.debug("_create_basic_vulnerability called for CVE: %s", cve_id)
        
        try:
            descriptions = cve_data.get('descriptions', [])
            english_desc = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), '')
            _logger.debug("Extracted description for %s: %s chars", cve_id, len(english_desc))
            
            # Extract basic CVSS score (any version)
            base_score = 0.0
            cvss_vector = ''
            
            metrics = cve_data.get('metrics', {})
            _logger.debug("Available CVSS metrics for %s: %s", cve_id, list(metrics.keys()))
            
            if metrics.get('cvssMetricV31'):
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                _logger.debug("Using CVSS v3.1 for %s: score=%s", cve_id, base_score)
            elif metrics.get('cvssMetricV30'):
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0) 
                cvss_vector = cvss_data.get('vectorString', '')
                _logger.debug("Using CVSS v3.0 for %s: score=%s", cve_id, base_score)
            elif metrics.get('cvssMetricV2'):
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                _logger.debug("Using CVSS v2 for %s: score=%s", cve_id, base_score)
            else:
                _logger.debug("No CVSS metrics available for %s", cve_id)
            
            # Parse dates
            published_date = self._parse_nvd_date(cve_data.get('published'))
            modified_date = self._parse_nvd_date(cve_data.get('lastModified'))
            
            # Get severity based on score
            severity = self._get_severity_from_score(base_score)
            _logger.debug("Severity for %s (score %s): %s", cve_id, base_score, severity.name if severity else 'None')
            
            vals = {
                'name': cve_id,
                'cve_id': cve_id,
                'title': f"{cve_id} Vulnerability",
                'description': english_desc,
                'vulnerability_type': 'cve',
                'external_id': cve_id,
                'published_date': published_date,
                'last_modified': modified_date,
                'base_score': base_score,
                'cvss_vector': cvss_vector,
                'severity_id': severity.id if severity else False,
                'state': 'published',
                'company_id': self.company_id.id,
            }
            
            _logger.debug("Creating vulnerability with vals: %s", {k: v for k, v in vals.items() if k != 'description'})
            
            try:
                new_vuln = self.env['vulnerability.vulnerability'].create(vals)
                _logger.info("Successfully created vulnerability record: %s (ID: %s)", cve_id, new_vuln.id)
                return new_vuln
            except Exception as create_error:
                _logger.error("Database error creating vulnerability %s: %s", cve_id, str(create_error))
                return None
                
        except Exception as e:
            _logger.warning("Failed to create vulnerability for %s: %s", cve_data.get('id', 'unknown'), str(e))
            return None
    
    def _update_basic_vulnerability(self, existing_record, cve_data):
        """Update existing vulnerability with basic NVD data"""
        try:
            descriptions = cve_data.get('descriptions', [])
            english_desc = next((desc['value'] for desc in descriptions if desc.get('lang') == 'en'), '')
            
            # Extract basic CVSS score
            base_score = existing_record.base_score
            cvss_vector = existing_record.cvss_vector
            
            metrics = cve_data.get('metrics', {})
            if metrics.get('cvssMetricV31'):
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', base_score)
                cvss_vector = cvss_data.get('vectorString', cvss_vector)
            elif metrics.get('cvssMetricV30'):
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', base_score)
                cvss_vector = cvss_data.get('vectorString', cvss_vector)
            
            severity = self._get_severity_from_score(base_score)
            
            vals = {
                'description': english_desc,
                'last_modified': self._parse_nvd_date(cve_data.get('lastModified')),
                'base_score': base_score,
                'cvss_vector': cvss_vector,
                'severity_id': severity.id if severity else False,
            }
            
            existing_record.write(vals)
            return existing_record
            
        except Exception as e:
            _logger.warning("Failed to update vulnerability %s: %s", existing_record.cve_id, str(e))
            return existing_record
    
    def _parse_nvd_date(self, date_string):
        """Parse NVD date format"""
        if not date_string:
            return None
        try:
            # NVD uses ISO format like '2023-11-15T10:15:00.000'
            dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            return dt.replace(tzinfo=None)  # Store as naive datetime
        except:
            return None
    
    def _get_severity_from_score(self, score):
        """Get severity record based on CVSS score"""
        if score >= 9.0:
            severity_name = 'Critical'
        elif score >= 7.0:
            severity_name = 'High'
        elif score >= 4.0:
            severity_name = 'Medium'
        elif score > 0.0:
            severity_name = 'Low'
        else:
            severity_name = 'Informational'
        
        return self.env['vulnerability.severity'].search([
            ('name', '=', severity_name)
        ], limit=1)
    
    def action_sync_nvd(self):
        """Manual sync action"""
        self.ensure_one()
        try:
            result = self.sync_from_nvd()
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD Sync Complete'),
                    'message': result['message'],
                    'type': 'success',
                    'sticky': False,
                }
            }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }
    
    def action_sync_sample(self):
        """Sync only 10 records as a sample"""
        self.ensure_one()
        try:
            # Use a small results_per_page to get only 10 records
            result = self.sync_from_nvd(results_per_page=10)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD Sample Sync Complete'),
                    'message': f"Sample sync: {result['message']}",
                    'type': 'success',
                    'sticky': False,
                }
            }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD Sample Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }    
    def _sync_cve_data_simple(self, start_date=None, end_date=None, results_per_page=100):
        """Simple CVE sync that only logs data without creating vulnerability records"""
        _logger.info("Starting simple CVE sync (standalone mode)")
        
        # Prepare API request
        base_url = self.api_url or "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        params = {
            'resultsPerPage': min(results_per_page, 2000),
            'startIndex': 0
        }
        
        if start_date:
            params['pubStartDate'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        if end_date:
            params['pubEndDate'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(base_url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            processed_count = len(vulnerabilities)
            
            _logger.info("Retrieved %d CVEs from NVD (standalone mode)", processed_count)
            
            # Create simple log entry
            log_vals = {
                'sync_date': fields.Datetime.now(),
                'status': 'success',
                'start_date': start_date,
                'end_date': end_date,
                'total_processed': processed_count,
                'created_count': 0,
                'updated_count': 0,
                'error_count': 0,
                'message': f'Simple sync completed. Retrieved {processed_count} CVE records for reference (not stored as vulnerabilities).',
                'details': f'Total results available: {total_results}. Using standalone NVD mode without vulnerability framework.',
            }
            
            sync_log = self.env['vuln.fw.nvd.sync.log'].create(log_vals)
            _logger.info("Simple CVE sync completed successfully")
            
            return {
                'processed': processed_count,
                'created': 0,
                'updated': 0,
                'log_id': sync_log.id,
                'message': f'Simple sync: Retrieved {processed_count} CVE records for reference.'
            }
            
        except Exception as e:
            _logger.error("Simple CVE sync failed: %s", str(e))
            raise UserError(_("Simple CVE sync failed: %s") % str(e))
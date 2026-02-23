# -*- coding: utf-8 -*-
"""VulnFwNvd Service API for external integrations"""
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdService(models.AbstractModel):
    """Service class providing clean API for external modules to interact with vuln_fw_nvd"""

    _name = 'vuln.fw.nvd.service'
    _description = 'Vulnerability Framework NVD Service API'

    @api.model
    def subscribe_cpe_for_asset(self, cpe_uri, asset_data, options=None):

        options = options or {}
        source = options.get('source', 'external')

        _logger.info(f"🔗 {source}: Subscribing CPE {cpe_uri} for asset {asset_data.get('asset_name', 'Unknown')}")

        try:
            _logger.info(f"🔧 Step 1: Ensuring CPE exists in dictionary")
            # Ensure CPE exists in dictionary
            cpe_dict = self._ensure_cpe_in_dictionary(cpe_uri)
            _logger.info(f"🔧 Step 1 completed: CPE dict ID {cpe_dict.id}")

            _logger.info(f"🔧 Step 2: Creating asset subscription")
            # Create or update asset subscription
            subscription = self._create_asset_subscription(cpe_dict, asset_data, source, options)
            _logger.info(f"🔧 Step 2 completed: Subscription ID {subscription.id}")

            _logger.info(f"🔧 Step 3: Activating subscription")
            # Activate subscription
            subscription.action_activate()
            _logger.info(f"🔧 Step 3 completed: Subscription activated")

            _logger.info(f"🔧 Step 4: Registering webhook (if available)")
            # Attempt webhook registration (will gracefully fail if not supported)
            webhook_result = self._register_webhook_if_available(cpe_uri)
            _logger.info(f"🔧 Step 4 completed: Webhook result {webhook_result}")

            _logger.info(f"🔧 Step 5: Performing initial sync")
            # Perform initial vulnerability sync
            sync_result = self._perform_initial_sync(subscription)
            _logger.info(f"🔧 Step 5 completed: Sync result {sync_result}")

            return {
                'success': True,
                'cpe_dictionary_id': cpe_dict.id,
                'subscription_id': subscription.id,
                'webhook_registered': webhook_result.get('success', False),
                'vulnerabilities_found': sync_result.get('vulnerabilities_found', 0),
                'critical_vulnerabilities': sync_result.get('critical_vulnerabilities', 0),
                'high_vulnerabilities': sync_result.get('high_vulnerabilities', 0),
                'medium_vulnerabilities': sync_result.get('medium_vulnerabilities', 0),
                'low_vulnerabilities': sync_result.get('low_vulnerabilities', 0),
                'cve_details': sync_result.get('cve_details', []),
                'message': f'Successfully subscribed {cpe_uri} for vulnerability monitoring'
            }

        except Exception as e:
            _logger.error(f"❌ Failed to subscribe CPE {cpe_uri}: {e}")
            import traceback
            _logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return {
                'success': False,
                'error': str(e),
                'cpe_uri': cpe_uri,
                'message': f'Failed to subscribe CPE for vulnerability monitoring: {str(e)}'
            }

    @api.model
    def sync_cpe_vulnerabilities(self, cpe_uri, options=None):
        options = options or {}

        _logger.info(f"🔄 Syncing vulnerabilities for CPE: {cpe_uri}")

        try:
            _logger.info(f"🔍 Finding CPE in dictionary: {cpe_uri}")
            # Find CPE in dictionary
            cpe_dict = self.env['vuln.fw.nvd.cpe.dictionary'].search([
                ('cpe_name', '=', cpe_uri)
            ], limit=1)
            _logger.info(f"🔍 CPE dictionary result: {cpe_dict.id if cpe_dict else 'Not found'}")

            if not cpe_dict:
                return {
                    'success': False,
                    'error': f'CPE {cpe_uri} not found in dictionary',
                    'message': 'CPE must be subscribed before syncing'
                }

            _logger.info(f"🔍 Looking for active NVD connector")
            # Perform sync
            connector = self.env['vuln.fw.nvd.api.connector'].search([
                ('active', '=', True),
                ('connector_active', '=', True)
            ], limit=1)
            _logger.info(f"🔍 Connector result: {connector.id if connector else 'No active connector'}")

            if not connector:
                return {
                    'success': False,
                    'error': 'No active NVD connector available',
                    'message': 'NVD connector must be configured and active'
                }

            _logger.info(f"🔄 Calling sync_vulnerabilities_for_cpe on connector {connector.id}")
            # Sync vulnerabilities for this CPE
            sync_result = connector.sync_vulnerabilities_for_cpe(cpe_dict)
            _logger.info(f"🔄 Sync result: {sync_result}")

            return {
                'success': True,
                'cpe_dictionary_id': cpe_dict.id,
                'vulnerabilities_found': sync_result.get('vulnerabilities_found', 0),
                'critical_vulnerabilities': sync_result.get('critical_vulnerabilities', 0),
                'high_vulnerabilities': sync_result.get('high_vulnerabilities', 0),
                'medium_vulnerabilities': sync_result.get('medium_vulnerabilities', 0),
                'low_vulnerabilities': sync_result.get('low_vulnerabilities', 0),
                'cve_details': sync_result.get('cve_details', []),
                'message': f'Successfully synced vulnerabilities for {cpe_uri}'
            }

        except Exception as e:
            _logger.error(f"❌ Failed to sync vulnerabilities for CPE {cpe_uri}: {e}")
            import traceback
            _logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return {
                'success': False,
                'error': str(e),
                'cpe_uri': cpe_uri,
                'message': f'Failed to sync vulnerabilities: {str(e)}'
            }

    @api.model
    def get_cpe_vulnerability_summary(self, cpe_uri):
        try:
            # Find CPE in dictionary
            cpe_dict = self.env['vuln.fw.nvd.cpe.dictionary'].search([
                ('cpe_name', '=', cpe_uri)
            ], limit=1)

            if not cpe_dict:
                return {
                    'success': False,
                    'error': f'CPE {cpe_uri} not found in dictionary',
                    'cpe_uri': cpe_uri
                }

            # Get vulnerability counts
            vuln_count = len(cpe_dict.vulnerability_ids)
            critical_count = len(cpe_dict.vulnerability_ids.filtered(lambda v: v.cvss_score >= 9.0))
            high_count = len(cpe_dict.vulnerability_ids.filtered(lambda v: 7.0 <= v.cvss_score < 9.0))
            medium_count = len(cpe_dict.vulnerability_ids.filtered(lambda v: 4.0 <= v.cvss_score < 7.0))
            low_count = len(cpe_dict.vulnerability_ids.filtered(lambda v: 0.0 <= v.cvss_score < 4.0))

            # Get latest vulnerabilities
            latest_vulns = cpe_dict.vulnerability_ids.sorted(
                key=lambda v: v.published_date, reverse=True
            )[:5]

            return {
                'success': True,
                'cpe_uri': cpe_uri,
                'cpe_dictionary_id': cpe_dict.id,
                'total_vulnerabilities': vuln_count,
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'latest_vulnerabilities': [{
                    'cve_id': v.cve_id,
                    'cvss_score': v.cvss_score,
                    'severity': v.severity_level,
                    'published_date': v.published_date.isoformat() if v.published_date else None,
                    'description': v.description[:200] + '...' if v.description and len(v.description) > 200 else v.description
                } for v in latest_vulns]
            }

        except Exception as e:
            _logger.error(f"❌ Failed to get vulnerability summary for CPE {cpe_uri}: {e}")
            return {
                'success': False,
                'error': str(e),
                'cpe_uri': cpe_uri
            }

    def _ensure_cpe_in_dictionary(self, cpe_uri):
        _logger.info(f"🔍 Ensuring CPE {cpe_uri} exists in dictionary")
        cpe_dict_model = self.env['vuln.fw.nvd.cpe.dictionary']

        cpe_dict = cpe_dict_model.search([
            ('cpe_name', '=', cpe_uri)
        ], limit=1)
        _logger.info(f"🔍 Found CPE dictionary entry: {cpe_dict.id if cpe_dict else 'None'}")

        if not cpe_dict:
            _logger.info(f"📝 Creating new CPE dictionary entry for {cpe_uri}")
            # Parse CPE URI to extract components
            components = cpe_dict_model._parse_cpe_name(cpe_uri)
            _logger.info(f"📝 Parsed CPE components: {components}")

            cpe_dict = cpe_dict_model.create({
                'cpe_uri': cpe_uri,
                'cpe_name': cpe_uri,
                'title': f"{components.get('vendor', 'Unknown')} {components.get('product', 'Unknown')}",
                'part': components.get('part', 'a'),
                'vendor': components.get('vendor', 'unknown'),
                'product': components.get('product', 'unknown'),
                'version': components.get('version', '*'),
                'update': components.get('update', '*'),
                'edition': components.get('edition', '*'),
                'language': components.get('language', '*'),
                'sw_edition': components.get('sw_edition', '*'),
                'target_sw': components.get('target_sw', '*'),
                'target_hw': components.get('target_hw', '*'),
                'other': components.get('other', '*'),
            })
            _logger.info(f"✅ Created CPE dictionary entry: {cpe_dict.id}")

        return cpe_dict

    def _create_asset_subscription(self, cpe_dict, asset_data, source, options):
        _logger.info(f"🔧 Creating asset subscription for CPE {cpe_dict.cpe_name} with asset data: {asset_data}")
        subscription_model = self.env['vuln.fw.nvd.asset.cpe.subscription']
        _logger.info(f"🔧 Using subscription model: {subscription_model}")

        # Create subscription using webhook method for consistency
        _logger.info(f"🔧 Calling create_from_webhook with cpe_uri={cpe_dict.cpe_name}")
        subscription = subscription_model.create_from_webhook(
            cpe_uri=cpe_dict.cpe_name,
            asset_data=asset_data,
            payload={
                'source': source,
                'options': options,
            }
        )
        _logger.info(f"✅ Created subscription with ID: {subscription.id}")

        return subscription

    def _register_webhook_if_available(self, cpe_uri):
        try:
            connector = self.env['vuln.fw.nvd.api.connector'].search([
                ('active', '=', True),
                ('connector_active', '=', True)
            ], limit=1)

            if connector:
                return connector.register_webhook_for_cpe(cpe_uri)
            else:
                return {'success': False, 'message': 'No active connector available'}

        except Exception as e:
            _logger.warning(f"⚠️ Webhook registration failed for {cpe_uri}: {e}")
            return {'success': False, 'error': str(e)}

    def _perform_initial_sync(self, subscription):
        try:
            _logger.info(f"🔄 Performing initial sync for subscription {subscription.id} with CPE {subscription.cpe_uri}")
            # Trigger sync on the CPE using the service API
            sync_result = self.sync_cpe_vulnerabilities(subscription.cpe_uri, {
                'source': 'initial_sync',
                'subscription_id': subscription.id
            })
            _logger.info(f"🔄 Initial sync completed: {sync_result}")

            return {
                'vulnerabilities_found': sync_result.get('vulnerabilities_found', 0),
                'critical_vulnerabilities': sync_result.get('critical_vulnerabilities', 0),
                'high_vulnerabilities': sync_result.get('high_vulnerabilities', 0),
                'medium_vulnerabilities': sync_result.get('medium_vulnerabilities', 0),
                'low_vulnerabilities': sync_result.get('low_vulnerabilities', 0),
                'cve_details': sync_result.get('cve_details', []),
                'sync_status': 'completed' if sync_result.get('success') else 'failed'
            }

        except Exception as e:
            _logger.error(f"❌ Initial sync failed for subscription {subscription.id}: {e}")
            import traceback
            _logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return {
                'vulnerabilities_found': 0,
                'critical_vulnerabilities': 0,
                'sync_status': 'failed',
                'error': str(e)
            }
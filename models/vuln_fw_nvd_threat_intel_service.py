# -*- coding: utf-8 -*-
"""Threat Intelligence service for NVD vulnerability framework"""
from odoo import models, api, fields, _
import logging
import requests
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class VulnFwNvdThreatIntelService(models.AbstractModel):
    """Service for threat intelligence gathering and processing"""
    _name = 'vuln.fw.nvd.threat.intel.service'
    _description = 'NVD Threat Intelligence Service'

    @api.model
    def gather_threat_intelligence(self, cve_id):
        """Gather threat intelligence for a CVE"""
        intel_data = {
            'cve_id': cve_id,
            'collection_timestamp': fields.Datetime.now(),
            'sources': []
        }

        try:
            # Check exploit databases
            exploit_data = self._check_exploit_databases(cve_id)
            if exploit_data:
                intel_data.update(exploit_data)
                intel_data['sources'].append('ExploitDB')

            # Check threat feeds
            threat_feed_data = self._check_threat_feeds(cve_id)
            if threat_feed_data:
                intel_data.update(threat_feed_data)
                intel_data['sources'].append('ThreatFeeds')

            # Check social media mentions
            social_data = self._check_social_mentions(cve_id)
            if social_data:
                intel_data.update(social_data)
                intel_data['sources'].append('Social')

            return intel_data

        except Exception as e:
            _logger.error("Threat intelligence gathering failed for %s: %s", cve_id, str(e))
            return {'error': str(e)}

    def _check_exploit_databases(self, cve_id):
        """Check exploit databases for available exploits"""
        try:
            # This is a placeholder - in real implementation would query ExploitDB API
            # For now, return mock data structure
            return {
                'intel_type': 'exploit_available',
                'confidence_level': 'high',
                'title': f'Exploit available for {cve_id}',
                'content': f'Exploit code has been identified for {cve_id}',
                'source': 'exploitdb'
            }
        except Exception as e:
            _logger.warning("Exploit database check failed: %s", str(e))
            return None

    def _check_threat_feeds(self, cve_id):
        """Check threat intelligence feeds"""
        try:
            # This is a placeholder - in real implementation would query threat feeds
            # For now, return mock data structure
            return {
                'intel_type': 'active_exploitation',
                'confidence_level': 'medium',
                'title': f'Active exploitation detected for {cve_id}',
                'content': f'Threat actors are actively exploiting {cve_id}',
                'source': 'threat_feed'
            }
        except Exception as e:
            _logger.warning("Threat feed check failed: %s", str(e))
            return None

    def _check_social_mentions(self, cve_id):
        """Check social media for mentions of the CVE"""
        try:
            # This is a placeholder - in real implementation would query social APIs
            # For now, return mock data structure
            return {
                'intel_type': 'poc_available',
                'confidence_level': 'low',
                'title': f'PoC mentioned for {cve_id}',
                'content': f'Proof of concept code discussed for {cve_id}',
                'source': 'social_media'
            }
        except Exception as e:
            _logger.warning("Social media check failed: %s", str(e))
            return None

    @api.model
    def process_intelligence_feed(self, feed_data):
        """Process intelligence from external feeds"""
        processed_count = 0

        try:
            for item in feed_data.get('items', []):
                cve_id = item.get('cve_id')
                if not cve_id:
                    continue

                # Find the CVE record
                cve_record = self.env['vuln.fw.nvd.cve.dictionary'].search([
                    ('cve_id', '=', cve_id)
                ], limit=1)

                if not cve_record:
                    _logger.warning("CVE %s not found for threat intelligence", cve_id)
                    continue

                # Create threat intelligence record
                intel_vals = {
                    'cve_id': cve_record.id,
                    'source': item.get('source', 'threat_feed'),
                    'confidence_level': item.get('confidence', 'medium'),
                    'intel_type': item.get('type', 'other'),
                    'title': item.get('title', f'Threat intelligence for {cve_id}'),
                    'content': item.get('content', ''),
                    'source_url': item.get('url'),
                    'author': item.get('author'),
                    'tags': item.get('tags'),
                }

                self.env['vuln.fw.nvd.threat.intel'].create(intel_vals)
                processed_count += 1

            _logger.info("Processed %d threat intelligence items", processed_count)
            return processed_count

        except Exception as e:
            _logger.error("Failed to process intelligence feed: %s", str(e))
            return 0

    @api.model
    def get_active_threats(self, days=7):
        """Get active threats from the last N days"""
        cutoff_date = fields.Datetime.now() - timedelta(days=days)

        threats = self.env['vuln.fw.nvd.threat.intel'].search([
            ('collection_timestamp', '>=', cutoff_date),
            ('is_active', '=', True),
            ('verification_status', '!=', 'false_positive')
        ])

        return threats

    @api.model
    def get_threat_summary(self):
        """Get summary of current threat landscape"""
        # Get threats from last 30 days
        recent_threats = self.get_active_threats(days=30)

        summary = {
            'total_threats': len(recent_threats),
            'by_source': {},
            'by_type': {},
            'by_confidence': {},
            'high_priority': []
        }

        for threat in recent_threats:
            # Count by source
            source = threat.source or 'unknown'
            summary['by_source'][source] = summary['by_source'].get(source, 0) + 1

            # Count by type
            intel_type = threat.intel_type or 'unknown'
            summary['by_type'][intel_type] = summary['by_type'].get(intel_type, 0) + 1

            # Count by confidence
            confidence = threat.confidence_level or 'unknown'
            summary['by_confidence'][confidence] = summary['by_confidence'].get(confidence, 0) + 1

            # Collect high priority threats
            if (threat.confidence_level in ['high', 'confirmed'] and
                threat.intel_type in ['active_exploitation', 'weaponized', 'ransomware']):
                summary['high_priority'].append({
                    'id': threat.id,
                    'cve_id': threat.cve_id.cve_id,
                    'title': threat.title,
                    'type': threat.intel_type,
                    'confidence': threat.confidence_level
                })

        return summary
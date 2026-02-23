# -*- coding: utf-8 -*-
"""VulnFwNvd Webhooks Controller for CPE 2.3 URI Data from Any Source"""
from odoo import http
from odoo.http import request
import logging
import json
from datetime import datetime

_logger = logging.getLogger(__name__)


class VulnFwNvdWebhooksController(http.Controller):
    """VulnFwNvd Controller to receive CPE 2.3 URIs from any external system"""
    
    @http.route(
        '/api/v1/cpe/subscribe',
        type='json',
        auth='none',
        methods=['POST'],
        csrf=False
    )
    def subscribe_cpe_api(self, **kwargs):
        """
        REST API endpoint for CPE subscription from external systems
        
        Expected JSON payload:
        {
            "api_key": "your_api_key_here",
            "cpe_uri": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*",
            "asset_data": {
                "asset_id": 123,
                "asset_name": "My Software Installation",
                "software_id": 456,
                "software_name": "Software Name",
                "software_version": "1.0.0"
            },
            "options": {
                "source": "external_system_name",
                "enable_alerts": true,
                "alert_threshold": "high"
            }
        }
        
        Returns:
            dict: Subscription result with vulnerability counts
        """
        _logger.info("=== CPE Subscription API Request Started ===")
        
        source_ip = request.httprequest.environ.get('REMOTE_ADDR', 'unknown')
        
        try:
            # Parse request body
            body = request.httprequest.get_json()
            if not body:
                return {
                    'status': 'error',
                    'message': 'No JSON payload received'
                }
            
            # Validate API token
            api_token = body.get('api_token')
            if not api_token:
                _logger.warning(f"Missing API token from {source_ip}")
                return {
                    'status': 'error',
                    'message': 'API token required'
                }
            
            # Authenticate using API client model
            api_client = request.env['vuln.fw.nvd.api.client'].sudo().authenticate(api_token)
            
            if not api_client:
                _logger.warning(f"Invalid API token from {source_ip}")
                return {
                    'status': 'error',
                    'message': 'Invalid or expired API token'
                }
            
            # Validate request against client configuration
            allowed, reason = api_client.validate_request(source_ip)
            if not allowed:
                _logger.warning(f"Request blocked for {api_client.name}: {reason}")
                return {
                    'status': 'error',
                    'message': f'Access denied: {reason}'
                }
            
            # Check endpoint permission
            if api_client.allowed_endpoints == 'sync_only':
                _logger.warning(f"Client {api_client.name} not allowed to subscribe")
                return {
                    'status': 'error',
                    'message': 'This client is not authorized for CPE subscription'
                }
            
            if api_client.allowed_endpoints == 'custom' and not api_client.can_subscribe_cpe:
                _logger.warning(f"Client {api_client.name} subscription permission denied")
                return {
                    'status': 'error',
                    'message': 'CPE subscription endpoint not allowed for this client'
                }
            
            # Extract parameters
            cpe_uri = body.get('cpe_uri')
            asset_data = body.get('asset_data', {})
            options = body.get('options', {})
            
            if not cpe_uri:
                return {
                    'status': 'error',
                    'message': 'CPE URI required'
                }
            
            _logger.info(f"✅ Authenticated API request from {api_client.name} ({source_ip}) for CPE: {cpe_uri}")
            
            # Call service API with sudo (no user context in auth='none')
            service = request.env['vuln.fw.nvd.service'].sudo()
            result = service.subscribe_cpe_for_asset(
                cpe_uri=cpe_uri,
                asset_data=asset_data,
                options=options
            )
            
            # Log successful request
            api_client.log_request(success=True, request_ip=source_ip)
            
            if result.get('success'):
                _logger.info(f"✅ Subscription successful for {api_client.name}: {result}")
                return {
                    'status': 'success',
                    'data': result,
                    'message': result.get('message', 'CPE subscribed successfully')
                }
            else:
                _logger.error(f"❌ Subscription failed for {api_client.name}: {result}")
                api_client.log_request(success=False, request_ip=source_ip)
                return {
                    'status': 'error',
                    'message': result.get('message', 'Subscription failed'),
                    'error': result.get('error')
                }
                
        except Exception as e:
            _logger.error(f"❌ API subscription error: {e}", exc_info=True)
            # Log failed request if client was authenticated
            if 'api_client' in locals() and api_client:
                api_client.log_request(success=False, request_ip=source_ip)
            return {
                'status': 'error',
                'message': f'Internal error: {str(e)}'
            }
    
    @http.route(
        '/api/v1/cpe/sync',
        type='json',
        auth='none',
        methods=['POST'],
        csrf=False
    )
    def sync_cpe_vulnerabilities_api(self, **kwargs):
        """
        REST API endpoint to sync vulnerabilities for a CPE
        
        Expected JSON payload:
        {
            "api_key": "your_api_key_here",
            "cpe_uri": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"
        }
        
        Returns:
            dict: Sync results with vulnerability counts
        """
        _logger.info("=== CPE Sync API Request Started ===")
        
        source_ip = request.httprequest.environ.get('REMOTE_ADDR', 'unknown')
        
        try:
            body = request.httprequest.get_json()
            if not body:
                return {
                    'status': 'error',
                    'message': 'No JSON payload received'
                }
            
            # Validate API token
            api_token = body.get('api_token')
            if not api_token:
                return {
                    'status': 'error',
                    'message': 'API token required'
                }
            
            api_client = request.env['vuln.fw.nvd.api.client'].sudo().authenticate(api_token)
            
            if not api_client:
                _logger.warning(f"Invalid API token from {source_ip}")
                return {
                    'status': 'error',
                    'message': 'Invalid or expired API token'
                }
            
            # Validate request
            allowed, reason = api_client.validate_request(source_ip)
            if not allowed:
                return {
                    'status': 'error',
                    'message': f'Access denied: {reason}'
                }
            
            # Check endpoint permission
            if api_client.allowed_endpoints == 'subscribe_only':
                return {
                    'status': 'error',
                    'message': 'This client is not authorized for CPE sync'
                }
            
            if api_client.allowed_endpoints == 'custom' and not api_client.can_sync_cpe:
                return {
                    'status': 'error',
                    'message': 'CPE sync endpoint not allowed for this client'
                }
            
            cpe_uri = body.get('cpe_uri')
            if not cpe_uri:
                return {
                    'status': 'error',
                    'message': 'CPE URI required'
                }
            
            _logger.info(f"✅ Authenticated sync request from {api_client.name} ({source_ip}) for CPE: {cpe_uri}")
            
            # Call service API with sudo (no user context in auth='none')
            service = request.env['vuln.fw.nvd.service'].sudo()
            result = service.sync_cpe_vulnerabilities(
                cpe_uri=cpe_uri,
                options=body.get('options', {})
            )
            
            # Log request
            api_client.log_request(success=result.get('success', False), request_ip=source_ip)
            
            if result.get('success'):
                return {
                    'status': 'success',
                    'data': result,
                    'message': 'Vulnerabilities synced successfully'
                }
            else:
                return {
                    'status': 'error',
                    'message': result.get('message', 'Sync failed'),
                    'error': result.get('error')
                }
                
        except Exception as e:
            _logger.error(f"❌ API sync error: {e}", exc_info=True)
            if 'api_client' in locals() and api_client:
                api_client.log_request(success=False, request_ip=source_ip)
            return {
                'status': 'error',
                'message': f'Internal error: {str(e)}'
            }
    
    @http.route(
        '/api/cpe/webhook',
        type='json',
        auth='none',
        methods=['POST'],
        csrf=False
    )
    def receive_cpe_webhook(self, **kwargs):
        """
        Receive CPE 2.3 URI from any external system
        
        Expected JSON payload:
        {
            "token": "webhook_token_from_receiver_config",
            "cpe_uri": "cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other",
            "source": "lansweeper_connector|any_other_source",
            "metadata": {
                "source_id": "...",
                "device_name": "...",
                "asset_type": "..."
            }
        }
        
        Returns:
            dict: Status and created/updated CPE dictionary record info
        """
        _logger.info("=== CPE Webhook Request Started ===")
        
        # Capture request metadata
        source_ip = request.httprequest.environ.get('REMOTE_ADDR', 'unknown')
        headers = dict(request.httprequest.headers)
        
        # Parse payload first (needed for queueing blocked requests)
        try:
            body = request.httprequest.get_json()
            _logger.debug(f"Webhook payload received: {body}")
            _logger.info(f"🔍 DEBUG - Full webhook payload: {json.dumps(body, indent=2) if body else 'None'}")
            
            if not body:
                _logger.warning("Empty JSON payload received")
                error_response = {
                    'status': 'error',
                    'message': 'No JSON payload received'
                }
                self._log_webhook_transaction(request, source_ip, None, error_response, 'error', 'Empty payload received')
                return error_response
                
        except Exception as parse_error:
            _logger.error(f"Failed to parse JSON payload: {parse_error}")
            error_response = {
                'status': 'error',
                'message': 'Invalid JSON payload'
            }
            self._log_webhook_transaction(request, source_ip, None, error_response, 'error', f'JSON parse error: {parse_error}')
            return error_response
        
        # Detect webhook type
        if body and 'cveId' in body:
            # This is an NVD CVE webhook notification
            _logger.info("Detected NVD CVE webhook payload")
            return self._process_nvd_cve_webhook(request, source_ip, body, headers)
        
        # Zero Trust Host Validation
        try:
            # Find receiver by looking up which allowed host contains the source IP
            allowed_host = request.env['vuln.fw.nvd.webhook.allowed.host'].sudo().search([
                ('host_pattern', '=', source_ip),
                ('host_type', '=', 'ip_single'),
                ('active', '=', True)
            ], limit=1)
            
            # Get receiver associated with this allowed host
            default_receiver = None
            if allowed_host:
                default_receiver = request.env['vuln.fw.nvd.webhook.receiver'].sudo().search([
                    ('allowed_host_ids', 'in', allowed_host.id),
                    ('active', '=', True)
                ], limit=1)
            
            if default_receiver:
                host_allowed, matched_host, reason = default_receiver.check_host_access(source_ip)
                if not host_allowed:
                    _logger.warning(f"Host {source_ip} blocked by zero trust policy: {reason}")
                    
                    # Queue payload as blocked for future processing when host is allowed
                    try:
                        blocked_queue_entry = self._queue_blocked_payload(request, source_ip, body, headers, default_receiver)
                        _logger.info(f"Blocked payload queued for future processing: {blocked_queue_entry.id}")
                    except Exception as queue_error:
                        _logger.error(f"Failed to queue blocked payload: {queue_error}")
                    
                    # Record blocked host for administrative review
                    try:
                        user_agent = headers.get('User-Agent', 'Unknown')
                        request.env['vuln.fw.nvd.webhook.blocked.host'].sudo().record_blocked_host(
                            source_ip=source_ip,
                            endpoint='/api/cpe/webhook',
                            user_agent=user_agent,
                            payload_sample=json.dumps(body)[:500] if body else None  # First 500 chars as sample
                        )
                    except Exception as record_error:
                        _logger.error(f"Failed to record blocked host {source_ip}: {record_error}")
                    
                    blocked_response = {
                        'status': 'error',
                        'message': 'Access denied: Host not authorized',
                        'reason': reason,
                        'source_ip': source_ip,
                        'note': 'This payload has been queued and will be processed when host is authorized'
                    }
                    self._log_webhook_transaction(request, source_ip, body, blocked_response, 'blocked', f'Host blocked: {reason}')
                    return blocked_response
                else:
                    _logger.info(f"Host {source_ip} passed zero trust validation: {reason}")
            else:
                # Zero Trust: Block by default when no receiver configured
                _logger.warning(f"No webhook receiver found - blocking {source_ip} (Zero Trust)")
                
                # Record blocked host for administrative review
                try:
                    user_agent = headers.get('User-Agent', 'Unknown')
                    request.env['vuln.fw.nvd.webhook.blocked.host'].sudo().record_blocked_host(
                        source_ip=source_ip,
                        endpoint='/api/cpe/webhook',
                        user_agent=user_agent,
                        payload_sample=json.dumps(body)[:500] if body else None
                    )
                except Exception as record_error:
                    _logger.error(f"Failed to record blocked host {source_ip}: {record_error}")
                
                no_receiver_response = {
                    'status': 'error',
                    'message': 'Access denied: No webhook receiver configured',
                    'reason': 'Zero Trust: No receiver found for host validation',
                    'source_ip': source_ip,
                    'note': 'Configure a webhook receiver and add this host to the allowlist'
                }
                self._log_webhook_transaction(request, source_ip, body, no_receiver_response, 'blocked', 'No receiver configured - Zero Trust block')
                return no_receiver_response
        
        except Exception as host_check_error:
            _logger.error(f"Error during host validation for {source_ip}: {host_check_error}")
            # In case of validation error, we could either allow or block
            # For security, we'll block by default
            error_response = {
                'status': 'error',
                'message': 'Access denied: Host validation error'
            }
            self._log_webhook_transaction(request, source_ip, None, error_response, 'error', f'Host validation error: {host_check_error}')
            return error_response
        # Host passed validation - continue with normal processing
        try:
            # Log inbound message
            self._log_webhook_transaction(request, source_ip, body, None, 'received', 'Webhook received')
            
            # Check if this is a webhook test from Lansweeper connector
            if (body.get('test') is True or 
                body.get('message') == 'This is a test webhook from Lansweeper Connector' or
                'test' in str(body.get('message', '')).lower()):
                _logger.info("Detected webhook test from Lansweeper connector - handling as test")
                
                test_response = {
                    'status': 'success',
                    'message': 'CPE webhook endpoint is working! This was a test from Lansweeper connector.',
                    'endpoint': 'CPE Webhook Controller',
                    'test_detected': True,
                    'received_test_data': bool(body.get('test')),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Log outbound test response
                self._log_webhook_transaction(request, source_ip, body, test_response, 'test_response', 'Test webhook handled')
                return test_response
            
            # Process CPE synchronously (live communication)
            return self._process_cpe_webhook_live(request, source_ip, body, headers, default_receiver)
            
            # Safe debug logging with token validation
            token_preview = token[:10] + '...' if token and len(str(token)) > 10 else str(token)
            _logger.debug(f"Extracted - Token: {token_preview}, CPE: {cpe_uri}, Source: {source}")
            
            # When Zero Trust passes, we already have a receiver - token is optional
            receiver = default_receiver
            
            # If no receiver from Zero Trust, try token-based authentication
            if not receiver:
                if not token:
                    _logger.error(f"Missing authentication - Token present: {bool(token)}, CPE present: {bool(cpe_uri)}")
                    return {
                        'status': 'error',
                        'message': 'Missing required fields: token (or authorized IP), cpe_uri'
                    }
                
                # Find webhook receiver by token
                _logger.debug(f"Searching for webhook receiver with token")
                receiver = request.env['vuln.fw.nvd.webhook.receiver'].sudo().search([
                    ('webhook_token', '=', token),
                    ('active', '=', True)
                ], limit=1)
            
            if not cpe_uri:
                _logger.error(f"Missing CPE URI - CPE present: {bool(cpe_uri)}")
                return {
                    'status': 'error',
                    'message': 'Missing required field: cpe_uri',
                    'cpe': {},
                    'subscription': {},
                    'timestamp': datetime.now().isoformat()
                }
            
            if not receiver:
                _logger.warning(f"Invalid webhook token received for CPE: {cpe_uri} from source: {source}")
                return {
                    'status': 'error',
                    'message': 'Invalid token',
                    'cpe': {'uri': cpe_uri if cpe_uri else None},
                    'subscription': {},
                    'timestamp': datetime.now().isoformat()
                }
            
            _logger.info(f"Webhook receiver found: {receiver.name}, internal_only={receiver.internal_only}")
            
            # Check if internal-only access is required
            if receiver.internal_only:
                _logger.debug("Checking internal-only access restriction")
                # Require authenticated Odoo user
                if not request.env.user or request.env.user.id == request.env.ref('base.public_user').id:
                    _logger.warning(f"Unauthorized external access to internal-only CPE webhook from source {source}")
                    return {
                        'status': 'error',
                        'message': 'This webhook is restricted to internal Odoo users only'
                    }
                _logger.info(f"Internal-only access granted to user: {request.env.user.login}")
            
            # Verify source is allowed
            allowed_sources = [s.strip() for s in (receiver.allowed_sources or '').split('\n') if s.strip()]
            _logger.debug(f"Allowed sources: {allowed_sources}, Incoming source: {source}")
            if allowed_sources and source not in allowed_sources:
                _logger.warning(f"Unauthorized source {source} attempting to send CPE: {cpe_uri}")
                return {
                    'status': 'error',
                    'message': f'Source {source} not allowed',
                    'cpe': {'uri': cpe_uri},
                    'subscription': {},
                    'timestamp': datetime.now().isoformat()
                }
            
            _logger.info(f"Source validation passed. Processing CPE: {cpe_uri}")
            
            # Process CPE webhook synchronously (live communication)
            return self._process_cpe_webhook_live(request, source_ip, body, headers, default_receiver)
                
        except json.JSONDecodeError as je:
            _logger.error(f"Invalid JSON in CPE webhook request: {str(je)}")
            return {
                'status': 'error',
                'message': 'Invalid JSON payload',
                'error': str(je),
                'cpe': {},
                'subscription': {},
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            _logger.exception(f"Error processing CPE webhook: {str(e)}")
            error_response = {
                'status': 'error',
                'message': f'Server error: {str(e)}'
            }
            self._log_webhook_transaction(request, source_ip, body, error_response, 'error', f'Processing error: {str(e)}')
            return error_response
        finally:
            _logger.info("=== CPE Webhook Request Completed ===")
    
    def _process_cpe_webhook_live(self, request, source_ip, body, headers, default_receiver):
        """Process CPE webhook synchronously (live communication)"""
        try:
            # Extract CPE components
            cpe_uri = body.get('cpe_uri', '')
            source = body.get('source', '')
            metadata = body.get('metadata', {})
            
            _logger.debug(f"🔍 DEBUG - Full webhook payload: {json.dumps(body, indent=2)}")
            
            # Check if CPE URI already exists
            existing_cpe = request.env['vuln.fw.nvd.cpe.dictionary'].sudo().search([
                ('cpe_name', '=', cpe_uri)
            ], limit=1)
            
            if existing_cpe:
                _logger.info(f"CPE URI already exists in dictionary: {existing_cpe.id} - {cpe_uri}")
                
                # Create asset subscription to this CPE
                asset_data = {
                    'asset_id': body.get('asset_id'),
                    'asset_name': body.get('asset_name'),
                    'software_id': body.get('software_id'),
                    'software_name': body.get('software_name'),
                    'software_version': body.get('software_version')
                }
                
                subscription = None
                try:
                    subscription = request.env['vuln.fw.nvd.asset.cpe.subscription'].sudo().create_from_webhook(
                        cpe_uri, asset_data, body
                    )
                    _logger.info(f"Asset subscription created: {subscription.id}")
                except Exception as sub_error:
                    _logger.error(f"Failed to create asset subscription: {sub_error}")
                
                # Build vendor dict or empty
                vendor_data = {}
                if hasattr(existing_cpe, 'vendor_id') and existing_cpe.vendor_id:
                    vendor = existing_cpe.vendor_id
                    vendor_data = {
                        'name': vendor.name,
                        'custom_name': vendor.custom_name if hasattr(vendor, 'custom_name') else None,
                        'website': vendor.website if hasattr(vendor, 'website') else None,
                        'active': vendor.active if hasattr(vendor, 'active') else True,
                        'last_changed': vendor.write_date.isoformat() if vendor.write_date else None
                    }
                
                # Build product dict or empty
                product_data = {}
                if hasattr(existing_cpe, 'product_id') and existing_cpe.product_id:
                    product = existing_cpe.product_id
                    product_data = {
                        'name': existing_cpe.product,
                        'custom_name': product.custom_name if hasattr(product, 'custom_name') else None,
                        'website': product.website if hasattr(product, 'website') else None,
                        'active': product.active if hasattr(product, 'active') else True,
                        'last_changed': product.write_date.isoformat() if product.write_date else None
                    }
                
                response = {
                    'status': 'success',
                    'message': 'CPE already exists in dictionary',
                    'cpe': {
                        'id': existing_cpe.id,
                        'uri': existing_cpe.cpe_name,
                        'vendor': vendor_data,
                        'product': product_data,
                        'version': existing_cpe.version,
                        'already_exists': True
                    },
                    'subscription': {
                        'id': subscription.id if subscription else None,
                        'asset_id': asset_data.get('asset_id'),
                        'asset_name': asset_data.get('asset_name'),
                        'software_name': asset_data.get('software_name'),
                        'software_version': asset_data.get('software_version'),
                        'state': subscription.state if subscription else 'pending',
                        'subscribed_date': subscription.subscribed_date.isoformat() if subscription else None
                    },
                    'timestamp': datetime.now().isoformat()
                }
                
                _logger.info(f"📤 Response payload: {json.dumps(response, indent=2)}")
                self._log_webhook_transaction(request, source_ip, body, response, 'success', 'CPE already exists, subscription created')
                return response
            
            # Process CPE URI if it doesn't exist
            cpe_dict = request.env['vuln.fw.nvd.cpe.dictionary'].sudo().process_cpe_uri(
                cpe_uri, 
                source=source,
                metadata=metadata
            )
            
            if cpe_dict:
                _logger.info(f"CPE processed successfully: {cpe_dict.cpe_name} (ID: {cpe_dict.id})")
                
                # Create asset subscription to this CPE
                asset_data = {
                    'asset_id': body.get('asset_id'),
                    'asset_name': body.get('asset_name'),
                    'software_id': body.get('software_id'),
                    'software_name': body.get('software_name'),
                    'software_version': body.get('software_version')
                }
                
                subscription = None
                try:
                    subscription = request.env['vuln.fw.nvd.asset.cpe.subscription'].sudo().create_from_webhook(
                        cpe_uri, asset_data, body
                    )
                    _logger.info(f"Asset subscription created: {subscription.id}")
                except Exception as sub_error:
                    _logger.error(f"Failed to create asset subscription: {sub_error}")
                
                # Build vendor dict or empty
                vendor_data = {}
                if hasattr(cpe_dict, 'vendor_id') and cpe_dict.vendor_id:
                    vendor = cpe_dict.vendor_id
                    vendor_data = {
                        'name': vendor.name,
                        'custom_name': vendor.custom_name if hasattr(vendor, 'custom_name') else None,
                        'website': vendor.website if hasattr(vendor, 'website') else None,
                        'active': vendor.active if hasattr(vendor, 'active') else True,
                        'last_changed': vendor.write_date.isoformat() if vendor.write_date else None
                    }
                
                # Build product dict or empty
                product_data = {}
                if hasattr(cpe_dict, 'product_id') and cpe_dict.product_id:
                    product = cpe_dict.product_id
                    product_data = {
                        'name': cpe_dict.product,
                        'custom_name': product.custom_name if hasattr(product, 'custom_name') else None,
                        'website': product.website if hasattr(product, 'website') else None,
                        'active': product.active if hasattr(product, 'active') else True,
                        'last_changed': product.write_date.isoformat() if product.write_date else None
                    }
                
                response = {
                    'status': 'success',
                    'message': 'CPE processed successfully',
                    'cpe': {
                        'id': cpe_dict.id,
                        'uri': cpe_dict.cpe_name,
                        'vendor': vendor_data,
                        'product': product_data,
                        'version': cpe_dict.version,
                        'newly_created': True
                    },
                    'subscription': {
                        'id': subscription.id if subscription else None,
                        'asset_id': asset_data.get('asset_id'),
                        'asset_name': asset_data.get('asset_name'),
                        'software_name': asset_data.get('software_name'),
                        'software_version': asset_data.get('software_version'),
                        'state': subscription.state if subscription else 'pending',
                        'subscribed_date': subscription.subscribed_date.isoformat() if subscription else None
                    },
                    'timestamp': datetime.now().isoformat()
                }
                
                _logger.info(f"📤 Response payload: {json.dumps(response, indent=2)}")
                self._log_webhook_transaction(request, source_ip, body, response, 'success', 'CPE created and subscription processed')
                return response
            else:
                _logger.error(f"Failed to process CPE URI: {cpe_uri}")
                response = {
                    'status': 'error',
                    'message': 'Failed to process CPE URI',
                    'cpe': {'uri': cpe_uri},
                    'subscription': {},
                    'timestamp': datetime.now().isoformat()
                }
                _logger.info(f"📤 Error response: {json.dumps(response, indent=2)}")
                self._log_webhook_transaction(request, source_ip, body, response, 'error', 'Failed to process CPE')
                return response
                
        except Exception as e:
            _logger.exception(f"Error in live CPE webhook processing: {str(e)}")
            error_response = {
                'status': 'error',
                'message': f'Server error: {str(e)}',
                'cpe': {},
                'subscription': {},
                'timestamp': datetime.now().isoformat()
            }
            self._log_webhook_transaction(request, source_ip, body, error_response, 'error', f'Processing error: {str(e)}')
            return error_response
    
    def _log_webhook_transaction(self, request, source_ip, inbound_payload, outbound_response, status, message):
        """Log inbound and outbound webhook messages"""
        try:
            # Find a receiver for logging (may be None for blocked requests)
            receiver = request.env['vuln.fw.nvd.webhook.receiver'].sudo().search([
                ('name', '=', 'CPE Webhook Controller'),
                ('active', '=', True)
            ], limit=1)
            
            if not receiver:
                # For blocked requests, create a logging-only receiver entry
                receiver = request.env['vuln.fw.nvd.webhook.receiver'].sudo().create({
                    'name': 'CPE Webhook Controller',
                    'description': 'Logging receiver for CPE webhook requests (created for audit trail)',
                    'webhook_token': 'cpe-webhook-logging',
                    'active': False,  # Inactive so it won't accept future requests
                    'endpoint_url': '/api/cpe/webhook',
                })
                _logger.info(f"Created logging-only receiver for audit trail: {receiver.id}")
            
            # Create webhook receiver log entry
            
            # Create webhook receiver log entry
            request.env['vuln.fw.nvd.webhook.receiver.log'].sudo().create({
                'receiver_id': receiver.id,
                'source_ip': source_ip,
                'payload': json.dumps(inbound_payload) if inbound_payload else None,
                'response': json.dumps(outbound_response) if outbound_response else None,
                'status': status,
                'notes': message,
                'endpoint': '/api/cpe/webhook'
            })
            _logger.debug(f"Webhook transaction logged: {status} - {message}")
        except Exception as log_error:
            _logger.error(f"Failed to log webhook transaction: {log_error}")
    
    def _queue_blocked_payload(self, request, source_ip, payload, headers, receiver):
        """Queue blocked payload for future processing when host is authorized"""
        try:
            # Create queue entry with blocked status
            queue_entry = request.env['vuln.fw.nvd.webhook.payload.queue'].sudo().create({
                'receiver_id': receiver.id,
                'payload': json.dumps(payload),
                'source_ip': source_ip,
                'state': 'blocked',  # Blocked status
                'priority': 10,  # Lower priority than normal requests
                'tags': 'blocked_host,zero_trust',
                'error_message': f'Blocked by Zero Trust - Host {source_ip} not in allowlist'
            })
            
            _logger.info(f"Queued blocked payload from {source_ip} for future processing: {queue_entry.id}")
            return queue_entry
            
        except Exception as queue_error:
            _logger.error(f"Failed to queue blocked payload: {queue_error}")
            raise

    def _queue_for_async_processing(self, request, source_ip, payload, headers, receiver=None):
        """Queue payload for asynchronous processing"""
        try:
            # Use the receiver passed from Zero Trust validation
            if not receiver:
                # Fallback: try to find any active receiver (should not happen normally)
                _logger.warning("No receiver passed to queuing - attempting fallback search")
                receiver = request.env['vuln.fw.nvd.webhook.receiver'].sudo().search([
                    ('active', '=', True)
                ], limit=1)
            
            if not receiver:
                # This should not happen if zero trust validation worked correctly
                _logger.error("No webhook receiver found during queuing - this indicates a validation error")
                raise ValueError("No webhook receiver available for queuing")
            
            # Create queue entry
            queue_entry = request.env['vuln.fw.nvd.webhook.payload.queue'].sudo().create({
                'receiver_id': receiver.id,
                'payload': json.dumps(payload),
                'source_ip': source_ip,
                'priority': 1 if payload.get('test') else 5,  # Lower priority for tests
                'tags': 'cpe_webhook,lansweeper_connector' if payload.get('source') == 'lansweeper_connector' else 'cpe_webhook'
            })
            
            # Try to trigger async processing if job queue available, otherwise will be processed manually
            try:
                queue_entry.with_delay(eta=5)._process_payload_async()  # Process in 5 seconds
            except AttributeError:
                # Job queue system not available, queue entry created for manual processing
                _logger.info(f"Job queue system not available, queue entry {queue_entry.id} ready for manual processing")
            
            return queue_entry
            
        except Exception as queue_error:
            _logger.error(f"Failed to queue payload: {queue_error}")
            raise
    
    def _process_cpe_payload_sync(self, request, source_ip, payload):
        """Fallback synchronous processing when async fails"""
        try:
            _logger.info("Processing CPE payload synchronously as fallback")
            # Continue with original synchronous logic
            token = payload.get('token')
            cpe_uri = payload.get('cpe_uri')
            source = payload.get('source', 'external_system')
            metadata = payload.get('metadata', {})
            
            # Safe debug logging with token validation
            token_preview = token[:10] + '...' if token and len(str(token)) > 10 else str(token)
            _logger.debug(f"Extracted - Token: {token_preview}, CPE: {cpe_uri}, Source: {source}")
            
            if not cpe_uri:
                error_msg = f"Missing required fields - CPE present: {bool(cpe_uri)}"
                _logger.error(error_msg)
                sync_response = {
                    'status': 'error',
                    'message': 'Missing required field: cpe_uri'
                }
                self._log_webhook_transaction(request, source_ip, payload, sync_response, 'error', error_msg)
                return sync_response
            
            # Continue with the rest of the original processing logic...
            # (The existing CPE processing code would go here)
            
            sync_response = {
                'status': 'success',
                'message': 'CPE processed synchronously',
                'processing_mode': 'synchronous_fallback'
            }
            
            self._log_webhook_transaction(request, source_ip, payload, sync_response, 'success', 'Processed synchronously')
            return sync_response
            
        except Exception as sync_error:
            _logger.error(f"Synchronous processing failed: {sync_error}")
            error_response = {
                'status': 'error',
                'message': f'Synchronous processing failed: {str(sync_error)}'
            }
            self._log_webhook_transaction(request, source_ip, payload, error_response, 'error', f'Sync processing error: {str(sync_error)}')
            return error_response

    def _process_nvd_cve_webhook(self, request, source_ip, body, headers):
        """Process NVD CVE webhook notification"""
        try:
            cve_id = body.get('cveId')
            if not cve_id:
                _logger.error("NVD webhook missing cveId")
                return {
                    'status': 'error',
                    'message': 'Missing cveId in NVD webhook payload'
                }
            
            _logger.info(f"🔄 Processing NVD CVE webhook for: {cve_id}")
            
            # Find existing vulnerability or create/update it
            vuln_model = request.env['vuln.fw.nvd.cve.dictionary']
            existing_vuln = vuln_model.sudo().search([('cve_id', '=', cve_id)], limit=1)
            
            if existing_vuln:
                _logger.info(f"Updating existing vulnerability: {cve_id}")
                # Update existing vulnerability with webhook data
                existing_vuln._update_from_webhook(body)
            else:
                _logger.info(f"Creating new CVE from webhook: {cve_id}")
                # Create new vulnerability from webhook data
                vuln_model.sudo().create_from_webhook(body)
            
            # Trigger subscription notifications for affected assets
            self._notify_subscriptions_for_cve(request, cve_id, body)
            
            response = {
                'status': 'success',
                'message': f'CVE {cve_id} processed successfully',
                'cve_id': cve_id,
                'action': 'updated' if existing_vuln else 'created'
            }
            
            self._log_webhook_transaction(request, source_ip, body, response, 'success', f'NVD CVE webhook processed: {cve_id}')
            return response
            
        except Exception as e:
            _logger.error(f"Failed to process NVD CVE webhook: {e}", exc_info=True)
            error_response = {
                'status': 'error',
                'message': f'Failed to process CVE webhook: {str(e)}'
            }
            self._log_webhook_transaction(request, source_ip, body, error_response, 'error', f'NVD webhook processing error: {str(e)}')
            return error_response

    def _notify_subscriptions_for_cve(self, request, cve_id, cve_data):
        """Notify asset subscriptions about CVE updates"""
        try:
            # Find all CPEs that match this CVE
            cpe_matches = self._find_matching_cpes_for_cve(cve_data)
            
            notified_count = 0
            for cpe_uri in cpe_matches:
                # Find subscriptions for this CPE
                subscriptions = request.env['vuln.fw.nvd.asset.cpe.subscription'].sudo().search([
                    ('cpe_dictionary_id.cpe_name', '=', cpe_uri),
                    ('active', '=', True)
                ])
                
                for subscription in subscriptions:
                    # Trigger notification (could be email, webhook, etc.)
                    subscription._notify_cve_update(cve_id, cve_data)
                    notified_count += 1
            
            _logger.info(f"✅ Notified {notified_count} subscriptions about CVE {cve_id}")
            
        except Exception as e:
            _logger.error(f"Failed to notify subscriptions for CVE {cve_id}: {e}")

    def _find_matching_cpes_for_cve(self, cve_data):
        """Find CPE URIs that match the CVE data"""
        # This would parse the CVE configurations to find matching CPEs
        # For now, return empty list - would need implementation based on CVE format
        return []

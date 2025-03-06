#!/usr/bin/env python3
# sentinel_integration.py
# This module handles sending data to Azure Sentinel Log Analytics

import base64
import datetime
import hashlib
import hmac
import json
import logging
import requests

logger = logging.getLogger('sentinel_integration')

class SentinelIntegration:
    """Class for sending data to Azure Sentinel Log Analytics"""
    
    def __init__(self, workspace_id, shared_key, log_type):
        """Initialize with required Sentinel credentials"""
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.log_type = log_type
        
    def build_signature(self, date, content_length):
        """Build the API signature for Log Analytics authentication"""
        string_to_hash = "POST\n" + str(content_length) + "\napplication/json\n" + \
                        f"x-ms-date:{date}\n/api/logs"
        bytes_to_hash = string_to_hash.encode('utf-8')
        
        # Decode the shared key (base64) and create signature
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode('utf-8')
        
        return f"SharedKey {self.workspace_id}:{encoded_hash}"
        
    def post_data(self, data):
        """Send data to Log Analytics workspace"""
        # Ensure data is properly formatted for Sentinel
        formatted_data = self._format_data_for_sentinel(data)
        json_data = json.dumps(formatted_data)
        body = json_data.encode('utf-8')
        
        # Build the API signature
        date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self.build_signature(date, content_length)
        
        # Build headers
        headers = {
            'content-type': 'application/json',
            'Authorization': signature,
            'Log-Type': self.log_type,
            'x-ms-date': date
        }
        
        # Send request
        uri = f'https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'
        
        try:
            response = requests.post(uri, data=body, headers=headers)
            
            if (response.status_code >= 200 and response.status_code <= 299):
                logger.info(f"Data accepted by Sentinel: {response.status_code}")
                return True
            else:
                logger.error(f"Error submitting data to Sentinel: {response.status_code}, {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception sending data to Sentinel: {str(e)}")
            return False
            
    def _format_data_for_sentinel(self, data):
        """Format data according to Log Analytics requirements"""
        # Sentinel requires an array of records, each with a timestamp
        # If the data is already an array, ensure each item has a timestamp
        # If not, wrap it in an array
        
        if isinstance(data, list):
            records = data
        else:
            records = [data]
            
        # Ensure each record has a timestamp
        current_time = datetime.datetime.utcnow().isoformat()
        
        for record in records:
            # Add a timestamp if not present
            if "TimeGenerated" not in record:
                record["TimeGenerated"] = current_time
                
            # Convert any nested dictionaries to strings to prevent Log Analytics issues
            for key, value in list(record.items()):
                if isinstance(value, dict):
                    record[key] = json.dumps(value)
                elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
                    # For lists of dictionaries, create summary fields
                    record[key] = json.dumps(value)
                    # Also add a count field for quick reference
                    record[f"{key}_count"] = len(value)
                    
        return records